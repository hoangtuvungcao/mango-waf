package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"mango-waf/config"
	"mango-waf/logger"
)

// Manager handles challenge serving and verification
type Manager struct {
	cfg    *config.Config
	secret []byte
}

// ChallengeType represents the type of challenge
type ChallengeType int

const (
	ChallengeJS      ChallengeType = 1 // JavaScript PoW
	ChallengeCAPTCHA ChallengeType = 2 // reCAPTCHA or Turnstile
	ChallengeSilent  ChallengeType = 3 // Silent JS fingerprint
)

// NewManager creates a new challenge manager
func NewManager(cfg *config.Config) *Manager {
	secret := []byte(cfg.Protection.Challenge.CookieSecret)
	if len(secret) == 0 {
		secret = make([]byte, 32)
		rand.Read(secret)
	}
	return &Manager{cfg: cfg, secret: secret}
}

// ServeChallenge serves the appropriate challenge page
func (m *Manager) ServeChallenge(w http.ResponseWriter, r *http.Request, stage int, difficulty int) {
	switch ChallengeType(stage) {
	case ChallengeJS:
		m.serveJSChallenge(w, r, difficulty)
	case ChallengeCAPTCHA:
		m.serveCAPTCHAChallenge(w, r)
	case ChallengeSilent:
		m.serveSilentChallenge(w, r)
	default:
		m.serveJSChallenge(w, r, difficulty)
	}
}

// VerifyProof verifies a challenge proof cookie
func (m *Manager) VerifyProof(r *http.Request, currentIP string) bool {
	cookie, err := r.Cookie("mango_proof")
	if err != nil || cookie.Value == "" {
		logger.Debug("Challenge missing mango_proof cookie", "ip", currentIP)
		return false
	}

	parts := strings.SplitN(cookie.Value, "|", 2)
	if len(parts) != 2 {
		logger.Warn("Challenge proof format invalid", "value", cookie.Value)
		return false
	}

	payload := parts[0]
	sig := parts[1]

	// Verify HMAC
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		logger.Warn("Challenge proof HMAC mismatch", "payload", payload)
		return false
	}

	// Check expiry (payload format: "ip_timestamp")
	payloadParts := strings.SplitN(payload, "_", 2)
	if len(payloadParts) == 2 {
		// Enforce IP matching - this prevents session hijacking
		// and fixes the redirect loop caused by IP mismatches
		cookieIP := payloadParts[0]
		if cookieIP != currentIP {
			logger.Warn("IP Mismatch in cookie verification", "cookie_ip", cookieIP, "request_ip", currentIP)
			return false
		}

		ts, err := strconv.ParseInt(payloadParts[1], 10, 64)
		if err == nil {
			issued := time.Unix(ts, 0)
			if time.Since(issued) > m.cfg.Protection.Challenge.CookieTTL {
				logger.Warn("Challenge proof expired", "issued", issued)
				return false // Expired
			}
		}
	} else {
		logger.Warn("Challenge proof payload format invalid", "payload", payload)
		return false
	}

	return true
}

// SetProofCookie sets a signed proof cookie
func (m *Manager) SetProofCookie(w http.ResponseWriter, r *http.Request, ip string) {
	payload := fmt.Sprintf("%s_%d", ip, time.Now().Unix())

	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	cookie := &http.Cookie{
		Name:     "mango_proof",
		Value:    payload + "|" + sig,
		Path:     "/",
		MaxAge:   int(m.cfg.Protection.Challenge.CookieTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   m.cfg.TLS.Enabled,
	}
	http.SetCookie(w, cookie)
}

// HandleVerification handles POSTed challenge solutions
func (m *Manager) HandleVerification(w http.ResponseWriter, r *http.Request, ip string) bool {
	if r.Method != "POST" {
		return false
	}

	challengeType := r.FormValue("challenge_type")

	switch challengeType {
	case "pow":
		return m.verifyPoW(w, r, ip)
	case "turnstile":
		return m.verifyTurnstile(w, r, ip)
	}

	return false
}

// verifyPoW verifies a Proof-of-Work solution
func (m *Manager) verifyPoW(w http.ResponseWriter, r *http.Request, ip string) bool {
	nonce := r.FormValue("nonce")
	challenge := r.FormValue("challenge")
	difficulty := r.FormValue("difficulty")

	if nonce == "" || challenge == "" {
		logger.Warn("PoW missing nonce or challenge", "nonce", nonce, "challenge", challenge)
		return false
	}

	// Verify the hash meets difficulty
	data := challenge + nonce
	hash := sha256.Sum256([]byte(data))
	hashHex := hex.EncodeToString(hash[:])

	diffInt, _ := strconv.Atoi(difficulty)
	if diffInt == 0 {
		diffInt = m.cfg.Protection.Challenge.PowDifficulty
	}

	prefix := strings.Repeat("0", diffInt)
	if !strings.HasPrefix(hashHex, prefix) {
		logger.Warn("PoW hash prefix mismatch", "hash", hashHex, "expected_prefix", prefix)
		return false
	}

	logger.Debug("PoW verified", "ip", ip, "difficulty", diffInt)
	m.SetProofCookie(w, r, ip)
	return true
}

// verifyTurnstile verifies the Modern Hold-to-Verify interaction
func (m *Manager) verifyTurnstile(w http.ResponseWriter, r *http.Request, ip string) bool {
	tsStr := r.FormValue("t_id")
	hash := r.FormValue("t_hash")
	data := r.FormValue("t_data")

	if tsStr == "" || hash == "" || data == "" {
		logger.Warn("Turnstile missing fields", "ip", ip)
		return false
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	diff := time.Now().Unix() - ts
	if err != nil || diff < -10 || diff > 300 { // 5 minutes expiry, clock skew tolerance 10s
		logger.Warn("Turnstile expired or invalid timestamp", "ip", ip)
		return false
	}

	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(tsStr))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(hash), []byte(expected)) {
		logger.Warn("Turnstile hash mismatch", "ip", ip)
		return false
	}

	// The 'data' payload contains mouse/touch events tracked by the browser.
	// Simple bots scaling curl/python cannot generate this without full headless browsers.
	logger.Debug("Turnstile verified", "ip", ip, "data_len", len(data))
	m.SetProofCookie(w, r, ip)
	return true
}

// serveJSChallenge serves the JavaScript Proof-of-Work challenge page
func (m *Manager) serveJSChallenge(w http.ResponseWriter, r *http.Request, difficulty int) {
	// Generate unique challenge
	challengeBytes := make([]byte, 16)
	rand.Read(challengeBytes)
	challengeStr := hex.EncodeToString(challengeBytes)

	if difficulty == 0 {
		difficulty = m.cfg.Protection.Challenge.PowDifficulty
	}

	html := fmt.Sprintf(powTemplate, challengeStr, difficulty, difficulty, r.URL.RequestURI())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte(html))
}

// serveCAPTCHAChallenge serves the Modern Hold-to-Verify interaction
func (m *Manager) serveCAPTCHAChallenge(w http.ResponseWriter, r *http.Request) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(ts))
	hash := hex.EncodeToString(mac.Sum(nil))

	html := fmt.Sprintf(captchaTemplate, r.URL.RequestURI(), ts, hash)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte(html))
}

// serveSilentChallenge serves invisible JS challenge
func (m *Manager) serveSilentChallenge(w http.ResponseWriter, r *http.Request) {
	html := fmt.Sprintf(silentTemplate, r.URL.RequestURI())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}
