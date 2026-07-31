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
	"sync"
	"time"

	"mango-waf/config"
	"mango-waf/logger"
)

// Manager handles challenge serving and verification
type Manager struct {
	cfg             *config.Config
	secret          []byte
	verifiedIPs     sync.Map // ip -> time.Time (expiration)
	OnVerifySuccess func(ip string)
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
	secretStr := cfg.Protection.Challenge.CookieSecret
	if secretStr == "" || strings.HasPrefix(secretStr, "${") {
		secretStr = "mango-shield-enterprise-cookie-hmac-secret-v2-cluster-sync"
	}
	secret := []byte(secretStr)
	m := &Manager{
		cfg:    cfg,
		secret: secret,
	}
	go m.startEvictionWorker()
	return m
}

// UpdateConfig updates configuration pointer live
func (m *Manager) UpdateConfig(cfg *config.Config) {
	if cfg != nil {
		m.cfg = cfg
		m.ClearCache()
	}
}

// ClearCache clears the verified IPs cache
func (m *Manager) ClearCache() {
	m.verifiedIPs.Range(func(key, value any) bool {
		m.verifiedIPs.Delete(key)
		return true
	})
	logger.Info("Challenge manager verified IPs cache cleared due to config reload")
}

func (m *Manager) startEvictionWorker() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		now := time.Now()
		m.verifiedIPs.Range(func(key, value any) bool {
			if expTime, ok := value.(time.Time); ok && now.After(expTime) {
				m.verifiedIPs.Delete(key)
			}
			return true
		})
	}
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

// VerifyProof verifies a challenge proof cookie or active session cookie or in-memory IP cache
func (m *Manager) VerifyProof(r *http.Request, currentIP string) bool {
	// Fast-path 1: Check in-memory verified IP cache
	if expVal, ok := m.verifiedIPs.Load(currentIP); ok {
		if time.Now().Before(expVal.(time.Time)) {
			return true
		}
		m.verifiedIPs.Delete(currentIP)
	}

	cookie, err := r.Cookie("mango_proof")
	isProof := true
	if err != nil || cookie.Value == "" {
		cookie, err = r.Cookie("mango_session")
		isProof = false
		if err != nil || cookie.Value == "" {
			return false
		}
	}

	parts := strings.SplitN(cookie.Value, "|", 2)
	if len(parts) != 2 {
		return false
	}

	payload := parts[0]
	sig := parts[1]

	// Verify HMAC signature
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return false
	}

	// Check expiry (payload format: "ip_timestamp")
	lastIdx := strings.LastIndex(payload, "_")
	if lastIdx > 0 {
		tsStr := payload[lastIdx+1:]
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err == nil {
			issued := time.Unix(ts, 0)
			ttl := m.cfg.Protection.Challenge.CookieTTL
			if ttl <= 0 {
				ttl = 1 * time.Hour
			}
			if time.Since(issued) > ttl {
				return false // Expired
			}
		}
	} else {
		return false
	}

	// Cache IP verification in memory for 1 hour ONLY if they solved a challenge (presented mango_proof)
	if isProof {
		ttl := m.cfg.Protection.Challenge.CookieTTL
		if ttl <= 0 {
			ttl = 1 * time.Hour
		}
		m.verifiedIPs.Store(currentIP, time.Now().Add(ttl))
	}
	return true
}

// SetProofCookie sets a signed proof cookie and registers in-memory verified IP
func (m *Manager) SetProofCookie(w http.ResponseWriter, r *http.Request, ip string) {
	ttl := m.cfg.Protection.Challenge.CookieTTL
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	m.verifiedIPs.Store(ip, time.Now().Add(ttl))
	m.setCookieWithName(w, r, ip, "mango_proof")
}

// SetSessionCookie sets a signed seamless session cookie for active visitors
func (m *Manager) SetSessionCookie(w http.ResponseWriter, r *http.Request, ip string) {
	// DO NOT store IP in verifiedIPs for seamless session cookies, only trust the cookie.
	m.setCookieWithName(w, r, ip, "mango_session")
}

func (m *Manager) setCookieWithName(w http.ResponseWriter, _ *http.Request, ip string, name string) {
	payload := fmt.Sprintf("%s_%d", ip, time.Now().Unix())

	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	cookie := &http.Cookie{
		Name:     name,
		Value:    payload + "|" + sig,
		Path:     "/",
		MaxAge:   int(m.cfg.Protection.Challenge.CookieTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false, // Allow HTTP and HTTPS
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
		logger.Debug("PoW missing nonce or challenge", "nonce", nonce, "challenge", challenge)
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
		logger.Debug("PoW hash prefix mismatch", "hash", hashHex, "expected_prefix", prefix)
		return false
	}

	logger.Debug("PoW verified", "ip", ip, "difficulty", diffInt)
	m.SetProofCookie(w, r, ip)
	if m.OnVerifySuccess != nil {
		m.OnVerifySuccess(ip)
	}
	return true
}

// verifyTurnstile verifies the Modern Hold-to-Verify interaction
func (m *Manager) verifyTurnstile(w http.ResponseWriter, r *http.Request, ip string) bool {
	tsStr := r.FormValue("t_id")
	hash := r.FormValue("t_hash")
	data := r.FormValue("t_data")

	if tsStr == "" || hash == "" || data == "" {
		logger.Debug("Turnstile missing fields", "ip", ip)
		return false
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	diff := time.Now().Unix() - ts
	if err != nil || diff < -10 || diff > 300 { // 5 minutes expiry, clock skew tolerance 10s
		logger.Debug("Turnstile expired or invalid timestamp", "ip", ip)
		return false
	}

	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(tsStr))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(hash), []byte(expected)) {
		logger.Debug("Turnstile hash mismatch", "ip", ip)
		return false
	}

	// The 'data' payload contains mouse/touch events tracked by the browser.
	// Simple bots scaling curl/python cannot generate this without full headless browsers.
	logger.Debug("Turnstile verified", "ip", ip, "data_len", len(data))
	m.SetProofCookie(w, r, ip)
	if m.OnVerifySuccess != nil {
		m.OnVerifySuccess(ip)
	}
	return true
}

// generateRayID returns a 16-character hexadecimal Ray ID
func generateRayID(r *http.Request) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d-%s", r.RemoteAddr, time.Now().UnixNano(), r.URL.Path)))
	return hex.EncodeToString(h[:])[:16]
}

// serveJSChallenge serves the JavaScript Proof-of-Work challenge page
func (m *Manager) serveJSChallenge(w http.ResponseWriter, r *http.Request, difficulty int) {
	challengeBytes := make([]byte, 16)
	rand.Read(challengeBytes)
	challengeStr := hex.EncodeToString(challengeBytes)

	if difficulty == 0 {
		difficulty = m.cfg.Protection.Challenge.PowDifficulty
	}

	rayID := generateRayID(r)
	clientIP := r.RemoteAddr
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		clientIP = cfip
	} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = strings.TrimSpace(strings.Split(xff, ",")[0])
	}

	html := fmt.Sprintf(powTemplate, r.Host, clientIP, rayID, challengeStr, difficulty, difficulty, r.URL.RequestURI())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(html))
}

// serveCAPTCHAChallenge serves the Modern Hold-to-Verify interaction
func (m *Manager) serveCAPTCHAChallenge(w http.ResponseWriter, r *http.Request) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(ts))
	hash := hex.EncodeToString(mac.Sum(nil))

	rayID := generateRayID(r)
	clientIP := r.RemoteAddr
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		clientIP = cfip
	} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = strings.TrimSpace(strings.Split(xff, ",")[0])
	}

	html := fmt.Sprintf(captchaTemplate, r.Host, r.URL.RequestURI(), ts, hash, clientIP, rayID)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(html))
}

// serveSilentChallenge serves invisible JS challenge
func (m *Manager) serveSilentChallenge(w http.ResponseWriter, r *http.Request) {
	html := fmt.Sprintf(silentTemplate, r.URL.RequestURI())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// ServeBlockPage serves the commercial WAF HTTP 403 Forbidden page
func (m *Manager) ServeBlockPage(w http.ResponseWriter, r *http.Request, clientIP, ruleID, reason string) {
	rayID := generateRayID(r)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	ruleInfo := ruleID
	if reason != "" {
		ruleInfo = fmt.Sprintf("%s (%s)", ruleID, reason)
	}

	html := fmt.Sprintf(blockTemplate, r.Host, clientIP, rayID, ruleInfo, ts)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Mango-Shield", "blocked")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(html))
}

// ServeRateLimitPage serves the commercial HTTP 403 Forbidden page (replaces 429 to prevent Cloudflare Error 1200)
func (m *Manager) ServeRateLimitPage(w http.ResponseWriter, r *http.Request, clientIP string, retryAfterSeconds int) {
	rayID := generateRayID(r)
	if retryAfterSeconds <= 0 {
		retryAfterSeconds = 10
	}

	html := fmt.Sprintf(rateLimitTemplate, r.Host, retryAfterSeconds, clientIP, rayID, retryAfterSeconds)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	w.Header().Set("X-Mango-Shield", "rate-limited")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(html))
}

// ServeAccessDeniedPage serves the commercial HTTP 401/403 Security Policy page
func (m *Manager) ServeAccessDeniedPage(w http.ResponseWriter, r *http.Request, clientIP, policy string) {
	rayID := generateRayID(r)
	if policy == "" {
		policy = "Unauthorized Client Request"
	}

	html := fmt.Sprintf(accessDeniedTemplate, r.Host, policy, clientIP, rayID)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Mango-Shield", "denied")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(html))
}
