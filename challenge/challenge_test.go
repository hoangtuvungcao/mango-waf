package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"mango-waf/config"
)

func TestVerifyPoW(t *testing.T) {
	cfg := &config.Config{}
	cfg.Protection.Challenge.PowDifficulty = 2
	cfg.Protection.Challenge.CookieSecret = "testsecret32byteslongstring12345"

	mgr := NewManager(cfg)

	challenge := "testchallenge"
	difficulty := 2
	prefix := strings.Repeat("0", difficulty)

	var nonce string
	for i := 0; i < 100000; i++ {
		n := fmt.Sprintf("%d", i)
		data := challenge + n
		hash := sha256.Sum256([]byte(data))
		hexHash := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hexHash, prefix) {
			nonce = n
			break
		}
	}

	if nonce == "" {
		t.Fatalf("failed to find valid nonce for test difficulty %d", difficulty)
	}

	form := url.Values{}
	form.Set("challenge", challenge)
	form.Set("nonce", nonce)
	form.Set("difficulty", strconv.Itoa(difficulty))

	req := httptest.NewRequest("POST", "/?challenge_type=pow", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	if !mgr.verifyPoW(rec, req, "127.0.0.1") {
		t.Errorf("verifyPoW failed for valid nonce %s", nonce)
	}
}

func TestVerifyTurnstileTimestampValidation(t *testing.T) {
	cfg := &config.Config{}
	cfg.Protection.Challenge.CookieSecret = "testsecret32byteslongstring12345"
	mgr := NewManager(cfg)

	futureTS := time.Now().Unix() + 10000
	tsStr := strconv.FormatInt(futureTS, 10)

	mac := hmac.New(sha256.New, []byte(cfg.Protection.Challenge.CookieSecret))
	mac.Write([]byte(tsStr))
	hash := hex.EncodeToString(mac.Sum(nil))

	form := url.Values{}
	form.Set("t_id", tsStr)
	form.Set("t_hash", hash)
	form.Set("t_data", "test_mouse_data")

	req := httptest.NewRequest("POST", "/?challenge_type=turnstile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	if mgr.verifyTurnstile(rec, req, "127.0.0.1") {
		t.Errorf("verifyTurnstile should reject future timestamp %d", futureTS)
	}
}

func TestServeRateLimitPage(t *testing.T) {
	cfg := &config.Config{}
	mgr := NewManager(cfg)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	mgr.ServeRateLimitPage(rec, req, "198.51.100.42", 10)

	if rec.Code != 429 {
		t.Errorf("expected status code 429 Too Many Requests, got %d", rec.Code)
	}

	if rec.Header().Get("Retry-After") != "10" {
		t.Errorf("expected Retry-After header '10', got '%s'", rec.Header().Get("Retry-After"))
	}

	if rec.Header().Get("X-Mango-Shield") != "rate-limited" {
		t.Errorf("expected X-Mango-Shield header 'rate-limited', got '%s'", rec.Header().Get("X-Mango-Shield"))
	}

	if !strings.Contains(rec.Body.String(), "429 Too Many Requests") {
		t.Errorf("expected body to contain '429 Too Many Requests'")
	}
}
