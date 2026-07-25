package core

import (
	"net/http/httptest"
	"testing"

	"mango-waf/config"
)

func TestExtractIPTrustedProxy(t *testing.T) {
	cfg := &config.Config{}
	cfg.Protection.TrustedProxies = []string{"10.0.0.1", "172.16.0.0/12"}

	s := &Shield{
		cfg: cfg,
	}

	// 1. Untrusted peer sending XFF header -> Should ignore XFF and return RemoteAddr
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "192.168.1.50:12345"
	req1.Header.Set("X-Forwarded-For", "8.8.8.8")

	if ip := s.extractIP(req1); ip != "192.168.1.50" {
		t.Errorf("expected 192.168.1.50 for untrusted peer, got %s", ip)
	}

	// 2. Trusted peer sending XFF header -> Should trust XFF header
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "10.0.0.1:54321"
	req2.Header.Set("X-Forwarded-For", "203.0.113.195, 10.0.0.1")

	if ip := s.extractIP(req2); ip != "203.0.113.195" {
		t.Errorf("expected 203.0.113.195 for trusted peer, got %s", ip)
	}
}
