package core

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"mango-waf/config"
)

func TestReverseProxyPassThrough(t *testing.T) {
	// 1. Start mock upstream backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from backend"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	// 2. Setup Shield config
	cfg := &config.Config{
		Domains: []config.DomainConfig{
			{
				Name: "example.com",
				Upstreams: []config.UpstreamConfig{
					{URL: backend.URL},
				},
			},
		},
	}
	cfg.Protection.Mode = "monitor"

	upstreams := NewUpstreamManager(cfg)

	shield := &Shield{
		cfg:       cfg,
		stats:     &Stats{Uptime: time.Now()},
		upstreams: upstreams,
	}

	pipeline := NewPipeline(shield)
	shield.pipeline = pipeline

	// 3. Send test request with realistic browser User-Agent
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Host = "example.com"
	req.URL.Host = backendURL.Host
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	rec := httptest.NewRecorder()

	shield.handleRequest(rec, req)

	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
	if string(body) != "hello from backend" {
		t.Errorf("expected 'hello from backend', got '%s'", string(body))
	}
}
