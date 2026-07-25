package rules

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"mango-waf/config"
)

func TestOWASPRuleEngine(t *testing.T) {
	cfg := &config.Config{}
	cfg.WAF.Enabled = true
	cfg.WAF.ParanoiaLevel = 2

	engine := NewEngine(cfg)

	// Test SQL Injection rule 942100 with URL-encoded query parameter
	req := httptest.NewRequest("GET", "/search?q=%27%20OR%201=1--", nil)
	res := engine.Inspect(req)
	if !res.Blocked {
		t.Errorf("expected WAF to match SQLi payload, but passed")
	}

	// Test clean request
	cleanReq := httptest.NewRequest("GET", "/search?q=mango", nil)
	cleanRes := engine.Inspect(cleanReq)
	if cleanRes.Blocked {
		t.Errorf("expected WAF to pass clean request, but blocked")
	}
}

func BenchmarkEngineInspect(b *testing.B) {
	cfg := &config.Config{}
	cfg.WAF.Enabled = true
	cfg.WAF.ParanoiaLevel = 2
	engine := NewEngine(cfg)

	req := httptest.NewRequest("GET", "/index.php?user=admin&id=100", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = engine.Inspect(req)
	}
}

func FuzzOWASPInspect(f *testing.F) {
	cfg := &config.Config{}
	cfg.WAF.Enabled = true
	cfg.WAF.ParanoiaLevel = 2
	engine := NewEngine(cfg)

	f.Add("select*from users")
	f.Add("../../../../etc/passwd")
	f.Add("<script>alert(1)</script>")

	f.Fuzz(func(t *testing.T, payload string) {
		req, err := http.NewRequest("GET", "/test?data="+url.QueryEscape(payload), nil)
		if err != nil {
			return
		}
		_ = engine.Inspect(req)
	})
}
