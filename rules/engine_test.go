package rules

import (
	"net/http"
	"testing"

	"mango-waf/config"
)

func BenchmarkWAFInspectClean(b *testing.B) {
	cfg := &config.Config{
		WAF: config.WAFConfig{
			Enabled:       true,
			ParanoiaLevel: 1,
		},
	}
	engine := NewEngine(cfg)

	req, _ := http.NewRequest("GET", "http://example.com/api/v1/users?page=2&limit=20", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res := engine.Inspect(req)
		if res.Blocked {
			b.Fatal("Expected clean request to pass")
		}
	}
}

func BenchmarkWAFInspectMaliciousSQLi(b *testing.B) {
	cfg := &config.Config{
		WAF: config.WAFConfig{
			Enabled:       true,
			ParanoiaLevel: 1,
		},
	}
	engine := NewEngine(cfg)

	req, _ := http.NewRequest("GET", "http://example.com/search?q=1%27%20OR%201=1--%20", nil)
	req.Header.Set("User-Agent", "sqlmap/1.5.2#stable (http://sqlmap.org)")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res := engine.Inspect(req)
		if !res.Blocked {
			b.Fatal("Expected SQLi attack to be blocked")
		}
	}
}

func BenchmarkWAFInspectPathTraversal(b *testing.B) {
	cfg := &config.Config{
		WAF: config.WAFConfig{
			Enabled:       true,
			ParanoiaLevel: 1,
		},
	}
	engine := NewEngine(cfg)

	req, _ := http.NewRequest("GET", "http://example.com/static/../../../../etc/passwd", nil)
	req.Header.Set("User-Agent", "curl/7.68.0")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res := engine.Inspect(req)
		if !res.Blocked {
			b.Fatal("Expected Path Traversal attack to be blocked")
		}
	}
}
