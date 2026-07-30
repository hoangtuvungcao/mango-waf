package core

import (
	"runtime"
	"sync/atomic"
	"testing"

	"mango-waf/config"
)

type StatsNoPadding struct {
	TotalRequests   int64
	BlockedRequests int64
	PassedRequests  int64
	CurrentRPS      int64
}

func BenchmarkStatsAtomicNoPadding(b *testing.B) {
	var stats StatsNoPadding
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			atomic.AddInt64(&stats.TotalRequests, 1)
			atomic.AddInt64(&stats.BlockedRequests, 1)
			atomic.AddInt64(&stats.PassedRequests, 1)
			atomic.AddInt64(&stats.CurrentRPS, 1)
		}
	})
}

func BenchmarkStatsAtomicWithPadding(b *testing.B) {
	var stats Stats
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			atomic.AddInt64(&stats.TotalRequests, 1)
			atomic.AddInt64(&stats.BlockedRequests, 1)
			atomic.AddInt64(&stats.PassedRequests, 1)
			atomic.AddInt64(&stats.CurrentRPS, 1)
		}
	})
}

func TestHotReload1000Times(t *testing.T) {
	cfg := &config.Config{
		Protection: config.ProtectionConfig{Mode: "auto"},
		Domains: []config.DomainConfig{
			{Name: "example.com", Upstreams: []config.UpstreamConfig{{URL: "http://127.0.0.1:8080"}}},
		},
	}
	s := New(cfg)
	startGoroutines := runtime.NumGoroutine()

	for i := 0; i < 1000; i++ {
		newCfg := &config.Config{
			Protection: config.ProtectionConfig{Mode: "under_attack"},
			Domains: []config.DomainConfig{
				{Name: "example.com", Upstreams: []config.UpstreamConfig{{URL: "http://127.0.0.1:8080"}}},
			},
		}
		s.ReloadConfig(newCfg)
	}

	endGoroutines := runtime.NumGoroutine()
	if endGoroutines-startGoroutines > 10 {
		t.Fatalf("Goroutine leak detected during 1000 hot reloads: start=%d, end=%d", startGoroutines, endGoroutines)
	}
}
