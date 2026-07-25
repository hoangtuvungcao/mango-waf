package perf

import (
	"fmt"
	"testing"
)

func TestIPRateLimiterAllow(t *testing.T) {
	limiter := NewIPRateLimiter(10, 10)

	for i := 0; i < 10; i++ {
		if !limiter.Allow("1.2.3.4") {
			t.Errorf("request %d should be allowed", i)
		}
	}

	if limiter.Allow("1.2.3.4") {
		t.Errorf("11th request should be rate limited")
	}
}

func BenchmarkIPRateLimiterAllow(b *testing.B) {
	limiter := NewIPRateLimiter(1000000, 1000000)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := fmt.Sprintf("10.0.%d.%d", (i>>8)&0xFF, i&0xFF)
			_ = limiter.Allow(ip)
			i++
		}
	})
}
