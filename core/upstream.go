package core

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"mango-waf/config"
	"mango-waf/logger"
)

// UpstreamBackend represents a single backend server
type UpstreamBackend struct {
	URL      string
	Weight   int
	IsAlive  bool
	Failures int
}

// UpstreamPool handles load balancing for a specific domain
type UpstreamPool struct {
	Backends []*UpstreamBackend
	Mutex    sync.RWMutex
	Current  int // For Round-Robin
}

// UpstreamManager manages all upstreams for all domains
type UpstreamManager struct {
	pools map[string]*UpstreamPool
	mutex sync.RWMutex
	stop  chan struct{}
}

// NewUpstreamManager creates and initializes the upstream load balancer
func NewUpstreamManager(cfg *config.Config) *UpstreamManager {
	um := &UpstreamManager{
		pools: make(map[string]*UpstreamPool),
		stop:  make(chan struct{}),
	}

	if cfg != nil {
		um.UpdateDomains(cfg.Domains)
	}

	// Start background health checks
	go um.healthCheckLoop()

	return um
}

// UpdateDomains dynamically updates the upstream pools for all domains
func (um *UpstreamManager) UpdateDomains(domains []config.DomainConfig) {
	if um == nil {
		return
	}
	um.mutex.Lock()
	defer um.mutex.Unlock()

	newPools := make(map[string]*UpstreamPool)
	for _, d := range domains {
		if d.Name == "" {
			continue
		}
		domainName := strings.ToLower(d.Name)
		pool := &UpstreamPool{
			Backends: make([]*UpstreamBackend, 0, len(d.Upstreams)),
		}

		for _, u := range d.Upstreams {
			weight := u.Weight
			if weight <= 0 {
				weight = 1
			}
			pool.Backends = append(pool.Backends, &UpstreamBackend{
				URL:     u.URL,
				Weight:  weight,
				IsAlive: true,
			})
		}
		newPools[domainName] = pool
	}
	um.pools = newPools
	logger.Info("Upstream pools updated dynamically", "domains_count", len(newPools))
}

// GetNext returns the next available backend URL for a given host
func (um *UpstreamManager) GetNext(host string) (string, error) {
	host = strings.ToLower(host)
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}

	um.mutex.RLock()
	var pool *UpstreamPool
	if p, ok := um.pools[host]; ok {
		pool = p
	} else {
		for dName, p := range um.pools {
			if strings.HasSuffix(host, "."+dName) || strings.Contains(host, dName) || strings.Contains(dName, host) {
				pool = p
				break
			}
		}
		if pool == nil && len(um.pools) == 1 {
			for _, p := range um.pools {
				pool = p
				break
			}
		}
	}
	um.mutex.RUnlock()

	if pool == nil || len(pool.Backends) == 0 {
		return "", fmt.Errorf("no upstream configured for host %s", host)
	}

	pool.Mutex.Lock()
	defer pool.Mutex.Unlock()

	// Simple Round-Robin finding the next alive backend
	startIdx := pool.Current
	for i := 0; i < len(pool.Backends); i++ {
		idx := (startIdx + i) % len(pool.Backends)
		backend := pool.Backends[idx]
		if backend.IsAlive {
			// Advance the pointer
			pool.Current = (idx + 1) % len(pool.Backends)
			return backend.URL, nil
		}
	}

	// FALLBACK: If health checker marked backends un-alive during startup, fallback to configured upstream
	if len(pool.Backends) > 0 {
		backend := pool.Backends[startIdx%len(pool.Backends)]
		pool.Current = (startIdx + 1) % len(pool.Backends)
		return backend.URL, nil
	}

	return "", errors.New("no upstream is alive")
}

// Close stops the health checking loop
func (um *UpstreamManager) Close() {
	close(um.stop)
}

// healthCheckLoop periodically checks all backends to see if they are alive
func (um *UpstreamManager) healthCheckLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: tr,
	}

	for {
		select {
		case <-ticker.C:
			um.runHealthChecks(client)
		case <-um.stop:
			return
		}
	}
}

func (um *UpstreamManager) runHealthChecks(client *http.Client) {
	um.mutex.RLock()
	pools := make([]*UpstreamPool, 0, len(um.pools))
	for _, p := range um.pools {
		pools = append(pools, p)
	}
	um.mutex.RUnlock()

	for _, pool := range pools {
		pool.Mutex.Lock()
		backends := make([]*UpstreamBackend, len(pool.Backends))
		copy(backends, pool.Backends)
		pool.Mutex.Unlock()

		for _, backend := range backends {
			targetUrl, err := url.Parse(backend.URL)
			if err != nil {
				continue
			}

			// Try GET request outside of mutex lock
			resp, err := client.Get(targetUrl.Scheme + "://" + targetUrl.Host)
			isAlive := err == nil
			if resp != nil {
				resp.Body.Close()
				if resp.StatusCode >= 500 && resp.StatusCode != 503 {
					if resp.StatusCode == 500 || resp.StatusCode == 502 || resp.StatusCode == 504 {
						isAlive = false
					}
				}
			}

			pool.Mutex.Lock()
			if isAlive {
				if !backend.IsAlive {
					logger.Info("Upstream backend recovered", "url", backend.URL)
				}
				backend.IsAlive = true
				backend.Failures = 0
			} else {
				backend.Failures++
				if backend.IsAlive && backend.Failures >= 3 {
					logger.Warn("Upstream backend is down after 3 failures", "url", backend.URL)
					backend.IsAlive = false
				}
			}
			pool.Mutex.Unlock()
		}
	}
}
