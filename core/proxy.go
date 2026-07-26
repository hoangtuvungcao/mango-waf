package core

import (
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"mango-waf/config"
	"mango-waf/logger"
)

var sharedTransport = &http.Transport{
	DialContext: (&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 60 * time.Second,
	}).DialContext,
	MaxIdleConns:          50000,
	MaxIdleConnsPerHost:   20000,
	MaxConnsPerHost:       50000,
	IdleConnTimeout:       120 * time.Second,
	ResponseHeaderTimeout: 10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ForceAttemptHTTP2:     true,
	DisableKeepAlives:     false,
	WriteBufferSize:       64 * 1024,
	ReadBufferSize:        64 * 1024,
}

// proxyRequest forwards the request to the backend
func (s *Shield) proxyRequest(w http.ResponseWriter, r *http.Request) {
	// Find next available upstream backend for this domain
	backend, err := s.upstreams.GetNext(r.Host)
	if err != nil || backend == "" {
		logger.Error("No upstream backend available", "host", r.Host, "error", err)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// Handle WebSocket upgrade
	if s.cfg.Proxy.WebSocket && isWebSocket(r) {
		s.proxyWebSocket(w, r, backend)
		return
	}

	// Regular HTTP reverse proxy
	target, err := url.Parse(backend)
	if err != nil {
		logger.Error("Invalid backend URL", "backend", backend, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// === ENTERPRISE CDN CACHING LAYER ===
	cdn := GetCDN()
	var cacheKey string
	var cacheBypass bool
	if cdn != nil && s.cfg.CDN.Enabled {
		cacheBypass = cdn.ShouldBypass(r)
		if !cacheBypass {
			cacheKey = cdn.GenerateCacheKey(r)
			if cached, found := cdn.Get(cacheKey); found {
				// CACHE HIT - Serve directly from RAM
				for k, v := range cached.Headers {
					for _, val := range v {
						w.Header().Add(k, val)
					}
				}
				w.Header().Set("X-Mango-Cache", "HIT")
				w.WriteHeader(cached.StatusCode)
				w.Write(cached.Body)
				return
			}
		} else {
			cdn.RecordBypass()
		}
	}
	// === END CACHING LAYER ===

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = sharedTransport

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("Proxy error", "backend", backend, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	// Intercept Response to Store in Cache
	proxy.ModifyResponse = func(resp *http.Response) error {
		if cdn != nil && s.cfg.CDN.Enabled {
			if cacheBypass {
				resp.Header.Set("X-Mango-Cache", "BYPASS")
			} else if cacheKey != "" {
				resp.Header.Set("X-Mango-Cache", "MISS")
				// Store handles Cache-Control checks and restores body stream
				err := cdn.Store(cacheKey, r, resp)
				if err != nil {
					logger.Warn("Failed to cache response", "url", r.URL.Path, "error", err)
				}
			}
		}
		return nil
	}

	// Set forwarding headers with real client IP
	clientIP := s.extractIP(r)
	r.Header.Set("X-Real-IP", clientIP)
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		r.Header.Set("CF-Connecting-IP", cfIP)
		r.Header.Set("X-Forwarded-For", cfIP)
	} else {
		r.Header.Set("X-Forwarded-For", clientIP)
	}
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Mango-Shield", "v2.0")

	proxy.ServeHTTP(w, r)
}

// isWebSocket checks if the request is a WebSocket upgrade
func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// proxyWebSocket handles WebSocket proxy
func (s *Shield) proxyWebSocket(w http.ResponseWriter, r *http.Request, backend string) {
	// Hijack the connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		logger.Error("WebSocket hijack failed", "error", err)
		return
	}
	defer clientConn.Close()

	// Connect to backend
	backendConn, err := net.DialTimeout("tcp", backend, s.cfg.Proxy.ConnectTimeout)
	if err != nil {
		logger.Error("WebSocket backend connection failed", "backend", backend, "error", err)
		return
	}
	defer backendConn.Close()

	// Forward the original request
	if err := r.Write(backendConn); err != nil {
		logger.Error("WebSocket forward failed", "error", err)
		return
	}

	// Bidirectional copy
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(backendConn, clientConn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, backendConn)
		errCh <- err
	}()

	<-errCh
}

// GetDomainConfig returns the domain config for a host
func GetDomainConfig(cfg *config.Config, host string) *config.DomainConfig {
	host = strings.ToLower(host)
	for i, d := range cfg.Domains {
		if strings.Contains(host, strings.ToLower(d.Name)) {
			return &cfg.Domains[i]
		}
	}
	return nil
}
