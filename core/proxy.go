package core

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"mango-waf/config"
	"mango-waf/logger"
)

var sharedTransport = &http.Transport{
	DialContext: (&net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 60 * time.Second,
	}).DialContext,
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
	MaxIdleConns:          1000,
	MaxIdleConnsPerHost:   200, // Safe pool size for 2-4GB VPS nodes without FD exhaustion
	MaxConnsPerHost:       0,   // 0 = unlimited per host so verified requests never queue
	IdleConnTimeout:       30 * time.Second,
	ResponseHeaderTimeout: 5 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ForceAttemptHTTP2:     true,
	DisableKeepAlives:     false,
	DisableCompression:    false, // Preserves CDN cache & HTTP Accept-Encoding negotiation semantics
	WriteBufferSize:       64 * 1024,
	ReadBufferSize:        64 * 1024,
}

var (
	target8080Host string
	target8080Once sync.Once
)

func get8080TargetHost() string {
	target8080Once.Do(func() {
		if _, err := net.LookupHost("mango-test-site"); err == nil {
			target8080Host = "mango-test-site:8080"
		} else {
			target8080Host = "127.0.0.1:8080"
		}
	})
	return target8080Host
}

func (s *Shield) getTransport() *http.Transport {
	s.transportOnce.Do(func() {
		if s.cfg == nil {
			s.configuredTransport = sharedTransport
			return
		}
		pCfg := s.cfg.Proxy
		maxIdle := pCfg.MaxIdleConns
		if maxIdle <= 0 {
			maxIdle = 1000
		}
		maxIdleHost := pCfg.MaxIdleConnsPerHost
		if maxIdleHost <= 0 {
			maxIdleHost = 200
		}
		idleTimeout := pCfg.IdleConnTimeout
		if idleTimeout <= 0 {
			idleTimeout = 30 * time.Second
		}
		respTimeout := pCfg.ResponseTimeout
		if respTimeout <= 0 {
			respTimeout = 5 * time.Second
		}
		connTimeout := pCfg.ConnectTimeout
		if connTimeout <= 0 {
			connTimeout = 3 * time.Second
		}
		bufSize := pCfg.BufferSizeKB
		if bufSize <= 0 {
			bufSize = 64
		}

		s.configuredTransport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   connTimeout,
				KeepAlive: 60 * time.Second,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:          maxIdle,
			MaxIdleConnsPerHost:   maxIdleHost,
			MaxConnsPerHost:       pCfg.MaxConnsPerHost,
			IdleConnTimeout:       idleTimeout,
			ResponseHeaderTimeout: respTimeout,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			DisableKeepAlives:     !pCfg.KeepAlive,
			DisableCompression:    pCfg.DisableCompression,
			WriteBufferSize:       bufSize * 1024,
			ReadBufferSize:        bufSize * 1024,
		}
	})
	if s.configuredTransport != nil {
		return s.configuredTransport
	}
	return sharedTransport
}

var proxyCache sync.Map // backend URL (string) -> *httputil.ReverseProxy

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
	v, ok := proxyCache.Load(backend)
	var proxy *httputil.ReverseProxy
	if ok {
		proxy = v.(*httputil.ReverseProxy)
	} else {
		target, err := url.Parse(backend)
		if err != nil {
			logger.Error("Invalid backend URL", "backend", backend, "error", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}

		// Zero-latency cached target host resolution for port 8080
		if strings.Contains(target.Host, "8080") {
			target.Host = get8080TargetHost()
		}

		proxy = httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = s.getTransport()
		proxy.BufferPool = sharedProxyBufferPool

		// Configure Director to forward Host headers and protocol
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Host = req.Header.Get("X-Forwarded-Host")
		}

		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("Proxy error", "backend", backend, "error", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}

		// Intercept Response to Store in Cache & Rewrite Location redirects
		proxy.ModifyResponse = func(resp *http.Response) error {
			// Rewrite backend IP in Location header to original Host domain
			if loc := resp.Header.Get("Location"); loc != "" {
				if target.Host != "" && strings.Contains(loc, target.Host) {
					origHost := resp.Request.Header.Get("X-Forwarded-Host")
					if origHost == "" {
						origHost = resp.Request.Host
					}
					resp.Header.Set("Location", strings.ReplaceAll(loc, target.Host, origHost))
				}
			}

			cdn := GetCDN()
			if cdn != nil && s.cfg.CDN.Enabled {
				cacheBypass := resp.Request.Header.Get("X-Mango-Cache-Bypass") == "true"
				cacheKey := resp.Request.Header.Get("X-Mango-Cache-Key")
				if cacheBypass {
					resp.Header.Set("X-Mango-Cache", "BYPASS")
				} else if cacheKey != "" {
					resp.Header.Set("X-Mango-Cache", "MISS")
					err := cdn.Store(cacheKey, resp.Request, resp)
					if err != nil {
						logger.Warn("Failed to cache response", "url", resp.Request.URL.Path, "error", err)
					}
				}
			}
			return nil
		}

		proxyCache.Store(backend, proxy)
	}

	// === ENTERPRISE CDN CACHING LAYER ===
	cdn := GetCDN()
	var cacheKey string
	var cacheBypass bool
	if cdn != nil && s.cfg.CDN.Enabled {
		cacheBypass = cdn.ShouldBypass(r)
		if !cacheBypass {
			cacheKey = cdn.GenerateCacheKey(r)
			if cached, found := cdn.Get(cacheKey); found && len(cached.Body) > 0 {
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

	// Set forwarding headers with real client IP
	r.Header.Set("X-Forwarded-Host", r.Host)
	if r.TLS != nil {
		r.Header.Set("X-Forwarded-Proto", "https")
	} else {
		r.Header.Set("X-Forwarded-Proto", "http")
	}

	if cacheBypass {
		r.Header.Set("X-Mango-Cache-Bypass", "true")
	}
	if cacheKey != "" {
		r.Header.Set("X-Mango-Cache-Key", cacheKey)
	}

	clientIP := s.extractIP(r)
	r.Header.Set("X-Real-IP", clientIP)
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		r.Header.Set("CF-Connecting-IP", cfIP)
		r.Header.Set("X-Forwarded-For", cfIP)
	} else {
		r.Header.Set("X-Forwarded-For", clientIP)
	}
	r.Header.Set("X-Mango-Shield", "v3.0")

	proxy.ServeHTTP(w, r)
}

// isWebSocket checks if the request is a WebSocket upgrade
func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

var wsBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

// bufferPool implements httputil.BufferPool
type bufferPool struct {
	pool sync.Pool
}

func (bp *bufferPool) Get() []byte {
	return bp.pool.Get().([]byte)
}

func (bp *bufferPool) Put(b []byte) {
	bp.pool.Put(b)
}

var sharedProxyBufferPool = &bufferPool{
	pool: sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024) // 32KB default reverse proxy buffer
		},
	},
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

	// Bidirectional copy with pooled buffers
	errCh := make(chan error, 2)
	go func() {
		buf := wsBufferPool.Get().([]byte)
		defer wsBufferPool.Put(buf)
		_, err := io.CopyBuffer(backendConn, clientConn, buf)
		errCh <- err
	}()
	go func() {
		buf := wsBufferPool.Get().([]byte)
		defer wsBufferPool.Put(buf)
		_, err := io.CopyBuffer(clientConn, backendConn, buf)
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
