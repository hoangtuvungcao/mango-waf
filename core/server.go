package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sys/unix"
	"mango-waf/challenge"
	"mango-waf/cluster"
	"mango-waf/config"
	"mango-waf/detection"
	"mango-waf/fingerprint"
	"mango-waf/intelligence"
	"mango-waf/logger"
	"mango-waf/perf"
	"mango-waf/rules"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Shield is the main Mango Shield server
type Shield struct {
	cfg                 *config.Config
	pipeline            *Pipeline
	stats               *Stats
	httpServer          *http.Server
	redirectServer      *http.Server
	listener            net.Listener
	fpStore             *fingerprint.FingerprintStore
	challMgr            *challenge.Manager
	intel               *intelligence.Intel
	detEngine           *detection.Engine
	behavior            *detection.BehaviorAnalyzer
	botClass            *detection.BotClassifier
	attackDet           *detection.AttackDetector
	adaptive            *detection.AdaptiveLearner
	wafEngine           *rules.Engine
	rateLimiter         *perf.IPRateLimiter
	degrader            *perf.GracefulDegrader
	validator           *perf.RequestValidator
	upstreams           *UpstreamManager
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	domainReqs          sync.Map // domain -> *DomainCounter
	domainLastReqs      sync.Map // domain -> int64
	domainRPS           sync.Map // domain -> int64
	domainUnderAttack   sync.Map // domain -> bool
	domainAttackStart   sync.Map // domain -> time.Time
	domainNormalCount   sync.Map // domain -> int
	configuredTransport *http.Transport
	transportOnce       sync.Once
}

// Stats holds real-time statistics
var fastUnixSec int64

func init() {
	atomic.StoreInt64(&fastUnixSec, time.Now().Unix())
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		for t := range ticker.C {
			atomic.StoreInt64(&fastUnixSec, t.Unix())
		}
	}()
}

// GetFastCurrentUnixSec returns 0-syscall cached Unix timestamp
func GetFastCurrentUnixSec() int64 {
	return atomic.LoadInt64(&fastUnixSec)
}

// Stats tracks real-time traffic & security statistics with 64-byte Cache Line Alignment (Anti-False-Sharing)
type Stats struct {
	TotalRequests   int64
	_               [56]byte
	BlockedRequests int64
	_               [56]byte
	ChallengedReqs  int64
	_               [56]byte
	PassedRequests  int64
	_               [56]byte
	ActiveConns     int64
	_               [56]byte
	CurrentRPS      int64
	_               [56]byte
	PeakRPS         int64
	_               [56]byte
	BannedIPs       int64
	WhitelistedIPs  int64
	AttacksDetected int64
	Uptime          time.Time
	IsUnderAttack   bool
	CurrentStage    int32
	AttackStartTime time.Time
}

// DomainCounter is a cache-line padded counter for high-throughput tracking
type DomainCounter struct {
	Reqs        int64
	ActiveConns int64
	_           [48]byte
}

// New creates a new Shield instance
func New(cfg *config.Config) *Shield {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Shield{
		cfg:       cfg,
		stats:     &Stats{Uptime: time.Now()},
		fpStore:   fingerprint.NewFingerprintStore(),
		challMgr:  challenge.NewManager(cfg),
		validator: perf.NewRequestValidator(),
		ctx:       ctx,
		cancel:    cancel,
	}
	s.pipeline = NewPipeline(s)
	s.challMgr.OnVerifySuccess = func(ip string) {
		s.pipeline.UnbanIP(ip)
	}
	GetLogStore().SetRPSPointer(&s.stats.CurrentRPS)
	return s
}

// SetIntel sets the intelligence engine
func (s *Shield) SetIntel(intel *intelligence.Intel) {
	s.intel = intel
	s.pipeline.intel = intel
}

// SetDetectionEngine sets the detection engine
func (s *Shield) SetDetectionEngine(e *detection.Engine) {
	s.detEngine = e
	s.pipeline.detEngine = e
}

// SetBehaviorAnalyzer sets the behavior analyzer
func (s *Shield) SetBehaviorAnalyzer(ba *detection.BehaviorAnalyzer) {
	s.behavior = ba
	s.pipeline.behavior = ba
}

// SetBotClassifier sets the bot classifier
func (s *Shield) SetBotClassifier(bc *detection.BotClassifier) {
	s.botClass = bc
	s.pipeline.botClass = bc
}

// SetAttackDetector sets the attack detector
func (s *Shield) SetAttackDetector(ad *detection.AttackDetector) {
	s.attackDet = ad
	s.pipeline.attackDet = ad
}

// SetAdaptiveLearner sets the adaptive learner
func (s *Shield) SetAdaptiveLearner(al *detection.AdaptiveLearner) {
	s.adaptive = al
	s.pipeline.adaptive = al
}

// SetWAFEngine sets the WAF rules engine
func (s *Shield) SetWAFEngine(we *rules.Engine) {
	s.wafEngine = we
	s.pipeline.wafEngine = we
}

// SetRateLimiter sets the IP rate limiter
func (s *Shield) SetRateLimiter(rl *perf.IPRateLimiter) {
	s.rateLimiter = rl
	s.pipeline.rateLimiter = rl
}

// SetGracefulDegrader sets the graceful degrader
func (s *Shield) SetGracefulDegrader(gd *perf.GracefulDegrader) {
	s.degrader = gd
	s.pipeline.degrader = gd
}

// SetUpstreamManager sets the upstream manager
func (s *Shield) SetUpstreamManager(um *UpstreamManager) {
	s.upstreams = um
}

// GetPipeline returns the underlying pipeline
func (s *Shield) GetPipeline() *Pipeline {
	return s.pipeline
}

// UpdateUpstreams dynamically updates the upstream pools
func (s *Shield) UpdateUpstreams(domains []config.DomainConfig) {
	if s.upstreams != nil {
		s.upstreams.UpdateDomains(domains)
	}
}

// ReloadConfig applies live configuration updates instantly across all WAF protection modules
func (s *Shield) ReloadConfig(newCfg *config.Config) {
	if newCfg == nil {
		return
	}
	s.cfg = newCfg
	s.pipeline.cfg = newCfg

	// Recompute O(1) domain protection mode map live
	domainModeMap := make(map[string]string)
	for _, d := range newCfg.Domains {
		if d.ProtectionMode != "" {
			domainModeMap[strings.ToLower(d.Name)] = d.ProtectionMode
		}
	}
	s.pipeline.domainModeMap = domainModeMap

	// Update Upstream Pools live
	if s.upstreams != nil {
		s.upstreams.UpdateDomains(newCfg.Domains)
	}

	// Update WAF Rules Engine Paranoia Level live
	if s.wafEngine != nil {
		s.wafEngine.SetParanoiaLevel(newCfg.WAF.ParanoiaLevel)
	}

	// Update IP Rate Limiter RPS & Burst live
	if s.rateLimiter != nil {
		s.rateLimiter.SetRate(
			float64(newCfg.Protection.RateLimit.RequestsPerSecond),
			float64(newCfg.Protection.RateLimit.Burst),
		)
	}

	// Update Challenge Manager Config live
	if s.challMgr != nil {
		s.challMgr.UpdateConfig(newCfg)
	}

	// Update Intelligence Engine Config live
	if s.intel != nil {
		s.intel.UpdateConfig(newCfg)
	}

	// Update Alert Manager Config live
	if s.pipeline != nil && s.pipeline.alerts != nil {
		s.pipeline.alerts.UpdateConfig(newCfg)
	}

	logger.Info("WAF Security Policies & Configuration reloaded dynamically in real-time",
		"mode", newCfg.Protection.Mode,
		"paranoia", newCfg.WAF.ParanoiaLevel,
		"rps", newCfg.Protection.RateLimit.RequestsPerSecond,
		"burst", newCfg.Protection.RateLimit.Burst,
		"pow_difficulty", newCfg.Protection.Challenge.PowDifficulty,
		"block_datacenter", newCfg.Intelligence.ASN.BlockDatacenter,
		"domains", len(newCfg.Domains),
	)
}

// Start starts the Mango Shield server
func (s *Shield) Start() error {
	logger.Info("Mango Shield v2.0 starting",
		"listen", s.cfg.Server.Listen,
		"http_listen", s.cfg.Server.HTTPListen,
		"domains", len(s.cfg.Domains),
	)

	// Start background workers
	s.wg.Add(4)
	go s.rpsCounter()
	go s.attackDetector()
	go s.cleanupWorker()
	go s.adaptiveSampler()

	// Start HTTP redirect (if TLS enabled)
	if s.cfg.TLS.Enabled {
		go s.startHTTPRedirect()
	}

	// Build TLS config if enabled
	var tlsConfig *tls.Config
	if s.cfg.TLS.Enabled {
		certFile := s.cfg.TLS.CertFile
		if certFile == "" {
			certFile = "certs/server.crt"
		}
		keyFile := s.cfg.TLS.KeyFile
		if keyFile == "" {
			keyFile = "certs/server.key"
		}
		if err := ensureTLSCertificates(s.cfg, certFile, keyFile); err != nil {
			logger.Warn("Failed to ensure TLS certificates", "error", err)
		}
		var certs []tls.Certificate
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err == nil {
			certs = append(certs, cert)
		}

		// Dynamically load extra domain certs from certs/ directory (e.g. bacsycay.crt / bacsycay.key)
		files, _ := os.ReadDir("certs")
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".crt") && f.Name() != "server.crt" {
				base := strings.TrimSuffix(f.Name(), ".crt")
				kFile := filepath.Join("certs", base+".key")
				cFile := filepath.Join("certs", f.Name())
				if _, errK := os.Stat(kFile); errK == nil {
					if extraCert, errL := tls.LoadX509KeyPair(cFile, kFile); errL == nil {
						certs = append(certs, extraCert)
						logger.Info("Loaded extra TLS certificate", "cert", cFile)
					}
				}
			}
		}

		minVer := uint16(tls.VersionTLS12)
		if s.cfg.TLS.MinVersion == "1.3" {
			minVer = tls.VersionTLS13
		}
		certMap := make(map[string]*tls.Certificate)
		for i := range certs {
			c := &certs[i]
			x509Cert, errParse := x509.ParseCertificate(c.Certificate[0])
			if errParse == nil {
				if x509Cert.Subject.CommonName != "" {
					certMap[strings.ToLower(x509Cert.Subject.CommonName)] = c
				}
				for _, dnsName := range x509Cert.DNSNames {
					certMap[strings.ToLower(dnsName)] = c
				}
			}
		}

		tlsConfig = &tls.Config{
			Certificates:           certs,
			NextProtos:             []string{"h3", "h2", "http/1.1"},
			MinVersion:             minVer,
			SessionTicketsDisabled: false,
			ClientSessionCache:     tls.NewLRUClientSessionCache(10000),
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if hello == nil || hello.ServerName == "" {
					if len(certs) > 0 {
						return &certs[0], nil
					}
					return nil, nil
				}
				serverName := strings.ToLower(hello.ServerName)
				if cert, ok := certMap[serverName]; ok {
					return cert, nil
				}
				for name, cert := range certMap {
					if strings.HasPrefix(name, "*.") {
						suffix := name[1:]
						if strings.HasSuffix(serverName, suffix) {
							return cert, nil
						}
					}
				}
				if len(certs) > 0 {
					return &certs[0], nil
				}
				return nil, fmt.Errorf("no certificate available for server_name: %s", hello.ServerName)
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}

		// Setup TLS fingerprint interceptor
		if s.cfg.Fingerprint.JA3.Enabled || s.cfg.Fingerprint.JA4.Enabled {
			fingerprint.NewTLSInterceptor(nil, tlsConfig, s.fpStore)
			logger.Info("TLS fingerprinting enabled (JA3/JA4)")
		}
	}

	// Create main HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	// Wrap with security headers middleware
	var handler http.Handler = mux
	handler = perf.SecurityHeaders(handler)

	listenAddr := s.cfg.Server.Listen
	if !s.cfg.TLS.Enabled {
		listenAddr = s.cfg.Server.HTTPListen
	}

	// Start HTTP/3 QUIC Server if enabled
	if s.cfg.HTTP3.Enabled && s.cfg.TLS.Enabled && tlsConfig != nil {
		h3Port := s.cfg.HTTP3.Port
		if h3Port <= 0 {
			h3Port = 443
		}
		h3Server := &http3.Server{
			Addr:      fmt.Sprintf(":%d", h3Port),
			Handler:   handler,
			TLSConfig: tlsConfig,
		}
		go func() {
			logger.Info("Starting HTTP/3 QUIC Server", "port", h3Port)
			if err := h3Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Warn("HTTP/3 QUIC Server error", "error", err)
			}
		}()
	}

	s.httpServer = &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       s.cfg.Server.ReadTimeout,
		WriteTimeout:      s.cfg.Server.WriteTimeout,
		IdleTimeout:       s.cfg.Server.IdleTimeout,
		ReadHeaderTimeout: 1500 * time.Millisecond,
		MaxHeaderBytes:    s.cfg.Server.MaxHeaderBytes,
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state != http.StateNew && state != http.StateClosed && state != http.StateHijacked {
				return
			}

			remoteAddr := conn.RemoteAddr().String()
			ip, _, _ := net.SplitHostPort(remoteAddr)

			// Do not apply socket-level CPS/Conn bans to trusted proxies (Cloudflare)
			if s.pipeline.isTrustedProxy(ip) {
				if state == http.StateNew {
					atomic.AddInt64(&s.stats.ActiveConns, 1)
				} else if state == http.StateClosed || state == http.StateHijacked {
					if atomic.LoadInt64(&s.stats.ActiveConns) > 0 {
						atomic.AddInt64(&s.stats.ActiveConns, -1)
					}
				}
				return
			}

			switch state {
			case http.StateNew:
				atomic.AddInt64(&s.stats.ActiveConns, 1)

				// CPS Protection
				if !s.pipeline.CheckConnRate(ip) {
					s.pipeline.banIP(ip, s.cfg.Protection.Ban.Duration)
					conn.Close()
					return
				}

				// Concurrent Connection Limit
				count := s.pipeline.IncrementConnCount(ip)
				if count > s.cfg.Protection.ConnectionLimit.MaxPerIP {
					s.pipeline.banIP(ip, s.cfg.Protection.Ban.Duration)
					conn.Close()
					return
				}
			case http.StateClosed, http.StateHijacked:
				if atomic.LoadInt64(&s.stats.ActiveConns) > 0 {
					atomic.AddInt64(&s.stats.ActiveConns, -1)
				}
				s.pipeline.DecrementConnCount(ip)
			}
		},
	}

	var err error
	baseListener, err := listenSOReuseport("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	// Early Reject Layer: Sniff TLS ClientHello before full handshake
	if s.cfg.TLS.Enabled {
		baseListener = fingerprint.NewSniffingListener(baseListener, s.fpStore, func() bool {
			return s.stats.IsUnderAttack
		})
	}

	if s.cfg.TLS.Enabled && tlsConfig != nil {
		s.listener = tls.NewListener(baseListener, tlsConfig)
	} else {
		s.listener = baseListener
	}

	printBanner(s.cfg)

	logger.Info("Mango Shield ready",
		"address", listenAddr,
		"tls", s.cfg.TLS.Enabled,
	)

	return s.httpServer.Serve(s.listener)
}

// GetStats returns the stats struct
func (s *Shield) GetStats() *Stats {
	return s.stats
}

// GetXDPStats returns the stats from the XDP/eBPF engine
func (s *Shield) GetXDPStats() (bool, int64, int64) {
	if s.pipeline != nil && s.pipeline.xdpMgr != nil {
		banned, drops := s.pipeline.xdpMgr.GetStats()
		return s.pipeline.xdpMgr.Enabled, banned, drops
	}
	return false, 0, 0
}

// SetFingerprintStore replaces the fingerprint store
func (s *Shield) SetFingerprintStore(store *fingerprint.FingerprintStore) {
	if store != nil {
		s.fpStore = store
	}
}

// Stop gracefully stops the server
func (s *Shield) Stop() {
	logger.Info("Mango Shield shutting down...")
	s.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if s.httpServer != nil {
		s.httpServer.Shutdown(ctx)
	}
	if s.redirectServer != nil {
		s.redirectServer.Shutdown(ctx)
	}
	s.wg.Wait()
	logger.Info("Mango Shield stopped")
}

// normalizeHost returns host without port and in lowercase
func (s *Shield) normalizeHost(host string) string {
	host = strings.ToLower(host)
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return host
}

func (s *Shield) IsDomainUnderAttack(host string) bool {
	host = s.normalizeHost(host)

	// 1. Fast global check
	if s.cfg != nil && (s.cfg.Protection.Mode == "under_attack" || s.cfg.Protection.Mode == "emergency") {
		return true
	}

	// 2. Fast dynamic attack state check (auto-triggered by AlertManager)
	if val, ok := s.domainUnderAttack.Load(host); ok {
		if val.(bool) {
			return true
		}
	}

	// 3. Fast O(1) domain protection mode check
	if s.pipeline != nil && s.pipeline.domainModeMap != nil {
		mode := s.pipeline.domainModeMap[host]
		if mode == "under_attack" || mode == "emergency" || mode == "challenge" || mode == "captcha" {
			return true
		}
	} else if s.cfg != nil {
		// Fallback O(N) if map is somehow nil
		for i := 0; i < len(s.cfg.Domains); i++ {
			dName := strings.ToLower(s.cfg.Domains[i].Name)
			if host == dName || strings.HasSuffix(host, "."+dName) {
				m := s.cfg.Domains[i].ProtectionMode
				if m == "under_attack" || m == "emergency" || m == "challenge" || m == "captcha" {
					return true
				}
				if val, ok := s.domainUnderAttack.Load(dName); ok {
					return val.(bool)
				}
			}
		}
	}

	return false
}

// GetDomainRPS returns current RPS for a domain
func (s *Shield) GetDomainRPS(host string) int64 {
	host = s.normalizeHost(host)
	if v, ok := s.domainRPS.Load(host); ok {
		return v.(int64)
	}
	return 0
}

// handleRequest is the main HTTP handler
func (s *Shield) handleRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			logger.Error("Panic recovered in HTTP request handler", "error", err, "uri", r.RequestURI)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}()

	if s.cfg.HTTP3.Enabled || s.cfg.HTTP3.AltSvcHeader {
		h3Port := s.cfg.HTTP3.Port
		if h3Port <= 0 {
			h3Port = 443
		}
		w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=86400`, h3Port))
	}

	// Extract client IP early for rate limit page
	ip := s.extractIP(r)

	// Exclude internal telemetry /api/ polling from request counters so dashboard polling doesn't inflate RPS charts
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		atomic.AddInt64(&s.stats.TotalRequests, 1)

		// Increment per-domain request counter
		hostDomain := s.normalizeHost(r.Host)
		v, ok := s.domainReqs.Load(hostDomain)
		if !ok {
			v, _ = s.domainReqs.LoadOrStore(hostDomain, &DomainCounter{})
		}
		dc := v.(*DomainCounter)
		atomic.AddInt64(&dc.Reqs, 1)

		// Track concurrent connections (without limiting)
		atomic.AddInt64(&dc.ActiveConns, 1)
		defer atomic.AddInt64(&dc.ActiveConns, -1)
	}

	// Fast-path static logo & favicon asset serving with long-term immutable caching
	if r.URL.Path == "/logo-mango.png" || r.URL.Path == "/logo-mango-small.png" || r.URL.Path == "/assets/logo-mango.png" || r.URL.Path == "/favicon.ico" || r.URL.Path == "/apple-touch-icon.png" {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		if r.URL.Path == "/logo-mango-small.png" {
			if _, err := os.Stat("assets/logo-mango-small.png"); err == nil {
				w.Header().Set("Content-Type", "image/png")
				http.ServeFile(w, r, "assets/logo-mango-small.png")
				return
			}
		}
		if _, err := os.Stat("assets/logo-mango.png"); err == nil {
			w.Header().Set("Content-Type", "image/png")
			http.ServeFile(w, r, "assets/logo-mango.png")
			return
		}
		// Vector SVG fallback guaranteed never 404
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="32" height="32"><defs><linearGradient id="mGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#FF5722"/><stop offset="50%" stop-color="#FF9800"/><stop offset="100%" stop-color="#FFC107"/></linearGradient><linearGradient id="lGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#4CAF50"/><stop offset="100%" stop-color="#2E7D32"/></linearGradient></defs><path d="M50 15 C25 15 15 35 15 60 C15 80 32 90 50 90 C72 90 85 75 85 55 C85 30 70 15 50 15 Z" fill="url(#mGrad)"/><path d="M50 15 C55 5 65 2 75 5 C70 15 60 18 50 15 Z" fill="url(#lGrad)"/></svg>`))
		return
	}

	// Handle Challenge Form Verification BEFORE pipeline processing
	if r.Method == "POST" && r.FormValue("challenge_type") != "" {
		if s.challMgr.HandleVerification(w, r, ip) {
			GetLogStore().RecordEvent("CHALLENGE", ip, r.Host, r.Method, r.URL.Path, http.StatusOK, "CHALLENGE_SOLVED", "PoW/Turnstile", "Browser security challenge solved successfully")
			// Redirect cleanly back to the same page using StatusSeeOther (HTTP 303)
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)
			return
		}
	}

	// FAST-PATH: Verified human proof/session cookie (Zero-latency pass for clean verified visitors under DDoS)
	if s.pipeline != nil && s.pipeline.hasValidProof(r, ip) {
		// Anti-Abuse Rate Limit: Enforce rate limit (Token Bucket) for verified users to prevent single-IP/session flooding (> 30-50 RPS)
		if s.pipeline.detEngine != nil && s.pipeline.detEngine.CheckRateLimit(ip) {
			atomic.AddInt64(&s.stats.BlockedRequests, 1)
			GetLogStore().RecordEvent("SECURITY", ip, r.Host, r.Method, r.URL.Path, http.StatusForbidden, "BLOCKED", "rate_limit", "Verified user exceeded RPS rate limit")
			if s.challMgr != nil {
				s.challMgr.ServeRateLimitPage(w, r, ip, 10)
			} else {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("X-Mango-Shield", "rate-limited")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("403 Forbidden - Rate Limit Exceeded"))
			}
			return
		}

		// ALWAYS RUN WAF RULES INSPECTION (OWASP Top 10: SQLi, XSS, Path Traversal, RCE, Log4Shell) even for verified users
		if s.pipeline.wafEngine != nil && s.cfg.WAF.Enabled {
			wafResult := s.pipeline.wafEngine.Inspect(r)
			if wafResult.Blocked {
				atomic.AddInt64(&s.stats.BlockedRequests, 1)
				GetLogStore().RecordEvent("EXPLOIT", ip, r.Host, r.Method, r.URL.Path, http.StatusForbidden, "BLOCKED", wafResult.TopRule, fmt.Sprintf("WAF %s exploit blocked (score %d)", wafResult.TopRule, wafResult.Score))
				if s.challMgr != nil {
					s.challMgr.ServeBlockPage(w, r, ip, "WAF Exploit Protection", wafResult.TopRule)
				} else {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Header().Set("X-Mango-Shield", "blocked")
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte("403 Forbidden - WAF Protection"))
				}
				return
			}
		}

		atomic.AddInt64(&s.stats.PassedRequests, 1)
		w.Header().Set("X-Mango-Shield", "verified-pass")
		cdn := GetCDN()
		if cdn != nil && cdn.ServeFromCache(w, r) {
			return
		}
		if s.upstreams != nil {
			s.proxyRequest(w, r)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mango Shield v2.0 Active"))
		}
		return
	}

	// ALWAYS RUN WAF RULES INSPECTION FIRST (OWASP Top 10: SQLi, XSS, Path Traversal, RCE, Log4Shell)
	if s.pipeline.wafEngine != nil && s.cfg.WAF.Enabled {
		wafResult := s.pipeline.wafEngine.Inspect(r)
		if wafResult.Blocked {
			atomic.AddInt64(&s.stats.BlockedRequests, 1)
			GetLogStore().RecordEvent("EXPLOIT", ip, r.Host, r.Method, r.URL.Path, http.StatusForbidden, "BLOCKED", wafResult.TopRule, fmt.Sprintf("WAF %s exploit blocked (score %d)", wafResult.TopRule, wafResult.Score))
			if s.challMgr != nil {
				s.challMgr.ServeBlockPage(w, r, ip, "WAF Exploit Protection", wafResult.TopRule)
			} else {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("X-Mango-Shield", "blocked")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("403 Forbidden - WAF Protection"))
			}
			return
		}
	}

	// Get TLS fingerprint for this connection
	var connFP *fingerprint.ConnectionFingerprint
	if s.fpStore != nil {
		connFP = s.fpStore.GetCompositeForRequest(r.RemoteAddr, r.UserAgent())
		if connFP != nil {
			logger.Debug("Fingerprint",
				"ip", ip,
				"ja3", connFP.JA3.Hash,
				"score", connFP.Composite.Total,
				"verdict", connFP.Composite.Verdict,
			)
		}
	}

	// Run full 10-layer protection pipeline
	action := s.pipeline.ProcessWithFingerprint(r, ip, connFP)

	// Execute action
	switch action.Type {
	case ActionAllow:
		atomic.AddInt64(&s.stats.PassedRequests, 1)
		GetLogStore().RecordEvent("ACCESS", ip, r.Host, r.Method, r.URL.RequestURI(), http.StatusOK, "PASSED", "-", "Proxy pass to upstream")

		// Seamless active user session cookie: issue cookie to active visitors so DDoS attacks never prompt them with Captcha!
		if s.challMgr != nil && !s.pipeline.hasValidProof(r, ip) {
			s.challMgr.SetSessionCookie(w, r, ip)
		}

		// Check CDN Cache before forwarding to upstream
		cdn := GetCDN()
		if cdn != nil {
			if cdn.ServeFromCache(w, r) {
				return // Served directly from RAM cache!
			}
		}

		// Forward to upstream
		if s.upstreams != nil {
			s.proxyRequest(w, r)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mango Shield v2.0 Active (No Upstream Configured)"))
		}

	case ActionChallenge:
		atomic.AddInt64(&s.stats.BlockedRequests, 1)
		GetLogStore().RecordEvent("CHALLENGE", ip, r.Host, r.Method, r.URL.RequestURI(), http.StatusForbidden, "CHALLENGE_REQUIRED", fmt.Sprintf("STAGE_%d", action.Stage), fmt.Sprintf("Security challenge triggered: %s", action.Reason))
		if s.challMgr != nil {
			s.challMgr.ServeChallenge(w, r, action.Stage, action.Difficulty)
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("403 Challenge Required"))
		}

	case ActionBlock, ActionRateLimit, ActionDrop:
		atomic.AddInt64(&s.stats.BlockedRequests, 1)
		GetLogStore().RecordEvent("SECURITY", ip, r.Host, r.Method, r.URL.RequestURI(), http.StatusForbidden, "BLOCKED", action.Reason, fmt.Sprintf("Pipeline %v: %s", action.Type, action.Reason))
		if action.Type == ActionDrop || action.Type == ActionRateLimit {
			if !s.pipeline.isTrustedProxy(ip) {
				s.pipeline.BanIPLocal(ip, s.cfg.Protection.Ban.Duration)
			}
		}
		// Fast-path for high RPS attack surges (>100 RPS) to prevent CPU & rendering bottlenecks
		if s.stats.IsUnderAttack || atomic.LoadInt64(&s.stats.CurrentRPS) > 100 {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Mango-Shield", "blocked")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("403 Forbidden - Mango Shield Protection"))
			return
		}
		if s.challMgr != nil {
			s.challMgr.ServeBlockPage(w, r, ip, "WAF Protection", action.Reason)
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Mango-Shield", "blocked")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(fmt.Sprintf(
				"<html><body style='background:#111;color:#f44;font-family:sans-serif;text-align:center;padding-top:100px;'>"+
					"<h1>403 Forbidden</h1><p>Access blocked by Mango Shield protection system.</p>"+
					"<p style='color:#666;font-size:12px;'>Reason: %s | IP: %s</p></body></html>",
				action.Reason, ip,
			)))
		}
	}
}

// startHTTPRedirect starts HTTP to HTTPS redirect server (with Cloudflare Flexible SSL support)
func (s *Shield) startHTTPRedirect() {
	redirect := &http.Server{
		Addr: s.cfg.Server.HTTPListen,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If request comes via proxy/Cloudflare or already forwarded as HTTPS, handle directly to prevent loops
			if r.Header.Get("CF-Connecting-IP") != "" || r.Header.Get("X-Forwarded-Proto") == "https" || strings.Contains(r.Header.Get("CF-Visitor"), "https") {
				s.handleRequest(w, r)
				return
			}
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	logger.Info("HTTP redirect server", "listen", s.cfg.Server.HTTPListen)
	rlis, err := listenSOReuseport("tcp", s.cfg.Server.HTTPListen)
	if err != nil {
		logger.Error("HTTP redirect server listen failed", "error", err)
		return
	}
	redirect.Serve(rlis)
}

// rpsCounter tracks requests per second globally and per domain
func (s *Shield) rpsCounter() {
	defer s.wg.Done()
	var lastTotal int64
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			current := atomic.LoadInt64(&s.stats.TotalRequests)
			rps := current - lastTotal
			lastTotal = current
			atomic.StoreInt64(&s.stats.CurrentRPS, rps)

			peak := atomic.LoadInt64(&s.stats.PeakRPS)
			if rps > peak {
				atomic.StoreInt64(&s.stats.PeakRPS, rps)
			}

			// Calculate per-domain RPS
			for _, d := range s.cfg.Domains {
				dName := strings.ToLower(d.Name)
				if v, ok := s.domainReqs.Load(dName); ok {
					curr := atomic.LoadInt64(&v.(*DomainCounter).Reqs)
					last := int64(0)
					if l, ok2 := s.domainLastReqs.Load(dName); ok2 {
						last = l.(int64)
					}
					dRPS := curr - last
					s.domainLastReqs.Store(dName, curr)
					s.domainRPS.Store(dName, dRPS)
				}
			}
		}
	}
}

// attackDetector monitors for attack conditions globally and per-domain
func (s *Shield) attackDetector() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var normalCount int

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			rps := atomic.LoadInt64(&s.stats.CurrentRPS)
			conns := atomic.LoadInt64(&s.stats.ActiveConns)
			thresholdRPS := int64(s.cfg.Protection.Emergency.RPSThreshold)
			if thresholdRPS == 0 {
				thresholdRPS = 200
			}

			// 1. Per-Domain Attack Detection with Mesh Aggregation
			for _, d := range s.cfg.Domains {
				dName := strings.ToLower(d.Name)
				localRPS := s.GetDomainRPS(dName)
				localConns := atomic.LoadInt64(&s.stats.ActiveConns)

				totalClusterRPS := localRPS
				totalClusterConns := localConns

				if m := cluster.GetMesh(); m != nil {
					m.BroadcastDomainMetric(dName, localRPS, localConns, false)
					peerRPS, peerConns := m.GetPeerDomainMetrics(dName)
					totalClusterRPS += peerRPS
					totalClusterConns += peerConns
				}

				dThreshold := int64(d.RateLimitRPS)
				if dThreshold <= 0 {
					dThreshold = thresholdRPS
				}

				isDomainAttack := totalClusterRPS > dThreshold
				isCurrentlyUnderAttack := false
				if ua, ok := s.domainUnderAttack.Load(dName); ok {
					isCurrentlyUnderAttack = ua.(bool)
				}

				if isDomainAttack {
					s.domainNormalCount.Store(dName, 0)
					if !isCurrentlyUnderAttack {
						s.domainUnderAttack.Store(dName, true)
						s.domainAttackStart.Store(dName, time.Now())
						atomic.AddInt64(&s.stats.AttacksDetected, 1)
						logger.Warn("ATTACK DETECTED ON DOMAIN (Cluster Aggregated)", "domain", dName, "total_cluster_rps", totalClusterRPS, "total_cluster_conns", totalClusterConns)
						s.pipeline.alerts.SendDomainAttackStart(dName, totalClusterRPS, totalClusterConns)
					}
				} else if isCurrentlyUnderAttack {
					nc := 0
					if c, ok := s.domainNormalCount.Load(dName); ok {
						nc = c.(int)
					}
					nc++
					s.domainNormalCount.Store(dName, nc)
					if nc >= 10 {
						s.domainUnderAttack.Store(dName, false)
						if m := cluster.GetMesh(); m != nil {
							m.BroadcastDomainMetric(dName, 0, 0, true)
						}
						start := time.Now()
						if st, ok := s.domainAttackStart.Load(dName); ok {
							start = st.(time.Time)
						}
						duration := time.Since(start)
						logger.Info("Domain attack ended", "domain", dName, "duration", duration.Round(time.Second))
						s.pipeline.alerts.SendDomainAttackEnd(dName, duration, atomic.LoadInt64(&s.stats.BlockedRequests))
						s.domainNormalCount.Store(dName, 0)
					}
				}
			}

			// 2. System-wide Extreme Overload Trigger
			isSystemAttack := rps > thresholdRPS*2 || conns > 500

			if isSystemAttack {
				normalCount = 0
				if !s.stats.IsUnderAttack {
					s.stats.IsUnderAttack = true
					s.stats.AttackStartTime = time.Now()
					atomic.AddInt64(&s.stats.AttacksDetected, 1)
					logger.Warn("SYSTEM EXTREME ATTACK DETECTED", "rps", rps, "conns", conns)
					s.pipeline.alerts.SendAttackStart(rps, conns)
				}
			} else if s.stats.IsUnderAttack {
				normalCount++
				if normalCount >= 10 {
					s.stats.IsUnderAttack = false
					duration := time.Since(s.stats.AttackStartTime)
					blocked := atomic.LoadInt64(&s.stats.BlockedRequests)
					logger.Info("System attack ended", "duration", duration.Round(time.Second), "blocked", blocked)
					s.pipeline.alerts.SendAttackEnd(duration, blocked)
					normalCount = 0
				}
			}
		}
	}
}

// cleanupWorker periodically cleans expired entries
func (s *Shield) cleanupWorker() {
	defer s.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.pipeline.Cleanup()
			// Cleanup detection engine sessions and rate limit buckets
			if s.detEngine != nil {
				s.detEngine.CleanupSessions()
			}
			// Cleanup behavior profiles older than 10 minutes
			if s.behavior != nil {
				s.behavior.Cleanup(10 * time.Minute)
			}
			// Cleanup bot classifier cache
			if s.botClass != nil {
				s.botClass.CleanupCache()
			}
		}
	}
}

// adaptiveSampler feeds traffic data to detection engine and adaptive learner
func (s *Shield) adaptiveSampler() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			rps := float64(atomic.LoadInt64(&s.stats.CurrentRPS))
			conns := float64(atomic.LoadInt64(&s.stats.ActiveConns))

			// Feed detection engine baseline
			if s.detEngine != nil {
				s.detEngine.RecordRPSSample(rps)
				detection.SetGlobalRPS(int64(rps))
			}

			// Feed adaptive learner
			if s.adaptive != nil {
				s.adaptive.RecordSample(rps, conns, 0)
			}
		}
	}
}

// extractIP gets real client IP from request safely
func (s *Shield) extractIP(r *http.Request) string {
	// Always prioritize Cloudflare connecting IP if header is present
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		return trimSpace(cfip)
	}

	// Always check X-Forwarded-For or X-Real-IP if present
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := splitFirst(xff, ",")
		ip := trimSpace(parts)
		if ip != "" {
			return ip
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := trimSpace(xri)
		if ip != "" {
			return ip
		}
	}

	peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return peerHost
}


func splitFirst(s, sep string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == sep[0] {
			return s[:i]
		}
	}
	return s
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && s[start] == ' ' {
		start++
	}
	for end > start && s[end-1] == ' ' {
		end--
	}
	return s[start:end]
}

func printBanner(cfg *config.Config) {
	banner := `
  ╔══════════════════════════════════════════╗
  ║                                          ║
  ║   🥭  M A N G O   S H I E L D   v2.0     ║
  ║       Anti-DDoS L7 Protection            ║
  ║                                          ║
  ╚══════════════════════════════════════════╝`
	fmt.Println("\033[36;1m" + banner + "\033[0m")
	fmt.Printf("\033[32m  Domains: %d | Mode: %s\033[0m\n", len(cfg.Domains), cfg.Protection.Mode)
	fmt.Printf("\033[32m  TLS: %v | Dashboard: %v\033[0m\n\n", cfg.TLS.Enabled, cfg.Dashboard.Enabled)
}

func ensureTLSCertificates(cfg *config.Config, certFile, keyFile string) error {
	if certFile == "" {
		certFile = "certs/server.crt"
	}
	if keyFile == "" {
		keyFile = "certs/server.key"
	}

	logger.Info("Generating SAN TLS certificate for configured domains...", "cert", certFile)

	_ = os.MkdirAll(filepath.Dir(certFile), 0755)
	_ = os.MkdirAll(filepath.Dir(keyFile), 0755)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate rsa key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	// Dynamic CommonName & Subject Alternative Names (DNSNames) from configured domains
	commonName := "localhost"
	dnsMap := map[string]bool{"localhost": true}

	if cfg != nil {
		for i, d := range cfg.Domains {
			if d.Name != "" {
				if i == 0 {
					commonName = d.Name
				}
				dnsMap[d.Name] = true
				dnsMap["*."+d.Name] = true // Wildcard SAN for subdomains
			}
		}
	}

	var dnsNames []string
	for name := range dnsMap {
		dnsNames = append(dnsNames, name)
	}

	// Dynamic IPAddresses from loopback + server listen settings
	ipMap := map[string]net.IP{
		"127.0.0.1": net.ParseIP("127.0.0.1"),
		"::1":       net.ParseIP("::1"),
	}
	if cfg != nil {
		for _, addr := range []string{cfg.Server.Listen, cfg.Server.HTTPListen} {
			if host, _, err := net.SplitHostPort(addr); err == nil && host != "" && host != "0.0.0.0" && host != "::" {
				if parsed := net.ParseIP(host); parsed != nil {
					ipMap[parsed.String()] = parsed
				}
			}
		}
	}

	var ipAddresses []net.IP
	for _, ip := range ipMap {
		if ip != nil {
			ipAddresses = append(ipAddresses, ip)
		}
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Mango Shield WAF"},
			CommonName:   commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ipAddresses,
		DNSNames:              dnsNames,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("encode cert: %w", err)
	}

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer keyOut.Close()
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("encode key: %w", err)
	}

	logger.Info("Self-signed TLS certificates generated successfully", "cert", certFile, "key", keyFile, "cn", commonName, "dns", dnsNames)
	return nil
}

func listenSOReuseport(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				if opErr != nil {
					return
				}
				_ = unix.SetsockoptInt(int(fd), unix.SOL_TCP, unix.TCP_FASTOPEN, 32)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	return lc.Listen(context.Background(), network, address)
}
