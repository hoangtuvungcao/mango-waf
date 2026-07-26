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
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"mango-waf/challenge"
	"mango-waf/config"
	"mango-waf/detection"
	"mango-waf/fingerprint"
	"mango-waf/intelligence"
	"mango-waf/logger"
	"mango-waf/perf"
	"mango-waf/rules"
)

// Shield is the main Mango Shield server
type Shield struct {
	cfg            *config.Config
	pipeline       *Pipeline
	stats          *Stats
	httpServer     *http.Server
	redirectServer *http.Server
	listener       net.Listener
	fpStore        *fingerprint.FingerprintStore
	challMgr       *challenge.Manager
	intel          *intelligence.Intel
	detEngine      *detection.Engine
	behavior       *detection.BehaviorAnalyzer
	botClass       *detection.BotClassifier
	attackDet      *detection.AttackDetector
	adaptive       *detection.AdaptiveLearner
	wafEngine      *rules.Engine
	rateLimiter    *perf.IPRateLimiter
	degrader       *perf.GracefulDegrader
	validator      *perf.RequestValidator
	upstreams      *UpstreamManager
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

// Stats holds real-time statistics
type Stats struct {
	TotalRequests   int64
	BlockedRequests int64
	ChallengedReqs  int64
	PassedRequests  int64
	ActiveConns     int64
	CurrentRPS      int64
	PeakRPS         int64
	BannedIPs       int64
	WhitelistedIPs  int64
	AttacksDetected int64
	Uptime          time.Time
	IsUnderAttack   bool
	CurrentStage    int32
	AttackStartTime time.Time
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
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("load TLS cert: %w", err)
		}
		minVer := uint16(tls.VersionTLS12)
		if s.cfg.TLS.MinVersion == "1.3" {
			minVer = tls.VersionTLS13
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   minVer,
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

	s.httpServer = &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       s.cfg.Server.ReadTimeout,
		WriteTimeout:      s.cfg.Server.WriteTimeout,
		IdleTimeout:       s.cfg.Server.IdleTimeout,
		ReadHeaderTimeout: 3 * time.Second,
		MaxHeaderBytes:    s.cfg.Server.MaxHeaderBytes,
		ConnState: func(conn net.Conn, state http.ConnState) {
			remoteAddr := conn.RemoteAddr().String()
			ip, _, _ := net.SplitHostPort(remoteAddr)

			switch state {
			case http.StateNew:
				active := atomic.AddInt64(&s.stats.ActiveConns, 1)
				if active > 100000 {
					atomic.AddInt64(&s.stats.ActiveConns, -1)
					conn.Close()
					return
				}
				// Do not apply socket-level CPS/Conn bans to trusted proxies (Cloudflare)
				if s.pipeline.isTrustedProxy(ip) {
					return
				}

				// CPS Protection
				if !s.pipeline.CheckConnRate(ip) {
					atomic.AddInt64(&s.stats.ActiveConns, -1)
					s.pipeline.banIP(ip, s.cfg.Protection.Ban.Duration)
					conn.Close()
					return
				}

				// Concurrent Connection Limit
				count := s.pipeline.IncrementConnCount(ip)
				if count > s.cfg.Protection.ConnectionLimit.MaxPerIP {
					atomic.AddInt64(&s.stats.ActiveConns, -1)
					s.pipeline.banIP(ip, s.cfg.Protection.Ban.Duration)
					conn.Close()
					return
				}
			case http.StateClosed, http.StateHijacked:
				atomic.AddInt64(&s.stats.ActiveConns, -1)
				s.pipeline.DecrementConnCount(ip)
			}
		},
	}

	var err error
	baseListener, err := net.Listen("tcp", listenAddr)
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

// handleRequest is the main HTTP handler
func (s *Shield) handleRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			logger.Error("Panic recovered in HTTP request handler", "error", err, "uri", r.RequestURI)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}()

	atomic.AddInt64(&s.stats.TotalRequests, 1)

	// Extract client IP
	ip := s.extractIP(r)

	// Handle Challenge Form Verification BEFORE pipeline processing
	if r.Method == "POST" && r.FormValue("challenge_type") != "" {
		if s.challMgr.HandleVerification(w, r, ip) {
			// Redirect cleanly back to the same page after successful verification
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusFound)
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

	case ActionBlock:
		atomic.AddInt64(&s.stats.BlockedRequests, 1)
		if s.challMgr != nil {
			s.challMgr.ServeBlockPage(w, r, ip, "WAF Rule", action.Reason)
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

	case ActionChallenge:
		atomic.AddInt64(&s.stats.ChallengedReqs, 1)
		if s.challMgr != nil {
			s.challMgr.ServeChallenge(w, r, action.Stage, action.Difficulty)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Challenge Required"))
		}

	case ActionRateLimit:
		atomic.AddInt64(&s.stats.BlockedRequests, 1)
		if s.challMgr != nil {
			s.challMgr.ServeRateLimitPage(w, r, ip, 10)
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Retry-After", "10")
			w.Header().Set("X-Mango-Shield", "rate-limited")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(fmt.Sprintf(
				"<html><body style='background:#111;color:#f90;font-family:sans-serif;text-align:center;padding-top:100px;'>"+
					"<h1>429 Too Many Requests</h1><p>Rate limit exceeded on Mango Shield.</p>"+
					"<p style='color:#666;font-size:12px;'>IP: %s</p></body></html>",
				ip,
			)))
		}

	case ActionDrop:
		atomic.AddInt64(&s.stats.BlockedRequests, 1)
		// Silently close connection
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			if conn != nil {
				conn.Close()
			}
		}
	}
}

// startHTTPRedirect starts HTTP to HTTPS redirect server
func (s *Shield) startHTTPRedirect() {
	redirect := &http.Server{
		Addr: s.cfg.Server.HTTPListen,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	logger.Info("HTTP redirect server", "listen", s.cfg.Server.HTTPListen)
	redirect.ListenAndServe()
}

// rpsCounter tracks requests per second
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
		}
	}
}

// attackDetector monitors for attack conditions
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
			threshold := int64(s.cfg.Protection.Emergency.RPSThreshold)

			if rps > threshold {
				normalCount = 0
				if !s.stats.IsUnderAttack {
					s.stats.IsUnderAttack = true
					s.stats.AttackStartTime = time.Now()
					atomic.AddInt64(&s.stats.AttacksDetected, 1)
					logger.Warn("ATTACK DETECTED",
						"rps", rps,
						"threshold", threshold,
					)
					s.pipeline.alerts.SendAttackStart(rps)
				}
			} else if s.stats.IsUnderAttack {
				normalCount++
				if normalCount >= 10 {
					s.stats.IsUnderAttack = false
					duration := time.Since(s.stats.AttackStartTime)
					blocked := atomic.LoadInt64(&s.stats.BlockedRequests)
					logger.Info("Attack ended",
						"duration", duration.Round(time.Second),
						"blocked", blocked,
					)
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
	peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerHost = r.RemoteAddr
	}

	// Always prioritize Cloudflare connecting IP if header is present
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		return trimSpace(cfip)
	}

	// Check if peer is in trusted proxies list
	if len(s.cfg.Protection.TrustedProxies) > 0 {
		isTrusted := false
		for _, trusted := range s.cfg.Protection.TrustedProxies {
			if trusted == peerHost {
				isTrusted = true
				break
			}
			_, cidr, err := net.ParseCIDR(trusted)
			if err == nil {
				ip := net.ParseIP(peerHost)
				if ip != nil && cidr.Contains(ip) {
					isTrusted = true
					break
				}
			}
		}

		if isTrusted {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := splitFirst(xff, ",")
				return trimSpace(parts)
			}
			if xri := r.Header.Get("X-Real-IP"); xri != "" {
				return trimSpace(xri)
			}
		}
	}

	return peerHost
}

func extractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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

	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	if certErr == nil && keyErr == nil {
		return nil // Both files exist
	}

	logger.Info("TLS certificate files missing, generating self-signed RSA certificate...", "cert", certFile, "key", keyFile)

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
