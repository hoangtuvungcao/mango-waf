package core

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mango-waf/cluster"
	"mango-waf/config"
	"mango-waf/detection"
	"mango-waf/fingerprint"
	"mango-waf/intelligence"
	"mango-waf/logger"
	"mango-waf/perf"
	"mango-waf/rules"
)

// ActionType represents the decision made by the pipeline
type ActionType int

const (
	ActionAllow ActionType = iota
	ActionChallenge
	ActionBlock
	ActionRateLimit
	ActionDrop
)

// Action is the result of pipeline processing
type Action struct {
	Type       ActionType
	Reason     string
	Stage      int
	Difficulty int
}

// Pipeline is the request processing pipeline
type Pipeline struct {
	shield      *Shield
	cfg         *config.Config
	ipStates    sync.Map // map[string]*IPState
	banned      sync.Map // map[string]time.Time
	whitelist   sync.Map // map[string]time.Time
	activeConns sync.Map // map[string]*int64
	connCount   sync.Map // map[string]int
	alerts      *AlertManager
	intel       *intelligence.Intel
	detEngine   *detection.Engine
	behavior    *detection.BehaviorAnalyzer
	botClass    *detection.BotClassifier
	attackDet   *detection.AttackDetector
	adaptive    *detection.AdaptiveLearner
	wafEngine   *rules.Engine
	rateLimiter *perf.IPRateLimiter
	degrader    *perf.GracefulDegrader
	validator   *perf.RequestValidator
	xdpMgr      *XDPManager
}

// IPState tracks per-IP behavior
type IPState struct {
	mu               sync.Mutex
	RequestCount     int64
	RPS              int
	LastReset        time.Time
	LastSeen         time.Time
	Stage            int
	Fails            int
	TrustScore       float64
	JA3Hash          string
	Countries        string
	FirstSeen        time.Time
	TotalRequests    int64
	ChallengesServed int
	ChallengesPassed int
	RateLimitHits    int
	CPS              int
	ConnLastReset    time.Time
}

// NewPipeline creates a new processing pipeline
func NewPipeline(s *Shield) *Pipeline {
	return &Pipeline{
		shield: s,
		cfg:    s.cfg,
		alerts: NewAlertManager(s.cfg),
		xdpMgr: NewXDPManager(s.cfg),
	}
}

// GetAlerts returns the alert manager
func (p *Pipeline) GetAlerts() *AlertManager {
	return p.alerts
}

// Process runs a request through the protection pipeline (no fingerprint)
func (p *Pipeline) Process(r *http.Request, ip string) Action {
	return p.ProcessWithFingerprint(r, ip, nil)
}

// ProcessWithFingerprint runs a request through the pipeline with TLS fingerprint data
func (p *Pipeline) ProcessWithFingerprint(r *http.Request, ip string, fp *fingerprint.ConnectionFingerprint) Action {
	// Layer 0: Check banned
	if p.isBanned(ip) {
		return Action{Type: ActionDrop, Reason: "banned"}
	}

	// Layer 0.1: Verified proof cookie (Human user bypass)
	if p.hasValidProof(r) {
		return Action{Type: ActionAllow, Reason: "verified_human"}
	}

	// Layer 0.2: Static assets & stats endpoints bypass
	if isStaticAsset(r.URL.Path) {
		return Action{Type: ActionAllow, Reason: "static_asset"}
	}

	// Layer 0.5: Emergency mode
	if p.shield.stats.IsUnderAttack && p.cfg.Protection.Emergency.AutoEnable {
		if !p.isWhitelisted(ip) {
			if p.cfg.Protection.Mode == "emergency" {
				return Action{Type: ActionBlock, Reason: "emergency_mode"}
			}
		}
	}

	// Layer 1: Connection limit
	count := p.getConnCount(ip)
	if count > p.cfg.Protection.ConnectionLimit.MaxPerIP {
		p.banIP(ip, p.cfg.Protection.Ban.Duration)
		return Action{Type: ActionBlock, Reason: "conn_limit"}
	}

	// Layer 1.5: Request Validation (method, URL length, null bytes, body size)
	if p.validator != nil {
		if valid, reason := p.validator.Validate(r); !valid {
			p.BanIPLocal(ip, 1*time.Hour)
			logger.Warn("Request validation failed", "ip", ip, "reason", reason)
			return Action{Type: ActionBlock, Reason: "validation:" + reason}
		}
	}

	// Layer 2: Basic validation
	if action := p.validateRequest(r, ip); action.Type != ActionAllow {
		return action
	}

	// Layer 2.5: TLS Fingerprint check
	if fp != nil && p.cfg.Fingerprint.JA3.Enabled {
		// Known attack tool fingerprint → immediate block
		if fp.JA3.Known && fp.JA3.TrustScore == 0 {
			// Ban for 6x default duration (e.g. 60m if default is 10m)
			p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration*6)
			logger.Warn("Attack tool detected via JA3",
				"ip", ip, "ja3", fp.JA3.Hash, "browser", fp.JA3.BrowserID)
			return Action{Type: ActionDrop, Reason: "attack_tool_ja3:" + fp.JA3.BrowserID}
		}

		// Very low composite trust → block
		if fp.Composite.Total < 15 {
			// Ban for 3x default duration
			p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration*3)
			logger.Warn("Extremely low trust fingerprint",
				"ip", ip, "trust", fp.Composite.Total, "verdict", fp.Composite.Verdict)
			return Action{Type: ActionBlock, Reason: "fp_malicious"}
		}

		// Trusted browser fingerprint → fast-track (skip challenge if not under attack)
		if fp.IsTrusted() && !p.shield.stats.IsUnderAttack {
			return Action{Type: ActionAllow, Reason: "fp_trusted:" + fp.Composite.Verdict}
		}

		// Update IP state with fingerprint trust score
		state := p.getState(ip)
		state.mu.Lock()
		state.TrustScore = fp.Composite.Total
		state.JA3Hash = fp.JA3.Hash
		state.mu.Unlock()
	}

	// Layer 3: Intelligence Layer (GeoIP, IP Reputation, ASN, Threat Feeds)
	// OPTIMIZATION: Disable under high load to save CPU/Network
	if p.intel != nil && (p.degrader == nil || !p.degrader.IsFeatureDisabled("reputation_lookup", p.shield.stats.CurrentRPS)) {
		evalResult := p.intel.Evaluate(ip)
		if evalResult.TrustScore <= 0 {
			// Completely untrusted (blacklisted, geo-blocked, etc.)
			p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration)
			reason := "intel_blocked"
			if len(evalResult.Actions) > 0 {
				reason = "intel:" + evalResult.Actions[0]
			}
			logger.Warn("Intelligence blocked IP", "ip", ip, "trust", evalResult.TrustScore, "actions", evalResult.Actions)
			return Action{Type: ActionBlock, Reason: reason}
		}
		if evalResult.TrustScore < 30 {
			// Very low trust → escalate to challenge
			state := p.getState(ip)
			state.mu.Lock()
			state.TrustScore = evalResult.TrustScore
			state.mu.Unlock()
		}
	}

	// Layer 3.5: Rate Limiting & Anti-DDoS Volumetric Mitigation
	if p.cfg.Protection.RateLimit.Enabled {
		isUnderAttack := p.shield.stats.IsUnderAttack || atomic.LoadInt64(&p.shield.stats.CurrentRPS) > 200

		// If under attack or high RPS surge, enforce strict anti-DDoS flood protection for unverified IPs
		if isUnderAttack && !p.isWhitelisted(ip) {
			state := p.getState(ip)
			state.mu.Lock()
			now := time.Now()
			if now.Sub(state.ConnLastReset) >= time.Second {
				state.RateLimitHits = 1
				state.ConnLastReset = now
			} else {
				state.RateLimitHits++
			}
			hits := state.RateLimitHits
			state.mu.Unlock()

			if hits > 15 {
				atomic.AddInt64(&p.shield.stats.BlockedRequests, 1)
				if hits > 30 {
					p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration)
					return Action{Type: ActionDrop, Reason: "ddos_flood_drop"}
				}
				return Action{Type: ActionBlock, Reason: "ddos_flood_block"}
			}
		}

		if p.rateLimiter != nil && !p.rateLimiter.Allow(ip) {
			logger.Info("Rate limited", "ip", ip)
			atomic.AddInt64(&p.shield.stats.BlockedRequests, 1)
			state := p.getState(ip)
			state.mu.Lock()
			state.RateLimitHits++
			hits := state.RateLimitHits
			state.mu.Unlock()

			// If they hit the rate limit too many times without a whitelist, they are likely a bot
			if hits > 20 {
				p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration*2)
				return Action{Type: ActionDrop, Reason: "rate_limit_persistent"}
			}

			return Action{Type: ActionRateLimit, Reason: "rate_limited"}
		}
	}

	// Layer 4: Check whitelist (already passed challenge)
	if p.isWhitelisted(ip) {
		return Action{Type: ActionAllow, Reason: "whitelisted"}
	}

	// Layer 5: WAF Rules Inspection
	// OPTIMIZATION: Skip deep inspection under high load
	if p.wafEngine != nil && p.cfg.WAF.Enabled {
		if p.degrader == nil || !p.degrader.IsFeatureDisabled("waf_deep_inspect", p.shield.stats.CurrentRPS) {
			wafResult := p.wafEngine.Inspect(r)
			if wafResult.Blocked {
				logger.Warn("WAF blocked", "ip", ip, "rule", wafResult.TopRule, "score", wafResult.Score)
				if wafResult.Action == "drop" {
					p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration)
					return Action{Type: ActionDrop, Reason: "waf:" + wafResult.TopRule}
				}
				return Action{Type: ActionBlock, Reason: "waf:" + wafResult.TopRule}
			}
		}
	}

	// Layer 6: Behavior Analysis
	var behaviorVerdict *detection.BehaviorVerdict
	if p.behavior != nil {
		behaviorVerdict = p.behavior.Analyze(ip, r.URL.Path, r.Method, r.UserAgent(), 200)
		if behaviorVerdict.IsBot && behaviorVerdict.Score < 20 {
			// Extreme bot behavior → block
			p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration)
			logger.Warn("Behavior analysis: DDoS bot detected",
				"ip", ip, "score", behaviorVerdict.Score, "profile", behaviorVerdict.Profile)
			return Action{Type: ActionBlock, Reason: "behavior_ddos"}
		}
	}

	// Layer 7: Bot Classification
	if p.botClass != nil && p.cfg.Detection.BotClassifier.Enabled {
		classReq := &detection.ClassifyRequest{
			IP:        ip,
			UserAgent: r.UserAgent(),
			Headers:   extractHeaders(r),
			URL:       r.URL.Path,
			Method:    r.Method,
			Behavior:  behaviorVerdict,
		}
		if fp != nil {
			classReq.Fingerprint = fp
		}
		classResult := p.botClass.Classify(classReq)
		if classResult.IsBot && classResult.Threat == "critical" {
			// Critical threat: 6x default duration
			p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration*6)
			logger.Warn("Bot classified as critical threat",
				"ip", ip, "type", classResult.BotType, "name", classResult.BotName, "confidence", classResult.Confidence)
			return Action{Type: ActionDrop, Reason: "bot:" + classResult.BotType}
		}
		if classResult.IsBot && classResult.Threat == "high" && !p.hasValidProof(r) {
			return Action{Type: ActionChallenge, Reason: "bot_suspicious", Stage: 2, Difficulty: p.cfg.Protection.Challenge.PowDifficulty + 1}
		}
	}

	// Layer 8: Session Tracking
	if p.detEngine != nil && p.cfg.Detection.SessionTracking.Enabled {
		session := p.detEngine.TrackSession(ip, r.URL.Path, r.UserAgent())
		if session != nil && session.Suspicious {
			logger.Info("Suspicious session detected", "ip", ip, "trust", session.TrustScore, "requests", session.Requests)
		}
	}

	// Layer 9: Rate limiting via detection engine (adaptive token bucket)
	if p.detEngine != nil && p.cfg.Protection.RateLimit.Enabled {
		if p.detEngine.CheckRateLimit(ip) && !p.hasValidProof(r) {
			return Action{Type: ActionChallenge, Reason: "det_rate_limited", Stage: 1, Difficulty: p.cfg.Protection.Challenge.PowDifficulty}
		}
	}

	// Layer 10: Determine challenge stage (fingerprint-aware + adaptive learner)
	state := p.getState(ip)
	p.updateRPS(state)

	stage := p.determineStageWithFP(state, r, fp)

	// Stage 4 triggers an immediate TCP Drop (no HTTP response sent) to save maximum network bandwidth/CPU.
	if stage == 4 {
		return Action{Type: ActionDrop, Reason: "auto_l7_drop"}
	}

	if stage > 0 {
		difficulty := p.cfg.Protection.Challenge.PowDifficulty
		if p.cfg.Protection.Challenge.PowAdaptive {
			if state.RPS > 50 {
				difficulty += 1
			}
			if state.RPS > 100 {
				difficulty += 2
			}
			// Fingerprint-based difficulty adjustment
			if fp != nil && fp.Composite.Total < 40 {
				difficulty += 1
			}
		}

		// Adaptive learner difficulty adjustment
		if p.adaptive != nil {
			adDecision := p.adaptive.GetDecision(float64(state.RPS))
			if adDecision.ChallengeLevel > stage {
				stage = adDecision.ChallengeLevel
			}
		}

		// Cap max difficulty to prevent browser hangs
		if difficulty > 6 {
			difficulty = 6
		}

		return Action{
			Type:       ActionChallenge,
			Reason:     fmt.Sprintf("stage_%d", stage),
			Stage:      stage,
			Difficulty: difficulty,
		}
	}

	return Action{Type: ActionAllow, Reason: "clean"}
}

// extractHeaders converts http.Header to map[string]string for bot classifier
func extractHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	return headers
}

// validateRequest performs basic request validation
func (p *Pipeline) validateRequest(r *http.Request, ip string) Action {
	if !p.validHost(r) {
		// Just block, don't ban for host mismatch
		return Action{Type: ActionBlock, Reason: "invalid_host"}
	}
	if p.isBadUA(r) {
		// Just block, don't ban for bad UA
		return Action{Type: ActionBlock, Reason: "bad_ua"}
	}
	return Action{Type: ActionAllow}
}

// validHost checks if the host header matches configured domains
func (p *Pipeline) validHost(r *http.Request) bool {
	host := strings.ToLower(r.Host)
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	for _, d := range p.cfg.Domains {
		if strings.Contains(host, strings.ToLower(d.Name)) {
			return true
		}
	}
	return false
}

// isBadUA detects known bot/tool user agents
func (p *Pipeline) isBadUA(r *http.Request) bool {
	ua := strings.ToLower(r.UserAgent())
	if ua == "" {
		return true
	}
	badAgents := []string{
		"curl", "wget", "python", "java", "go-http-client",
		"node-fetch", "axios", "httpie", "scrapy",
		"crawler", "spider", "scan", "masscan", "nikto",
		"sqlmap", "nmap", "dirbuster", "gobuster",
	}
	for _, bad := range badAgents {
		if strings.Contains(ua, bad) {
			return true
		}
	}
	return false
}

// determineStageWithFP determines challenge stage with fingerprint awareness
func (p *Pipeline) determineStageWithFP(state *IPState, r *http.Request, fp *fingerprint.ConnectionFingerprint) int {
	mode := p.cfg.Protection.Mode

	switch mode {
	case "off":
		return 0
	case "silent":
		if p.hasValidProof(r) {
			return 0
		}
		return 3
	case "challenge":
		if p.hasValidProof(r) {
			return 0
		}
		return 1
	case "captcha":
		if p.hasValidProof(r) {
			return 0
		}
		return 2
	case "emergency":
		if p.hasValidProof(r) {
			return 0
		}
		return 4 // Drop all unauthenticated traffic
	case "auto":
		if p.hasValidProof(r) {
			return 0
		}

		limit := p.cfg.Protection.RateLimit.RequestsPerSecond
		systemRPS := atomic.LoadInt64(&p.shield.stats.CurrentRPS)
		threshold := int64(p.cfg.Protection.Emergency.RPSThreshold)

		// 1. Extreme System Load (DDoS Tsunami)
		//    - Maximize bandwidth saving: Drop worst offenders instantly (TCP Reset)
		//    - Captcha for everyone else
		if systemRPS > threshold*2 {
			if state.RPS > limit*2 {
				return 4 // Drop instantly
			}
			return 2 // Turnstile Captcha
		}

		// 2. Security Checks inside auto mode are handled by Smart Per-IP logic below

		// 3. Smart Per-IP Behavioral Analysis
		if fp != nil {
			switch {
			case fp.Composite.Total >= 60: // High trust: known browsers
				if p.shield.stats.IsUnderAttack {
					if state.RPS > limit*4 {
						return 2 // Extremely high RPS during attack -> Captcha
					}
					if state.RPS > limit*2 {
						return 1 // High RPS during attack -> JS Challenge
					}
					return 0 // Seamless even under attack if RPS is very low
				}
				if state.RPS > limit*4 {
					return 2 // Extremely high RPS -> Captcha
				}
				if state.RPS > limit*2 {
					return 1 // High RPS -> JS Challenge
				}
				return 0

			case fp.Composite.Total >= 30: // Medium trust: Incognito / Unknown but likely legit
				if p.shield.stats.IsUnderAttack {
					if state.RPS > limit*2 {
						return 2 // High RPS during attack -> Captcha
					}
					if state.RPS > 10 { // Moderate RPS during attack -> JS Challenge
						return 1
					}
					return 0 // Seamless for normal browsing even under attack
				}
				if state.RPS > limit*3 {
					return 2 // Very high RPS -> Captcha
				}
				if state.RPS > limit*3/2 {
					return 1 // Moderate-High RPS -> JS Challenge
				}
				return 0 // Seamless for normal browsing (Incognito Fix)

			default: // Low trust: Score < 30 (Bots, automated scripts, or suspicious)
				if p.shield.stats.IsUnderAttack {
					if state.RPS > limit {
						return 2 // High RPS from suspicious source during attack -> Captcha
					}
					return 1 // Suspected bot during attack -> JS Challenge
				}
				if state.RPS > limit {
					return 1 // Moderate RPS from suspicious source -> JS Challenge
				}
				return 0 // Seamless for first visit even if suspicious (allows Check-host etc)
			}
		}

		// Fallback (no fingerprinting available yet)
		if p.shield.stats.IsUnderAttack {
			if state.RPS > limit {
				return 2 // Captcha during attack if RPS is high
			}
			return 1 // JS Challenge otherwise
		}
		if state.RPS > limit*2 {
			return 2 // Captcha for very high RPS
		}
		if state.RPS > limit {
			return 1 // JS Challenge for moderate RPS
		}
		return 0 // Truly seamless for first-time visitors when system is healthy
	}
	return 0
}

// hasValidProof checks if the request has a valid PoW proof cookie
func (p *Pipeline) hasValidProof(r *http.Request) bool {
	if p.shield != nil && p.shield.challMgr != nil {
		// Extract client IP
		ip := extractIP(r)
		return p.shield.challMgr.VerifyProof(r, ip)
	}
	return false
}

// getState gets or creates IP state
func (p *Pipeline) getState(ip string) *IPState {
	now := time.Now()
	v, loaded := p.ipStates.LoadOrStore(ip, &IPState{
		LastReset:  now,
		FirstSeen:  now,
		TrustScore: 50,
	})
	state := v.(*IPState)
	if loaded {
		state.mu.Lock()
		state.LastSeen = now
		state.mu.Unlock()
	}
	return state
}

// updateRPS updates the per-IP RPS counter
func (p *Pipeline) updateRPS(s *IPState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.TotalRequests++
	if now.Sub(s.LastReset) >= time.Second {
		s.RPS = 1
		s.LastReset = now
	} else {
		s.RPS++
	}
}

// getConnCount gets the active connection count for an IP
func (p *Pipeline) getConnCount(ip string) int {
	v, ok := p.connCount.Load(ip)
	if !ok {
		return 0
	}
	return v.(int)
}

// IncrementConnCount increments the active connection count for an IP
func (p *Pipeline) IncrementConnCount(ip string) int {
	v, _ := p.connCount.LoadOrStore(ip, 0)
	count := v.(int) + 1
	p.connCount.Store(ip, count)
	return count
}

// DecrementConnCount decrements the active connection count for an IP
func (p *Pipeline) DecrementConnCount(ip string) int {
	v, ok := p.connCount.Load(ip)
	if !ok {
		return 0
	}
	count := v.(int) - 1
	if count <= 0 {
		p.connCount.Delete(ip)
		return 0
	}
	p.connCount.Store(ip, count)
	return count
}

// isBanned checks if an IP is banned
func (p *Pipeline) isBanned(ip string) bool {
	v, ok := p.banned.Load(ip)
	if !ok {
		return false
	}
	expiry := v.(time.Time)
	if time.Now().After(expiry) {
		p.banned.Delete(ip)
		return false
	}
	return true
}

// isTrustedProxy checks if an IP belongs to trusted proxies (e.g. Cloudflare)
func (p *Pipeline) isTrustedProxy(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return false
	}

	for _, trusted := range p.cfg.Protection.TrustedProxies {
		if trusted == ipStr {
			return true
		}
		_, cidr, err := net.ParseCIDR(trusted)
		if err == nil && cidr.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// isWhitelisted checks if an IP is whitelisted (static or dynamic)
func (p *Pipeline) isWhitelisted(ip string) bool {
	if p.isTrustedProxy(ip) {
		return true
	}
	// Check static whitelist from config
	for _, w := range p.cfg.Protection.WhitelistIPs {
		if ip == w {
			return true
		}
	}

	// Check dynamic whitelist (passed challenges)
	v, ok := p.whitelist.Load(ip)
	if !ok {
		return false
	}
	expiry := v.(time.Time)
	if time.Now().After(expiry) {
		p.whitelist.Delete(ip)
		return false
	}
	return true
}

// CheckConnRate checks if an IP is opening connections too fast (CPS)
func (p *Pipeline) CheckConnRate(ip string) bool {
	if p.isTrustedProxy(ip) {
		return true
	}
	state := p.getState(ip)
	state.mu.Lock()
	defer state.mu.Unlock()

	now := time.Now()
	if now.Sub(state.ConnLastReset) >= time.Second {
		state.CPS = 1
		state.ConnLastReset = now
	} else {
		state.CPS++
	}

	// Connection Per Second (CPS) limit
	// Default: 20 CPS is suspicious for a single IP address
	if state.CPS > 20 {
		return false
	}
	return true
}

// BanIPLocal is called by engines locally to ban an IP and broadcast it to the mesh
func (p *Pipeline) BanIPLocal(ip string, duration time.Duration) {
	if p.isTrustedProxy(ip) || p.isWhitelisted(ip) {
		logger.Info("Refusing to ban trusted proxy or whitelisted IP", "ip", ip)
		return
	}
	p.banIP(ip, duration)

	// Broadcast to cluster mesh
	if mesh := cluster.GetMesh(); mesh != nil {
		mesh.BroadcastBan(ip, duration)
	}
}

// BanIPRemote is called by the Gossip network when another node bans an IP
func (p *Pipeline) BanIPRemote(ip string, duration time.Duration) {
	if p.isTrustedProxy(ip) || p.isWhitelisted(ip) {
		return
	}
	p.banIP(ip, duration)
}

// banIP bans an IP for a duration with high-performance kernel-level blocking
func (p *Pipeline) banIP(ip string, duration time.Duration) {
	if p.isTrustedProxy(ip) || p.isWhitelisted(ip) {
		logger.Info("Refusing to ban trusted proxy or whitelisted IP", "ip", ip)
		return
	}
	if _, already := p.banned.LoadOrStore(ip, time.Now().Add(duration)); !already {
		atomic.AddInt64(&p.shield.stats.BannedIPs, 1)
	} else {
		p.banned.Store(ip, time.Now().Add(duration))
	}
	logger.Info("IP banned", "ip", ip, "duration", duration)

	// 1. Unbeatable Hardware-level Drop (XDP / eBPF)
	if p.xdpMgr != nil && p.xdpMgr.Enabled {
		if err := p.xdpMgr.BanIP(ip); err != nil {
			logger.Warn("XDP Map insertion failed", "ip", ip, "err", err)
		}
	}

	if p.cfg.Protection.Ban.UseIptables {
		// Kernel-level blocking using ipset (fastest way for Linux)
		// ipset add mango_bans <ip> timeout <seconds>
		// We use timeout flag so ipset automatically cleans up old bans
		timeoutSec := int(duration.Seconds())
		go func() {
			cmd := exec.Command("ipset", "add", "mango_bans", ip, "timeout", fmt.Sprintf("%d", timeoutSec), "-exist")
			if err := cmd.Run(); err != nil {
				logger.Error("IPSet ban failed", "ip", ip, "error", err)
				// Fallback to simple iptables if ipset fails
				exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP").Run()
			}
		}()
	}
}

// WhitelistIP whitelists an IP for a duration
func (p *Pipeline) WhitelistIP(ip string, duration time.Duration) {
	p.whitelist.Store(ip, time.Now().Add(duration))
}

// Cleanup removes expired entries
func (p *Pipeline) Cleanup() {
	now := time.Now()
	p.banned.Range(func(key, value interface{}) bool {
		if now.After(value.(time.Time)) {
			ipStr := key.(string)
			p.banned.Delete(key)
			atomic.AddInt64(&p.shield.stats.BannedIPs, -1)
			if p.xdpMgr != nil && p.xdpMgr.Enabled {
				p.xdpMgr.UnbanIP(ipStr)
			}
		}
		return true
	})
	p.whitelist.Range(func(key, value interface{}) bool {
		if now.After(value.(time.Time)) {
			p.whitelist.Delete(key)
		}
		return true
	})

	p.ipStates.Range(func(key, value interface{}) bool {
		state := value.(*IPState)
		if now.Sub(state.LastSeen) > 10*time.Minute {
			p.ipStates.Delete(key)
		}
		return true
	})
}

func isStaticAsset(path string) bool {
	// Whitelist all /api/ endpoints (login, admin authentication, stats, etc.) so API calls NEVER return HTML Captchas
	if strings.HasPrefix(path, "/api/") || path == "/api" {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot":
		return true
	}
	return path == "/favicon.ico"
}
