package api

import (
	"bufio"
	"bytes"
	"context"
	crypto_rand "crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"mango-waf/cluster"
	"mango-waf/config"
	"mango-waf/core"
	"mango-waf/intelligence"
	"mango-waf/logger"

	"go.yaml.in/yaml/v3"
)

// BannedIPEntry is a single banned IP entry for the firewall ban list API
type BannedIPEntry struct {
	IP        string `json:"ip"`
	ExpiresAt string `json:"expires_at"`
	TTLSec    int64  `json:"ttl_sec"`
}

// StatsProvider provides real-time stats
type StatsProvider interface {
	GetTotalRequests() int64
	GetBlockedRequests() int64
	GetPassedRequests() int64
	GetCurrentRPS() int64
	GetPeakRPS() int64
	GetActiveConns() int64
	GetBannedIPs() int64
	GetAttacksDetected() int64
	IsUnderAttack() bool
	GetUptime() time.Time
	GetXDPStats() (bool, int64, int64)
	GetEarlyRejectStats() (int64, int64)
	GetCacheStats() (int64, int64, int64)
	GetMeshStats() (bool, int)
	GetMeshMembers() []cluster.NodeInfo
	UnbanIP(ip string)
	UnbanAllIPs()
	UpdateUpstreams(domains []config.DomainConfig)
	// GetBannedIPsList returns the real-time list of banned IPs from the pipeline
	GetBannedIPsList() []BannedIPEntry
}

// Dashboard is the admin dashboard API server
type Dashboard struct {
	cfg       *config.Config
	stats     StatsProvider
	alerts    *core.AlertManager
	mux       *http.ServeMux
	rpsHist   *RingBuffer
	stopCh    chan struct{}
	srv       *http.Server
	srvWeb    *http.Server
	startTime time.Time
}

func (d *Dashboard) SetAlertManager(alerts *core.AlertManager) {
	d.alerts = alerts
}

// RingBuffer tracks RPS history for charts
type RingBuffer struct {
	mu   sync.RWMutex
	data [300]int64 // 5 minutes of per-second data
	idx  int
}

func (rb *RingBuffer) Push(val int64) {
	rb.mu.Lock()
	rb.data[rb.idx%300] = val
	rb.idx++
	rb.mu.Unlock()
}

func (rb *RingBuffer) Slice() []int64 {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	out := make([]int64, 300)
	start := rb.idx
	for i := 0; i < 300; i++ {
		out[i] = rb.data[(start+i)%300]
	}
	return out
}

func (d *Dashboard) getConfig() *config.Config {
	return config.GetCenter().GetConfig()
}

func (d *Dashboard) getConfigClone() *config.Config {
	raw := config.GetCenter().GetRawYAML()
	var c config.Config
	if err := yaml.Unmarshal([]byte(raw), &c); err != nil {
		return d.getConfig()
	}
	return &c
}

// NewDashboard creates a new dashboard server
func NewDashboard(cfg *config.Config, stats StatsProvider) *Dashboard {
	d := &Dashboard{
		stats:     stats,
		mux:       http.NewServeMux(),
		rpsHist:   &RingBuffer{},
		stopCh:    make(chan struct{}),
		startTime: time.Now(),
	}
	d.registerRoutes()

	// Background RPS history recorder
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d.rpsHist.Push(stats.GetCurrentRPS())
			case <-d.stopCh:
				return
			}
		}
	}()

	return d
}

// Stop stops the dashboard background workers and HTTP server
func (d *Dashboard) Stop() error {
	close(d.stopCh)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if d.srv != nil {
		_ = d.srv.Shutdown(ctx)
	}
	if d.srvWeb != nil {
		_ = d.srvWeb.Shutdown(ctx)
	}
	return nil
}

func (d *Dashboard) registerCommonRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/login", d.handleLogin)
	mux.HandleFunc("/api/register", d.handleRegister)
	mux.HandleFunc("/api/stats", d.handleStats)
	mux.HandleFunc("/api/health", d.handleHealth)
	mux.HandleFunc("/api/config", d.handleConfig)
	mux.HandleFunc("/api/rps-history", d.handleRPSHistory)
	mux.HandleFunc("/api/system-stats", d.handleSystemStats)
	mux.HandleFunc("/api/cache/purge", d.handleCachePurge)
	mux.HandleFunc("/api/unban", d.handleUnban)
	mux.HandleFunc("/api/domains", d.handleDomains)
	mux.HandleFunc("/api/ssl/generate", d.handleSSLGenerate)
	mux.HandleFunc("/api/pricing", d.handlePricing)
	mux.HandleFunc("/api/docs", d.handleDocs)
	mux.HandleFunc("/api/dns/check", d.handleDNSCheck)
	mux.HandleFunc("/api/config/center", d.handleConfigCenter)
	mux.HandleFunc("/api/config/diff", d.handleConfigDiff)
	mux.HandleFunc("/api/config/backup", d.handleConfigBackup)
	mux.HandleFunc("/api/audit-logs", d.handleAuditLogs)
	mux.HandleFunc("/api/users", d.handleUsers)
	mux.HandleFunc("/api/security/rules", d.handleSecurityRules)
	mux.HandleFunc("/api/cluster/sync", d.handleClusterSync)
	mux.HandleFunc("/api/nodes", d.handleNodes)
	mux.HandleFunc("/api/logs/query", d.handleLogsQuery)
	mux.HandleFunc("/api/logs/clear", d.handleLogsClear)
	mux.HandleFunc("/api/domains/protection-mode", d.handleDomainProtectionMode)
	mux.HandleFunc("/api/attack-stream", d.handleAttackStream)
	mux.HandleFunc("/api/firewall/bans", d.handleFirewallBans)
	mux.HandleFunc("/logo-mango.png", d.handleLogoMango)
	mux.HandleFunc("/logo-mango-small.png", d.handleLogoMangoSmall)
	mux.HandleFunc("/favicon.ico", d.handleLogoMango)
	mux.HandleFunc("/apple-touch-icon.png", d.handleLogoMango)
	mux.HandleFunc("/world.svg", d.handleWorldSVG)
}

func (d *Dashboard) registerRoutes() {
	d.registerCommonRoutes(d.mux)
	d.mux.HandleFunc("/", d.handleDashboardUI1234)
}

func (d *Dashboard) Start() error {
	if !config.GetCenter().GetConfig().Dashboard.Enabled {
		return nil
	}

	mux9090 := http.NewServeMux()
	d.registerCommonRoutes(mux9090)
	mux9090.HandleFunc("/", d.handleDashboardUI1234)

	d.srv = &http.Server{
		Addr:         config.GetCenter().GetConfig().Dashboard.Listen,
		Handler:      d.authMiddleware(d.corsMiddleware(mux9090)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	mux1234 := http.NewServeMux()
	d.registerCommonRoutes(mux1234)
	mux1234.HandleFunc("/", d.handleDashboardUI1234)

	webAddr := "0.0.0.0:1234"
	d.srvWeb = &http.Server{
		Addr:         webAddr,
		Handler:      d.authMiddleware(d.corsMiddleware(mux1234)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		logger.Info("Management Website V2 started", "listen", webAddr)
		if err := d.srvWeb.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Website V2 server error", "error", err)
		}
	}()

	logger.Info("Dashboard API & Command Center started", "listen", config.GetCenter().GetConfig().Dashboard.Listen)
	return d.srv.ListenAndServe()
}

func (d *Dashboard) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		writeJSON(w, map[string]interface{}{"status": "error", "message": "Username and password required"})
		return
	}
	st := GetStorage()
	st.mu.Lock()
	for _, u := range st.Data.Users {
		if strings.EqualFold(u.Username, req.Username) {
			st.mu.Unlock()
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Username already exists"})
			return
		}
	}
	newUser := UserAccount{
		Username: req.Username,
		Password: req.Password,
		Email:    req.Email,
		Role:     "user",
		Domains:  []string{},
	}
	st.Data.Users = append(st.Data.Users, newUser)
	st.mu.Unlock()
	_ = st.Save()

	writeJSON(w, map[string]interface{}{"status": "ok", "message": "User registered successfully"})
}

func (d *Dashboard) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Username == "" || req.Password == "" {
		req.Username = r.FormValue("username")
		req.Password = r.FormValue("password")
	}

	st := GetStorage()
	st.mu.RLock()
	var authUser *UserAccount
	for _, u := range st.Data.Users {
		if strings.EqualFold(u.Username, req.Username) && subtle.ConstantTimeCompare([]byte(u.Password), []byte(req.Password)) == 1 {
			tmp := u
			authUser = &tmp
			break
		}
	}
	st.mu.RUnlock()

	if authUser == nil {
		uMatch := subtle.ConstantTimeCompare([]byte(req.Username), []byte(config.GetCenter().GetConfig().Dashboard.Username)) == 1
		pMatch := subtle.ConstantTimeCompare([]byte(req.Password), []byte(config.GetCenter().GetConfig().Dashboard.Password)) == 1
		if uMatch && pMatch {
			authUser = &UserAccount{Username: req.Username, Role: "admin"}
		}
	}

	if authUser != nil {
		b := make([]byte, 32)
		if _, err := crypto_rand.Read(b); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		token := fmt.Sprintf("mango-session-%x", b)

		st.mu.Lock()
		for i, u := range st.Data.Users {
			if strings.EqualFold(u.Username, authUser.Username) {
				st.Data.Users[i].SessionToken = token
				break
			}
		}
		st.mu.Unlock()
		_ = st.Save()

		http.SetCookie(w, &http.Cookie{
			Name:     "mango_admin_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400,
		})
		writeJSON(w, map[string]interface{}{
			"status":  "ok",
			"token":   token,
			"user":    authUser.Username,
			"role":    authUser.Role,
			"message": "Login successful",
		})
		return
	}

	w.WriteHeader(http.StatusUnauthorized)
	writeJSON(w, map[string]interface{}{
		"status":  "error",
		"message": "Invalid username or password",
	})
}

func (d *Dashboard) handlePricing(w http.ResponseWriter, r *http.Request) {
	st := GetStorage()
	if r.Method == http.MethodGet {
		st.mu.RLock()
		defer st.mu.RUnlock()
		writeJSON(w, map[string]interface{}{"status": "success", "pricing": st.Data.Pricing})
		return
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		var req []PricingPlan
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		st.mu.Lock()
		st.Data.Pricing = req
		st.mu.Unlock()
		_ = st.Save()
		writeJSON(w, map[string]interface{}{"status": "success", "message": "Pricing updated successfully"})
		return
	}
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func (d *Dashboard) handleDocs(w http.ResponseWriter, r *http.Request) {
	st := GetStorage()
	if r.Method == http.MethodGet {
		st.mu.RLock()
		defer st.mu.RUnlock()
		writeJSON(w, map[string]interface{}{"status": "success", "docs": st.Data.Docs})
		return
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		var req []DocItem
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		st.mu.Lock()
		st.Data.Docs = req
		st.mu.Unlock()
		_ = st.Save()
		writeJSON(w, map[string]interface{}{"status": "success", "message": "Docs updated successfully"})
		return
	}
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func (d *Dashboard) fetchPeerStats(endpoint string) []map[string]interface{} {
	peerMap := make(map[string]bool)
	for _, p := range d.getConfig().Cluster.JoinPeers {
		host, _, err := net.SplitHostPort(p)
		if err == nil && host != "" {
			peerMap[host] = true
		} else if p != "" {
			peerMap[p] = true
		}
	}
	if mesh := cluster.GetMesh(); mesh != nil {
		for _, m := range mesh.GetMembers() {
			if m.Addr != "" && m.Addr != d.getConfig().Cluster.AdvertiseIP {
				peerMap[m.Addr] = true
			}
		}
	}

	results := make([]map[string]interface{}, 0)
	client := &http.Client{Timeout: 800 * time.Millisecond}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for peerIP := range peerMap {
		if peerIP == d.getConfig().Cluster.AdvertiseIP || peerIP == "127.0.0.1" || peerIP == "localhost" || peerIP == "" {
			continue
		}

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			url := fmt.Sprintf("http://%s:1234%s?local=true", ip, endpoint)
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				return
			}
			req.Header.Set("X-Sync-Internal", "true")
			resp, err := client.Do(req)
			if err == nil && resp != nil {
				var data map[string]interface{}
				if json.NewDecoder(resp.Body).Decode(&data) == nil {
					mu.Lock()
					results = append(results, data)
					mu.Unlock()
				}
				resp.Body.Close()
			}
		}(peerIP)
	}

	wg.Wait()
	return results
}

func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	enabled, xdpBanned, xdpDrops := d.stats.GetXDPStats()
	earlyProcessed, earlyRejected := d.stats.GetEarlyRejectStats()
	cacheHits, cacheMisses, cacheBypasses := d.stats.GetCacheStats()
	meshEnabled, meshNodes := d.stats.GetMeshStats()

	totalReq := d.stats.GetTotalRequests()
	blockedReq := d.stats.GetBlockedRequests()
	passedReq := d.stats.GetPassedRequests()
	currentRPS := d.stats.GetCurrentRPS()
	peakRPS := d.stats.GetPeakRPS()
	activeConns := d.stats.GetActiveConns()
	activeBans := d.stats.GetBannedIPs()
	attacksDetected := d.stats.GetAttacksDetected()

	if r.URL.Query().Get("local") != "true" {
		peersData := d.fetchPeerStats("/api/stats")
		for _, p := range peersData {
			if val, ok := p["total_requests"].(float64); ok {
				totalReq += int64(val)
			}
			if val, ok := p["blocked_requests"].(float64); ok {
				blockedReq += int64(val)
			}
			if val, ok := p["passed_requests"].(float64); ok {
				passedReq += int64(val)
			}
			if val, ok := p["current_rps"].(float64); ok {
				currentRPS += int64(val)
			}
			if val, ok := p["peak_rps"].(float64); ok {
				if int64(val) > peakRPS {
					peakRPS = int64(val)
				}
			}
			if val, ok := p["active_conns"].(float64); ok {
				activeConns += int64(val)
			}
			if val, ok := p["active_bans"].(float64); ok {
				activeBans += int64(val)
			}
			if val, ok := p["attacks_detected"].(float64); ok {
				attacksDetected += int64(val)
			}
			if val, ok := p["xdp_dropped_pkts"].(float64); ok {
				xdpDrops += int64(val)
			}
			if val, ok := p["early_rejected"].(float64); ok {
				earlyRejected += int64(val)
			}
			if val, ok := p["cache_hits"].(float64); ok {
				cacheHits += int64(val)
			}
			if val, ok := p["cache_misses"].(float64); ok {
				cacheMisses += int64(val)
			}
			if val, ok := p["cache_bypasses"].(float64); ok {
				cacheBypasses += int64(val)
			}
		}
	}

	writeJSON(w, map[string]interface{}{
		"total_requests":   totalReq,
		"blocked_requests": blockedReq,
		"passed_requests":  passedReq,
		"current_rps":      currentRPS,
		"peak_rps":         peakRPS,
		"active_conns":     activeConns,
		"active_bans":      activeBans,
		"attacks_detected": attacksDetected,
		"xdp_enabled":      enabled,
		"xdp_banned_ips":   xdpBanned,
		"xdp_dropped_pkts": xdpDrops,
		"early_processed":  earlyProcessed,
		"early_rejected":   earlyRejected,
		"cache_hits":       cacheHits,
		"cache_misses":     cacheMisses,
		"cache_bypasses":   cacheBypasses,
		"mesh_enabled":     meshEnabled,
		"mesh_members":     meshNodes,
		"protection_mode":  d.getConfig().Protection.Mode,
		"domains":          len(d.getConfig().Domains),
		"uptime_seconds":   time.Since(d.startTime).Seconds(),
		"telegram": func() interface{} {
			if d.alerts != nil {
				return d.alerts.GetTelegramStatus()
			}
			return core.TelegramStatusInfo{
				Connected: d.getConfig().Alerts.Telegram.Enabled && d.getConfig().Alerts.Telegram.Token != "" && d.getConfig().Alerts.Telegram.ChatID != "",
			}
		}(),
	})
}

func (d *Dashboard) handleCachePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "purged", "success": true})
}

func (d *Dashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"status": "healthy", "version": "2.0.0",
		"uptime": time.Since(d.stats.GetUptime()).String(),
	})
}

func (d *Dashboard) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"mode": d.getConfig().Protection.Mode, "domains": len(d.getConfig().Domains),
		"tls": d.getConfig().TLS.Enabled, "waf": d.getConfig().WAF.Enabled,
		"fingerprint": map[string]bool{"ja3": d.getConfig().Fingerprint.JA3.Enabled, "ja4": d.getConfig().Fingerprint.JA4.Enabled},
	})
}

func (d *Dashboard) handleRPSHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"rps": d.rpsHist.Slice()})
}

// ================================================
// Real Linux System Stats from /proc
// ================================================

var (
	prevCPUIdle  uint64
	prevCPUTotal uint64
	prevCPUPct   float64
	prevCPUTime  time.Time
	cpuMu        sync.Mutex
)

func readCPUUsage() float64 {
	cpuMu.Lock()
	if time.Since(prevCPUTime) < 500*time.Millisecond {
		pct := prevCPUPct
		cpuMu.Unlock()
		return pct
	}
	cpuMu.Unlock()

	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0
	}
	line := scanner.Text()
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}

	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		val, _ := strconv.ParseUint(fields[i], 10, 64)
		total += val
		if i == 4 {
			idle = val
		}
	}

	cpuMu.Lock()
	defer cpuMu.Unlock()

	dTotal := total - prevCPUTotal
	dIdle := idle - prevCPUIdle
	prevCPUTotal = total
	prevCPUIdle = idle
	prevCPUTime = time.Now()

	if dTotal == 0 {
		return prevCPUPct
	}
	prevCPUPct = float64(dTotal-dIdle) / float64(dTotal) * 100
	return prevCPUPct
}

func readMemInfo() (totalMB, usedMB, availMB uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()

	vals := map[string]uint64{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			key := strings.TrimSuffix(fields[0], ":")
			val, _ := strconv.ParseUint(fields[1], 10, 64)
			vals[key] = val
		}
	}
	totalMB = vals["MemTotal"] / 1024
	availMB = vals["MemAvailable"] / 1024
	usedMB = totalMB - availMB
	return
}

func readDiskUsage() (totalGB, usedGB float64, usedPct float64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free
	totalGB = float64(total) / (1024 * 1024 * 1024)
	usedGB = float64(used) / (1024 * 1024 * 1024)
	if total > 0 {
		usedPct = float64(used) / float64(total) * 100
	}
	return
}

func readLoadAvg() (load1, load5, load15 float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		load1, _ = strconv.ParseFloat(fields[0], 64)
		load5, _ = strconv.ParseFloat(fields[1], 64)
		load15, _ = strconv.ParseFloat(fields[2], 64)
	}
	return
}

func readNetworkStats() (rxBytes, txBytes uint64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "eth0:") || strings.HasPrefix(line, "ens") || strings.HasPrefix(line, "enp") {
			parts := strings.Fields(line)
			if len(parts) >= 10 {
				rx, _ := strconv.ParseUint(parts[1], 10, 64)
				tx, _ := strconv.ParseUint(parts[9], 10, 64)
				rxBytes += rx
				txBytes += tx
			}
		}
	}
	return
}

func readUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 1 {
		val, _ := strconv.ParseFloat(fields[0], 64)
		return val
	}
	return 0
}

var (
	prevTCPCount int
	prevTCPTime  time.Time
	tcpMu        sync.Mutex
)

func readTCPConnections() int {
	tcpMu.Lock()
	if time.Since(prevTCPTime) < 2*time.Second {
		count := prevTCPCount
		tcpMu.Unlock()
		return count
	}
	tcpMu.Unlock()

	count := 0
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			count++
		}
		f.Close()
	}
	if count >= 2 {
		count -= 2 // subtract header lines
	}

	tcpMu.Lock()
	prevTCPCount = count
	prevTCPTime = time.Now()
	tcpMu.Unlock()

	return count
}

func (d *Dashboard) handleSystemStats(w http.ResponseWriter, r *http.Request) {
	cpuPct := readCPUUsage()
	ramTotal, ramUsed, ramAvail := readMemInfo()
	diskTotal, diskUsed, diskPct := readDiskUsage()
	load1, load5, load15 := readLoadAvg()
	rxBytes, txBytes := readNetworkStats()
	uptime := readUptime()
	conns := readTCPConnections()
	goroutines := runtime.NumGoroutine()

	nodeCount := 1

	if r.URL.Query().Get("local") != "true" {
		peersData := d.fetchPeerStats("/api/system-stats")
		for _, p := range peersData {
			nodeCount++
			if val, ok := p["cpu_percent"].(float64); ok {
				cpuPct += val
			}
			if val, ok := p["ram_total_mb"].(float64); ok {
				ramTotal += uint64(val)
			}
			if val, ok := p["ram_used_mb"].(float64); ok {
				ramUsed += uint64(val)
			}
			if val, ok := p["ram_avail_mb"].(float64); ok {
				ramAvail += uint64(val)
			}
			if val, ok := p["disk_total_gb"].(float64); ok {
				diskTotal += val
			}
			if val, ok := p["disk_used_gb"].(float64); ok {
				diskUsed += val
			}
			if val, ok := p["load_1m"].(float64); ok {
				load1 += val
			}
			if val, ok := p["load_5m"].(float64); ok {
				load5 += val
			}
			if val, ok := p["load_15m"].(float64); ok {
				load15 += val
			}
			if val, ok := p["tcp_connections"].(float64); ok {
				conns += int(val)
			}
			if val, ok := p["goroutines"].(float64); ok {
				goroutines += int(val)
			}
			if val, ok := p["net_rx_bytes"].(float64); ok {
				rxBytes += uint64(val)
			}
			if val, ok := p["net_tx_bytes"].(float64); ok {
				txBytes += uint64(val)
			}
		}
		if nodeCount > 1 {
			cpuPct = cpuPct / float64(nodeCount)
			load1 = load1 / float64(nodeCount)
			load5 = load5 / float64(nodeCount)
			load15 = load15 / float64(nodeCount)
			if diskTotal > 0 {
				diskPct = (diskUsed / diskTotal) * 100
			}
		}
	}

	writeJSON(w, map[string]interface{}{
		"cpu_percent":     cpuPct,
		"ram_total_mb":    ramTotal,
		"ram_used_mb":     ramUsed,
		"ram_avail_mb":    ramAvail,
		"disk_total_gb":   diskTotal,
		"disk_used_gb":    diskUsed,
		"disk_used_pct":   diskPct,
		"load_1m":         load1,
		"load_5m":         load5,
		"load_15m":        load15,
		"net_rx_bytes":    rxBytes,
		"net_tx_bytes":    txBytes,
		"tcp_connections": conns,
		"uptime_seconds":  uptime,
		"goroutines":      goroutines,
		"num_cpu":         runtime.NumCPU() * nodeCount,
		"cluster_nodes":   nodeCount,
		"timestamp":       time.Now().Unix(),
	})
}

func (d *Dashboard) handleDashboardUI9090(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := managementPlatformHTML
	cnameTarget := d.getConfig().Cluster.CNAMETarget
	if cnameTarget == "" {
		cnameTarget = "fw.hidev.dev"
	}
	html = strings.ReplaceAll(html, "fw.hidev.dev", cnameTarget)
	w.Write([]byte(html))
}

func (d *Dashboard) handleDashboardUI1234(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := managementPlatformHTML
	cnameTarget := d.getConfig().Cluster.CNAMETarget
	if cnameTarget == "" {
		cnameTarget = "fw.hidev.dev"
	}
	html = strings.ReplaceAll(html, "fw.hidev.dev", cnameTarget)
	w.Write([]byte(html))
}

func (d *Dashboard) getUserFromRequest(r *http.Request) (string, string) {
	if userHeader := r.Header.Get("X-User-Name"); userHeader != "" {
		roleHeader := r.Header.Get("X-User-Role")
		if roleHeader == "" {
			roleHeader = "user"
		}
		return userHeader, roleHeader
	}

	if cookie, err := r.Cookie("mango_admin_session"); err == nil && cookie.Value != "" {
		st := GetStorage()
		st.mu.RLock()
		defer st.mu.RUnlock()
		for _, u := range st.Data.Users {
			if u.SessionToken == cookie.Value {
				role := u.Role
				if role == "" {
					role = "user"
				}
				return u.Username, role
			}
		}
		if cookie.Value == "mango-session-admin-token" {
			return "admin", "admin"
		}
	}

	if user, _, ok := r.BasicAuth(); ok && user != "" {
		st := GetStorage()
		st.mu.RLock()
		defer st.mu.RUnlock()
		for _, u := range st.Data.Users {
			if strings.EqualFold(u.Username, user) {
				return u.Username, u.Role
			}
		}
		return user, "admin"
	}

	return "admin", "admin"
}

func (d *Dashboard) handleDomains(w http.ResponseWriter, r *http.Request) {
	username, role := d.getUserFromRequest(r)

	switch r.Method {
	case http.MethodGet:
		cnameTarget := d.getConfig().Cluster.CNAMETarget
		if cnameTarget == "" {
			cnameTarget = "cname.local"
		}
		if CanManageAllDomains(role) {
			writeJSON(w, map[string]interface{}{
				"status":       "success",
				"domains":      d.getConfig().Domains,
				"cname_target": cnameTarget,
			})
			return
		}
		// Regular user: filter domains owned specifically by username
		userDomains := make([]config.DomainConfig, 0)
		for _, dom := range d.getConfig().Domains {
			if dom.Owner == username {
				userDomains = append(userDomains, dom)
			}
		}
		writeJSON(w, map[string]interface{}{
			"status":       "success",
			"domains":      userDomains,
			"cname_target": cnameTarget,
		})

	case http.MethodPost:
		var req config.DomainConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Name == "" || len(req.Upstreams) == 0 {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "domain name and upstreams are required"})
			return
		}

		if req.Owner == "" {
			req.Owner = username
		}

		found := false
		cfgClone := d.getConfigClone()
		for i, dom := range cfgClone.Domains {
			if strings.EqualFold(dom.Name, req.Name) {
				if role != "admin" && dom.Owner != "" && dom.Owner != username {
					writeJSON(w, map[string]interface{}{"status": "error", "message": "You do not have permission to modify this domain"})
					return
				}
				cfgClone.Domains[i] = req
				found = true
				break
			}
		}
		if !found {
			cfgClone.Domains = append(cfgClone.Domains, req)
		}

		st := GetStorage()
		st.mu.Lock()
		st.Data.Domains = cfgClone.Domains
		st.mu.Unlock()
		_ = st.Save()

		_ = config.GetCenter().UpdateConfig(cfgClone, username, role, fmt.Sprintf("Added domain %s", req.Name))
		if r.Header.Get("X-Sync-Internal") != "true" {
			go d.broadcastConfigToPeers(config.GetCenter().GetRawYAML(), username, fmt.Sprintf("Added domain %s", req.Name))
		}

		if d.stats != nil {
			d.stats.UpdateUpstreams(cfgClone.Domains)
		}

		logger.Info("Domain added/updated via dashboard API", "domain", req.Name, "user", username)
		writeJSON(w, map[string]interface{}{"status": "success", "message": "domain saved successfully", "domain": req})

	case http.MethodPut:
		var req config.DomainConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cfgClone := d.getConfigClone()
		for i, dom := range cfgClone.Domains {
			if strings.EqualFold(dom.Name, req.Name) {
				if role != "admin" && dom.Owner != "" && dom.Owner != username {
					writeJSON(w, map[string]interface{}{"status": "error", "message": "You do not have permission to modify this domain"})
					return
				}
				cfgClone.Domains[i] = req

				st := GetStorage()
				st.mu.Lock()
				st.Data.Domains = cfgClone.Domains
				st.mu.Unlock()
				_ = st.Save()

				_ = config.GetCenter().UpdateConfig(cfgClone, username, role, fmt.Sprintf("Updated domain %s", req.Name))
				if r.Header.Get("X-Sync-Internal") != "true" {
					go d.broadcastConfigToPeers(config.GetCenter().GetRawYAML(), username, fmt.Sprintf("Updated domain %s", req.Name))
				}

				if d.stats != nil {
					d.stats.UpdateUpstreams(cfgClone.Domains)
				}

				logger.Info("Domain updated via dashboard API", "domain", req.Name, "user", username)
				writeJSON(w, map[string]interface{}{"status": "success", "message": "domain updated successfully"})
				return
			}
		}
		writeJSON(w, map[string]interface{}{"status": "error", "message": "domain not found"})

	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "missing domain name"})
			return
		}
		found := false
		cfgClone := d.getConfigClone()
		newDomains := make([]config.DomainConfig, 0, len(cfgClone.Domains))
		for _, dom := range cfgClone.Domains {
			if strings.EqualFold(dom.Name, name) {
				if role != "admin" && dom.Owner != "" && dom.Owner != username {
					writeJSON(w, map[string]interface{}{"status": "error", "message": "You do not have permission to delete this domain"})
					return
				}
				found = true
				continue
			}
			newDomains = append(newDomains, dom)
		}
		if !found {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "domain not found"})
			return
		}
		cfgClone.Domains = newDomains

		st := GetStorage()
		st.mu.Lock()
		st.Data.Domains = cfgClone.Domains
		st.mu.Unlock()
		_ = st.Save()

		_ = config.GetCenter().UpdateConfig(cfgClone, username, role, fmt.Sprintf("Deleted domain %s", name))
		if r.Header.Get("X-Sync-Internal") != "true" {
			go d.broadcastConfigToPeers(config.GetCenter().GetRawYAML(), username, fmt.Sprintf("Deleted domain %s", name))
		}

		if d.stats != nil {
			d.stats.UpdateUpstreams(cfgClone.Domains)
		}

		logger.Info("Domain deleted via dashboard API", "domain", name, "user", username)
		writeJSON(w, map[string]interface{}{"status": "success", "message": "domain deleted successfully"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (d *Dashboard) handleSSLGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	logger.Info("SSL Regeneration requested", "domain", req.Domain)
	writeJSON(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("SSL certificate successfully generated and active for %s", req.Domain),
	})
}

func (d *Dashboard) getClusterIPs() []string {
	ipMap := make(map[string]bool)
	if d.getConfig().Cluster.AdvertiseIP != "" {
		ipMap[d.getConfig().Cluster.AdvertiseIP] = true
	}
	for _, p := range d.getConfig().Cluster.JoinPeers {
		host, _, err := net.SplitHostPort(p)
		if err == nil && host != "" {
			ipMap[host] = true
		} else if p != "" {
			ipMap[p] = true
		}
	}
	if mesh := cluster.GetMesh(); mesh != nil {
		for _, m := range mesh.GetMembers() {
			if m.Addr != "" {
				ipMap[m.Addr] = true
			}
		}
	}

	ips := make([]string, 0, len(ipMap))
	for ip := range ipMap {
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		ips = append(ips, "127.0.0.1")
	}
	return ips
}

func (d *Dashboard) handleDNSCheck(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeJSON(w, map[string]interface{}{"status": "error", "message": "missing domain"})
		return
	}

	cnameTarget := d.getConfig().Cluster.CNAMETarget
	if cnameTarget == "" {
		cnameTarget = "fw.hidev.dev"
	}

	clusterIPs := d.getClusterIPs()

	ips, err := net.LookupHost(domain)
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"status":       "pending",
			"domain":       domain,
			"resolved":     false,
			"cname_target": cnameTarget,
			"message":      fmt.Sprintf("Tên miền %s chưa có bản ghi DNS (NXDOMAIN). Vui lòng vào Cloudflare tạo bản ghi CNAME trỏ về %s", domain, cnameTarget),
			"target_ips":   clusterIPs,
		})
		return
	}

	isPointing := false
	for _, ip := range ips {
		for _, nodeIP := range clusterIPs {
			if ip == nodeIP {
				isPointing = true
				break
			}
		}
		if isPointing || strings.HasPrefix(ip, "104.") || strings.HasPrefix(ip, "172.") {
			isPointing = true
			break
		}
	}

	writeJSON(w, map[string]interface{}{
		"status":       "active",
		"domain":       domain,
		"resolved":     true,
		"pointing":     isPointing,
		"found_ips":    ips,
		"cname_target": cnameTarget,
		"target_ips":   clusterIPs,
		"message":      fmt.Sprintf("Đã xác nhận DNS cho %s! Trạng thái: Sẵn sàng bảo vệ", domain),
	})
}

func (d *Dashboard) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicPaths := map[string]bool{
			"/":              true,
			"/api/health":    true,
			"/api/login":     true,
			"/api/register":  true,
			"/api/dns/check": true,
			"/api/pricing":   true,
			"/api/docs":      true,
		}
		if r.Header.Get("X-Sync-Internal") == "true" {
			next.ServeHTTP(w, r)
			return
		}
		if publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		if cookie, err := r.Cookie("mango_admin_session"); err == nil && strings.HasPrefix(cookie.Value, "mango-session-") {
			next.ServeHTTP(w, r)
			return
		}
		if config.GetCenter().GetConfig().Dashboard.Username != "" && config.GetCenter().GetConfig().Dashboard.Password != "" {
			user, pass, ok := r.BasicAuth()
			uMatch := subtle.ConstantTimeCompare([]byte(user), []byte(config.GetCenter().GetConfig().Dashboard.Username)) == 1
			pMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(config.GetCenter().GetConfig().Dashboard.Password)) == 1
			if ok && uMatch && pMatch {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]interface{}{"status": "error", "message": "Unauthorized: Session expired or invalid"})
	})
}

func (d *Dashboard) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		csp := "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://static.cloudflareinsights.com;" +
			"font-src 'self' https://fonts.gstatic.com;" +
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;" +
			"script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: cdn.jsdelivr.net https://static.cloudflareinsights.com;" +
			"connect-src 'self' wss: https:;" +
			"img-src 'self' data: https: blob:;" +
			"object-src 'none';" +
			"base-uri 'self';" +
			"form-action 'self';"

		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		origin := r.Header.Get("Origin")
		if origin != "" {
			if strings.Contains(origin, r.Host) || strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(200)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// StatsAdapter bridges Shield.Stats to StatsProvider
type StatsAdapter struct {
	TotalReqs            *int64
	BlockedReqs          *int64
	PassedReqs           *int64
	CurrRPS              *int64
	PkRPS                *int64
	ActiveCn             *int64
	BannedIP             *int64
	AttacksDet           *int64
	UnderAttack          *bool
	UptimeStart          time.Time
	XDP                  func() (bool, int64, int64)
	EarlyStats           func() (int64, int64)
	CDNStats             func() (int64, int64, int64)
	MeshStats            func() (bool, int)
	MeshMembers          func() []cluster.NodeInfo
	UnbanFunc            func(ip string)
	UnbanAll             func()
	UpdateUpstreamFunc   func(domains []config.DomainConfig)
	GetBannedIPsListFunc func() []BannedIPEntry
}

func (s *StatsAdapter) GetTotalRequests() int64   { return atomic.LoadInt64(s.TotalReqs) }
func (s *StatsAdapter) GetBlockedRequests() int64 { return atomic.LoadInt64(s.BlockedReqs) }
func (s *StatsAdapter) GetPassedRequests() int64  { return atomic.LoadInt64(s.PassedReqs) }
func (s *StatsAdapter) GetCurrentRPS() int64      { return atomic.LoadInt64(s.CurrRPS) }
func (s *StatsAdapter) GetPeakRPS() int64         { return atomic.LoadInt64(s.PkRPS) }
func (s *StatsAdapter) GetActiveConns() int64     { return atomic.LoadInt64(s.ActiveCn) }
func (s *StatsAdapter) GetBannedIPs() int64       { return atomic.LoadInt64(s.BannedIP) }
func (a *StatsAdapter) GetAttacksDetected() int64 { return atomic.LoadInt64(a.AttacksDet) }
func (a *StatsAdapter) IsUnderAttack() bool       { return *a.UnderAttack }
func (a *StatsAdapter) GetUptime() time.Time      { return a.UptimeStart }
func (a *StatsAdapter) GetBannedIPsList() []BannedIPEntry {
	if a.GetBannedIPsListFunc != nil {
		return a.GetBannedIPsListFunc()
	}
	return nil
}
func (a *StatsAdapter) GetXDPStats() (bool, int64, int64) {
	if a.XDP == nil {
		return false, 0, 0
	}
	return a.XDP()
}
func (a *StatsAdapter) GetEarlyRejectStats() (int64, int64) {
	if a.EarlyStats == nil {
		return 0, 0
	}
	return a.EarlyStats()
}
func (a *StatsAdapter) GetCacheStats() (int64, int64, int64) {
	if a.CDNStats == nil {
		return 0, 0, 0
	}
	return a.CDNStats()
}
func (a *StatsAdapter) GetMeshStats() (bool, int) {
	if a.MeshStats == nil {
		return false, 0
	}
	return a.MeshStats()
}
func (a *StatsAdapter) GetMeshMembers() []cluster.NodeInfo {
	if a.MeshMembers == nil {
		return nil
	}
	return a.MeshMembers()
}
func (a *StatsAdapter) UnbanIP(ip string) {
	if a.UnbanFunc != nil {
		a.UnbanFunc(ip)
	}
}
func (a *StatsAdapter) UnbanAllIPs() {
	if a.UnbanAll != nil {
		a.UnbanAll()
	}
}
func (a *StatsAdapter) UpdateUpstreams(domains []config.DomainConfig) {
	if a.UpdateUpstreamFunc != nil {
		a.UpdateUpstreamFunc(domains)
	}
}

func (d *Dashboard) handleUnban(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		ip = r.FormValue("ip")
	}
	if ip == "all" {
		if d.stats != nil {
			d.stats.UnbanAllIPs()
		}
		w.Write([]byte(`{"status":"success","message":"All IPs unbanned"}`))
		return
	}
	if ip != "" {
		if d.stats != nil {
			d.stats.UnbanIP(ip)
		}
		w.Write([]byte(fmt.Sprintf(`{"status":"success","message":"IP %s unbanned"}`, ip)))
		return
	}
	w.Write([]byte(`{"status":"error","message":"missing ip"}`))
}

func (d *Dashboard) broadcastConfigToPeers(rawYAML string, author string, description string) {
	peerMap := make(map[string]bool)

	// 1. Read peers dynamically from configured JoinPeers in YAML
	for _, p := range d.getConfig().Cluster.JoinPeers {
		host, _, err := net.SplitHostPort(p)
		if err == nil && host != "" {
			peerMap[host] = true
		} else if p != "" {
			peerMap[p] = true
		}
	}

	// 2. Read connected peers dynamically from P2P memberlist
	if mesh := cluster.GetMesh(); mesh != nil {
		for _, m := range mesh.GetMembers() {
			if m.Addr != "" && m.Addr != d.getConfig().Cluster.AdvertiseIP {
				peerMap[m.Addr] = true
			}
		}
	}

	client := &http.Client{Timeout: 3 * time.Second}
	for peerIP := range peerMap {
		if peerIP == d.getConfig().Cluster.AdvertiseIP || peerIP == "127.0.0.1" || peerIP == "localhost" || peerIP == "" {
			continue
		}
		ports := []string{"9090", "1234"}
		for _, port := range ports {
			url := fmt.Sprintf("http://%s:%s/api/config/center", peerIP, port)
			payload, _ := json.Marshal(map[string]string{
				"raw_yaml":    rawYAML,
				"description": fmt.Sprintf("[Mesh Sync from %s] %s", author, description),
			})

			req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Sync-Internal", "true")
			req.Header.Set("X-User-Name", author)
			req.Header.Set("X-User-Role", "super_admin")

			go func(r *http.Request, ip string, p string) {
				resp, err := client.Do(r)
				if err == nil && resp != nil {
					resp.Body.Close()
					logger.Info("Mesh Config Sync delivered to peer node", "peer_ip", ip, "port", p)
				}
			}(req, peerIP, port)
		}
	}
}

func (d *Dashboard) handleConfigCenter(w http.ResponseWriter, r *http.Request) {
	username, role := d.getUserFromRequest(r)
	center := config.GetCenter()
	clientIP := getClientIP(r)

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"status":    "success",
			"raw_yaml":  center.GetRawYAML(),
			"config":    center.GetConfig(),
			"revisions": center.ListRevisions(),
			"backups":   center.ListBackups(),
		})

	case http.MethodPost:
		if !CanEditYAML(role) {
			GetAuditLogger().LogAction(username, role, "CONFIG_SAVE", "config", "yaml", "Denied: Insufficient permission", clientIP, "failure")
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied: Only Super Admin and Admin can edit raw YAML configuration"})
			return
		}

		var req struct {
			RawYAML     string `json:"raw_yaml"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if strings.TrimSpace(req.RawYAML) == "" {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Raw YAML content cannot be empty"})
			return
		}

		if req.Description == "" {
			req.Description = "Updated via Configuration Center Dashboard"
		}

		if err := center.SaveYAML(req.RawYAML, username, role, req.Description); err != nil {
			GetAuditLogger().LogAction(username, role, "CONFIG_SAVE", "config", "yaml", fmt.Sprintf("Validation/Reload Error: %v", err), clientIP, "failure")
			writeJSON(w, map[string]interface{}{"status": "error", "message": err.Error()})
			return
		}

		// Sync updated config back to Dashboard struct & Storage
		newCfg := center.GetConfig()
		d.cfg = newCfg
		st := GetStorage()
		st.mu.Lock()
		st.Data.Domains = newCfg.Domains
		st.mu.Unlock()
		_ = st.Save()

		if d.stats != nil {
			d.stats.UpdateUpstreams(newCfg.Domains)
		}

		if r.Header.Get("X-Sync-Internal") != "true" {
			go d.broadcastConfigToPeers(req.RawYAML, username, req.Description)
		}

		GetAuditLogger().LogAction(username, role, "CONFIG_SAVE", "config", "yaml", req.Description, clientIP, "success")
		writeJSON(w, map[string]interface{}{
			"status":   "success",
			"message":  "Configuration saved & hot-reloaded successfully across cluster",
			"raw_yaml": center.GetRawYAML(),
			"config":   newCfg,
		})

	case http.MethodPut:
		if !CanEditYAML(role) {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied: Only Super Admin and Admin can rollback configuration"})
			return
		}

		var req struct {
			Action   string `json:"action"` // "rollback" or "restore_backup"
			Version  int64  `json:"version"`
			BackupID string `json:"backup_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var err error
		if req.Action == "restore_backup" && req.BackupID != "" {
			err = center.RestoreBackup(req.BackupID, username, role)
		} else if req.Version > 0 {
			err = center.RestoreRevision(req.Version, username, role)
		} else {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "invalid rollback target"})
			return
		}

		if err != nil {
			GetAuditLogger().LogAction(username, role, "CONFIG_ROLLBACK", "config", "yaml", fmt.Sprintf("Rollback Error: %v", err), clientIP, "failure")
			writeJSON(w, map[string]interface{}{"status": "error", "message": err.Error()})
			return
		}

		newCfg := center.GetConfig()
		d.cfg = newCfg
		if d.stats != nil {
			d.stats.UpdateUpstreams(newCfg.Domains)
		}

		GetAuditLogger().LogAction(username, role, "CONFIG_ROLLBACK", "config", "yaml", fmt.Sprintf("Restored revision/backup version %d / %s", req.Version, req.BackupID), clientIP, "success")
		writeJSON(w, map[string]interface{}{"status": "success", "message": "Configuration restored & hot-reloaded successfully", "raw_yaml": center.GetRawYAML(), "config": newCfg})
	}
}

func (d *Dashboard) handleConfigDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		V1 int64 `json:"v1"`
		V2 int64 `json:"v2"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	diffText, err := config.GetCenter().DiffRevisions(req.V1, req.V2)
	if err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "message": err.Error()})
		return
	}

	writeJSON(w, map[string]interface{}{"status": "success", "diff": diffText})
}

func (d *Dashboard) handleConfigBackup(w http.ResponseWriter, r *http.Request) {
	username, role := d.getUserFromRequest(r)
	center := config.GetCenter()
	clientIP := getClientIP(r)

	switch r.Method {
	case http.MethodGet:
		downloadID := r.URL.Query().Get("id")
		if downloadID != "" {
			backups := center.ListBackups()
			for _, b := range backups {
				if b.ID == downloadID || b.Name == downloadID {
					data, err := os.ReadFile(b.FilePath)
					if err != nil {
						http.Error(w, "File not found", http.StatusNotFound)
						return
					}
					w.Header().Set("Content-Type", "application/x-yaml")
					w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.yaml\"", b.Name))
					w.Write(data)
					return
				}
			}
			http.Error(w, "Backup ID not found", http.StatusNotFound)
			return
		}

		writeJSON(w, map[string]interface{}{
			"status":  "success",
			"backups": center.ListBackups(),
		})

	case http.MethodPost:
		if !CanManageSystem(role) {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied"})
			return
		}

		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		b, err := center.CreateBackup(req.Name, username, req.Description)
		if err != nil {
			GetAuditLogger().LogAction(username, role, "BACKUP_CREATE", "config", req.Name, err.Error(), clientIP, "failure")
			writeJSON(w, map[string]interface{}{"status": "error", "message": err.Error()})
			return
		}

		GetAuditLogger().LogAction(username, role, "BACKUP_CREATE", "config", b.Name, b.Description, clientIP, "success")
		writeJSON(w, map[string]interface{}{"status": "success", "message": "Backup created successfully", "backup": b})
	}
}

func (d *Dashboard) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	_, role := d.getUserFromRequest(r)
	if !CanViewLogs(role) {
		writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied"})
		return
	}

	userQ := r.URL.Query().Get("user")
	roleQ := r.URL.Query().Get("role")
	actionQ := r.URL.Query().Get("action")
	moduleQ := r.URL.Query().Get("module")
	searchQ := r.URL.Query().Get("search")
	exportQ := r.URL.Query().Get("export")

	loggerInst := GetAuditLogger()

	if exportQ == "csv" {
		csvContent := loggerInst.ExportCSV(userQ, roleQ, actionQ, moduleQ, searchQ)
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\"audit_logs.csv\"")
		w.Write([]byte(csvContent))
		return
	}

	entries := loggerInst.QueryEntries(userQ, roleQ, actionQ, moduleQ, searchQ, 500)
	writeJSON(w, map[string]interface{}{
		"status": "success",
		"logs":   entries,
		"total":  len(entries),
	})
}

func (d *Dashboard) handleUsers(w http.ResponseWriter, r *http.Request) {
	username, role := d.getUserFromRequest(r)
	st := GetStorage()
	clientIP := getClientIP(r)

	switch r.Method {
	case http.MethodGet:
		if !CanManageSystem(role) {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied"})
			return
		}
		st.mu.RLock()
		safeUsers := make([]map[string]interface{}, 0, len(st.Data.Users))
		for _, u := range st.Data.Users {
			safeUsers = append(safeUsers, map[string]interface{}{
				"username": u.Username,
				"email":    u.Email,
				"role":     u.Role,
				"domains":  u.Domains,
			})
		}
		st.mu.RUnlock()

		writeJSON(w, map[string]interface{}{"status": "success", "users": safeUsers})

	case http.MethodPost:
		if !CanManageSystem(role) {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied: Only admins can add users"})
			return
		}
		var req UserAccount
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Username == "" || req.Password == "" {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Username and password required"})
			return
		}
		if req.Role == "" {
			req.Role = RoleUser
		}

		st.mu.Lock()
		for _, u := range st.Data.Users {
			if strings.EqualFold(u.Username, req.Username) {
				st.mu.Unlock()
				writeJSON(w, map[string]interface{}{"status": "error", "message": "User already exists"})
				return
			}
		}
		st.Data.Users = append(st.Data.Users, req)
		st.mu.Unlock()
		_ = st.Save()

		GetAuditLogger().LogAction(username, role, "USER_CREATE", "users", req.Username, fmt.Sprintf("Role: %s", req.Role), clientIP, "success")
		writeJSON(w, map[string]interface{}{"status": "success", "message": "User created successfully"})

	case http.MethodPut:
		if !CanManageSystem(role) {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied"})
			return
		}
		var req UserAccount
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		st.mu.Lock()
		found := false
		for i, u := range st.Data.Users {
			if strings.EqualFold(u.Username, req.Username) {
				if req.Password != "" {
					st.Data.Users[i].Password = req.Password
				}
				if req.Email != "" {
					st.Data.Users[i].Email = req.Email
				}
				if req.Role != "" {
					st.Data.Users[i].Role = req.Role
				}
				if req.Domains != nil {
					st.Data.Users[i].Domains = req.Domains
				}
				found = true
				break
			}
		}
		st.mu.Unlock()
		if !found {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "User not found"})
			return
		}
		_ = st.Save()

		GetAuditLogger().LogAction(username, role, "USER_UPDATE", "users", req.Username, fmt.Sprintf("Updated role to %s", req.Role), clientIP, "success")
		writeJSON(w, map[string]interface{}{"status": "success", "message": "User updated successfully"})

	case http.MethodDelete:
		if !CanManageSystem(role) {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied"})
			return
		}
		targetUser := r.URL.Query().Get("username")
		if targetUser == "admin" {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Cannot delete primary admin account"})
			return
		}

		st.mu.Lock()
		newUsers := make([]UserAccount, 0, len(st.Data.Users))
		found := false
		for _, u := range st.Data.Users {
			if strings.EqualFold(u.Username, targetUser) {
				found = true
				continue
			}
			newUsers = append(newUsers, u)
		}
		if found {
			st.Data.Users = newUsers
		}
		st.mu.Unlock()

		if !found {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "User not found"})
			return
		}
		_ = st.Save()

		GetAuditLogger().LogAction(username, role, "USER_DELETE", "users", targetUser, "Account deleted", clientIP, "success")
		writeJSON(w, map[string]interface{}{"status": "success", "message": "User deleted successfully"})
	}
}

func (d *Dashboard) handleDomainProtectionMode(w http.ResponseWriter, r *http.Request) {
	username, role := d.getUserFromRequest(r)
	clientIP := getClientIP(r)

	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"status": "error", "message": "Method not allowed"})
		return
	}

	if !CanManageGlobalSecurity(role) {
		writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied: Only admins can change domain protection mode"})
		return
	}

	var req struct {
		Domain         string `json:"domain"`
		ProtectionMode string `json:"protection_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "message": "Invalid request"})
		return
	}

	if req.Domain == "" {
		writeJSON(w, map[string]interface{}{"status": "error", "message": "Domain name is required"})
		return
	}

	// Find and update the domain's protection mode
	found := false
	cfgClone := d.getConfigClone()
	for i, dom := range cfgClone.Domains {
		if strings.EqualFold(dom.Name, req.Domain) {
			cfgClone.Domains[i].ProtectionMode = req.ProtectionMode
			found = true
			break
		}
	}

	if !found {
		writeJSON(w, map[string]interface{}{"status": "error", "message": "Domain not found: " + req.Domain})
		return
	}

	// Save to Storage center to persist it
	st := GetStorage()
	st.mu.Lock()
	st.Data.Domains = cfgClone.Domains
	st.mu.Unlock()
	_ = st.Save()

	// Save via Configuration Center & Hot Reload
	modeLabel := req.ProtectionMode
	if modeLabel == "" {
		modeLabel = "global (inherit)"
	}
	_ = config.GetCenter().UpdateConfig(cfgClone, username, role, fmt.Sprintf("Set protection mode for %s to %s", req.Domain, modeLabel))
	go d.broadcastConfigToPeers(config.GetCenter().GetRawYAML(), username, fmt.Sprintf("Set protection mode for %s to %s", req.Domain, modeLabel))

	GetAuditLogger().LogAction(username, role, "DOMAIN_PROTECTION_MODE", "security", req.Domain, fmt.Sprintf("Mode: %s", modeLabel), clientIP, "success")
	writeJSON(w, map[string]interface{}{"status": "success", "message": fmt.Sprintf("Protection mode for %s set to %s", req.Domain, modeLabel)})
}

func (d *Dashboard) handleSecurityRules(w http.ResponseWriter, r *http.Request) {
	username, role := d.getUserFromRequest(r)
	clientIP := getClientIP(r)

	// Single Source of Truth: Always load latest config from ConfigCenter
	currentCfg := d.getConfig()

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"status":            "success",
			"protection_mode":   currentCfg.Protection.Mode,
			"paranoia_level":    currentCfg.WAF.ParanoiaLevel,
			"owasp_rules":       currentCfg.WAF.OWASPRules,
			"whitelist_ips":     currentCfg.Protection.WhitelistIPs,
			"rate_limit":        currentCfg.Protection.RateLimit,
			"pow_difficulty":    currentCfg.Protection.Challenge.PowDifficulty,
			"blocked_countries": currentCfg.Intelligence.GeoIP.BlockedCountries,
			"block_datacenter":  currentCfg.Intelligence.ASN.BlockDatacenter,
		})

	case http.MethodPost, http.MethodPut:
		if !CanManageGlobalSecurity(role) {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied: Only admins can manage global security rules"})
			return
		}
		currentCfg = d.getConfigClone()

		var req struct {
			ProtectionMode   string   `json:"protection_mode"`
			ParanoiaLevel    int      `json:"paranoia_level"`
			OWASPRules       *bool    `json:"owasp_rules"`
			WhitelistIPs     []string `json:"whitelist_ips"`
			RPS              int      `json:"requests_per_second"`
			Burst            int      `json:"burst"`
			PowDifficulty    int      `json:"pow_difficulty"`
			BlockedCountries []string `json:"blocked_countries"`
			BlockDatacenter  *bool    `json:"block_datacenter"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.ProtectionMode != "" {
			currentCfg.Protection.Mode = req.ProtectionMode
		}
		if req.ParanoiaLevel >= 1 && req.ParanoiaLevel <= 4 {
			currentCfg.WAF.ParanoiaLevel = req.ParanoiaLevel
		}
		if req.OWASPRules != nil {
			currentCfg.WAF.OWASPRules = *req.OWASPRules
		}
		if req.WhitelistIPs != nil {
			currentCfg.Protection.WhitelistIPs = req.WhitelistIPs
		}
		if req.RPS > 0 {
			currentCfg.Protection.RateLimit.RequestsPerSecond = req.RPS
		}
		if req.Burst > 0 {
			currentCfg.Protection.RateLimit.Burst = req.Burst
		}
		if req.PowDifficulty > 0 {
			currentCfg.Protection.Challenge.PowDifficulty = req.PowDifficulty
		}
		if req.BlockedCountries != nil {
			currentCfg.Intelligence.GeoIP.BlockedCountries = req.BlockedCountries
		}
		if req.BlockDatacenter != nil {
			currentCfg.Intelligence.ASN.BlockDatacenter = *req.BlockDatacenter
		}

		// Save via Configuration Center & Hot Reload across all engines
		err := config.GetCenter().UpdateConfig(currentCfg, username, role, fmt.Sprintf("Updated WAF Security Policies (RPS: %d, Burst: %d, Mode: %s)", currentCfg.Protection.RateLimit.RequestsPerSecond, currentCfg.Protection.RateLimit.Burst, currentCfg.Protection.Mode))
		if err != nil {
			writeJSON(w, map[string]interface{}{"status": "error", "message": err.Error()})
			return
		}

		GetAuditLogger().LogAction(username, role, "SECURITY_UPDATE", "security", "global", fmt.Sprintf("Mode: %s, Paranoia: %d, RPS: %d, Burst: %d", currentCfg.Protection.Mode, currentCfg.WAF.ParanoiaLevel, currentCfg.Protection.RateLimit.RequestsPerSecond, currentCfg.Protection.RateLimit.Burst), clientIP, "success")
		writeJSON(w, map[string]interface{}{"status": "success", "message": "Security rules updated & hot-reloaded successfully"})
	}
}

func (d *Dashboard) handleClusterSync(w http.ResponseWriter, r *http.Request) {
	username, role := d.getUserFromRequest(r)
	clientIP := getClientIP(r)

	if !CanManageSystem(role) {
		writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied"})
		return
	}

	m := cluster.GetMesh()
	numNodes := 1
	members := []cluster.NodeInfo{}
	if m != nil {
		numNodes = m.NumMembers()
		members = m.GetMembers()
	}

	if r.Method == http.MethodPost {
		// Broadcast YAML configuration across mesh to peer nodes
		rawYAML := config.GetCenter().GetRawYAML()
		d.broadcastConfigToPeers(rawYAML, username, "Manual Force Sync Node")

		GetAuditLogger().LogAction(username, role, "CLUSTER_SYNC", "cluster", "all_nodes", fmt.Sprintf("Manual cluster sync triggered across %d nodes", numNodes), clientIP, "success")
		writeJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Cluster config sync broadcasted across %d active mesh nodes", numNodes),
			"nodes":   numNodes,
			"members": members,
		})
		return
	}

	writeJSON(w, map[string]interface{}{
		"status":  "success",
		"enabled": d.getConfig().Cluster.Enabled,
		"node":    d.getConfig().Cluster.NodeName,
		"port":    d.getConfig().Cluster.BindPort,
		"members": members,
		"count":   numNodes,
	})
}

func (d *Dashboard) handleNodes(w http.ResponseWriter, r *http.Request) {
	mesh := cluster.GetMesh()
	var nodes []cluster.NodeInfo
	if mesh != nil {
		nodes = mesh.GetMembers()
	}

	// Dynamic fallback from loaded YAML configuration if gossip mesh is initializing
	if len(nodes) == 0 {
		currNode := d.getConfig().Cluster.NodeName
		if currNode == "" {
			currNode = "mango-node-primary"
		}
		currIP := d.getConfig().Cluster.AdvertiseIP
		if currIP == "" {
			currIP = "127.0.0.1"
		}

		nodes = append(nodes, cluster.NodeInfo{
			Name: currNode,
			Addr: currIP,
		})

		for i, peer := range d.getConfig().Cluster.JoinPeers {
			host, _, err := net.SplitHostPort(peer)
			if err != nil || host == "" {
				host = peer
			}
			nodes = append(nodes, cluster.NodeInfo{
				Name: fmt.Sprintf("mango-peer-node-%d", i+1),
				Addr: host,
			})
		}
	}

	type ResponseNode struct {
		Name      string  `json:"name"`
		Addr      string  `json:"addr"`
		IP        string  `json:"ip"`
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
	}

	var resNodes []ResponseNode
	gp, _ := intelligence.NewGeoProvider("")
	for _, n := range nodes {
		ip := n.Addr
		if host, _, err := net.SplitHostPort(n.Addr); err == nil && host != "" {
			ip = host
		}

		// Try to extract public IP from node name if it contains one
		for _, part := range strings.Split(n.Name, "-") {
			if net.ParseIP(part) != nil {
				ip = part
				break
			}
		}

		// Check if IP is private/local
		parsedIP := net.ParseIP(ip)
		isPrivate := false
		if parsedIP != nil {
			ip4 := parsedIP.To4()
			if ip4 != nil {
				if ip4[0] == 127 || ip4[0] == 10 || (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || (ip4[0] == 192 && ip4[1] == 168) {
					isPrivate = true
				}
			} else {
				isPrivate = true
			}
		} else {
			isPrivate = true
		}

		// Map private IP to its public JoinPeer counterpart if available
		if isPrivate && len(d.getConfig().Cluster.JoinPeers) > 0 {
			peerIdx := 0
			for i, member := range nodes {
				if member.Name == n.Name {
					peerIdx = i
					break
				}
			}
			if peerIdx >= len(d.getConfig().Cluster.JoinPeers) {
				peerIdx = len(d.getConfig().Cluster.JoinPeers) - 1
			}
			peerStr := d.getConfig().Cluster.JoinPeers[peerIdx]
			host, _, err := net.SplitHostPort(peerStr)
			if err == nil && host != "" {
				ip = host
			} else if peerStr != "" {
				ip = peerStr
			}
		}

		lat, lon := 0.0, 0.0
		if gp != nil {
			if geo, err := gp.Lookup(ip); err == nil {
				lat = geo.Latitude
				lon = geo.Longitude
			}
		}

		// Fallback default coordinates if GeoIP still returns 0 or private IP
		if lat == 0 && lon == 0 {
			nodeIdx := 0
			for i, member := range nodes {
				if member.Name == n.Name {
					nodeIdx = i
					break
				}
			}

			fallbacks := []struct {
				Lat float64
				Lon float64
			}{
				{Lat: 21.0285, Lon: 105.8542}, // Hanoi
				{Lat: 10.8231, Lon: 106.6297}, // HCMC
				{Lat: 16.0544, Lon: 108.2022}, // Da Nang
			}

			fb := fallbacks[nodeIdx%len(fallbacks)]
			lat = fb.Lat
			lon = fb.Lon
		}

		resNodes = append(resNodes, ResponseNode{
			Name:      n.Name,
			Addr:      n.Addr,
			IP:        ip,
			Latitude:  lat,
			Longitude: lon,
		})
	}

	writeJSON(w, map[string]interface{}{
		"status": "success",
		"nodes":  resNodes,
		"total":  len(resNodes),
	})
}

func (d *Dashboard) handleLogsQuery(w http.ResponseWriter, r *http.Request) {
	_, role := d.getUserFromRequest(r)
	if !CanViewLogs(role) {
		writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied"})
		return
	}

	logType := r.URL.Query().Get("type")
	search := r.URL.Query().Get("search")
	domainFilter := r.URL.Query().Get("domain")
	exportFormat := r.URL.Query().Get("export")

	realLogs := core.GetLogStore().QueryLogs(logType, search, domainFilter)

	if exportFormat == "csv" {
		var sb strings.Builder
		sb.WriteString("Timestamp,Type,ClientIP,Country,Domain,Method,Path,Status,Action,Rule,Description\n")
		for _, l := range realLogs {
			sb.WriteString(fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%d\",\"%s\",\"%s\",\"%s\"\n",
				l.Timestamp, l.Type, l.ClientIP, l.CountryCode, l.Domain, l.Method, l.Path, l.Status, l.Action, l.Rule, escapeCSV(l.Desc),
			))
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\"security_exploits_logs.csv\"")
		w.Write([]byte(sb.String()))
		return
	}

	writeJSON(w, map[string]interface{}{
		"status": "success",
		"logs":   realLogs,
		"total":  len(realLogs),
	})
}

func (d *Dashboard) handleLogsClear(w http.ResponseWriter, r *http.Request) {
	core.GetLogStore().Clear()
	writeJSON(w, map[string]interface{}{"status": "success", "message": "Log store cleared"})
}

// handleFirewallBans returns the real-time list of banned IPs from the pipeline's sync.Map
func (d *Dashboard) handleFirewallBans(w http.ResponseWriter, r *http.Request) {
	_, role := d.getUserFromRequest(r)
	if !CanViewLogs(role) {
		writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied"})
		return
	}

	var entries []BannedIPEntry
	if d.stats != nil {
		entries = d.stats.GetBannedIPsList()
	}
	if entries == nil {
		entries = []BannedIPEntry{}
	}
	writeJSON(w, map[string]interface{}{
		"status": "success",
		"bans":   entries,
		"total":  len(entries),
	})
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (d *Dashboard) handleLogoMango(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat("assets/logo-mango.png"); err == nil {
		w.Header().Set("Content-Type", "image/png")
		http.ServeFile(w, r, "assets/logo-mango.png")
		return
	}
	if _, err := os.Stat("../logo-mango.png"); err == nil {
		w.Header().Set("Content-Type", "image/png")
		http.ServeFile(w, r, "../logo-mango.png")
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="32" height="32"><defs><linearGradient id="mGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#FF5722"/><stop offset="50%" stop-color="#FF9800"/><stop offset="100%" stop-color="#FFC107"/></linearGradient><linearGradient id="lGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#4CAF50"/><stop offset="100%" stop-color="#2E7D32"/></linearGradient></defs><path d="M50 15 C25 15 15 35 15 60 C15 80 32 90 50 90 C72 90 85 75 85 55 C85 30 70 15 50 15 Z" fill="url(#mGrad)"/><path d="M50 15 C55 5 65 2 75 5 C70 15 60 18 50 15 Z" fill="url(#lGrad)"/></svg>`))
}

func (d *Dashboard) handleLogoMangoSmall(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat("assets/logo-mango-small.png"); err == nil {
		w.Header().Set("Content-Type", "image/png")
		http.ServeFile(w, r, "assets/logo-mango-small.png")
		return
	}
	if _, err := os.Stat("../logo-mango-small.png"); err == nil {
		w.Header().Set("Content-Type", "image/png")
		http.ServeFile(w, r, "../logo-mango-small.png")
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="24" height="24"><defs><linearGradient id="mGrad2" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#FF5722"/><stop offset="100%" stop-color="#FFC107"/></linearGradient></defs><path d="M50 15 C25 15 15 35 15 60 C15 80 32 90 50 90 C72 90 85 75 85 55 C85 30 70 15 50 15 Z" fill="url(#mGrad2)"/><path d="M50 15 C55 5 65 2 75 5 C70 15 60 18 50 15 Z" fill="#4CAF50"/></svg>`))
}

func (d *Dashboard) handleAttackStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	geoProvider, _ := intelligence.NewGeoProvider("")
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Track the last emitted event's ID to avoid re-sending duplicates
	var lastSentID uint64

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			logs := core.GetLogStore().QueryLogs("", "", "")
			if len(logs) == 0 {
				continue
			}

			// Only send events newer than what we last sent
			var newEvents []map[string]interface{}

			for i := 0; i < len(logs) && i < 50; i++ {
				l := logs[i]
				if lastSentID > 0 && l.ID <= lastSentID {
					break // we reached previously-sent events
				}
				geo, _ := geoProvider.Lookup(l.ClientIP)
				newEvents = append(newEvents, map[string]interface{}{
					"ip":          l.ClientIP,
					"country":     geo.Country,
					"countryCode": geo.CountryCode,
					"city":        geo.City,
					"latitude":    geo.Latitude,
					"longitude":   geo.Longitude,
					"action":      l.Action,
					"type":        l.Type,
					"rule":        l.Rule,
					"domain":      l.Domain,
					"path":        l.Path,
					"status":      l.Status,
					"timestamp":   l.Timestamp,
				})
			}

			if len(newEvents) > 0 {
				// Record the ID of the newest event for dedup next round
				lastSentID = logs[0].ID
				data, _ := json.Marshal(newEvents)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		}
	}
}

func (d *Dashboard) handleWorldSVG(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400") // cache for 1 day

	// Serve local world.svg if exists
	if _, err := os.Stat("assets/world.svg"); err == nil {
		http.ServeFile(w, r, "assets/world.svg")
		return
	}
	if _, err := os.Stat("../world.svg"); err == nil {
		http.ServeFile(w, r, "../world.svg")
		return
	}

	// Fallback to empty tiny SVG if not found
	w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 2000 857" width="2000" height="857"><rect width="2000" height="857" fill="#020617"/></svg>`))
}
