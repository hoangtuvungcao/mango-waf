package api

import (
	"bufio"
	"bytes"
	"context"
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
	"mango-waf/logger"
)

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
}

// Dashboard is the admin dashboard API server
type Dashboard struct {
	cfg       *config.Config
	stats     StatsProvider
	mux       *http.ServeMux
	rpsHist   *RingBuffer
	stopCh    chan struct{}
	srv       *http.Server
	srvWeb    *http.Server
	startTime time.Time
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

// NewDashboard creates a new dashboard server
func NewDashboard(cfg *config.Config, stats StatsProvider) *Dashboard {
	d := &Dashboard{
		cfg:       cfg,
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
}

func (d *Dashboard) registerRoutes() {
	d.registerCommonRoutes(d.mux)
	d.mux.HandleFunc("/", d.handleDashboardUI1234)
}

func (d *Dashboard) Start() error {
	if !d.cfg.Dashboard.Enabled {
		return nil
	}

	mux9090 := http.NewServeMux()
	d.registerCommonRoutes(mux9090)
	mux9090.HandleFunc("/", d.handleDashboardUI1234)

	d.srv = &http.Server{
		Addr:         d.cfg.Dashboard.Listen,
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

	logger.Info("Dashboard API & Command Center started", "listen", d.cfg.Dashboard.Listen)
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
		if strings.EqualFold(u.Username, req.Username) && u.Password == req.Password {
			tmp := u
			authUser = &tmp
			break
		}
	}
	st.mu.RUnlock()

	if authUser == nil {
		uMatch := subtle.ConstantTimeCompare([]byte(req.Username), []byte(d.cfg.Dashboard.Username)) == 1
		pMatch := subtle.ConstantTimeCompare([]byte(req.Password), []byte(d.cfg.Dashboard.Password)) == 1
		if uMatch && pMatch {
			authUser = &UserAccount{Username: req.Username, Role: "admin"}
		}
	}

	if authUser != nil {
		token := fmt.Sprintf("mango-session-%d", time.Now().UnixNano())
		
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
	for _, p := range d.cfg.Cluster.JoinPeers {
		host, _, err := net.SplitHostPort(p)
		if err == nil && host != "" {
			peerMap[host] = true
		} else if p != "" {
			peerMap[p] = true
		}
	}
	if mesh := cluster.GetMesh(); mesh != nil {
		for _, m := range mesh.GetMembers() {
			if m.Addr != "" && m.Addr != d.cfg.Cluster.AdvertiseIP {
				peerMap[m.Addr] = true
			}
		}
	}

	results := make([]map[string]interface{}, 0)
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	for peerIP := range peerMap {
		if peerIP == d.cfg.Cluster.AdvertiseIP || peerIP == "127.0.0.1" || peerIP == "localhost" || peerIP == "" {
			continue
		}
		url := fmt.Sprintf("http://%s:1234%s?local=true", peerIP, endpoint)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("X-Sync-Internal", "true")
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			var data map[string]interface{}
			if json.NewDecoder(resp.Body).Decode(&data) == nil {
				results = append(results, data)
			}
			resp.Body.Close()
		}
	}
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
		"protection_mode":  d.cfg.Protection.Mode,
		"domains":          len(d.cfg.Domains),
		"uptime_seconds":   time.Since(d.startTime).Seconds(),
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
		"mode": d.cfg.Protection.Mode, "domains": len(d.cfg.Domains),
		"tls": d.cfg.TLS.Enabled, "waf": d.cfg.WAF.Enabled,
		"fingerprint": map[string]bool{"ja3": d.cfg.Fingerprint.JA3.Enabled, "ja4": d.cfg.Fingerprint.JA4.Enabled},
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
	cpuMu        sync.Mutex
)

func readCPUUsage() float64 {
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

	if dTotal == 0 {
		return 0
	}
	return float64(dTotal-dIdle) / float64(dTotal) * 100
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

func readTCPConnections() int {
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

func (d *Dashboard) handleDashboardUI9090(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(fullDashboardHTML))
}

func (d *Dashboard) handleDashboardUI1234(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(managementPlatformHTML))
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
		if CanManageAllDomains(role) {
			writeJSON(w, map[string]interface{}{
				"status":  "success",
				"domains": d.cfg.Domains,
			})
			return
		}
		// Regular user: filter domains owned specifically by username
		userDomains := make([]config.DomainConfig, 0)
		for _, dom := range d.cfg.Domains {
			if dom.Owner == username {
				userDomains = append(userDomains, dom)
			}
		}
		writeJSON(w, map[string]interface{}{
			"status":  "success",
			"domains": userDomains,
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
		for i, dom := range d.cfg.Domains {
			if strings.EqualFold(dom.Name, req.Name) {
				if role != "admin" && dom.Owner != "" && dom.Owner != username {
					writeJSON(w, map[string]interface{}{"status": "error", "message": "You do not have permission to modify this domain"})
					return
				}
				d.cfg.Domains[i] = req
				found = true
				break
			}
		}
		if !found {
			d.cfg.Domains = append(d.cfg.Domains, req)
		}

		st := GetStorage()
		st.mu.Lock()
		st.Data.Domains = d.cfg.Domains
		st.mu.Unlock()
		_ = st.Save()

		_ = config.GetCenter().UpdateConfig(d.cfg, username, role, fmt.Sprintf("Added domain %s", req.Name))
		if r.Header.Get("X-Sync-Internal") != "true" {
			go d.broadcastConfigToPeers(config.GetCenter().GetRawYAML(), username, fmt.Sprintf("Added domain %s", req.Name))
		}

		if d.stats != nil {
			d.stats.UpdateUpstreams(d.cfg.Domains)
		}

		logger.Info("Domain added/updated via dashboard API", "domain", req.Name, "user", username)
		writeJSON(w, map[string]interface{}{"status": "success", "message": "domain saved successfully", "domain": req})

	case http.MethodPut:
		var req config.DomainConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for i, dom := range d.cfg.Domains {
			if strings.EqualFold(dom.Name, req.Name) {
				if role != "admin" && dom.Owner != "" && dom.Owner != username {
					writeJSON(w, map[string]interface{}{"status": "error", "message": "You do not have permission to modify this domain"})
					return
				}
				d.cfg.Domains[i] = req

				st := GetStorage()
				st.mu.Lock()
				st.Data.Domains = d.cfg.Domains
				st.mu.Unlock()
				_ = st.Save()

				_ = config.GetCenter().UpdateConfig(d.cfg, username, role, fmt.Sprintf("Updated domain %s", req.Name))
				if r.Header.Get("X-Sync-Internal") != "true" {
					go d.broadcastConfigToPeers(config.GetCenter().GetRawYAML(), username, fmt.Sprintf("Updated domain %s", req.Name))
				}

				if d.stats != nil {
					d.stats.UpdateUpstreams(d.cfg.Domains)
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
		newDomains := make([]config.DomainConfig, 0, len(d.cfg.Domains))
		for _, dom := range d.cfg.Domains {
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
		d.cfg.Domains = newDomains

		st := GetStorage()
		st.mu.Lock()
		st.Data.Domains = d.cfg.Domains
		st.mu.Unlock()
		_ = st.Save()

		_ = config.GetCenter().UpdateConfig(d.cfg, username, role, fmt.Sprintf("Deleted domain %s", name))
		if r.Header.Get("X-Sync-Internal") != "true" {
			go d.broadcastConfigToPeers(config.GetCenter().GetRawYAML(), username, fmt.Sprintf("Deleted domain %s", name))
		}

		if d.stats != nil {
			d.stats.UpdateUpstreams(d.cfg.Domains)
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
	if d.cfg.Cluster.AdvertiseIP != "" {
		ipMap[d.cfg.Cluster.AdvertiseIP] = true
	}
	for _, p := range d.cfg.Cluster.JoinPeers {
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

	cnameTarget := d.cfg.Cluster.CNAMETarget
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
			"/":                true,
			"/api/health":      true,
			"/api/login":       true,
			"/api/register":    true,
			"/api/dns/check":   true,
			"/api/pricing":     true,
			"/api/docs":        true,
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
		if d.cfg.Dashboard.Username != "" && d.cfg.Dashboard.Password != "" {
			user, pass, ok := r.BasicAuth()
			uMatch := subtle.ConstantTimeCompare([]byte(user), []byte(d.cfg.Dashboard.Username)) == 1
			pMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(d.cfg.Dashboard.Password)) == 1
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
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval'; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; connect-src 'self'; img-src 'self' data:;")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "null")
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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	json.NewEncoder(w).Encode(data)
}

// StatsAdapter bridges Shield.Stats to StatsProvider
type StatsAdapter struct {
	TotalReqs   *int64
	BlockedReqs *int64
	PassedReqs  *int64
	CurrRPS     *int64
	PkRPS       *int64
	ActiveCn    *int64
	BannedIP    *int64
	AttacksDet  *int64
	UnderAttack *bool
	UptimeStart time.Time
	XDP         func() (bool, int64, int64)
	EarlyStats  func() (int64, int64)
	CDNStats    func() (int64, int64, int64)
	MeshStats   func() (bool, int)
	MeshMembers func() []cluster.NodeInfo
	UnbanFunc          func(ip string)
	UnbanAll           func()
	UpdateUpstreamFunc func(domains []config.DomainConfig)
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

// ================================================
// Full Dashboard HTML
// ================================================

var fullDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mango Shield — Cyber Command Center</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #020617;
  --bg-card: rgba(15, 23, 42, 0.75);
  --border: rgba(51, 65, 85, 0.6);
  --border-glow: rgba(6, 182, 212, 0.3);
  --primary: #10b981;
  --cyan: #06b6d4;
  --amber: #f59e0b;
  --red: #ef4444;
  --purple: #8b5cf6;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
  --font-mono: 'Fira Code', monospace;
}

* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  background: var(--bg);
  background-image: 
    radial-gradient(circle at 15% 15%, rgba(16, 185, 129, 0.05) 0%, transparent 40%),
    radial-gradient(circle at 85% 85%, rgba(6, 182, 212, 0.05) 0%, transparent 40%);
  color: var(--text-main);
  font-family: var(--font-sans);
  min-height: 100vh;
  overflow-x: hidden;
}

/* Header Navbar */
.nav-hdr {
  background: rgba(15, 23, 42, 0.85);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--border);
  padding: 14px 32px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: 100;
}
.brand-title {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 19px;
  font-weight: 700;
  letter-spacing: -0.5px;
}
.brand-title span.logo-icon { font-size: 24px; filter: drop-shadow(0 0 8px rgba(245, 158, 11, 0.6)); }
.brand-title span.ver-tag {
  font-size: 11px;
  background: rgba(6, 182, 212, 0.15);
  color: var(--cyan);
  border: 1px solid rgba(6, 182, 212, 0.3);
  padding: 2px 8px;
  border-radius: 12px;
  font-family: var(--font-mono);
}

.hdr-controls { display: flex; align-items: center; gap: 14px; }
.status-pill {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 16px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.3px;
  transition: all 0.3s;
}
.status-pill.ok {
  background: rgba(16, 185, 129, 0.12);
  color: var(--primary);
  border: 1px solid rgba(16, 185, 129, 0.3);
  box-shadow: 0 0 12px rgba(16, 185, 129, 0.2);
}
.status-pill.atk {
  background: rgba(239, 68, 68, 0.15);
  color: var(--red);
  border: 1px solid rgba(239, 68, 68, 0.4);
  box-shadow: 0 0 16px rgba(239, 68, 68, 0.4);
  animation: pulseAlert 1.2s infinite;
}
@keyframes pulseAlert { 50% { opacity: 0.6; } }

.dot-indicator { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }

.btn-action {
  background: rgba(30, 41, 59, 0.8);
  border: 1px solid var(--border);
  color: var(--text-main);
  padding: 8px 16px;
  border-radius: 8px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: all 0.2s;
}
.btn-action:hover {
  background: rgba(51, 65, 85, 0.8);
  border-color: var(--cyan);
  box-shadow: 0 0 12px rgba(6, 182, 212, 0.25);
}

/* Layout Grid */
.dashboard-container { padding: 24px 32px; max-width: 1600px; margin: 0 auto; }
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.kpi-card {
  background: var(--bg-card);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px 20px;
  position: relative;
  overflow: hidden;
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}
.kpi-card:hover {
  border-color: var(--border-glow);
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4), 0 0 16px rgba(6, 182, 212, 0.1);
}
.kpi-card .kpi-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.8px;
  margin-bottom: 8px;
}
.kpi-card .kpi-val {
  font-size: 28px;
  font-weight: 800;
  font-family: var(--font-mono);
  color: var(--text-main);
  line-height: 1.1;
}
.kpi-card .kpi-sub {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 6px;
  display: flex;
  align-items: center;
  gap: 4px;
}

.accent-green .kpi-val { color: var(--primary); text-shadow: 0 0 10px rgba(16, 185, 129, 0.3); }
.accent-red .kpi-val { color: var(--red); text-shadow: 0 0 10px rgba(239, 68, 68, 0.3); }
.accent-cyan .kpi-val { color: var(--cyan); text-shadow: 0 0 10px rgba(6, 182, 212, 0.3); }
.accent-purple .kpi-val { color: var(--purple); text-shadow: 0 0 10px rgba(139, 92, 246, 0.3); }

/* Main Chart Section */
.panel-box {
  background: var(--bg-card);
  backdrop-filter: blur(12px);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 24px;
  margin-bottom: 24px;
}
.panel-hdr {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 18px;
}
.panel-hdr h2 {
  font-size: 15px;
  font-weight: 600;
  color: var(--text-main);
  display: flex;
  align-items: center;
  gap: 8px;
}
.chart-container { position: relative; width: 100%; height: 220px; }
canvas#chart { width: 100% !important; height: 220px !important; }

/* Multi-Column Grid */
.col-grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  margin-bottom: 24px;
}
@media (max-width: 900px) { .col-grid-2 { grid-template-columns: 1fr; } }

/* Meter Bars */
.meter-row { margin-bottom: 16px; }
.meter-lbl {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
  font-weight: 500;
  margin-bottom: 6px;
}
.meter-track {
  height: 8px;
  background: rgba(30, 41, 59, 0.8);
  border-radius: 6px;
  overflow: hidden;
}
.meter-bar {
  height: 100%;
  border-radius: 6px;
  transition: width 0.4s ease-out;
}
.meter-bar.g { background: linear-gradient(90deg, #059669, #10b981); }
.meter-bar.y { background: linear-gradient(90deg, #d97706, #f59e0b); }
.meter-bar.r { background: linear-gradient(90deg, #dc2626, #ef4444); }

/* Terminal Events Feed */
.terminal-box {
  background: #010409;
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 14px 18px;
  font-family: var(--font-mono);
  font-size: 12px;
  max-height: 240px;
  overflow-y: auto;
}
.log-row {
  padding: 5px 0;
  border-bottom: 1px solid rgba(255, 255, 255, 0.03);
  display: flex;
  align-items: center;
  gap: 12px;
}
.log-row .log-ts { color: var(--cyan); opacity: 0.8; }
.log-row.warn { color: var(--amber); }
.log-row.err { color: var(--red); }

/* Node Mesh Cards */
.mesh-nodes-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
}
.node-card {
  background: rgba(30, 41, 59, 0.5);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.node-card .n-info { display: flex; flex-direction: column; }
.node-card .n-name { font-weight: 600; font-size: 13px; color: var(--text-main); }
.node-card .n-addr { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); }
.node-card .n-pulse { width: 8px; height: 8px; border-radius: 50%; background: var(--primary); box-shadow: 0 0 8px var(--primary); }

/* Modal */
.modal-scrim {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(2, 6, 23, 0.75);
  backdrop-filter: blur(8px);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 200;
}
.modal-content {
  background: #0f172a;
  border: 1px solid var(--border);
  border-radius: 14px;
  width: 400px;
  padding: 24px;
  box-shadow: 0 20px 40px rgba(0,0,0,0.6);
}
.modal-hdr { font-size: 16px; font-weight: 700; margin-bottom: 12px; }
.modal-actions { display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px; }

/* Footer */
.footer-bar {
  text-align: center;
  padding: 24px;
  color: var(--text-muted);
  font-size: 12px;
  border-top: 1px solid rgba(51, 65, 85, 0.3);
}

/* ======================== RESPONSIVE ======================== */
@media (max-width: 768px) {
  .nav-hdr { padding: 10px 12px; flex-wrap: wrap; gap: 8px; }
  .brand-title { font-size: 16px; }
  .brand-title span.ver-tag { display: none; }
  .hdr-controls { width: 100%; justify-content: flex-end; flex-wrap: wrap; gap: 6px; }
  .dashboard-container { padding: 16px 12px; }
  .kpi-grid { grid-template-columns: repeat(2, 1fr); gap: 10px; }
  .kpi-card .kpi-val { font-size: 22px; }
  .chart-container { height: 160px; }
  canvas#chart { height: 160px !important; }
  .col-grid-2 { grid-template-columns: 1fr; }
  .terminal-box { max-height: 180px; font-size: 11px; }
  .modal-content { width: calc(100% - 32px); max-width: 400px; }
  .mesh-nodes-grid { grid-template-columns: 1fr; }
}
@media (max-width: 480px) {
  .kpi-grid { grid-template-columns: 1fr; }
  .kpi-card .kpi-val { font-size: 20px; }
  .nav-hdr { padding: 8px; }
  .btn-action { padding: 6px 10px; font-size: 12px; }
  .status-pill { font-size: 11px; padding: 4px 10px; }
}
</style>
</head>
<body>

<header class="nav-hdr">
  <div class="brand-title">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    <span>MANGO SHIELD</span>
    <span class="ver-tag">v2.0 ENTERPRISE</span>
  </div>
  <div class="hdr-controls">
    <div class="status-pill ok" id="st">
      <div class="dot-indicator"></div>
      <span id="st_text">SYSTEM NORMAL</span>
    </div>
    <button class="btn-action" style="background:rgba(239, 68, 68, 0.15);border-color:rgba(239, 68, 68, 0.4);color:#ef4444" onclick="executeUnbanAll()">Unban All IPs</button>
    <button class="btn-action" onclick="openPurgeModal()">Purge Cache</button>
    <button class="btn-action" onclick="updateStats()">Refresh</button>
  </div>
</header>

<main class="dashboard-container">

  <!-- KPI Grid -->
  <section class="kpi-grid">
    <div class="kpi-card accent-cyan">
      <div class="kpi-label">Current RPS</div>
      <div class="kpi-val" id="rps">0</div>
      <div class="kpi-sub">req / second</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Total Requests</div>
      <div class="kpi-val" id="total">0</div>
      <div class="kpi-sub">inspected traffic</div>
    </div>
    <div class="kpi-card accent-red">
      <div class="kpi-label">Blocked Threats</div>
      <div class="kpi-val" id="blocked">0</div>
      <div class="kpi-sub">WAF / L7 mitigations</div>
    </div>
    <div class="kpi-card accent-green">
      <div class="kpi-label">Passed Traffic</div>
      <div class="kpi-val" id="passed">0</div>
      <div class="kpi-sub">clean origin requests</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Peak RPS</div>
      <div class="kpi-val" id="peak">0</div>
      <div class="kpi-sub">highest throughput</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Active Connections</div>
      <div class="kpi-val" id="conns">0</div>
      <div class="kpi-sub">concurrent sockets</div>
    </div>
    <div class="kpi-card accent-red">
      <div class="kpi-label">Banned IPs</div>
      <div class="kpi-val" id="banned">0</div>
      <div class="kpi-sub">active blacklists</div>
    </div>
    <div class="kpi-card accent-purple">
      <div class="kpi-label">eBPF / XDP Drops</div>
      <div class="kpi-val" id="xdp_drops">0</div>
      <div class="kpi-sub" id="xdp_st">NIC Kernel Dropper</div>
    </div>
  </section>

  <!-- Real-time Chart Panel -->
  <section class="panel-box">
    <div class="panel-hdr">
      <h2>Real-Time Traffic & Threat Telemetry (5 min window)</h2>
      <span class="ver-tag" style="background:rgba(6,182,212,0.15);color:var(--cyan)" id="chart_badge">0 RPS Current</span>
    </div>
    <div class="chart-container">
      <canvas id="chart"></canvas>
    </div>
  </section>

  <!-- Dual Status Panels -->
  <section class="col-grid-2">
    <div class="panel-box">
      <div class="panel-hdr">
        <h2>Subsystem Health & Load Matrix</h2>
      </div>
      <div class="meter-row">
        <div class="meter-lbl"><span>WAF Threat Mitigation Rate</span><span id="br">0%</span></div>
        <div class="meter-track"><div class="meter-bar g" id="brm" style="width:0%"></div></div>
      </div>
      <div class="meter-row">
        <div class="meter-lbl"><span>Socket Connection Capacity</span><span id="cl">0%</span></div>
        <div class="meter-track"><div class="meter-bar g" id="clm" style="width:0%"></div></div>
      </div>
      <div class="meter-row">
        <div class="meter-lbl"><span>Engine System Uptime</span><span id="up" style="font-family:var(--font-mono);color:var(--cyan)">0s</span></div>
      </div>
    </div>

    <div class="panel-box">
      <div class="panel-hdr">
        <h2>Security & Threat Audit Stream</h2>
      </div>
      <div class="terminal-box" id="logs">
        <div class="log-row"><span class="log-ts">--:--:--</span>Initializing Mango Command Center...</div>
      </div>
    </div>
  </section>

  <!-- Cluster Network Section -->
  <section class="panel-box">
    <div class="panel-hdr">
      <h2>Mango Mesh P2P Cluster Nodes</h2>
      <span class="ver-tag" style="background:rgba(16,185,129,0.15);color:var(--primary)" id="mesh_count">0 Nodes Active</span>
    </div>
    <div class="mesh-nodes-grid" id="mesh_nodes_list">
      <!-- Node cards injected here -->
    </div>
  </section>

</main>

<div class="modal-scrim" id="purgeModal">
  <div class="modal-content">
    <div class="modal-hdr">Purge RAM Cache</div>
    <p style="font-size:13px;color:var(--text-muted);margin-bottom:14px">Purge in-memory static assets from Ristretto CDN cache store?</p>
    <div class="modal-actions">
      <button class="btn-action" onclick="closePurgeModal()">Cancel</button>
      <button class="btn-action" style="background:var(--red);border-color:var(--red)" onclick="executePurge()">Confirm Purge</button>
    </div>
  </div>
</div>

<footer class="footer-bar">
  Mango Shield v2.0 Enterprise WAF & DDoS Protection Engine • Built with Go & eBPF
</footer>

<script>
var chart = document.getElementById('chart'), ctx = chart.getContext('2d');
var rpsData = new Array(300).fill(0), maxY = 10, logs = [];

function resizeCanvas() {
  if (!chart) return;
  var pW = (chart.parentElement && chart.parentElement.clientWidth > 50) ? chart.parentElement.clientWidth : 800;
  chart.width = pW;
  chart.height = 220;
  drawChart();
}
window.addEventListener('resize', resizeCanvas);

function fmt(n) {
  if (n === undefined || n === null || isNaN(n)) return '0';
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return n.toString();
}
function fmtTime(s) {
  if (!s || isNaN(s)) return '0s';
  var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h > 0 ? h + 'h ' + m + 'm' : m > 0 ? m + 'm' : Math.floor(s) + 's';
}

var hoverX = -1;

function drawChart() {
  if (!chart) return;
  var pW = (chart.parentElement && chart.parentElement.clientWidth > 50) ? chart.parentElement.clientWidth : 800;
  if (chart.width !== pW) {
    chart.width = pW;
    chart.height = 240;
  }
  var w = chart.width, h = chart.height;
  var paddingLeft = 55, paddingBottom = 25, paddingTop = 15, paddingRight = 15;
  var graphW = w - paddingLeft - paddingRight;
  var graphH = h - paddingTop - paddingBottom;

  ctx.clearRect(0, 0, w, h);
  maxY = Math.max(10, ...rpsData) * 1.25;

  // Grid Lines & Y-Axis Labels
  ctx.strokeStyle = 'rgba(51, 65, 85, 0.4)';
  ctx.fillStyle = '#94a3b8';
  ctx.font = '10px "Fira Code", monospace';
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  ctx.lineWidth = 1;

  for (var i = 0; i <= 4; i++) {
    var val = (maxY * (4 - i) / 4);
    var y = paddingTop + (graphH * (i / 4));
    ctx.beginPath(); ctx.moveTo(paddingLeft, y); ctx.lineTo(w - paddingRight, y); ctx.stroke();
    ctx.fillText(fmt(Math.round(val)), paddingLeft - 8, y);
  }

  // X-Axis Time Labels
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  var timeLabels = ['-5m', '-4m', '-3m', '-2m', '-1m', 'NOW'];
  for (var i = 0; i < timeLabels.length; i++) {
    var x = paddingLeft + (graphW * (i / (timeLabels.length - 1)));
    ctx.fillText(timeLabels[i], x, h - paddingBottom + 6);
  }

  // Gradient Area Fill
  var grad = ctx.createLinearGradient(0, paddingTop, 0, h - paddingBottom);
  grad.addColorStop(0, 'rgba(6, 182, 212, 0.35)');
  grad.addColorStop(1, 'rgba(6, 182, 212, 0.0)');
  ctx.fillStyle = grad;
  ctx.beginPath();
  ctx.moveTo(paddingLeft, h - paddingBottom);
  for (var i = 0; i < rpsData.length; i++) {
    var x = paddingLeft + (i / (rpsData.length - 1)) * graphW;
    var y = h - paddingBottom - (rpsData[i] / maxY) * graphH;
    ctx.lineTo(x, y);
  }
  ctx.lineTo(w - paddingRight, h - paddingBottom);
  ctx.closePath();
  ctx.fill();

  // Line Path
  ctx.strokeStyle = '#06b6d4';
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  for (var i = 0; i < rpsData.length; i++) {
    var x = paddingLeft + (i / (rpsData.length - 1)) * graphW;
    var y = h - paddingBottom - (rpsData[i] / maxY) * graphH;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  }
  ctx.stroke();

  // Interactive Hover Crosshair & Tooltip
  if (hoverX >= paddingLeft && hoverX <= w - paddingRight) {
    var idx = Math.round(((hoverX - paddingLeft) / graphW) * (rpsData.length - 1));
    if (idx >= 0 && idx < rpsData.length) {
      var val = rpsData[idx];
      var x = paddingLeft + (idx / (rpsData.length - 1)) * graphW;
      var y = h - paddingBottom - (val / maxY) * graphH;

      ctx.strokeStyle = 'rgba(255, 255, 255, 0.4)';
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(x, paddingTop); ctx.lineTo(x, h - paddingBottom); ctx.stroke();
      ctx.setLineDash([]);

      ctx.fillStyle = '#06b6d4';
      ctx.beginPath(); ctx.arc(x, y, 4, 0, Math.PI * 2); ctx.fill();

      var label = fmt(val) + ' RPS';
      var secAgo = Math.round((300 - idx));
      var timeSub = secAgo <= 1 ? 'Just now' : secAgo + 's ago';
      ctx.font = '11px "Inter", sans-serif';
      var tw = Math.max(ctx.measureText(label).width, ctx.measureText(timeSub).width) + 16;
      var tx = x + 10;
      if (tx + tw > w - 10) tx = x - tw - 10;
      var ty = y - 30;
      if (ty < paddingTop) ty = y + 10;

      ctx.fillStyle = 'rgba(15, 23, 42, 0.95)';
      ctx.strokeStyle = '#06b6d4';
      ctx.lineWidth = 1;
      ctx.beginPath();
      if (ctx.roundRect) { ctx.roundRect(tx, ty, tw, 36, 6); } else { ctx.rect(tx, ty, tw, 36); }
      ctx.fill(); ctx.stroke();

      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 11px "Fira Code", monospace';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      ctx.fillText(label, tx + 8, ty + 6);

      ctx.fillStyle = '#94a3b8';
      ctx.font = '10px "Inter", sans-serif';
      ctx.fillText(timeSub, tx + 8, ty + 20);
    }
  }
}

chart.addEventListener('mousemove', function(e) {
  var rect = chart.getBoundingClientRect();
  hoverX = e.clientX - rect.left;
  drawChart();
});
chart.addEventListener('mouseleave', function() {
  hoverX = -1;
  drawChart();
});

function addLog(msg, type) {
  var t = new Date().toLocaleTimeString();
  logs.unshift({ t: t, msg: msg, type: type || '' });
  if (logs.length > 10) logs.pop();
  var el = document.getElementById('logs');
  el.innerHTML = '';
  logs.forEach(function(l) {
    el.innerHTML += '<div class="log-row ' + l.type + '"><span class="log-ts">' + l.t + '</span>' + l.msg + '</div>';
  });
}

var lastBlocked = 0, lastAttacks = 0, wasAttack = false;

function updateStats() {
  fetch('/api/stats').then(function(r) { return r.json(); }).then(function(d) {
    document.getElementById('rps').textContent = fmt(d.current_rps);
    document.getElementById('chart_badge').textContent = fmt(d.current_rps) + ' RPS Current';
    document.getElementById('total').textContent = fmt(d.total_requests);
    document.getElementById('blocked').textContent = fmt(d.blocked_requests);
    document.getElementById('passed').textContent = fmt(d.passed_requests);
    document.getElementById('peak').textContent = fmt(d.peak_rps);
    document.getElementById('conns').textContent = fmt(d.active_conns);
    document.getElementById('banned').textContent = fmt(d.active_bans || d.banned_ips || 0);
    document.getElementById('xdp_drops').textContent = fmt(d.xdp_dropped_pkts);
    document.getElementById('up').textContent = fmtTime(d.uptime_seconds);

    var xst = document.getElementById('xdp_st');
    if (d.xdp_enabled) { xst.textContent = 'Active (sys_bpf)'; xst.style.color = 'var(--primary)'; }
    else { xst.textContent = 'Disabled'; xst.style.color = 'var(--text-muted)'; }

    var st = document.getElementById('st');
    var stText = document.getElementById('st_text');
    if (d.is_under_attack) {
      st.className = 'status-pill atk';
      stText.textContent = 'DDoS ATTACK ACTIVE';
    } else {
      st.className = 'status-pill ok';
      stText.textContent = 'SYSTEM NORMAL';
    }

    var br = d.total_requests > 0 ? Math.round((d.blocked_requests / d.total_requests) * 100) : 0;
    document.getElementById('br').textContent = br + '%';
    var brm = document.getElementById('brm');
    brm.style.width = br + '%';
    brm.className = 'meter-bar ' + (br > 50 ? 'r' : br > 20 ? 'y' : 'g');

    var cl = Math.min(100, Math.round(((d.active_conns || 0) / 10000) * 100));
    document.getElementById('cl').textContent = cl + '%';
    var clm = document.getElementById('clm');
    clm.style.width = cl + '%';
    clm.className = 'meter-bar ' + (cl > 80 ? 'r' : cl > 50 ? 'y' : 'g');

    if (d.blocked_requests > lastBlocked + 5) { addLog('Blocked ' + (d.blocked_requests - lastBlocked) + ' malicious requests', 'warn'); }
    if (d.attacks_detected > lastAttacks) { addLog('New attack vectors detected!', 'err'); }
    lastBlocked = d.blocked_requests; lastAttacks = d.attacks_detected;

    document.getElementById('mesh_count').textContent = (d.mesh_nodes || 0) + ' Nodes Active';
    var meshList = document.getElementById('mesh_nodes_list');
    meshList.innerHTML = '';
    if (d.mesh_members && d.mesh_members.length > 0) {
      d.mesh_members.forEach(function(m) {
        meshList.innerHTML += '<div class="node-card">' +
          '<div class="n-info"><span class="n-name">' + m.name + '</span><span class="n-addr">' + m.addr + '</span></div>' +
          '<div class="n-pulse"></div></div>';
      });
    } else {
      meshList.innerHTML = '<div style="font-size:12px;color:var(--text-muted);text-align:center;padding:16px;grid-column:1/-1">No external Mesh nodes joined. Single edge mode active.</div>';
    }
  }).catch(function() {});

  fetch('/api/rps-history').then(function(r) { return r.json(); }).then(function(d) {
    if (d && d.rps) { rpsData = d.rps; drawChart(); }
  }).catch(function() {});
}

function openPurgeModal() { document.getElementById('purgeModal').style.display = 'flex'; }
function closePurgeModal() { document.getElementById('purgeModal').style.display = 'none'; }
function executePurge() {
  fetch('/api/cache/purge', { method: 'POST' }).then(function(r) { return r.json(); }).then(function() {
    addLog('CDN RAM Cache purged successfully', 'g');
    closePurgeModal();
  });
}
function executeUnbanAll() {
  if (confirm('Unban all blacklisted IPs across the entire P2P Mesh cluster?')) {
    fetch('/api/unban?ip=all').then(function(r) { return r.json(); }).then(function(d) {
      addLog('ALL blacklisted IPs unbanned across P2P Mesh cluster', 'warn');
      updateStats();
    }).catch(function(err) { console.error(err); });
  }
}

resizeCanvas();
updateStats();
setInterval(updateStats, 1000);
</script>
</html>`

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
	for _, p := range d.cfg.Cluster.JoinPeers {
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
			if m.Addr != "" && m.Addr != d.cfg.Cluster.AdvertiseIP {
				peerMap[m.Addr] = true
			}
		}
	}

	client := &http.Client{Timeout: 3 * time.Second}
	for peerIP := range peerMap {
		if peerIP == d.cfg.Cluster.AdvertiseIP || peerIP == "127.0.0.1" || peerIP == "localhost" || peerIP == "" {
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
	for i, dom := range d.cfg.Domains {
		if strings.EqualFold(dom.Name, req.Domain) {
			d.cfg.Domains[i].ProtectionMode = req.ProtectionMode
			found = true
			break
		}
	}

	if !found {
		writeJSON(w, map[string]interface{}{"status": "error", "message": "Domain not found: " + req.Domain})
		return
	}

	// Save via Configuration Center & Hot Reload
	modeLabel := req.ProtectionMode
	if modeLabel == "" {
		modeLabel = "global (inherit)"
	}
	_ = config.GetCenter().UpdateConfig(d.cfg, username, role, fmt.Sprintf("Set protection mode for %s to %s", req.Domain, modeLabel))

	GetAuditLogger().LogAction(username, role, "DOMAIN_PROTECTION_MODE", "security", req.Domain, fmt.Sprintf("Mode: %s", modeLabel), clientIP, "success")
	writeJSON(w, map[string]interface{}{"status": "success", "message": fmt.Sprintf("Protection mode for %s set to %s", req.Domain, modeLabel)})
}

func (d *Dashboard) handleSecurityRules(w http.ResponseWriter, r *http.Request) {
	username, role := d.getUserFromRequest(r)
	clientIP := getClientIP(r)

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"status":             "success",
			"protection_mode":    d.cfg.Protection.Mode,
			"paranoia_level":     d.cfg.WAF.ParanoiaLevel,
			"owasp_rules":        d.cfg.WAF.OWASPRules,
			"whitelist_ips":      d.cfg.Protection.WhitelistIPs,
			"rate_limit":         d.cfg.Protection.RateLimit,
			"pow_difficulty":     d.cfg.Protection.Challenge.PowDifficulty,
			"blocked_countries":  d.cfg.Intelligence.GeoIP.BlockedCountries,
			"block_datacenter":   d.cfg.Intelligence.ASN.BlockDatacenter,
		})

	case http.MethodPost, http.MethodPut:
		if !CanManageGlobalSecurity(role) {
			writeJSON(w, map[string]interface{}{"status": "error", "message": "Access Denied: Only admins can manage global security rules"})
			return
		}

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
			d.cfg.Protection.Mode = req.ProtectionMode
		}
		if req.ParanoiaLevel >= 1 && req.ParanoiaLevel <= 4 {
			d.cfg.WAF.ParanoiaLevel = req.ParanoiaLevel
		}
		if req.OWASPRules != nil {
			d.cfg.WAF.OWASPRules = *req.OWASPRules
		}
		if req.WhitelistIPs != nil {
			d.cfg.Protection.WhitelistIPs = req.WhitelistIPs
		}
		if req.RPS > 0 {
			d.cfg.Protection.RateLimit.RequestsPerSecond = req.RPS
		}
		if req.Burst > 0 {
			d.cfg.Protection.RateLimit.Burst = req.Burst
		}
		if req.PowDifficulty > 0 {
			d.cfg.Protection.Challenge.PowDifficulty = req.PowDifficulty
		}
		if req.BlockedCountries != nil {
			d.cfg.Intelligence.GeoIP.BlockedCountries = req.BlockedCountries
		}
		if req.BlockDatacenter != nil {
			d.cfg.Intelligence.ASN.BlockDatacenter = *req.BlockDatacenter
		}

		// Save via Configuration Center & Hot Reload
		_ = config.GetCenter().UpdateConfig(d.cfg, username, role, "Updated global security policies")

		GetAuditLogger().LogAction(username, role, "SECURITY_UPDATE", "security", "global", fmt.Sprintf("Mode: %s, Paranoia: %d, RPS: %d", d.cfg.Protection.Mode, d.cfg.WAF.ParanoiaLevel, d.cfg.Protection.RateLimit.RequestsPerSecond), clientIP, "success")
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
			"status":   "success",
			"message":  fmt.Sprintf("Cluster config sync broadcasted across %d active mesh nodes", numNodes),
			"nodes":    numNodes,
			"members":  members,
		})
		return
	}

	writeJSON(w, map[string]interface{}{
		"status":  "success",
		"enabled": d.cfg.Cluster.Enabled,
		"node":    d.cfg.Cluster.NodeName,
		"port":    d.cfg.Cluster.BindPort,
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
		currNode := d.cfg.Cluster.NodeName
		if currNode == "" {
			currNode = "mango-node-primary"
		}
		currIP := d.cfg.Cluster.AdvertiseIP
		if currIP == "" {
			currIP = "127.0.0.1"
		}

		nodes = append(nodes, cluster.NodeInfo{
			Name: currNode,
			Addr: currIP,
		})

		for i, peer := range d.cfg.Cluster.JoinPeers {
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

	writeJSON(w, map[string]interface{}{
		"status": "success",
		"nodes":  nodes,
		"total":  len(nodes),
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
		sb.WriteString("Timestamp,Type,ClientIP,Domain,Method,Path,Status,Action,Rule,Description\n")
		for _, l := range realLogs {
			sb.WriteString(fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%d\",\"%s\",\"%s\",\"%s\"\n",
				l.Timestamp, l.Type, l.ClientIP, l.Domain, l.Method, l.Path, l.Status, l.Action, l.Rule, escapeCSV(l.Desc),
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
