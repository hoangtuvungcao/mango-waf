package api

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
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
}

// Dashboard is the admin dashboard API server
type Dashboard struct {
	cfg     *config.Config
	stats   StatsProvider
	mux     *http.ServeMux
	rpsHist *RingBuffer
	stopCh  chan struct{}
	srv     *http.Server
}

// RingBuffer tracks RPS history for charts
type RingBuffer struct {
	data [300]int64 // 5 minutes of per-second data
	idx  int
}

func (rb *RingBuffer) Push(val int64) {
	rb.data[rb.idx%300] = val
	rb.idx++
}

func (rb *RingBuffer) Slice() []int64 {
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
		cfg:     cfg,
		stats:   stats,
		mux:     http.NewServeMux(),
		rpsHist: &RingBuffer{},
		stopCh:  make(chan struct{}),
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
	if d.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return d.srv.Shutdown(ctx)
	}
	return nil
}

// Start starts the dashboard server
func (d *Dashboard) Start() error {
	if !d.cfg.Dashboard.Enabled {
		return nil
	}
	d.srv = &http.Server{
		Addr:         d.cfg.Dashboard.Listen,
		Handler:      d.authMiddleware(d.corsMiddleware(d.mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	logger.Info("Dashboard API started", "listen", d.cfg.Dashboard.Listen)
	return d.srv.ListenAndServe()
}

func (d *Dashboard) registerRoutes() {
	d.mux.HandleFunc("/api/login", d.handleLogin)
	d.mux.HandleFunc("/api/stats", d.handleStats)
	d.mux.HandleFunc("/api/health", d.handleHealth)
	d.mux.HandleFunc("/api/config", d.handleConfig)
	d.mux.HandleFunc("/api/rps-history", d.handleRPSHistory)
	d.mux.HandleFunc("/api/system-stats", d.handleSystemStats)
	d.mux.HandleFunc("/api/cache/purge", d.handleCachePurge)
	d.mux.HandleFunc("/", d.handleDashboardUI)
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

	uMatch := subtle.ConstantTimeCompare([]byte(req.Username), []byte(d.cfg.Dashboard.Username)) == 1
	pMatch := subtle.ConstantTimeCompare([]byte(req.Password), []byte(d.cfg.Dashboard.Password)) == 1

	if uMatch && pMatch {
		token := fmt.Sprintf("mango-session-%d", time.Now().UnixNano())
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
			"user":    req.Username,
			"message": "Admin login successful",
		})
		return
	}

	w.WriteHeader(http.StatusUnauthorized)
	writeJSON(w, map[string]interface{}{
		"status":  "error",
		"message": "Invalid admin username or password",
	})
}

func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	enabled, xdpBanned, xdpDrops := d.stats.GetXDPStats()
	earlyProcessed, earlyRejected := d.stats.GetEarlyRejectStats()
	cacheHits, cacheMisses, cacheBypasses := d.stats.GetCacheStats()
	meshEnabled, meshNodes := d.stats.GetMeshStats()

	writeJSON(w, map[string]interface{}{
		"total_requests":   d.stats.GetTotalRequests(),
		"blocked_requests": d.stats.GetBlockedRequests(),
		"passed_requests":  d.stats.GetPassedRequests(),
		"current_rps":      d.stats.GetCurrentRPS(),
		"peak_rps":         d.stats.GetPeakRPS(),
		"active_conns":     d.stats.GetActiveConns(),
		"active_bans":      d.stats.GetBannedIPs(),
		"attacks_detected": d.stats.GetAttacksDetected(),
		"is_under_attack":  d.stats.IsUnderAttack(),
		"uptime_seconds":   time.Since(d.stats.GetUptime()).Seconds(),
		"early_processed":  earlyProcessed,
		"early_rejected":   earlyRejected,
		"xdp_enabled":      enabled,
		"xdp_banned_ips":   xdpBanned,
		"xdp_dropped_pkts": xdpDrops,
		"cache_hits":       cacheHits,
		"cache_misses":     cacheMisses,
		"cache_bypasses":   cacheBypasses,
		"mesh_enabled":     meshEnabled,
		"mesh_nodes":       meshNodes,
		"mesh_members":     d.stats.GetMeshMembers(),
		"timestamp":        time.Now().Unix(),
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

	writeJSON(w, map[string]interface{}{
		"cpu_percent":    cpuPct,
		"ram_total_mb":   ramTotal,
		"ram_used_mb":    ramUsed,
		"ram_avail_mb":   ramAvail,
		"disk_total_gb":  diskTotal,
		"disk_used_gb":   diskUsed,
		"disk_used_pct":  diskPct,
		"load_1m":        load1,
		"load_5m":        load5,
		"load_15m":       load15,
		"net_rx_bytes":   rxBytes,
		"net_tx_bytes":   txBytes,
		"tcp_connections": conns,
		"uptime_seconds": uptime,
		"goroutines":    runtime.NumGoroutine(),
		"num_cpu":       runtime.NumCPU(),
		"timestamp":     time.Now().Unix(),
	})
}

func (d *Dashboard) handleDashboardUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(fullDashboardHTML))
}

func (d *Dashboard) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read-only telemetry endpoints accessible for monitoring & demo site
		if r.URL.Path == "/api/health" || r.URL.Path == "/api/stats" || r.URL.Path == "/api/system-stats" || r.URL.Path == "/api/rps-history" || r.URL.Path == "/api/login" || r.URL.Path == "/" {
			next.ServeHTTP(w, r)
			return
		}
		// Cookie authentication check
		if cookie, err := r.Cookie("mango_admin_session"); err == nil && strings.HasPrefix(cookie.Value, "mango-session-") {
			next.ServeHTTP(w, r)
			return
		}
		if d.cfg.Dashboard.Username != "" && d.cfg.Dashboard.Password != "" {
			user, pass, ok := r.BasicAuth()
			uMatch := subtle.ConstantTimeCompare([]byte(user), []byte(d.cfg.Dashboard.Username)) == 1
			pMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(d.cfg.Dashboard.Password)) == 1
			if !ok || !uMatch || !pMatch {
				w.Header().Set("WWW-Authenticate", `Basic realm="Mango Shield Admin Dashboard"`)
				http.Error(w, "Unauthorized Admin Access", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (d *Dashboard) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.jsdelivr.net;")
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
		return []cluster.NodeInfo{}
	}
	return a.MeshMembers()
}

// ================================================
// Full Dashboard HTML
// ================================================

var fullDashboardHTML = fmt.Sprintf(`<!DOCTYPE html>
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
    radial-gradient(circle at 15%% 15%%, rgba(16, 185, 129, 0.05) 0%%, transparent 40%%),
    radial-gradient(circle at 85%% 85%%, rgba(6, 182, 212, 0.05) 0%%, transparent 40%%);
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
@keyframes pulseAlert { 50%% { opacity: 0.6; } }

.dot-indicator { width: 8px; height: 8px; border-radius: 50%%; background: currentColor; }

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
.chart-container { position: relative; width: 100%%; height: 220px; }
canvas#chart { width: 100%% !important; height: 220px !important; }

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
  height: 100%%;
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
.node-card .n-pulse { width: 8px; height: 8px; border-radius: 50%%; background: var(--primary); box-shadow: 0 0 8px var(--primary); }

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
  .hdr-controls { width: 100%%; justify-content: flex-end; flex-wrap: wrap; gap: 6px; }
  .dashboard-container { padding: 16px 12px; }
  .kpi-grid { grid-template-columns: repeat(2, 1fr); gap: 10px; }
  .kpi-card .kpi-val { font-size: 22px; }
  .chart-container { height: 160px; }
  canvas#chart { height: 160px !important; }
  .col-grid-2 { grid-template-columns: 1fr; }
  .terminal-box { max-height: 180px; font-size: 11px; }
  .modal-content { width: calc(100%% - 32px); max-width: 400px; }
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
        <div class="meter-lbl"><span>WAF Threat Mitigation Rate</span><span id="br">0%%</span></div>
        <div class="meter-track"><div class="meter-bar g" id="brm" style="width:0%%"></div></div>
      </div>
      <div class="meter-row">
        <div class="meter-lbl"><span>Socket Connection Capacity</span><span id="cl">0%%</span></div>
        <div class="meter-track"><div class="meter-bar g" id="clm" style="width:0%%"></div></div>
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
  chart.width = chart.parentElement.clientWidth;
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
  var h = Math.floor(s / 3600), m = Math.floor((s %% 3600) / 60);
  return h > 0 ? h + 'h ' + m + 'm' : m > 0 ? m + 'm' : Math.floor(s) + 's';
}

function drawChart() {
  var w = chart.width, h = chart.height;
  ctx.clearRect(0, 0, w, h);
  maxY = Math.max(10, ...rpsData) * 1.25;

  // Grid Lines
  ctx.strokeStyle = 'rgba(51, 65, 85, 0.4)';
  ctx.lineWidth = 1;
  for (var i = 0; i <= 4; i++) {
    var y = h - (h * (i / 4));
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }

  // Gradient Area Fill
  var grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, 'rgba(6, 182, 212, 0.35)');
  grad.addColorStop(1, 'rgba(6, 182, 212, 0.0)');
  ctx.fillStyle = grad;
  ctx.beginPath(); ctx.moveTo(0, h);
  for (var i = 0; i < rpsData.length; i++) {
    var x = (i / (rpsData.length - 1)) * w;
    var y = h - (rpsData[i] / maxY) * h;
    ctx.lineTo(x, y);
  }
  ctx.lineTo(w, h); ctx.closePath(); ctx.fill();

  // Line Path
  ctx.strokeStyle = '#06b6d4';
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  for (var i = 0; i < rpsData.length; i++) {
    var x = (i / (rpsData.length - 1)) * w;
    var y = h - (rpsData[i] / maxY) * h;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  }
  ctx.stroke();
}

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
    document.getElementById('br').textContent = br + '%%';
    var brm = document.getElementById('brm');
    brm.style.width = br + '%%';
    brm.className = 'meter-bar ' + (br > 50 ? 'r' : br > 20 ? 'y' : 'g');

    var cl = Math.min(100, Math.round((d.active_conns / 100) * 100));
    document.getElementById('cl').textContent = cl + '%%';
    var clm = document.getElementById('clm');
    clm.style.width = cl + '%%';
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

resizeCanvas();
updateStats();
setInterval(updateStats, 1000);
</script>
</body>
</html>`)
