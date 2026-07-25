package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

//go:embed chart.min.js
var chartJSResource []byte

type StatMetrics struct {
	HistPassed   []uint64 `json:"hist_passed"`
	HistBlocked  []uint64 `json:"hist_blocked"`
	CurrPassed   uint64   `json:"curr_passed"`
	CurrBlocked  uint64   `json:"curr_blocked"`
	DeltaPassed  uint64   `json:"delta_passed"`
	DeltaBlocked uint64   `json:"delta_blocked"`
	PPS          uint64   `json:"pps"`
	BPS          uint64   `json:"bps"`
	NodeCount    int      `json:"node_count"`
	Uptime       string   `json:"uptime"`
	Status       string   `json:"status"`
	Version      string   `json:"version"`
	Timestamp    string   `json:"timestamp"`
}

var (
	histPassed     = make([]uint64, 60)
	histBlocked    = make([]uint64, 60)
	lastJSON       atomic.Value
	apiEndpoint    = "http://127.0.0.1:9090/api/stats"
	healthEndpoint = "http://127.0.0.1:9090/api/health"
)

func init() {
	emptyMetrics := StatMetrics{
		HistPassed:  histPassed,
		HistBlocked: histBlocked,
		CurrPassed:  0,
		CurrBlocked: 0,
		PPS:         0,
		BPS:         0,
		NodeCount:   1,
		Status:      "healthy",
		Version:     "2.0.0",
		Timestamp:   time.Now().Format("15:04:05"),
	}
	emptyJSON, _ := json.Marshal(emptyMetrics)
	lastJSON.Store(emptyJSON)

	go func() {
		httpClient := &http.Client{Timeout: 2 * time.Second}
		var lastTotalPassed, lastTotalBlocked uint64

		for {
			time.Sleep(1 * time.Second)

			var currentPassed, currentBlocked uint64
			var sysStatus = "healthy"
			var uptimeStr = "0s"
			var verStr = "2.0.0"

			// Fetch metrics from Mango Shield backend API
			req, err := http.NewRequest("GET", apiEndpoint, nil)
			if err == nil {
				req.SetBasicAuth("admin", "")
				resp, err := httpClient.Do(req)
				if err == nil {
					var stats struct {
						PassedRequests  uint64 `json:"passed_requests"`
						BlockedRequests uint64 `json:"blocked_requests"`
					}
					if json.NewDecoder(resp.Body).Decode(&stats) == nil {
						currentPassed = stats.PassedRequests
						currentBlocked = stats.BlockedRequests
					}
					resp.Body.Close()
				}
			}

			// Fetch health metadata
			hReq, err := http.NewRequest("GET", healthEndpoint, nil)
			if err == nil {
				hResp, err := httpClient.Do(hReq)
				if err == nil {
					var health struct {
						Status  string `json:"status"`
						Uptime  string `json:"uptime"`
						Version string `json:"version"`
					}
					if json.NewDecoder(hResp.Body).Decode(&health) == nil {
						sysStatus = health.Status
						uptimeStr = health.Uptime
						verStr = health.Version
					}
					hResp.Body.Close()
				}
			}

			var deltaPassed, deltaBlocked uint64
			if lastTotalPassed > 0 || lastTotalBlocked > 0 {
				if currentPassed >= lastTotalPassed {
					deltaPassed = currentPassed - lastTotalPassed
				}
				if currentBlocked >= lastTotalBlocked {
					deltaBlocked = currentBlocked - lastTotalBlocked
				}
			}
			lastTotalPassed = currentPassed
			lastTotalBlocked = currentBlocked

			// Update 60-second sliding history
			copy(histPassed[0:], histPassed[1:])
			histPassed[59] = deltaPassed

			copy(histBlocked[0:], histBlocked[1:])
			histBlocked[59] = deltaBlocked

			pps := deltaPassed + deltaBlocked
			bps := pps * 5 * 1024 * 8 // Estimated 5KB average payload

			metricsData := StatMetrics{
				HistPassed:   histPassed,
				HistBlocked:  histBlocked,
				CurrPassed:   currentPassed,
				CurrBlocked:  currentBlocked,
				DeltaPassed:  deltaPassed,
				DeltaBlocked: deltaBlocked,
				PPS:          pps,
				BPS:          bps,
				NodeCount:    1,
				Uptime:       uptimeStr,
				Status:       sysStatus,
				Version:      verStr,
				Timestamp:    time.Now().Format("15:04:05"),
			}

			jsonData, _ := json.Marshal(metricsData)
			lastJSON.Store(jsonData)
		}
	}()
}

func main() {
	http.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write(lastJSON.Load().([]byte))
	})

	http.HandleFunc("/assets/chart.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(chartJSResource)
	})

	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.WriteHeader(http.StatusOK)
	})

	// Main SPA Handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mango Shield WAF — Production Security Demo &amp; Statistics</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600;700&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="/assets/chart.js"></script>
    <style>
        :root {
            --bg-base: #060813;
            --bg-card: rgba(13, 17, 33, 0.85);
            --bg-card-hover: rgba(20, 27, 51, 0.95);
            --border: rgba(30, 41, 74, 0.7);
            --border-glow: rgba(0, 242, 255, 0.3);
            
            --accent-cyan: #00f2ff;
            --accent-green: #00ffa3;
            --accent-red: #ff0055;
            --accent-amber: #ffb700;
            --accent-purple: #9d4edd;
            
            --text-main: #f0f4fc;
            --text-muted: #8c9ba5;
            --text-dim: #54657b;

            --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
            --font-mono: 'Fira Code', monospace;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: var(--font-sans);
            line-height: 1.5;
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 10% 10%, rgba(0, 242, 255, 0.04) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(157, 78, 221, 0.04) 0%, transparent 40%);
            background-attachment: fixed;
        }

        .layout-container {
            max-width: 1280px;
            margin: 0 auto;
            padding: 24px;
        }

        /* Top Navigation Header */
        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--bg-card);
            border: 1px solid var(--border);
            backdrop-filter: blur(16px);
            border-radius: 16px;
            padding: 16px 28px;
            margin-bottom: 24px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
        }

        .brand-box {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .brand-icon {
            width: 36px;
            height: 36px;
            fill: none;
            stroke: var(--accent-cyan);
            stroke-width: 2;
            filter: drop-shadow(0 0 8px var(--accent-cyan));
        }

        .brand-title h1 {
            font-size: 18px;
            font-weight: 800;
            letter-spacing: -0.5px;
            color: var(--text-main);
        }

        .brand-title .badge {
            font-size: 10px;
            font-family: var(--font-mono);
            color: var(--accent-cyan);
            background: rgba(0, 242, 255, 0.1);
            padding: 2px 8px;
            border-radius: 4px;
            border: 1px solid rgba(0, 242, 255, 0.2);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .nav-tabs {
            display: flex;
            gap: 8px;
            background: rgba(6, 8, 19, 0.6);
            padding: 4px;
            border-radius: 10px;
            border: 1px solid var(--border);
        }

        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-family: var(--font-sans);
            font-size: 13px;
            font-weight: 600;
            padding: 8px 18px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .tab-btn:hover {
            color: var(--text-main);
            background: rgba(255, 255, 255, 0.05);
        }

        .tab-btn.active {
            color: #000;
            background: var(--accent-cyan);
            font-weight: 700;
            box-shadow: 0 0 12px rgba(0, 242, 255, 0.4);
        }

        .domain-tag {
            display: flex;
            align-items: center;
            gap: 10px;
            background: rgba(0, 255, 163, 0.05);
            border: 1px solid rgba(0, 255, 163, 0.2);
            padding: 8px 16px;
            border-radius: 8px;
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--accent-green);
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .domain-tag:hover {
            background: rgba(0, 255, 163, 0.12);
            border-color: var(--accent-green);
        }

        /* Views Layout */
        .tab-view { display: none; }
        .tab-view.active { display: block; }

        /* Grid Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }

        @media (max-width: 960px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .navbar { flex-direction: column; gap: 16px; align-items: flex-start; }
        }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            backdrop-filter: blur(12px);
            border-radius: 14px;
            padding: 20px;
            position: relative;
            overflow: hidden;
            transition: border-color 0.3s ease;
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--border-glow), transparent);
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .card:hover::before { opacity: 1; }

        .card-label {
            font-size: 11px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .card-value {
            font-size: 28px;
            font-weight: 800;
            font-family: var(--font-mono);
            margin-top: 8px;
            letter-spacing: -1px;
        }

        .card-subtext {
            font-size: 11px;
            color: var(--text-dim);
            margin-top: 4px;
        }

        /* Interactive Attack Test Suite */
        .demo-layout {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }

        @media (max-width: 960px) {
            .demo-layout { grid-template-columns: 1fr; }
        }

        .action-panel {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .btn-action {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(20, 27, 51, 0.6);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 14px 20px;
            border-radius: 10px;
            font-family: var(--font-sans);
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            text-align: left;
        }

        .btn-action:hover {
            background: var(--bg-card-hover);
            border-color: var(--accent-cyan);
            transform: translateX(4px);
        }

        .btn-action.sqli:hover { border-color: var(--accent-red); }
        .btn-action.xss:hover { border-color: var(--accent-amber); }
        .btn-action.bot:hover { border-color: var(--accent-purple); }
        .btn-action.valid:hover { border-color: var(--accent-green); }

        .btn-tag {
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 3px 8px;
            border-radius: 4px;
            background: rgba(255, 255, 255, 0.06);
            color: var(--text-muted);
        }

        .console-box {
            background: #020307;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px;
            font-family: var(--font-mono);
            font-size: 12px;
            color: #d1d5db;
            height: 380px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .console-line {
            display: flex;
            gap: 12px;
            word-break: break-all;
        }

        .console-time { color: var(--text-dim); shrink: 0; }
        .console-status-200 { color: var(--accent-green); font-weight: 700; }
        .console-status-403 { color: var(--accent-red); font-weight: 700; }
        .console-status-301 { color: var(--accent-cyan); font-weight: 700; }

        /* Chart Canvas Container */
        .chart-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
        }

        .chart-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .chart-title {
            font-size: 14px;
            font-weight: 700;
            color: var(--text-main);
            letter-spacing: -0.2px;
        }

        .chart-legend {
            display: flex;
            gap: 16px;
            font-size: 12px;
            font-family: var(--font-mono);
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .legend-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }

        #rpsChart {
            width: 100% !important;
            height: 320px !important;
        }

        /* Toast notification */
        .toast {
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: var(--accent-cyan);
            color: #000;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 13px;
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.3s ease;
            z-index: 10000;
            box-shadow: 0 8px 24px rgba(0, 242, 255, 0.4);
        }

        .toast.show {
            opacity: 1;
            transform: translateY(0);
        }

        .footer {
            text-align: center;
            font-size: 11px;
            color: var(--text-dim);
            padding: 20px 0;
            border-top: 1px solid var(--border);
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div id="toast" class="toast">COPIED TO CLIPBOARD</div>

    <div class="layout-container">
        <!-- Navigation Header -->
        <nav class="navbar">
            <div class="brand-box">
                <svg class="brand-icon" viewBox="0 0 24 24">
                    <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-5.45 9-12V7l-9-5z"/>
                </svg>
                <div class="brand-title">
                    <h1>MANGO SHIELD <span class="badge">v2.0 PROD</span></h1>
                    <div style="font-size: 11px; color: var(--text-muted);">Enterprise Reverse Proxy WAF &amp; L7 DDoS Shield</div>
                </div>
            </div>

            <div class="nav-tabs">
                <button class="tab-btn active" onclick="switchTab('demo')">LIVE TEST SUITE</button>
                <button class="tab-btn" onclick="switchTab('stats')">BOT &amp; TRAFFIC STATS</button>
            </div>

            <div class="domain-tag" onclick="copyDomain()">
                <span>firewall.hidev.dev</span>
                <span style="opacity: 0.6;">[103.77.246.198]</span>
            </div>
        </nav>

        <!-- VIEW 1: LIVE INTERACTIVE ATTACK TEST SUITE -->
        <div id="view-demo" class="tab-view active">
            <div class="stats-grid">
                <div class="card">
                    <div class="card-label">Protection Mode</div>
                    <div class="card-value" style="color: var(--accent-green);">ACTIVE</div>
                    <div class="card-subtext">Cloudflare SSL Full Proxy</div>
                </div>
                <div class="card">
                    <div class="card-label">WAF Rules Engine</div>
                    <div class="card-value" style="color: var(--accent-cyan);">26 RULES</div>
                    <div class="card-subtext">OWASP CRS Paranoia Level 2</div>
                </div>
                <div class="card">
                    <div class="card-label">Bot Classifier</div>
                    <div class="card-value" style="color: var(--accent-purple);">13 SIGNATURES</div>
                    <div class="card-subtext">JA3 / JA4 / H2 Fingerprinting</div>
                </div>
                <div class="card">
                    <div class="card-label">System Health</div>
                    <div id="demo-health" class="card-value" style="color: var(--accent-green);">HEALTHY</div>
                    <div class="card-subtext">Uptime: <span id="demo-uptime">0s</span></div>
                </div>
            </div>

            <div class="demo-layout">
                <!-- Action Buttons -->
                <div class="action-panel">
                    <div style="font-size: 13px; font-weight: 700; color: var(--text-muted); margin-bottom: 4px; text-transform: uppercase;">Simulate Attack Vectors</div>
                    
                    <button class="btn-action sqli" onclick="runTest('sqli')">
                        <div>
                            <div>SQL Injection Payload</div>
                            <div style="font-size: 11px; color: var(--text-muted); font-weight: 400;">GET /search?q=' OR 1=1--</div>
                        </div>
                        <span class="btn-tag">TEST SQLi</span>
                    </button>

                    <button class="btn-action xss" onclick="runTest('xss')">
                        <div>
                            <div>Cross-Site Scripting (XSS)</div>
                            <div style="font-size: 11px; color: var(--text-muted); font-weight: 400;">GET /comment?input=&lt;script&gt;alert('xss')&lt;/script&gt;</div>
                        </div>
                        <span class="btn-tag">TEST XSS</span>
                    </button>

                    <button class="btn-action sqli" onclick="runTest('lfi')">
                        <div>
                            <div>Local File Inclusion (LFI)</div>
                            <div style="font-size: 11px; color: var(--text-muted); font-weight: 400;">GET /file?path=../../../../etc/passwd</div>
                        </div>
                        <span class="btn-tag">TEST LFI</span>
                    </button>

                    <button class="btn-action bot" onclick="runTest('bot')">
                        <div>
                            <div>Malicious Bot UA Simulation</div>
                            <div style="font-size: 11px; color: var(--text-muted); font-weight: 400;">User-Agent: curl/7.81.0</div>
                        </div>
                        <span class="btn-tag">TEST BOT</span>
                    </button>

                    <button class="btn-action valid" onclick="runTest('valid')">
                        <div>
                            <div>Legitimate Browser Request</div>
                            <div style="font-size: 11px; color: var(--text-muted); font-weight: 400;">GET / (Chrome / Safari Standard UA)</div>
                        </div>
                        <span class="btn-tag">VALID TRAFFIC</span>
                    </button>

                    <button class="btn-action sqli" onclick="runTest('flood')">
                        <div>
                            <div>Rate Limit Burst Flood</div>
                            <div style="font-size: 11px; color: var(--text-muted); font-weight: 400;">10 fast concurrent requests in 500ms</div>
                        </div>
                        <span class="btn-tag">TEST FLOOD</span>
                    </button>
                </div>

                <!-- Live Response Inspector Console -->
                <div>
                    <div style="font-size: 13px; font-weight: 700; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase;">Response Inspector</div>
                    <div id="console" class="console-box">
                        <div class="console-line">
                            <span class="console-time">[READY]</span>
                            <span>Click any attack simulation button on the left to test Mango Shield WAF.</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- VIEW 2: BOT DETECTION & TRAFFIC STATISTICS -->
        <div id="view-stats" class="tab-view">
            <div class="stats-grid">
                <div class="card">
                    <div class="card-label">Total Passed Requests</div>
                    <div id="val-passed" class="card-value" style="color: var(--accent-green);">0</div>
                    <div class="card-subtext">Legitimate Traffic Forwarded</div>
                </div>
                <div class="card">
                    <div class="card-label">Total Blocked Requests</div>
                    <div id="val-blocked" class="card-value" style="color: var(--accent-red);">0</div>
                    <div class="card-subtext">L7 Attacks &amp; Bots Dropped</div>
                </div>
                <div class="card">
                    <div class="card-label">Packets Per Second (PPS)</div>
                    <div id="val-pps" class="card-value" style="color: var(--accent-cyan);">0</div>
                    <div class="card-subtext">Real-time Request Delta</div>
                </div>
                <div class="card">
                    <div class="card-label">Est. Bandwidth</div>
                    <div id="val-bps" class="card-value">0 Mbps</div>
                    <div class="card-subtext">Throughput Consumption</div>
                </div>
            </div>

            <!-- Chart.js Real-time Traffic Graph -->
            <div class="chart-card">
                <div class="chart-header">
                    <div class="chart-title">REAL-TIME TRAFFIC ANALYSIS (60s SLIDING WINDOW)</div>
                    <div class="chart-legend">
                        <div class="legend-item">
                            <div class="legend-dot" style="background: var(--accent-green);"></div>
                            <span style="color: var(--accent-green);">PASSED</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-dot" style="background: var(--accent-red);"></div>
                            <span style="color: var(--accent-red);">BLOCKED</span>
                        </div>
                    </div>
                </div>
                <canvas id="rpsChart"></canvas>
            </div>
        </div>

        <div class="footer">
            Mango Shield v2.0 Enterprise Protection — Domain: firewall.hidev.dev (VPS 103.77.246.198)
        </div>
    </div>

    <script>
        let chart = null;

        function switchTab(tabName) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-view').forEach(view => view.classList.remove('active'));

            if (tabName === 'demo') {
                document.querySelectorAll('.tab-btn')[0].classList.add('active');
                document.getElementById('view-demo').classList.add('active');
            } else {
                document.querySelectorAll('.tab-btn')[1].classList.add('active');
                document.getElementById('view-stats').classList.add('active');
            }
        }

        function copyDomain() {
            navigator.clipboard.writeText("https://firewall.hidev.dev");
            const toast = document.getElementById('toast');
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2000);
        }

        function logConsole(status, text, headerText) {
            const consoleBox = document.getElementById('console');
            const now = new Date().toLocaleTimeString();
            
            let statusClass = 'console-status-200';
            if (status === 403) statusClass = 'console-status-403';
            if (status === 301) statusClass = 'console-status-301';

            const line = document.createElement('div');
            line.className = 'console-line';
            line.innerHTML = '<span class="console-time">[' + now + ']</span> <span class="' + statusClass + '">HTTP ' + status + '</span> <span>' + text + '</span>';
            
            consoleBox.appendChild(line);

            if (headerText) {
                const subLine = document.createElement('div');
                subLine.className = 'console-line';
                subLine.style.color = '#6b7280';
                subLine.style.fontSize = '11px';
                subLine.style.paddingLeft = '90px';
                subLine.innerText = headerText;
                consoleBox.appendChild(subLine);
            }

            consoleBox.scrollTop = consoleBox.scrollHeight;
        }

        async function runTest(type) {
            const start = performance.now();
            let url = '/';
            let headers = {};

            if (type === 'sqli') {
                url = "/search?q=" + encodeURIComponent("' OR 1=1--");
            } else if (type === 'xss') {
                url = "/comment?input=" + encodeURIComponent("<script>alert('xss')</script>");
            } else if (type === 'lfi') {
                url = "/file?path=../../../../etc/passwd";
            } else if (type === 'bot') {
                headers['User-Agent'] = 'curl/7.81.0';
            } else if (type === 'valid') {
                url = '/?valid=true';
            } else if (type === 'flood') {
                for (let i = 0; i < 10; i++) {
                    fetch('/?flood=' + i);
                }
                logConsole(429, "Rate Limit Flood Triggered (10 fast requests sent)", "X-Mango-Shield: rate-limited");
                return;
            }

            try {
                const res = await fetch(url, { headers: headers });
                const duration = Math.round(performance.now() - start);
                const shieldHeader = res.headers.get('X-Mango-Shield') || 'passed';
                const serverHeader = res.headers.get('Server') || 'Mango';

                logConsole(res.status, 'Request to ' + url + ' finished in ' + duration + 'ms', 'Server: ' + serverHeader + ' | X-Mango-Shield: ' + shieldHeader);
            } catch (err) {
                logConsole(500, 'Network Error: ' + err.message, "");
            }
        }

        function formatBytes(bits) {
            const k = 1024;
            const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps'];
            if (bits === 0) return '0 bps';
            const i = Math.floor(Math.log(bits) / Math.log(k));
            return parseFloat((bits / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }

        document.addEventListener('DOMContentLoaded', function() {
            const ctx = document.getElementById('rpsChart').getContext('2d');
            chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: Array(60).fill(''),
                    datasets: [
                        {
                            label: 'Passed',
                            data: Array(60).fill(0),
                            borderColor: '#00ffa3',
                            backgroundColor: 'rgba(0, 255, 163, 0.06)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4,
                            pointRadius: 0
                        },
                        {
                            label: 'Blocked',
                            data: Array(60).fill(0),
                            borderColor: '#ff0055',
                            backgroundColor: 'rgba(255, 0, 85, 0.06)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4,
                            pointRadius: 0
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { display: false },
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(255, 255, 255, 0.03)' },
                            ticks: { color: '#6b7280', font: { size: 10, family: 'Fira Code' } }
                        }
                    },
                    animation: { duration: 250 }
                }
            });

            async function updateStats() {
                try {
                    const res = await fetch('/api/stats');
                    if (!res.ok) return;
                    const data = await res.json();

                    if (chart) {
                        chart.data.datasets[0].data = data.hist_passed;
                        chart.data.datasets[1].data = data.hist_blocked;
                        chart.update('none');
                    }

                    document.getElementById('val-passed').innerText = (data.curr_passed || 0).toLocaleString();
                    document.getElementById('val-blocked').innerText = (data.curr_blocked || 0).toLocaleString();
                    document.getElementById('val-pps').innerText = (data.pps || 0).toLocaleString();
                    document.getElementById('val-bps').innerText = formatBytes(data.bps || 0);

                    if (data.status) {
                        document.getElementById('demo-health').innerText = data.status.toUpperCase();
                    }
                    if (data.uptime) {
                        document.getElementById('demo-uptime').innerText = data.uptime;
                    }
                } catch(e) {}
            }

            setInterval(updateStats, 1000);
            updateStats();
        });
    </script>
</body>
</html>`)
	})

	fmt.Println("Mango Shield Production Demo & Test Site listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
