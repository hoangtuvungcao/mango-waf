package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"
	"time"

	"mango-waf/api"
	"mango-waf/cluster"
	"mango-waf/config"
	"mango-waf/core"
	"mango-waf/detection"
	"mango-waf/fingerprint"
	"mango-waf/intelligence"
	"mango-waf/logger"
	"mango-waf/perf"
	"mango-waf/rules"
)

var (
	version   = "v3.0"
	buildDate = "dev"
)

func main() {
	configPath := flag.String("config", "config/default.yaml", "Đường dẫn file cấu hình")
	testConfig := flag.Bool("test", false, "Kiểm tra cú pháp file cấu hình rồi thoát")
	showVersion := flag.Bool("version", false, "Hiển thị phiên bản")
	showHelp := flag.Bool("help", false, "Hiển thị trợ giúp")
	flag.Parse()

	if *showHelp {
		printBanner()
		flag.Usage()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("Mango Shield v%s (build: %s, go: %s)\n", version, buildDate, runtime.Version())
		os.Exit(0)
	}

	// Set soft GOMEMLIMIT (2.5 GiB) to force aggressive GC sweeps under heavy HTTPS DDoS before OS OOM killer
	debug.SetMemoryLimit(2500 * 1024 * 1024)

	// GOGC=20: trigger GC when heap grows by 20% instead of default 100%.
	// This keeps heap small at the cost of more frequent GC cycles.
	// Critical for HTTPS DDoS: each TLS conn allocates ~32KB, 10K conns = 320MB heap growth.
	// With GOGC=100 (default), GC only fires at 640MB → OOM before GC can help.
	// With GOGC=20, GC fires at 64MB growth → keeps memory manageable.
	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(20)

	printBanner()

	// === 1. Load Configuration ===
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[LỖI] Không thể tải cấu hình: %v\n", err)
		os.Exit(1)
	}

	if *testConfig {
		fmt.Printf("   Cú pháp cấu hình chuẩn xác (Syntax OK): %s\n", *configPath)
		fmt.Printf("   Test thành công. WAF sẵn sàng khởi chạy.\n")
		os.Exit(0)
	}

	fmt.Printf("   Cấu hình đã tải: %s\n", *configPath)

	// Merge persistent dynamic domains from storage without randomizing domain order
	st := api.GetStorage()
	if st != nil && len(st.Data.Domains) > 0 {
		domainMap := make(map[string]config.DomainConfig)
		for _, d := range st.Data.Domains {
			domainMap[strings.ToLower(d.Name)] = d
		}
		for i, d := range cfg.Domains {
			if stored, ok := domainMap[strings.ToLower(d.Name)]; ok {
				cfg.Domains[i] = stored
				delete(domainMap, strings.ToLower(d.Name))
			}
		}
		var newNames []string
		for k := range domainMap {
			newNames = append(newNames, k)
		}
		sort.Strings(newNames)
		for _, k := range newNames {
			cfg.Domains = append(cfg.Domains, domainMap[k])
		}
	}

	// === 2. Initialize Logger ===
	if err := logger.Init(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.File); err != nil {
		fmt.Fprintf(os.Stderr, "[LỖI] Khởi tạo logger thất bại: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()
	fmt.Printf("   Logger khởi tạo: level=%s, format=%s\n", cfg.Logging.Level, cfg.Logging.Format)

	// === 3. Configure Runtime & Operating System Limits ===
	runtime.GOMAXPROCS(runtime.NumCPU())
	fmt.Printf("   Runtime: GOMAXPROCS=%d\n", runtime.NumCPU())

	var rLimit syscall.Rlimit
	rLimit.Max = 100000
	rLimit.Cur = 100000
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		fmt.Printf("   RLIMIT_NOFILE warning: %v\n", err)
	} else {
		fmt.Println("   OS Socket Limit: RLIMIT_NOFILE set to 100,000 file descriptors")
	}

	// === 4. Initialize Fingerprint Engine ===
	fingerprint.InitKnownBrowsers()
	fingerprint.InitKnownH2Fingerprints()
	fpStore := fingerprint.NewFingerprintStore()
	fmt.Println("   Fingerprint engine: JA3/JA4/H2 databases loaded")

	// === 5. Initialize Intelligence Layer ===
	intel := intelligence.NewIntel(cfg)
	defer intel.Close()
	fmt.Println("   Intelligence layer: GeoIP, Reputation, ASN, Feeds")

	// === 6. Initialize Detection Engine ===
	detEngine := detection.NewEngine(cfg)
	behaviorAnalyzer := detection.NewBehaviorAnalyzer()
	botClassifier := detection.NewBotClassifier()
	attackDetector := detection.NewAttackDetector()
	adaptiveLearner := detection.NewAdaptiveLearner()
	fmt.Println("   Detection engine: Behavior, Bot Classifier, Attack Detector, Adaptive")

	// === 7. Initialize WAF Rules Engine ===
	wafEngine := rules.NewEngine(cfg)
	if cfg.WAF.CustomRulesPath != "" {
		if err := wafEngine.LoadCustomRules(cfg.WAF.CustomRulesPath); err != nil {
			logger.Warn("Custom WAF rules load failed", "error", err)
		}
	}
	fmt.Printf("   WAF engine: %d rules loaded (paranoia=%d)\n", len(wafEngine.GetRules()), cfg.WAF.ParanoiaLevel)

	// === 8. Initialize Performance Manager ===
	memMgr := perf.NewMemoryManager(2048) // 2GB max
	rateLimiter := perf.NewIPRateLimiter(
		float64(cfg.Protection.RateLimit.RequestsPerSecond),
		float64(cfg.Protection.RateLimit.Burst),
	)
	degrader := perf.NewGracefulDegrader()
	fmt.Println("   Performance: Rate Limiter, Memory Manager, Graceful Degradation")

	// === 9. Initialize CDN Smart Cache ===
	if err := core.InitCDN(cfg.CDN); err != nil {
		logger.Warn("Failed to initialize CDN", "error", err)
	} else if cfg.CDN.Enabled {
		fmt.Println("   CDN Caching Engine enabled (Ristretto)")
	}

	// === 9.5 Initialize Cloudflare Edge Banning Worker ===
	core.InitCloudflareManager()
	go core.CFManager.RunWorker()
	core.CFManager.StartAutoCleanup(cfg.Protection.Ban.Duration)
	if cfg.Cloudflare.Enabled {
		fmt.Println("   Cloudflare API Integration enabled (Background Sync)")
	}

	// === 10. Create Shield Server & Wire All Engines ===
	um := core.NewUpstreamManager(cfg)
	defer um.Close()

	shield := core.New(cfg)

	// === Initialize Configuration Center (Single Source of Truth) ===
	center := config.InitCenter(*configPath)
	center.RegisterReloadHook(func(newCfg *config.Config) error {
		shield.ReloadConfig(newCfg)
		logger.Info("ConfigCenter: Hot-reloaded all WAF security engines successfully", "domains", len(newCfg.Domains))
		return nil
	})
	shield.SetFingerprintStore(fpStore)
	shield.SetIntel(intel)
	shield.SetDetectionEngine(detEngine)
	shield.SetBehaviorAnalyzer(behaviorAnalyzer)
	shield.SetBotClassifier(botClassifier)
	shield.SetAttackDetector(attackDetector)
	shield.SetAdaptiveLearner(adaptiveLearner)
	shield.SetWAFEngine(wafEngine)
	shield.SetRateLimiter(rateLimiter)
	shield.SetGracefulDegrader(degrader)
	shield.SetUpstreamManager(um)
	fmt.Printf("   Shield server: domains=%d, mode=%s (ALL engines wired)\n", len(cfg.Domains), cfg.Protection.Mode)

	// === 11. Initialize Mango P2P Mesh ===
	if err := cluster.InitMesh(cfg.Cluster, func(ip string, duration time.Duration) {
		shield.GetPipeline().BanIPRemote(ip, duration)
	}, func(alertType string) {
		shield.GetPipeline().GetAlerts().RemoteSilence(alertType)
	}); err != nil {
		logger.Warn("Failed to initialize Mango Mesh", "error", err)
	} else if cfg.Cluster.Enabled {
		if mesh := cluster.GetMesh(); mesh != nil {
			mesh.SetUnbanHandler(func(ip string) {
				if ip == "all" {
					shield.GetPipeline().UnbanAllIPs()
				} else {
					shield.GetPipeline().UnbanIP(ip)
				}
			})
		}
		fmt.Printf("   Mango P2P Mesh enabled: Node %s (Port %d)\n", cfg.Cluster.NodeName, cfg.Cluster.BindPort)
	}

	// Keep memory manager reference alive (it runs its own goroutine)
	_ = memMgr

	// === 11. Start Dashboard API ===
	if cfg.Dashboard.Enabled {
		statsAdapter := &api.StatsAdapter{
			TotalReqs:   &shield.GetStats().TotalRequests,
			BlockedReqs: &shield.GetStats().BlockedRequests,
			PassedReqs:  &shield.GetStats().PassedRequests,
			CurrRPS:     &shield.GetStats().CurrentRPS,
			PkRPS:       &shield.GetStats().PeakRPS,
			ActiveCn:    &shield.GetStats().ActiveConns,
			BannedIP:    &shield.GetStats().BannedIPs,
			AttacksDet:  &shield.GetStats().AttacksDetected,
			UnderAttack: &shield.GetStats().IsUnderAttack,
			UptimeStart: shield.GetStats().Uptime,
			XDP:         shield.GetXDPStats,
			EarlyStats:  fingerprint.GetEarlyRejectStats,
			CDNStats:    core.GetCDN().GetStats,
			MeshStats: func() (bool, int) {
				m := cluster.GetMesh()
				if m == nil {
					return false, 0
				}
				return true, m.NumMembers()
			},
			MeshMembers: func() []cluster.NodeInfo {
				m := cluster.GetMesh()
				if m == nil {
					return []cluster.NodeInfo{}
				}
				return m.GetMembers()
			},
			UnbanFunc: func(ip string) {
				shield.GetPipeline().UnbanIP(ip)
			},
			UnbanAll: func() {
				shield.GetPipeline().UnbanAllIPs()
			},
			UpdateUpstreamFunc: func(domains []config.DomainConfig) {
				shield.UpdateUpstreams(domains)
			},
			GetBannedIPsListFunc: func() []api.BannedIPEntry {
				rawList := shield.GetPipeline().GetBannedIPsList()
				entries := make([]api.BannedIPEntry, 0, len(rawList))
				for _, raw := range rawList {
					parts := strings.SplitN(raw, "|", 3)
					if len(parts) == 3 {
						ttl := int64(0)
						fmt.Sscanf(parts[2], "%d", &ttl)
						entries = append(entries, api.BannedIPEntry{
							IP:        parts[0],
							ExpiresAt: parts[1],
							TTLSec:    ttl,
						})
					}
				}
				return entries
			},
		}
		dashboard := api.NewDashboard(cfg, statsAdapter)
		if shield.GetPipeline() != nil {
			dashboard.SetAlertManager(shield.GetPipeline().GetAlerts())
		}
		go func() {
			if err := dashboard.Start(); err != nil {
				logger.Error("Dashboard failed", "error", err)
			}
		}()
		fmt.Printf("   Dashboard API: http://%s\n", cfg.Dashboard.Listen)
	}

	// === 12. Start Metrics Endpoint ===
	if cfg.Metrics.Enabled {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc(cfg.Metrics.Path, func(w http.ResponseWriter, r *http.Request) {
				stats := shield.GetStats()
				uptime := time.Since(stats.Uptime).Seconds()
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				fmt.Fprintf(w, "# HELP mango_requests_total Total requests processed\n")
				fmt.Fprintf(w, "# TYPE mango_requests_total counter\n")
				fmt.Fprintf(w, "mango_requests_total %d\n", stats.TotalRequests)
				fmt.Fprintf(w, "# HELP mango_requests_blocked Total blocked requests\n")
				fmt.Fprintf(w, "# TYPE mango_requests_blocked counter\n")
				fmt.Fprintf(w, "mango_requests_blocked %d\n", stats.BlockedRequests)
				fmt.Fprintf(w, "# HELP mango_requests_passed Total passed requests\n")
				fmt.Fprintf(w, "# TYPE mango_requests_passed counter\n")
				fmt.Fprintf(w, "mango_requests_passed %d\n", stats.PassedRequests)
				fmt.Fprintf(w, "# HELP mango_rps_current Current requests per second\n")
				fmt.Fprintf(w, "# TYPE mango_rps_current gauge\n")
				fmt.Fprintf(w, "mango_rps_current %d\n", stats.CurrentRPS)
				fmt.Fprintf(w, "# HELP mango_rps_peak Peak RPS\n")
				fmt.Fprintf(w, "# TYPE mango_rps_peak gauge\n")
				fmt.Fprintf(w, "mango_rps_peak %d\n", stats.PeakRPS)
				fmt.Fprintf(w, "# HELP mango_active_connections Current active connections\n")
				fmt.Fprintf(w, "# TYPE mango_active_connections gauge\n")
				fmt.Fprintf(w, "mango_active_connections %d\n", stats.ActiveConns)
				fmt.Fprintf(w, "# HELP mango_banned_ips Total banned IPs\n")
				fmt.Fprintf(w, "# TYPE mango_banned_ips gauge\n")
				fmt.Fprintf(w, "mango_banned_ips %d\n", stats.BannedIPs)
				fmt.Fprintf(w, "# HELP mango_attacks_detected Total attacks detected\n")
				fmt.Fprintf(w, "# TYPE mango_attacks_detected counter\n")
				fmt.Fprintf(w, "mango_attacks_detected %d\n", stats.AttacksDetected)
				fmt.Fprintf(w, "# HELP mango_uptime_seconds Uptime in seconds\n")
				fmt.Fprintf(w, "# TYPE mango_uptime_seconds gauge\n")
				fmt.Fprintf(w, "mango_uptime_seconds %.0f\n", uptime)
				// WAF stats
				wafStats := wafEngine.GetStats()
				fmt.Fprintf(w, "# HELP mango_waf_inspected Total WAF inspected requests\n")
				fmt.Fprintf(w, "# TYPE mango_waf_inspected counter\n")
				fmt.Fprintf(w, "mango_waf_inspected %v\n", wafStats["total_inspected"])
				fmt.Fprintf(w, "# HELP mango_waf_blocked Total WAF blocked requests\n")
				fmt.Fprintf(w, "# TYPE mango_waf_blocked counter\n")
				fmt.Fprintf(w, "mango_waf_blocked %v\n", wafStats["total_blocked"])
				// Memory stats
				memStats := memMgr.GetMemStats()
				fmt.Fprintf(w, "# HELP mango_memory_alloc_mb Allocated memory in MB\n")
				fmt.Fprintf(w, "# TYPE mango_memory_alloc_mb gauge\n")
				fmt.Fprintf(w, "mango_memory_alloc_mb %v\n", memStats["alloc_mb"])
				fmt.Fprintf(w, "# HELP mango_goroutines Number of goroutines\n")
				fmt.Fprintf(w, "# TYPE mango_goroutines gauge\n")
				fmt.Fprintf(w, "mango_goroutines %v\n", memStats["goroutines"])
			})
			server := &http.Server{Addr: cfg.Metrics.Listen, Handler: mux}
			logger.Info("Metrics endpoint started", "listen", cfg.Metrics.Listen, "path", cfg.Metrics.Path)
			fmt.Printf("   Metrics: http://%s%s\n", cfg.Metrics.Listen, cfg.Metrics.Path)
			if err := server.ListenAndServe(); err != nil {
				logger.Error("Metrics server failed", "error", err)
			}
		}()
	}

	// === 11. Graceful Shutdown ===
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				logger.Info("SIGHUP received — hot reload config")
				if err := config.Reload(*configPath); err != nil {
					logger.Error("Config reload failed", "error", err)
				} else {
					logger.Info("Config reloaded successfully")
				}
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("Shutdown signal received, stopping...")
				fmt.Println("\n Đang dừng Mango Shield...")
				shield.Stop()
				intel.Close()
				logger.Info("Mango Shield stopped gracefully")
				os.Exit(0)
			}
		}
	}()

	// === 13. Start Server ===
	fmt.Println("\n Mango Shield v3.0 — Đang bảo vệ!")
	fmt.Printf("   HTTPS: %s | HTTP: %s\n", cfg.Server.Listen, cfg.Server.HTTPListen)
	fmt.Println("   Nhấn Ctrl+C để dừng, gửi SIGHUP để tải lại cấu hình")

	if err := shield.Start(); err != nil {
		logger.Fatal("Server khởi động thất bại", "error", err)
	}
}

func printBanner() {
	fmt.Println(`
  
            MANGO SHIELD v3.0         
         L7 DDoS Protection & WAF       
        github.com/hoangtuvungcao       
  `)
	fmt.Println()
}
