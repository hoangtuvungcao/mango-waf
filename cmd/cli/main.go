package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	baseURL := "http://127.0.0.1:9090"
	if envURL := os.Getenv("MANGO_API"); envURL != "" {
		baseURL = envURL
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "status", "st":
		cmdStatus(baseURL)
	case "health", "h":
		cmdHealth(baseURL)
	case "config", "cf":
		cmdConfig(baseURL)
	case "watch", "w":
		cmdWatch(baseURL, args)
	case "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Lệnh không hợp lệ: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(` Mango Shield CLI — Công cụ quản lý

SỬ DỤNG:
  mango-cli <lệnh> [tùy chọn]

CÁC LỆNH:
  status, st      Xem trạng thái hệ thống hiện tại
  health, h       Kiểm tra sức khỏe server
  config, cf      Xem cấu hình đang chạy
  watch,  w       Theo dõi thời gian thực (cập nhật mỗi giây)
  help            Hiển thị trợ giúp này

BIẾN MÔI TRƯỜNG:
  MANGO_API       URL Dashboard API (mặc định: http://127.0.0.1:9090)

VÍ DỤ:
  mango-cli status
  mango-cli watch --interval 2
  MANGO_API=http://admin:pass@10.0.0.1:9090 mango-cli status`)
}

func cmdStatus(base string) {
	data, err := apiGet(base, "/api/stats")
	if err != nil {
		fmt.Fprintf(os.Stderr, " Không kết nối được: %v\n", err)
		os.Exit(1)
	}

	var stats map[string]interface{}
	json.Unmarshal(data, &stats)

	underAttack := getBool(stats, "is_under_attack")
	statusStr := "🟢 Bình thường"
	if underAttack {
		statusStr = " ĐANG BỊ TẤN CÔNG"
	}

	fmt.Println("\n Mango Shield — Trạng thái hệ thống")
	fmt.Println(strings.Repeat("", 45))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  Trạng thái:\t%s\n", statusStr)
	fmt.Fprintf(w, "  RPS hiện tại:\t%s req/s\n", fmtNum(getFloat(stats, "current_rps")))
	fmt.Fprintf(w, "  RPS đỉnh:\t%s req/s\n", fmtNum(getFloat(stats, "peak_rps")))
	fmt.Fprintf(w, "  Tổng requests:\t%s\n", fmtNum(getFloat(stats, "total_requests")))
	fmt.Fprintf(w, "  Đã chặn:\t%s\n", fmtNum(getFloat(stats, "blocked_requests")))
	fmt.Fprintf(w, "  Đã cho qua:\t%s\n", fmtNum(getFloat(stats, "passed_requests")))
	fmt.Fprintf(w, "  Kết nối đang mở:\t%s\n", fmtNum(getFloat(stats, "active_conns")))
	fmt.Fprintf(w, "  IP bị cấm:\t%s\n", fmtNum(getFloat(stats, "banned_ips")))
	fmt.Fprintf(w, "  Số cuộc tấn công:\t%s\n", fmtNum(getFloat(stats, "attacks_detected")))
	fmt.Fprintf(w, "  Uptime:\t%s\n", fmtDuration(getFloat(stats, "uptime_seconds")))
	w.Flush()

	total := getFloat(stats, "total_requests")
	blocked := getFloat(stats, "blocked_requests")
	if total > 0 {
		rate := blocked / total * 100
		fmt.Printf("\n   Tỷ lệ chặn: %.1f%%\n", rate)
	}
	fmt.Println()
}

func cmdHealth(base string) {
	data, err := apiGet(base, "/api/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, " Server không phản hồi: %v\n", err)
		os.Exit(1)
	}

	var health map[string]interface{}
	json.Unmarshal(data, &health)

	status := getString(health, "status")
	version := getString(health, "version")
	uptime := getString(health, "uptime")

	icon := "🟢"
	if status != "healthy" {
		icon = ""
	}

	fmt.Printf("\n%s Sức khỏe: %s\n", icon, strings.ToUpper(status))
	fmt.Printf("  Phiên bản: %s\n", version)
	fmt.Printf("  Uptime: %s\n\n", uptime)
}

func cmdConfig(base string) {
	data, err := apiGet(base, "/api/config")
	if err != nil {
		fmt.Fprintf(os.Stderr, " Không thể lấy cấu hình: %v\n", err)
		os.Exit(1)
	}

	var cfg map[string]interface{}
	json.Unmarshal(data, &cfg)

	fmt.Println("\n Cấu hình đang chạy")
	fmt.Println(strings.Repeat("", 35))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  Chế độ bảo vệ:\t%s\n", getString(cfg, "mode"))
	fmt.Fprintf(w, "  Số domain:\t%.0f\n", getFloat(cfg, "domains"))
	fmt.Fprintf(w, "  TLS:\t%v\n", getBool(cfg, "tls"))
	fmt.Fprintf(w, "  WAF:\t%v\n", getBool(cfg, "waf"))
	w.Flush()

	if fp, ok := cfg["fingerprint"].(map[string]interface{}); ok {
		fmt.Printf("  JA3 Fingerprint:\t%v\n", getBool(fp, "ja3"))
		fmt.Printf("  JA4 Fingerprint:\t%v\n", getBool(fp, "ja4"))
	}
	fmt.Println()
}

func cmdWatch(base string, args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	interval := fs.Int("interval", 1, "Thời gian cập nhật (giây)")
	fs.Parse(args)

	fmt.Println(" Mango Shield — Theo dõi thời gian thực")
	fmt.Println("   Nhấn Ctrl+C để thoát")

	for {
		data, err := apiGet(base, "/api/stats")
		if err != nil {
			fmt.Printf("\r Mất kết nối...                    ")
			time.Sleep(time.Duration(*interval) * time.Second)
			continue
		}

		var stats map[string]interface{}
		json.Unmarshal(data, &stats)

		underAttack := getBool(stats, "is_under_attack")
		status := "🟢 OK"
		if underAttack {
			status = " ATTACK"
		}

		fmt.Printf("\r%s | RPS: %-6s | Blocked: %-8s | Conns: %-5s | Banned: %-5s | Uptime: %s     ",
			status,
			fmtNum(getFloat(stats, "current_rps")),
			fmtNum(getFloat(stats, "blocked_requests")),
			fmtNum(getFloat(stats, "active_conns")),
			fmtNum(getFloat(stats, "banned_ips")),
			fmtDuration(getFloat(stats, "uptime_seconds")),
		)

		time.Sleep(time.Duration(*interval) * time.Second)
	}
}

// === Helpers ===

func apiGet(base, path string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(base + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf, nil
}

func getFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return n
		case int64:
			return float64(n)
		}
	}
	return 0
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func fmtNum(n float64) string {
	if n >= 1e9 {
		return fmt.Sprintf("%.1fB", n/1e9)
	}
	if n >= 1e6 {
		return fmt.Sprintf("%.1fM", n/1e6)
	}
	if n >= 1e3 {
		return fmt.Sprintf("%.1fK", n/1e3)
	}
	return fmt.Sprintf("%.0f", n)
}

func fmtDuration(secs float64) string {
	d := time.Duration(secs) * time.Second
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
