package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"mango-waf/cluster"
	"mango-waf/config"
	"mango-waf/logger"
)

// TelegramStatusInfo tracks telemetry and health status for Telegram alerts
type TelegramStatusInfo struct {
	Connected   bool      `json:"connected"`
	LastSentAt  time.Time `json:"last_sent_at"`
	LastError   string    `json:"last_error"`
	TotalSent   int64     `json:"total_sent"`
	TotalFailed int64     `json:"total_failed"`
}

// AlertManager handles multi-channel alerts with rate limiting
type AlertManager struct {
	cfg        *config.Config
	mu         sync.Mutex
	lastSent   map[string]time.Time // rate limit per alert type
	cooldown   time.Duration
	queue      chan func()
	tgStatus   TelegramStatusInfo
	statusLock sync.RWMutex
	httpClient *http.Client
}

// NewAlertManager creates a new alert manager
func NewAlertManager(cfg *config.Config) *AlertManager {
	am := &AlertManager{
		cfg:      cfg,
		lastSent: make(map[string]time.Time),
		cooldown: 5 * time.Minute, // Tăng cooldown mặc định lên 5 phút để chống spam
		queue:    make(chan func(), 1000),
		tgStatus: TelegramStatusInfo{
			Connected: cfg.Alerts.Telegram.Enabled && cfg.Alerts.Telegram.Token != "" && cfg.Alerts.Telegram.ChatID != "",
		},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
	go am.workerLoop()
	return am
}

func (a *AlertManager) UpdateConfig(cfg *config.Config) {
	if a == nil || cfg == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg = cfg
}

func (a *AlertManager) workerLoop() {
	for job := range a.queue {
		if job != nil {
			job()
		}
	}
}

// GetTelegramStatus returns current Telegram integration health telemetry
func (a *AlertManager) GetTelegramStatus() TelegramStatusInfo {
	a.statusLock.RLock()
	defer a.statusLock.RUnlock()
	return a.tgStatus
}

// RemoteSilence is called when another node in the mesh has already sent an alert
func (a *AlertManager) RemoteSilence(alertType string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastSent[alertType] = time.Now()
	logger.Info("Alert silenced by Mesh sync", "type", alertType)
}

// canSend checks rate limit for an alert type
func (a *AlertManager) canSend(alertType string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Rate limit: 5 phút cho các cảnh báo tấn công, 30s cho các loại khác
	cd := a.cooldown
	if strings.Contains(alertType, "ban_") {
		cd = 30 * time.Second
	} else if strings.HasPrefix(alertType, "attack_start_") || strings.HasPrefix(alertType, "attack_end_") {
		cd = 0 // Bỏ rate limit, vì logic quản lý state ở server.go đã chống spam rồi
	}

	if last, ok := a.lastSent[alertType]; ok {
		if time.Since(last) < cd {
			return false
		}
	}
	a.lastSent[alertType] = time.Now()

	// Phát tín hiệu ra Mesh để các máy khác im lặng
	if m := cluster.GetMesh(); m != nil {
		go m.BroadcastAlert(alertType)
	}

	return true
}

// ClearCooldown resets the rate limit for a specific alert type
func (a *AlertManager) ClearCooldown(alertType string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.lastSent, alertType)
}

// SendDomainAttackStart sends attack start notification for a specific target domain with aggregated cluster metrics
func (a *AlertManager) SendDomainAttackStart(domain string, totalRPS, totalConns int64) {
	// Only the designated cluster leader sends external notifications to prevent duplication
	if m := cluster.GetMesh(); m != nil && !m.IsLeader() {
		return
	}

	if !a.canSend("attack_start_" + domain) {
		return
	}

	// Reset cooldown for attack_end so the end alert always triggers
	a.ClearCooldown("attack_end_" + domain)

	if domain != "General System" {
		domainAttackActiveMu.Lock()
		activeAttackDomain = domain
		domainAttackActiveMu.Unlock()
	}

	clusterSize := 1
	if m := cluster.GetMesh(); m != nil {
		clusterSize = m.NumMembers()
	}

	triggerReason := "L7 HTTP DDoS Attack"
	if totalConns > 500 {
		triggerReason = "L7 Connection Load / Slowloris Flood"
	}

	var title, domainLine, stateLine string
	if domain == "System" || domain == "General System" {
		title = "🚨 CẢNH BÁO TẤN CÔNG DDoS TOÀN HỆ THỐNG"
		domainLine = "🎯 Mục tiêu: Toàn bộ máy chủ (Global)"
		stateLine = "🔴 Trạng thái: UNDER ATTACK (Bảo vệ toàn cầu)"
	} else {
		title = "🚨 CẢNH BÁO TẤN CÔNG DDoS TÊN MIỀN"
		domainLine = fmt.Sprintf("🎯 Tên miền bị tấn công: <code>%s</code>", domain)
		stateLine = fmt.Sprintf("🔴 Trạng thái: UNDER ATTACK (Chế độ tự động bật cho domain %s)", domain)
	}

	telegramHTML := fmt.Sprintf(
		"<b>%s</b>\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n\n"+
			"%s\n"+
			"💥 <b>Loại tấn công:</b> <code>%s</code>\n"+
			"📊 <b>Tổng lưu lượng Cluster:</b> <code>%d req/s</code>\n"+
			"⚡ <b>Tổng Socket Cluster:</b> <code>%d conns</code>\n"+
			"🔗 <b>Trạng thái Mesh:</b> <code>%d Nodes Online</code>\n\n"+
			"%s\n"+
			"🛡️ <b>Hành động WAF:</b> Tự động nâng cấp siết chặt bảo vệ (PoW & eBPF)\n\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n"+
			"🥭 <i>Mango Shield Enterprise</i>",
		title,
		domainLine,
		triggerReason,
		totalRPS,
		totalConns,
		clusterSize,
		stateLine,
	)

	var discordTitle, discordDesc string
	if domain == "System" || domain == "General System" {
		discordTitle = "🚨 CẢNH BÁO TẤN CÔNG DDoS TOÀN HỆ THỐNG"
		discordDesc = fmt.Sprintf("Phát hiện tấn công DDoS trên **Toàn bộ máy chủ** (Tổng Cluster: **%d req/s**)", totalRPS)
	} else {
		discordTitle = "🚨 CẢNH BÁO TẤN CÔNG DDoS DOMAIN"
		discordDesc = fmt.Sprintf("Phát hiện tấn công DDoS trên tên miền **%s** (Tổng Cluster: **%d req/s**)", domain, totalRPS)
	}

	discordEmbed := DiscordEmbed{
		Title:       discordTitle,
		Description: discordDesc,
		Color:       0xFF4B4B, // Red
		Fields: []DiscordField{
			{Name: "🎯 Mục tiêu", Value: fmt.Sprintf("`%s`", domain), Inline: false},
			{Name: "💥 Loại tấn công", Value: fmt.Sprintf("`%s`", triggerReason), Inline: false},
			{Name: "📊 Tổng RPS Cluster", Value: fmt.Sprintf("`%d req/s`", totalRPS), Inline: true},
			{Name: "⚡ Tổng Sockets Cluster", Value: fmt.Sprintf("`%d conns`", totalConns), Inline: true},
			{Name: "🔗 Cluster Status", Value: fmt.Sprintf("`%d Nodes Online`", clusterSize), Inline: true},
			{Name: "🔴 Trạng thái", Value: "**UNDER ATTACK**", Inline: false},
			{Name: "🛡️ Hành động WAF", Value: "Tự động nâng cấp siết chặt bảo vệ (PoW & eBPF)", Inline: false},
		},
		Footer: DiscordFooter{Text: "🥭 Mango Shield v3.0 Enterprise"},
	}

	a.sendAllRich(telegramHTML, discordEmbed)
}

var (
	activeAttackDomain   string
	lastDomainAttackTime time.Time
	domainAttackActiveMu sync.RWMutex
)

// SendDomainAttackEnd sends attack end notification for a specific target domain
func (a *AlertManager) SendDomainAttackEnd(domain string, duration time.Duration, blocked int64) {
	logger.Info("AlertManager executing SendDomainAttackEnd", "domain", domain, "blocked", blocked, "duration", duration)

	// Only the designated cluster leader sends external notifications to prevent duplication
	if m := cluster.GetMesh(); m != nil && !m.IsLeader() {
		logger.Debug("AlertManager dropped SendDomainAttackEnd: not cluster leader")
		return
	}

	if !a.canSend("attack_end_" + domain) {
		logger.Warn("AlertManager dropped SendDomainAttackEnd: canSend returned false (Rate Limited)", "domain", domain)
		return
	}

	if domain != "General System" {
		domainAttackActiveMu.Lock()
		activeAttackDomain = ""
		lastDomainAttackTime = time.Now()
		domainAttackActiveMu.Unlock()
	}

	// Reset cooldown for attack_start so the NEXT attack triggers an alert immediately
	a.ClearCooldown("attack_start_" + domain)

	durStr := formatDuration(duration)

	var title, domainLine, stateLine string
	if domain == "System" || domain == "General System" {
		title = "✅ TẤN CÔNG TOÀN HỆ THỐNG ĐÃ KẾT THÚC"
		domainLine = "🎯 Mục tiêu: Toàn bộ máy chủ (Global)"
		stateLine = "🍀 Trạng thái: STABLE (Hệ thống trở lại bình thường)"
	} else {
		title = "✅ TẤN CÔNG ĐÃ KẾT THÚC"
		domainLine = fmt.Sprintf("🎯 Tên miền: <code>%s</code>", domain)
		stateLine = fmt.Sprintf("🍀 Trạng thái: STABLE (Domain %s trở lại bình thường)", domain)
	}

	telegramHTML := fmt.Sprintf(
		"<b>%s</b>\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n\n"+
			"%s\n"+
			"⏱️ <b>Thời gian kéo dài:</b> <code>%s</code>\n"+
			"🔒 <b>Đã chặn tổng cộng:</b> <code>%s requests</code>\n\n"+
			"%s\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n"+
			"🥭 <i>Mango Shield Enterprise</i>",
		title, domainLine, durStr, formatNumber(blocked), stateLine,
	)

	var discordTitle, discordDesc string
	if domain == "System" || domain == "General System" {
		discordTitle = "✅ TẤN CÔNG TOÀN HỆ THỐNG ĐÃ KẾT THÚC"
		discordDesc = "Đã phòng thủ thành công trên **Toàn bộ máy chủ**"
	} else {
		discordTitle = "✅ TẤN CÔNG ĐÃ KẾT THÚC"
		discordDesc = fmt.Sprintf("Đã phòng thủ thành công cho tên miền **%s**", domain)
	}

	discordEmbed := DiscordEmbed{
		Title:       discordTitle,
		Description: discordDesc,
		Color:       0x00D68F, // Green
		Fields: []DiscordField{
			{Name: "🎯 Mục tiêu", Value: fmt.Sprintf("`%s`", domain), Inline: false},
			{Name: "⏱️ Thời gian", Value: durStr, Inline: true},
			{Name: "🔒 Đã chặn", Value: formatNumber(blocked), Inline: true},
		},
		Footer: DiscordFooter{Text: "🥭 Mango Shield v3.0 Enterprise"},
	}

	a.sendAllRich(telegramHTML, discordEmbed)
}

// SendAttackStart sends beautiful attack start notification (suppressed if domain-specific alert active)
func (a *AlertManager) SendAttackStart(rps, conns int64) {
	domainAttackActiveMu.RLock()
	activeDomain := activeAttackDomain
	lastTime := lastDomainAttackTime
	domainAttackActiveMu.RUnlock()

	if activeDomain != "" || time.Since(lastTime) < 10*time.Minute {
		return // Suppress duplicate "General System" notification when domain attack is active or recently finished
	}
	a.SendDomainAttackStart("General System", rps, conns)
}

// SendAttackEnd sends attack ended notification (suppressed if domain-specific alert active)
func (a *AlertManager) SendAttackEnd(duration time.Duration, blocked int64) {
	domainAttackActiveMu.RLock()
	activeDomain := activeAttackDomain
	lastTime := lastDomainAttackTime
	domainAttackActiveMu.RUnlock()

	if activeDomain != "" || time.Since(lastTime) < 10*time.Minute {
		return // Suppress duplicate "General System" notification when domain attack is active or recently finished
	}
	a.SendDomainAttackEnd("General System", duration, blocked)
}

// SendBan sends IP ban notification (Disabled from Webhook to prevent spam during DDoS)
func (a *AlertManager) SendBan(ip, reason string, duration time.Duration) {
	// Only log to console/file, don't spam Webhooks during heavy botnet attacks
	// where thousands of IPs are banned per minute.
	logger.Debug("IP Banned", "ip", ip, "reason", reason, "duration", duration)
}

// SendReport sends periodic status report
func (a *AlertManager) SendReport(totalReqs, blocked, passed, bannedIPs, attacks int64, uptime time.Duration) {
	if !a.canSend("report") {
		return
	}

	blockRate := float64(0)
	if totalReqs > 0 {
		blockRate = float64(blocked) / float64(totalReqs) * 100
	}

	telegramHTML := fmt.Sprintf(
		"📊 <b>BÁO CÁO HỆ THỐNG</b>\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n\n"+
			"🖥️ <b>Node:</b> <code>%s</code>\n"+
			"📈 <b>Requests:</b> <code>%s</code>\n"+
			"🔒 <b>Đã chặn:</b> <code>%s</code> (%.1f%%)\n"+
			"✅ <b>Cho qua:</b> <code>%s</code>\n"+
			"🚫 <b>IP bị cấm:</b> <code>%d IP</code>\n"+
			"⚔️ <b>Tấn công:</b> <code>%d lần</code>\n"+
			"⏱️ <b>Uptime:</b> <code>%s</code>\n\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n"+
			"🥭 <i>Mango Shield v3.0 Enterprise</i>",
		a.cfg.Cluster.NodeName,
		formatNumber(totalReqs), formatNumber(blocked), blockRate,
		formatNumber(passed), bannedIPs, attacks, formatDuration(uptime),
	)

	discordEmbed := DiscordEmbed{
		Title: "📊 Báo cáo định kỳ",
		Color: 0x6B7AFF,
		Fields: []DiscordField{
			{Name: "🖥️ Node", Value: fmt.Sprintf("`%s`", a.cfg.Cluster.NodeName), Inline: true},
			{Name: "⏱️ Uptime", Value: formatDuration(uptime), Inline: true},
			{Name: "📈 Tổng Req", Value: formatNumber(totalReqs), Inline: true},
			{Name: "🔒 Đã chặn", Value: fmt.Sprintf("%s (%.1f%%)", formatNumber(blocked), blockRate), Inline: true},
			{Name: "🚫 IP cấm", Value: fmt.Sprintf("%d", bannedIPs), Inline: true},
			{Name: "⚔️ Tấn công", Value: fmt.Sprintf("%d", attacks), Inline: true},
		},
		Footer: DiscordFooter{Text: "🥭 Mango Shield v3.0 Enterprise"},
	}

	a.sendAllRich(telegramHTML, discordEmbed)
}

// SendCustom sends a custom alert message
func (a *AlertManager) SendCustom(msg string) {
	telegramHTML := fmt.Sprintf("ℹ️ <b>Mango Shield</b>\n\n%s", msg)
	discordEmbed := DiscordEmbed{
		Title:       "ℹ️ Thông báo",
		Description: msg,
		Color:       0x6B7AFF,
		Footer:      DiscordFooter{Text: "🥭 Mango Shield v3.0"},
	}
	a.sendAllRich(telegramHTML, discordEmbed)
}

// ================================================
// Discord Embed types
// ================================================

type DiscordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color"`
	Fields      []DiscordField `json:"fields,omitempty"`
	Footer      DiscordFooter  `json:"footer,omitempty"`
}

type DiscordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type DiscordFooter struct {
	Text string `json:"text"`
}

// ================================================
// Send methods
// ================================================

func (a *AlertManager) sendAllRich(telegramHTML string, discordEmbed DiscordEmbed) {
	select {
	case a.queue <- func() {
		if a.cfg.Alerts.Telegram.Enabled {
			go a.sendTelegram(telegramHTML)
		}
		if a.cfg.Alerts.Discord.Enabled {
			go a.sendDiscord(discordEmbed)
		}
		if a.cfg.Alerts.Webhook.Enabled {
			go a.sendWebhook(telegramHTML)
		}
	}:
	default:
		logger.Warn("Alert queue full, dropping notification")
	}
}

func (a *AlertManager) sendTelegram(html string) {
	cfg := a.cfg.Alerts.Telegram
	if cfg.Token == "" || cfg.ChatID == "" {
		return
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.Token)
	data := url.Values{
		"chat_id":                  {cfg.ChatID},
		"text":                     {html},
		"parse_mode":               {"HTML"},
		"disable_web_page_preview": {"true"},
	}

	backoffs := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	var lastErr error

	for attempt := 0; attempt < 3; attempt++ {
		resp, err := a.httpClient.PostForm(apiURL, data)
		if err == nil {
			if resp.StatusCode == 200 {
				resp.Body.Close()
				a.statusLock.Lock()
				a.tgStatus.Connected = true
				a.tgStatus.LastSentAt = time.Now()
				a.tgStatus.TotalSent++
				a.statusLock.Unlock()
				return
			}
			lastErr = fmt.Errorf("HTTP status %d", resp.StatusCode)
			resp.Body.Close()
		} else {
			lastErr = err
		}

		if attempt < 2 {
			time.Sleep(backoffs[attempt])
		}
	}

	logger.Error("Telegram gửi thất bại sau khi retry", "error", lastErr)
	a.statusLock.Lock()
	a.tgStatus.Connected = false
	a.tgStatus.LastError = fmt.Sprintf("%v", lastErr)
	a.tgStatus.TotalFailed++
	a.statusLock.Unlock()
}

func (a *AlertManager) sendDiscord(embed DiscordEmbed) {
	cfg := a.cfg.Alerts.Discord
	if cfg.WebhookURL == "" {
		return
	}

	payload := map[string]interface{}{
		"embeds": []DiscordEmbed{embed},
	}
	body, _ := json.Marshal(payload)
	logger.Debug("Sending Discord alert", "embed_title", embed.Title)

	backoffs := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	var lastErr error

	for attempt := 0; attempt < 3; attempt++ {
		resp, err := a.httpClient.Post(cfg.WebhookURL, "application/json", bytes.NewReader(body))
		if err == nil {
			if resp.StatusCode < 400 {
				resp.Body.Close()
				logger.Info("Discord alert sent successfully", "title", embed.Title)
				return
			}
			b, _ := io.ReadAll(resp.Body)
			lastErr = fmt.Errorf("HTTP status %d: %s", resp.StatusCode, string(b))
			resp.Body.Close()
		} else {
			lastErr = err
		}
		if attempt < 2 {
			time.Sleep(backoffs[attempt])
		}
	}
	logger.Error("Discord gửi thất bại sau khi retry", "error", lastErr)
}

func (a *AlertManager) sendWebhook(text string) {
	cfg := a.cfg.Alerts.Webhook
	if cfg.URL == "" {
		return
	}

	payload := map[string]interface{}{
		"message":   text,
		"timestamp": time.Now().Format(time.RFC3339),
		"source":    "mango-shield",
		"version":   "v3.0",
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", cfg.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Secret != "" {
		req.Header.Set("X-Webhook-Secret", cfg.Secret)
	}

	backoffs := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	var lastErr error

	for attempt := 0; attempt < 3; attempt++ {
		// Recreate body reader for each retry
		req.Body = io.NopCloser(bytes.NewReader(body))
		
		resp, err := a.httpClient.Do(req)
		if err == nil {
			if resp.StatusCode < 400 {
				resp.Body.Close()
				return
			}
			lastErr = fmt.Errorf("HTTP status %d", resp.StatusCode)
			resp.Body.Close()
		} else {
			lastErr = err
		}
		if attempt < 2 {
			time.Sleep(backoffs[attempt])
		}
	}
	logger.Error("Webhook gửi thất bại sau khi retry", "error", lastErr)
}

// ================================================
// Helpers
// ================================================

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func formatNumber(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	if n < 1000000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	return fmt.Sprintf("%.1fB", float64(n)/1000000000)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 24 {
		days := h / 24
		return fmt.Sprintf("%d ngày %d giờ", days, h%24)
	}
	if h > 0 {
		return fmt.Sprintf("%d giờ %d phút", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%d phút %d giây", m, s)
	}
	return fmt.Sprintf("%d giây", s)
}
