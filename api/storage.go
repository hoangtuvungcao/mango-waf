package api

import (
	"encoding/json"
	"os"
	"sync"

	"mango-waf/config"
	"mango-waf/logger"
)

type StorageData struct {
	Users    []UserAccount         `json:"users"`
	Domains  []config.DomainConfig `json:"domains"`
	Pricing  []PricingPlan         `json:"pricing"`
	Docs     []DocItem             `json:"docs"`
	Settings SystemSettings        `json:"settings"`
}

type UserAccount struct {
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	Email        string   `json:"email"`
	Role         string   `json:"role"` // "admin" or "user"
	Domains      []string `json:"domains"`
	SessionToken string   `json:"session_token,omitempty"`
}

type PricingPlan struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Price      string   `json:"price"`
	Period     string   `json:"period"`
	Subtitle   string   `json:"subtitle"`
	Featured   bool     `json:"featured"`
	Features   []string `json:"features"`
	ButtonText string   `json:"button_text"`
}

type DocItem struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Content  string `json:"content"`
}

type SystemSettings struct {
	TelegramToken  string `json:"telegram_token"`
	TelegramChat   string `json:"telegram_chat"`
	DiscordURL     string `json:"discord_url"`
	WebhookURL     string `json:"webhook_url"`
	ProtectionMode string `json:"protection_mode"`
}

type Storage struct {
	mu       sync.RWMutex
	filePath string
	Data     StorageData
}

var globalStorage *Storage

func GetStorage() *Storage {
	if globalStorage == nil {
		globalStorage = InitStorage("data/mango_db.json")
	}
	return globalStorage
}

func InitStorage(filePath string) *Storage {
	s := &Storage{
		filePath: filePath,
	}
	s.load()
	globalStorage = s
	return s
}

func (s *Storage) load() {
	s.mu.Lock()
	defer s.mu.Unlock()

	adminUser := "admin"
	adminPass := "admin123"
	adminEmail := "admin@mango-shield.local"

	cfg := config.Get()
	if cfg != nil {
		if cfg.Dashboard.Username != "" {
			adminUser = cfg.Dashboard.Username
		}
		if cfg.Dashboard.Password != "" {
			adminPass = cfg.Dashboard.Password
		}
		adminEmail = adminUser + "@mango-shield.local"
	}

	s.Data = StorageData{
		Users: []UserAccount{
			{Username: adminUser, Password: adminPass, Email: adminEmail, Role: "super_admin"},
		},
		Pricing: []PricingPlan{
			{ID: "enterprise_free", Name: "Enterprise Shield Plan", Price: "Free", Period: "/trọn đời", Subtitle: "Gói cao cấp nhất - 100% Free thử nghiệm hệ thống", Featured: true, Features: []string{"Không Giới Hạn Tên Miền", "Công Nghệ eBPF/XDP Kernel", "WAF Rules Engine - OWASP Top 10", "PoW Browser Challenge", "Multi-Node Cluster", "Tự Động Cấp Phát Chứng Chỉ SSL/TLS", "Hỗ Trợ Ẩn IP Gốc Bằng Bản Ghi CNAME"}, ButtonText: "Đăng Ký & Sử Dụng Ngay (Free)"},
		},
		Docs: []DocItem{
			{ID: "quickstart", Title: "Quickstart Guide", Category: "Getting Started", Content: "To protect your website with Mango Shield WAF, add your domain in Domain Manager and point your DNS CNAME record to the WAF CNAME target configured in YAML."},
			{ID: "ssl-setup", Title: "Auto SSL Setup", Category: "Security", Content: "Mango Shield automatically generates and renews SAN SSL certificates for all your domains. Ensure your domain points to the WAF node."},
			{ID: "ddos-defense", Title: "DDoS Mitigation Layer", Category: "Protection", Content: "Layer 7 DDoS attacks are mitigated automatically using eBPF/XDP kernel drop filters and adaptive browser PoW challenges."},
			{ID: "dns-pointing", Title: "DNS & NameServer Setup", Category: "DNS & Proxy", Content: "Point your domain CNAME record to your WAF CNAME Target or A records to WAF Cluster IPs for full proxy protection."},
		},
	}

	data, err := os.ReadFile(s.filePath)
	if err == nil {
		var loaded StorageData
		if err := json.Unmarshal(data, &loaded); err == nil {
			if len(loaded.Users) > 0 {
				s.Data.Users = loaded.Users
			}
			if len(loaded.Domains) > 0 {
				s.Data.Domains = loaded.Domains
			}
			if len(loaded.Pricing) > 0 {
				s.Data.Pricing = loaded.Pricing
			}
			if len(loaded.Docs) > 0 {
				s.Data.Docs = loaded.Docs
			}
			s.Data.Settings = loaded.Settings
		}
	} else {
		logger.Info("Initial DB file created", "path", s.filePath)
	}
}

func (s *Storage) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s.Data, "", "  ")
	if err != nil {
		return err
	}
	_ = os.MkdirAll("data", 0755)
	return os.WriteFile(s.filePath, data, 0644)
}
