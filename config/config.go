package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Config holds the complete Mango Shield configuration
type Config struct {
	Server       ServerConfig      `yaml:"server"`
	TLS          TLSConfig         `yaml:"tls"`
	Domains      []DomainConfig    `yaml:"domains"`
	Proxy        ProxyConfig       `yaml:"proxy"`
	Protection   ProtectionConfig  `yaml:"protection"`
	Fingerprint  FingerprintConfig `yaml:"fingerprint"`
	Intelligence IntelConfig       `yaml:"intelligence"`
	Detection    DetectionConfig   `yaml:"detection"`
	WAF          WAFConfig         `yaml:"waf"`
	Logging      LoggingConfig     `yaml:"logging"`
	Metrics      MetricsConfig     `yaml:"metrics"`
	Dashboard    DashboardConfig   `yaml:"dashboard"`
	Alerts       AlertsConfig      `yaml:"alerts"`
	CDN          CDNConfig         `yaml:"cdn"`
	Cluster      ClusterConfig     `yaml:"cluster"`
	XDP          XDPConfig         `yaml:"xdp"`
	HTTP3        HTTP3Config       `yaml:"http3"`
}

type HTTP3Config struct {
	Enabled      bool `yaml:"enabled"`
	Port         int  `yaml:"port"`
	AltSvcHeader bool `yaml:"alt_svc_header"`
}

type ServerConfig struct {
	Listen         string        `yaml:"listen"`
	HTTPListen     string        `yaml:"http_listen"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	MaxHeaderBytes int           `yaml:"max_header_bytes"`
}

type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	AutoCert   bool   `yaml:"auto_cert"`
	ACMEEmail  string `yaml:"acme_email"`
	MinVersion string `yaml:"min_version"`
}

type DomainConfig struct {
	Name           string           `yaml:"name" json:"name"`
	Upstreams      []UpstreamConfig `yaml:"upstreams" json:"upstreams"`
	SSL            bool             `yaml:"ssl" json:"ssl"`
	Owner          string           `yaml:"owner,omitempty" json:"owner,omitempty"`
	RateLimitRPS   int              `yaml:"rate_limit_rps,omitempty" json:"rate_limit_rps,omitempty"`
	RateLimitConn  int              `yaml:"rate_limit_conn,omitempty" json:"rate_limit_conn,omitempty"`
	PoWDifficulty  int              `yaml:"pow_difficulty,omitempty" json:"pow_difficulty,omitempty"`
	ProtectionMode string           `yaml:"protection_mode,omitempty" json:"protection_mode,omitempty"`
}

type UpstreamConfig struct {
	URL    string `yaml:"url"`
	Weight int    `yaml:"weight"` // default 1
}

type ProxyConfig struct {
	ConnectTimeout      time.Duration `yaml:"connect_timeout"`
	ResponseTimeout     time.Duration `yaml:"response_timeout"`
	MaxIdleConns        int           `yaml:"max_idle_conns"`
	MaxIdleConnsPerHost int           `yaml:"max_idle_conns_per_host"`
	MaxConnsPerHost     int           `yaml:"max_conns_per_host"`
	IdleConnTimeout     time.Duration `yaml:"idle_conn_timeout"`
	KeepAlive           bool          `yaml:"keep_alive"`
	WebSocket           bool          `yaml:"websocket"`
	DisableCompression  bool          `yaml:"disable_compression"`
	BufferSizeKB        int           `yaml:"buffer_size_kb"`
}

type ProtectionConfig struct {
	Mode            string          `yaml:"mode"`
	WhitelistIPs    []string        `yaml:"whitelist_ips"`
	TrustedProxies  []string        `yaml:"trusted_proxies"`
	RateLimit       RateLimitConfig `yaml:"rate_limit"`
	ConnectionLimit ConnLimitConfig `yaml:"connection_limit"`
	Challenge       ChallengeConfig `yaml:"challenge"`
	Ban             BanConfig       `yaml:"ban"`
	Emergency       EmergencyConfig `yaml:"emergency"`
}

type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerSecond int  `yaml:"requests_per_second"`
	Burst             int  `yaml:"burst"`
	PerIP             bool `yaml:"per_ip"`
	Adaptive          bool `yaml:"adaptive"`
}

type ConnLimitConfig struct {
	MaxPerIP int `yaml:"max_per_ip"`
	MaxTotal int `yaml:"max_total"`
}

type ChallengeConfig struct {
	PowDifficulty int           `yaml:"pow_difficulty"`
	PowAdaptive   bool          `yaml:"pow_adaptive"`
	CookieTTL     time.Duration `yaml:"cookie_ttl"`
	CookieSecret  string        `yaml:"cookie_secret"`
}

type BanConfig struct {
	Duration    time.Duration `yaml:"duration"`
	MaxFails    int           `yaml:"max_fails"`
	UseIptables bool          `yaml:"use_iptables"`
}

type EmergencyConfig struct {
	RPSThreshold int           `yaml:"rps_threshold"`
	Duration     time.Duration `yaml:"duration"`
	AutoEnable   bool          `yaml:"auto_enable"`
}

type FingerprintConfig struct {
	JA3           JA3Config     `yaml:"ja3"`
	JA4           JA4Config     `yaml:"ja4"`
	HTTP2         HTTP2FPConfig `yaml:"http2"`
	UAConsistency UAConfig      `yaml:"ua_consistency"`
}

type JA3Config struct {
	Enabled      bool `yaml:"enabled"`
	BlockUnknown bool `yaml:"block_unknown"`
}

type JA4Config struct {
	Enabled bool `yaml:"enabled"`
}

type HTTP2FPConfig struct {
	Enabled bool `yaml:"enabled"`
}

type UAConfig struct {
	Enabled bool `yaml:"enabled"`
	Strict  bool `yaml:"strict"`
}

type IntelConfig struct {
	GeoIP        GeoIPConfig        `yaml:"geoip"`
	IPReputation IPReputationConfig `yaml:"ip_reputation"`
	ASN          ASNConfig          `yaml:"asn"`
}

type GeoIPConfig struct {
	Enabled          bool     `yaml:"enabled"`
	DBPath           string   `yaml:"db_path"`
	BlockedCountries []string `yaml:"blocked_countries"`
	AllowedCountries []string `yaml:"allowed_countries"`
}

type IPReputationConfig struct {
	Enabled      bool          `yaml:"enabled"`
	AbuseIPDBKey string        `yaml:"abuseipdb_key"`
	CacheTTL     time.Duration `yaml:"cache_ttl"`
}

type ASNConfig struct {
	Enabled         bool `yaml:"enabled"`
	BlockDatacenter bool `yaml:"block_datacenter"`
}

type DetectionConfig struct {
	Baseline        BaselineConfig `yaml:"baseline"`
	Anomaly         AnomalyConfig  `yaml:"anomaly"`
	BotClassifier   BotClassConfig `yaml:"bot_classifier"`
	SessionTracking SessionConfig  `yaml:"session_tracking"`
}

type BaselineConfig struct {
	Enabled        bool          `yaml:"enabled"`
	LearningPeriod time.Duration `yaml:"learning_period"`
}

type AnomalyConfig struct {
	Enabled     bool    `yaml:"enabled"`
	Sensitivity float64 `yaml:"sensitivity"`
}

type BotClassConfig struct {
	Enabled   bool   `yaml:"enabled"`
	ModelPath string `yaml:"model_path"`
}

type SessionConfig struct {
	Enabled bool          `yaml:"enabled"`
	TTL     time.Duration `yaml:"ttl"`
}

type WAFConfig struct {
	Enabled         bool   `yaml:"enabled"`
	OWASPRules      bool   `yaml:"owasp_rules"`
	CustomRulesPath string `yaml:"custom_rules_path"`
	ParanoiaLevel   int    `yaml:"paranoia_level"`
}

type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	File       string `yaml:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	AttackLog  string `yaml:"attack_log"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Path    string `yaml:"path"`
}

type DashboardConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Listen    string `yaml:"listen"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	JWTSecret string `yaml:"jwt_secret"`
}

type AlertsConfig struct {
	Telegram TelegramConfig `yaml:"telegram"`
	Discord  DiscordConfig  `yaml:"discord"`
	Webhook  WebhookConfig  `yaml:"webhook"`
}

type TelegramConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
	ChatID  string `yaml:"chat_id"`
}

type DiscordConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

type WebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Secret  string `yaml:"secret"`
}

type CDNConfig struct {
	Enabled          bool     `yaml:"enabled"`
	MemoryLimitMB    int      `yaml:"memory_limit_mb"`
	StaticExtensions []string `yaml:"static_extensions"`
	BypassRules      []string `yaml:"bypass_rules"`
	BypassCookies    []string `yaml:"bypass_cookies"`
	BypassHeaders    []string `yaml:"bypass_headers"`
}

type ClusterConfig struct {
	Enabled     bool     `yaml:"enabled"`
	NodeName    string   `yaml:"node_name"`
	BindPort    int      `yaml:"bind_port"`
	AdvertiseIP string   `yaml:"advertise_ip"`
	CNAMETarget string   `yaml:"cname_target"`
	JoinPeers   []string `yaml:"join_peers"`
	SecretKey   string   `yaml:"secret_key"`
}

type XDPConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Interface   string `yaml:"interface"`
	Mode        string `yaml:"mode"` // "skb", "native", "offload"
	MapPinPath  string `yaml:"map_pin_path"`
	AutoCompile bool   `yaml:"auto_compile"`
	AutoAttach  bool   `yaml:"auto_attach"`
}

var (
	global     *Config
	globalLock sync.RWMutex
)

// Load reads and parses the config file, allowing Environment Variable overrides (MANGO_*)
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("MANGO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	err := v.Unmarshal(cfg, func(c *mapstructure.DecoderConfig) {
		c.TagName = "yaml"
	})
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	setDefaults(cfg)
	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	globalLock.Lock()
	global = cfg
	globalLock.Unlock()

	return cfg, nil
}

// Get returns the current global config
func Get() *Config {
	globalLock.RLock()
	defer globalLock.RUnlock()
	return global
}

// Reload hot-reloads the config from the same path
func Reload(path string) error {
	_, err := Load(path)
	return err
}

func setDefaults(cfg *Config) {
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = "0.0.0.0:443"
	}
	if cfg.Server.HTTPListen == "" {
		cfg.Server.HTTPListen = "0.0.0.0:80"
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 10 * time.Second
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 30 * time.Second
	}
	if cfg.Server.IdleTimeout == 0 {
		cfg.Server.IdleTimeout = 120 * time.Second
	}
	if cfg.Server.MaxHeaderBytes == 0 {
		cfg.Server.MaxHeaderBytes = 65536
	}
	if cfg.Proxy.ConnectTimeout == 0 {
		cfg.Proxy.ConnectTimeout = 3 * time.Second
	}
	if cfg.Proxy.ResponseTimeout == 0 {
		cfg.Proxy.ResponseTimeout = 5 * time.Second
	}
	if cfg.Proxy.MaxIdleConns == 0 {
		cfg.Proxy.MaxIdleConns = 20000
	}
	if cfg.Proxy.MaxIdleConnsPerHost == 0 {
		cfg.Proxy.MaxIdleConnsPerHost = 5000
	}
	if cfg.Proxy.IdleConnTimeout == 0 {
		cfg.Proxy.IdleConnTimeout = 90 * time.Second
	}
	if cfg.Proxy.BufferSizeKB == 0 {
		cfg.Proxy.BufferSizeKB = 64
	}
	if cfg.Protection.RateLimit.RequestsPerSecond == 0 {
		cfg.Protection.RateLimit.RequestsPerSecond = 50
	}
	if cfg.Protection.RateLimit.Burst == 0 {
		cfg.Protection.RateLimit.Burst = 100
	}
	if cfg.Protection.ConnectionLimit.MaxPerIP == 0 {
		cfg.Protection.ConnectionLimit.MaxPerIP = 50
	}
	if cfg.Protection.ConnectionLimit.MaxTotal == 0 {
		cfg.Protection.ConnectionLimit.MaxTotal = 10000
	}
	if cfg.Protection.Challenge.PowDifficulty == 0 {
		cfg.Protection.Challenge.PowDifficulty = 3
	}
	if cfg.Protection.Challenge.CookieTTL == 0 {
		cfg.Protection.Challenge.CookieTTL = 30 * time.Minute
	}
	if cfg.Protection.Challenge.CookieSecret == "" {
		cfg.Protection.Challenge.CookieSecret = randomHex(32)
	}
	if cfg.Protection.Ban.Duration == 0 {
		cfg.Protection.Ban.Duration = 2 * time.Hour
	}
	if cfg.Protection.Ban.MaxFails == 0 {
		cfg.Protection.Ban.MaxFails = 3
	}
	if cfg.Protection.Emergency.RPSThreshold == 0 {
		cfg.Protection.Emergency.RPSThreshold = 200
	}
	if cfg.Protection.Emergency.Duration == 0 {
		cfg.Protection.Emergency.Duration = 30 * time.Second
	}
	if cfg.Detection.Anomaly.Sensitivity == 0 {
		cfg.Detection.Anomaly.Sensitivity = 0.7
	}
	if cfg.Detection.Baseline.LearningPeriod == 0 {
		cfg.Detection.Baseline.LearningPeriod = 24 * time.Hour
	}
	if cfg.Detection.SessionTracking.TTL == 0 {
		cfg.Detection.SessionTracking.TTL = 30 * time.Minute
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	if cfg.Logging.MaxSizeMB == 0 {
		cfg.Logging.MaxSizeMB = 100
	}
	if cfg.Logging.MaxBackups == 0 {
		cfg.Logging.MaxBackups = 5
	}
	if cfg.Dashboard.JWTSecret == "" {
		cfg.Dashboard.JWTSecret = randomHex(32)
	}
	if cfg.Dashboard.Username == "" {
		cfg.Dashboard.Username = "admin"
	}
	if cfg.Dashboard.Password == "" {
		cfg.Dashboard.Password = "admin123_change_in_production"
	}
	if cfg.WAF.ParanoiaLevel == 0 {
		cfg.WAF.ParanoiaLevel = 1
	}
	if cfg.Protection.Mode == "" {
		cfg.Protection.Mode = "auto"
	}
	if cfg.XDP.Interface == "" {
		cfg.XDP.Interface = "eth0"
	}
	if cfg.XDP.Mode == "" {
		cfg.XDP.Mode = "skb"
	}
	if cfg.XDP.MapPinPath == "" {
		cfg.XDP.MapPinPath = "/sys/fs/bpf/mango_blacklist"
	}
	if cfg.HTTP3.Port == 0 {
		cfg.HTTP3.Port = 443
	}
}

func validate(cfg *Config) error {
	if len(cfg.Domains) == 0 {
		return fmt.Errorf("at least one domain must be configured")
	}
	for i, d := range cfg.Domains {
		if d.Name == "" {
			return fmt.Errorf("domain[%d].name is required", i)
		}
		if len(d.Upstreams) == 0 {
			return fmt.Errorf("domain %s must have at least one upstream", d.Name)
		}
	}
	if cfg.Protection.Emergency.RPSThreshold < 10 {
		return fmt.Errorf("emergency.rps_threshold must be >= 10")
	}

	// Validate protection mode enum
	validModes := map[string]bool{
		"auto": true, "challenge": true, "captcha": true, "block": true,
		"monitor": true, "emergency": true, "off": true, "silent": true,
		"under_attack": true,
	}
	if !validModes[strings.ToLower(cfg.Protection.Mode)] {
		return fmt.Errorf("invalid protection mode '%s': must be auto, challenge, captcha, block, monitor, emergency, off, silent, or under_attack", cfg.Protection.Mode)
	}

	// Validate CIDRs in trusted_proxies
	for _, proxy := range cfg.Protection.TrustedProxies {
		if !strings.Contains(proxy, "/") {
			proxy = proxy + "/32"
		}
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			return fmt.Errorf("invalid trusted_proxy CIDR '%s': %w", proxy, err)
		}
	}

	// Validate PoW difficulty bounds
	if cfg.Protection.Challenge.PowDifficulty < 1 || cfg.Protection.Challenge.PowDifficulty > 10 {
		return fmt.Errorf("pow_difficulty must be between 1 and 10, got %d", cfg.Protection.Challenge.PowDifficulty)
	}

	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand read failure: %v", err))
	}
	return hex.EncodeToString(b)
}
