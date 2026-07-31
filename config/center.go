package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
	"mango-waf/logger"
)

// ConfigRevision metadata
type ConfigRevision struct {
	Version     int64     `json:"version"`
	Timestamp   time.Time `json:"timestamp"`
	Author      string    `json:"author"`
	Role        string    `json:"role"`
	Description string    `json:"description"`
	FilePath    string    `json:"file_path"`
}

// ConfigBackup metadata
type ConfigBackup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Timestamp   time.Time `json:"timestamp"`
	Author      string    `json:"author"`
	Description string    `json:"description"`
	FilePath    string    `json:"file_path"`
}

// ConfigCenter manages single source of truth configuration
type ConfigCenter struct {
	mu            sync.RWMutex
	currentPath   string
	currentConfig *Config
	rawYAML       string
	revisions     []ConfigRevision
	backups       []ConfigBackup
	reloadHooks   []func(newCfg *Config) error
	historyDir    string
	backupDir     string
}

var globalCenter *ConfigCenter
var centerOnce sync.Once

// InitCenter initializes the global ConfigCenter instance with a specific configuration path
func InitCenter(yamlPath string) *ConfigCenter {
	centerOnce.Do(func() {
		globalCenter = NewCenter(yamlPath)
	})
	return globalCenter
}

// GetCenter returns the global ConfigCenter instance
func GetCenter() *ConfigCenter {
	if globalCenter == nil {
		return InitCenter("config/production.yaml")
	}
	return globalCenter
}

// NewCenter creates a new ConfigCenter instance
func NewCenter(yamlPath string) *ConfigCenter {
	absPath, err := filepath.Abs(yamlPath)
	if err != nil {
		absPath = yamlPath
	}

	histDir := filepath.Join(filepath.Dir(absPath), "..", "data", "config_history")
	backDir := filepath.Join(filepath.Dir(absPath), "..", "data", "backups")
	_ = os.MkdirAll(histDir, 0755)
	_ = os.MkdirAll(backDir, 0755)

	cc := &ConfigCenter{
		currentPath: absPath,
		historyDir:  histDir,
		backupDir:   backDir,
	}

	// Try loading existing file, or load default config if missing
	if err := cc.ReloadFromDisk(); err != nil {
		logger.Warn("ConfigCenter: Failed to load from disk, using default config", "path", absPath, "error", err)
		defaultCfg := DefaultConfig()
		cc.currentConfig = defaultCfg
		_ = cc.saveYAMLToDisk(defaultCfg, "Initial default config", "system")
	}

	cc.loadRevisionsList()
	cc.loadBackupsList()
	return cc
}

// RegisterReloadHook registers a function to execute when config is updated
func (cc *ConfigCenter) RegisterReloadHook(fn func(newCfg *Config) error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.reloadHooks = append(cc.reloadHooks, fn)
}

// GetConfig returns a copy of current configuration
func (cc *ConfigCenter) GetConfig() *Config {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.currentConfig
}

// GetRawYAML returns current raw YAML content
func (cc *ConfigCenter) GetRawYAML() string {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	if cc.rawYAML != "" {
		return cc.rawYAML
	}
	data, err := yaml.Marshal(cc.currentConfig)
	if err != nil {
		return ""
	}
	return string(data)
}

// ReloadFromDisk reloads config from disk
func (cc *ConfigCenter) ReloadFromDisk() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	data, err := os.ReadFile(cc.currentPath)
	if err != nil {
		return err
	}

	cfg, err := Load(cc.currentPath)
	if err != nil {
		return err
	}

	cc.currentConfig = cfg
	cc.rawYAML = string(data)
	return nil
}

// ValidateYAML validates raw YAML string against schema bounds
func (cc *ConfigCenter) ValidateYAML(raw string) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("YAML syntax error: %w", err)
	}

	if err := ValidateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("Config validation error: %w", err)
	}

	return &cfg, nil
}

// ValidateConfig checks schema bounds and logical validity
func ValidateConfig(cfg *Config) error {
	if cfg.Server.Listen == "" {
		return fmt.Errorf("server.listen cannot be empty")
	}
	if cfg.WAF.ParanoiaLevel < 1 || cfg.WAF.ParanoiaLevel > 4 {
		return fmt.Errorf("waf.paranoia_level must be between 1 and 4")
	}
	for i, dom := range cfg.Domains {
		if strings.TrimSpace(dom.Name) == "" {
			return fmt.Errorf("domain[%d] name cannot be empty", i)
		}
		if len(dom.Upstreams) == 0 {
			return fmt.Errorf("domain %s must have at least one upstream", dom.Name)
		}
		for j, up := range dom.Upstreams {
			if strings.TrimSpace(up.URL) == "" {
				return fmt.Errorf("domain %s upstream[%d] URL cannot be empty", dom.Name, j)
			}
		}
	}
	return nil
}

// SaveConfig updates configuration from raw YAML string with validation, backup, history, and hot reload
func (cc *ConfigCenter) SaveYAML(raw string, author string, role string, description string) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// 1. Validate
	newCfg, err := cc.ValidateYAML(raw)
	if err != nil {
		return err
	}

	// 2. Keep old state for rollback in case hot reload fails
	oldCfg := cc.currentConfig
	oldYAML := cc.rawYAML

	// 3. Save snapshot to version history
	ts := time.Now().UnixNano()
	revFileName := fmt.Sprintf("v_%d.yaml", ts)
	revPath := filepath.Join(cc.historyDir, revFileName)
	if err := os.WriteFile(revPath, []byte(raw), 0644); err != nil {
		return fmt.Errorf("failed to write revision file: %w", err)
	}

	rev := ConfigRevision{
		Version:     ts,
		Timestamp:   time.Now(),
		Author:      author,
		Role:        role,
		Description: description,
		FilePath:    revPath,
	}
	cc.revisions = append([]ConfigRevision{rev}, cc.revisions...)

	// Save revisions index
	cc.saveRevisionsIndex()

	// 4. Save to production YAML path with fallback for read-only mounts
	if err := os.WriteFile(cc.currentPath, []byte(raw), 0644); err != nil {
		altPaths := []string{
			"config/production.yaml",
			"/root/mango-waf/config/production.yaml",
		}
		wrote := false
		for _, alt := range altPaths {
			if alt != cc.currentPath {
				_ = os.MkdirAll(filepath.Dir(alt), 0755)
				if err2 := os.WriteFile(alt, []byte(raw), 0644); err2 == nil {
					cc.currentPath = alt
					wrote = true
					logger.Info("Saved config to alternative path", "path", alt)
					break
				}
			}
		}
		if !wrote {
			logger.Warn("Main YAML file is read-only on disk, hot-reloaded configuration in memory", "path", cc.currentPath, "error", err)
		}
	}

	cc.currentConfig = newCfg
	cc.rawYAML = raw

	// 5. Trigger Hot Reload Hooks
	for _, hook := range cc.reloadHooks {
		if err := hook(newCfg); err != nil {
			logger.Error("Hot reload failed, rolling back to previous configuration", "error", err)
			// Automatic Rollback
			_ = os.WriteFile(cc.currentPath, []byte(oldYAML), 0644)
			cc.currentConfig = oldCfg
			cc.rawYAML = oldYAML
			for _, rbHook := range cc.reloadHooks {
				_ = rbHook(oldCfg)
			}
			return fmt.Errorf("hot reload failed (%v), rolled back to previous config", err)
		}
	}

	logger.Info("Configuration saved & hot-reloaded successfully", "author", author, "domains", len(newCfg.Domains))
	return nil
}

// UpdateConfig updates configuration from struct
func (cc *ConfigCenter) UpdateConfig(newCfg *Config, author string, role string, description string) error {
	// Preserve cluster config from existing on-disk YAML to prevent dashboard saves
	// from erasing advertise_ip, join_peers, secret_key, and node_name.
	if cc.currentConfig != nil {
		existing := cc.currentConfig.Cluster
		if newCfg.Cluster.NodeName == "" && existing.NodeName != "" {
			newCfg.Cluster.NodeName = existing.NodeName
		}
		if newCfg.Cluster.AdvertiseIP == "" && existing.AdvertiseIP != "" {
			newCfg.Cluster.AdvertiseIP = existing.AdvertiseIP
		}
		if len(newCfg.Cluster.JoinPeers) == 0 && len(existing.JoinPeers) > 0 {
			newCfg.Cluster.JoinPeers = existing.JoinPeers
		}
		if newCfg.Cluster.SecretKey == "" && existing.SecretKey != "" {
			newCfg.Cluster.SecretKey = existing.SecretKey
		}
		if newCfg.Cluster.BindPort == 0 && existing.BindPort != 0 {
			newCfg.Cluster.BindPort = existing.BindPort
		}
		if !newCfg.Cluster.Enabled && existing.Enabled {
			newCfg.Cluster.Enabled = existing.Enabled
		}
		if newCfg.Cluster.CNAMETarget == "" && existing.CNAMETarget != "" {
			newCfg.Cluster.CNAMETarget = existing.CNAMETarget
		}
	}

	rawBytes, err := yaml.Marshal(newCfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}
	return cc.SaveYAML(string(rawBytes), author, role, description)
}

// saveYAMLToDisk internal helper
func (cc *ConfigCenter) saveYAMLToDisk(cfg *Config, description string, author string) error {
	rawBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	_ = os.WriteFile(cc.currentPath, rawBytes, 0644)
	cc.rawYAML = string(rawBytes)
	return nil
}

// ListRevisions returns version history
func (cc *ConfigCenter) ListRevisions() []ConfigRevision {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.revisions
}

// RestoreRevision rolls back to a specific version timestamp
func (cc *ConfigCenter) RestoreRevision(ts int64, author string, role string) error {
	revPath := filepath.Join(cc.historyDir, fmt.Sprintf("v_%d.yaml", ts))
	data, err := os.ReadFile(revPath)
	if err != nil {
		return fmt.Errorf("revision file not found: %w", err)
	}

	desc := fmt.Sprintf("Restored from version %d", ts)
	return cc.SaveYAML(string(data), author, role, desc)
}

// DiffRevisions compares two revisions or current vs revision
func (cc *ConfigCenter) DiffRevisions(v1 int64, v2 int64) (string, error) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	var yaml1, yaml2 string

	if v1 == 0 {
		yaml1 = cc.rawYAML
	} else {
		data, e := os.ReadFile(filepath.Join(cc.historyDir, fmt.Sprintf("v_%d.yaml", v1)))
		if e != nil {
			return "", fmt.Errorf("version 1 error: %w", e)
		}
		yaml1 = string(data)
	}

	if v2 == 0 {
		yaml2 = cc.rawYAML
	} else {
		data, e := os.ReadFile(filepath.Join(cc.historyDir, fmt.Sprintf("v_%d.yaml", v2)))
		if e != nil {
			return "", fmt.Errorf("version 2 error: %w", e)
		}
		yaml2 = string(data)
	}

	return generateDiff(yaml1, yaml2), nil
}

// CreateBackup creates a named snapshot backup
func (cc *ConfigCenter) CreateBackup(name string, author string, description string) (*ConfigBackup, error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if name == "" {
		name = fmt.Sprintf("backup_%s", time.Now().Format("20060102_150405"))
	}
	fileName := fmt.Sprintf("%s.yaml", name)
	bPath := filepath.Join(cc.backupDir, fileName)

	if err := os.WriteFile(bPath, []byte(cc.rawYAML), 0644); err != nil {
		return nil, fmt.Errorf("failed to write backup file: %w", err)
	}

	b := ConfigBackup{
		ID:          fmt.Sprintf("b_%d", time.Now().UnixNano()),
		Name:        name,
		Timestamp:   time.Now(),
		Author:      author,
		Description: description,
		FilePath:    bPath,
	}

	cc.backups = append([]ConfigBackup{b}, cc.backups...)
	cc.saveBackupsIndex()

	return &b, nil
}

// ListBackups returns list of backups
func (cc *ConfigCenter) ListBackups() []ConfigBackup {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.backups
}

// RestoreBackup restores a named backup
func (cc *ConfigCenter) RestoreBackup(backupID string, author string, role string) error {
	cc.mu.RLock()
	var targetB *ConfigBackup
	for _, b := range cc.backups {
		if b.ID == backupID || b.Name == backupID {
			targetB = &b
			break
		}
	}
	cc.mu.RUnlock()

	if targetB == nil {
		return fmt.Errorf("backup ID %s not found", backupID)
	}

	data, err := os.ReadFile(targetB.FilePath)
	if err != nil {
		return fmt.Errorf("backup file unreadable: %w", err)
	}

	desc := fmt.Sprintf("Restored backup: %s", targetB.Name)
	return cc.SaveYAML(string(data), author, role, desc)
}

// saveRevisionsIndex saves index JSON
func (cc *ConfigCenter) saveRevisionsIndex() {
	indexPath := filepath.Join(cc.historyDir, "revisions.json")
	data, _ := json.MarshalIndent(cc.revisions, "", "  ")
	_ = os.WriteFile(indexPath, data, 0644)
}

// loadRevisionsList loads index JSON
func (cc *ConfigCenter) loadRevisionsList() {
	indexPath := filepath.Join(cc.historyDir, "revisions.json")
	data, err := os.ReadFile(indexPath)
	if err == nil {
		_ = json.Unmarshal(data, &cc.revisions)
	}
}

// saveBackupsIndex saves index JSON
func (cc *ConfigCenter) saveBackupsIndex() {
	indexPath := filepath.Join(cc.backupDir, "backups.json")
	data, _ := json.MarshalIndent(cc.backups, "", "  ")
	_ = os.WriteFile(indexPath, data, 0644)
}

// loadBackupsList loads index JSON
func (cc *ConfigCenter) loadBackupsList() {
	indexPath := filepath.Join(cc.backupDir, "backups.json")
	data, err := os.ReadFile(indexPath)
	if err == nil {
		_ = json.Unmarshal(data, &cc.backups)
	}
}

// generateDiff produces a simple line-by-line diff between old and new text
func generateDiff(oldText, newText string) string {
	oldLines := strings.Split(oldText, "\n")
	newLines := strings.Split(newText, "\n")

	var diffBuilder strings.Builder
	maxLines := len(oldLines)
	if len(newLines) > maxLines {
		maxLines = len(newLines)
	}

	m1 := make(map[string]bool)
	for _, l := range oldLines {
		m1[l] = true
	}
	m2 := make(map[string]bool)
	for _, l := range newLines {
		m2[l] = true
	}

	diffBuilder.WriteString("--- Original Configuration\n+++ Proposed Configuration\n\n")

	i, j := 0, 0
	for i < len(oldLines) || j < len(newLines) {
		if i < len(oldLines) && j < len(newLines) && oldLines[i] == newLines[j] {
			diffBuilder.WriteString("  " + oldLines[i] + "\n")
			i++
			j++
		} else if j < len(newLines) && !m1[newLines[j]] {
			diffBuilder.WriteString("+ " + newLines[j] + "\n")
			j++
		} else if i < len(oldLines) && !m2[oldLines[i]] {
			diffBuilder.WriteString("- " + oldLines[i] + "\n")
			i++
		} else {
			if i < len(oldLines) {
				diffBuilder.WriteString("- " + oldLines[i] + "\n")
				i++
			}
			if j < len(newLines) {
				diffBuilder.WriteString("+ " + newLines[j] + "\n")
				j++
			}
		}
	}

	return diffBuilder.String()
}

// DefaultConfig provides a safe fallback configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:         "0.0.0.0:443",
			HTTPListen:     "0.0.0.0:80",
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   30 * time.Second,
			IdleTimeout:    60 * time.Second,
			MaxHeaderBytes: 1048576,
		},
		TLS: TLSConfig{
			Enabled:    true,
			CertFile:   "certs/server.crt",
			KeyFile:    "certs/server.key",
			AutoCert:   true,
			MinVersion: "1.2",
		},
		Domains: []DomainConfig{
			{
				Name:      "waf.local",
				Upstreams: []UpstreamConfig{{URL: "http://127.0.0.1:1234", Weight: 1}},
				SSL:       true,
				Owner:     "admin",
			},
			{
				Name:      "app.local",
				Upstreams: []UpstreamConfig{{URL: "http://127.0.0.1:8080", Weight: 1}},
				SSL:       true,
				Owner:     "admin",
			},
			{
				Name:      "localhost",
				Upstreams: []UpstreamConfig{{URL: "http://127.0.0.1:8080", Weight: 1}},
				SSL:       true,
				Owner:     "admin",
			},
		},
		Protection: ProtectionConfig{
			Mode:         "auto",
			WhitelistIPs: []string{"127.0.0.1", "::1"},
			RateLimit: RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
				PerIP:             true,
				Adaptive:          true,
			},
			Ban: BanConfig{
				Duration: 15 * time.Minute,
				MaxFails: 10,
			},
		},
		WAF: WAFConfig{
			Enabled:       true,
			OWASPRules:    true,
			ParanoiaLevel: 2,
		},
		Dashboard: DashboardConfig{
			Enabled:   true,
			Listen:    "0.0.0.0:9090",
			Username:  "admin",
			Password:  "admin123",
			JWTSecret: "mango_super_secret_jwt_key_2026",
		},
		Cluster: ClusterConfig{
			Enabled:  true,
			NodeName: "mango-node-1",
			BindPort: 7946,
		},
	}
}
