package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"mango-waf/config"
	"mango-waf/logger"
)

// CloudflareBanRequest represents the item in the queue
type CloudflareBanRequest struct {
	IP string
}

// CloudflareManager handles the worker queue for syncing bans to Cloudflare
type CloudflareManager struct {
	BanQueue chan CloudflareBanRequest
	Client   *http.Client
}

// Global instance
var CFManager *CloudflareManager

// InitCloudflareManager initializes the queue and HTTP client
func InitCloudflareManager() {
	CFManager = &CloudflareManager{
		BanQueue: make(chan CloudflareBanRequest, 1000), // Buffer up to 1000 requests
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// RunWorker runs in the background and processes the queue
func (m *CloudflareManager) RunWorker() {
	cfg := config.Get().Cloudflare
	if !cfg.Enabled || cfg.APIToken == "" {
		return
	}

	logger.Info("Cloudflare API Edge Banning worker started")

	// Rate limiter: 4 requests per second to stay under Cloudflare's 1200 req/5min limit
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for req := range m.BanQueue {
		<-ticker.C
		m.processBan(req, cfg)
	}
}

func (m *CloudflareManager) processBan(req CloudflareBanRequest, cfg config.CloudflareConfig) {
	// Construct the payload for IP Access Rule
	payload := map[string]interface{}{
		"mode": "block",
		"configuration": map[string]string{
			"target": "ip",
			"value":  req.IP,
		},
		"notes": fmt.Sprintf("Banned by Mango WAF on %s", time.Now().Format(time.RFC3339)),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		logger.Error("Failed to marshal Cloudflare payload", "ip", req.IP, "error", err)
		return
	}

	var apiURLs []string

	// Determine if we should use Account Level or Zone Level API
	if cfg.AccountID != "" {
		apiURLs = append(apiURLs, fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/firewall/access_rules/rules", cfg.AccountID))
	} else if len(cfg.Zones) > 0 {
		// If AccountID is not set, ban the IP across all configured zones
		for _, zoneID := range cfg.Zones {
			if zoneID != "" {
				apiURLs = append(apiURLs, fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/firewall/access_rules/rules", zoneID))
			}
		}
	}

	if len(apiURLs) == 0 {
		logger.Warn("Cannot ban IP on Cloudflare: No AccountID and no ZoneIDs configured")
		return
	}

	for _, apiURL := range apiURLs {
		httpReq, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(payloadBytes))
		if err != nil {
			logger.Error("Failed to create Cloudflare request", "error", err)
			continue
		}

		httpReq.Header.Set("Authorization", "Bearer "+cfg.APIToken)
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := m.Client.Do(httpReq)
		if err != nil {
			logger.Error("Failed to execute Cloudflare request", "ip", req.IP, "error", err)
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			logger.Info("Successfully pushed IP ban to Cloudflare", "ip", req.IP, "url", apiURL)
		} else {
			var errorBody map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&errorBody)
			
			isAlreadyExists := false
			if errors, ok := errorBody["errors"].([]interface{}); ok {
				for _, e := range errors {
					if errMap, ok := e.(map[string]interface{}); ok {
						if code, ok := errMap["code"].(float64); ok && code == 81057 {
							isAlreadyExists = true
							break
						}
					}
				}
			}

			if isAlreadyExists {
				logger.Debug("IP already banned on Cloudflare", "ip", req.IP)
			} else {
				logger.Error("Cloudflare API returned error", "ip", req.IP, "status", resp.StatusCode, "response", errorBody)
			}
		}
		resp.Body.Close()
	}
}

// StartAutoCleanup starts a background worker that runs periodically to fetch CF rules
// and delete the ones older than banDuration. This makes the system stateless and immune to crashes.
func (m *CloudflareManager) StartAutoCleanup(banDuration time.Duration) {
	cfg := config.Get().Cloudflare
	if !cfg.Enabled || cfg.APIToken == "" {
		return
	}

	logger.Info("Cloudflare Auto-Cleanup worker started", "interval", "1 hour", "ban_duration", banDuration)

	go func() {
		// Run immediately on startup to clean up leftover bans from crashes
		m.cleanExpiredRules(cfg, banDuration)

		// Then run periodically every 1 hour
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			m.cleanExpiredRules(cfg, banDuration)
		}
	}()
}

type cloudflareRulesResponse struct {
	Result []struct {
		ID        string `json:"id"`
		CreatedOn string `json:"created_on"`
	} `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (m *CloudflareManager) cleanExpiredRules(cfg config.CloudflareConfig, banDuration time.Duration) {
	var apiURLs []string
	var apiDeleteURLs []string

	if cfg.AccountID != "" {
		base := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/firewall/access_rules/rules", cfg.AccountID)
		apiURLs = append(apiURLs, base)
		apiDeleteURLs = append(apiDeleteURLs, base)
	} else {
		for _, zoneID := range cfg.Zones {
			if zoneID != "" {
				base := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/firewall/access_rules/rules", zoneID)
				apiURLs = append(apiURLs, base)
				apiDeleteURLs = append(apiDeleteURLs, base)
			}
		}
	}

	for i, apiURL := range apiURLs {
		page := 1
		for {
			// Query CF rules specifically created by Mango WAF
			reqURL := fmt.Sprintf("%s?notes=Banned%%20by%%20Mango%%20WAF&per_page=100&page=%d", apiURL, page)
			req, err := http.NewRequest("GET", reqURL, nil)
			if err != nil {
				break
			}
			req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := m.Client.Do(req)
			if err != nil {
				logger.Error("Failed to fetch Cloudflare rules for cleanup", "error", err)
				break
			}

			var cfResp cloudflareRulesResponse
			json.NewDecoder(resp.Body).Decode(&cfResp)
			resp.Body.Close()

			if len(cfResp.Result) == 0 {
				break
			}

			now := time.Now()
			deletedCount := 0

			for _, rule := range cfResp.Result {
				createdTime, err := time.Parse(time.RFC3339, rule.CreatedOn)
				if err != nil {
					continue
				}

				// If rule is older than banDuration, delete it
				if now.Sub(createdTime) > banDuration {
					deleteURL := fmt.Sprintf("%s/%s", apiDeleteURLs[i], rule.ID)
					delReq, _ := http.NewRequest("DELETE", deleteURL, nil)
					delReq.Header.Set("Authorization", "Bearer "+cfg.APIToken)
					
					delResp, delErr := m.Client.Do(delReq)
					if delErr == nil {
						if delResp.StatusCode == 200 {
							deletedCount++
						}
						delResp.Body.Close()
					}
					// Sleep briefly to respect CF API rate limits (1200 per 5 min)
					time.Sleep(250 * time.Millisecond)
				}
			}

			if deletedCount > 0 {
				logger.Info("Cloudflare auto-cleanup removed expired IP bans", "count", deletedCount)
			}

			if page >= cfResp.ResultInfo.TotalPages {
				break
			}
			page++
		}
	}
}
