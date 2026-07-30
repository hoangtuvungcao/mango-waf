package intelligence

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"mango-waf/config"
	"mango-waf/logger"
)

// Intel is the intelligence engine
type Intel struct {
	cfg        *config.Config
	geo        *GeoProvider
	reputation *ReputationEngine
	asn        *ASNAnalyzer
	feeds      *ThreatFeedManager
	lists      *ListManager
}

// EvalResult holds the intelligence evaluation result for an IP
type EvalResult struct {
	IP         string
	TrustScore float64
	Geo        *GeoResult
	Reputation *ReputationResult
	ASN        *ASNInfo
	Actions    []string
	EvalTime   time.Duration
}

// NewIntel creates a new intelligence engine
func NewIntel(cfg *config.Config) *Intel {
	intel := &Intel{
		cfg:   cfg,
		lists: NewListManager(),
	}

	// Initialize GeoIP
	if cfg.Intelligence.GeoIP.Enabled {
		geo, err := NewGeoProvider(cfg.Intelligence.GeoIP.DBPath)
		if err != nil {
			logger.Warn("GeoIP init failed, using fallback", "error", err)
			fallback := &GeoProvider{fallback: true}
			intel.geo = fallback
		} else {
			intel.geo = geo
			logger.Info("GeoIP loaded", "path", cfg.Intelligence.GeoIP.DBPath)
		}
	}

	// Initialize IP Reputation
	if cfg.Intelligence.IPReputation.Enabled {
		intel.reputation = NewReputationEngine(cfg)
		logger.Info("IP Reputation engine enabled")
	}

	// Initialize ASN Analyzer
	if cfg.Intelligence.ASN.Enabled {
		intel.asn = NewASNAnalyzer()
		logger.Info("ASN Analyzer enabled")
	}

	// Initialize Threat Feeds
	intel.feeds = NewThreatFeedManager(cfg)
	go intel.feeds.StartPeriodicUpdate(1 * time.Hour)

	// Load static lists
	intel.lists.LoadReservedIPs()

	return intel
}

// UpdateConfig updates configuration pointer live
func (i *Intel) UpdateConfig(cfg *config.Config) {
	if cfg != nil {
		i.cfg = cfg
	}
}

// Evaluate evaluates an IP's trust level through all intelligence layers
func (i *Intel) Evaluate(ip string) *EvalResult {
	start := time.Now()
	result := &EvalResult{
		IP:         ip,
		TrustScore: 70, // Neutral default
		Actions:    make([]string, 0),
	}

	// Layer 1: Static lists check (fastest)
	if i.lists.IsBlacklisted(ip) {
		result.TrustScore = 0
		result.Actions = append(result.Actions, "blacklisted")
		result.EvalTime = time.Since(start)
		return result
	}
	if i.lists.IsWhitelisted(ip) {
		result.TrustScore = 100
		result.Actions = append(result.Actions, "whitelisted")
		result.EvalTime = time.Since(start)
		return result
	}

	// Layer 2: Threat feeds check
	if i.feeds.IsKnownThreat(ip) {
		result.TrustScore -= 40
		result.Actions = append(result.Actions, "threat_feed_match")
	}

	// Layer 3: GeoIP evaluation
	if i.geo != nil && !i.geo.fallback {
		geo, err := i.geo.Lookup(ip)
		if err == nil {
			result.Geo = geo

			// Blocked countries
			for _, blocked := range i.cfg.Intelligence.GeoIP.BlockedCountries {
				if strings.EqualFold(geo.CountryCode, blocked) {
					result.TrustScore = 0
					result.Actions = append(result.Actions, "geo_blocked:"+blocked)
					result.EvalTime = time.Since(start)
					return result
				}
			}

			// Allowed-only countries
			if len(i.cfg.Intelligence.GeoIP.AllowedCountries) > 0 {
				allowed := false
				for _, a := range i.cfg.Intelligence.GeoIP.AllowedCountries {
					if strings.EqualFold(geo.CountryCode, a) {
						allowed = true
						break
					}
				}
				if !allowed {
					result.TrustScore -= 30
					result.Actions = append(result.Actions, "geo_not_allowed:"+geo.CountryCode)
				}
			}
		}
	}

	// Layer 4: IP Reputation
	if i.reputation != nil {
		rep := i.reputation.Check(ip)
		if rep != nil {
			result.Reputation = rep
			if rep.IsKnownBad {
				result.TrustScore -= 50
				result.Actions = append(result.Actions, "known_bad_ip")
			}
			if rep.IsProxy || rep.IsTor || rep.IsVPN {
				result.TrustScore -= 20
				result.Actions = append(result.Actions, "anonymizer")
			}
			if rep.IsDatacenter {
				result.TrustScore -= 15
				result.Actions = append(result.Actions, "datacenter_ip")
			}
			// Apply reputation score directly
			if rep.AbuseScore > 0 {
				result.TrustScore -= float64(rep.AbuseScore) * 0.5
			}
		}
	}

	// Layer 5: ASN analysis
	if i.asn != nil {
		asn := i.asn.Analyze(ip, result.Geo)
		if asn != nil {
			result.ASN = asn
			if asn.IsHosting && i.cfg.Intelligence.ASN.BlockDatacenter {
				result.TrustScore -= 25
				result.Actions = append(result.Actions, "hosting_asn:"+asn.Organization)
			}
			if asn.RiskLevel == "high" {
				result.TrustScore -= 20
				result.Actions = append(result.Actions, "high_risk_asn")
			}
		}
	}

	// Clamp score
	if result.TrustScore < 0 {
		result.TrustScore = 0
	}
	if result.TrustScore > 100 {
		result.TrustScore = 100
	}

	result.EvalTime = time.Since(start)
	return result
}

// Close cleans up resources
func (i *Intel) Close() {
	if i.geo != nil {
		i.geo.Close()
	}
}

// ================================================
// GeoIP Provider
// ================================================

// GeoResult holds geo-location data
type GeoResult struct {
	Country     string
	CountryCode string
	City        string
	Region      string
	Latitude    float64
	Longitude   float64
	ASN         uint
	ASNOrg      string
	IsEU        bool
}

// GeoProvider provides GeoIP lookups
type GeoProvider struct {
	dbPath   string
	fallback bool
	// In production with MaxMind:
	// reader *geoip2.Reader
}

// NewGeoProvider creates a GeoIP provider
func NewGeoProvider(dbPath string) (*GeoProvider, error) {
	if dbPath == "" {
		return &GeoProvider{fallback: true}, nil
	}

	// Check if DB file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		logger.Warn("GeoIP DB not found, download with: "+
			"wget https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City",
			"path", dbPath)
		return &GeoProvider{fallback: true}, nil
	}

	// In production: use github.com/oschwald/geoip2-golang
	// reader, err := geoip2.Open(dbPath)
	return &GeoProvider{dbPath: dbPath}, nil
}

// Lookup performs a GeoIP lookup
func (g *GeoProvider) Lookup(ipStr string) (*GeoResult, error) {
	if g.fallback {
		return &GeoResult{Country: "Unknown", CountryCode: "XX"}, nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", ipStr)
	}

	// In production with MaxMind:
	// record, err := g.reader.City(ip)
	// return &GeoResult{
	//     Country:     record.Country.Names["en"],
	//     CountryCode: record.Country.IsoCode,
	//     City:        record.City.Names["en"],
	//     Region:      record.Subdivisions[0].Names["en"],
	//     Latitude:    record.Location.Latitude,
	//     Longitude:   record.Location.Longitude,
	//     IsEU:        record.Country.IsInEuropeanUnion,
	// }, nil

	return &GeoResult{Country: "Unknown", CountryCode: "XX"}, nil
}

// Close closes the GeoIP provider
func (g *GeoProvider) Close() {
	// In production: g.reader.Close()
}

// ================================================
// List Manager (Blacklist/Whitelist)
// ================================================

// ListManager manages dynamic IP/CIDR/Country lists
type ListManager struct {
	mu        sync.RWMutex
	blacklist map[string]ListEntry
	whitelist map[string]ListEntry
	cidrBlack []*net.IPNet
	cidrWhite []*net.IPNet
}

// ListEntry holds metadata for a list entry
type ListEntry struct {
	Value     string
	Reason    string
	AddedAt   time.Time
	ExpiresAt time.Time // Zero = permanent
	Source    string
}

// NewListManager creates a new list manager
func NewListManager() *ListManager {
	return &ListManager{
		blacklist: make(map[string]ListEntry),
		whitelist: make(map[string]ListEntry),
	}
}

// LoadReservedIPs whitelists private/reserved IP ranges
func (lm *ListManager) LoadReservedIPs() {
	reserved := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	}
	for _, cidr := range reserved {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			lm.cidrWhite = append(lm.cidrWhite, network)
		}
	}
}

// IsBlacklisted checks if an IP is blacklisted
func (lm *ListManager) IsBlacklisted(ip string) bool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	// Direct IP check
	if entry, ok := lm.blacklist[ip]; ok {
		if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
			return false // Expired
		}
		return true
	}

	// CIDR check
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range lm.cidrBlack {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// IsWhitelisted checks if an IP is whitelisted
func (lm *ListManager) IsWhitelisted(ip string) bool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if entry, ok := lm.whitelist[ip]; ok {
		if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
			return false
		}
		return true
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range lm.cidrWhite {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// AddBlacklist adds an IP/CIDR to the blacklist
func (lm *ListManager) AddBlacklist(value, reason, source string, ttl time.Duration) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	entry := ListEntry{
		Value:   value,
		Reason:  reason,
		AddedAt: time.Now(),
		Source:  source,
	}
	if ttl > 0 {
		entry.ExpiresAt = time.Now().Add(ttl)
	}

	if strings.Contains(value, "/") {
		_, network, err := net.ParseCIDR(value)
		if err == nil {
			lm.cidrBlack = append(lm.cidrBlack, network)
		}
	} else {
		lm.blacklist[value] = entry
	}
}

// AddWhitelist adds an IP/CIDR to the whitelist
func (lm *ListManager) AddWhitelist(value, reason, source string, ttl time.Duration) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	entry := ListEntry{
		Value:   value,
		Reason:  reason,
		AddedAt: time.Now(),
		Source:  source,
	}
	if ttl > 0 {
		entry.ExpiresAt = time.Now().Add(ttl)
	}

	if strings.Contains(value, "/") {
		_, network, err := net.ParseCIDR(value)
		if err == nil {
			lm.cidrWhite = append(lm.cidrWhite, network)
		}
	} else {
		lm.whitelist[value] = entry
	}
}

// RemoveBlacklist removes an IP from blacklist
func (lm *ListManager) RemoveBlacklist(ip string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	delete(lm.blacklist, ip)
}

// RemoveWhitelist removes an IP from whitelist
func (lm *ListManager) RemoveWhitelist(ip string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	delete(lm.whitelist, ip)
}

// CleanupExpired removes expired entries
func (lm *ListManager) CleanupExpired() {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	now := time.Now()
	for k, v := range lm.blacklist {
		if !v.ExpiresAt.IsZero() && now.After(v.ExpiresAt) {
			delete(lm.blacklist, k)
		}
	}
	for k, v := range lm.whitelist {
		if !v.ExpiresAt.IsZero() && now.After(v.ExpiresAt) {
			delete(lm.whitelist, k)
		}
	}
}

// Stats returns list statistics
func (lm *ListManager) Stats() (blackCount, whiteCount int) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return len(lm.blacklist) + len(lm.cidrBlack), len(lm.whitelist) + len(lm.cidrWhite)
}
