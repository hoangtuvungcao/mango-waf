package core

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mango-waf/intelligence"
)

// SecurityLogEvent represents a single security or WAF event
type SecurityLogEvent struct {
	ID          uint64 `json:"id"`
	Timestamp   string `json:"timestamp"`
	Type        string `json:"type"`      // SECURITY, EXPLOIT, ACCESS, CHALLENGE, BAN
	ClientIP    string `json:"client_ip"`
	Domain      string `json:"domain"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Status      int    `json:"status"`
	Action      string `json:"action"`    // BLOCKED, DROPPED, PASSED, CHALLENGE_SOLVED
	Rule        string `json:"rule"`      // Rule ID or category (e.g., OWASP-942100, SQLi, XSS)
	Desc        string `json:"desc"`      // Event details / payload snippet
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
}

var logGeoProvider *intelligence.GeoProvider
var logGeoOnce sync.Once

func getLogGeoProvider() *intelligence.GeoProvider {
	logGeoOnce.Do(func() {
		dbPath := "GeoLite2-City.mmdb"
		if _, err := os.Stat(dbPath); err != nil {
			if _, err2 := os.Stat("../GeoLite2-City.mmdb"); err2 == nil {
				dbPath = "../GeoLite2-City.mmdb"
			}
		}
		p, err := intelligence.NewGeoProvider(dbPath)
		if err == nil {
			logGeoProvider = p
		}
	})
	return logGeoProvider
}

// LogStore holds recent security events in a thread-safe ring buffer with async worker
type LogStore struct {
	mu     sync.RWMutex
	events []SecurityLogEvent
	head   int
	maxCap int
	ch     chan SecurityLogEvent
	curRPS *int64
}

var globalLogStore *LogStore
var logStoreOnce sync.Once
var vtZone = time.FixedZone("ICT", 7*3600)
var logIDCounter uint64

// GetLogStore returns the singleton LogStore
func GetLogStore() *LogStore {
	logStoreOnce.Do(func() {
		ls := &LogStore{
			events: make([]SecurityLogEvent, 0, 2000),
			maxCap: 2000,
			ch:     make(chan SecurityLogEvent, 10000),
		}
		go ls.worker()
		globalLogStore = ls
	})
	return globalLogStore
}

// SetRPSPointer binds current RPS counter for smart DDoS sampling
func (ls *LogStore) SetRPSPointer(rpsPtr *int64) {
	if ls != nil {
		ls.curRPS = rpsPtr
	}
}

// worker processes log events asynchronously without blocking HTTP request workers
func (ls *LogStore) worker() {
	for event := range ls.ch {
		ls.mu.Lock()
		if len(ls.events) < ls.maxCap {
			ls.events = append(ls.events, event)
		} else {
			ls.events[ls.head] = event
			ls.head = (ls.head + 1) % ls.maxCap
		}
		ls.mu.Unlock()
	}
}

// RecordEvent appends a security event asynchronously without blocking HTTP workers
func (ls *LogStore) RecordEvent(eventType, clientIP, domain, method, path string, status int, action, rule, desc string) {
	if ls == nil {
		return
	}

	// Smart Log Sampling under DDoS / Heavy Load (> 200 RPS):
	// Under DDoS, sampling high-frequency repetitive logs (ACCESS, CHALLENGE_REQUIRED) prevents API & UI lag
	if ls.curRPS != nil {
		rps := atomic.LoadInt64(ls.curRPS)
		if rps > 200 {
			if eventType == "ACCESS" || (eventType == "CHALLENGE" && action == "CHALLENGE_REQUIRED") {
				// Sample 1 out of 20 logs during DDoS surge
				if rand.Intn(20) != 0 {
					return
				}
			}
		}
	}

	var countryCode, countryName string
	if gp := getLogGeoProvider(); gp != nil {
		if geo, err := gp.Lookup(clientIP); err == nil {
			countryCode = geo.CountryCode
			countryName = geo.Country
		}
	}
	if countryCode == "" {
		countryCode = "XX"
	}
	if countryName == "" {
		countryName = "Unknown"
	}

	event := SecurityLogEvent{
		ID:          atomic.AddUint64(&logIDCounter, 1),
		Timestamp:   time.Now().In(vtZone).Format("2006-01-02 15:04:05"),
		Type:        eventType,
		ClientIP:    clientIP,
		Domain:      domain,
		Method:      method,
		Path:        path,
		Status:      status,
		Action:      action,
		Rule:        rule,
		Desc:        desc,
		CountryCode: countryCode,
		CountryName: countryName,
	}

	// Non-blocking channel push: if channel is full during 100k+ RPS Tsunami, drop log silently (0ms overhead)
	select {
	case ls.ch <- event:
	default:
	}
}

// QueryLogs filters events based on type, search query, and domain
func (ls *LogStore) QueryLogs(logType, search, domain string) []SecurityLogEvent {
	if ls == nil {
		return nil
	}
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	search = strings.ToLower(strings.TrimSpace(search))
	domain = strings.ToLower(strings.TrimSpace(domain))
	logType = strings.ToUpper(strings.TrimSpace(logType))

	n := len(ls.events)
	if n == 0 {
		return []SecurityLogEvent{}
	}

	result := make([]SecurityLogEvent, 0, 100)

	// Iterate in reverse (newest first) considering ring buffer head
	for i := 0; i < n; i++ {
		idx := (ls.head - 1 - i + n) % n
		e := ls.events[idx]

		if logType != "" && logType != "ALL" && !strings.EqualFold(e.Type, logType) {
			continue
		}

		if domain != "" && !strings.Contains(strings.ToLower(e.Domain), domain) {
			continue
		}

		if search != "" {
			combined := strings.ToLower(fmt.Sprintf("%s %s %s %s %s %s", e.ClientIP, e.Domain, e.Path, e.Rule, e.Action, e.Desc))
			if !strings.Contains(combined, search) {
				continue
			}
		}

		result = append(result, e)
		if len(result) >= 500 {
			break
		}
	}
	return result
}

// Clear empties all stored security log events
func (ls *LogStore) Clear() {
	if ls == nil {
		return
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.events = make([]SecurityLogEvent, 0, ls.maxCap)
	ls.head = 0
}
