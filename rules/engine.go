package rules

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"mango-waf/config"
	"mango-waf/logger"
)

// Engine is the WAF rules engine
type Engine struct {
	cfg       *config.Config
	rules     []*Rule
	ruleIndex map[string]*Rule // by ID
	mu        sync.RWMutex
	stats     EngineStats
}

// SetParanoiaLevel updates the WAF paranoia level dynamically
func (e *Engine) SetParanoiaLevel(level int) {
	if level < 1 {
		level = 1
	}
	if level > 4 {
		level = 4
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cfg != nil {
		e.cfg.WAF.ParanoiaLevel = level
	}
}

// UpdateConfig updates the rules engine configuration pointer
func (e *Engine) UpdateConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
}

// Rule represents a single WAF rule
type Rule struct {
	ID           string
	Name         string
	Description  string
	Category     string   // sqli, xss, rce, lfi, rfi, ssrf, dos, scanner, custom
	Severity     string   // low, medium, high, critical
	Phase        int      // 1=request_headers, 2=request_body, 3=response_headers, 4=response_body
	Targets      []string // URL, ARGS, HEADERS, BODY, COOKIE, UA, METHOD
	Operator     string   // rx (regex), eq, contains, beginsWith, endsWith, gt, lt
	Pattern      string
	PatternLower string
	Compiled     *regexp.Regexp
	Action       string // block, log, challenge, drop
	Enabled      bool
	Tags         []string
	Paranoia     int // 1-4 paranoia level
}

// MatchResult holds the result of a rule match
type MatchResult struct {
	Matched    bool
	Rule       *Rule
	MatchedVal string
	Target     string
}

// InspectResult holds all matches for a request
type InspectResult struct {
	Blocked bool
	Matches []MatchResult
	Score   int
	Action  string
	TopRule string
}

// EngineStats tracks WAF engine statistics
type EngineStats struct {
	TotalInspected int64
	TotalBlocked   int64
	TotalMatched   int64
	statsMu        sync.Mutex
	RuleHits       map[string]int64
}

// NewEngine creates a new WAF rules engine
func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{
		cfg:       cfg,
		ruleIndex: make(map[string]*Rule),
		stats:     EngineStats{RuleHits: make(map[string]int64)},
	}

	if cfg.WAF.Enabled {
		e.loadOWASPRules(cfg.WAF.ParanoiaLevel)
		logger.Info("WAF engine loaded", "rules", len(e.rules), "paranoia", cfg.WAF.ParanoiaLevel)
	}

	return e
}

// Inspect inspects a request against all loaded rules
func (e *Engine) Inspect(r *http.Request) *InspectResult {
	if !e.cfg.WAF.Enabled {
		return &InspectResult{Blocked: false}
	}

	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	result := &InspectResult{
		Matches: make([]MatchResult, 0, 2),
	}

	atomic.AddInt64(&e.stats.TotalInspected, 1)

	// Fast bypass for framework static assets to prevent false-positive blocks
	if strings.HasPrefix(r.URL.Path, "/_next/static/") || strings.HasSuffix(r.URL.Path, ".png") || strings.HasSuffix(r.URL.Path, ".jpg") || strings.HasSuffix(r.URL.Path, ".css") || strings.HasSuffix(r.URL.Path, ".js") || strings.HasSuffix(r.URL.Path, ".woff2") || strings.HasSuffix(r.URL.Path, ".svg") {
		return result
	}

	// Zero-allocation request data wrapper
	reqData := extractRequestData(r)

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if rule.Paranoia > e.cfg.WAF.ParanoiaLevel {
			continue
		}

		match := e.matchRule(rule, reqData)
		if match.Matched {
			result.Matches = append(result.Matches, match)
			result.Score += severityScore(rule.Severity)

			atomic.AddInt64(&e.stats.TotalMatched, 1)
			e.stats.statsMu.Lock()
			e.stats.RuleHits[rule.ID]++
			e.stats.statsMu.Unlock()

			if rule.Action == "block" || rule.Action == "drop" {
				result.Blocked = true
				result.Action = rule.Action
				result.TopRule = rule.ID
			}
		}
	}

	if result.Blocked {
		atomic.AddInt64(&e.stats.TotalBlocked, 1)

		if atomic.LoadInt64(&e.stats.TotalInspected) < 50 {
			logger.Warn("WAF blocked request",
				"rule", result.TopRule,
				"matches", len(result.Matches),
				"score", result.Score,
				"uri", r.RequestURI,
			)
		}
	}

	return result
}

// requestData holds zero-allocation request data wrappers for inspection
type requestData struct {
	r      *http.Request
	URL    string
	Path   string
	Query  string
	Method string
	UA     string
}

func extractRequestData(r *http.Request) *requestData {
	return &requestData{
		r:      r,
		URL:    r.URL.String(),
		Path:   r.URL.Path,
		Query:  r.URL.RawQuery,
		Method: r.Method,
		UA:     r.UserAgent(),
	}
}

// matchRule checks a single rule against request data with zero map allocations
func (e *Engine) matchRule(rule *Rule, rd *requestData) MatchResult {
	for _, target := range rule.Targets {
		switch target {
		case "URL":
			if e.matchOperator(rule, rd.URL) {
				return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(rd.URL, 100), Target: target}
			}
		case "PATH":
			if e.matchOperator(rule, rd.Path) {
				return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(rd.Path, 100), Target: target}
			}
		case "QUERY":
			if e.matchOperator(rule, rd.Query) {
				return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(rd.Query, 100), Target: target}
			}
		case "METHOD":
			if e.matchOperator(rule, rd.Method) {
				return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(rd.Method, 100), Target: target}
			}
		case "UA":
			if e.matchOperator(rule, rd.UA) {
				return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(rd.UA, 100), Target: target}
			}
		case "HEADERS":
			for _, vals := range rd.r.Header {
				for _, val := range vals {
					if e.matchOperator(rule, val) {
						return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(val, 100), Target: target}
					}
				}
			}
		case "ARGS":
			if rd.Query != "" {
				for _, vals := range rd.r.URL.Query() {
					for _, val := range vals {
						if e.matchOperator(rule, val) {
							return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(val, 100), Target: target}
						}
					}
				}
			}
		case "COOKIES":
			for _, c := range rd.r.Cookies() {
				if e.matchOperator(rule, c.Value) {
					return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(c.Value, 100), Target: target}
				}
			}
		}
	}
	return MatchResult{Matched: false}
}

func (e *Engine) matchOperator(rule *Rule, value string) bool {
	switch rule.Operator {
	case "rx":
		if rule.Compiled != nil {
			return rule.Compiled.MatchString(value)
		}
		return false
	case "!rx":
		if rule.Compiled != nil {
			return !rule.Compiled.MatchString(value)
		}
		return false
	case "contains":
		pat := rule.PatternLower
		if pat == "" {
			pat = strings.ToLower(rule.Pattern)
		}
		return strings.Contains(strings.ToLower(value), pat)
	case "eq":
		return strings.EqualFold(value, rule.Pattern)
	case "beginsWith":
		pat := rule.PatternLower
		if pat == "" {
			pat = strings.ToLower(rule.Pattern)
		}
		return strings.HasPrefix(strings.ToLower(value), pat)
	case "endsWith":
		pat := rule.PatternLower
		if pat == "" {
			pat = strings.ToLower(rule.Pattern)
		}
		return strings.HasSuffix(strings.ToLower(value), pat)
	default:
		return false
	}
}

// AddRule adds a custom rule
func (e *Engine) AddRule(rule *Rule) error {
	rule.PatternLower = strings.ToLower(rule.Pattern)
	if (rule.Operator == "rx" || rule.Operator == "!rx") && rule.Pattern != "" {
		compiled, err := regexp.Compile("(?i)" + rule.Pattern)
		if err != nil {
			return err
		}
		rule.Compiled = compiled
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
	e.ruleIndex[rule.ID] = rule
	return nil
}

// GetStats returns engine stats
func (e *Engine) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_inspected": atomic.LoadInt64(&e.stats.TotalInspected),
		"total_blocked":   atomic.LoadInt64(&e.stats.TotalBlocked),
		"total_matched":   atomic.LoadInt64(&e.stats.TotalMatched),
		"rules_loaded":    len(e.rules),
	}
}

func severityScore(severity string) int {
	switch severity {
	case "critical":
		return 25
	case "high":
		return 15
	case "medium":
		return 10
	case "low":
		return 5
	default:
		return 1
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
