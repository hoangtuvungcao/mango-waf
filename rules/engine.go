package rules

import (
	"net/http"
	"net/url"
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
	ID              string
	Name            string
	Description     string
	Category        string   // sqli, xss, rce, lfi, rfi, ssrf, dos, scanner, custom
	Severity        string   // low, medium, high, critical
	Phase           int      // 1=request_headers, 2=request_body, 3=response_headers, 4=response_body
	Targets         []string // URL, ARGS, HEADERS, BODY, COOKIE, UA, METHOD
	Operator        string   // rx (regex), eq, contains, beginsWith, endsWith, gt, lt
	Pattern         string
	PatternLower    string
	RequiredKeyword string
	Compiled        *regexp.Regexp
	Action          string // block, log, challenge, drop
	Enabled         bool
	Tags            []string
	Paranoia        int // 1-4 paranoia level
	Hits            int64
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

	// Zero-allocation request data wrapper (pass by value, lazy evaluation)
	reqData := extractRequestData(r)

	// Build a single concatenated string for fast keyword pre-filtering
	var pb strings.Builder
	pb.Grow(1024)
	pb.WriteString(reqData.PathLower)
	pb.WriteByte('|')
	pb.WriteString(reqData.QueryLower)
	pb.WriteByte('|')
	pb.WriteString(reqData.MethodLower)
	pb.WriteByte('|')
	for _, h := range reqData.getHeaders() {
		pb.WriteString(h.lower)
		pb.WriteByte('|')
	}
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		pb.WriteString(strings.ToLower(cookie))
	}
	fullPayload := pb.String()

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if rule.Paranoia > e.cfg.WAF.ParanoiaLevel {
			continue
		}

		// Fast-path Request-Level Keyword Pre-filtering
		// Reduces O(N * Targets) down to O(N) simple string lookups
		if rule.RequiredKeyword != "" && !strings.Contains(fullPayload, rule.RequiredKeyword) {
			continue
		}

		match := e.matchRule(rule, &reqData)
		if match.Matched {
			result.Matches = append(result.Matches, match)
			result.Score += severityScore(rule.Severity)

			atomic.AddInt64(&e.stats.TotalMatched, 1)
			atomic.AddInt64(&rule.Hits, 1)

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
	r           *http.Request
	url         string
	urlLower    string
	ua          string
	uaLower     string
	Path        string
	PathLower   string
	Query       string
	QueryLower  string
	Method      string
	MethodLower string
	headers     []headerVal
	headersDone bool
}

type headerVal struct {
	raw   string
	lower string
}

func (rd *requestData) getURL() (string, string) {
	if rd.url == "" && rd.r.URL != nil {
		rd.url = rd.r.URL.String()
		rd.urlLower = strings.ToLower(rd.url)
	}
	return rd.url, rd.urlLower
}

func (rd *requestData) getUA() (string, string) {
	if rd.ua == "" {
		rd.ua = rd.r.UserAgent()
		rd.uaLower = strings.ToLower(rd.ua)
	}
	return rd.ua, rd.uaLower
}

func (rd *requestData) getHeaders() []headerVal {
	if !rd.headersDone {
		rd.headers = make([]headerVal, 0, len(rd.r.Header))
		for _, vals := range rd.r.Header {
			for _, val := range vals {
				rd.headers = append(rd.headers, headerVal{
					raw:   val,
					lower: strings.ToLower(val),
				})
			}
		}
		rd.headersDone = true
	}
	return rd.headers
}

func extractRequestData(r *http.Request) requestData {
	return requestData{
		r:           r,
		Path:        r.URL.Path,
		PathLower:   strings.ToLower(r.URL.Path),
		Query:       r.URL.RawQuery,
		QueryLower:  strings.ToLower(r.URL.RawQuery),
		Method:      r.Method,
		MethodLower: strings.ToLower(r.Method),
	}
}

// matchRule checks a single rule against request data with zero map allocations
func (e *Engine) matchRule(rule *Rule, rd *requestData) MatchResult {
	for _, target := range rule.Targets {
		switch target {
		case "URL":
			urlStr, urlLower := rd.getURL()
			if e.matchOperator(rule, urlStr, urlLower) {
				return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(urlStr, 100), Target: target}
			}
		case "PATH":
			if e.matchOperator(rule, rd.Path, rd.PathLower) {
				return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(rd.Path, 100), Target: target}
			}
		case "QUERY":
			if e.matchOperator(rule, rd.Query, rd.QueryLower) {
				return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(rd.Query, 100), Target: target}
			}
		case "METHOD":
			if e.matchOperator(rule, rd.Method, rd.MethodLower) {
				return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(rd.Method, 100), Target: target}
			}
		case "UA":
			uaStr, uaLower := rd.getUA()
			if e.matchOperator(rule, uaStr, uaLower) {
				return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(uaStr, 100), Target: target}
			}
		case "HEADERS":
			for _, h := range rd.getHeaders() {
				if e.matchOperator(rule, h.raw, h.lower) {
					return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(h.raw, 100), Target: target}
				}
			}
		case "ARGS":
			if rd.Query != "" {
				var matched bool
				var matchedVal string
				forEachQueryArg(rd.Query, func(val string) bool {
					valLower := strings.ToLower(val)
					if e.matchOperator(rule, val, valLower) {
						matched = true
						matchedVal = val
						return true
					}
					return false
				})
				if matched {
					return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(matchedVal, 100), Target: target}
				}
			}
		case "COOKIES":
			cookieHeader := rd.r.Header.Get("Cookie")
			if cookieHeader != "" {
				var matched bool
				var matchedVal string
				forEachCookieValue(cookieHeader, func(val string) bool {
					valLower := strings.ToLower(val)
					if e.matchOperator(rule, val, valLower) {
						matched = true
						matchedVal = val
						return true
					}
					return false
				})
				if matched {
					return MatchResult{Matched: true, Rule: rule, MatchedVal: truncate(matchedVal, 100), Target: target}
				}
			}
		}
	}
	return MatchResult{Matched: false}
}

func forEachQueryArg(query string, cb func(val string) bool) {
	for query != "" {
		var part string
		if i := strings.IndexAny(query, "&;"); i >= 0 {
			part, query = query[:i], query[i+1:]
		} else {
			part, query = query, ""
		}
		if part == "" {
			continue
		}
		val := part
		if i := strings.Index(part, "="); i >= 0 {
			val = part[i+1:]
		}
		if strings.Contains(val, "%") {
			if decoded, err := url.QueryUnescape(val); err == nil {
				val = decoded
			}
		}
		if cb(val) {
			return
		}
	}
}

func forEachCookieValue(cookieHeader string, cb func(val string) bool) {
	for cookieHeader != "" {
		var part string
		if i := strings.Index(cookieHeader, ";"); i >= 0 {
			part, cookieHeader = cookieHeader[:i], cookieHeader[i+1:]
		} else {
			part, cookieHeader = cookieHeader, ""
		}
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		val := part
		if i := strings.Index(part, "="); i >= 0 {
			val = part[i+1:]
		}
		if len(val) > 1 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		if cb(val) {
			return
		}
	}
}

func (e *Engine) matchOperator(rule *Rule, value, valueLower string) bool {
	switch rule.Operator {
	case "rx":
		if rule.Compiled != nil {
			if rule.RequiredKeyword != "" && !strings.Contains(valueLower, rule.RequiredKeyword) {
				return false
			}
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
		return strings.Contains(valueLower, pat)
	case "eq":
		return strings.EqualFold(value, rule.Pattern)
	case "beginsWith":
		pat := rule.PatternLower
		if pat == "" {
			pat = strings.ToLower(rule.Pattern)
		}
		return strings.HasPrefix(valueLower, pat)
	case "endsWith":
		pat := rule.PatternLower
		if pat == "" {
			pat = strings.ToLower(rule.Pattern)
		}
		return strings.HasSuffix(valueLower, pat)
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

		// Fast-path: extract exact literal keyword if rule contains a fixed substring
		rule.RequiredKeyword = extractRequiredKeyword(rule.PatternLower)
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

func extractRequiredKeyword(pat string) string {
	// If pattern contains disjunctions (OR |, character sets []), we cannot guarantee a single keyword
	if strings.ContainsAny(pat, "|[]()?*+^$") {
		return ""
	}

	var current strings.Builder
	var longest string

	for i := 0; i < len(pat); i++ {
		ch := pat[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
			current.WriteByte(ch)
		} else {
			if current.Len() > len(longest) {
				longest = current.String()
			}
			current.Reset()
		}
	}
	if current.Len() > len(longest) {
		longest = current.String()
	}

	if len(longest) >= 4 {
		return longest
	}
	return ""
}
