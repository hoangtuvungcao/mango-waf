package rules

import (
	"net/http"
	"regexp"
	"strings"
	"sync"

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

// Rule represents a single WAF rule
type Rule struct {
	ID          string
	Name        string
	Description string
	Category    string   // sqli, xss, rce, lfi, rfi, ssrf, dos, scanner, custom
	Severity    string   // low, medium, high, critical
	Phase       int      // 1=request_headers, 2=request_body, 3=response_headers, 4=response_body
	Targets     []string // URL, ARGS, HEADERS, BODY, COOKIE, UA, METHOD
	Operator    string   // rx (regex), eq, contains, beginsWith, endsWith, gt, lt
	Pattern     string
	Compiled    *regexp.Regexp
	Action      string // block, log, challenge, drop
	Enabled     bool
	Tags        []string
	Paranoia    int // 1-4 paranoia level
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
	mu             sync.Mutex
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
		Matches: make([]MatchResult, 0),
	}

	e.stats.mu.Lock()
	e.stats.TotalInspected++
	e.stats.mu.Unlock()

	// Extract request data for inspection
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

			e.stats.mu.Lock()
			e.stats.TotalMatched++
			e.stats.RuleHits[rule.ID]++
			e.stats.mu.Unlock()

			if rule.Action == "block" || rule.Action == "drop" {
				result.Blocked = true
				result.Action = rule.Action
				result.TopRule = rule.ID
			}
		}
	}

	if result.Blocked {
		e.stats.mu.Lock()
		e.stats.TotalBlocked++
		e.stats.mu.Unlock()

		logger.Warn("WAF blocked request",
			"rule", result.TopRule,
			"matches", len(result.Matches),
			"score", result.Score,
			"uri", r.RequestURI,
		)
	}

	return result
}

// requestData holds extracted request data for inspection
type requestData struct {
	URL     string
	Path    string
	Query   string
	Method  string
	Headers map[string]string
	Cookies map[string]string
	UA      string
	Body    string // first 8KB
	Args    map[string]string
}

func extractRequestData(r *http.Request) *requestData {
	rd := &requestData{
		URL:     r.URL.String(),
		Path:    r.URL.Path,
		Query:   r.URL.RawQuery,
		Method:  r.Method,
		Headers: make(map[string]string),
		Cookies: make(map[string]string),
		Args:    make(map[string]string),
		UA:      r.UserAgent(),
	}

	for k, v := range r.Header {
		rd.Headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	for _, c := range r.Cookies() {
		rd.Cookies[c.Name] = c.Value
	}

	for k, v := range r.URL.Query() {
		rd.Args[k] = strings.Join(v, ", ")
	}

	return rd
}

// matchRule checks a single rule against request data
func (e *Engine) matchRule(rule *Rule, rd *requestData) MatchResult {
	for _, target := range rule.Targets {
		values := getTargetValues(target, rd)
		for _, val := range values {
			if e.matchOperator(rule, val) {
				return MatchResult{
					Matched:    true,
					Rule:       rule,
					MatchedVal: truncate(val, 100),
					Target:     target,
				}
			}
		}
	}
	return MatchResult{Matched: false}
}

func getTargetValues(target string, rd *requestData) []string {
	switch target {
	case "URL":
		return []string{rd.URL}
	case "PATH":
		return []string{rd.Path}
	case "QUERY":
		return []string{rd.Query}
	case "METHOD":
		return []string{rd.Method}
	case "UA":
		return []string{rd.UA}
	case "HEADERS":
		vals := make([]string, 0, len(rd.Headers))
		for _, v := range rd.Headers {
			vals = append(vals, v)
		}
		return vals
	case "ARGS":
		vals := make([]string, 0, len(rd.Args))
		for _, v := range rd.Args {
			vals = append(vals, v)
		}
		return vals
	case "COOKIES":
		vals := make([]string, 0, len(rd.Cookies))
		for _, v := range rd.Cookies {
			vals = append(vals, v)
		}
		return vals
	case "BODY":
		return []string{rd.Body}
	default:
		return nil
	}
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
		return strings.Contains(strings.ToLower(value), strings.ToLower(rule.Pattern))
	case "eq":
		return strings.EqualFold(value, rule.Pattern)
	case "beginsWith":
		return strings.HasPrefix(strings.ToLower(value), strings.ToLower(rule.Pattern))
	case "endsWith":
		return strings.HasSuffix(strings.ToLower(value), strings.ToLower(rule.Pattern))
	default:
		return false
	}
}

// AddRule adds a custom rule
func (e *Engine) AddRule(rule *Rule) error {
	if rule.Operator == "rx" && rule.Pattern != "" {
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
	e.stats.mu.Lock()
	defer e.stats.mu.Unlock()
	return map[string]interface{}{
		"total_inspected": e.stats.TotalInspected,
		"total_blocked":   e.stats.TotalBlocked,
		"total_matched":   e.stats.TotalMatched,
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
