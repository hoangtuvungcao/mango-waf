package rules

import (
	"mango-waf/logger"
	"regexp"
)

// loadOWASPRules loads OWASP Core Rule Set inspired rules
func (e *Engine) loadOWASPRules(paranoiaLevel int) {
	owaspRules := []*Rule{
		// ================================================================
		// 920xxx — Protocol Enforcement
		// ================================================================
		{
			ID: "920100", Name: "Invalid HTTP Request Line",
			Category: "protocol", Severity: "high", Phase: 1, Paranoia: 1,
			Targets: []string{"METHOD"}, Operator: "!rx",
			Pattern: `^(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|CONNECT|TRACE)$`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "protocol"},
		},
		{
			ID: "920170", Name: "GET/HEAD with Body",
			Category: "protocol", Severity: "medium", Phase: 1, Paranoia: 1,
			Targets: []string{"HEADERS"}, Operator: "rx",
			Pattern: `^[1-9]\d*$`,
			Action:  "block", Enabled: false,
			Tags: []string{"OWASP_CRS", "protocol"},
		},
		{
			ID: "920270", Name: "Invalid Character in Request",
			Category: "protocol", Severity: "high", Phase: 1, Paranoia: 2,
			Targets: []string{"URL"}, Operator: "rx",
			Pattern: `[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "protocol"},
		},

		// ================================================================
		// 930xxx — Local File Inclusion (LFI)
		// ================================================================
		{
			ID: "930100", Name: "Path Traversal Attack",
			Category: "lfi", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"URL", "ARGS"}, Operator: "rx",
			Pattern: `(?:\.\./|\.\.\\|%2e%2e[/\\%]|%252e%252e)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "LFI", "path-traversal"},
		},
		{
			ID: "930110", Name: "OS File Access Attempt",
			Category: "lfi", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"URL", "ARGS"}, Operator: "rx",
			Pattern: `(?:/etc/passwd|/etc/shadow|/proc/self|c:\\windows|boot\.ini|win\.ini)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "LFI"},
		},
		{
			ID: "930120", Name: "Restricted File Access",
			Category: "lfi", Severity: "high", Phase: 1, Paranoia: 1,
			Targets: []string{"URL"}, Operator: "rx",
			Pattern: `(?:\.htaccess|\.htpasswd|\.env|\.git/|\.svn/|\.DS_Store|web\.config|\.bak|\.old|\.sql|\.log)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "LFI", "info-disclosure"},
		},

		// ================================================================
		// 941xxx — Cross-Site Scripting (XSS)
		// ================================================================
		{
			ID: "941100", Name: "XSS Attack via Script Tag",
			Category: "xss", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL", "HEADERS", "COOKIES"}, Operator: "rx",
			Pattern: `(?:<script[^>]*>|<\/script>|javascript\s*:|on\w+\s*=)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "XSS"},
		},
		{
			ID: "941110", Name: "XSS Attack via Event Handler",
			Category: "xss", Severity: "high", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL"}, Operator: "rx",
			Pattern: `(?:on(?:abort|blur|change|click|dblclick|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|resize|select|submit|unload)\s*=)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "XSS"},
		},
		{
			ID: "941120", Name: "XSS Attack via img/iframe/object",
			Category: "xss", Severity: "high", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL"}, Operator: "rx",
			Pattern: `(?:<(?:img|iframe|object|embed|svg|math|video|audio|source|base|link|meta|form|input|button|textarea|select)\b)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "XSS"},
		},
		{
			ID: "941130", Name: "XSS eval/alert Injection",
			Category: "xss", Severity: "high", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL"}, Operator: "rx",
			Pattern: `(?:eval\s*\(|alert\s*\(|prompt\s*\(|confirm\s*\(|String\.fromCharCode|document\.cookie|document\.write|window\.location)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "XSS"},
		},

		// ================================================================
		// 942xxx — SQL Injection (SQLi)
		// ================================================================
		{
			ID: "942100", Name: "SQL Injection Attack — Tautology",
			Category: "sqli", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL", "COOKIES"}, Operator: "rx",
			Pattern: `(?:'\s*(?:or|and)\s*'?\d*\s*[=<>]|"\s*(?:or|and)\s*"\s*[=<>]|(?:or|and)\s+\d+\s*=\s*\d+|\bor\b\s+\d+\s*=\s*\d+|'\s*or\s+'[^']*'\s*=\s*')`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "SQLi"},
		},
		{
			ID: "942110", Name: "SQL Injection Attack — UNION",
			Category: "sqli", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL"}, Operator: "rx",
			Pattern: `(?:union\s+(?:all\s+)?select\s|union\s+select\s)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "SQLi"},
		},
		{
			ID: "942120", Name: "SQL Injection — Stacked Queries",
			Category: "sqli", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL"}, Operator: "rx",
			Pattern: `(?:;\s*(?:drop|alter|create|truncate|rename|insert|update|delete|exec|execute)\s)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "SQLi"},
		},
		{
			ID: "942130", Name: "SQL Injection — Comment Bypass",
			Category: "sqli", Severity: "high", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL"}, Operator: "rx",
			Pattern: `(?:/\*[\s\S]*?\*/|--\s|#\s|;\s*--|%23|%2d%2d)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "SQLi"},
		},
		{
			ID: "942140", Name: "SQL Injection — Information Schema",
			Category: "sqli", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL"}, Operator: "rx",
			Pattern: `(?:information_schema|sysobjects|syscolumns|sysusers|pg_catalog|pg_tables)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "SQLi"},
		},
		{
			ID: "942150", Name: "SQL Injection — Functions",
			Category: "sqli", Severity: "high", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL"}, Operator: "rx",
			Pattern: `(?:(?:sleep|benchmark|waitfor|delay|load_file|into\s+(?:out|dump)file)\s*\()`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "SQLi"},
		},

		// ================================================================
		// 932xxx — Remote Code Execution (RCE)
		// ================================================================
		{
			ID: "932100", Name: "Unix Command Injection",
			Category: "rce", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL", "HEADERS"}, Operator: "rx",
			Pattern: `(?:;\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|netcat|bash|sh|python|perl|php|ruby|gcc|chmod|chown)\b|` + "`" + `|\$\(|\|\||\&\&)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "RCE"},
		},
		{
			ID: "932110", Name: "Windows Command Injection",
			Category: "rce", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL"}, Operator: "rx",
			Pattern: `(?:cmd\.exe|powershell|command\.com|cscript|wscript|mshta|regsvr32|rundll32|certutil)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "RCE"},
		},

		// ================================================================
		// 931xxx — Remote File Inclusion (RFI)
		// ================================================================
		{
			ID: "931100", Name: "Remote File Inclusion — URL in Parameter",
			Category: "rfi", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS"}, Operator: "rx",
			Pattern: `(?:https?://|ftp://|data:|php://|zlib://|glob://|expect://|phar://)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "RFI"},
		},

		// ================================================================
		// 934xxx — Node.js / Java Attacks
		// ================================================================
		{
			ID: "934100", Name: "Node.js Injection",
			Category: "rce", Severity: "critical", Phase: 1, Paranoia: 2,
			Targets: []string{"ARGS", "URL"}, Operator: "rx",
			Pattern: `(?:require\s*\(\s*['"]\s*(?:child_process|fs|net|http|crypto)|process\.(?:env|exit|argv|mainModule)|__proto__|constructor\s*\[)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "NodeJS"},
		},

		// ================================================================
		// 944xxx — Java / Deserialization
		// ================================================================
		{
			ID: "944100", Name: "Java Deserialization Attack",
			Category: "rce", Severity: "critical", Phase: 1, Paranoia: 2,
			Targets: []string{"ARGS", "URL", "HEADERS"}, Operator: "rx",
			Pattern: `(?:java\.lang\.Runtime|ProcessBuilder|javax\.script|org\.apache\.commons|com\.sun\.org\.apache|java\.io\.ObjectInputStream)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "Java"},
		},

		// ================================================================
		// 913xxx — Scanner Detection
		// ================================================================
		{
			ID: "913100", Name: "Known Security Scanner",
			Category: "scanner", Severity: "high", Phase: 1, Paranoia: 1,
			Targets: []string{"UA"}, Operator: "rx",
			Pattern: `(?:nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|ffuf|burpsuite|zaproxy|acunetix|nessus|openvas|qualys|nuclei|httpx|subfinder)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "scanner"},
		},
		{
			ID: "913110", Name: "Known Scraping Tool",
			Category: "scanner", Severity: "medium", Phase: 1, Paranoia: 2,
			Targets: []string{"UA"}, Operator: "rx",
			Pattern: `(?:scrapy|beautifulsoup|mechanize|phantom|headless|puppeteer|playwright|selenium)`,
			Action:  "challenge", Enabled: true,
			Tags: []string{"OWASP_CRS", "scraper"},
		},

		// ================================================================
		// 921xxx — Protocol Attack
		// ================================================================
		{
			ID: "921100", Name: "HTTP Splitting/Smuggling",
			Category: "protocol", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"HEADERS", "ARGS"}, Operator: "rx",
			Pattern: `(?:\r\n|\n)(?:Content-|Transfer-|Set-Cookie|Location)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "HTTP-smuggling"},
		},

		// ================================================================
		// 933xxx — PHP Injection
		// ================================================================
		{
			ID: "933100", Name: "PHP Injection Attack",
			Category: "rce", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS", "URL"}, Operator: "rx",
			Pattern: `(?:<\?(?:php)?|assert\s*\(|eval\s*\(|preg_replace\s*\(.*/e|system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\(|popen\s*\()`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "PHP"},
		},

		// ================================================================
		// 950xxx — SSRF Prevention
		// ================================================================
		{
			ID: "950100", Name: "SSRF — Internal Network Access",
			Category: "ssrf", Severity: "critical", Phase: 1, Paranoia: 1,
			Targets: []string{"ARGS"}, Operator: "rx",
			Pattern: `(?:127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+|\[::1\]|metadata\.google|instance-data)`,
			Action:  "block", Enabled: true,
			Tags: []string{"OWASP_CRS", "SSRF"},
		},
	}

	for _, rule := range owaspRules {
		if rule.Paranoia <= paranoiaLevel {
			if (rule.Operator == "rx" || rule.Operator == "!rx") && rule.Pattern != "" {
				compiled, err := regexp.Compile("(?i)" + rule.Pattern)
				if err != nil {
					logger.Warn("Failed to compile WAF rule", "rule", rule.ID, "error", err)
					continue
				}
				rule.Compiled = compiled
			}
			e.rules = append(e.rules, rule)
			e.ruleIndex[rule.ID] = rule
		}
	}
}
