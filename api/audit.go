package api

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"mango-waf/logger"
)

// AuditEntry represents a single audit log item
type AuditEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Role      string    `json:"role"`
	Action    string    `json:"action"`
	Module    string    `json:"module"`
	Target    string    `json:"target"`
	Details   string    `json:"details"`
	ClientIP  string    `json:"client_ip"`
	Status    string    `json:"status"` // "success" or "failure"
}

// AuditLogger manages persistent audit logs
type AuditLogger struct {
	mu       sync.RWMutex
	filePath string
	entries  []AuditEntry
}

var globalAuditLogger *AuditLogger
var auditOnce sync.Once

// GetAuditLogger returns global AuditLogger instance
func GetAuditLogger() *AuditLogger {
	auditOnce.Do(func() {
		globalAuditLogger = NewAuditLogger("data/audit_logs.json")
	})
	return globalAuditLogger
}

// NewAuditLogger initializes audit logger
func NewAuditLogger(filePath string) *AuditLogger {
	al := &AuditLogger{
		filePath: filePath,
		entries:  make([]AuditEntry, 0),
	}
	al.load()
	return al
}

// LogAction records an audit entry
func (al *AuditLogger) LogAction(user, role, action, module, target, details, clientIP, status string) {
	al.mu.Lock()
	defer al.mu.Unlock()

	entry := AuditEntry{
		ID:        fmt.Sprintf("audit_%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		User:      user,
		Role:      role,
		Action:    action,
		Module:    module,
		Target:    target,
		Details:   details,
		ClientIP:  clientIP,
		Status:    status,
	}

	al.entries = append([]AuditEntry{entry}, al.entries...)
	if len(al.entries) > 5000 {
		al.entries = al.entries[:5000] // Cap at 5,000 entries
	}

	go al.saveAsync()
	logger.Info("Audit Log", "user", user, "role", role, "action", action, "module", module, "target", target, "status", status)
}

// QueryEntries filters and returns audit entries
func (al *AuditLogger) QueryEntries(user, role, action, module, search string, limit int) []AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	result := make([]AuditEntry, 0)
	searchLower := strings.ToLower(search)

	for _, e := range al.entries {
		if user != "" && !strings.EqualFold(e.User, user) {
			continue
		}
		if role != "" && !strings.EqualFold(e.Role, role) {
			continue
		}
		if action != "" && !strings.EqualFold(e.Action, action) {
			continue
		}
		if module != "" && !strings.EqualFold(e.Module, module) {
			continue
		}
		if searchLower != "" {
			combined := strings.ToLower(fmt.Sprintf("%s %s %s %s %s %s", e.User, e.Action, e.Module, e.Target, e.Details, e.ClientIP))
			if !strings.Contains(combined, searchLower) {
				continue
			}
		}
		result = append(result, e)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

// ExportCSV exports filtered audit logs as CSV string
func (al *AuditLogger) ExportCSV(user, role, action, module, search string) string {
	entries := al.QueryEntries(user, role, action, module, search, 0)
	var sb strings.Builder
	sb.WriteString("Timestamp,User,Role,Action,Module,Target,ClientIP,Status,Details\n")
	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
			e.Timestamp.Format(time.RFC3339),
			escapeCSV(e.User),
			escapeCSV(e.Role),
			escapeCSV(e.Action),
			escapeCSV(e.Module),
			escapeCSV(e.Target),
			escapeCSV(e.ClientIP),
			escapeCSV(e.Status),
			escapeCSV(e.Details),
		))
	}
	return sb.String()
}

func escapeCSV(s string) string {
	return strings.ReplaceAll(s, "\"", "\"\"")
}

func (al *AuditLogger) load() {
	al.mu.Lock()
	defer al.mu.Unlock()

	data, err := os.ReadFile(al.filePath)
	if err == nil {
		var loaded []AuditEntry
		if err := json.Unmarshal(data, &loaded); err == nil {
			al.entries = loaded
		}
	}
}

func (al *AuditLogger) saveAsync() {
	al.mu.RLock()
	data, err := json.MarshalIndent(al.entries, "", "  ")
	al.mu.RUnlock()

	if err == nil {
		_ = os.MkdirAll("data", 0755)
		_ = os.WriteFile(al.filePath, data, 0644)
	}
}
