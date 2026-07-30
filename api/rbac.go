package api

import (
	"net/http"

	"mango-waf/config"
)

// Role constants
const (
	RoleSuperAdmin = "super_admin"
	RoleAdmin      = "admin"
	RoleOperator   = "operator"
	RoleUser       = "user"
)

type contextKey string

const (
	UserContextKey contextKey = "user"
	RoleContextKey contextKey = "role"
)

// Permission matrix helpers
func IsSuperAdmin(role string) bool {
	return role == RoleSuperAdmin || role == RoleAdmin // admin treated as super_admin if default admin account
}

func CanEditYAML(role string) bool {
	return role == RoleSuperAdmin || role == "admin"
}

func CanManageSystem(role string) bool {
	return role == RoleSuperAdmin || role == RoleAdmin
}

func CanManageGlobalSecurity(role string) bool {
	return role == RoleSuperAdmin || role == RoleAdmin
}

func CanManageAllDomains(role string) bool {
	return role == RoleSuperAdmin || role == RoleAdmin
}

func CanViewLogs(role string) bool {
	return role == RoleSuperAdmin || role == RoleAdmin || role == RoleOperator
}

func CanRestartServices(role string) bool {
	return role == RoleSuperAdmin || role == RoleAdmin || role == RoleOperator
}

// CheckDomainOwnership checks if a user has access to a domain
func CheckDomainOwnership(username, role, domainName string, domains []config.DomainConfig) bool {
	if CanManageAllDomains(role) {
		return true
	}
	for _, d := range domains {
		if d.Name == domainName {
			return d.Owner == username || d.Owner == ""
		}
	}
	return false
}

// RBACMiddleware returns middleware for specific required roles
func RequireRole(allowedRoles ...string) func(http.Handler) http.Handler {
	allowedMap := make(map[string]bool)
	for _, r := range allowedRoles {
		allowedMap[r] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, _ := r.Context().Value(RoleContextKey).(string)
			if role == "" {
				role = RoleUser
			}

			// SuperAdmin always allowed
			if role == RoleSuperAdmin {
				next.ServeHTTP(w, r)
				return
			}

			if !allowedMap[role] {
				writeJSON(w, map[string]interface{}{
					"status":  "error",
					"message": "Access Denied: Your role does not have permission for this resource",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
