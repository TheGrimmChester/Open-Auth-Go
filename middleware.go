package openauth

import (
	"net/http"
	"strings"
)

// MiddlewareConfig configures HTTP JWT middleware for product APIs.
type MiddlewareConfig struct {
	// Secret is the user JWT_SECRET.
	Secret []byte
	// CookieName defaults to CookieName ("opa_token").
	CookieName string
	// ServiceSecret is OPEN_SERVICE_JWT_SECRET (optional).
	ServiceSecret []byte
	// ServiceAudience is the expected aud for service JWTs (e.g. "ora-api").
	ServiceAudience string
}

func (c MiddlewareConfig) cookie() string {
	if c.CookieName == "" {
		return CookieName
	}
	return c.CookieName
}

// RequireUser wraps a handler with user JWT auth and optional role check.
// On success it sets X-User-Username and X-User-Role request headers.
func (c MiddlewareConfig) RequireUser(requiredRole string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := BearerOrCookie(r, c.cookie())
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := ParseUserJWT(token, c.Secret)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if requiredRole != "" && !HasPermission(claims.Role, requiredRole) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		r.Header.Set("X-User-Username", claims.Username)
		r.Header.Set("X-User-Role", claims.Role)
		next(w, r)
	}
}

// RequireUserOrService accepts a user JWT or a short-lived service JWT with the
// configured audience. Service callers map to role=admin and set X-Service-*
// headers. requiredServiceScope applies to service JWTs only.
func (c MiddlewareConfig) RequireUserOrService(requiredRole, requiredServiceScope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := BearerOrCookie(r, c.cookie())
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if len(c.ServiceSecret) > 0 && c.ServiceAudience != "" {
			if sc, err := ValidateServiceJWT(token, c.ServiceSecret, c.ServiceAudience); err == nil {
				if requiredServiceScope != "" {
					if err := RequireScope(sc, requiredServiceScope); err != nil {
						http.Error(w, "missing scope", http.StatusForbidden)
						return
					}
				}
				r.Header.Set("X-User-Username", "service:"+sc.Issuer)
				r.Header.Set("X-User-Role", "admin")
				r.Header.Set("X-Service-Issuer", sc.Issuer)
				r.Header.Set("X-Service-Scope", sc.Scope)
				if org := strings.TrimSpace(sc.OrgID); org != "" {
					r.Header.Set("X-Organization-ID", org)
				}
				next(w, r)
				return
			}
		}
		claims, err := ParseUserJWT(token, c.Secret)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if requiredRole != "" && !HasPermission(claims.Role, requiredRole) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		r.Header.Set("X-User-Username", claims.Username)
		r.Header.Set("X-User-Role", claims.Role)
		next(w, r)
	}
}
