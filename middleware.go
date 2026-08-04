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
		if err := ApplyUserTenantHeaders(r, claims); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := EnforceProjectACL(r, claims); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// ApplyUserTenantHeaders enforces JWT-bound org/project against request headers.
// When claims bind a dimension, a mismatched client header is rejected; matching
// or missing headers are overwritten from the claims so handlers never trust a
// wider client scope than the token allows. Project allowlists (project_ids) are
// enforced separately via EnforceProjectACL.
func ApplyUserTenantHeaders(r *http.Request, claims *UserClaims) error {
	if r == nil || claims == nil {
		return nil
	}
	if org := strings.TrimSpace(claims.OrgID); org != "" {
		reqOrg := strings.TrimSpace(r.Header.Get("X-Organization-ID"))
		if reqOrg != "" && !strings.EqualFold(reqOrg, "all") && reqOrg != org {
			return ErrTenantMismatch
		}
		r.Header.Set("X-Organization-ID", org)
	}
	if proj := strings.TrimSpace(claims.ProjectID); proj != "" {
		reqProj := strings.TrimSpace(r.Header.Get("X-Project-ID"))
		if reqProj != "" && !strings.EqualFold(reqProj, "all") && reqProj != proj {
			return ErrTenantMismatch
		}
		r.Header.Set("X-Project-ID", proj)
	}
	return nil
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
		if err := ApplyUserTenantHeaders(r, claims); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := EnforceProjectACL(r, claims); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
