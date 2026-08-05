package openauth

import (
	"net/http"
	"strings"
)

// HeaderTenantUserID names the personal-tenant owner for a request made by a
// user who belongs to no organization.
//
// The value must stay identical to opentenant.HeaderTenantUserID. It is declared
// here rather than imported for the same reason X-Organization-ID and
// X-Project-ID are written as literals in this package: the auth library does not
// depend on the tenant library, and adding that edge would force the two to be
// version-bumped in lockstep across every product.
const HeaderTenantUserID = "X-Tenant-User-ID"

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
	// Strip any inbound personal-owner header before deciding anything. This
	// header names whose private rows the request may read, so a client that
	// could set it would be choosing its own answer. Deleting first — rather
	// than only overwriting in the personal branch — is what makes it
	// unspoofable for organization members and admins too.
	r.Header.Del(HeaderTenantUserID)

	if org := strings.TrimSpace(claims.OrgID); org != "" {
		reqOrg := strings.TrimSpace(r.Header.Get("X-Organization-ID"))
		if reqOrg != "" && !strings.EqualFold(reqOrg, "all") && reqOrg != org {
			return ErrTenantMismatch
		}
		r.Header.Set("X-Organization-ID", org)
	} else if !HasPermission(claims.Role, "admin") {
		// No organization claim, and not an admin: a private individual. Belonging
		// to an organization is not a requirement in this product, so this is a
		// permanent, first-class scope — not a user awaiting provisioning.
		//
		// Two things have to happen together. The request is pinned to a personal
		// scope owned by this user, and the organization it asked for is dropped:
		// without the second, an unattached user kept whatever X-Organization-ID
		// it sent and was served that organization's data, because the block above
		// only pins the header when a claim binds it.
		username := strings.TrimSpace(claims.Username)
		if username == "" {
			// An unidentifiable non-admin with no organization cannot be given a
			// personal scope, and must not fall through to an unbound one.
			return ErrTenantMismatch
		}
		r.Header.Set(HeaderTenantUserID, username)
		r.Header.Set("X-Organization-ID", "")
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
				// This branch does not go through ApplyUserTenantHeaders, so it has
				// to strip the personal-owner header itself. A peer service call is
				// never personal-scoped, and leaving an inbound value here would
				// let a caller name whose private rows to read.
				r.Header.Del(HeaderTenantUserID)
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
