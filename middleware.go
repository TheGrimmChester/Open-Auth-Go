package openauth

import (
	"errors"
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
			writeProjectACLError(w, err)
			return
		}
		next(w, r)
	}
}

// writeProjectACLError maps ACL failures to HTTP status (400 over-cap, else 403).
func writeProjectACLError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrTooManyProjectIDs) {
		http.Error(w, "too many project ids", http.StatusBadRequest)
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}

// IsPersonalAccount reports whether the token represents an immutable personal
// account (OAM account_type=personal). Legacy tokens without account_type fall
// back to empty org_id + non-admin, preserving pre-OAM behaviour.
//
// Role admin is never personal-scoped: the platform operator (including the
// bootstrap seed, which is account_type=personal with an empty org) must keep
// cross-organization reach. Private individuals remain isolated.
func IsPersonalAccount(claims *UserClaims) bool {
	if claims == nil {
		return false
	}
	if HasPermission(claims.Role, "admin") {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(claims.AccountType)) {
	case AccountTypePersonal:
		return true
	case AccountTypeOrganization:
		return false
	default:
		return strings.TrimSpace(claims.OrgID) == ""
	}
}

// IsOrganizationAccount reports whether the token is bound to one organization.
func IsOrganizationAccount(claims *UserClaims) bool {
	if claims == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(claims.AccountType)) {
	case AccountTypeOrganization:
		return true
	case AccountTypePersonal:
		return false
	default:
		return strings.TrimSpace(claims.OrgID) != ""
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

	if IsPersonalAccount(claims) {
		username := strings.TrimSpace(claims.Username)
		if username == "" {
			return ErrTenantMismatch
		}
		// Personal (non-admin) accounts never operate in an organization context.
		reqOrg := strings.TrimSpace(r.Header.Get("X-Organization-ID"))
		if reqOrg != "" && !strings.EqualFold(reqOrg, "all") {
			return ErrTenantMismatch
		}
		r.Header.Set(HeaderTenantUserID, username)
		r.Header.Set("X-Organization-ID", "")
	} else if org := strings.TrimSpace(claims.OrgID); org != "" {
		reqOrg := strings.TrimSpace(r.Header.Get("X-Organization-ID"))
		if reqOrg != "" && !strings.EqualFold(reqOrg, "all") && reqOrg != org {
			return ErrTenantMismatch
		}
		r.Header.Set("X-Organization-ID", org)
	} else if !HasPermission(claims.Role, "admin") {
		// Legacy: no organization claim and not admin — private individual.
		username := strings.TrimSpace(claims.Username)
		if username == "" {
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
			writeProjectACLError(w, err)
			return
		}
		next(w, r)
	}
}
