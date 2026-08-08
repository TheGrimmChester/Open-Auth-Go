package openauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestSecurityTenantContract locks the cross-product tenant-scope contract in one
// table: RequireUser authn, ApplyUserTenantHeaders pinning/mismatch, EnforceProjectACL
// via middleware (including X-Project-ID=all and X-Project-IDs over-ACL), service JWT
// subject rules, and unbound-admin directory pattern (empty org, never invent default-org).
func TestSecurityTenantContract(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	cfg := MiddlewareConfig{Secret: secret}

	mintOrg := func(t *testing.T, user, role, org string, projectIDs []string) string {
		t.Helper()
		tok, err := MintUserJWTWithAccount(secret, user, role, "opa-hub", AccountTypeOrganization, org, projectIDs, 0)
		if err != nil {
			t.Fatalf("mint org: %v", err)
		}
		return tok
	}
	mintPersonal := func(t *testing.T, user, role string) string {
		t.Helper()
		tok, err := MintUserJWTWithAccount(secret, user, role, "opa-hub", AccountTypePersonal, "", nil, 0)
		if err != nil {
			t.Fatalf("mint personal: %v", err)
		}
		return tok
	}
	mintACL := func(t *testing.T, user, role, org string, projectIDs []string) string {
		t.Helper()
		tok, err := MintUserJWTWithACL(secret, user, role, "opa-hub", org, projectIDs, 0)
		if err != nil {
			t.Fatalf("mint acl: %v", err)
		}
		return tok
	}
	mintAdmin := func(t *testing.T) string {
		t.Helper()
		tok, err := MintUserJWT(secret, "root", "admin", "opa-hub", 0)
		if err != nil {
			t.Fatalf("mint admin: %v", err)
		}
		return tok
	}

	okHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Org", r.Header.Get("X-Organization-ID"))
		w.Header().Set("X-Seen-Project", r.Header.Get("X-Project-ID"))
		w.WriteHeader(http.StatusNoContent)
	}

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "1_require_user_no_jwt_401",
			run: func(t *testing.T) {
				h := cfg.RequireUser("viewer", okHandler)
				rr := httptest.NewRecorder()
				h(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
				if rr.Code != http.StatusUnauthorized {
					t.Fatalf("code=%d want 401", rr.Code)
				}
			},
		},
		{
			name: "2_org_member_no_org_header_pins_jwt_org_never_default_org",
			run: func(t *testing.T) {
				tok, err := MintUserJWTWithAccount(secret, "bob", "editor", "opa-hub", AccountTypeOrganization, "acme", nil, 0)
				if err != nil {
					t.Fatal(err)
				}
				claims, err := ParseUserJWT(tok, secret)
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				if err := ApplyUserTenantHeaders(r, claims); err != nil {
					t.Fatal(err)
				}
				if got := r.Header.Get("X-Organization-ID"); got != "acme" {
					t.Fatalf("org=%q want acme (pinned from JWT)", got)
				}
				if got := r.Header.Get("X-Organization-ID"); got == DefaultOrganizationID {
					t.Fatal("must never invent default-org")
				}
			},
		},
		{
			name: "3a_wrong_org_err_tenant_mismatch",
			run: func(t *testing.T) {
				tok := mintOrg(t, "bob", "editor", "acme", nil)
				claims, err := ParseUserJWT(tok, secret)
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-Organization-ID", "other")
				if err := ApplyUserTenantHeaders(r, claims); err != ErrTenantMismatch {
					t.Fatalf("want ErrTenantMismatch, got %v", err)
				}
			},
		},
		{
			name: "3b_personal_plus_org_err_tenant_mismatch",
			run: func(t *testing.T) {
				tok := mintPersonal(t, "alice", "editor")
				claims, err := ParseUserJWT(tok, secret)
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-Organization-ID", "acme")
				if err := ApplyUserTenantHeaders(r, claims); err != ErrTenantMismatch {
					t.Fatalf("want ErrTenantMismatch, got %v", err)
				}
			},
		},
		{
			name: "3c_org_member_foreign_via_require_user_403",
			run: func(t *testing.T) {
				tok := mintOrg(t, "bob", "viewer", "acme", nil)
				h := cfg.RequireUser("viewer", okHandler)
				req := httptest.NewRequest(http.MethodGet, "/x", nil)
				req.Header.Set("Authorization", "Bearer "+tok)
				req.Header.Set("X-Organization-ID", "other-org")
				rr := httptest.NewRecorder()
				h(rr, req)
				if rr.Code != http.StatusForbidden {
					t.Fatalf("code=%d want 403", rr.Code)
				}
			},
		},
		{
			name: "4a_require_user_project_all_single_allowlist_pins_not_widening",
			run: func(t *testing.T) {
				tok := mintACL(t, "dev", "viewer", "acme", []string{"only-proj"})
				h := cfg.RequireUser("viewer", okHandler)
				req := httptest.NewRequest(http.MethodGet, "/x", nil)
				req.Header.Set("Authorization", "Bearer "+tok)
				req.Header.Set("X-Organization-ID", "acme")
				req.Header.Set("X-Project-ID", "all")
				rr := httptest.NewRecorder()
				h(rr, req)
				if rr.Code != http.StatusNoContent {
					t.Fatalf("code=%d want 204 body=%s", rr.Code, rr.Body.String())
				}
				if got := rr.Header().Get("X-Seen-Project"); got != "only-proj" {
					t.Fatalf("project=%q want only-proj (all collapsed/pinned, not widened)", got)
				}
				if got := rr.Header().Get("X-Seen-Org"); got != "acme" {
					t.Fatalf("org=%q want acme", got)
				}
			},
		},
		{
			name: "4b_require_user_project_all_multi_allowlist_deny_via_enforce",
			run: func(t *testing.T) {
				tok := mintACL(t, "dev", "viewer", "acme", []string{"alpha", "beta"})
				h := cfg.RequireUser("viewer", okHandler)
				req := httptest.NewRequest(http.MethodGet, "/x", nil)
				req.Header.Set("Authorization", "Bearer "+tok)
				req.Header.Set("X-Organization-ID", "acme")
				req.Header.Set("X-Project-ID", "all")
				rr := httptest.NewRecorder()
				h(rr, req)
				// "all" → default-project → not in allowlist → ErrProjectDenied → 403
				if rr.Code != http.StatusForbidden {
					t.Fatalf("code=%d want 403 (all must not widen multi ACL)", rr.Code)
				}
			},
		},
		{
			name: "5_project_ids_over_acl_403_through_require_user",
			run: func(t *testing.T) {
				tok := mintACL(t, "dev", "viewer", "acme", []string{"alpha", "beta"})
				h := cfg.RequireUser("viewer", okHandler)
				req := httptest.NewRequest(http.MethodGet, "/x", nil)
				req.Header.Set("Authorization", "Bearer "+tok)
				req.Header.Set("X-Organization-ID", "acme")
				req.Header.Set(HeaderProjectIDs, "alpha,gamma")
				rr := httptest.NewRecorder()
				h(rr, req)
				if rr.Code != http.StatusForbidden {
					t.Fatalf("code=%d want 403", rr.Code)
				}
				// Direct EnforceProjectACL also returns ErrProjectDenied.
				claims, err := ParseUserJWT(tok, secret)
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest(http.MethodGet, "/x", nil)
				r.Header.Set("X-Organization-ID", "acme")
				r.Header.Set(HeaderProjectIDs, "alpha,gamma")
				if err := EnforceProjectACL(r, claims); err != ErrProjectDenied {
					t.Fatalf("want ErrProjectDenied, got %v", err)
				}
			},
		},
		{
			name: "6_validate_service_jwt_rejects_user_subject",
			run: func(t *testing.T) {
				userTok := mintAdmin(t)
				if _, err := ValidateServiceJWT(userTok, secret, "opa-hub"); err == nil {
					t.Fatal("expected reject for user JWT subject")
				}
				// Explicit subject=user service-shaped token.
				now := time.Now().UTC()
				claims := ServiceClaims{
					Scope: "scm:clone",
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    "opm-api",
						Audience:  jwt.ClaimStrings{"opa-hub"},
						Subject:   "user",
						IssuedAt:  jwt.NewNumericDate(now),
						ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
					},
				}
				tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ValidateServiceJWT(tok, secret, "opa-hub"); err == nil {
					t.Fatal("expected reject for subject=user")
				}
			},
		},
		{
			name: "7a_unbound_admin_no_org_header_leaves_org_empty_never_default_org",
			run: func(t *testing.T) {
				tok := mintAdmin(t)
				claims, err := ParseUserJWT(tok, secret)
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				if err := ApplyUserTenantHeaders(r, claims); err != nil {
					t.Fatal(err)
				}
				if got := r.Header.Get("X-Organization-ID"); got != "" {
					t.Fatalf("org=%q want empty (directory OK; never invent default-org)", got)
				}
				if got := r.Header.Get(HeaderTenantUserID); got != "" {
					t.Fatalf("admin must not be personal-scoped: %q", got)
				}
			},
		},
		{
			name: "7b_unbound_admin_concrete_org_header_allowed",
			run: func(t *testing.T) {
				tok := mintAdmin(t)
				claims, err := ParseUserJWT(tok, secret)
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-Organization-ID", "acme")
				if err := ApplyUserTenantHeaders(r, claims); err != nil {
					t.Fatal(err)
				}
				if got := r.Header.Get("X-Organization-ID"); got != "acme" {
					t.Fatalf("org=%q want acme", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}
