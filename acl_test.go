package openauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCanAccessProject(t *testing.T) {
	admin := &UserClaims{Username: "admin", Role: "admin"}
	if !CanAccessProject(admin, "default-org", "secret-proj") {
		t.Fatal("admin should access any project")
	}

	unbound := &UserClaims{Username: "u", Role: "viewer"}
	if !CanAccessProject(unbound, "acme", "prod") {
		t.Fatal("unbound viewer should allow (legacy)")
	}

	allow := &UserClaims{
		Username:   "dev",
		Role:       "viewer",
		OrgID:      "acme",
		ProjectIDs: []string{"alpha", "beta"},
	}
	if !CanAccessProject(allow, "acme", "alpha") {
		t.Fatal("allowlisted project should pass")
	}
	if CanAccessProject(allow, "acme", "gamma") {
		t.Fatal("non-member project should deny")
	}
	if CanAccessProject(allow, "other", "alpha") {
		t.Fatal("wrong org should deny")
	}

	bound := &UserClaims{Username: "b", Role: "editor", OrgID: "acme", ProjectID: "prod"}
	if !CanAccessProject(bound, "acme", "prod") {
		t.Fatal("singular bind should pass")
	}
	if CanAccessProject(bound, "acme", "staging") {
		t.Fatal("singular bind mismatch should deny")
	}

	if CanAccessProject(nil, "acme", "prod") {
		t.Fatal("nil claims deny")
	}
}

func TestEnforceProjectACLDeny(t *testing.T) {
	claims := &UserClaims{
		Username:   "dev",
		Role:       "viewer",
		OrgID:      "default-org",
		ProjectIDs: []string{"allowed-only"},
	}
	r := httptest.NewRequest(http.MethodGet, "/api/key-transactions", nil)
	r.Header.Set("X-Organization-ID", "default-org")
	r.Header.Set("X-Project-ID", "other-project")
	if err := EnforceProjectACL(r, claims); err != ErrProjectDenied {
		t.Fatalf("want ErrProjectDenied, got %v", err)
	}

	ok := httptest.NewRequest(http.MethodGet, "/api/key-transactions", nil)
	ok.Header.Set("X-Organization-ID", "default-org")
	ok.Header.Set("X-Project-ID", "allowed-only")
	if err := EnforceProjectACL(ok, claims); err != nil {
		t.Fatal(err)
	}

	// Single-project allowlist pins omitted project header to the member.
	omit := httptest.NewRequest(http.MethodGet, "/api/tenancy/organizations", nil)
	if err := EnforceProjectACL(omit, claims); err != nil {
		t.Fatalf("single allowlist pin: %v", err)
	}
	if omit.Header.Get("X-Project-ID") != "allowed-only" {
		t.Fatalf("pinned project=%q", omit.Header.Get("X-Project-ID"))
	}

	// Multi-project allowlist + omitted headers → default-project → deny.
	multi := &UserClaims{
		Username:   "dev",
		Role:       "viewer",
		OrgID:      "default-org",
		ProjectIDs: []string{"alpha", "beta"},
	}
	omitMulti := httptest.NewRequest(http.MethodGet, "/api/tenancy/organizations", nil)
	if err := EnforceProjectACL(omitMulti, multi); err != ErrProjectDenied {
		t.Fatalf("multi omit want deny, got %v", err)
	}
}

func TestEnforceProjectACLAdminUnrestricted(t *testing.T) {
	admin := &UserClaims{Username: "admin", Role: "admin"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Organization-ID", "default-org")
	r.Header.Set("X-Project-ID", "default-project")
	if err := EnforceProjectACL(r, admin); err != nil {
		t.Fatal(err)
	}
	if HasProjectRestriction(admin) {
		t.Fatal("admin must not be project-restricted")
	}
}

func TestMintUserJWTWithACLRoundTrip(t *testing.T) {
	secret := []byte(strings.Repeat("g", 32))
	tok, err := MintUserJWTWithACL(secret, "dev", "viewer", "opa-hub", "acme", []string{"p1", "p1", " p2 "}, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseUserJWT(tok, secret)
	if err != nil {
		t.Fatal(err)
	}
	if got.OrgID != "acme" || len(got.ProjectIDs) != 2 || got.ProjectIDs[0] != "p1" || got.ProjectIDs[1] != "p2" {
		t.Fatalf("claims=%+v", got)
	}
}

func TestLocalIssuerMembership(t *testing.T) {
	secret := []byte(strings.Repeat("h", 32))
	li := NewLocalIssuer(secret, "opa-hub", "admin", "admin")

	// Lab admin login remains unbound + admin role.
	tok, _, claims, err := li.Login("admin", "admin")
	if err != nil || claims.Role != "admin" {
		t.Fatalf("admin login: %+v err=%v", claims, err)
	}
	parsed, err := li.Parse(tok)
	if err != nil || HasProjectRestriction(parsed) {
		t.Fatalf("admin token restricted=%v err=%v", HasProjectRestriction(parsed), err)
	}

	if err := li.RegisterWithMembership("devuser", "password1", "viewer", "default-org", []string{"alpha"}); err != nil {
		t.Fatal(err)
	}
	tok2, _, claims2, err := li.Login("devuser", "password1")
	if err != nil {
		t.Fatal(err)
	}
	if claims2.OrgID != "default-org" || len(claims2.ProjectIDs) != 1 || claims2.ProjectIDs[0] != "alpha" {
		t.Fatalf("membership claims=%+v", claims2)
	}
	got, err := li.Parse(tok2)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Organization-ID", "default-org")
	r.Header.Set("X-Project-ID", "beta")
	if err := EnforceProjectACL(r, got); err != ErrProjectDenied {
		t.Fatalf("want deny for beta, got %v", err)
	}

	if err := li.SetMembership("devuser", "default-org", []string{"beta"}); err != nil {
		t.Fatal(err)
	}
	_, _, claims3, err := li.Login("devuser", "password1")
	if err != nil || claims3.ProjectIDs[0] != "beta" {
		t.Fatalf("after SetMembership: %+v err=%v", claims3, err)
	}
}
