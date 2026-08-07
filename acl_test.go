package openauth

import (
	"net/http"
	"net/http/httptest"
	"strconv"
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

	// Single-project allowlist pins omitted project header to the member;
	// omitted org header pins from JWT org_id (never invents default-org).
	omit := httptest.NewRequest(http.MethodGet, "/api/tenancy/organizations", nil)
	if err := EnforceProjectACL(omit, claims); err != nil {
		t.Fatalf("single allowlist pin: %v", err)
	}
	if omit.Header.Get("X-Organization-ID") != "default-org" {
		t.Fatalf("pinned org=%q", omit.Header.Get("X-Organization-ID"))
	}
	if omit.Header.Get("X-Project-ID") != "allowed-only" {
		t.Fatalf("pinned project=%q", omit.Header.Get("X-Project-ID"))
	}

	// Multi-project allowlist + omitted headers → JWT org + default-project → deny.
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

func TestEnforceProjectACLMissingOrgUsesJWTOrDeny(t *testing.T) {
	bound := &UserClaims{
		Username:   "dev",
		Role:       "viewer",
		OrgID:      "acme",
		ProjectIDs: []string{"alpha"},
	}
	// Missing / "all" org → JWT org_id.
	for _, orgHdr := range []string{"", "all"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if orgHdr != "" {
			r.Header.Set("X-Organization-ID", orgHdr)
		}
		r.Header.Set("X-Project-ID", "alpha")
		if err := EnforceProjectACL(r, bound); err != nil {
			t.Fatalf("orgHdr=%q: %v", orgHdr, err)
		}
		if r.Header.Get("X-Organization-ID") != "acme" {
			t.Fatalf("orgHdr=%q pinned org=%q", orgHdr, r.Header.Get("X-Organization-ID"))
		}
	}

	// Restricted token with empty org_id and no header → deny (never default-org).
	unboundOrg := &UserClaims{
		Username:   "dev",
		Role:       "viewer",
		ProjectIDs: []string{"alpha"},
	}
	deny := httptest.NewRequest(http.MethodGet, "/", nil)
	deny.Header.Set("X-Project-ID", "alpha")
	if err := EnforceProjectACL(deny, unboundOrg); err != ErrProjectDenied {
		t.Fatalf("empty JWT org want deny, got %v", err)
	}
	if deny.Header.Get("X-Organization-ID") == DefaultOrganizationID {
		t.Fatal("must not invent DefaultOrganizationID")
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

func TestEnforceProjectACLMultiIDs(t *testing.T) {
	claims := &UserClaims{
		Username:   "dev",
		Role:       "viewer",
		OrgID:      "default-org",
		ProjectIDs: []string{"alpha", "beta"},
	}

	ok := httptest.NewRequest(http.MethodGet, "/api/list", nil)
	ok.Header.Set("X-Organization-ID", "default-org")
	ok.Header.Set(HeaderProjectIDs, "alpha,beta")
	if err := EnforceProjectACL(ok, claims); err != nil {
		t.Fatalf("allowlisted multi: %v", err)
	}
	// Multi list must not pin/overwrite single X-Project-ID when omitted.
	if ok.Header.Get("X-Project-ID") != "" {
		t.Fatalf("unexpected pin of X-Project-ID=%q", ok.Header.Get("X-Project-ID"))
	}

	deny := httptest.NewRequest(http.MethodGet, "/api/list", nil)
	deny.Header.Set("X-Organization-ID", "default-org")
	deny.Header.Set(HeaderProjectIDs, "alpha,gamma")
	if err := EnforceProjectACL(deny, claims); err != ErrProjectDenied {
		t.Fatalf("non-member in multi want deny, got %v", err)
	}

	// Query fallback.
	q := httptest.NewRequest(http.MethodGet, "/api/list?project_ids=alpha,beta", nil)
	q.Header.Set("X-Organization-ID", "default-org")
	if err := EnforceProjectACL(q, claims); err != nil {
		t.Fatalf("query multi: %v", err)
	}

	// Concrete single still checked when multi is set.
	badSingle := httptest.NewRequest(http.MethodGet, "/api/list", nil)
	badSingle.Header.Set("X-Organization-ID", "default-org")
	badSingle.Header.Set(HeaderProjectIDs, "alpha")
	badSingle.Header.Set("X-Project-ID", "gamma")
	if err := EnforceProjectACL(badSingle, claims); err != ErrProjectDenied {
		t.Fatalf("bad single with multi want deny, got %v", err)
	}
}

func TestEnforceProjectACLTooManyIDs(t *testing.T) {
	ids := make([]string, MaxProjectIDs+1)
	for i := range ids {
		ids[i] = "proj-" + strconv.Itoa(i)
	}
	raw := strings.Join(ids, ",")

	admin := &UserClaims{Username: "admin", Role: "admin"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderProjectIDs, raw)
	if err := EnforceProjectACL(r, admin); err != ErrTooManyProjectIDs {
		t.Fatalf("admin over-cap want ErrTooManyProjectIDs, got %v", err)
	}

	viewer := &UserClaims{
		Username:   "dev",
		Role:       "viewer",
		OrgID:      "default-org",
		ProjectIDs: []string{"alpha"},
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set(HeaderProjectIDs, raw)
	if err := EnforceProjectACL(r2, viewer); err != ErrTooManyProjectIDs {
		t.Fatalf("viewer over-cap want ErrTooManyProjectIDs, got %v", err)
	}

	// Exactly MaxProjectIDs is allowed (admin unrestricted after cap check).
	exact := strings.Join(ids[:MaxProjectIDs], ",")
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r3.Header.Set(HeaderProjectIDs, exact)
	if err := EnforceProjectACL(r3, admin); err != nil {
		t.Fatalf("exact cap should pass for admin: %v", err)
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
	if got.Impersonator != "" {
		t.Fatalf("unexpected impersonator=%q", got.Impersonator)
	}
}

func TestMintUserJWTWithImpersonatorRoundTrip(t *testing.T) {
	secret := []byte(strings.Repeat("i", 32))
	tok, err := MintUserJWTWithImpersonator(
		secret, "target", "editor", "oam-api",
		AccountTypePersonal, "", nil, "admin", 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseUserJWT(tok, secret)
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "target" || got.AccountType != AccountTypePersonal || got.OrgID != "" {
		t.Fatalf("target claims=%+v", got)
	}
	if got.Impersonator != "admin" {
		t.Fatalf("impersonator=%q", got.Impersonator)
	}

	// Impersonated personal target still clears org and sets X-Tenant-User-ID.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Organization-ID", "spoof-org")
	r.Header.Set(HeaderTenantUserID, "attacker")
	if err := ApplyUserTenantHeaders(r, got); err != ErrTenantMismatch {
		t.Fatalf("want ErrTenantMismatch for spoof org, got %v", err)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set(HeaderTenantUserID, "attacker")
	if err := ApplyUserTenantHeaders(r2, got); err != nil {
		t.Fatal(err)
	}
	if r2.Header.Get(HeaderTenantUserID) != "target" {
		t.Fatalf("tenant user=%q", r2.Header.Get(HeaderTenantUserID))
	}
	if r2.Header.Get("X-Organization-ID") != "" {
		t.Fatalf("org should stay clear, got %q", r2.Header.Get("X-Organization-ID"))
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
