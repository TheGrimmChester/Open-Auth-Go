package openauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoadJWTSecret(t *testing.T) {
	stable := strings.Repeat("a", 32)
	sec, eph, err := LoadJWTSecret(stable, true)
	if err != nil || eph || string(sec) != stable {
		t.Fatalf("stable: eph=%v err=%v", eph, err)
	}
	if _, _, err := LoadJWTSecret(JWTSecretPlaceholder, true); err == nil {
		t.Fatal("expected error when auth required + placeholder")
	}
	sec, eph, err = LoadJWTSecret("", false)
	if err != nil || !eph || len(sec) != 32 {
		t.Fatalf("ephemeral: eph=%v len=%d err=%v", eph, len(sec), err)
	}
}

func TestHasPermission(t *testing.T) {
	if !HasPermission("admin", "viewer") || !HasPermission("editor", "editor") {
		t.Fatal("expected allow")
	}
	if HasPermission("viewer", "admin") {
		t.Fatal("expected deny")
	}
	if !HasPermission("viewer", "") {
		t.Fatal("empty required always ok")
	}
}

func TestBearerOrCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer abc.def")
	if got := BearerOrCookie(r, ""); got != "abc.def" {
		t.Fatalf("bearer=%q", got)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(&http.Cookie{Name: CookieName, Value: "cookietok"})
	if got := BearerOrCookie(r2, ""); got != "cookietok" {
		t.Fatalf("cookie=%q", got)
	}
}

func TestApplyUserTenantHeaders(t *testing.T) {
	claims := &UserClaims{Username: "a", Role: "viewer", OrgID: "acme", ProjectID: "prod"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Organization-ID", "other")
	if err := ApplyUserTenantHeaders(r, claims); err != ErrTenantMismatch {
		t.Fatalf("want mismatch, got %v", err)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-Organization-ID", "all")
	if err := ApplyUserTenantHeaders(r2, claims); err != nil {
		t.Fatal(err)
	}
	if r2.Header.Get("X-Organization-ID") != "acme" || r2.Header.Get("X-Project-ID") != "prod" {
		t.Fatalf("headers=%v", r2.Header)
	}
}

func TestRequireUserMiddleware(t *testing.T) {
	secret := []byte(strings.Repeat("b", 32))
	tok, err := MintUserJWT(secret, "alice", "editor", "ora-api", 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := MiddlewareConfig{Secret: secret}
	var sawUser, sawRole string
	h := cfg.RequireUser("viewer", func(w http.ResponseWriter, r *http.Request) {
		sawUser = r.Header.Get("X-User-Username")
		sawRole = r.Header.Get("X-User-Role")
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusNoContent || sawUser != "alice" || sawRole != "editor" {
		t.Fatalf("code=%d user=%s role=%s", rr.Code, sawUser, sawRole)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr2 := httptest.NewRecorder()
	h(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr2.Code)
	}
}

func TestRequireUserOrService(t *testing.T) {
	userSecret := []byte(strings.Repeat("c", 32))
	svcSecret := []byte(strings.Repeat("d", 32))
	svcTok, err := MintServiceJWT(svcSecret, "osa-api", "ora-api", "connectors:read")
	if err != nil {
		t.Fatal(err)
	}
	cfg := MiddlewareConfig{
		Secret:          userSecret,
		ServiceSecret:   svcSecret,
		ServiceAudience: "ora-api",
	}
	var issuer string
	h := cfg.RequireUserOrService("viewer", "connectors:read", func(w http.ResponseWriter, r *http.Request) {
		issuer = r.Header.Get("X-Service-Issuer")
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+svcTok)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusNoContent || issuer != "osa-api" {
		t.Fatalf("code=%d issuer=%s", rr.Code, issuer)
	}
}

func TestLocalAuthHandlersStandalone(t *testing.T) {
	secret := []byte(strings.Repeat("e", 32))
	li := NewLocalIssuer(secret, "osa-api", "admin", "admin")
	h := &LocalAuthHandlers{
		Mode:         ModeStandalone,
		Local:        li,
		Secret:       li.Secret,
		IssuerID:     "osa-api",
		AuthRequired: false,
	}
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{"username":"admin","password":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", rr.Code, rr.Body.String())
	}
	var login map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	tok, _ := login["token"].(string)
	if tok == "" {
		t.Fatal("missing token")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK || !strings.Contains(rr2.Body.String(), `"authenticated":true`) {
		t.Fatalf("status=%d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestLocalAuthHandlersCodeployedLogin(t *testing.T) {
	h := &LocalAuthHandlers{Mode: ModeCodeployed, IssuerID: "opl-api"}
	mux := http.NewServeMux()
	h.Register(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"a","password":"b"}`))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "oam-api") && !strings.Contains(rr.Body.String(), "OAM") {
		t.Fatalf("503 body should point to OAM, got %s", rr.Body.String())
	}
}

func TestBootstrapStandalone(t *testing.T) {
	g, err := Bootstrap(BootstrapConfig{
		IssuerID:     "ora-api",
		JWTSecretEnv: strings.Repeat("f", 32),
		AuthModeEnv:  "standalone",
		SeedUsername: "admin",
		SeedPassword: "admin",
	})
	if err != nil || g == nil || !g.IsStandalone() || g.Local == nil {
		t.Fatalf("gate=%+v err=%v", g, err)
	}
	tok, _, _, err := g.Local.Login("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.ParseUser(tok); err != nil {
		t.Fatal(err)
	}
}

// ---- Personal tenant scope -------------------------------------------------
//
// A user who belongs to no organization is a private individual, not a member
// awaiting provisioning. These tests pin the isolation that makes that state
// safe: the request is pinned to that person, and cannot be pointed at an
// organization.

func TestUnattachedNonAdminIsPinnedToItsOwnScope(t *testing.T) {
	claims := &UserClaims{Username: "alice", Role: "editor"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := ApplyUserTenantHeaders(r, claims); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get(HeaderTenantUserID); got != "alice" {
		t.Fatalf("personal owner = %q, want alice", got)
	}
}

// The regression that motivated this: an unattached editor sent
// X-Organization-ID: acme and was served acme's data, because the org header was
// only pinned when a claim bound it. Personal accounts now reject foreign org
// headers with ErrTenantMismatch instead of silently clearing them.
func TestUnattachedNonAdminCannotAssertAnOrganization(t *testing.T) {
	claims := &UserClaims{Username: "alice", Role: "editor"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Organization-ID", "acme")
	if err := ApplyUserTenantHeaders(r, claims); err != ErrTenantMismatch {
		t.Fatalf("want ErrTenantMismatch, got %v", err)
	}
}

func TestPersonalAccountTypeRejectsOrganizationHeader(t *testing.T) {
	claims := &UserClaims{Username: "alice", Role: "editor", AccountType: AccountTypePersonal}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Organization-ID", "acme")
	if err := ApplyUserTenantHeaders(r, claims); err != ErrTenantMismatch {
		t.Fatalf("personal non-admin must not select an org: %v", err)
	}
}

// Bootstrap seeds the platform operator as account_type=personal with an empty
// org. That must not shrink role=admin into a private individual — admins keep
// cross-organization reach (and may select any org header).
func TestPersonalAccountTypeAdminKeepsCrossOrganizationReach(t *testing.T) {
	claims := &UserClaims{Username: "root", Role: "admin", AccountType: AccountTypePersonal}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Organization-ID", "acme")
	if err := ApplyUserTenantHeaders(r, claims); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("X-Organization-ID"); got != "acme" {
		t.Fatalf("admin lost its selected organization: %q", got)
	}
	if got := r.Header.Get(HeaderTenantUserID); got != "" {
		t.Fatalf("admin must not be personal-scoped: %q", got)
	}
}

func TestPersonalAccountTypeAdminIsNotPinned(t *testing.T) {
	claims := &UserClaims{Username: "root", Role: "admin", AccountType: AccountTypePersonal}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := ApplyUserTenantHeaders(r, claims); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get(HeaderTenantUserID); got != "" {
		t.Fatalf("admin must not be personal-scoped: %q", got)
	}
}

func TestOrganizationAccountTypeEnforcesJWTOrg(t *testing.T) {
	claims := &UserClaims{Username: "bob", Role: "editor", AccountType: AccountTypeOrganization, OrgID: "acme"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Organization-ID", "other")
	if err := ApplyUserTenantHeaders(r, claims); err != ErrTenantMismatch {
		t.Fatalf("want mismatch, got %v", err)
	}
}

// Two private individuals must not be able to reach each other's rows by naming
// the other in the header.
func TestPersonalOwnerHeaderCannotBeSpoofed(t *testing.T) {
	claims := &UserClaims{Username: "nomad", Role: "editor"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderTenantUserID, "alice")
	if err := ApplyUserTenantHeaders(r, claims); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get(HeaderTenantUserID); got != "nomad" {
		t.Fatalf("spoofed owner survived: %q", got)
	}
}

// An organization member is not personal-scoped, and an inbound header must not
// make them appear to be.
func TestOrganizationMemberGetsNoPersonalOwner(t *testing.T) {
	claims := &UserClaims{Username: "bob", Role: "editor", OrgID: "acme"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderTenantUserID, "alice")
	if err := ApplyUserTenantHeaders(r, claims); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get(HeaderTenantUserID); got != "" {
		t.Fatalf("organization member carried a personal owner: %q", got)
	}
	if got := r.Header.Get("X-Organization-ID"); got != "acme" {
		t.Fatalf("organization pin = %q", got)
	}
}

// An unbound admin keeps its cross-organization reach — that is the documented
// lab / operator role, and is not what this change restricts.
func TestUnboundAdminKeepsCrossOrganizationReach(t *testing.T) {
	claims := &UserClaims{Username: "root", Role: "admin"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Organization-ID", "acme")
	if err := ApplyUserTenantHeaders(r, claims); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("X-Organization-ID"); got != "acme" {
		t.Fatalf("admin lost its selected organization: %q", got)
	}
	if got := r.Header.Get(HeaderTenantUserID); got != "" {
		t.Fatalf("admin must not be personal-scoped: %q", got)
	}
}

// Fail closed rather than falling through to an unbound scope.
func TestUnidentifiableNonAdminIsRejected(t *testing.T) {
	claims := &UserClaims{Username: "  ", Role: "viewer"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := ApplyUserTenantHeaders(r, claims); err != ErrTenantMismatch {
		t.Fatalf("want ErrTenantMismatch, got %v", err)
	}
}

// The service branch does not go through ApplyUserTenantHeaders, so it needs its
// own strip — otherwise a peer call is a second way to spoof the owner.
func TestServiceTokenStripsThePersonalOwnerHeader(t *testing.T) {
	userSecret := []byte(strings.Repeat("u", 32))
	svcSecret := []byte(strings.Repeat("s", 32))
	tok, err := MintServiceJWT(svcSecret, "opm-api", "oam-api", "creds:resolve")
	if err != nil {
		t.Fatal(err)
	}
	cfg := MiddlewareConfig{Secret: userSecret, ServiceSecret: svcSecret, ServiceAudience: "oam-api"}
	var seen string
	h := cfg.RequireUserOrService("viewer", "creds:resolve", func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get(HeaderTenantUserID)
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set(HeaderTenantUserID, "alice")
	h(httptest.NewRecorder(), r)
	if seen != "" {
		t.Fatalf("service call carried a spoofed personal owner: %q", seen)
	}
}
