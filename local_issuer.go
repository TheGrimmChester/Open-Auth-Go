package openauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"
	"time"
)

// LocalIssuer is a minimal in-memory user store for standalone product auth.
// It seeds one admin user for lab installs. Co-deployed installs should leave
// issuance to OPA-Hub and only validate with a shared JWT_SECRET.
//
// Per-user project membership (OrgID + ProjectIDs) is stored alongside the
// password hash and minted into JWT claims at login. Role admin ignores the
// allowlist (lab seed admin keeps full default-org access).
type LocalIssuer struct {
	Secret []byte
	Issuer string // e.g. "ora-api"
	TTL    time.Duration

	mu    sync.RWMutex
	users map[string]localUser
}

type localUser struct {
	Username     string
	PasswordHash string
	Role         string
	OrgID        string
	ProjectIDs   []string
}

// NewLocalIssuer builds a LocalIssuer. When secret is empty, a process-local
// ephemeral secret is generated (tokens reset on restart).
// seedPassword defaults to "admin" when empty (lab only).
func NewLocalIssuer(secret []byte, issuer, seedUsername, seedPassword string) *LocalIssuer {
	if len(secret) == 0 {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
	}
	if seedUsername == "" {
		seedUsername = "admin"
	}
	if seedPassword == "" {
		seedPassword = "admin"
	}
	li := &LocalIssuer{
		Secret: secret,
		Issuer: issuer,
		TTL:    defaultUserTTL,
		users:  make(map[string]localUser),
	}
	li.users[seedUsername] = localUser{
		Username:     seedUsername,
		PasswordHash: hashLocalPassword(seedPassword, secret),
		Role:         "admin",
		// No ProjectIDs: admin bypasses ACL and retains full org access.
	}
	return li
}

func hashLocalPassword(password string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(password))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Login validates credentials and returns a user JWT that includes any stored
// org / project membership claims.
func (li *LocalIssuer) Login(username, password string) (token string, exp time.Time, claims *UserClaims, err error) {
	if li == nil {
		return "", time.Time{}, nil, ErrInvalidToken
	}
	li.mu.RLock()
	u, ok := li.users[username]
	li.mu.RUnlock()
	if !ok || u.PasswordHash != hashLocalPassword(password, li.Secret) {
		return "", time.Time{}, nil, ErrInvalidToken
	}
	tok, err := MintUserJWTWithACL(li.Secret, u.Username, u.Role, li.Issuer, u.OrgID, u.ProjectIDs, li.TTL)
	if err != nil {
		return "", time.Time{}, nil, err
	}
	ttl := li.TTL
	if ttl <= 0 {
		ttl = defaultUserTTL
	}
	exp = time.Now().UTC().Add(ttl)
	out := &UserClaims{
		Username:   u.Username,
		Role:       u.Role,
		OrgID:      u.OrgID,
		ProjectIDs: NormalizeProjectIDs(u.ProjectIDs),
	}
	return tok, exp, out, nil
}

// Register adds a user with no project membership (unbound until SetMembership).
// Returns ErrInvalidToken when username exists or inputs are weak.
func (li *LocalIssuer) Register(username, password, role string) error {
	return li.RegisterWithMembership(username, password, role, "", nil)
}

// RegisterWithMembership adds a user bound to orgID and an optional project
// allowlist. Empty projectIDs leaves the user unbound (legacy behaviour).
func (li *LocalIssuer) RegisterWithMembership(username, password, role, orgID string, projectIDs []string) error {
	if li == nil || username == "" || len(password) < 8 {
		return ErrInvalidToken
	}
	if role == "" {
		role = "viewer"
	}
	li.mu.Lock()
	defer li.mu.Unlock()
	if _, exists := li.users[username]; exists {
		return ErrInvalidToken
	}
	li.users[username] = localUser{
		Username:     username,
		PasswordHash: hashLocalPassword(password, li.Secret),
		Role:         role,
		OrgID:        strings.TrimSpace(orgID),
		ProjectIDs:   NormalizeProjectIDs(projectIDs),
	}
	return nil
}

// SetMembership updates a user's org / project allowlist. Role is unchanged.
// Used by hub admins after register, or lab scripts that create a second user.
func (li *LocalIssuer) SetMembership(username, orgID string, projectIDs []string) error {
	if li == nil || strings.TrimSpace(username) == "" {
		return ErrInvalidToken
	}
	li.mu.Lock()
	defer li.mu.Unlock()
	u, ok := li.users[username]
	if !ok {
		return ErrInvalidToken
	}
	u.OrgID = strings.TrimSpace(orgID)
	u.ProjectIDs = NormalizeProjectIDs(projectIDs)
	li.users[username] = u
	return nil
}

// Membership returns the stored org / project allowlist for username.
func (li *LocalIssuer) Membership(username string) (orgID string, projectIDs []string, ok bool) {
	if li == nil {
		return "", nil, false
	}
	li.mu.RLock()
	defer li.mu.RUnlock()
	u, exists := li.users[username]
	if !exists {
		return "", nil, false
	}
	return u.OrgID, append([]string(nil), u.ProjectIDs...), true
}

// Parse validates a user JWT against this issuer's secret.
func (li *LocalIssuer) Parse(token string) (*UserClaims, error) {
	if li == nil {
		return nil, ErrInvalidToken
	}
	return ParseUserJWT(token, li.Secret)
}
