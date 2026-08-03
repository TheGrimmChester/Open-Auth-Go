package openauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

// LocalIssuer is a minimal in-memory user store for standalone product auth.
// It seeds one admin user for lab installs. Co-deployed installs should leave
// issuance to OPA-Hub and only validate with a shared JWT_SECRET.
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
	}
	return li
}

func hashLocalPassword(password string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(password))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Login validates credentials and returns a user JWT.
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
	tok, err := MintUserJWT(li.Secret, u.Username, u.Role, li.Issuer, li.TTL)
	if err != nil {
		return "", time.Time{}, nil, err
	}
	ttl := li.TTL
	if ttl <= 0 {
		ttl = defaultUserTTL
	}
	exp = time.Now().UTC().Add(ttl)
	return tok, exp, &UserClaims{Username: u.Username, Role: u.Role}, nil
}

// Register adds a user. Returns ErrInvalidToken when username exists or inputs are weak.
func (li *LocalIssuer) Register(username, password, role string) error {
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
	}
	return nil
}

// Parse validates a user JWT against this issuer's secret.
func (li *LocalIssuer) Parse(token string) (*UserClaims, error) {
	if li == nil {
		return nil, ErrInvalidToken
	}
	return ParseUserJWT(token, li.Secret)
}
