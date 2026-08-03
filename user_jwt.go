package openauth

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultUserTTL = 24 * time.Hour

// MintUserJWT issues a user-facing HS256 JWT with JWT_SECRET.
// issuer should be the product service id (e.g. "ora-api", "opa-hub").
func MintUserJWT(secret []byte, username, role, issuer string, ttl time.Duration) (string, error) {
	username = strings.TrimSpace(username)
	role = strings.TrimSpace(role)
	issuer = strings.TrimSpace(issuer)
	if len(secret) == 0 || username == "" {
		return "", ErrInvalidToken
	}
	if ttl <= 0 {
		ttl = defaultUserTTL
	}
	now := time.Now().UTC()
	if role == "" {
		role = "viewer"
	}
	claims := UserClaims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(secret)
}
