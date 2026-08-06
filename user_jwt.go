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
	return MintUserJWTWithACL(secret, username, role, issuer, "", nil, ttl)
}

// MintUserJWTWithTenant issues a user JWT optionally bound to org_id / project_id.
// When orgID or projectID is non-empty, product middleware should enforce that
// request tenant headers match (or overwrite them from the claims).
func MintUserJWTWithTenant(secret []byte, username, role, issuer, orgID, projectID string, ttl time.Duration) (string, error) {
	projectID = strings.TrimSpace(projectID)
	var projectIDs []string
	if projectID != "" {
		projectIDs = []string{projectID}
	}
	return mintUserClaims(secret, UserClaims{
		Username:   strings.TrimSpace(username),
		Role:       strings.TrimSpace(role),
		OrgID:      strings.TrimSpace(orgID),
		ProjectID:  projectID,
		ProjectIDs: projectIDs,
	}, strings.TrimSpace(issuer), ttl)
}

// MintUserJWTWithACL issues a user JWT with an optional org bind and project
// allowlist (project_ids). Empty projectIDs means unbound (legacy lab tokens);
// role admin always bypasses the allowlist at enforcement time.
func MintUserJWTWithACL(secret []byte, username, role, issuer, orgID string, projectIDs []string, ttl time.Duration) (string, error) {
	return MintUserJWTWithAccount(secret, username, role, issuer, "", orgID, projectIDs, ttl)
}

// MintUserJWTWithAccount issues a user JWT with an immutable account_type from OAM.
func MintUserJWTWithAccount(secret []byte, username, role, issuer, accountType, orgID string, projectIDs []string, ttl time.Duration) (string, error) {
	username = strings.TrimSpace(username)
	role = strings.TrimSpace(role)
	issuer = strings.TrimSpace(issuer)
	orgID = strings.TrimSpace(orgID)
	accountType = strings.ToLower(strings.TrimSpace(accountType))
	if len(secret) == 0 || username == "" {
		return "", ErrInvalidToken
	}
	if role == "" {
		role = "viewer"
	}
	switch accountType {
	case "", AccountTypePersonal, AccountTypeOrganization:
	default:
		return "", ErrInvalidToken
	}
	if accountType == AccountTypePersonal && orgID != "" {
		return "", ErrInvalidToken
	}
	if accountType == AccountTypeOrganization && orgID == "" {
		return "", ErrInvalidToken
	}
	return mintUserClaims(secret, UserClaims{
		Username:    username,
		Role:        role,
		AccountType: accountType,
		OrgID:       orgID,
		ProjectIDs:  NormalizeProjectIDs(projectIDs),
	}, issuer, ttl)
}

func mintUserClaims(secret []byte, claims UserClaims, issuer string, ttl time.Duration) (string, error) {
	if len(secret) == 0 || claims.Username == "" {
		return "", ErrInvalidToken
	}
	if claims.Role == "" {
		claims.Role = "viewer"
	}
	claims.ProjectIDs = NormalizeProjectIDs(claims.ProjectIDs)
	if ttl <= 0 {
		ttl = defaultUserTTL
	}
	now := time.Now().UTC()
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   claims.Username,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(secret)
}
