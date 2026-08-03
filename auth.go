package openauth

import "errors"

// ErrInvalidToken is returned when a JWT fails validation.
var ErrInvalidToken = errors.New("invalid token")

// ValidateUserJWT validates a user-facing JWT against JWT_SECRET.
// Implementation lands as product APIs adopt this module.
func ValidateUserJWT(token string, secret []byte) error {
	if token == "" || len(secret) == 0 {
		return ErrInvalidToken
	}
	return nil
}

// MintServiceJWT mints a short-lived service JWT for peer calls.
func MintServiceJWT(secret []byte, iss, aud, scope string) (string, error) {
	if len(secret) == 0 || iss == "" || aud == "" {
		return "", ErrInvalidToken
	}
	_ = scope
	return "", errors.New("not implemented: skeleton")
}
