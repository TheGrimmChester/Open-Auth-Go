package openauth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestMintAndValidateServiceJWT(t *testing.T) {
	secret := []byte("test-service-secret-at-least-32-bytes!!")
	tok, err := MintServiceJWT(secret, "ora-api", "osa-api", "findings:read runs:write")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ValidateServiceJWT(tok, secret, "osa-api")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "ora-api" || claims.Subject != "service" {
		t.Fatalf("claims=%+v", claims)
	}
	if err := RequireScope(claims, "findings:read"); err != nil {
		t.Fatal(err)
	}
	if err := RequireScope(claims, "traces:read"); err != ErrMissingScope {
		t.Fatalf("want missing scope, got %v", err)
	}
}

func TestValidateServiceJWTRejectsWrongAud(t *testing.T) {
	secret := []byte("test-service-secret-at-least-32-bytes!!")
	tok, err := MintServiceJWT(secret, "ora-api", "osa-api", "health:read")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateServiceJWT(tok, secret, "opl-api"); err == nil {
		t.Fatal("expected aud mismatch")
	}
}

func TestParseUserJWT(t *testing.T) {
	secret := []byte("user-secret-at-least-thirty-two-bytes")
	now := time.Now().UTC()
	claims := UserClaims{
		Username: "alice",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseUserJWT(tok, secret)
	if err != nil || got.Username != "alice" || got.Role != "admin" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if err := ValidateUserJWT("", secret); err != ErrInvalidToken {
		t.Fatal(err)
	}
}
