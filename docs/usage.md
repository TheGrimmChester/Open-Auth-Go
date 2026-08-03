# Usage

## User JWT (standalone or shared secret)

```go
import openauth "github.com/TheGrimmChester/open-auth-go"

tok, err := openauth.MintUserJWT(secret, "admin", "admin", "ora-api", 0)
claims, err := openauth.ParseUserJWT(tok, secret)
err = openauth.ValidateUserJWT(tok, secret)
```

## Auth mode

| Mode | When | Behavior |
|------|------|----------|
| **standalone** | `AUTH_MODE=standalone`, or `PEER_OPA_URL` empty | Product issues JWTs with its own `JWT_SECRET` (local login) |
| **co-deployed** | `AUTH_MODE=codeployed`, or `PEER_OPA_URL` set | **OPA-Hub** issues user JWTs; product validates with shared `JWT_SECRET` |

```go
mode := openauth.ResolveMode(os.Getenv("AUTH_MODE"), os.Getenv("PEER_OPA_URL"))
if openauth.IsStandalone(mode) {
    issuer := openauth.NewLocalIssuer(secret, "ora-api", "admin", "admin")
    tok, exp, claims, err := issuer.Login(user, pass)
}
```

## Service JWT (peer calls)

```go
tok, err := openauth.MintServiceJWT(secret, "ora-api", "osa-api", "findings:read runs:write")
claims, err := openauth.ValidateServiceJWT(tok, secret, "osa-api")
err = openauth.RequireScope(claims, "findings:read")
```

Service JWTs use HS256 with `iss` / `aud` / `sub=service` / `scope` / short `exp`. Prefer `OPEN_SERVICE_JWT_SECRET` distinct from user `JWT_SECRET`.
