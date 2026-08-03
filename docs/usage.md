# Usage

```go
import openauth "github.com/TheGrimmChester/open-auth-go"

tok, err := openauth.MintServiceJWT(secret, "ora-api", "osa-api", "findings:read runs:write")
claims, err := openauth.ValidateServiceJWT(tok, secret, "osa-api")
err = openauth.RequireScope(claims, "findings:read")

err = openauth.ValidateUserJWT(userTok, userSecret)
```

Service JWTs use HS256 with `iss` / `aud` / `sub=service` / `scope` / short `exp`. Prefer `OPEN_SERVICE_JWT_SECRET` distinct from user `JWT_SECRET`.
