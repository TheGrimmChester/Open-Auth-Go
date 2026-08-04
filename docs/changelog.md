# Changelog

## Unreleased

- Add HTTP middleware (`RequireUser`, `RequireUserOrService`), `Gate` / `Bootstrap`, `LocalAuthHandlers`, `LoadJWTSecret`, `BearerOrCookie`, and `HasPermission`.
- Add `MintUserJWT`, `ResolveMode` / `ModeStandalone` / `ModeCodeployed`, and `LocalIssuer` for per-product standalone auth.
- Implement user JWT validate and service JWT mint/validate (`iss`/`aud`/`scope`).
