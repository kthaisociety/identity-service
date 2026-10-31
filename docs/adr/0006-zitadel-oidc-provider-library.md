# 0006. Use ZITADEL's OIDC provider library

Status: Accepted

## Context
ADR 0004 requires identity-service to act as an OpenID Connect provider. The service needs an
authorization code flow with PKCE, refresh tokens, discovery and JWKS. Implementing the protocol by hand
would put more security-sensitive code in this small service.

## Decision
Use [`github.com/zitadel/oidc/v3/pkg/op`](https://github.com/zitadel/oidc) for the OIDC provider. It
supplies the protocol behavior; identity-service supplies registered clients, persistent provider state,
Google sign-in, KTHAIS users and roles, and signing-key configuration. Connect the provider to the public
listener without moving user or role management onto it.

## Consequences
- Keep OIDC protocol code in the library and KTHAIS-specific rules in our code, so another developer can
  see which part owns each check.
- The database schema for authorization codes and refresh state must satisfy the library's storage
  interface. Validate integration with Gin, Postgres and this repo's Go version before building the full
  flow.
- This choice does not verify Google's ID token for us. Identity must still check its signature, `iss`,
  `aud`, `exp` and `email_verified` before using any claim.
- Apps continue to use standard OIDC, so changing the provider implementation later need not change them.
