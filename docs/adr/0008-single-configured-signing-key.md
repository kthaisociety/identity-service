# 0008. Use one configured signing key for the prototype

Status: Proposed

## Context
Apps verify identity's JWTs against public keys from `/keys`. The first version needs a stable key across restarts, but key rotation is deferred by the agreed prototype scope.

## Decision
Load one RSA private key (at least 2048 bits) from `OIDC_SIGNING_KEY_PEM_BASE64` at startup. Sign JWTs with RS256 and publish the corresponding public key through JWKS. Derive a stable key ID from the public key. Keep the same private key on all identity instances and across restarts. Also load a separate, stable 32-byte `OIDC_CRYPTO_KEY_BASE64` for the provider library's encrypted protocol state.

Store both values as deployment secrets. Local development uses `.env`; deployed environments should supply them through the existing secret management path. Never log them.

## Consequences
- Replacing the signing key immediately invalidates JWTs signed by the old key once apps refresh JWKS. A rotation procedure is future work.
- Replacing the encryption key can invalidate in-progress authorization requests. It must be kept stable during normal deployments.
- Access tokens expire after one hour, limiting the lifetime of an old JWT when a key changes.
