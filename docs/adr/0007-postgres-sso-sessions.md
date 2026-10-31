# 0007. Store single sign-on sessions in Postgres

Status: Proposed

## Context
After Google sign-in, a person should be able to visit another KTHAIS app without signing in to Google again. The session must survive a service restart and work across service instances.

## Decision
Keep an opaque, random browser cookie on the identity domain. Store only its SHA-256 hash, user ID, original Google authentication time and expiry in Postgres. The cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` when the issuer uses HTTPS. A session lasts 12 hours. The Google callback creates it; later authorization requests use it to complete login without another Google redirect. Reusing the session keeps the original `auth_time` in OIDC ID tokens.

The Google redirect also uses a separate, 10-minute `HttpOnly` state cookie scoped to `/auth/callback`. The callback requires it to match the state in the URL, binding the Google response to the browser that started login. The callback clears it before exchanging the Google code. This is distinct from the SSO session cookie.

`/end_session` removes the current session and clears the cookie. When the OIDC logout request contains a valid ID token hint, the provider also ends that user's identity sessions and the requesting client's refresh tokens. Already issued JWT access tokens remain valid until their one-hour expiry.

## Consequences
- Postgres is required for sign-in and SSO.
- Apps remain responsible for their own local cookies or sessions and for deleting them on app logout.
- Expired session rows can be cleaned up later; expiry is checked on every lookup.
