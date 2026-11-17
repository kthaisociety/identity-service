# 0007. Store single sign-on sessions in Postgres

Status: Proposed

## Context
After Google sign-in, a person should be able to visit another KTHAIS app without signing in to Google again. The session must survive a service restart and work across service instances.

## Decision
Keep an opaque, random browser cookie on the identity domain. Store only its SHA-256 hash, user ID, original Google authentication time and expiry in Postgres. The cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` when the issuer uses HTTPS. A session lasts 12 hours. The Google callback creates it; later authorization requests use it to complete login without another Google redirect. Reusing the session keeps the original `auth_time` in OIDC ID tokens.

At `/authorize`, identity sets a separate opaque, 10-minute `HttpOnly` browser cookie for each pending authorization request and stores only its hash on that request. The cookie name includes the server-generated request ID, so concurrent first sign-ins in different tabs do not overwrite each other's binding. `/login`, the Google callback, and `/authorize/callback` require the cookie for their request before using it; the database writes require its hash as well. The Google callback also requires the one-use state stored on the request. These cookies are distinct from the SSO session cookie.

`/end_session` removes the current session and clears the cookie. When the OIDC logout request contains a valid ID token hint, the provider also ends that user's identity sessions and the requesting client's refresh tokens. Already issued JWT access tokens remain valid until their one-hour expiry.

## Consequences
- Postgres is required for sign-in and SSO.
- Apps remain responsible for their own local cookies or sessions and for deleting them on app logout.
- Expired session rows can be cleaned up later; expiry is checked on every lookup.
