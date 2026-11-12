# 0007. Store single sign-on sessions in Postgres

Status: Proposed

## Context
After Google sign-in, a person should be able to visit another KTHAIS app without signing in to Google again. The session must survive a service restart and work across service instances.

## Decision
Keep an opaque, random browser cookie on the identity domain. Store only its SHA-256 hash, user ID, original Google authentication time and expiry in Postgres. The cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` when the issuer uses HTTPS. A session lasts 12 hours. The Google callback creates it; later authorization requests use it to complete login without another Google redirect. Reusing the session keeps the original `auth_time` in OIDC ID tokens.

Once ZITADEL validates and stores an `/authorize` request, identity sets a separate opaque, 10-minute `HttpOnly` browser cookie for it and stores only its hash on that request. The cookie name includes the server-generated request ID, so concurrent first sign-ins in different tabs do not overwrite each other's binding or extend each other's lifetime. On HTTPS, its name uses the `__Host-` prefix, `Secure`, and `Path=/`. Incoming values must have the canonical base64url form generated from 32 bytes; the stored hash establishes the actual binding. `/login`, the Google callback, and `/authorize/callback` require the cookie for their request before using it; the database writes require its hash as well. The Google callback also requires the one-use state stored on the request. Identity clears the request cookie after issuing the app's authorization code and clears all pending request cookies presented by the browser at `/end_session`. These cookies are distinct from the SSO session cookie.

`/end_session` accepts GET and POST requests with an ID token hint. ZITADEL validates the hint, client and redirect before our handler checks the browser session cookie. Browser Fetch Metadata must show a same-site or user-initiated request. If the cookie identifies a live session for the hinted user, logout atomically removes all of that user's identity sessions and the requesting app's refresh tokens. If there is no live identity session, logout deletes no records. Both accepted paths clear the identity and pending sign-in cookies and redirect to the validated return URL. A live session for another user, or an invalid request, is rejected without clearing cookies or deleting records. Already issued JWT access tokens remain valid until their one-hour expiry.

## Consequences
- Postgres is required for sign-in and SSO.
- Apps remain responsible for clearing their own sessions and revoking their refresh tokens on app logout, including when the identity browser session has expired.
- Expired session rows can be cleaned up later; expiry is checked on every lookup.
