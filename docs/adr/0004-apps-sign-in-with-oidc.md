# 0004. Apps sign in through OIDC

Status: Accepted

## Context
Every app that wants "Sign in with Google" needs its own Google OAuth client and its own copy of the
sign-in logic. We want one sign-in for all KTHAIS apps, and we want to be able to swap this service for
an off-the-shelf one (Zitadel, Keycloak) later without changing the apps.

## Decision
Apps are [OpenID Connect](https://openid.net/developers/how-connect-works/) clients of identity-service,
not of Google:

```
app ──(1) redirect: client_id, redirect_uri, state, PKCE──▶ identity
identity ──(2) Google sign-in, its own OAuth client──▶ Google
Google ──(3) callback to identity's own URL──▶ identity
identity ──(4) redirect to the app's redirect_uri with a one-time code──▶ app
app backend ──(5) exchange the code for tokens──▶ identity
```

- Authorization code flow with PKCE. Tokens never travel in URLs.
- Standard tokens: short-lived signed JWTs with `iss`, `aud` (the app's client ID), `sub`, `exp`, plus
  role claims. Public keys at a JWKS endpoint, and a discovery document at
  `/.well-known/openid-configuration`.
- Apps must check `aud`: a token issued for one app is rejected by every other app.
- Single sign-on: someone signed in to one app is not asked to sign in to Google again for the next.
- Before trusting a Google sign-in, identity fully verifies Google's ID token: signature, `iss`, `aud`,
  `exp` and `email_verified`.

## Consequences
- Google's allowed redirect URIs contain only identity's own callback, one per environment. Adding an app
  never touches Google.
- Apps can use any standard OIDC library to sign people in.
