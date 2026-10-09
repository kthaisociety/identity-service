# Vocabulary

Words as this project uses them.

- **User**: a person known to KTHAIS, signed in with Google. Applicants and visitors are users too, not
  only members.
- **Role**: what a user may do: `user`, `member` or `admin` today. Identity owns roles; apps read them from
  tokens.
- **Workspace account**: a user's kthais.com Google Workspace account. Members have one, applicants don't.
- **App** (OIDC client): a KTHAIS application that signs people in through identity, e.g. kthais.com.
  Registered in config with a client ID and its redirect URIs.
- **Redirect URI**: where identity sends the user back to after sign-in. Must exactly match one the app
  registered ([ADR 0005](docs/adr/0005-redirect-uri-allowlist-in-config.md)).
- **Token**: a signed JWT identity issues to an app. Its `aud` is that app's client ID.
- **Session**: identity's memory that someone is signed in, so the next app doesn't send them to Google
  again.
- **Public listener / internal listener**: the two HTTP servers this service runs
  ([ADR 0003](docs/adr/0003-two-listeners.md)).
- **Caller**: another KTHAIS service using the internal API, e.g. onboarding-service. Authenticates with
  the **service secret**.
- **Profile**: what the website shows about a member. Not owned here: it lives in landingpage-backend.
