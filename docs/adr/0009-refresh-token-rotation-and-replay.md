# 0009. Rotate refresh tokens and revoke their chain on replay

Status: Accepted

## Context

ADR 0006 provides refresh tokens through the OIDC provider, but does not define how long
renewal may continue or what happens when an old token is reused. Without an absolute
limit, repeated refreshes can extend access indefinitely. The service also needs a
defined response when a used token is presented again.

## Decision

Issue refresh tokens only when the client requests `offline_access`. Each token is
single-use and expires within 30 days. Renewal stops 90 days after the original
authentication time, regardless of how often the token is refreshed.

Group each token and its replacements into one refresh-token family for one client.
Rotate atomically: mark the presented token used and issue its replacement in the same
database transaction. Keep hashes of used tokens until the family's absolute expiry so
reuse can be detected. Reusing a token revokes that family, including its current token.
Revoking a refresh token also revokes its family. Other clients' families are unaffected.

## Consequences

- App backends must coordinate refresh requests for each session. A duplicate request
  with the same token counts as replay and ends that family's ability to refresh.
- Revocation does not invalidate access JWTs already issued; they remain valid until
  their one-hour expiry.
- Expired family and token rows need a cleanup job; expiry and revocation are checked
  whenever a refresh token is used.
