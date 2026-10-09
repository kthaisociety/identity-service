# 0005. Registered apps and redirect URIs come from config

Status: Accepted

## Context
After sign-in, identity sends the user back to the app with a code. If it redirected to whatever URL a
request asks for, any site could receive signed-in users' codes.

## Decision
Each app (client) is registered in config, from the environment (PCR 0002): its client ID, its allowed
redirect URIs, and whether it has a backend that can hold a secret. Redirect URIs are an exact-match
allowlist: no wildcards, no prefix matching.

## Consequences
- Adding an app or a redirect URI is a config change in `kthaisociety/deployments`, not a code change.
- Staging and production can allow different URIs.
- How the clients are written in env is up to the implementation; document it in `.env.example`.
