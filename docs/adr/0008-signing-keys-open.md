# 0008. Signing keys: open

Status: Proposed

## Context
Identity signs the tokens apps receive (ADR 0004). Apps verify them with the public keys at the JWKS
endpoint.

## Decision
Not decided: where the private key is kept and how it's rotated. Whatever is chosen, the key is a secret
(it lives in OpenBao in deployed environments, PCR 0002), and rotating it must not sign everyone out of
every app at once. Record the choice in a new ADR that supersedes this one.

## Consequences
None yet.
