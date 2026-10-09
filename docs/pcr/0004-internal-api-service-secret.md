# 0004. The internal API authenticates callers with a shared secret

Status: Accepted

## Convention
Everything under `/v1` on the internal listener requires the header `X-Service-Secret`, compared in
constant time with `IDENTITY_SERVICE_SECRET`. An empty configured secret rejects every request. `/health`
is open.

## Why
Same pattern as onboarding-service and luma-service. The internal API can create and delete Google
Workspace accounts, so being on the internal network alone isn't enough.

## How to apply
Each environment has its own secret in OpenBao. If callers later need to be told apart (who may do
what), replace this with a new PCR.
