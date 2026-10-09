# 0002. The only service with Google credentials

Status: Accepted

## Context
Google credentials are spread over several services: landingpage-backend's OAuth client for sign-in and
onboarding-service's Workspace admin service account. Each copy is one more place to leak or
misconfigure.

## Decision
identity-service is the only KTHAIS service that holds Google credentials. It holds two:

- an **OAuth client**, for signing people in with Google
- a **Workspace admin service account** (domain-wide delegation, acting as a narrowly privileged admin),
  for managing kthais.com accounts

## Consequences
- Every other app signs in through identity (ADR 0004) and manages accounts through its internal API.
- Admin scopes stay as narrow as onboarding-service's are today.
- Once an app has moved over, its own Google credentials are removed.
