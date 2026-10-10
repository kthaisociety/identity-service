# 0003. Two listeners: public sign-in, internal API

Status: Accepted

## Context
Sign-in has to be public: people's browsers go through it. Account management uses Workspace admin rights
(ADR 0002). If both shared one public server, a bug in sign-in code could reach account creation and
deletion.

## Decision
The service runs two HTTP listeners from one process:

- **Public** (`PUBLIC_PORT`, 8000 in the image): the sign-in endpoints. The only port given a domain.
- **Internal** (`INTERNAL_PORT`, 8001 in the image): user, role and Workspace management, under `/v1`,
  with the service secret (PCR 0003). Never given a domain; reachable only on the internal network.

## Consequences
- A route goes on the public listener only if a browser or an app must reach it from the internet.
- Each listener has its own router (`handlers.NewPublicRouter`, `handlers.NewInternalRouter`), so a
  route can't end up public by accident.
