# 0001. Scope: users, roles and Google Workspace accounts

Status: Accepted

## Context
Today user logic is spread out. landingpage-backend signs people in with Google and stores users and
roles. onboarding-service creates, deactivates and deletes kthais.com Google Workspace accounts and group
memberships. Each holds its own Google credentials.

## Decision
identity-service owns:

- **Sign-in** for every KTHAIS app (ADR 0004).
- **Users and roles**: who someone is and what they may do.
- **Google Workspace accounts**: creating, deactivating and deleting kthais.com accounts and their group
  memberships. This part moves here from onboarding-service.

It does not own:

- **Profiles** and anything else the website shows about a member. These stay in landingpage-backend,
  linked to identity's users and roles.
- **The rest of onboarding**: the kth.se email confirmation, onboarding emails and their templates, the
  onboarding pages, and Mattermost. These stay in onboarding-service, which calls identity's internal API
  when it needs a Workspace account.

## Consequences
- Other services ask identity, not Google, about users and accounts.
- Moving Workspace provisioning out of onboarding-service is its own piece of work, after sign-in works.
