# 0004. Gin and GORM, like every KTHAIS Go service

Status: Accepted

## Convention
HTTP is served with [Gin](https://gin-gonic.com) and Postgres is accessed with [GORM](https://gorm.io).

## Why
landingpage-backend, onboarding-service, luma-service and growth-portal use the same two. Members change
every year, and one stack makes it easier for the same people to work on several services.

## How to apply
The open ADRs (0006–0008) are about how sign-in works, not about the framework: build on Gin and GORM.
Libraries for OIDC, tokens and similar sit on top of them.
