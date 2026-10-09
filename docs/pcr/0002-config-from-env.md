# 0002. All configuration comes from the environment

Status: Accepted

## Convention
Every setting is an environment variable, read once in `internal/config` at boot. Required ones are checked
in `Config.Validate`, so a missing one stops the service at startup. Nothing secret is ever committed or
baked into the image. `.env` is for local dev only and is git-ignored; `.env.example` lists every variable.

## Why
The same image runs in staging and production with different env, set by `kthaisociety/deployments`.
Secrets live in OpenBao.

## How to apply
A new setting means a field in `Config`, a line in `.env.example` and, when deploying, a line in the
project's `project.yaml` in `deployments`.
