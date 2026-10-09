# 0001. Conventional Commits, squash merges

Status: Accepted

## Convention
PR titles are [Conventional Commits](https://www.conventionalcommits.org) (`feat:`, `fix:`, `docs:`,
`chore:`, `refactor:`, `test:`, `ci:`, …; `!` for breaking changes). PRs are squash-merged, so the title
becomes the commit on `main`.

## Why
release-please reads the commits on `main` to pick the next version and write `CHANGELOG.md`. The `pr`
workflow checks the title.

## How to apply
`feat:` and `fix:` produce a release; the other types don't.
