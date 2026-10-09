# 0003. Tests: next to the code, acceptance tests per ticket

Status: Accepted

## Convention
- **Module tests** are standard Go tests: `foo_test.go` next to `foo.go`, same package. They're permanent
  and run with `go test ./...`. They never call real Google APIs: use `httptest.Server` or a fake.
- **Acceptance tests** live in `test/acceptance/`, one file per ticket, with the build tag
  `//go:build acceptance`. They're written first, describe the ticket's behaviour end to end, and exist
  only on that ticket's branch: before merging, delete the file, moving anything worth keeping into module
  tests.

## Why
Module tests guard the code permanently. Acceptance tests pin down "done" for one ticket without piling
up slow end-to-end tests on `main`. Sign-in code is security code: every rule it enforces (a rejected
token, a rejected redirect URI) deserves a test that proves it.

## How to apply
`go test ./...` runs module tests only. `go test -tags acceptance ./test/acceptance/...` runs acceptance
tests. CI runs `go vet` and `go test -race ./...`.
