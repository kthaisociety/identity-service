# 0003. Tests live next to the code and run on every PR

Status: Accepted

## Convention
- Tests are standard Go tests: `foo_test.go` next to `foo.go`, same package. They run with
  `go test ./...`, in CI on every PR and every merge to `main`.
- Every PR adds or updates tests that show its ticket's behaviour works. Writing that test first is a good
  way to pin down what "done" means.
- Tests never call real Google APIs: use `httptest.Server` or a fake.

## Why
One kind of test that always runs is easier to keep up than several kinds with their own rules. Sign-in
code is security code: every rule it enforces (a rejected token, a rejected redirect URI) deserves a test
that proves it, and keeps proving it.

## How to apply
CI runs `go vet ./...` and `go test -race ./...`. Run the same locally before pushing.
