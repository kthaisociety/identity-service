# Acceptance tests

One file per ticket, on that ticket's branch only ([docs/pcr/0003](../../docs/pcr/0003-tests.md)). Each file
starts with:

```go
//go:build acceptance

package acceptance
```

Run with `go test -tags acceptance ./test/acceptance/...`. Delete the file before merging.
