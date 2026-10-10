# Every check CI runs, in one place (docs/pcr/0002). `go test` finds the tests next to the code;
# nothing here lists them. Same targets as the fullstack repos, minus test-frontend.
# Database tests use the docker compose Postgres (`docker compose up -d`); CI sets its own.
export TEST_DATABASE_URL ?= postgres://identity:identity@127.0.0.1:5437/identity?sslmode=disable

.PHONY: test test-backend

test: test-backend

test-backend:
	go vet ./...
	go test -race ./...
