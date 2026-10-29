.PHONY: build test vet evaluate fmt-check test-db test-db-local ci
build:
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -o bin/zoli-intel ./cmd/zoli-intel
test:
	go test -buildvcs=false ./...
vet:
	go vet -buildvcs=false ./...
evaluate: build
	./bin/zoli-intel evaluate

fmt-check:
	@test -z "$$(gofmt -l cmd internal pkg examples)" || { gofmt -l cmd internal pkg examples; exit 1; }

# Mandatory database gate: never silently substitute a suite with skipped tests.
test-db:
	@test -n "$${ZOLI_TEST_DATABASE_URL:-}" || { echo 'ZOLI_TEST_DATABASE_URL must name a dedicated test database'; exit 1; }
	go test -race -count=1 ./...

test-db-local:
	bash tools/test-postgres.sh

ci: fmt-check test-db vet
	node --test testdata/sandbox/offline-lock.test.cjs
	$(MAKE) build evaluate
