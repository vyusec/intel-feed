.PHONY: build test vet evaluate
build:
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -o bin/zoli-intel ./cmd/zoli-intel
test:
	go test -buildvcs=false ./...
vet:
	go vet -buildvcs=false ./...
evaluate: build
	./bin/zoli-intel evaluate
