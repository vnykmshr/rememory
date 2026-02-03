.PHONY: build test lint clean install

BINARY := rememory
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/rememory

install:
	go install $(LDFLAGS) ./cmd/rememory

test:
	go test -v ./...

test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"

clean:
	rm -f $(BINARY) coverage.out coverage.html
