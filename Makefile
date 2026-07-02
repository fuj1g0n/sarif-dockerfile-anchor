# Run these targets inside the Nix dev shell for the pinned toolchain:
#   nix develop -c make <target>

.PHONY: test build vet lint fmt cover cover-html

test:
	go test ./... -race -count=1

build:
	go build ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

fmt:
	golangci-lint fmt ./...

cover:
	go test ./... -covermode=atomic -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1

cover-html:
	go test ./... -covermode=atomic -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo wrote coverage.html
