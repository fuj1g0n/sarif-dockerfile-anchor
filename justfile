# Run these recipes inside the Nix dev shell for the pinned toolchain:
#   nix develop -c just <recipe>

# List available recipes
default:
    @just --list

# Run tests with the race detector
test:
    go test ./... -race -count=1

# Build all packages
build:
    go build ./...

# Run go vet
vet:
    go vet ./...

# Run golangci-lint
lint:
    golangci-lint run ./...

# Format the code
fmt:
    golangci-lint fmt ./...

# Report total test coverage
cover:
    go test ./... -covermode=atomic -coverprofile=coverage.out
    go tool cover -func=coverage.out | tail -1

# Write an HTML coverage report
cover-html:
    go test ./... -covermode=atomic -coverprofile=coverage.out
    go tool cover -html=coverage.out -o coverage.html
    @echo wrote coverage.html
