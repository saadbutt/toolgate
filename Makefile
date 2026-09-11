.PHONY: all build test race lint demo bench clean

all: lint test build

build:
	go build -trimpath -o bin/demo ./cmd/demo

test:
	go test ./... -count=1

race:
	go test ./... -race -count=1

# vet is the lint floor. gofmt printing anything is a failure.
lint:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt found unformatted files"; exit 1)
	go vet ./...

demo:
	go run ./cmd/demo

bench:
	go test ./... -bench=. -benchmem -run=^$$

clean:
	rm -rf bin
