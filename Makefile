.PHONY: build test vet tidy image conformance

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

tidy:
	go mod tidy

image:
	docker build -t gateway-acme .

## Start the gateway on loopback first; this points the published probe at it.
conformance:
	go run github.com/certpilot/certpilot-gateway-sdk/cmd/conformance@v0.2.0 -addr 127.0.0.1:9092 -insecure
