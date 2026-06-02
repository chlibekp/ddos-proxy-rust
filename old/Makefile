# Makefile for ddos-proxy

# Build the application
build:
	go build -o proxy cmd/ddos-proxy/main.go

# Run the application
run:
	PROXY_BACKEND_URL=https://example.com PORT=8080 go run cmd/ddos-proxy/main.go

# Run tests
test:
	go test -v ./...

# Build Docker image
docker-build:
	docker build -t ddos-proxy .

# Run Docker container
docker-run:
	docker run -p 8080:8080 -e PROXY_BACKEND_URL=https://example.com ddos-proxy

.PHONY: build run test docker-build docker-run
