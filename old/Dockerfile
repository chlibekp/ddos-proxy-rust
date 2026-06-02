# Use a minimal base image for the final build
FROM golang:alpine AS builder

# Install dependencies for building BPF (clang, llvm, kernel headers)
RUN apk add --no-cache clang llvm libbpf-dev linux-headers make

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum (if present) first for caching dependencies
COPY go.mod ./
COPY go.sum ./ 

# Download dependencies
RUN go mod download

# Copy the rest of the source code
COPY . .

# Generate eBPF bytecodes
RUN go generate ./...

# Build the application statically linked
RUN CGO_ENABLED=0 GOOS=linux go build -o proxy cmd/ddos-proxy/main.go

# Use a minimal image for the final build
FROM alpine:latest

# Install ca-certificates for HTTPS support and libbpf for eBPF
RUN apk --no-cache add ca-certificates libbpf

WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/proxy .
COPY --from=builder /app/challenge.html .

# Expose the port
EXPOSE 8080

# Run the binary
CMD ["./proxy"]
