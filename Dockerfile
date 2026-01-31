# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /alist-encrypt-go ./cmd/server

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary
COPY --from=builder /alist-encrypt-go .

# Copy web static files (frontend UI)
COPY --from=builder /app/web/public ./web/public

# Copy config example
COPY --from=builder /app/configs/config.example.json ./configs/

# Create data directory
RUN mkdir -p /app/data

# Expose port
EXPOSE 5344

# Run
ENTRYPOINT ["/app/alist-encrypt-go"]
