# Frontend build stage
FROM node:20-alpine AS frontend-builder

WORKDIR /app/enc-webui

COPY enc-webui/package.json enc-webui/package-lock.json ./
RUN apk add --no-cache python3 build-base && npm ci

COPY enc-webui/ ./
RUN npm run build

# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Sync freshly built frontend assets into the embedded web directory before compiling Go.
COPY --from=frontend-builder /app/enc-webui/dist/ /app/web/public/

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /alist-encrypt-go ./cmd/server

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata
RUN addgroup -S alistenc && adduser -S -G alistenc alistenc

WORKDIR /app

# Copy binary
COPY --from=builder /alist-encrypt-go .

# Copy configs (includes config.example.json and proxy_domain_dict.seed.json)
COPY --from=builder /app/configs/ ./configs/

# Create data and conf directories for persistence
RUN mkdir -p /app/data /app/conf && chown -R alistenc:alistenc /app

USER alistenc

# Expose port
EXPOSE 5344

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:5344/health >/dev/null || exit 1

# Run
ENTRYPOINT ["/app/alist-encrypt-go"]
