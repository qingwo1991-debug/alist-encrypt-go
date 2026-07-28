# Frontend build stage. The generated assets are architecture-independent, so
# run Node on the native builder platform instead of under QEMU for arm64.
FROM --platform=$BUILDPLATFORM node:22-alpine AS frontend-builder

WORKDIR /app/enc-webui

COPY enc-webui/package.json enc-webui/package-lock.json enc-webui/.npmrc ./
RUN apk add --no-cache python3 build-base && npm ci

COPY enc-webui/ ./
COPY tools/vite-svg-sprite-plugin.mjs /app/tools/vite-svg-sprite-plugin.mjs
RUN npm run build

# Build stage. Compile target binaries natively via Go cross-compilation instead
# of running the full toolchain under emulation for non-amd64 images.
FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

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
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -ldflags="-w -s" -o /alist-encrypt-go ./cmd/server

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata
RUN addgroup -S alistenc && adduser -S -G alistenc alistenc

WORKDIR /app

# Copy binary
COPY --from=builder /alist-encrypt-go .

# Copy configs (includes config.example.json and proxy_domain_dict.seed.json)
COPY --from=builder /app/configs/ ./configs/

# Create data and conf directories for persistence. The container intentionally
# runs as root by default so existing bind mounts owned by root remain writable.
RUN mkdir -p /app/data /app/conf && chown -R alistenc:alistenc /app

# Expose port
EXPOSE 5344

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:5344/health >/dev/null || exit 1

# Run
ENTRYPOINT ["/app/alist-encrypt-go"]
