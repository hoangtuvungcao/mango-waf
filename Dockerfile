# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o mango-shield ./main.go

# Production Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata iptables

# Create non-root system user and group
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /app/mango-shield .
COPY --from=builder /app/config/default.yaml ./config/default.yaml
COPY --from=builder /app/config/production.yaml ./config/production.yaml
COPY --from=builder /app/rules ./rules

# Set ownership and permissions
RUN mkdir -p /app/logs /app/certs /app/data && \
    chown -R appuser:appgroup /app

USER 10001:10001

EXPOSE 443 80 9090

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:9090/api/health || exit 1

ENTRYPOINT ["./mango-shield"]
CMD ["-config", "config/production.yaml"]

