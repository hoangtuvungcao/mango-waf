# Build stage
FROM golang:1.24-alpine AS builder

ENV GOTOOLCHAIN=auto

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o mango-shield ./main.go

# Production Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata iptables iproute2 clang llvm libbpf-dev bpftool gcc make musl-dev linux-headers

WORKDIR /app

COPY --from=builder /app/mango-shield .
COPY --from=builder /app/config ./config
COPY --from=builder /app/rules ./rules
COPY --from=builder /app/xdp ./xdp
COPY --from=builder /app/certs ./certs
COPY --from=builder /app/world.svg .

# Create required directory structure
RUN mkdir -p /app/logs /app/certs /app/data /sys/fs/bpf

USER root

EXPOSE 443 80 9090 9100

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:9090/api/health || exit 1

ENTRYPOINT ["./mango-shield"]
CMD ["-config", "config/production.yaml"]
