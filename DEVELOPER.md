# Developer Guide - Mango Shield WAF

This guide covers local development workflows, testing strategies, benchmark execution, and code style standards.

---

## Workspace Layout

- `cmd/cli/`: Main CLI entrypoint (`main.go`).
- `config/`: Configuration parsing, validation, and defaults (`config.go`).
- `core/`: Reverse proxy server, pipeline stage engine, upstream load balancer, and XDP manager.
- `rules/`: OWASP CRS engine and RE2 rule definitions (`engine.go`, `owasp.go`).
- `challenge/`: JS Proof-of-Work and Turnstile challenge generator (`challenge.go`).
- `perf/`: Token bucket rate limiter (`pool.go`).
- `xdp/`: eBPF C program (`mango_xdp.c`).

---

## Running Verification Commands

```bash
# Code formatting check
go fmt ./...

# Static analysis check
go vet ./...

# Unit and integration tests
go test -v ./...

# Race condition detection
go test -race ./...

# Performance benchmarks
go test -bench=. -benchmem ./...
```
