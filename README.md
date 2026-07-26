# Mango Shield WAF (v2.0)

[![Go Reference](https://img.shields.io/badge/go-1.24.0-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Race Detector](https://img.shields.io/badge/race-0%20detected-brightgreen.svg)]()

**Mango Shield** is an enterprise-grade, high-performance Web Application Firewall (WAF) and DDoS protection reverse proxy written in Go, powered by **eBPF/XDP hardware packet filtering** and **OWASP CRS detection**.

Designed for high-throughput edge environments, Mango Shield combines L3/L4 hardware-level packet dropping (10M+ RPS capacity) with intelligent L7 application protection, TLS fingerprinting (JA3/JA4), automated JavaScript Proof-of-Work (PoW) challenges, and peer-to-peer cluster synchronization via a Gossip mesh protocol.

---

## Key Features

- ⚡ **10M+ RPS eBPF/XDP Dropping**: Zero-fork native kernel packet filtering via direct Linux `sys_bpf` map system calls (`/sys/fs/bpf/mango_blacklist`).
- 🛡️ **OWASP CRS Layer 7 Protection**: Deep inspection for SQL Injection (SQLi), Cross-Site Scripting (XSS), Remote Code Execution (RCE), Path Traversal, and Protocol Violations using RE2-optimized regex rules.
- 🔑 **TLS Fingerprinting**: Connection-level JA3/JA4 hash extraction and bot classification prior to HTTP payload parsing.
- 🧩 **Multi-Stage Challenges**: Automated JS Proof-of-Work (SHA-256) and Turnstile hold-to-verify challenges for suspicious or automated clients.
- 🚀 **Smart CDN Caching**: High-concurrency in-memory response caching backed by Ristretto.
- 🌐 **P2P Gossip Mesh**: Decentralized cluster threat intelligence sharing using Memberlist Gossip protocol.
- 📊 **Real-time Dashboard & Metrics**: Web UI dashboard with basic auth, anti-CSRF protection, and Prometheus metrics endpoint (`/metrics`).

---

## Quick Start

```bash
# Clone repository
git clone https://github.com/hoangtuvungcao/mango-waf.git
cd mango-waf

# Build binary
go build -o mango-shield ./cmd/cli

# Run server with default configuration
sudo ./mango-shield -config config/default.yaml
```

For complete setup guides, refer to [INSTALL.md](INSTALL.md) and [DEPLOYMENT.md](DEPLOYMENT.md).

---

## Architecture Overview

```
Client Traffic
      │
      ▼
┌─────────────────────────────────────────┐
│ Kernel eBPF / XDP Layer (mango_xdp.c)   │ ◄── [XDP_DROP via BPF Map Blacklist]
└────────────────────┬────────────────────┘
                     │ (XDP_PASS)
                     ▼
┌─────────────────────────────────────────┐
│ Go Reverse Proxy Engine (core/server)   │
├─────────────────────────────────────────┤
│ 1. IP Whitelist & Trusted Proxy Check   │
│ 2. TLS Fingerprinting (JA3 / JA4)       │
│ 3. Connection Rate & Limiters           │
│ 4. WAF Engine (OWASP CRS Rules)         │
│ 5. Challenge Engine (JS PoW / Turnstile)│
│ 6. CDN RAM Cache (Ristretto)            │
└────────────────────┬────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│ Upstream Backend Origin Servers         │
└─────────────────────────────────────────┘
```

For technical deep dives, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Documentation Index

- [INSTALL.md](INSTALL.md) — Prerequisites, compilation, and systemd service configuration.
- [docs/XDP_GUIDE.md](docs/XDP_GUIDE.md) — Authoritative eBPF/XDP hardware packet filtering, map inspection, and drop verification guide.
- [CONFIGURATION.md](CONFIGURATION.md) — Comprehensive YAML configuration options reference.
- [ARCHITECTURE.md](ARCHITECTURE.md) — System design, eBPF map mechanics, pipeline flow, and concurrency model.
- [API.md](API.md) — Dashboard REST API endpoints and schema specifications.
- [SECURITY.md](SECURITY.md) — Vulnerability reporting policy, security model, and defense-in-depth design.
- [DEPLOYMENT.md](DEPLOYMENT.md) — Docker Compose, Kubernetes, and production multi-node cluster deployment.
- [DEVELOPER.md](DEVELOPER.md) — Development workflow, testing strategies, and benchmark execution.
- [CONTRIBUTING.md](CONTRIBUTING.md) — Contribution guidelines and code of conduct.
- [CHANGELOG.md](CHANGELOG.md) — Release notes and version history.
- [LICENSE](LICENSE) — Open source license details.
