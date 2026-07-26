# Changelog - Mango Shield WAF

All notable changes to **Mango Shield** are documented in this file.

---

## [2.0.1] - 2026-07-26

### Added
- **Exhaustive Production Configuration**: Created fully documented `config/production.yaml` with inline comments for every setting (purpose, valid values, recommended default, performance impact, security impact).
- **Admin Authentication API (`POST /api/login`)**: Added session authentication token endpoint and modal UI for dashboard administration.
- **Upgraded Interactive Canvas Charts**: Added numerical Y-axis labels, units, X-axis time markers (-60s to now), and hover tooltips across all test-site charts.
- **Tab Navigation Auto-Redraw**: Fixed tab click handlers in `test-site/server.go` to force instant canvas redrawing upon switching active tab views.
- **XDP/eBPF Subsystem Auto-Attach & Map Pinning**: Added `auto_compile`, `auto_attach`, and `bpftool` map ID discovery to `core/xdp.go`.
- **HTTP 429 Rate Limit Response**: Wired `ActionRateLimit` in `core/pipeline.go` and `core/server.go` to return HTTP 429 Too Many Requests with commercial 429 template.
- **Authoritative eBPF/XDP Documentation**: Added `docs/XDP_GUIDE.md` and synchronized all project documentation.

---

## [2.0.0] - 2026-07-26

### Added
- **Native Zero-Fork eBPF Syscalls**: Implemented direct Linux `sys_bpf` kernel syscalls (`unix.BPFObjGet`, `bpfMapUpdateElem`, `bpfMapDeleteElem`) in `core/xdp.go` to eliminate per-ban subprocess overhead.
- **802.1Q & 802.1ad VLAN Parsing**: Added VLAN tag encapsulation handling in `xdp/mango_xdp.c`.
- **Trusted Proxy Verification**: Added `protection.trusted_proxies` CIDR list checking to prevent IP header spoofing (`X-Forwarded-For`, `X-Real-IP`).
- **Negative Regex (`!rx`) Operator**: Introduced `!rx` operator in `rules/engine.go` to support RE2-compatible whitelist matching.
- **Comprehensive Test Suite**: Added `challenge_test.go`, `server_test.go`, `proxy_test.go`, `rules_test.go`, and `pool_test.go`.

### Security & Hardening
- **Secrets Sanitization**: Removed all hardcoded bot tokens, AbuseIPDB keys, passwords, and static HMAC keys across `config/*.yaml`.
- **Turnstile Replay Bounds**: Fixed timestamp validation window in `challenge/challenge.go` (`diff < -10 || diff > 300`).
- **Timing Attack Mitigation**: Applied `subtle.ConstantTimeCompare` in `api/dashboard.go`.
- **Panic Recovery Middleware**: Added panic recovery wrapping to HTTP connection handlers.

### Removed
- Removed duplicate legacy challenge file `core/challenge.go`.
- Removed obsolete `xdp/SETUP_XDP.md` file (consolidated into architecture and deployment manuals).
- Removed dead configuration fields (`tls.auto_cert`, `tls.acme_email`).
