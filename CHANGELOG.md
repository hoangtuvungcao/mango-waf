# Changelog - Mango Shield WAF

All notable changes to **Mango Shield** are documented in this file.

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
