# Security Policy - Mango Shield WAF

Mango Shield is committed to maintaining high security standards. This document outlines vulnerability reporting practices and security design principles enforced within the repository.

---

## Reporting a Vulnerability

If you discover a security vulnerability in Mango Shield, please report it privately:

- **Email**: `security@vutrungocrong.fun`
- **Response Time**: We acknowledge reports within 24 hours and aim to release fixes within 72 hours for critical vulnerabilities.
- **Please DO NOT open public GitHub issues for unpatched vulnerabilities.**

---

## Security Model & Hardening

1. **IP Address Spoofing Protection**: `Shield.extractIP` verifies client socket IP against `protection.trusted_proxies` before evaluating `X-Forwarded-For` or `X-Real-IP` headers.
2. **Timing Attack Defense**: Basic Auth credential comparison in `api/dashboard.go` uses `crypto/subtle.ConstantTimeCompare`.
3. **Turnstile Proof Replay Protection**: Challenge tokens enforce strict timestamp windows (`[-10, 300]` seconds) and HMAC signature checks (`mango_proof`).
4. **ReDoS Protection**: All WAF regular expressions are compiled via Go's RE2 engine, guaranteeing linear time inspection without catastrophic backtracking.
5. **Panic Safety**: All HTTP request handlers are wrapped in panic recovery middleware.
