# Contributing Guidelines - Mango Shield WAF

Thank you for contributing to **Mango Shield**! To maintain production quality, please follow these guidelines.

---

## Code Quality Standards

1. **Clean Compilation**: All code must compile cleanly using Go 1.24+ without warnings (`go vet ./...` must pass).
2. **Zero Data Races**: New concurrency code must pass `go test -race ./...`.
3. **ReDoS Safety**: Any new regular expression added to WAF rules must be compatible with Go's `regexp` (RE2) engine. Perl negative lookaheads (`(?!...)`) are not permitted.
4. **Documentation**: Update [CONFIGURATION.md](CONFIGURATION.md) or [API.md](API.md) if adding new configuration keys or REST endpoints.

---

## Pull Request Workflow

1. Fork the repository and create your feature branch: `git checkout -b feature/my-feature`.
2. Commit your changes: `git commit -m 'Add new WAF inspection rule'`.
3. Ensure all tests pass: `go test -v ./...`.
4. Open a Pull Request detailing the changes and verification steps.
