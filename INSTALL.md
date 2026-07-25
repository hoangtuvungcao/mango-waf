# Installation Guide - Mango Shield WAF

This guide covers system prerequisites, manual compilation, Docker deployment, and systemd service installation for **Mango Shield WAF**.

---

## System Requirements

- **Operating System**: Linux (Ubuntu 22.04+, Debian 11+, RHEL 9+, Alpine Linux 3.18+)
- **Kernel Version**: Linux 5.8 or higher (required for eBPF `CAP_BPF` & `CAP_PERFMON` support)
- **Architecture**: `amd64` (x86_64) or `arm64` (aarch64)
- **Go Toolchain**: Go 1.24.0 or higher
- **C Compiler (for eBPF compilation)**: `clang` & `llvm` (version >= 12.0)

---

## 1. Manual Compilation & Installation

### Step 1: Install Build Dependencies

**Ubuntu / Debian**:
```bash
sudo apt-get update
sudo apt-get install -y build-essential clang llvm libbpf-dev linux-tools-common golang-go
```

### Step 2: Clone & Build Mango Shield

```bash
# Clone the repository
git clone https://github.com/hoangtuvungcao/mango-waf.git
cd mango-waf

# Verify Go toolchain version
go version

# Download Go dependencies
go mod download

# Build CLI and server binaries
go build -o bin/mango-shield ./cmd/cli
```

### Step 3: Compile eBPF Bytecode (Optional for XDP Mode)

```bash
clang -O2 -target bpf -c xdp/mango_xdp.c -o xdp/mango_xdp.o
```

---

## 2. Docker Installation

Run Mango Shield using Docker Compose with eBPF privileges enabled:

```bash
docker-compose up -d --build
```

### Docker Compose Configuration Highlights
Ensure the container runs with `CAP_BPF` and `CAP_PERFMON` Linux capabilities:
```yaml
capabilities:
  add:
    - CAP_BPF
    - CAP_PERFMON
    - CAP_NET_ADMIN
volumes:
  - /sys/fs/bpf:/sys/fs/bpf
```

---

## 3. Systemd Service Installation

Create `/etc/systemd/system/mango-shield.service`:

```ini
[Unit]
Description=Mango Shield WAF & Reverse Proxy
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/mango-shield -config /etc/mango-waf/default.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo cp bin/mango-shield /usr/local/bin/
sudo mkdir -p /etc/mango-waf
sudo cp config/default.yaml /etc/mango-waf/
sudo systemctl daemon-reload
sudo systemctl enable --now mango-shield
```
