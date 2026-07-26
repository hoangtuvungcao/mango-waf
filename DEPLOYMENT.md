# Production Deployment Guide — Mango Shield WAF v2.0

> Enterprise L7 DDoS Protection & Web Application Firewall with eBPF/XDP + P2P Mesh Cluster

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Single Node Deployment](#2-single-node-deployment)
3. [Multi-Node P2P Mesh Cluster](#3-multi-node-p2p-mesh-cluster)
4. [XDP eBPF Kernel Setup](#4-xdp-ebpf-kernel-setup)
5. [Cloudflare Integration](#5-cloudflare-integration)
6. [SSL/TLS Certificate Configuration](#6-ssltls-certificate-configuration)
7. [Production Linux Tuning](#7-production-linux-tuning)
8. [Monitoring & Health Checks](#8-monitoring--health-checks)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 22.04+ / Debian 12+ | Ubuntu 24.04 LTS |
| Go | 1.24+ | 1.24.0 |
| Docker | 24.0+ | 27.0+ |
| Docker Compose | v2.20+ | v2.30+ |
| RAM | 512 MB | 2 GB+ |
| CPU | 1 vCPU | 2+ vCPU |
| Kernel | 5.4+ (for eBPF) | 6.1+ |
| Capabilities | `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_SYS_ADMIN` | — |

---

## 2. Single Node Deployment

### 2.1 Clone & Build

```bash
git clone https://github.com/hoangtuvungcao/mango-waf.git
cd mango-waf
```

### 2.2 Configure

Edit `config/production.yaml`:

```yaml
server:
  listen: "0.0.0.0:443"
  http_listen: "0.0.0.0:80"

domains:
  - name: "your-domain.com"
    upstreams:
      - url: "http://mango-test-site:8080"
        weight: 1
    ssl: true

tls:
  enabled: true
  auto_cert: true
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
```

### 2.3 Deploy with Docker Compose

```bash
docker compose up -d --build
```

### 2.4 Verify

```bash
# Check containers
docker ps

# Check health
curl -s http://localhost:9090/api/health | jq

# Check stats
curl -s http://localhost:9090/api/stats | jq
```

---

## 3. Multi-Node P2P Mesh Cluster

Mango Shield uses HashiCorp Memberlist (Gossip protocol) for decentralized cluster synchronization. When an IP is banned on any node, the ban propagates to all cluster members within **< 100ms**.

### 3.1 Cluster Architecture

```
┌──────────────────────┐     P2P Gossip (7946/TCP+UDP)     ┌──────────────────────┐
│   Node 1             │◄──────────────────────────────────►│   Node 2             │
│   103.77.246.167     │     AES-256 Encrypted Channel      │   103.77.246.165     │
│   mango-node-1       │                                    │   mango-node-2       │
│   ├── Port 443 HTTPS │                                    │   ├── Port 443 HTTPS │
│   ├── Port 80 HTTP   │                                    │   ├── Port 80 HTTP   │
│   ├── Port 9090 API  │                                    │   ├── Port 9090 API  │
│   └── Port 7946 Mesh │                                    │   └── Port 7946 Mesh │
└──────────────────────┘                                    └──────────────────────┘
```

### 3.2 Node Configuration

#### Node 1 (`config/production.yaml`)

```yaml
cluster:
  enabled: true
  node_name: "mango-node-1"
  bind_port: 7946
  advertise_addr: "103.77.246.167"
  secret_key: "mangoshieldclustersecretkey32000"  # Must be 16, 24, or 32 bytes
  join_peers:
    - "103.77.246.165:7946"
```

#### Node 2 (`config/production.yaml`)

```yaml
cluster:
  enabled: true
  node_name: "mango-node-2"
  bind_port: 7946
  advertise_addr: "103.77.246.165"
  secret_key: "mangoshieldclustersecretkey32000"  # Same key across all nodes
  join_peers:
    - "103.77.246.167:7946"
```

### 3.3 Docker Compose Ports

Ensure both TCP and UDP are exposed for Memberlist:

```yaml
ports:
  - "443:443"
  - "80:80"
  - "9090:9090"
  - "7946:7946/tcp"
  - "7946:7946/udp"
```

### 3.4 Verify Cluster Sync

```bash
# From any node
curl -s http://localhost:9090/api/stats | jq '{mesh_enabled, mesh_nodes, mesh_members}'
```

Expected output:
```json
{
  "mesh_enabled": true,
  "mesh_nodes": 2,
  "mesh_members": [
    { "name": "mango-node-1", "addr": "103.77.246.167" },
    { "name": "mango-node-2", "addr": "103.77.246.165" }
  ]
}
```

### 3.5 Important Memberlist Notes

- **Secret Key**: Must be exactly 16, 24, or 32 bytes (AES-GCM requirement). Keys are auto-padded to 32 bytes by `cluster/gossip.go`.
- **Firewall**: Port 7946 must be open for both TCP and UDP between all cluster nodes.
- **Sync Interval**: Push/pull sync every 60 seconds by default.
- **Convergence**: Ban propagation < 100ms via UDP gossip broadcast.

---

## 4. XDP eBPF Kernel Setup

### 4.1 How XDP Works

XDP (eXpress Data Path) drops malicious packets at the Linux NIC driver layer **before** the kernel TCP/IP stack processes them. This achieves 10M+ packets/sec drop rate with near-zero CPU usage.

```
Packet Arrives at NIC
       │
  ┌────▼────┐
  │ XDP BPF │──── Source IP in blacklist? ─── YES ──► XDP_DROP (discarded at NIC)
  │ Filter  │
  └────┬────┘
       │ NO
  XDP_PASS ──► Normal kernel TCP/IP processing ──► Mango Shield L7 WAF
```

### 4.2 XDP Configuration

```yaml
xdp:
  enabled: true
  interface: "eth0"
  mode: "skb"              # "skb" (generic), "drv" (native), "offload" (smartNIC)
  map_pin_path: "/sys/fs/bpf/mango_blacklist"
  auto_compile: true
  auto_attach: true
```

### 4.3 Docker Capabilities for XDP

```yaml
cap_add:
  - NET_ADMIN
  - BPF
  - PERFMON
  - SYS_ADMIN
volumes:
  - /sys/fs/bpf:/sys/fs/bpf
```

### 4.4 Standalone BPF Map

In Docker containers, Mango Shield automatically creates a standalone BPF hash map via `BPF_MAP_CREATE` syscall if no pre-existing map is found. The map is pinned to `/sys/fs/bpf/mango_blacklist` for persistence.

### 4.5 Safety Guarantees

- XDP **ONLY** checks source IP against the blacklist BPF map
- **NEVER** blocks based on port numbers
- All ports (SSH 22, HTTP 80, HTTPS 443, Dashboard 9090, Cluster 7946, Metrics 9100) remain open
- Clean traffic always receives `XDP_PASS`
- Only blacklisted IPs receive `XDP_DROP`

---

## 5. Cloudflare Integration

### 5.1 DNS Setup

Point your domain to the VPS IP via Cloudflare DNS (A record):

```
firewall.hidev.dev → 103.77.246.167 (Proxied via Cloudflare)
```

### 5.2 Cloudflare SSL Settings

| Setting | Value |
|---------|-------|
| SSL/TLS mode | Full (Strict) |
| Always Use HTTPS | ON |
| Minimum TLS Version | 1.2 |
| Automatic HTTPS Rewrites | ON |

### 5.3 Trusted Proxy Configuration

Cloudflare IP ranges are automatically trusted in `config/production.yaml`:

```yaml
trusted_proxies:
  - "173.245.48.0/20"
  - "103.21.244.0/22"
  - "103.22.200.0/22"
  - "103.31.4.0/22"
  - "141.101.64.0/18"
  - "108.162.192.0/18"
  - "190.93.240.0/20"
  - "188.114.96.0/20"
  - "197.234.240.0/22"
  - "198.41.128.0/17"
  - "162.158.0.0/15"
  - "104.16.0.0/13"
  - "104.24.0.0/14"
  - "172.64.0.0/13"
  - "131.0.72.0/22"
```

---

## 6. SSL/TLS Certificate Configuration

### 6.1 Self-Signed (Development/Testing)

Mango Shield auto-generates self-signed certificates on startup if `tls.auto_cert: true`.

### 6.2 Custom Certificates

```yaml
tls:
  enabled: true
  auto_cert: false
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
```

### 6.3 Let's Encrypt (via Cloudflare)

When using Cloudflare proxy, Cloudflare handles the public-facing TLS. The origin certificate is a Cloudflare Origin CA certificate installed on the VPS.

---

## 7. Production Linux Tuning

Apply in `/etc/sysctl.d/99-mango-waf.conf`:

```ini
# File descriptor limits
fs.file-max = 2097152

# Network stack tuning
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Memory limits for BPF maps
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# Connection tracking
net.netfilter.nf_conntrack_max = 1000000
net.nf_conntrack_max = 1000000
```

Apply:
```bash
sudo sysctl -p /etc/sysctl.d/99-mango-waf.conf
```

---

## 8. Monitoring & Health Checks

### 8.1 API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Health check (no auth required) |
| `GET /api/stats` | Real-time WAF statistics |
| `GET /api/system-stats` | CPU, RAM, Disk, Network metrics |
| `GET /api/rps-history` | 5-minute RPS history (300 data points) |
| `POST /api/login` | Admin authentication |
| `POST /api/cache/purge` | Clear CDN cache (requires auth) |
| `GET /api/config` | Current configuration summary |
| `GET /metrics` | Prometheus metrics endpoint |

### 8.2 Docker Health Check

The compose file includes automatic health checking:

```yaml
healthcheck:
  test: ["CMD", "wget", "-qO-", "http://localhost:9090/api/health"]
  interval: 30s
  timeout: 5s
  retries: 3
```

### 8.3 Dashboard UI

- **Test Site**: `https://firewall.hidev.dev/`
- **Admin Dashboard Node 1**: `http://103.77.246.167:9090/`
- **Admin Dashboard Node 2**: `http://103.77.246.165:9090/`

---

## 9. Troubleshooting

### Container won't start
```bash
docker logs mango-shield 2>&1 | tail -50
```

### XDP shows disabled
- Ensure `/sys/fs/bpf` is mounted in the container
- Verify capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`
- Check logs: `docker logs mango-shield 2>&1 | grep -i xdp`

### Cluster nodes not syncing
- Verify port 7946 (TCP+UDP) is open between nodes
- Ensure `secret_key` is identical and exactly 16, 24, or 32 bytes
- Check: `curl -s http://localhost:9090/api/stats | jq .mesh_members`

### 403 Forbidden from WAF
- WAF blocks suspicious User-Agents (curl, wget, etc.)
- Add `-A "Mozilla/5.0"` to curl for testing
- Check WAF rules in `config/production.yaml` under `waf:` section

### Test-site tabs not switching
- Ensure `Content-Security-Policy` allows Google Fonts
- Check browser console (F12) for CSP errors
- Verify API endpoints are accessible: `curl https://domain/api/dstat`
