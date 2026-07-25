# Production Deployment Guide - Mango Shield WAF

This guide outlines production deployment best practices for standalone edge instances, Docker containers, and multi-node P2P clusters.

---

## 1. Production Linux Tuning

Apply the following sysctl kernel settings for high-throughput edge proxies (`/etc/sysctl.d/99-mango-waf.conf`):

```ini
# Maximum open file descriptors
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
```

Apply settings:
```bash
sudo sysctl -p /etc/sysctl.d/99-mango-waf.conf
```

---

## 2. Docker Compose Cluster Deployment

For multi-node setups using Docker Compose:

```yaml
version: '3.8'

services:
  mango-node-1:
    build: .
    container_name: mango-node-1
    cap_add:
      - CAP_BPF
      - CAP_PERFMON
      - CAP_NET_ADMIN
    volumes:
      - /sys/fs/bpf:/sys/fs/bpf
      - ./config/node-1.yaml:/etc/mango-waf/config.yaml:ro
    ports:
      - "80:80"
      - "443:443"
      - "9090:9090"
    environment:
      - MANGO_DASHBOARD_PASSWORD=${DASHBOARD_PASS}
      - MANGO_CLUSTER_SECRET_KEY=${CLUSTER_SECRET}
    restart: always
```
