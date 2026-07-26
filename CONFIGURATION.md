# Configuration Reference - Mango Shield WAF

Mango Shield utilizes YAML configuration files. All sensitive options can be overridden using environment variables prefixed with `MANGO_`.

---

## Environment Variable Overrides

| Environment Variable | YAML Target Key | Description |
|---|---|---|
| `MANGO_SERVER_LISTEN` | `server.listen` | HTTPS listen address |
| `MANGO_SERVER_HTTP_LISTEN` | `server.http_listen` | HTTP redirect listen address |
| `MANGO_PROTECTION_MODE` | `protection.mode` | Mode (`auto`, `challenge`, `block`, `monitor`) |
| `MANGO_PROTECTION_TRUSTED_PROXIES` | `protection.trusted_proxies` | Comma-separated trusted proxy CIDRs |
| `MANGO_DASHBOARD_PASSWORD` | `dashboard.password` | Admin dashboard password |
| `MANGO_ALERTS_TELEGRAM_TOKEN` | `alerts.telegram.token` | Telegram bot token |
| `MANGO_CLUSTER_SECRET_KEY` | `cluster.secret_key` | Gossip cluster encryption key |

---

## Detailed YAML Schema Reference

### `server` Section
```yaml
server:
  listen: "0.0.0.0:443"        # HTTPS listen socket
  http_listen: "0.0.0.0:80"    # HTTP to HTTPS redirect socket
  read_timeout: 10s            # Connection read timeout (Slowloris protection)
  write_timeout: 30s           # Response write timeout
  idle_timeout: 120s           # Connection keep-alive idle timeout
  max_header_bytes: 65536      # Maximum HTTP request header size (64KB)
```

### `tls` Section
```yaml
tls:
  enabled: true
  cert_file: "/etc/letsencrypt/live/example.com/fullchain.pem"
  key_file: "/etc/letsencrypt/live/example.com/privkey.pem"
  min_version: "1.2"           # Minimum TLS version ("1.2" or "1.3")
```

### `protection` Section
```yaml
protection:
  mode: "auto"                 # "auto", "challenge", "block", "monitor"
  trusted_proxies:
    - "127.0.0.1/32"
    - "10.0.0.0/8"
  whitelist_ips:
    - "192.168.1.100"
  rate_limit:
    enabled: true
    requests_per_sec: 100
    burst: 200
  challenge:
    pow_difficulty: 3          # Leading hex zero count for SHA-256 PoW (default=3)
    cookie_secret: ""          # Dynamic HMAC cookie key (auto-generated if empty)
  ban:
    duration: 30m              # Ban duration (e.g. 30m, 1h)
```

### `dashboard` Section
```yaml
dashboard:
  enabled: true
  listen: "0.0.0.0:9090"
  username: "admin"
  password: ""                 # Set via MANGO_DASHBOARD_PASSWORD env var
```

### `xdp` Section (Kernel eBPF/XDP Acceleration)
```yaml
xdp:
  enabled: true                      # Enable eBPF/XDP kernel packet dropping
  interface: "eth0"                  # Target network interface
  mode: "skb"                        # "skb" (generic) | "drv" (native) | "hw" (offload)
  map_pin_path: "/sys/fs/bpf/mango_blacklist" # Pinned BPF map location
  auto_compile: true                 # Auto-compile xdp/mango_xdp.c if object missing
  auto_attach: true                  # Auto-attach XDP filter on server startup
```

### `cluster` Section
```yaml
cluster:
  enabled: false
  node_name: "mango-node-1"
  bind_port: 7946
  advertise_ip: "103.77.246.172"
  secret_key: ""              # Set via MANGO_CLUSTER_SECRET_KEY env var
  join_peers:
    - "103.77.246.153:7946"
```
