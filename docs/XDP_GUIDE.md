# eBPF / XDP Hardware Packet Filtering Guide — Mango Shield WAF

**Mango Shield** uses eBPF (Extended Berkeley Packet Filter) and XDP (eXpress Data Path) to drop malicious traffic directly inside the Linux network driver before network packets reach the TCP/IP stack or Go application layer. This provides high-throughput DDoS packet filtering capability (10M+ RPS).

---

## 1. How XDP Works in Mango Shield

```
Network Interface (NIC / eth0)
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│ Kernel XDP Filter (xdp/mango_xdp.c)                     │
│ Checks Source IP against BPF Hash Map (mango_blacklist) │
└─────────────┬─────────────────────────────┬─────────────┘
              │                             │
    Match (Banned IP)               No Match (Clean)
              │                             │
              ▼                             ▼
        [XDP_DROP]                    [XDP_PASS]
(Dropped at NIC driver)       (Passes to TCP/IP Stack -> Go WAF)
```

1. **Kernel Program (`xdp/mango_xdp.c`)**: Attached to network interface (e.g. `eth0`). Parses Ethernet, 802.1Q/802.1ad VLAN, and IPv4 headers. Performs zero-overhead lookup in the `blacklist` BPF HASH map.
2. **BPF Map Pinning (`/sys/fs/bpf/mango_blacklist`)**: Persistent BPF map stored in kernel `bpffs`.
3. **Zero-Fork Go Interface (`core/xdp.go`)**: Go application accesses the map via direct Linux `sys_bpf` kernel syscalls (`bpfObjGet`, `bpfMapUpdateElem`, `bpfMapDeleteElem`) under 200 nanoseconds per IP update.

---

## 2. Enabling XDP in Configuration

In `config/production.yaml` (or `config/default.yaml`):

```yaml
xdp:
  enabled: true                      # Enable eBPF/XDP subsystem
  interface: "eth0"                  # Network interface name
  mode: "skb"                        # Mode: "skb" (generic) | "drv" (native) | "hw" (offload)
  map_pin_path: "/sys/fs/bpf/mango_blacklist"
  auto_compile: true                 # Auto-compile xdp/mango_xdp.c using clang if object missing
  auto_attach: true                  # Auto-attach XDP filter on startup
```

---

## 3. Verification Commands

### 3.1 Verify XDP Interface Attachment
```bash
# Check if XDP program is attached to interface
ip link show dev eth0 | grep -i xdp

# Expected output (skb or drv mode):
# 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric/id:123 ...
```

### 3.2 Inspect BPF Map & Blacklisted IPs
```bash
# Inspect pinned BPF map
bpftool map show name blacklist

# Dump all banned IPs stored in the map
bpftool map dump name blacklist
```

### 3.3 Verify WAF Telemetry API Output
```bash
# Query Dashboard Stats API
curl -s http://127.0.0.1:9090/api/stats | jq '{xdp_enabled, xdp_banned_ips, xdp_dropped_pkts}'

# Expected output:
# {
#   "xdp_enabled": true,
#   "xdp_banned_ips": 1,
#   "xdp_dropped_pkts": 450
# }
```

### 3.4 Test Packet Drops
```bash
# 1. Ban an IP via CLI or WAF pipeline
sudo ./mango-shield -config config/production.yaml

# 2. Perform ping or curl from the banned IP
curl -v https://firewall.hidev.dev/

# Output: Connection times out (packets dropped at NIC layer by XDP_DROP)
```

---

## 4. Detaching & Removing XDP

To manually remove the XDP filter from the network interface:

```bash
# Detach XDP filter from eth0
sudo ip link set dev eth0 xdp off

# Unpin BPF map from bpffs
sudo rm -f /sys/fs/bpf/mango_blacklist
```

---

## 5. Troubleshooting & Requirements

| Issue | Cause | Resolution |
| :--- | :--- | :--- |
| `XDP requires root / CAP_BPF` | Process running as non-root without eBPF capabilities | Run as `root` or add `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_SYS_ADMIN` |
| `/sys/fs/bpf: No such file` | `bpffs` filesystem not mounted | Run `sudo mount -t bpf bpffs /sys/fs/bpf` |
| `Operation not supported` | NIC driver doesn't support native XDP | Set `mode: "skb"` in config to use XDP generic mode |
| `bpftool: command not found` | `bpftool` package missing | Install `bpftool` (`apt install linux-tools-generic` or `apk add bpftool`) |
