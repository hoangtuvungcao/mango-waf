# Architecture Specification - Mango Shield WAF

This document outlines the internal system architecture, eBPF map mechanics, pipeline flow, and concurrency design of **Mango Shield WAF**.

---

## 1. Multi-Layer Protection Pipeline

```
Incoming Request (TCP / L4 / L7)
        │
  [Layer 0: eBPF / XDP Hardware Drop (Kernel NIC Layer)]
        │ (XDP_PASS)
  [Layer 1: Connection Rate & Concurrency Limiter]
        │
  [Layer 2: IP Whitelist & Trusted Proxy Validation]
        │
  [Layer 3: TLS Fingerprint Extraction (JA3 / JA4)]
        │
  [Layer 4: Request Sanity & Protocol Enforcement]
        │
  [Layer 5: IP Reputation & GeoIP Intelligence]
        │
  [Layer 6: WAF Rule Engine (OWASP CRS RE2 Engine)]
        │
  [Layer 7: Challenge Verification (JS PoW / Turnstile)]
        │
  [Layer 8: CDN Smart RAM Cache (Ristretto)]
        │
  [Layer 9: Upstream Load Balancer & Reverse Proxy]
```

---

## 2. Kernel eBPF / XDP Hardware Dropping

Mango Shield integrates hardware-level packet dropping via XDP (`xdp/mango_xdp.c`). Banned IPv4 addresses are stored in a BPF Hash Map (`blacklist`).

### Native Zero-Fork Syscall Architecture
Instead of invoking `bpftool` per ban operation, `core/xdp.go` accesses the BPF map directly via Linux kernel syscalls:
- **`bpfObjGet("/sys/fs/bpf/mango_blacklist")`**: Opens the pinned BPF map file descriptor (`mapFD`).
- **`bpfMapUpdateElem(mapFD, &key, &val)`**: Executes opcode `SYS_BPF` directly in Go memory (`<200ns` execution cost).

### VLAN Packet Parsing
`xdp/mango_xdp.c` parses Ethernet frames with single (`0x8100`) or double (`0x88A8` QinQ) 802.1Q VLAN tags prior to inspecting IPv4 headers:

```c
struct vlan_hdr *vlan = (void *)(eth + 1);
if (eth->h_proto == bpf_htons(ETH_P_8021Q) || eth->h_proto == bpf_htons(ETH_P_8021AD)) {
    if ((void *)(vlan + 1) > data_end) return XDP_PASS;
    h_proto = vlan->h_vlan_encapsulated_proto;
}
```

---

## 3. Concurrency & Goroutine Lifecycle Model

- **`Shield.httpServer` & `Shield.redirectServer`**: Managed HTTP listeners equipped with `context.WithTimeout` graceful shutdown.
- **`IPRateLimiter` Cleanup Routine**: Evicts stale token buckets (>10m idle) without resetting active token limits.
- **`UpstreamManager` Lock Strategy**: Reads backend state under `RLock()`, performs HTTP GET health checks outside the mutex lock, and locks `Lock()` only for state transitions.
