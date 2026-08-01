#!/bin/bash
# Mango Shield - Kernel TCP Optimization for Millions of RPS
# Run this script as root to tune Linux sysctl for hardcore layer 7 DDoS mitigation.

echo "[*] Optimizing Linux TCP/IP stack for High Concurrency DDoS mitigation..."

cat <<EOF > /etc/sysctl.d/mango-waf.conf
# 1. Maximize Open Files & File Descriptors (Crucial for Millions of Connections)
fs.file-max = 2097152
fs.nr_open = 2097152
net.ipv4.tcp_max_tw_buckets = 2000000

# 2. Defend Against SYN Flood (Millions of spoofed packets)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_max_syn_backlog = 65536

# 3. Connection Tracking (Prevent nf_conntrack table full dropping legit traffic)
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15

# 4. Reclaim Sockets Instantly (Reduce TIME_WAIT states)
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# 5. Socket Buffers (Better network throughput under load)
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.core.optmem_max = 25165824
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
EOF

sysctl -p /etc/sysctl.d/mango-waf.conf

echo "[✓] Kernel networking parameters optimized for Mango Shield!"
echo "    - Raised max file descriptors to 2 Million"
echo "    - Enabled SYN Flood protections"
echo "    - Optimized socket reclaiming to prevent TIME_WAIT exhaustion"
