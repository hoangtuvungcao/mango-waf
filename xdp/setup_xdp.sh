#!/bin/bash
# Mango Shield - eBPF/XDP Setup Script
# Run this on your VPS to compile and attach the XDP filter to your network interface.

set -e

# 1. Install necessary compile tools
echo "[*] Installing eBPF dependencies (clang, llvm, libbpf)..."
if [ -x "$(command -v apt-get)" ]; then
    sudo apt-get update
    sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) gcc make
    sudo apt-get install -y linux-tools-common linux-tools-generic || true
elif [ -x "$(command -v dnf)" ]; then
    sudo dnf install -y clang llvm libbpf-devel kernel-headers bpftool gcc make
else
    echo "[!] Unsupported OS package manager. Please manually install: clang, llvm, libbpf-dev, bpftool."
    exit 1
fi

echo "[*] eBPF dependencies loaded successfully."

# Link bpftool if it's in a kernel-specific path
if ! command -v bpftool &>/dev/null; then
    ANY_BPFTOOL=$(find /usr/lib/linux-tools -name "bpftool" | head -n 1)
    if [ -n "$ANY_BPFTOOL" ]; then
        echo "[*] Found bpftool at $ANY_BPFTOOL, linking to /usr/local/bin/bpftool"
        sudo ln -sf "$ANY_BPFTOOL" /usr/local/bin/bpftool
    else
        # Try to find it anywhere else
        ANY_BPFTOOL=$(find /usr -name "bpftool" -type f -executable 2>/dev/null | head -n 1)
        if [ -n "$ANY_BPFTOOL" ]; then
            echo "[*] Found bpftool at $ANY_BPFTOOL, linking to /usr/local/bin/bpftool"
            sudo ln -sf "$ANY_BPFTOOL" /usr/local/bin/bpftool
        fi
    fi
fi

# 2. Find Network Interface Name
NIC=$(ip route show default | awk '/default/ {print $5}')
echo "[*] Detected external network interface: $NIC"

# 3. Compile the C code into eBPF object format
echo "[*] Compiling mango_xdp.c to BPF ELF object..."
ARCH_PATH="/usr/include/$(uname -m)-linux-gnu"
clang -O2 -g -target bpf -c mango_xdp.c -o mango_xdp.o -I$ARCH_PATH -I/usr/include

# 4. Attach the compiled XDP BPF object to the Network Interface (NIC)
echo "[*] Attaching XDP filter to $NIC..."
if [ -z "$NIC" ]; then
    echo "[!] Error: Could not detect network interface."
    exit 1
fi
sudo ip link set dev "$NIC" xdp off 2>/dev/null || true
sudo ip link set dev "$NIC" xdpgeneric off 2>/dev/null || true
sudo ip link set dev "$NIC" xdpgeneric obj mango_xdp.o sec xdp_mango

echo "
===================================================
✅ M A N G O   S H I E L D   --   X D P   A C T I V E
===================================================
The Kernel-level packet filter (10M RPS) has been attached to interface \$NIC.

To remove it, run:
  sudo ip link set dev \$NIC xdp off

To manage banned IPs, you can use bpftool or interact via the Go application later.
==================================================="
