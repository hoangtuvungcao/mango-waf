#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

// BPF Map for banned IPv4 addresses (Key: uint32 IPv4 Little-Endian, Val: uint64 drop count)
struct bpf_map_def SEC("maps") blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1000000,
    .map_flags = 0,
};

// Main XDP program entry point
SEC("xdp_mango")
int xdp_drop_banned(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Check Ethernet header bounds
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    void *l3_hdr = (void *)(eth + 1);

    // 2. Parse L2 / 802.1Q / 802.1ad VLAN tags (up to 2 nested VLAN headers)
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(0x88A8) || h_proto == bpf_htons(0x9100)) {
            struct vlan_hdr {
                __be16 tci;
                __be16 encap_proto;
            } *vlan = l3_hdr;

            if ((void *)(vlan + 1) > data_end)
                return XDP_PASS;

            h_proto = vlan->encap_proto;
            l3_hdr = (void *)(vlan + 1);
        }
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 3. Inspect IPv4 header bounds
    struct iphdr *ip = l3_hdr;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 4. Extract Source IPv4 address
    __u32 src_ip = ip->saddr;

    // 5. Query BPF blacklist HASH map FIRST (Fastest O(1) path for clean traffic)
    __u64 *drop_count = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (drop_count) {
        // Bypass SSH (Port 22) to prevent accidental admin lockout
        if (ip->protocol == IPPROTO_TCP) {
            __u32 ihl = ip->ihl * 4;
            if (ihl >= 20 && ihl <= 60) {
                struct tcphdr {
                    __be16 source;
                    __be16 dest;
                } *tcp = (void *)ip + ihl;

                if ((void *)(tcp + 1) <= data_end) {
                    if (tcp->dest == bpf_htons(22)) {
                        return XDP_PASS;
                    }
                }
            }
        }

        // Drop packet at NIC driver layer and increment drop counter atomically
        __sync_fetch_and_add(drop_count, 1);
        return XDP_DROP;
    }

    return XDP_PASS; // Pass clean traffic to Linux kernel TCP/IP stack
}

char _license[] SEC("license") = "GPL";
