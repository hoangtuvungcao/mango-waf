#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

// Legacy bpf_map_def structure for iproute2 ELF BPF loader
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

// BPF Map for banned IPv4 addresses
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

    // 2. Parse L2 / 802.1Q / 802.1ad VLAN tags
    __u16 h_proto = eth->h_proto;
    void *l3_hdr = (void *)(eth + 1);

    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(0x88A8)) {
        struct vlan_hdr {
            __be16 tci;
            __be16 encap_proto;
        } *vlan = l3_hdr;

        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        h_proto = vlan->encap_proto;
        l3_hdr = (void *)(vlan + 1);
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 3. Inspect IPv4 header bounds
    struct iphdr *ip = l3_hdr;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 4. Extract Source IPv4 address
    __u32 src_ip = ip->saddr;

    // 5. Query BPF blacklist HASH map
    __u64 *drop_count = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (drop_count) {
        __sync_fetch_and_add(drop_count, 1);
        return XDP_DROP; // Discard packet at NIC layer
    }

    return XDP_PASS; // Pass clean traffic to Linux kernel stack
}

char _license[] SEC("license") = "GPL";
