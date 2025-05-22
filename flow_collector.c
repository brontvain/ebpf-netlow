#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <linux/in.h>

struct flow_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

BPF_HASH(flows, struct flow_t, __u64);

int xdp_flow_collector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct flow_t flow = {};
    flow.src_ip = ip->saddr;
    flow.dst_ip = ip->daddr;
    flow.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        flow.src_port = tcp->source;
        flow.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        flow.src_port = udp->source;
        flow.dst_port = udp->dest;
    } else {
        flow.src_port = 0;
        flow.dst_port = 0;
    }

    __u64 zero = 0, *count;
    count = flows.lookup_or_init(&flow, &zero);
    if (count) {
        (*count)++;
    }
    return XDP_PASS;
} 