//go:build ignore
#include "bpf_all.h"

#define LATENCY_MS 200
#define DELAY_CIDR_CAPACITY 128

/* Internet Control Message Protocol	*/
#define IPPROTO_ICMP 1

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} xdp_sockets SEC(".maps");

struct delay_cidr {
    __u32 start;
    __u32 end;
};

typedef struct {
    struct delay_cidr cidrs[DELAY_CIDR_CAPACITY];
} delay_cidrs_t;

static const volatile delay_cidrs_t delay_cidrs;
static const volatile __u32 delay_cidrs_len = 0;

#ifdef __USE_LOOP

struct delay_ctx {
    __u32 lo, hi;
    __u32 ip;
    bool found;
};

static long loop_delay_cidrs(__u32 index, struct delay_ctx *ctx)
{
    if (!ctx)                               // It's required to check NULL ctx.
        return 1;

    if (ctx->lo > ctx->hi)                  // Checking lo > hi for the end of binary search.
        return 1;

    __u32 mid = (ctx->lo + ctx->hi) >> 1;
    if (mid >= DELAY_CIDR_CAPACITY)         // It's required to do bound check for mid.
        return 1;

    struct delay_cidr *cidr = (typeof(cidr))&delay_cidrs.cidrs[mid];
    if (ctx->ip >= cidr->start && ctx->ip <= cidr->end) {
        ctx->found = true;
        return 1;
    }

    if (ctx->ip < cidr->start) {
        ctx->hi = mid - 1;
    } else {
        ctx->lo = mid + 1;
    }

    return 0;
}

static __always_inline bool
__should_delay_sip(__be32 ip)
{
    struct delay_ctx ctx = {
        .lo = 0,
        .hi = delay_cidrs_len - 1,
        .ip = bpf_ntohl(ip),
        .found = false,
    };

    bpf_loop(32, loop_delay_cidrs, &ctx, 0);

    return ctx.found;
}

#else

static __always_inline bool
__should_delay_sip(__be32 ip)
{
    __u32 lo = 0;
    volatile __u32 hi = delay_cidrs_len - 1;    // Note: volatile is to avoid reusing R2 register.
    __u32 addr = bpf_ntohl(ip);

#pragma clang loop unroll(full)                 // It's optional to use unroll pragma. Or the verifier will take long time to emulate this loop.
    for (int i = 0; i < 32; i++) {
        if (lo > hi)                            // Checking lo > hi for the end of binary search.
            return false;

        __u32 mid = (lo + hi) >> 1;
        if (mid >= DELAY_CIDR_CAPACITY)         // It's required to do bound check for mid.
            return false;

        struct delay_cidr *cidr = (typeof(cidr))&delay_cidrs.cidrs[mid];
        if (addr >= cidr->start && addr <= cidr->end) {
            return true;
        }

        if (addr < cidr->start) {
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }

    return false;
}

#endif // __USE_LOOP

SEC("xdp")
int xdp_fn(struct xdp_md *ctx)
{
    void *data = ctx_ptr(ctx, data);
    void *data_end = ctx_ptr(ctx, data_end);

    struct ethhdr *eth;
    eth = (typeof(eth))data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph;
    iph = (typeof(iph))(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    struct icmphdr *ih;
    ih = (typeof(ih))((void *)iph + (iph->ihl * 4));
    if ((void *)(ih + 1) > data_end)
        return XDP_PASS;

    if (ih->type != ICMP_ECHO)
        return XDP_PASS;

    if (!__should_delay_sip(iph->saddr))
        return XDP_PASS;

    __u32 *val;
    const int siz = sizeof(*val);

    if (bpf_xdp_adjust_meta(ctx, -siz) != 0)
        return XDP_PASS;

    data = ctx_ptr(ctx, data); // required to re-obtain data pointer
    void *data_meta = ctx_ptr(ctx, data_meta);

    val = (typeof(val))data_meta;
    if ((void *)(val + 1) > data)
        return XDP_PASS;

    *val = LATENCY_MS;

    return bpf_redirect_map(&xdp_sockets, 0, 0);
}