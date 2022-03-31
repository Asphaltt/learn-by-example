#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

char _license[] SEC("license") = "GPL";

struct rule_struct {
  __u64 key;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16);
  __type(key, u32);
  __type(value, struct rule_struct);
} filter_saddrs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16);
  __type(key, u32);
  __type(value, struct rule_struct);
} filter_daddrs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16);
  __type(key, struct rule_struct);
  __type(value, u32);
} filter_rules SEC(".maps");

SEC("socket")
int filter_iptables(void *skb) {
  struct iphdr iph;
  struct rule_struct result, *saddr, *daddr;
  u32 *res;

  if (bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph),
                                  BPF_HDR_START_NET) < 0)
    return BPF_OK;

  if (iph.protocol != IPPROTO_ICMP) return BPF_OK;

  bpf_printk("from ebpf acl, %8x -> %8x\n", iph.saddr, iph.daddr);

  saddr = bpf_map_lookup_elem(&filter_saddrs, &iph.saddr);
  if (saddr == NULL) return BPF_OK;

  daddr = bpf_map_lookup_elem(&filter_daddrs, &iph.daddr);
  if (daddr == NULL) return BPF_OK;

  result.key = saddr->key & daddr->key;
  result.key = result.key & ((~result.key) + 1);  // get the very first bit

  res = bpf_map_lookup_elem(&filter_rules, &result);
  if (res != NULL && *res == 1) return BPF_DROP;

  return BPF_OK;
}