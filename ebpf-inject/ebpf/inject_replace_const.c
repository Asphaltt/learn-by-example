#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_tc.h"

char _license[] SEC("license") = "GPL";

#define target_addr 0xFEDCBA98

SEC("egress")
int filter_out(void *skb) {
  struct iphdr iph;

  if (bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph),
                                  BPF_HDR_START_NET) < 0)
    return TC_ACT_OK;

  if (iph.protocol != IPPROTO_ICMP) return TC_ACT_OK;

  bpf_printk(
      "from ebpf inject-replace-const, 0x%08X -> 0x%08X, target 0x%08X\n",
      iph.saddr, iph.daddr, target_addr);

  if (iph.daddr == target_addr) return TC_ACT_SHOT;

  return TC_ACT_OK;
}