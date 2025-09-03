//go:build ignore

#include "bpf_all.h"
#include "preempt.h"

int interrupt_cnt_igr;
int interrupt_cnt_egr;

SEC("tc/ingress")
int dummy_ingress(struct __sk_buff *skb)
{
    interrupt_cnt_igr = bpf_in_interrupt();
    return TCX_NEXT;
}

SEC("tc/egress")
int dummy_egress(struct __sk_buff *skb)
{
    interrupt_cnt_egr = bpf_in_interrupt();
    return TCX_NEXT;
}