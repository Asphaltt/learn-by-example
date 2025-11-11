//go:build ignore

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"

char _license[] SEC("license") = "GPL";

extern void css_rstat_flush(struct cgroup_subsys_state *css) __weak __ksym;

SEC("tp_btf/memcg_flush_stats")
int BPF_PROG(memcg_flush_stats, struct mem_cgroup *memcg, s64 stats_updates, bool force, bool needs_flush)
{
	if (!force || !needs_flush) {
		css_rstat_flush(&memcg->css);
		__bpf_vprintk("memcg_flush_stats: memcg id=%d, stats_updates=%lld, force=%d, needs_flush=%d\n",
					  memcg->id.id, stats_updates, force, needs_flush);
	}
    return 0;
}