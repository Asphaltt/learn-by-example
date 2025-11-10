//go:build ignore

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"

char _license[] SEC("license") = "GPL";

extern void css_rstat_flush(struct cgroup_subsys_state *css) __weak __ksym;

static inline struct cftype *of_cft(struct kernfs_open_file *of)
{
	return of->kn->priv;
}

struct cgroup_subsys_state *of_css(struct kernfs_open_file *of)
{
	struct cgroup *cgrp = of->kn->parent->priv;
	struct cftype *cft = of_cft(of);

	/*
	 * This is open and unprotected implementation of cgroup_css().
	 * seq_css() is only called from a kernfs file operation which has
	 * an active reference on the file.  Because all the subsystem
	 * files are drained before a css is disassociated with a cgroup,
	 * the matching css from the cgroup's subsys table is guaranteed to
	 * be and stay valid until the enclosing operation is complete.
	 */
	if (cft->ss)
		return cgrp->subsys[cft->ss->id];
	else
		return &cgrp->self;
}

static inline struct cgroup_subsys_state *seq_css(struct seq_file *seq)
{
	return of_css(seq->private);
}

SEC("fentry/memory_stat_show")
int BPF_PROG(memory_stat_show, struct seq_file *seq, void *v)
{
    struct cgroup_subsys_state *css = seq_css(seq);

    if (css)
        css_rstat_flush(css);

    return 0;
}