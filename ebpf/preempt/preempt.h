#ifndef __PREEMPT_H__
#define __PREEMPT_H__

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define PREEMPT_BITS    8
#define SOFTIRQ_BITS    8
#define HARDIRQ_BITS    4
#define NMI_BITS        4

#define PREEMPT_SHIFT   0
#define SOFTIRQ_SHIFT   (PREEMPT_SHIFT + PREEMPT_BITS)
#define HARDIRQ_SHIFT   (SOFTIRQ_SHIFT + SOFTIRQ_BITS)
#define NMI_SHIFT       (HARDIRQ_SHIFT + HARDIRQ_BITS)

#define __IRQ_MASK(x)   ((1UL << (x))-1)

#define SOFTIRQ_MASK    (__IRQ_MASK(SOFTIRQ_BITS) << SOFTIRQ_SHIFT)
#define HARDIRQ_MASK    (__IRQ_MASK(HARDIRQ_BITS) << HARDIRQ_SHIFT)
#define NMI_MASK        (__IRQ_MASK(NMI_BITS)     << NMI_SHIFT)

volatile bool CONFIG_PREEMPT_RT;
#ifdef bpf_target_x86
volatile const u64 __preempt_count;
#endif

struct task_struct___preempt_rt {
        int softirq_disable_cnt;
} __attribute__((preserve_access_index));

static inline int get_preempt_count(void)
{
#if defined(bpf_target_x86)
        return *(int *) bpf_this_cpu_ptr((void *) 0xffffffff9966f030);
#elif defined(bpf_target_arm64)
        return bpf_get_current_task_btf()->thread_info.preempt.count;
#endif
        return 0;
}

/* Description
 *      Report whether it is in interrupt context. Only works on the following archs:
 *      * x86
 *      * arm64
 */
static inline int bpf_in_interrupt(void)
{
        struct task_struct___preempt_rt *tsk;
        int pcnt;

        pcnt = get_preempt_count();
        if (!CONFIG_PREEMPT_RT)
                return pcnt & (NMI_MASK | HARDIRQ_MASK | SOFTIRQ_MASK);

        tsk = (void *) bpf_get_current_task_btf();
        return (pcnt & (NMI_MASK | HARDIRQ_MASK)) |
               (tsk->softirq_disable_cnt & SOFTIRQ_MASK);
}

#endif
