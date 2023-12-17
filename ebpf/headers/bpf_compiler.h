#ifndef __BPF_COMPILER_H__
#define __BPF_COMPILER_H__

#include "vmlinux.h"

#include "bpf_helpers.h"

#ifndef barrier
#define barrier() asm volatile("" \
                               :  \
                               :  \
                               : "memory")
#endif

#ifndef barrier_data
#define barrier_data(ptr) asm volatile(""         \
                                       :          \
                                       : "r"(ptr) \
                                       : "memory")
#endif

static __always_inline void bpf_barrier(void)
{
    /* Workaround to avoid verifier complaint:
     * "dereference of modified ctx ptr R5 off=48+0, ctx+const is allowed,
     *        ctx+const+const is not"
     */
    barrier();
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))
#endif

#ifndef __READ_ONCE
#define __READ_ONCE(X) (*(volatile typeof(X) *)&X)
#endif

#ifndef __WRITE_ONCE
#define __WRITE_ONCE(X, V) (*(volatile typeof(X) *)&X) = (V)
#endif

/* {READ,WRITE}_ONCE() with verifier workaround via bpf_barrier(). */

#ifndef READ_ONCE
#define READ_ONCE(X) \
    ({ typeof(X) __val = __READ_ONCE(X);	\
			   bpf_barrier();			\
			   __val; })
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(X, V) \
    ({ typeof(X) __val = (V);	\
				   __WRITE_ONCE(X, __val);	\
				   bpf_barrier();		\
				   __val; })
#endif

#ifndef __inline
#define __inline inline __attribute__((always_inline))
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif /* likely */

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif /* unlikely */

#define _ntohl __builtin_bswap32
#define _htonl __builtin_bswap32
#define _htons __builtin_bswap16
#define _ntohs __builtin_bswap16

struct vxlan_hdr {

    __be32 vx_flags;
    __be32 vx_vni;

} __attribute__((packed));

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TOS_OFF (ETH_HLEN + offsetof(struct iphdr, tos))

#endif /* __BPF_COMPILER_H__ */
