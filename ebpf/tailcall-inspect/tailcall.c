//go:build ignore
#include "bpf_all.h"

/* It's to inspect some details about tailcall for such case:
 *
 * __noinline int
 * my_tailcall_fn(void *ctx, __u32 index)
 * {
 *   volatile int retval = -1;
 *
 *   bpf_tail_call(ctx, &jmp_table, index);
 *
 *   // my_tailcall_inspect(ctx, &jmp_table, index);
 *
 *   return retval;
 * }
 *
 * When fail to call bpf_tail_call(), it has to inspect the details about
 * tailcall by:
 *
 * __noinline void
 * my_tailcall_inspect(void *ctx, void *prog_array, __u32 index)
 * {
 *   bpf_printk("tailcall_inspect: ctx=%p prog_array=%p index=%u\n",
 *              ctx, prog_array, index);
 * }
 *
 * Then, use current inspect function to inspect the details about tailcall.
 *
 * With current inspect function, the stack layout is:
 *
 * +-------+ FP of entry
 * |  ...  |
 * |  var  | <- tcc read here
 * |  tcc  |
 * |  reg  |
 * |  reg  |
 * |  rip  | IP of entry
 * |  rbp  | FP of entry
 * +-------+ FP of my_tailcall
 * |  ...  |
 * |  var  | <- tcc read here
 * |  tcc  |
 * |  reg  |
 * |  reg  |
 * |  rip  | IP of my_tailcall
 * |  rip  | IP of my_tailcall_inspect
 * |  rbp  | FP of my_tailcall
 * +-------+ FP of trampoline
 * |  ...  |
 * |  arg  |
 * |  arg  |
 * |  arg  | <- ctx of tailcall_inspect
 * |  rip  | IP of trampoline
 * |  rbp  | FP of trampoline
 * +-------+ FP of tailcall_inspect
 * |  ...  |
 * +-------+ RSP of tailcall_inspect
 */

struct tramp_stack {
    __u64 fp;
    __u64 rip;
    __u64 args[3];
};

struct my_tailcall_stack {
    __u64 fp;
    __u64 rip[2];
    __u64 regs[2];
    __u64 tcc;
    __u64 var;
};

struct fentry_stack {
    __u64 fp;
    __u64 rip;
    __u64 regs[2];
    __u64 tcc;
    __u64 var;
};

SEC("fentry/my_tailcall_inspect")
int BPF_PROG(tailcall_inspect, void *tgt_ctx, void *prog_array, __u32 index)
{
    struct bpf_array *arr = (struct bpf_array *) prog_array;
    struct my_tailcall_stack my_tailcall;
    struct fentry_stack fentry;
    struct tramp_stack tramp;
    struct bpf_prog *prog;
    __u32 prog_id;
    __u64 fp;

    asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);
    bpf_probe_read_kernel(&prog, sizeof(prog), (const void *) (arr->ptrs + index));
    BPF_CORE_READ_INTO(&prog_id, prog, aux, id);

    bpf_probe_read_kernel(&tramp, sizeof(tramp), (const void *) fp);
    bpf_probe_read_kernel(&my_tailcall, sizeof(my_tailcall), (const void *) tramp.fp);
    bpf_probe_read_kernel(&fentry, sizeof(fentry), (const void *) my_tailcall.fp);

    bpf_printk("tailcall_inspect: ctx=%016llx prog_array=%016llx index=%d\n",
               tgt_ctx, prog_array, index);
    bpf_printk("tailcall_inspect: prog=%016llx prog_id=%d\n", prog, prog_id);
    bpf_printk("tailcall_inspect: trampoline: rip=%016llx args=%016llx %016llx\n",
               tramp.rip, tramp.args[0], tramp.args[1]);
    bpf_printk("tailcall_inspect: my_tailcall: rip=%016llx %016llx regs=%016llx\n",
               my_tailcall.rip[0], my_tailcall.rip[1], my_tailcall.regs[0]);
    bpf_printk("tailcall_inspect: my_tailcall: tcc=%016llx var=%016llx\n", my_tailcall.tcc, my_tailcall.var);
    bpf_printk("tailcall_inspect: fentry: rip=%016llx tcc=%016llx var=%016llx\n",
               fentry.rip, fentry.tcc, fentry.var);

    return 0;
}
