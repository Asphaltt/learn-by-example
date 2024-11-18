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
 * +-------+ FP of my_tailcall_fn
 * |  ...  |
 * |  tcc  |
 * |  reg  |
 * |  reg  |
 * |  rip  | IP of my_tailcall_fn
 * |  rip  | IP of my_tailcall_inspect
 * |  rbp  | FP of my_tailcall_fn
 * +-------+ FP of trampoline
 * |  ...  |
 * |  rip  | IP of trampoline
 * |  rbp  | FP of trampoline
 * +-------+ FP of tailcall_inspect
 * |  ...  |
 * +-------+ RSP of tailcall_inspect
 */

volatile const __u32 TCC_OFFSET; /* offset to FP of trampoline */

SEC("fentry/my_tailcall_inspect")
int BPF_PROG(tailcall_inspect, void *tgt_ctx, void *prog_array, __u32 index)
{
    struct bpf_array *arr = (struct bpf_array *) prog_array;
    struct bpf_prog *prog;
    __u32 tcc, prog_id;
    __u64 fp, tramp_fp;

    asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);
    bpf_probe_read_kernel(&tramp_fp, sizeof(tramp_fp), (const void *) fp);
    bpf_probe_read_kernel(&tcc, sizeof(tcc), (const void *) (tramp_fp + TCC_OFFSET));
    bpf_probe_read_kernel(&prog, sizeof(prog), (const void *) (arr->ptrs + index));
    BPF_CORE_READ_INTO(&prog_id, prog, aux, id);

    bpf_printk("tailcall_inspect: ctx=%p prog_array=%p index=%d tcc=%d prog=%p prog_id=%d\n",
               tgt_ctx, prog_array, index, tcc, prog, prog_id);

    return 0;
}
