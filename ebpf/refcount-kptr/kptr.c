//go:build ignore
/**
 * Copyright 2025 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

#include "bpf_all.h"

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

/* Convenience macro to wrap over bpf_refcount_acquire_impl */
#define bpf_refcount_acquire(kptr) bpf_refcount_acquire_impl(kptr, NULL)

/* Convenience macro to wrap over bpf_obj_new_impl */
#define bpf_obj_new(type) ((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))
/* Convenience macro to wrap over bpf_obj_drop_impl */
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)

/* Convenience macro to wrap over bpf_list_push_front_impl */
#define bpf_list_push_front(head, node) bpf_list_push_front_impl(head, node, NULL, 0)

struct node_data {
    struct bpf_refcount refcount;
    int value;
    struct bpf_list_node l;
};

struct map_value {
    struct node_data __kptr *node;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, int);
    __type(value, struct map_value);
    __uint(max_entries, 1);
} pcap_hash SEC(".maps");

#define private(name) SEC(".bss." #name) __attribute__((aligned(8)))
#define __contains(name, node) __attribute__((btf_decl_tag("contains:" #name ":" #node)))

private(list) struct bpf_spin_lock lock;
private(list) struct bpf_list_head head __contains(node_data, l);

int run;
u64 node_data_ptr;

static long __insert_in__list(struct bpf_list_head *head,
                              struct bpf_spin_lock *lock,
                              struct map_value *v)
{
    struct node_data *n, *m;

    if (run)
        return 0;
    run = 1;

    n = bpf_obj_new(typeof(*n));
    if (!n)
            return -1;

    m = bpf_refcount_acquire(n);
    m->value = 42;

    bpf_spin_lock(lock);
    if (bpf_list_push_front(head, &m->l)) {
        /* Failure to insert - unexpected */
        bpf_spin_unlock(lock);
        return -3;
    }
    bpf_spin_unlock(lock);

    node_data_ptr = (u64)(void *) m;
    v->node = m;
    return 0;
}

SEC("fentry/__x64_sys_nanosleep")
int BPF_PROG(fentry__nanosleep)
{
    struct map_value *v;
    int key = 0;

    v = bpf_map_lookup_elem(&pcap_hash, &key);
    if (!v)
        return 0;

    __insert_in__list(&head, &lock, v);

    return 0;
}
