/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2020 Facebook */
/* "undefine" structs in vmlinux.h, because we "override" them below */
#define bpf_iter_meta bpf_iter_meta___not_used
#define bpf_iter__bpf_map bpf_iter__bpf_map___not_used
#define bpf_iter__ipv6_route bpf_iter__ipv6_route___not_used
#define bpf_iter__netlink bpf_iter__netlink___not_used
#define bpf_iter__task bpf_iter__task___not_used
#define bpf_iter__task_file bpf_iter__task_file___not_used
#define bpf_iter__task_vma bpf_iter__task_vma___not_used
#define bpf_iter__tcp bpf_iter__tcp___not_used
#define tcp6_sock tcp6_sock___not_used
#define bpf_iter__udp bpf_iter__udp___not_used
#define udp6_sock udp6_sock___not_used
#define bpf_iter__unix bpf_iter__unix___not_used
#define bpf_iter__bpf_map_elem bpf_iter__bpf_map_elem___not_used
#define bpf_iter__bpf_sk_storage_map bpf_iter__bpf_sk_storage_map___not_used
#define bpf_iter__sockmap bpf_iter__sockmap___not_used
#define bpf_iter__bpf_link bpf_iter__bpf_link___not_used
#define bpf_iter__cgroup bpf_iter__cgroup___not_used
#define btf_ptr btf_ptr___not_used
#define BTF_F_COMPACT BTF_F_COMPACT___not_used
#define BTF_F_NONAME BTF_F_NONAME___not_used
#define BTF_F_PTR_RAW BTF_F_PTR_RAW___not_used
#define BTF_F_ZERO BTF_F_ZERO___not_used
#define bpf_iter__ksym bpf_iter__ksym___not_used
#include "vmlinux.h"
#undef bpf_iter_meta
#undef bpf_iter__bpf_map
#undef bpf_iter__ipv6_route
#undef bpf_iter__netlink
#undef bpf_iter__task
#undef bpf_iter__task_file
#undef bpf_iter__task_vma
#undef bpf_iter__tcp
#undef tcp6_sock
#undef bpf_iter__udp
#undef udp6_sock
#undef bpf_iter__unix
#undef bpf_iter__bpf_map_elem
#undef bpf_iter__bpf_sk_storage_map
#undef bpf_iter__sockmap
#undef bpf_iter__bpf_link
#undef bpf_iter__cgroup
#undef btf_ptr
#undef BTF_F_COMPACT
#undef BTF_F_NONAME
#undef BTF_F_PTR_RAW
#undef BTF_F_ZERO
#undef bpf_iter__ksym
