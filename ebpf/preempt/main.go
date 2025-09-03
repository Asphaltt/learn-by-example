// SPDX-License-Identifier: MIT
// Copyright 2025 Leon Hwang.

package main

import (
	"bytes"
	"context"
	"internal/assert"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcx ./tcx.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach tc-bpf program")
	flag.Parse()

	ifi, err := netlink.LinkByName(device)
	assert.NoErr(err, "Failed to find link %s: %v", device)

	err = rlimit.RemoveMemlock()
	assert.NoErr(err, "Failed to remove rlimit memlock: %v")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadTcx()
	assert.NoErr(err, "Failed to load tcx spec: %v")

	err = spec.Variables["CONFIG_PREEMPT_RT"].Set(true)
	assert.NoErr(err, "Failed to set CONFIG_PREEMPT_RT: %v")

	out, err := exec.Command("grep", "D __preempt_count", "/proc/kallsyms").Output()
	assert.NoErr(err, "Failed to get __preempt_count symbol: %v")

	s, _, _ := bytes.Cut(out, []byte(" "))
	n, err := strconv.ParseUint(string(s), 16, 64)
	assert.NoErr(err, "Failed to parse __preempt_count address: %v")
	err = spec.Variables["__preempt_count"].Set(uint64(n))
	assert.NoErr(err, "Failed to set __preempt_count: %v")

	// Failed to run:
	/*
		load program: permission denied:
		        0: R1=ctx() R10=fp0
		        ; return *(int *) bpf_this_cpu_ptr((void *) 0xffffffff9966f030); @ preempt.h:36
		        0: (b7) r1 = -1721307088              ; R1_w=0xffffffff9966f030
		        1: (85) call bpf_this_cpu_ptr#154
		        R1 type=scalar expected=percpu_ptr_, percpu_rcu_ptr_, percpu_trusted_ptr_
		        processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
	*/

	var obj tcxObjects
	err = spec.LoadAndAssign(&obj, nil)
	assert.NoVerifierErr(err, "Failed to load tcx objs: %v")
	defer obj.Close()

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifi.Attrs().Index,
		Program:   obj.DummyIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	assert.NoErr(err, "Failed to attach tcx program: %v")
	defer l.Close()

	l, err = link.AttachTCX(link.TCXOptions{
		Interface: ifi.Attrs().Index,
		Program:   obj.DummyEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	assert.NoErr(err, "Failed to attach tcx program: %v")
	defer l.Close()

	log.Println("Attached tcx programs to", device, "interface")

	<-ctx.Done()

	var interruptCntIgr, interruptCntEgr uint32
	err = obj.InterruptCntIgr.Get(&interruptCntIgr)
	assert.NoErr(err, "Failed to get ingress interrupt count: %v")
	err = obj.InterruptCntEgr.Get(&interruptCntEgr)
	assert.NoErr(err, "Failed to get egress interrupt count: %v")

	log.Printf("Interrupt count (ingress): %#x", interruptCntIgr)
	log.Printf("Interrupt count (egress): %#x", interruptCntEgr)
}
