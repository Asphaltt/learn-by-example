// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"internal/assert"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang fentry ./fentry.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove memlock: %v")

	var obj fentryObjects
	err := loadFentryObjects(&obj, nil)
	assert.NoVerifierErr(err, "Failed to load fentry objects: %v")
	defer obj.Close()

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    obj.FentryIcmpRcv,
		AttachType: ebpf.AttachTraceFEntry,
	})
	assert.NoErr(err, "Failed to attach fentry program: %v")
	defer l.Close()

	l, err = link.AttachTracing(link.TracingOptions{
		Program:    obj.FentryTcpConnect,
		AttachType: ebpf.AttachTraceFEntry,
	})
	assert.NoErr(err, "Failed to attach fentry program: %v")
	defer l.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()

	var runICMP, inInterruptICMP uint32
	err = obj.RunIcmp.Get(&runICMP)
	assert.NoErr(err, "Failed to get run value: %v")
	err = obj.InInterruptIcmpRcv.Get(&inInterruptICMP)
	assert.NoErr(err, "Failed to get in_interrupt value: %v")

	var runTCP, inInterruptTCP uint32
	err = obj.RunTcp.Get(&runTCP)
	assert.NoErr(err, "Failed to get run value: %v")
	err = obj.InInterruptTcpConnect.Get(&inInterruptTCP)
	assert.NoErr(err, "Failed to get in_interrupt value: %v")

	log.Printf("Run ICMP: %d, In Interrupt ICMP: %d", runICMP, inInterruptICMP)
	log.Printf("Run TCP: %d, In Interrupt TCP: %d", runTCP, inInterruptTCP)
}
