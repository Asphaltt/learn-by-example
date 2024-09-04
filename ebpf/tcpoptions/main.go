// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"internal/pkg/errx"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcp ./tcp.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang topt ./topt.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var iface, buf string
	flag.StringVarP(&iface, "iface", "i", "lo", "interface to attach")
	flag.StringVarP(&buf, "buf", "b", "Hello, world!", "a custom string that will be written to specific tcp option")
	flag.Parse()

	if len(buf) > 35 {
		log.Fatalf("buf length should be less than 36")
	}

	ifi, err := net.InterfaceByName(iface)
	errx.Check(err, "Failed to get interface by name (%s)", iface)

	errx.Check(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var tcpObjs tcpObjects
	errx.CheckVerifierErr(loadTcpObjects(&tcpObjs, nil), "Failed to load toa objects")
	defer tcpObjs.Close()

	spec, err := loadTopt()
	errx.Check(err, "Failed to load topt bpf spec")
	spec.Programs["topt"].AttachTarget = tcpObjs.XdpTops

	var opval [36]byte
	copy(opval[:], buf)
	opval[len(buf)] = 0
	err = spec.RewriteConstants(map[string]interface{}{
		"TARGET_OPCODE":    uint8(30),
		"TARGET_OPVAL":     opval,
		"TARGET_OPVAL_LEN": uint32(len(buf) + 1),
	})
	errx.Check(err, "Failed to rewrite constants")

	var toptObjs toptObjects
	errx.CheckVerifierErr(spec.LoadAndAssign(&toptObjs, &ebpf.CollectionOptions{}), "Failed to load topt objects")
	defer toptObjs.Close()

	l, err := link.AttachFreplace(tcpObjs.XdpTops, "option_parser", toptObjs.Topt)
	errx.Check(err, "Failed to attach freplace")
	defer l.Close()

	l, err = link.AttachXDP(link.XDPOptions{
		Program:   tcpObjs.XdpTops,
		Interface: ifi.Index,
	})
	errx.Check(err, "Failed to attach xdp(%s)", iface)
	defer l.Close()
	log.Printf("Attached xdp(%s)", iface)

	log.Println("Check TCP options by `cat /sys/kernel/debug/tracing/trace_pipe` ..")

	<-ctx.Done()
}
