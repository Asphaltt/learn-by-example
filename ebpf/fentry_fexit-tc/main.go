// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"internal/pkg/bpf"
	_tc "internal/pkg/tc"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	nl "github.com/mdlayher/netlink"
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang fftc ./tc.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach tc-bpf program")
	flag.Parse()

	ifi, err := netlink.LinkByName(device)
	if err != nil {
		log.Fatalf("Failed to get link by name: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadFftc()
	if err != nil {
		log.Fatalf("Failed to load tcpconn bpf spec: %v", err)
		return
	}

	tcDummy := spec.Programs["dummy"]
	dummyProg, err := ebpf.NewProgram(tcDummy)
	if err != nil {
		log.Fatalf("Failed to create dummy program: %v", err)
	}
	defer dummyProg.Close()

	// get function name by dummy program
	funcName, err := bpf.GetProgEntryFuncName(dummyProg)
	if err != nil {
		funcName = "dummy"
		log.Printf("Failed to get dummy program name: %v. Use %s instead", err, funcName)
	}

	tcFentry := spec.Programs["fentry_tc"]
	tcFentry.AttachTarget = dummyProg
	tcFentry.AttachTo = funcName
	tcFexit := spec.Programs["fexit_tc"]
	tcFexit.AttachTarget = dummyProg
	tcFexit.AttachTo = funcName

	var obj fftcObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Fatalf("Failed to load bpf obj: %v", err)
		}
	}
	defer obj.Close()

	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		log.Printf("Failed to open rtnetlink: %v", err)
		return
	}
	defer rtnl.Close()

	if err := rtnl.SetOption(nl.ExtendedAcknowledge, true); err != nil {
		log.Printf("Failed to set extended acknowledge: %v", err)
		return
	}

	tcQdiscObj := tc.Object{
		Msg: tc.Msg{
			Family:  syscall.AF_UNSPEC,
			Ifindex: uint32(ifi.Attrs().Index),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: "ingress",
		},
	}
	if err := rtnl.Qdisc().Replace(&tcQdiscObj); err != nil {
		log.Printf("Failed to replace ingress qdisc: %v", err)
		return
	}
	defer rtnl.Qdisc().Delete(&tcQdiscObj)

	htons := func(n uint16) uint16 {
		b := *(*[2]byte)(unsafe.Pointer(&n))
		return binary.BigEndian.Uint16(b[:])
	}

	progFD := uint32(dummyProg.FD())
	annotation := "dummy"
	tcFlags := uint32(tc.BpfActDirect)

	tcFilterObj := tc.Object{
		Msg: tc.Msg{
			Family:  syscall.AF_UNSPEC,
			Ifindex: uint32(ifi.Attrs().Index),
			Handle:  0xFFFFFFF1,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    10<<16 | uint32(htons(unix.ETH_P_ALL)),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &progFD,
				Name:  &annotation,
				Flags: &tcFlags,
			},
		},
	}
	if err := rtnl.Filter().Replace(&tcFilterObj); err != nil {
		log.Printf("Failed to replace tc filter: %v", err)
		return
	}
	defer rtnl.Filter().Delete(&tcFilterObj)

	if link, err := link.AttachTracing(link.TracingOptions{
		Program: obj.FentryTc,
	}); err != nil {
		log.Printf("Failed to attach fentry(tc): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fentry(tc)")
	}

	// attach fexit(tc) to the device
	if link, err := link.AttachTracing(link.TracingOptions{
		Program: obj.FexitTc,
	}); err != nil {
		log.Printf("Failed to attach fexit(tc): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fexit(tc)")
	}

	go handlePerfEvent(ctx, obj.Events)

	<-ctx.Done()
}

func handlePerfEvent(ctx context.Context, events *ebpf.Map) {
	eventReader, err := perf.NewReader(events, 4096)
	if err != nil {
		log.Printf("Failed to create perf-event reader: %v", err)
		return
	}

	log.Printf("Listening events...")

	go func() {
		<-ctx.Done()
		eventReader.Close()
	}()

	var ev struct {
		Saddr, Daddr [4]byte
		ProbeType    uint8
		Verdict      _tc.Action
		Pad          uint16
	}
	for {
		event, err := eventReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			log.Printf("Reading perf-event: %v", err)
		}

		if event.LostSamples != 0 {
			log.Printf("Lost %d events", event.LostSamples)
		}

		binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev)

		switch ev.ProbeType {
		case 1:
			log.Printf("Tracing packet: %s -> %s (fentry)",
				netip.AddrFrom4(ev.Saddr),
				netip.AddrFrom4(ev.Daddr))
		case 2:
			log.Printf("Tracing packet: %s -> %s (fexit: %s)",
				netip.AddrFrom4(ev.Saddr),
				netip.AddrFrom4(ev.Daddr), ev.Verdict)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
