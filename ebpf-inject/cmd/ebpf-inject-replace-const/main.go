package main

import (
	"bytes"
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

//go:embed ebpf-inject-replace-const.elf
var bpfElf []byte

func mustDo(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func must[T any](t T, err error) T {
	if err != nil {
		log.Fatalln(err)
	}
	return t
}

func attachTcEgress(ifindex int, bpfProgFd int) error {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return err
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifindex),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %d: %v\n", ifindex, err)
		return err
	}
	// when deleting the qdisc, the applied filter will also be gone
	defer tcnl.Qdisc().Delete(&qdisc)

	fd := uint32(bpfProgFd)
	flags := uint32(0x1)

	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifindex),
			Handle:  1,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
			Info:    0x300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}

	if err := tcnl.Filter().Replace(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not attach filter for eBPF program: %v\n", err)
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	<-ctx.Done()

	return nil
}

func attachBpfProg(ifindex int, targetAddr uint32, data []byte) error {
	var bpfObj struct {
		Prog *ebpf.Program `ebpf:"filter_out"`
	}

	bpfSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return err
	}

	for _, prog := range bpfSpec.Programs {
		prog.Type = ebpf.SchedCLS
	}

	// update target address
	for _, prog := range bpfSpec.Programs {
		for i := range prog.Instructions {
			if prog.Instructions[i].Constant == 0xFEDCBA98 {
				prog.Instructions[i].Constant = int64(targetAddr)
			}
		}
	}

	if err := bpfSpec.LoadAndAssign(&bpfObj, nil); err != nil {
		return err
	}

	return attachTcEgress(ifindex, bpfObj.Prog.FD())
}

func main() {
	var targetIP, targetDev string
	flag.StringVar(&targetIP, "ip", "8.8.4.4", "target IP address")
	flag.StringVar(&targetDev, "dev", "enp1s0", "target device")
	flag.Parse()

	netIP := net.ParseIP(targetIP).To4()
	if netIP == nil {
		log.Fatal("invalid IP address")
	}

	ifi := must(net.InterfaceByName(targetDev))

	netNum := *(*uint32)(unsafe.Pointer(&netIP[0]))
	mustDo(attachBpfProg(ifi.Index, netNum, bpfElf))
}
