package main

import (
	"bytes"
	"context"
	"debug/elf"
	_ "embed"
	"encoding/binary"
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

//go:embed ebpf-inject-global-var.elf
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

type entry struct {
	off uint64
	val interface{}
}

func (e *entry) get(data []byte, size uint64, bo binary.ByteOrder) {
	switch size {
	case 1:
		e.val = data[0]
	case 2:
		e.val = bo.Uint16(data[:2])
	case 4:
		e.val = bo.Uint32(data[:4])
	case 8:
		e.val = bo.Uint64(data[:8])
	default:
		e.val = int(-1)
	}
}

func (e *entry) put(data []byte, val uint32, bo binary.ByteOrder) {
	data = data[e.off:]
	switch e.val.(type) {
	case uint8:
		data[0] = byte(val)
	case uint16:
		bo.PutUint16(data[:2], uint16(val))
	case uint32:
		bo.PutUint32(data[:4], val)
	case uint64:
		bo.PutUint64(data[:8], uint64(val))
	}
}

func getEntry(f *elf.File, name string) (*entry, error) {
	syms := must(f.Symbols())
	for _, s := range syms {
		if s.Name == name {
			sect := f.Sections[s.Section]
			bs, _ := sect.Data()
			varOff := s.Value - sect.Addr

			var e entry
			e.off = sect.Offset + varOff
			e.get(bs[varOff:], s.Size, f.ByteOrder)
			return &e, nil
		}
	}
	return nil, fmt.Errorf("can't find symbol '%s'", name)
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

func attachBpfProg(ifindex int, data []byte) error {
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

	if err := bpfSpec.LoadAndAssign(&bpfObj, nil); err != nil {
		return err
	}

	return attachTcEgress(ifindex, bpfObj.Prog.FD())
}

func updateElf(ip uint32) ([]byte, error) {
	elfFile, err := elf.NewFile(bytes.NewReader(bpfElf))
	if err != nil {
		return nil, err
	}

	entry, err := getEntry(elfFile, "target_addr")
	if err != nil {
		return nil, err
	}

	data := make([]byte, len(bpfElf))
	copy(data, bpfElf)
	entry.put(data, ip, elfFile.ByteOrder)
	return data, nil
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
	data := must(updateElf(netNum))
	mustDo(attachBpfProg(ifi.Index, data))
}
