package main

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"time"
	"unsafe"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc clang xdpfn ./xdp.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc clang xdpfnLoop ./xdp.c -- -D__TARGET_ARCH_x86 -D__USE_LOOP -I../headers -Wall

func main() {
	var dev, cidrFile string
	var loop bool
	flag.StringVarP(&dev, "dev", "D", "", "device to inject latency to ping")
	flag.StringVarP(&cidrFile, "cidr", "C", "", "file containing CIDR to match")
	flag.BoolVarP(&loop, "loop", "L", false, "binary search by loop method or unroll method")
	flag.Parse()

	ifi, err := netlink.LinkByName(dev)
	if err != nil {
		log.Fatalf("Failed to get device info: %v", err)
	}

	cidrs, cidrNum, err := readCidrFile(cidrFile)
	if err != nil {
		log.Fatalf("Failed to read CIDR file: %v", err)
	}

	xsk, err := xdp.NewSocket(ifi.Attrs().Index, 0, nil)
	if err != nil {
		log.Fatalf("Failed to new XDP socket: %v", err)
	}
	defer xsk.Close()

	var spec *ebpf.CollectionSpec
	if loop {
		spec, err = loadXdpfnLoop()
	} else {
		spec, err = loadXdpfn()
	}
	if err != nil {
		log.Printf("Failed to load XDP bpf: %v", err)
		return
	}

	err = spec.RewriteConstants(map[string]interface{}{
		"delay_cidrs":     cidrs,
		"delay_cidrs_len": uint32(cidrNum),
	})
	if err != nil {
		log.Printf("Failed to rewrite constants: %v", err)
		return
	}

	var obj xdpfnObjects
	if err := spec.LoadAndAssign(&obj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			// LogLevel: ebpf.LogLevelInstruction | ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogSize:  10 * ebpf.DefaultVerifierLogSize,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Verifier error: %+v", ve)
			return
		}
		log.Printf("Failed to load XDP bpf obj: %v", err)
		return
	}
	defer obj.Close()

	if len(obj.XdpFn.VerifierLog) != 0 {
		log.Printf("Verifier log:\n%s", obj.XdpFn.VerifierLog)
	}

	if err := obj.XdpSockets.Put(uint32(0), uint32(xsk.FD())); err != nil {
		log.Printf("Failed to update XDP socket bpf map: %v", err)
		return
	}

	if link, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.XdpFn,
		Interface: ifi.Attrs().Index,
		Flags:     link.XDPGenericMode,
	}); err != nil {
		log.Printf("Failed to attach XDP to %s: %v", dev, err)
		return
	} else {
		log.Printf("Attached XDP to %s", dev)
		defer link.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	var nHandling int
	var isExiting bool

	for {
		select {
		case <-ctx.Done():
			if nHandling <= 0 {
				return
			}

			isExiting = true

		default:
		}

		if n := xsk.NumFreeFillSlots(); n > 0 {
			_ = xsk.Fill(xsk.GetDescs(n))
		}

		nRecv, nComp, err := xsk.Poll(1) // 1ms timeout
		if err != nil {
			if os.IsTimeout(err) {
				continue
			}

			log.Printf("Failed to poll packets: %v", err)
			return
		}

		nHandling -= nComp

		if nRecv != 0 && !isExiting {
			nHandling += nRecv

			descs := xsk.Receive(nRecv)
			delayPackets(xsk, descs)
		}
	}
}

func delayPackets(xsk *xdp.Socket, descs []xdp.Desc) {
	for _, desc := range descs {
		desc := desc
		latency := readLatency(xsk, desc)
		log.Printf("Delaying packet by %s", latency)
		delayPacket(xsk, desc, latency)
	}
}

func readLatency(xsk *xdp.Socket, desc xdp.Desc) time.Duration {
	frame := xsk.GetFrame(desc)

	sh := (*reflect.SliceHeader)(unsafe.Pointer(&frame))
	sh.Data -= 4
	sh.Len += 4
	sh.Cap += 4

	lat := *(*uint32)(unsafe.Pointer(&frame[0]))
	return time.Duration(lat) * time.Millisecond
}

func delayPacket(xsk *xdp.Socket, desc xdp.Desc, latency time.Duration) {
	_ = time.AfterFunc(latency, func() {
		transformPacket(xsk.GetFrame(desc))
		_ = xsk.Transmit([]xdp.Desc{desc})
	})
}

func transformPacket(buf []byte) {
	// Note: This packet has been validated by XDP. It's not neccessary to check
	// it again.

	eth := buf[0:]
	iph := buf[14:]
	icmph := buf[14+((iph[0]&0x0F)*4):]

	updateICMP(icmph)

	updateNetworkLayer(iph)

	updateLinkLayer(eth)
}

func updateLinkLayer(buf []byte) {
	var tmpMac [6]byte
	_ = copy(tmpMac[:], buf[:6])
	_ = copy(buf[:6], buf[6:12])
	_ = copy(buf[6:12], tmpMac[:])
}

var be = binary.BigEndian

func updateNetworkLayer(buf []byte) {
	buf[8] = 64 // TTL

	var tmpIP [4]byte
	_ = copy(tmpIP[:], buf[12:16])
	_ = copy(buf[12:16], buf[16:20])
	_ = copy(buf[16:20], tmpIP[:])

	// update checksum
	be.PutUint16(buf[10:12], 0)
	csum := tcpipChecksum(buf, 0)
	be.PutUint16(buf[10:12], csum)
}

func updateICMP(buf []byte) {
	buf[0] = 0 // type = ECHOREPLY

	// update checksum
	be.PutUint16(buf[2:], 0)
	csum := tcpipChecksum(buf, 0)
	be.PutUint16(buf[2:], csum)
}

// copied from google/gopacket

// Calculate the TCP/IP checksum defined in rfc1071.  The passed-in csum is any
// initial checksum data that's already been computed.
func tcpipChecksum(data []byte, csum uint32) uint16 {
	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}
