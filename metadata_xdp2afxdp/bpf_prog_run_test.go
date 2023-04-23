package main

import (
	"testing"
	"unsafe"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

func preparePacketData() []byte {
	buf := make([]byte, 14+20+8)     // eth + iph + icmph
	be.PutUint16(buf[12:14], 0x0800) // ethertype = IPv4

	iph := buf[14:]
	iph[0] = 0x45 // version = 4, ihl = 5
	iph[9] = 1    // protocol = ICMP

	icmph := iph[20:]
	icmph[0] = 8 // type = ECHO

	return buf
}

func TestXDPProgRun(t *testing.T) {
	ifi, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("Failed to get device info: %v", err)
	}

	xsk, err := xdp.NewSocket(ifi.Attrs().Index, 0, nil)
	if err != nil {
		t.Fatalf("Failed to new XDP socket: %v", err)
	}
	defer xsk.Close()

	var obj xdpfnObjects
	if err := loadXdpfnObjects(&obj, nil); err != nil {
		t.Fatalf("Failed to load XDP bpf obj: %v", err)
	}
	defer obj.Close()

	// Map is required to be populated before running the program for `bpf_redirect_map`.
	if err := obj.XdpSockets.Put(uint32(0), uint32(xsk.FD())); err != nil {
		t.Fatalf("Failed to update XDP socket bpf map: %v", err)
		return
	}

	data := preparePacketData()
	dataOut := make([]byte, len(data)+4)

	act, err := obj.XdpFn.Run(&ebpf.RunOptions{
		Data:    data,
		DataOut: dataOut,
	})
	if err != nil {
		t.Fatalf("Failed to run XDP bpf prog: %v", err)
	}

	if act != 4 { // XDP_REDIRECT
		t.Fatalf("Expected action %d, got %d", 4, act)
	}

	lat := *(*uint32)(unsafe.Pointer(&dataOut[0]))
	if lat != 200 {
		t.Fatalf("Expected latency %d, got %d", 200, lat)
	}
}
