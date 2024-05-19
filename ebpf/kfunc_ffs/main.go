// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang ffs ./ffs.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

type Pkt struct {
	Saddr    [4]byte
	Daddr    [4]byte
	Sport    [2]byte
	Dport    [2]byte
	Protocol uint8
	IcmpType uint8
	IcmpCode uint8
	IsSynack uint8
}

func ntohs(n [2]byte) uint16 {
	return binary.BigEndian.Uint16(n[:])
}

func buildSkbData() ([]byte, error) {
	pkt := &Pkt{
		Saddr:    [4]byte{192, 168, 1, 1},
		Daddr:    [4]byte{192, 168, 1, 2},
		Sport:    [2]byte{0x30, 0x39},
		Dport:    [2]byte{0x30, 0x39},
		Protocol: 6,
	}

	// Create a new Ethernet frame
	ethLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create a new IPv4 packet
	ipLayer := &layers.IPv4{
		SrcIP:    net.IP(pkt.Saddr[:]),
		DstIP:    net.IP(pkt.Daddr[:]),
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		IHL:      5,
	}

	var l4layer gopacket.SerializableLayer
	switch pkt.Protocol {
	case 6: // TCP
		ipLayer.Protocol = layers.IPProtocolTCP
		l4layer = &layers.TCP{
			SrcPort: layers.TCPPort(ntohs(pkt.Sport)),
			DstPort: layers.TCPPort(ntohs(pkt.Dport)),
		}

		if pkt.IsSynack == 1 {
			l4layer.(*layers.TCP).SYN = true
			l4layer.(*layers.TCP).ACK = true
		}

	case 17: // UDP
		ipLayer.Protocol = layers.IPProtocolUDP
		l4layer = &layers.UDP{
			SrcPort: layers.UDPPort(ntohs(pkt.Sport)),
			DstPort: layers.UDPPort(ntohs(pkt.Dport)),
		}

	case 1: // ICMP
		ipLayer.Protocol = layers.IPProtocolICMPv4
		l4layer = &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(pkt.IcmpType, pkt.IcmpCode),
		}
	}

	// Create the encapsulated payload (in this case, a simple payload)
	payload := []byte("Hello, Packet!")

	// Serialize the layers
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		ethLayer,
		ipLayer,
		l4layer,
		gopacket.Payload(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to gen packet: %w", err)
	}

	return buffer.Bytes(), nil
}

var flags struct {
	offset int
	times  int
}

func init() {
	flag.IntVar(&flags.offset, "offset", 0, "offset")
	flag.IntVar(&flags.times, "times", 1000000, "times")

	flag.Parse()
}

func main() {
	spec, err := loadFfs()
	if err != nil {
		log.Fatalf("Failed to load ffs bpf spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to load ffs bpf obj: %v", err)
	}

	ffsProg1, ok := coll.Programs["tc_ffs1"]
	if !ok {
		log.Fatalf("Failed to find tc_ffs1 program")
	}

	ffsProg2, ok := coll.Programs["tc_ffs2"]
	if !ok {
		log.Fatalf("Failed to find tc_ffs2 program")
	}

	pktBuff, err := buildSkbData()
	if err != nil {
		log.Fatalf("Failed to build skb data: %v", err)
	}

	n := 1 << flags.offset
	binary.LittleEndian.PutUint64(pktBuff[0:8], uint64(n))

	times := flags.times
	ret, latency, err := ffsProg1.Benchmark(pktBuff, times, func() {})
	if err != nil {
		log.Fatalf("Failed to run tc_ffs1: %v", err)
	}

	log.Printf("tc_ffs1: run %d times, ret: %d, latency: %s", times, ret, latency)

	ret, latency, err = ffsProg2.Benchmark(pktBuff, times, func() {})
	if err != nil {
		log.Fatalf("Failed to run tc_ffs2: %v", err)
	}

	log.Printf("tc_ffs2: run %d times, ret: %d, latency: %s", times, ret, latency)
}
