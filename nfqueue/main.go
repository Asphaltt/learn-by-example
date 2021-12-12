package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/florianl/go-nfqueue"
)

type packet []byte

func (p packet) srcIP() net.IP {
	return net.IP(p[12:16])
}

func (p packet) dstIP() net.IP {
	return net.IP(p[16:20])
}

func (p packet) srcPort() uint16 {
	tcphdr := p[20:]
	return binary.BigEndian.Uint16(tcphdr[:2])
}

func (p packet) dstPort() uint16 {
	tcphdr := p[20:]
	return binary.BigEndian.Uint16(tcphdr[2:4])
}

func handlePacket(q *nfqueue.Nfqueue, a nfqueue.Attribute) int {
	if a.Payload != nil && len(*a.Payload) != 0 {
		pkt := packet(*a.Payload)
		fmt.Printf("tcp connect: %s:%d -> %s:%d\n", pkt.srcIP(), pkt.srcPort(), pkt.dstIP(), pkt.dstPort())
	}
	_ = q.SetVerdict(*a.PacketID, nfqueue.NfAccept)
	return 0
}

func main() {
	cfg := nfqueue.Config{
		NfQueue:     1,
		MaxQueueLen: 2,
		Copymode:    nfqueue.NfQnlCopyPacket,
	}

	nfq, err := nfqueue.Open(&cfg)
	if err != nil {
		fmt.Println("failed to open nfqueue, err:", err)
		return
	}

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	if err := nfq.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		return handlePacket(nfq, a)
	}, func(e error) int {
		return 0
	}); err != nil {
		fmt.Println("failed to register handlers, err:", err)
		return
	}

	select {}
}
