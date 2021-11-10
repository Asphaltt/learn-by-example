package main

import (
	"fmt"
	"os"

	"github.com/subgraph/go-nfnetlink/nfqueue"
)

func main() {
	q := nfqueue.NewNFQueue(1)

	ps, err := q.Open()
	if err != nil {
		fmt.Printf("Error opening NFQueue: %v\n", err)
		os.Exit(1)
	}
	defer q.Close()

	for p := range ps {
		networkLayer := p.Packet.NetworkLayer()
		ipsrc, ipdst := networkLayer.NetworkFlow().Endpoints()

		transportLayer := p.Packet.TransportLayer()
		tcpsrc, tcpdst := transportLayer.TransportFlow().Endpoints()

		fmt.Printf("A new tcp connection will be established: %s:%s -> %s:%s\n",
			ipsrc, tcpsrc, ipdst, tcpdst)
		p.Accept()
	}
}
