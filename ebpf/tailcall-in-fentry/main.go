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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcpconn ./tcp-connecting.c -- -D__TARGET_ARCH_x86 -I../headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang fentry ./fentry.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove memlock: %v")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var tcObj tcpconnObjects
	err := loadTcpconnObjects(&tcObj, nil)
	assert.NoVerifierErr(err, "Failed to load tcpconn bpf obj: %v")
	defer tcObj.Close()

	spec, err := loadFentry()
	assert.NoErr(err, "Failed to load fentry spec: %v")

	spec.Programs["fentry__k_tcp_connect"].AttachTarget = tcObj.K_tcpConnect
	spec.Programs["tailcallee"].AttachTarget = tcObj.K_tcpConnect

	coll, err := ebpf.NewCollection(spec)
	assert.NoVerifierErr(err, "Failed to create ebpf collection: %v")
	defer coll.Close()

	err = coll.Maps["prog_array"].Put(uint32(0), coll.Programs["tailcallee"])
	assert.NoErr(err, "Failed to put tail call program into prog_array: %v")

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    coll.Programs["fentry__k_tcp_connect"],
		AttachType: ebpf.AttachTraceFEntry,
	})
	assert.NoErr(err, "Failed to attach fentry program: %v")
	defer l.Close()

	l, err = link.Kprobe("tcp_connect", tcObj.K_tcpConnect, nil)
	assert.NoErr(err, "Failed to attach kprobe(tcp_connect): %v")
	defer l.Close()

	log.Print("Running ...")

	<-ctx.Done()

	var run uint32
	err = coll.Variables["run"].Get(&run)
	assert.NoErr(err, "Failed to get run variable: %v")
	log.Printf("run variable: %d", run)

	err = tcObj.Run.Get(&run)
	assert.NoErr(err, "Failed to get run variable from tcpconn: %v")
	log.Printf("tcpconn run variable: %d", run)
}
