package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcpconn ./tcp-connecting.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadTcpconn()
	if err != nil {
		log.Fatalf("Failed to load tcpconn bpf spec: %v", err)
		return
	}

	var obj tcpconnObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Fatalf("Failed to load bpf obj: %v", err)
		}
	}
	defer obj.Close()

	if link, err := link.AttachTracing(link.TracingOptions{
		Program: obj.TcpConnect,
	}); err != nil {
		log.Printf("Failed to attach fentry(tcp_connect): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fentry(tcp_connect)")
	}

	if link, err := link.AttachTracing(link.TracingOptions{
		Program: obj.InetCskCompleteHashdance,
	}); err != nil {
		log.Printf("Failed to attach fexit(inet_csk_complete_hashdance): %v", err)
		return
	} else {
		defer link.Close()
		log.Printf("Attached fexit(inet_csk_complete_hashdance)")
	}

	log.Printf("Waiting for TCP connections...")

	<-ctx.Done()
}
