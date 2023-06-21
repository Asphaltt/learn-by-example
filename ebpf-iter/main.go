package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang itertcp4 ./bpf_iter_tcp4.c -- -D__TARGET_ARCH_x86 -I../ebpf-headers -Wall

func main() {
	var hz uint32
	flag.Uint32Var(&hz, "hz", 250, "kernel CONFIG_HZ, must be same as `cat /boot/config-$(uname -r) | grep CONFIG_HZ`")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("CONFIG_HZ: %d (must same as the one in `/boot/config-$(uname -r)`)", hz)

	spec, err := loadItertcp4()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"CONFIG_HZ": hz,
	}); err != nil {
		log.Fatalf("Failed to rewrite constants: %v", err)
	}

	var obj itertcp4Objects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		log.Fatalf("Failed to load bpf obj: %v", err)
	}
	defer obj.Close()

	link, err := link.AttachIter(link.IterOptions{
		Program: obj.DumpTcp4,
	})
	if err != nil {
		log.Printf("Failed to attach iter: %v", err)
		return
	}
	defer link.Close()

	if err := link.Pin("/sys/fs/bpf/itertcp4"); err != nil {
		log.Printf("Failed to pin iter: %v", err)
		return
	}
	defer link.Unpin()

	log.Printf("cat /sys/fs/bpf/itertcp4 to check tcp4 connections")

	log.Printf("Attached iter")

	<-ctx.Done()
}
