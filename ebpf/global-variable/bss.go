package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/iovisor/gobpf/pkg/bpffs"
)

const bssMapName = "gvar_bss"

func loadBssMap(spec *ebpf.MapSpec) *ebpf.Map {
	mapPinPath := filepath.Join(bpffs.BPFFSPath, bssMapName)
	if m, err := ebpf.LoadPinnedMap(mapPinPath, nil); err == nil {
		return m
	}

	spec.Name = bssMapName
	spec.Pinning = ebpf.PinByName
	m, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{
		PinPath: bpffs.BPFFSPath,
	})
	if err != nil {
		log.Fatalf("Failed to new bpf map %s: %v", bssMapName, err)
	}

	return m
}

func genBssStruct() {
	bpfSpec, err := loadTcpconn()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	m, ok := bpfSpec.Maps[".bss"]
	if !ok {
		log.Fatalf(".bss map not found")
	}

	fmt.Printf(".bss map spec: %v\n", m)

	var gof btf.GoFormatter
	out, err := gof.TypeDeclaration("bssValue", m.Value)
	if err != nil {
		log.Fatalf("Failed to generate Go struct for .bss value")
	}

	fmt.Println(".bss map value:", out)
}

// get and update from genBssStruct()
type bssValue struct {
	Daddr [4]byte
	Dport uint16
}
