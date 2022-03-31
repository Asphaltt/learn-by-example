package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

func main() {
	var sip, dip string
	flag.StringVar(&sip, "s", "", "Source IP address")
	flag.StringVar(&dip, "d", "", "Destination IP address")
	flag.Parse()

	// validate IP addresses
	netSip, err := netip.ParseAddr(sip)
	if err != nil {
		log.Fatalf("Invalid source IP address: %s", sip)
	}
	netDip, err := netip.ParseAddr(dip)
	if err != nil {
		log.Fatalf("Invalid destination IP address: %s", dip)
	}

	maps, err := findEbpfMaps()
	if err != nil {
		log.Fatalf("Failed to find maps: %v", err)
	}

	if err := updateMap(maps[mSaddrs], netSip); err != nil {
		log.Fatalf("Failed to update source IP address: %v", err)
	}
	if err := updateMap(maps[mDaddrs], netDip); err != nil {
		log.Fatalf("Failed to update destination IP address: %v", err)
	}

	key, val := ruleStruct{key: 1}, uint32(1)
	mapRules, err := ebpf.NewMapFromID(ebpf.MapID(maps[mRules]))
	if err != nil {
		log.Fatalf("Failed to open map %d: %v", maps[mRules], err)
	}
	if err := mapRules.Update(key, val, ebpf.UpdateAny); err != nil {
		log.Fatalf("Failed to update rule: %v", err)
	}

	log.Printf("%s -> %s is disallowed to be pinged\n", sip, dip)
}

type ruleStruct struct {
	key uint64
}

const (
	// eBPF map names
	mSaddrs = "filter_saddrs"
	mDaddrs = "filter_daddrs"
	mRules  = "filter_rules"
)

func findEbpfMaps() (map[string]int, error) {
	out, err := exec.Command("bpftool", "map", "list").Output()
	if err != nil {
		return nil, err
	}

	m := map[string]int{
		mSaddrs: -1,
		mDaddrs: -1,
		mRules:  -1,
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "name") {
			continue
		}

		fields := strings.Fields(line)
		name := fields[3]
		if _, ok := m[name]; !ok {
			continue
		}

		n, _ := strconv.Atoi(fields[0][:len(fields[0])-1])
		m[name] = n
	}

	if m[mSaddrs] == -1 {
		return m, fmt.Errorf("Failed to find map %s", mSaddrs)
	}

	if m[mDaddrs] == -1 {
		return m, fmt.Errorf("Failed to find map %s", mDaddrs)
	}

	if m[mRules] == -1 {
		return m, fmt.Errorf("Failed to find map %s", mRules)
	}

	log.Printf("Found maps: %v\n", m)

	return m, scanner.Err()
}

func updateMap(mid int, ip netip.Addr) error {
	m, err := ebpf.NewMapFromID(ebpf.MapID(mid))
	if err != nil {
		return fmt.Errorf("Failed to open map %d: %v", mid, err)
	}

	key := ruleStruct{key: 1}
	_ip := ip.As4()
	ipval := binary.LittleEndian.Uint32(_ip[:])
	return m.Update(ipval, key, ebpf.UpdateAny)
}
