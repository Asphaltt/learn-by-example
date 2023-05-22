package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"inet.af/netaddr"
)

const cidrCapacity = 128

type cidr struct {
	Start uint32
	End   uint32
}

func readCidrFile(cidrFile string) ([cidrCapacity]cidr, int, error) {
	var cidrs [cidrCapacity]cidr

	f, err := os.Open(cidrFile)
	if err != nil {
		return cidrs, 0, fmt.Errorf("failed to open cidr file: %w", err)
	}
	defer f.Close()

	var content struct {
		Cidrs []string `json:"cidrs"`
	}

	err = json.NewDecoder(f).Decode(&content)
	if err != nil {
		return cidrs, 0, fmt.Errorf("failed to decode cidr file: %w", err)
	}

	for i, cidr := range content.Cidrs {
		pref, err := netaddr.ParseIPPrefix(cidr)
		if err != nil {
			return cidrs, 0, fmt.Errorf("failed to parse cidr %s: %w", cidr, err)
		}

		rang := pref.Range()
		start, end := rang.From().As4(), rang.To().As4()
		cidrs[i].Start = be.Uint32(start[:])
		cidrs[i].End = be.Uint32(end[:])
	}

	cidrNum := len(content.Cidrs)
	sort.Slice(cidrs[:cidrNum], func(i, j int) bool {
		return cidrs[i].Start < cidrs[j].Start
	})

	return cidrs, cidrNum, nil
}
