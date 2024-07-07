// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/tklauser/ps"
	"golang.org/x/sync/errgroup"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang sysctl ./sysctl.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	var obj sysctlObjects
	if err := loadSysctlObjects(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%+v", err, ve)
		}
		log.Fatalf("Failed to load bpf obj: %v", err)
	}
	defer obj.Close()

	if l, err := link.AttachTracing(link.TracingOptions{
		Program: obj.FexitDevinetConfProc,
	}); err != nil {
		log.Fatalf("Failed to attach fexit(devinet_conf_proc): %v", err)
	} else {
		log.Printf("Attached fexit(devinet_conf_proc)")
		defer l.Close()
	}

	if l, err := link.AttachTracing(link.TracingOptions{
		Program: obj.FexitIpv4DointAndFlush,
	}); err != nil {
		log.Fatalf("Failed to attach fexit(ipv4_doint_and_flush): %v", err)
	} else {
		log.Printf("Attached fexit(ipv4_doint_and_flush)")
		defer l.Close()
	}

	if l, err := link.AttachTracing(link.TracingOptions{
		Program: obj.FexitDevinetSysctlForward,
	}); err != nil {
		log.Fatalf("Failed to attach fexit(devinet_sysctl_forward): %v", err)
	} else {
		log.Printf("Attached fexit(devinet_sysctl_forward)")
		defer l.Close()
	}

	events := obj.Events
	reader, err := perf.NewReader(events, os.Getpagesize()*2)
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		<-ctx.Done()
		_ = reader.Close()
		return nil
	})

	errg.Go(func() error {
		var event struct {
			Comm         [32]byte
			Pad          uint32
			Pid          uint32
			Ifindex      int32
			DevConfValue int32
			CnfDataPtr   uint64
			CtlDataPtr   uint64
		}

		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return nil
				}

				return fmt.Errorf("failed to read record: %w", err)
			}

			if record.LostSamples != 0 {
				log.Printf("Lost %d events", record.LostSamples)
			}

			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				return fmt.Errorf("failed to decode event: %w", err)
			}

			var ifname string
			ifindex := event.Ifindex
			switch ifindex {
			case -1:
				ifname = "ALL"
			case -2:
				ifname = "DEFAULT"
			default:
				ifi, err := net.InterfaceByIndex(int(ifindex))
				if err != nil {
					return fmt.Errorf("failed to get interface by index(%d): %w", ifindex, err)
				}

				ifname = ifi.Name
			}

			proc, err := ps.FindProcess(int(event.Pid))
			if err != nil {
				return fmt.Errorf("failed to find process(%d): %w", event.Pid, err)
			}

			p := proc.ExecutablePath()
			i := (event.CtlDataPtr-event.CnfDataPtr)/4 + 1
			n := idx2name(i)
			log.Printf("Update %s to %d on interface %s(%d) by process %s",
				n, event.DevConfValue, ifname, ifindex, p)
		}
	})

	if err := errg.Wait(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func idx2name(idx uint64) string {
	const (
		IPV4_DEVCONF_FORWARDING = 1 + iota
		IPV4_DEVCONF_MC_FORWARDING
		IPV4_DEVCONF_PROXY_ARP
		IPV4_DEVCONF_ACCEPT_REDIRECTS
		IPV4_DEVCONF_SECURE_REDIRECTS
		IPV4_DEVCONF_SEND_REDIRECTS
		IPV4_DEVCONF_SHARED_MEDIA
		IPV4_DEVCONF_RP_FILTER
		IPV4_DEVCONF_ACCEPT_SOURCE_ROUTE
		IPV4_DEVCONF_BOOTP_RELAY
		IPV4_DEVCONF_LOG_MARTIANS
		IPV4_DEVCONF_TAG
		IPV4_DEVCONF_ARPFILTER
		IPV4_DEVCONF_MEDIUM_ID
		IPV4_DEVCONF_NOXFRM
		IPV4_DEVCONF_NOPOLICY
		IPV4_DEVCONF_FORCE_IGMP_VERSION
		IPV4_DEVCONF_ARP_ANNOUNCE
		IPV4_DEVCONF_ARP_IGNORE
		IPV4_DEVCONF_PROMOTE_SECONDARIES
		IPV4_DEVCONF_ARP_ACCEPT
		IPV4_DEVCONF_ARP_NOTIFY
		IPV4_DEVCONF_ACCEPT_LOCAL
		IPV4_DEVCONF_SRC_VMARK
		IPV4_DEVCONF_PROXY_ARP_PVLAN
		IPV4_DEVCONF_ROUTE_LOCALNET
		IPV4_DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL
		IPV4_DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL
		IPV4_DEVCONF_IGNORE_ROUTES_WITH_LINKDOWN
		IPV4_DEVCONF_DROP_UNICAST_IN_L2_MULTICAST
		IPV4_DEVCONF_DROP_GRATUITOUS_ARP
		IPV4_DEVCONF_BC_FORWARDING
		IPV4_DEVCONF_ARP_EVICT_NOCARRIER
	)

	names := map[uint64]string{
		IPV4_DEVCONF_FORWARDING:                         "forwarding",
		IPV4_DEVCONF_MC_FORWARDING:                      "mc_forwarding",
		IPV4_DEVCONF_PROXY_ARP:                          "proxy_arp",
		IPV4_DEVCONF_ACCEPT_REDIRECTS:                   "accept_redirects",
		IPV4_DEVCONF_SECURE_REDIRECTS:                   "secure_redirects",
		IPV4_DEVCONF_SEND_REDIRECTS:                     "send_redirects",
		IPV4_DEVCONF_SHARED_MEDIA:                       "shared_media",
		IPV4_DEVCONF_RP_FILTER:                          "rp_filter",
		IPV4_DEVCONF_ACCEPT_SOURCE_ROUTE:                "accept_source_route",
		IPV4_DEVCONF_BOOTP_RELAY:                        "bootp_relay",
		IPV4_DEVCONF_LOG_MARTIANS:                       "log_martians",
		IPV4_DEVCONF_TAG:                                "tag",
		IPV4_DEVCONF_ARPFILTER:                          "arpfilter",
		IPV4_DEVCONF_MEDIUM_ID:                          "medium_id",
		IPV4_DEVCONF_NOXFRM:                             "disable_xfrm",
		IPV4_DEVCONF_NOPOLICY:                           "disable_policy",
		IPV4_DEVCONF_FORCE_IGMP_VERSION:                 "force_igmp_version",
		IPV4_DEVCONF_ARP_ANNOUNCE:                       "arp_announce",
		IPV4_DEVCONF_ARP_IGNORE:                         "arp_ignore",
		IPV4_DEVCONF_PROMOTE_SECONDARIES:                "promote_secondaries",
		IPV4_DEVCONF_ARP_ACCEPT:                         "arp_accept",
		IPV4_DEVCONF_ARP_NOTIFY:                         "arp_notify",
		IPV4_DEVCONF_ACCEPT_LOCAL:                       "accept_local",
		IPV4_DEVCONF_SRC_VMARK:                          "src_vmark",
		IPV4_DEVCONF_PROXY_ARP_PVLAN:                    "proxy_arp_pvlan",
		IPV4_DEVCONF_ROUTE_LOCALNET:                     "route_localnet",
		IPV4_DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL: "igmpv2_unsolicited_report_interval",
		IPV4_DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL: "igmpv3_unsolicited_report_interval",
		IPV4_DEVCONF_IGNORE_ROUTES_WITH_LINKDOWN:        "ignore_routes_with_linkdown",
		IPV4_DEVCONF_DROP_UNICAST_IN_L2_MULTICAST:       "drop_unicast_in_l2_multicast",
		IPV4_DEVCONF_DROP_GRATUITOUS_ARP:                "drop_gratuitous_arp",
		IPV4_DEVCONF_BC_FORWARDING:                      "bc_forwarding",
		IPV4_DEVCONF_ARP_EVICT_NOCARRIER:                "arp_evict_nocarrier",
	}

	name, ok := names[idx]
	if !ok {
		return fmt.Sprintf("unknown(%d)", idx)
	}

	return name
}
