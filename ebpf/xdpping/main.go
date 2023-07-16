package main

import (
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/iovisor/gobpf/pkg/bpffs"
	"github.com/spf13/cobra"
)

const bpffsPath = "bpffs"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdpping ./xdp_ping.c -- -D__TARGET_ARCH_x86 -I../headers -Wall

var flags struct {
	device string
}

var rootCmd = cobra.Command{
	Use: "xdpmetadata",
}

func init() {
	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		runXDPPing()
	}

	flag := rootCmd.PersistentFlags()
	flag.StringVar(&flags.device, "dev", "", "device to run XDP")
}

func runXDPPing() {
	ifiDev, err := net.InterfaceByName(flags.device)
	if err != nil {
		log.Fatalf("Failed to fetch device info of %s: %v", flags.device, err)
	}

	devPinPath := filepath.Join(bpffsPath, flags.device)
	removePinnedXDP(devPinPath)

	var obj xdppingObjects
	if err := loadXdppingObjects(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load xdpping bpf obj: %v\n%+v", err, ve)
		}
		log.Fatalf("Failed to load xdpping bpf obj: %v", err)
	}
	defer obj.Close()

	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.XdpPing,
		Interface: ifiDev.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach xdpping to %s: %v", flags.device, err)
	}
	defer xdp.Close()
	if err := xdp.Pin(devPinPath); err != nil {
		log.Fatalf("Failed to pin xdpping to %s: %v", flags.device, err)
	}

	log.Printf("xdpping is running on %s\n", flags.device)
}

func removePinnedXDP(devPinPath string) {
	xdp, err := link.LoadPinnedLink(devPinPath, nil)
	if err == nil {
		_ = xdp.Unpin()
		_ = xdp.Close()
	}
}

func checkBpffs() {
	_ = os.Mkdir(bpffsPath, 0o700)
	mounted, _ := bpffs.IsMountedAt(bpffsPath)
	if mounted {
		return
	}

	err := bpffs.MountAt(bpffsPath)
	if err != nil {
		log.Fatalf("Failed to mount -t bpf %s: %v", bpffsPath, err)
	}
}

func main() {
	checkBpffs()
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
