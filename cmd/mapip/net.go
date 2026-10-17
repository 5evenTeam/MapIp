package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/5evenTeam/mapip/internal/netutil"
	"github.com/5evenTeam/mapip/internal/wol"
)

func cmdWOL(args []string) {
	fs := flag.NewFlagSet("wol", flag.ExitOnError)
	var broadcast string
	fs.StringVar(&broadcast, "b", "255.255.255.255", "broadcast address")
	fs.StringVar(&broadcast, "broadcast", "255.255.255.255", "broadcast address")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: mapip wol <mac-address> [-b 255.255.255.255]")
		os.Exit(1)
	}
	mac := fs.Arg(0)
	if err := wol.Wake(mac, broadcast); err != nil {
		fmt.Fprintln(os.Stderr, "wake failed:", err)
		os.Exit(1)
	}
	fmt.Printf("magic packet sent to %s via %s\n", mac, broadcast)
}

func cmdInterfaces(args []string) {
	list, err := netutil.LocalInterfaces()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cidr, _ := netutil.PrimaryLocalCIDR()
	fmt.Printf("%-24s %-18s %-20s %s\n", "NAME", "ADDRESS", "CIDR", "PRIVATE")
	for _, i := range list {
		fmt.Printf("%-24s %-18s %-20s %v\n", i.Name, i.Address, i.CIDR, i.Private)
	}
	fmt.Printf("\nprimary subnet: %s\n", cidr)
}
