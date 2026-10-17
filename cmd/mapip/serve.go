package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/5evenTeam/mapip/internal/api"
	"github.com/5evenTeam/mapip/internal/netutil"
	"github.com/5evenTeam/mapip/internal/store"
)

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var addr string
	var token string
	fs.StringVar(&addr, "addr", "127.0.0.1:8765", "listen address")
	fs.StringVar(&token, "token", "", "api token (generated when empty)")
	_ = fs.Parse(args)

	st := store.New("")
	srv := api.New(token, st)
	httpSrv, ln, err := api.Listen(addr, srv.Handler())
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not listen on", addr, ":", err)
		os.Exit(1)
	}
	defer httpSrv.Close()

	cidr, _ := netutil.PrimaryLocalCIDR()

	fmt.Printf("mapip %s api listening on http://%s\n", version, ln.Addr().String())
	fmt.Printf("token: %s\n", srv.Token())
	fmt.Printf("history: %s\n", st.Dir())
	if cidr != "" {
		fmt.Printf("primary subnet: %s\n", cidr)
	}
	fmt.Printf("\n%s\n", disclaimer)
	fmt.Println("the desktop app reads the address and token from stdout; press ctrl+c to stop")

	select {}
}
