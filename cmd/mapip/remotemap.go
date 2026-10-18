package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/5evenTeam/mapip/internal/remotemap"
)

func cmdRemoteMap(args []string) {
	if len(args) == 0 {
		remoteMapUsage()
		return
	}
	switch args[0] {
	case "host", "server", "agent":
		cmdRemoteMapHost(args[1:])
	case "client", "connect":
		cmdRemoteMapClient(args[1:])
	case "key":
		cmdRemoteMapKey(args[1:])
	case "help", "--help", "-h":
		remoteMapUsage()
	default:
		remoteMapUsage()
		os.Exit(1)
	}
}

func remoteMapUsage() {
	fmt.Printf(`RemoteMap %s — consent-based remote host manager

RemoteMap is two halves:
  host    runs on a machine you own and chooses to share
  client  connects to one of your hosts

Everything is authenticated and encrypted with a pre-shared key
(AES-256-GCM, HMAC-SHA256 handshake). The host logs every connection and
never contacts anything on the internet. There are no hidden or
persistent components: stop the process and RemoteMap is gone.

Usage:
  mapip remotemap host [flags]     start the host agent on this machine
  mapip remotemap client [flags] <op> [args]
  mapip remotemap key              generate a new pre-shared key

Host flags:
      --addr HOST:PORT   listen address (default 0.0.0.0:8530)
      --key PASS         pre-shared key (a passphrase)
      --key-file PATH    read or create the key at PATH
      --root DIR         the only directory shared with clients
      --allow-shell      allow remote command execution (off by default)
      --allow LIST       comma-separated CIDR allow-list for clients

Client ops:
  info | ping | list [path] | get <remote> [-o <local>] | exec <cmd> | shell
`, version)
}

func resolveHostKey(key, keyFile string) (resolved string, source string, created bool, err error) {
	if key != "" {
		return key, "--key", false, nil
	}
	if keyFile == "" {
		keyFile = remotemap.DefaultKeyFile()
	}
	k, created, err := remotemap.LoadOrCreateKey(keyFile)
	if err != nil {
		return "", "", false, err
	}
	return k, keyFile, created, nil
}

func resolveClientKey(key, keyFile string) (string, error) {
	if key != "" {
		return key, nil
	}
	if keyFile == "" {
		keyFile = remotemap.DefaultKeyFile()
	}
	b, err := os.ReadFile(keyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no key: pass --key or --key-file (looked in %s)", keyFile)
		}
		return "", err
	}
	k := strings.TrimSpace(string(b))
	if k == "" {
		return "", fmt.Errorf("key file %s is empty", keyFile)
	}
	return k, nil
}

func cmdRemoteMapHost(args []string) {
	fs := flag.NewFlagSet("remotemap host", flag.ExitOnError)
	var addr, key, keyFile, root, allow string
	var allowShell bool
	var timeout time.Duration
	fs.StringVar(&addr, "addr", fmt.Sprintf("0.0.0.0:%d", remotemap.DefaultPort), "listen address")
	fs.StringVar(&key, "key", "", "pre-shared key (passphrase)")
	fs.StringVar(&keyFile, "key-file", "", "read or create the pre-shared key at PATH")
	fs.StringVar(&root, "root", "", "directory shared with clients (default: current directory)")
	fs.BoolVar(&allowShell, "allow-shell", false, "allow remote command execution")
	fs.StringVar(&allow, "allow", "", "comma-separated CIDR allow-list for clients")
	fs.DurationVar(&timeout, "timeout", 30*time.Second, "per-request idle timeout")
	_ = fs.Parse(reorderFlags(fs, args))

	resolvedKey, source, created, err := resolveHostKey(key, keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "remotemap:", err)
		os.Exit(1)
	}
	if len(resolvedKey) < 12 {
		fmt.Fprintln(os.Stderr, "warning: short key; use at least 12 characters or a generated key")
	}

	var nets []string
	if strings.TrimSpace(allow) != "" {
		nets = strings.Split(allow, ",")
	}

	host, err := remotemap.NewHost(remotemap.HostConfig{
		Addr:       addr,
		Key:        resolvedKey,
		Root:       root,
		AllowShell: allowShell,
		Allow:      nets,
		Timeout:    timeout,
		Version:    version,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "remotemap:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := host.Listen(); err != nil {
		fmt.Fprintln(os.Stderr, "remotemap: could not listen:", err)
		os.Exit(1)
	}

	fmt.Printf("RemoteMap %s host (MapIp)\n", version)
	fmt.Printf("listening on  %s\n", host.Addr().String())
	fmt.Printf("shared root   %s\n", host.Root())
	fmt.Printf("key source    %s\n", source)
	fmt.Printf("key fingerprint  %s\n", remotemap.Fingerprint(resolvedKey))
	if created {
		fmt.Printf("generated key %s\n", resolvedKey)
		fmt.Println("              (store it securely; the client needs this exact key)")
	}
	shell := "no"
	if allowShell {
		shell = "yes"
	}
	fmt.Printf("allow-shell   %s\n", shell)
	fmt.Println()
	fmt.Println("This process is visible and logs every connection. Stop it (Ctrl-C) to stop RemoteMap.")
	fmt.Println()

	if err := host.Serve(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "remotemap:", err)
		os.Exit(1)
	}
}

func cmdRemoteMapKey(args []string) {
	fs := flag.NewFlagSet("remotemap key", flag.ExitOnError)
	var write string
	fs.StringVar(&write, "o", "", "write the key to PATH")
	_ = fs.Parse(args)

	key := remotemap.GenerateKey()
	if write != "" {
		if dir := filepath.Dir(write); dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0o700)
		}
		if err := os.WriteFile(write, []byte(key+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "remotemap:", err)
			os.Exit(1)
		}
		fmt.Printf("key written to %s\n", write)
	} else {
		fmt.Println(key)
	}
	fmt.Printf("fingerprint %s\n", remotemap.Fingerprint(key))
}

func cmdRemoteMapClient(args []string) {
	fs := flag.NewFlagSet("remotemap client", flag.ExitOnError)
	var host string
	var port int
	var key, keyFile, out string
	var connectTimeout, execTimeout time.Duration
	var asJSON bool
	fs.StringVar(&host, "host", "", "RemoteMap host address (required)")
	fs.IntVar(&port, "port", remotemap.DefaultPort, "RemoteMap host port")
	fs.StringVar(&key, "key", "", "pre-shared key (passphrase)")
	fs.StringVar(&keyFile, "key-file", "", "read the pre-shared key from PATH")
	fs.DurationVar(&connectTimeout, "timeout", 30*time.Second, "connect/handshake timeout")
	fs.DurationVar(&execTimeout, "exec-timeout", 60*time.Second, "remote command timeout")
	fs.StringVar(&out, "o", "", "write a downloaded file to PATH ('-' for stdout)")
	fs.StringVar(&out, "out", "", "write a downloaded file to PATH ('-' for stdout)")
	fs.BoolVar(&asJSON, "json", false, "print the raw JSON reply")
	_ = fs.Parse(reorderFlags(fs, args))

	rest := fs.Args()
	if len(rest) == 0 {
		rest = []string{"info"}
	}
	op, opArgs := rest[0], rest[1:]

	if strings.TrimSpace(host) == "" {
		fmt.Fprintln(os.Stderr, "usage: mapip remotemap client --host HOST <info|ping|list|get|exec|shell> [args]")
		os.Exit(1)
	}
	resolvedKey, err := resolveClientKey(key, keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "remotemap:", err)
		os.Exit(1)
	}

	addr := host
	if _, _, err := splitHostPortSafe(host); err != nil {
		addr = joinHostPort(host, port)
	}

	client, err := remotemap.Dial(addr, resolvedKey, connectTimeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "remotemap: connect failed:", err)
		os.Exit(1)
	}
	defer client.Close()

	switch op {
	case "ping":
		if err := client.Ping(); err != nil {
			fail(err)
		}
		fmt.Printf("pong from %s\n", client.RemoteAddr())

	case "info":
		info, err := client.Info()
		if err != nil {
			fail(err)
		}
		if asJSON {
			printJSON(info)
			return
		}
		fmt.Printf("host       %s (%s/%s)\n", info.Hostname, info.OS, info.Arch)
		fmt.Printf("user       %s\n", info.User)
		fmt.Printf("version    %s\n", info.Version)
		fmt.Printf("uptime     %s\n", (time.Duration(info.UptimeSec) * time.Second).String())
		fmt.Printf("root       %s\n", info.Root)
		fmt.Printf("allow-shell %v\n", info.AllowShell)
		for _, iface := range info.Interfaces {
			fmt.Printf("iface      %s  %s\n", iface.Name, strings.Join(iface.Addresses, ", "))
		}

	case "list", "ls":
		p := "."
		if len(opArgs) > 0 {
			p = opArgs[0]
		}
		res, err := client.List(p)
		if err != nil {
			fail(err)
		}
		if asJSON {
			printJSON(res)
			return
		}
		fmt.Printf("%s\n", res.Path)
		for _, e := range res.Entries {
			if e.Dir {
				fmt.Printf("  %-9s %s/\n", "<dir>", e.Name)
			} else {
				fmt.Printf("  %-9s %s\n", humanSize(e.Size), e.Name)
			}
		}

	case "get":
		if len(opArgs) < 1 {
			fmt.Fprintln(os.Stderr, "usage: mapip remotemap client --host HOST get <remote-path> [-o local]")
			os.Exit(1)
		}
		remote := opArgs[0]
		if out == "-" {
			header, err := client.Get(remote, os.Stdout)
			if err != nil {
				fail(err)
			}
			fmt.Fprintf(os.Stderr, "\nreceived %s (%d bytes)\n", header.Name, header.Size)
			return
		}
		dest := out
		if dest == "" {
			dest = filepath.Base(strings.TrimRight(remote, "/"))
		}
		f, err := os.Create(dest)
		if err != nil {
			fail(err)
		}
		header, err := client.Get(remote, f)
		closeErr := f.Close()
		if err != nil {
			_ = os.Remove(dest)
			fail(err)
		}
		if closeErr != nil {
			fail(closeErr)
		}
		fmt.Printf("wrote %s (%d bytes) to %s\n", header.Name, header.Size, dest)

	case "exec", "run":
		if len(opArgs) == 0 {
			fmt.Fprintln(os.Stderr, "usage: mapip remotemap client --host HOST exec <command>")
			os.Exit(1)
		}
		command := strings.Join(opArgs, " ")
		res, err := client.Exec(command, execTimeout)
		if err != nil {
			fail(err)
		}
		if asJSON {
			printJSON(res)
		} else {
			fmt.Print(res.Stdout)
			if res.Stderr != "" {
				fmt.Fprint(os.Stderr, res.Stderr)
			}
		}
		if res.ExitCode != 0 {
			os.Exit(res.ExitCode)
		}

	case "shell":
		remoteShell(client, execTimeout)

	default:
		fmt.Fprintf(os.Stderr, "unknown op %q\n", op)
		os.Exit(1)
	}
}

func remoteShell(client *remotemap.Client, timeout time.Duration) {
	info, err := client.Info()
	if err == nil {
		fmt.Printf("connected to %s (%s)\n", info.Hostname, client.RemoteAddr())
		if !info.AllowShell {
			fmt.Println("this host was not started with --allow-shell; only :info, :ls and :get are available")
		}
	}
	fmt.Println("type a command, or :info, :ls [path], :get <remote> [local], exit")

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for {
		fmt.Print("remotemap> ")
		if !in.Scan() {
			fmt.Println()
			return
		}
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			return
		}
		switch {
		case line == ":info":
			if info, err := client.Info(); err != nil {
				fmt.Fprintln(os.Stderr, err)
			} else {
				printJSON(info)
			}
		case strings.HasPrefix(line, ":ls"):
			p := "."
			if fields := strings.Fields(line); len(fields) > 1 {
				p = fields[1]
			}
			res, err := client.List(p)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			for _, e := range res.Entries {
				if e.Dir {
					fmt.Printf("  %-9s %s/\n", "<dir>", e.Name)
				} else {
					fmt.Printf("  %-9s %s\n", humanSize(e.Size), e.Name)
				}
			}
		case strings.HasPrefix(line, ":get"):
			fields := strings.Fields(line)
			if len(fields) < 2 {
				fmt.Fprintln(os.Stderr, "usage: :get <remote> [local]")
				continue
			}
			dest := filepath.Base(fields[1])
			if len(fields) > 2 {
				dest = fields[2]
			}
			f, err := os.Create(dest)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			header, err := client.Get(fields[1], f)
			_ = f.Close()
			if err != nil {
				_ = os.Remove(dest)
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			fmt.Printf("wrote %s (%d bytes) to %s\n", header.Name, header.Size, dest)
		default:
			res, err := client.Exec(line, timeout)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			fmt.Print(res.Stdout)
			if res.Stderr != "" {
				fmt.Fprint(os.Stderr, res.Stderr)
			}
		}
	}
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println(string(b))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "remotemap:", err)
	os.Exit(1)
}

func joinHostPort(host string, port int) string {
	return host + ":" + strconv.Itoa(port)
}

func splitHostPortSafe(hostport string) (string, string, error) {
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		return "", "", fmt.Errorf("no port")
	}
	return hostport[:i], hostport[i+1:], nil
}

func reorderFlags(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			positional = append(positional, args[i+1:]...)
			i = len(args)
		case a == "-" || !strings.HasPrefix(a, "-"):
			positional = append(positional, a)
		default:
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if strings.Contains(name, "=") {
				continue
			}
			f := fs.Lookup(name)
			if f != nil && !isBoolFlag(f) && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	return append(flags, positional...)
}

func isBoolFlag(f *flag.Flag) bool {
	type boolFlag interface{ IsBoolFlag() bool }
	if bf, ok := f.Value.(boolFlag); ok {
		return bf.IsBoolFlag()
	}
	return false
}
