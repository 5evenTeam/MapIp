package discovery

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/5evenTeam/mapip/internal/enrich"
	"github.com/5evenTeam/mapip/internal/model"
	"github.com/5evenTeam/mapip/internal/oui"
	"github.com/5evenTeam/mapip/internal/portscan"
)

type Options struct {
	Targets     []string
	Timeout     time.Duration
	Concurrency int
	Ports       []int
	UdpPorts    []int
	PortScan    bool
	Enrich      bool
	PingFirst   bool
}

type Progress struct {
	Done  int
	Total int
	Host  model.Host
	Found bool
}

type Result struct {
	Hosts  []model.Host
	Errors []string
}

func ScanAll(ctx context.Context, opts Options, progress func(Progress)) Result {
	if opts.Timeout <= 0 {
		opts.Timeout = time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 64
	}

	arp := ARPTable()
	total := len(opts.Targets)
	var (
		mu    sync.Mutex
		hosts []model.Host
		errs  []string
		done  int
		wg    sync.WaitGroup
		sem   = make(chan struct{}, opts.Concurrency)
	)

	for _, ip := range opts.Targets {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			host, alive := probeHost(ctx, ip, opts)

			mu.Lock()
			done++
			if alive {
				hosts = append(hosts, host)
			}
			if progress != nil {
				progress(Progress{Done: done, Total: total, Host: host, Found: alive})
			}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	sort.Slice(hosts, func(i, j int) bool { return ipLess(hosts[i].IP, hosts[j].IP) })
	mergeARP(hosts, arp)
	return Result{Hosts: hosts, Errors: errs}
}

func probeHost(ctx context.Context, ip string, opts Options) (model.Host, bool) {
	host := model.Host{IP: ip}

	if h, ok := ICMPPing(ip, opts.Timeout); ok {
		host = h
	} else if h, ok := TCPPing(ip, []int{80, 443, 22, 445, 3389, 139, 8080}, opts.Timeout); ok {
		host.Alive = true
		host.RTTMs = h.RTTMs
	} else {
		host.Alive = false
		return host, false
	}

	if opts.Enrich {
		if name := enrich.ReverseDNS(ip, opts.Timeout); name != "" {
			host.Hostname = name
		}
		if mac, ok := ARPTable()[ip]; ok {
			host.MAC = mac
			host.Vendor = oui.Lookup(mac)
		}
		if name := enrich.NetBIOSName(ip, opts.Timeout); name != "" {
			host.Names.NetBIOS = name
		}
		if name := enrich.MDNSName(ip, opts.Timeout); name != "" {
			host.Names.MDNS = name
		}
		if name := enrich.LLMNRName(ip, opts.Timeout); name != "" {
			host.Names.LLMNR = name
		}
		if host.Hostname == "" {
			host.Hostname = firstNonEmpty(host.Names.MDNS, host.Names.NetBIOS, host.Names.LLMNR)
		}
	}

	if opts.PortScan {
		ports := portscan.ScanViaNetBreak(ctx, ip, opts.Ports, opts.UdpPorts, opts.Timeout)
		if ports == nil {
			ports = portscan.Scan(ctx, ip, portscan.Options{
				Ports:       opts.Ports,
				Timeout:     opts.Timeout,
				Concurrency: 64,
				Banners:     true,
			})
		}
		if len(ports) > 0 {
			host.Ports = ports
			for _, p := range ports {
				if p.Port == 80 || p.Port == 8080 || p.Port == 443 || p.Port == 8443 {
					if title := enrich.HTTPTitle(ip, p.Port, opts.Timeout); title != "" && host.Hostname == "" {
						host.Hostname = title
					}
					break
				}
			}
		}
	}

	now := time.Now()
	host.FirstSeen = now
	host.LastSeen = now
	return host, true
}

func mergeARP(hosts []model.Host, arp map[string]string) {
	for i := range hosts {
		if hosts[i].MAC == "" {
			if mac, ok := arp[hosts[i].IP]; ok {
				hosts[i].MAC = mac
				hosts[i].Vendor = oui.Lookup(mac)
			}
		}
	}
}

func ipLess(a, b string) bool {
	ai, bi := ipBytes(a), ipBytes(b)
	for i := 0; i < len(ai) && i < len(bi); i++ {
		if ai[i] != bi[i] {
			return ai[i] < bi[i]
		}
	}
	return len(ai) < len(bi)
}

func ipBytes(s string) []byte {
	var out []byte
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			out = append(out, byte(n))
			n = 0
			continue
		}
		if c < '0' || c > '9' {
			return out
		}
		n = n*10 + int(c-'0')
	}
	out = append(out, byte(n))
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
