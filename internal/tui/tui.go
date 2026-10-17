package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/5evenTeam/mapip/internal/discovery"
	"github.com/5evenTeam/mapip/internal/model"
	"github.com/5evenTeam/mapip/internal/netutil"
	"github.com/5evenTeam/mapip/internal/store"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("213"))
	noteStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("208"))
	upStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	accentStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	statusStyle = lipgloss.NewStyle().Background(lipgloss.Color("236")).Foreground(lipgloss.Color("252")).Padding(0, 1)
)

type startScanMsg struct{}

type progressMsg struct{ done, total int }

type hostMsg model.Host

type scanClosedMsg struct {
	hosts []model.Host
	path  string
	err   error
}

type resultBox struct {
	mu    sync.Mutex
	hosts []model.Host
	path  string
	err   error
}

type Model struct {
	targets  string
	ports    []int
	portScan bool
	enrich   bool
	timeout  time.Duration

	hosts    []model.Host
	seen     map[string]bool
	done     int
	total    int
	scanning bool
	status   string

	width, height int
	scroll        int

	cancel context.CancelFunc
	prog   chan discovery.Progress
	box    *resultBox
}

func New(targets string, ports []int, portScan bool, timeout time.Duration) Model {
	if targets == "" {
		if cidr, err := netutil.PrimaryLocalCIDR(); err == nil {
			targets = cidr
		} else {
			targets = "127.0.0.1"
		}
	}
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	return Model{
		targets:  targets,
		ports:    ports,
		portScan: portScan,
		enrich:   true,
		timeout:  timeout,
		seen:     map[string]bool{},
		status:   "ready — starting scan of " + targets,
	}
}

func Run(targets string, ports []int, portScan bool, timeout time.Duration) error {
	p := tea.NewProgram(New(targets, ports, portScan, timeout), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m Model) Init() tea.Cmd {
	return func() tea.Msg { return startScanMsg{} }
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case startScanMsg:
		ips, err := netutil.ParseTargets(m.targets)
		if err != nil || len(ips) == 0 {
			m.status = "no usable targets in " + m.targets
			return m, nil
		}
		ips = netutil.NormalizeTargets(ips)

		ctx, cancel := context.WithCancel(context.Background())
		m.cancel = cancel
		m.scanning = true
		m.total = len(ips)
		m.done = 0
		m.hosts = nil
		m.seen = map[string]bool{}
		m.scroll = 0
		m.status = fmt.Sprintf("scanning %d address(es) in %s", len(ips), m.targets)

		box := &resultBox{}
		m.box = box
		prog := make(chan discovery.Progress, 512)
		m.prog = prog

		opts := discovery.Options{
			Targets:     ips,
			Timeout:     m.timeout,
			Concurrency: 64,
			Ports:       m.ports,
			PortScan:    m.portScan,
			Enrich:      m.enrich,
		}

		go func() {
			res := discovery.ScanAll(ctx, opts, func(p discovery.Progress) {
				select {
				case prog <- p:
				default:
				}
			})
			path := ""
			if st := store.New(""); st != nil {
				if p, err := st.Save(store.Snapshot{
					TakenAt: time.Now(),
					Targets: ips,
					Hosts:   res.Hosts,
				}); err == nil {
					path = p
				}
			}
			box.mu.Lock()
			box.hosts = res.Hosts
			box.path = path
			box.mu.Unlock()
			close(prog)
		}()

		return m, readProgress(prog)

	case progressMsg:
		m.done = msg.done
		if msg.total > 0 {
			m.total = msg.total
		}
		return m, readProgress(m.prog)

	case hostMsg:
		h := model.Host(msg)
		if !m.seen[h.IP] {
			m.seen[h.IP] = true
			m.hosts = append(m.hosts, h)
			sortHosts(m.hosts)
		}
		m.done++
		return m, readProgress(m.prog)

	case scanClosedMsg:
		m.scanning = false
		m.status = fmt.Sprintf("done — %d host(s) up", len(m.hosts))
		if msg.path != "" {
			m.status += "  •  saved to " + msg.path
		}
		if msg.err != nil {
			m.status = "error: " + msg.err.Error()
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		case "s", "r":
			if !m.scanning {
				return m, func() tea.Msg { return startScanMsg{} }
			}
		case "down", "j":
			if m.scroll < len(m.hosts)-1 {
				m.scroll++
			}
		case "up", "k":
			if m.scroll > 0 {
				m.scroll--
			}
		case "g":
			m.scroll = 0
		}
	}
	return m, nil
}

func readProgress(ch chan discovery.Progress) tea.Cmd {
	return func() tea.Msg {
		p, ok := <-ch
		if !ok {
			return scanClosedMsg{}
		}
		if p.Found {
			return hostMsg(p.Host)
		}
		return progressMsg{done: p.Done, total: p.Total}
	}
}

func (m Model) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("MapIp") + dimStyle.Render("   network host mapper") + "\n")
	b.WriteString(noteStyle.Render("Maps hosts on your own network. It does not geolocate IP addresses.") + "\n")
	b.WriteString(noteStyle.Render("https://github.com/5evenTeam/mapip") + "\n\n")

	b.WriteString(headerStyle.Render("targets  ") + m.targets + "\n")
	if m.portScan {
		b.WriteString(headerStyle.Render("ports    ") + fmt.Sprint(m.ports) + "\n")
	}
	b.WriteString("\n")

	barWidth := m.width - 24
	if barWidth < 12 {
		barWidth = 12
	}
	if barWidth > 60 {
		barWidth = 60
	}
	b.WriteString(renderBar(m.done, m.total, barWidth) + "\n\n")

	limit := m.height - 11
	if limit < 3 {
		limit = 3
	}

	b.WriteString(headerStyle.Render(fmt.Sprintf("%-16s %-22s %-18s %-16s %s",
		"IP", "HOSTNAME", "MAC", "VENDOR", "PORTS")) + "\n")

	if len(m.hosts) == 0 {
		b.WriteString(dimStyle.Render("  no hosts found yet") + "\n")
	}
	for i, h := range m.hosts {
		if i < m.scroll || i >= m.scroll+limit {
			continue
		}
		ports := make([]string, 0, len(h.Ports))
		for _, p := range h.Ports {
			label := strconv.Itoa(p.Port)
			if p.Service != "" {
				label += "/" + p.Service
			}
			ports = append(ports, label)
		}
		line := fmt.Sprintf("%-16s %-22s %-18s %-16s %s",
			h.IP, dash(h.Hostname), dash(h.MAC), dash(h.Vendor), strings.Join(ports, " "))
		b.WriteString(upStyle.Render(line) + "\n")
	}

	if len(m.hosts) > limit {
		b.WriteString(dimStyle.Render(fmt.Sprintf("  showing %d-%d of %d",
			m.scroll+1, minInt(m.scroll+limit, len(m.hosts)), len(m.hosts))) + "\n")
	}

	b.WriteString("\n")
	b.WriteString(statusStyle.Render(m.status))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("[s] rescan   [↑/↓] scroll   [g] top   [q] quit"))
	return b.String()
}

func renderBar(done, total, width int) string {
	if total <= 0 {
		return dimStyle.Render(strings.Repeat("·", width))
	}
	filled := done * width / total
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return accentStyle.Render(bar) + "  " + strconv.Itoa(done*100/total) + "%"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func sortHosts(hosts []model.Host) {
	for i := 1; i < len(hosts); i++ {
		for j := i; j > 0 && ipLess(hosts[j].IP, hosts[j-1].IP); j-- {
			hosts[j], hosts[j-1] = hosts[j-1], hosts[j]
		}
	}
}

func ipLess(a, b string) bool {
	ab, bb := ipBytes(a), ipBytes(b)
	for i := 0; i < len(ab) && i < len(bb); i++ {
		if ab[i] != bb[i] {
			return ab[i] < bb[i]
		}
	}
	return len(ab) < len(bb)
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
	return append(out, byte(n))
}
