package tui

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/5evenTeam/mapip/internal/discovery"
	"github.com/5evenTeam/mapip/internal/model"
	"github.com/5evenTeam/mapip/internal/netutil"
	"github.com/5evenTeam/mapip/internal/output"
	"github.com/5evenTeam/mapip/internal/portscan"
	"github.com/5evenTeam/mapip/internal/store"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("213"))
	noteStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("208"))
	upStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	accentStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	statusStyle = lipgloss.NewStyle().Background(lipgloss.Color("236")).Foreground(lipgloss.Color("252")).Padding(0, 1)
	helpStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)

type progressMsg discovery.Progress
type closedMsg struct {
	count int
	path  string
	err   error
}
type tickMsg time.Time
type exportMsg struct {
	path string
	err  error
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
	err      string

	width, height int
	scroll        int
	filter        string
	filtering     bool

	mode string

	changes []store.Change

	cancel context.CancelFunc
	prog   chan discovery.Progress
	box    *resultBox

	watch         bool
	watchInterval time.Duration
	lastScan      time.Time

	help bool
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
	if len(ports) == 0 && portScan {
		ports = portscan.DefaultPorts()
	}
	return Model{
		targets:       targets,
		ports:         ports,
		portScan:      portScan,
		enrich:        true,
		timeout:       timeout,
		seen:          map[string]bool{},
		status:        "ready — press s to scan " + targets,
		mode:          "devices",
		watchInterval: 60 * time.Second,
	}
}

func Run(targets string, ports []int, portScan bool, timeout time.Duration) error {
	p := tea.NewProgram(New(targets, ports, portScan, timeout), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(tea.EnterAltScreen, func() tea.Msg { return nil })
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		if m.filtering {
			switch msg.String() {
			case "enter", "esc":
				m.filtering = false
				if msg.String() == "esc" {
					m.filter = ""
				}
				return m, nil
			case "backspace":
				if len(m.filter) > 0 {
					m.filter = m.filter[:len(m.filter)-1]
				}
				return m, nil
			default:
				if len(msg.String()) == 1 {
					m.filter += msg.String()
				}
				return m, nil
			}
		}

		switch msg.String() {
		case "q", "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		case "s", "r":
			if !m.scanning {
				return m, m.startScan()
			}
		case "w":
			m.watch = !m.watch
			if m.watch {
				m.status = "watch mode on — rescanning every " + m.watchInterval.String()
			} else {
				m.status = "watch mode off"
			}
			return m, nil
		case "h", "?":
			m.help = !m.help
			return m, nil
		case "tab":
			if m.mode == "devices" {
				m.mode = "changes"
			} else {
				m.mode = "devices"
			}
			return m, nil
		case "e":
			return m, m.export("json")
		case "c":
			return m, m.export("csv")
		case "x":
			return m, m.export("xml")
		case "/":
			m.filtering = true
			m.filter = ""
			return m, nil
		case "down", "j":
			if m.scroll < len(m.visibleHosts())-1 {
				m.scroll++
			}
		case "up", "k":
			if m.scroll > 0 {
				m.scroll--
			}
		case "g":
			m.scroll = 0
		case "G":
			hosts := m.visibleHosts()
			if len(hosts) > 0 {
				m.scroll = len(hosts) - 1
			}
		}
		return m, nil

	case progressMsg:
		p := discovery.Progress(msg)
		m.done = p.Done
		if p.Total > 0 {
			m.total = p.Total
		}
		if p.Found && p.Host.IP != "" {
			if !m.seen[p.Host.IP] {
				m.seen[p.Host.IP] = true
				m.hosts = append(m.hosts, p.Host)
				sortHosts(m.hosts)
			}
		}
		if m.prog != nil {
			return m, readProgress(m.prog)
		}
		return m, nil

	case closedMsg:
		m.scanning = false
		m.lastScan = time.Now()
		m.status = fmt.Sprintf("done — %d host(s) up in %s", len(m.hosts), time.Since(m.lastScan).Round(time.Millisecond))
		if msg.path != "" {
			m.status += "  •  saved " + msg.path
		}
		if msg.err != nil {
			m.err = msg.err.Error()
			m.status = "error: " + msg.err.Error()
		}
		if m.box != nil {
			m.box.mu.Lock()
			snap := store.Snapshot{TakenAt: time.Now(), Targets: parseTargets(m.targets), Hosts: m.box.hosts}
			prev, _ := store.New("").Latest()
			if prev.Hosts != nil {
				m.changes = store.Diff(prev, snap)
			}
			m.box.mu.Unlock()
		}
		if m.watch {
			return m, tea.Tick(m.watchInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
		}
		return m, nil

	case tickMsg:
		if m.watch && !m.scanning {
			return m, m.startScan()
		}
		return m, nil

	case exportMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
			m.status = "export failed: " + msg.err.Error()
		} else {
			m.status = "exported to " + msg.path
		}
		return m, nil
	}

	return m, nil
}

func (m *Model) startScan() tea.Cmd {
	ips, err := netutil.ParseTargets(m.targets)
	if err != nil || len(ips) == 0 {
		m.err = "no usable targets in " + m.targets
		m.status = m.err
		return nil
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
	m.err = ""
	m.status = fmt.Sprintf("scanning %d address(es) in %s", len(ips), m.targets)

	box := &resultBox{}
	m.box = box
	prog := make(chan discovery.Progress, 1024)
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
		st := store.New("")
		if p, err := st.Save(store.Snapshot{TakenAt: time.Now(), Targets: ips, Hosts: res.Hosts}); err == nil {
			path = p
		}
		box.mu.Lock()
		box.hosts = res.Hosts
		box.path = path
		box.mu.Unlock()
		close(prog)
	}()

	return readProgress(prog)
}

func readProgress(ch chan discovery.Progress) tea.Cmd {
	return func() tea.Msg {
		p, ok := <-ch
		if !ok {
			return closedMsg{}
		}
		return progressMsg(p)
	}
}

func (m Model) visibleHosts() []model.Host {
	if m.filter == "" {
		return m.hosts
	}
	q := strings.ToLower(m.filter)
	var out []model.Host
	for _, h := range m.hosts {
		if strings.Contains(strings.ToLower(h.IP), q) ||
			strings.Contains(strings.ToLower(h.Hostname), q) ||
			strings.Contains(strings.ToLower(h.MAC), q) ||
			strings.Contains(strings.ToLower(h.Vendor), q) {
			out = append(out, h)
		}
	}
	return out
}

func (m Model) export(format string) tea.Cmd {
	return func() tea.Msg {
		st := store.New("")
		snap, ok := st.Latest()
		if !ok {
			return exportMsg{err: fmt.Errorf("no scan to export")}
		}
		report := model.ScanReport{Targets: snap.Targets, Hosts: snap.Hosts, Started: snap.TakenAt, Finished: snap.TakenAt}
		name := "mapip-" + time.Now().Format("20060102-150405")
		var ext string
		switch format {
		case "csv":
			ext = ".csv"
		case "xml":
			ext = ".xml"
		case "html":
			ext = ".html"
		default:
			ext = ".json"
			format = "json"
		}
		f, err := os.Create(name + ext)
		if err != nil {
			return exportMsg{err: err}
		}
		defer f.Close()
		var werr error
		switch format {
		case "csv":
			werr = output.WriteCSV(f, report)
		case "xml":
			werr = output.WriteNmapXML(f, report)
		case "html":
			werr = output.WriteHTML(f, report)
		default:
			werr = output.WriteJSON(f, report)
		}
		if werr != nil {
			return exportMsg{err: werr}
		}
		return exportMsg{path: name + ext}
	}
}

func (m Model) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("MapIp") + dimStyle.Render("  network host mapper  (TUI)") + "\n")
	b.WriteString(noteStyle.Render("Maps hosts on your own network. Does not geolocate IP addresses.") + "\n\n")

	if m.help {
		b.WriteString(helpStyle.Render("Keys:\n"))
		b.WriteString(helpStyle.Render("  s/r   rescan          w       toggle watch mode\n"))
		b.WriteString(helpStyle.Render("  ↑/↓   scroll          g/G     top/bottom\n"))
		b.WriteString(helpStyle.Render("  tab   devices/changes  /       filter\n"))
		b.WriteString(helpStyle.Render("  e     export json     c       export csv\n"))
		b.WriteString(helpStyle.Render("  x     export xml      h/?     this help\n"))
		b.WriteString(helpStyle.Render("  q     quit\n\n"))
		b.WriteString(helpStyle.Render("Watch mode rescans automatically every " + m.watchInterval.String() + ".\n"))
		b.WriteString(helpStyle.Render("Press h to close this screen.\n"))
		return b.String()
	}

	b.WriteString(headerStyle.Render("targets  ") + m.targets + "\n")
	if m.portScan {
		b.WriteString(headerStyle.Render("ports    ") + fmt.Sprint(m.ports) + "\n")
	}
	if m.filter != "" || m.filtering {
		b.WriteString(headerStyle.Render("filter   ") + m.filter + ifelse(m.filtering, "_", "") + "\n")
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

	limit := m.height - 14
	if limit < 3 {
		limit = 3
	}

	if m.mode == "devices" {
		b.WriteString(headerStyle.Render(fmt.Sprintf("%-16s %-20s %-18s %-18s %s",
			"IP", "HOSTNAME", "MAC", "VENDOR", "PORTS")) + "\n")

		hosts := m.visibleHosts()
		if len(hosts) == 0 {
			b.WriteString(dimStyle.Render("  no hosts found yet") + "\n")
		}
		for i, h := range hosts {
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
			line := fmt.Sprintf("%-16s %-20s %-18s %-18s %s",
				h.IP, dash(h.Hostname), dash(h.MAC), dash(h.Vendor), strings.Join(ports, " "))
			style := upStyle
			if i == m.scroll {
				style = accentStyle
			}
			b.WriteString(style.Render(line) + "\n")
		}
		if len(hosts) > limit {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  showing %d-%d of %d",
				m.scroll+1, minInt(m.scroll+limit, len(hosts)), len(hosts))) + "\n")
		}
	} else {
		b.WriteString(headerStyle.Render("Changes since previous scan") + "\n")
		if len(m.changes) == 0 {
			b.WriteString(dimStyle.Render("  no changes yet — run at least two scans") + "\n")
		}
		for _, c := range m.changes {
			color := upStyle
			switch c.Kind {
			case "missing", "port-closed":
				color = errStyle
			case "new", "port-opened":
				color = okStyle
			}
			b.WriteString(color.Render(fmt.Sprintf("  %-16s %-18s %s", c.IP, c.Kind, c.Detail)) + "\n")
		}
	}

	b.WriteString("\n")
	if m.err != "" {
		b.WriteString(errStyle.Render("error: "+m.err) + "\n")
	}
	b.WriteString(statusStyle.Render(m.status))
	b.WriteString("\n")
	watch := "off"
	if m.watch {
		watch = "on"
	}
	b.WriteString(dimStyle.Render(fmt.Sprintf("[s] scan  [w] watch:%s  [tab] %s  [/] filter  [e/c/x] export  [h] help  [q] quit",
		watch, m.mode)))
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

func ifelse(cond bool, a, b string) string {
	if cond {
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

func parseTargets(s string) []string {
	ips, _ := netutil.ParseTargets(s)
	return ips
}
