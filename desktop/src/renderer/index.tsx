import { useEffect, useMemo, useRef, useState } from 'react'
import './styles.css'
import * as api from './api'
import type { Core, Host, Change, Iface, ScanRequest } from './api'

type SortKey = 'ip' | 'hostname' | 'mac' | 'vendor' | 'ports'

function sortHosts(hosts: Host[], key: SortKey, dir: 1 | -1): Host[] {
  const copy = [...hosts]
  copy.sort((a, b) => {
    let va = ''
    let vb = ''
    switch (key) {
      case 'ip':
        va = a.ip
        vb = b.ip
        break
      case 'hostname':
        va = a.hostname || ''
        vb = b.hostname || ''
        break
      case 'mac':
        va = a.mac || ''
        vb = b.mac || ''
        break
      case 'vendor':
        va = a.vendor || ''
        vb = b.vendor || ''
        break
      case 'ports':
        va = String((a.ports || []).length)
        vb = String((b.ports || []).length)
        break
    }
    if (va < vb) return -1 * dir
    if (va > vb) return 1 * dir
    return 0
  })
  return copy
}

function ipLess(a: string, b: string): boolean {
  const pa = a.split('.').map((n) => Number(n))
  const pb = b.split('.').map((n) => Number(n))
  for (let i = 0; i < 4; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i]
  }
  return false
}

function portsLabel(host: Host): string {
  return (host.ports || []).map((p) => `${p.port}${p.service ? '/' + p.service : ''}`).join(' ')
}

export default function App() {
  const [core, setCore] = useState<Core | null>(null)
  const [coreReady, setCoreReady] = useState(false)
  const [coreError, setCoreError] = useState<string | null>(null)

  const [interfaces, setInterfaces] = useState<Iface[]>([])
  const [primaryCidr, setPrimaryCidr] = useState<string>('')

  const [target, setTarget] = useState('')
  const [portScan, setPortScan] = useState(true)
  const [enrich, setEnrich] = useState(true)
  const [ports, setPorts] = useState('80,443,22,23,25,53,110,135,139,143,445,993,995,3389,5900,8080,8443')
  const [timeoutMs, setTimeoutMs] = useState(1500)

  const [scanning, setScanning] = useState(false)
  const [scanId, setScanId] = useState<string | null>(null)
  const [progress, setProgress] = useState({ done: 0, total: 0 })
  const [status, setStatus] = useState('connecting to core...')
  const [hosts, setHosts] = useState<Host[]>([])
  const [error, setError] = useState<string | null>(null)

  const [selectedIp, setSelectedIp] = useState<string | null>(null)
  const [sortKey, setSortKey] = useState<SortKey>('ip')
  const [sortDir, setSortDir] = useState<1 | -1>(1)
  const [filter, setFilter] = useState('')

  const [tab, setTab] = useState<'devices' | 'changes'>('devices')
  const [changes, setChanges] = useState<Change[]>([])
  const [watchEnabled, setWatchEnabled] = useState(false)
  const [watchInterval, setWatchInterval] = useState(60)

  const stopStreamRef = useRef<(() => void) | null>(null)
  const watchTimerRef = useRef<number | null>(null)

  useEffect(() => {
    let alive = true
    const timer = window.setInterval(async () => {
      try {
        const c = await api.getCore()
        if (!alive) return
        setCore(c)
        if (c.url && c.token) {
          setCoreReady(true)
          setCoreError(null)
          setStatus('ready')
        }
      } catch (e) {
        if (alive) setCoreError(String(e))
      }
    }, 500)
    return () => {
      alive = false
      window.clearInterval(timer)
    }
  }, [])

  useEffect(() => {
    if (!coreReady || !core) return
    api
      .getInterfaces(core)
      .then((r) => {
        setInterfaces(r.interfaces)
        setPrimaryCidr(r.primary_cidr)
        if (!target) setTarget(r.primary_cidr)
      })
      .catch((e) => setError(String(e)))
  }, [coreReady, core])

  useEffect(() => {
    if (coreReady) setStatus('ready — press scan to discover hosts')
  }, [coreReady])

  const stopStream = () => {
    if (stopStreamRef.current) {
      stopStreamRef.current()
      stopStreamRef.current = null
    }
  }

  const runScan = async (silent = false) => {
    if (!core || !coreReady) return
    setError(null)
    stopStream()
    setScanning(true)
    setHosts([])
    setProgress({ done: 0, total: 0 })
    setStatus(silent ? 'watching: scanning…' : 'scanning…')

    let request: ScanRequest = { enrich, port_scan: portScan, timeout_ms: timeoutMs }
    if (target.trim()) {
      if (target.includes('/') || target.includes('-') || target.includes(',')) {
        request.cidr = target.trim()
      } else {
        request.targets = [target.trim()]
      }
    } else if (primaryCidr) {
      request.cidr = primaryCidr
    }
    if (portScan && ports.trim()) {
      request.ports = ports
        .split(',')
        .map((p) => Number(p.trim()))
        .filter((n) => Number.isFinite(n) && n > 0 && n < 65536)
    }

    try {
      const started = await api.startScan(core, request)
      setScanId(started.id)
      setProgress({ done: 0, total: started.total })
      const stop = api.streamScan(
        core,
        started.id,
        (event) => {
          switch (event.type) {
            case 'progress':
              setProgress({ done: event.done || 0, total: event.total || started.total })
              break
            case 'host':
              if (event.host) {
                setHosts((prev) => {
                  const next = [...prev.filter((h) => h.ip !== event.host!.ip), event.host!]
                  return next.sort((a, b) => (ipLess(a.ip, b.ip) ? -1 : 1))
                })
              }
              break
            case 'done':
              setScanning(false)
              setStatus(`done — ${event.total || 0} host(s) up`)
              void api.getDiff(core).then((r) => setChanges(r.changes || []))
              break
          }
        },
        () => {
          setScanning(false)
          setStatus('stream error — check the core process')
        },
      )
      stopStreamRef.current = stop
    } catch (e) {
      setScanning(false)
      setError(String(e))
      setStatus('scan failed')
    }
  }

  const cancel = async () => {
    if (core && scanId) {
      try {
        await api.cancelScan(core, scanId)
      } catch {
      }
    }
    stopStream()
    setScanning(false)
    setStatus('cancelled')
  }

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === 1 ? -1 : 1))
    else {
      setSortKey(key)
      setSortDir(1)
    }
  }

  const sortedHosts = useMemo(() => sortHosts(hosts, sortKey, sortDir), [hosts, sortKey, sortDir])

  const filteredHosts = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return sortedHosts
    return sortedHosts.filter((h) => {
      return (
        h.ip.includes(q) ||
        (h.hostname || '').toLowerCase().includes(q) ||
        (h.mac || '').toLowerCase().includes(q) ||
        (h.vendor || '').toLowerCase().includes(q) ||
        portsLabel(h).toLowerCase().includes(q)
      )
    })
  }, [sortedHosts, filter])

  const selected = useMemo(() => hosts.find((h) => h.ip === selectedIp) || null, [hosts, selectedIp])

  useEffect(() => {
    if (!watchEnabled || !coreReady) {
      if (watchTimerRef.current) {
        window.clearInterval(watchTimerRef.current)
        watchTimerRef.current = null
      }
      return
    }
    const id = window.setInterval(() => {
      if (!scanning) void runScan(true)
    }, watchInterval * 1000)
    watchTimerRef.current = id
    return () => {
      window.clearInterval(id)
      watchTimerRef.current = null
    }
  }, [watchEnabled, watchInterval, coreReady, scanning])

  const exportFile = (format: string) => {
    if (!core) return
    try {
      const url = api.exportURL(core, format)
      window.open(url, '_blank')
    } catch (e) {
      setError(String(e))
    }
  }

  const sendWol = async (mac: string) => {
    if (!core) return
    try {
      await api.wake(core, mac)
      setStatus(`wake-on-lan packet sent to ${mac}`)
    } catch (e) {
      setError(String(e))
    }
  }

  return (
    <div className="app">
      <div className="topbar">
        <span className="wordmark">MapIp</span>
        <span className="tagline">network host mapper — desktop edition</span>
        <span style={{ marginLeft: 'auto', color: 'var(--dim)', fontSize: 11 }}>
          {coreReady ? 'core online' : 'waiting for core…'}
        </span>
      </div>

      <div className="disclaimer">
        MapIp maps the hosts on your own network. It does not geolocate IP addresses. No telemetry, no third-party IP
        lookups.
      </div>

      {error && <div className="notice">{error}</div>}

      <div className="toolbar">
        <div className="field grow">
          <label>target</label>
          <input
            style={{ width: '100%' }}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={primaryCidr || '192.168.1.0/24'}
            disabled={scanning}
          />
        </div>
        <div className="field">
          <label>
            <input type="checkbox" checked={portScan} onChange={(e) => setPortScan(e.target.checked)} /> ports
          </label>
        </div>
        <div className="field">
          <label>
            <input type="checkbox" checked={enrich} onChange={(e) => setEnrich(e.target.checked)} /> enrich
          </label>
        </div>
        <div className="field">
          <label>timeout</label>
          <input
            style={{ width: 74 }}
            type="number"
            value={timeoutMs}
            onChange={(e) => setTimeoutMs(Number(e.target.value))}
            disabled={scanning}
          />
        </div>
        {!scanning ? (
          <button className="primary" onClick={() => void runScan()} disabled={!coreReady || (!target.trim() && !primaryCidr)}>
            Scan
          </button>
        ) : (
          <button className="danger" onClick={() => void cancel()}>
            Cancel
          </button>
        )}
        <div className="field">
          <label>
            <input type="checkbox" checked={watchEnabled} onChange={(e) => setWatchEnabled(e.target.checked)} /> watch
          </label>
          <input
            style={{ width: 52 }}
            type="number"
            value={watchInterval}
            onChange={(e) => setWatchInterval(Number(e.target.value))}
            disabled={!watchEnabled}
            title="seconds between rescans"
          />
          <span style={{ color: 'var(--dim)', fontSize: 11 }}>s</span>
        </div>
      </div>

      {portScan && (
        <div className="toolbar" style={{ borderTop: 'none', paddingTop: 0 }}>
          <div className="field grow">
            <label>ports</label>
            <input style={{ width: '100%' }} value={ports} onChange={(e) => setPorts(e.target.value)} disabled={scanning} />
          </div>
          <div className="field">
            <label>filter</label>
            <input style={{ width: 200 }} value={filter} onChange={(e) => setFilter(e.target.value)} />
          </div>
        </div>
      )}

      <div className="progress">
        <span style={{ width: `${progress.total ? Math.min(100, (progress.done / progress.total) * 100) : 0}%` }} />
      </div>

      <div className="tabs">
        <button className={`tab ${tab === 'devices' ? 'active' : ''}`} onClick={() => setTab('devices')}>
          Devices ({hosts.length})
        </button>
        <button className={`tab ${tab === 'changes' ? 'active' : ''}`} onClick={() => setTab('changes')}>
          Changes ({changes.length})
        </button>
      </div>

      {tab === 'devices' && (
        <div className="main">
          <div className="panel">
            <h2>Discovered hosts</h2>
            <div className="scroll">
              {filteredHosts.length === 0 ? (
                <div className="empty">
                  {scanning ? 'scanning…' : 'no hosts yet — press Scan to discover your network'}
                </div>
              ) : (
                <table>
                  <thead>
                    <tr>
                      <th onClick={() => toggleSort('ip')}>IP</th>
                      <th onClick={() => toggleSort('hostname')}>Hostname</th>
                      <th onClick={() => toggleSort('mac')}>MAC</th>
                      <th onClick={() => toggleSort('vendor')}>Vendor</th>
                      <th onClick={() => toggleSort('ports')}>Ports</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredHosts.map((h) => (
                      <tr
                        key={h.ip}
                        className={selectedIp === h.ip ? 'selected' : ''}
                        onClick={() => setSelectedIp(h.ip)}
                      >
                        <td className="ip">{h.ip}</td>
                        <td>{h.hostname || '-'}</td>
                        <td className="mac">{h.mac || '-'}</td>
                        <td>{h.vendor || '-'}</td>
                        <td>{portsLabel(h) || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          <div className="panel">
            <h2>Device detail</h2>
            {selected ? (
              <div className="detail">
                <div className="kv">
                  <dt>IP</dt>
                  <dd className="ip">{selected.ip}</dd>
                  <dt>Hostname</dt>
                  <dd>{selected.hostname || '-'}</dd>
                  <dt>MAC</dt>
                  <dd className="mac">{selected.mac || '-'}</dd>
                  <dt>Vendor</dt>
                  <dd>{selected.vendor || '-'}</dd>
                  <dt>OS</dt>
                  <dd>{selected.os || '-'}</dd>
                  <dt>TTL</dt>
                  <dd>{selected.ttl || '-'}</dd>
                  <dt>RTT</dt>
                  <dd>{selected.rtt_ms ? selected.rtt_ms.toFixed(1) + ' ms' : '-'}</dd>
                </div>

                <div>
                  <div style={{ color: 'var(--orange)', marginBottom: 4, fontSize: 11, textTransform: 'uppercase' }}>
                    Name resolution
                  </div>
                  <div className="kv">
                    <dt>mDNS</dt>
                    <dd>{selected.names?.mdns || '-'}</dd>
                    <dt>NetBIOS</dt>
                    <dd>{selected.names?.netbios || '-'}</dd>
                    <dt>LLMNR</dt>
                    <dd>{selected.names?.llmnr || '-'}</dd>
                  </div>
                </div>

                <div>
                  <div style={{ color: 'var(--orange)', marginBottom: 4, fontSize: 11, textTransform: 'uppercase' }}>
                    Open ports
                  </div>
                  {selected.ports && selected.ports.length > 0 ? (
                    <div className="ports">
                      {selected.ports.map((p) => (
                        <span key={p.port} className="badge" title={p.banner}>
                          {p.port}/{p.service || p.state}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="dim">none detected</div>
                  )}
                  {selected.ports?.map((p) =>
                    p.banner ? (
                      <div key={'b' + p.port} style={{ marginTop: 6, fontSize: 11, color: 'var(--dim)' }}>
                        <span style={{ color: 'var(--accent)' }}>{p.port}</span> {p.banner}
                      </div>
                    ) : null,
                  )}
                </div>

                {selected.mac && (
                  <button onClick={() => void sendWol(selected.mac)}>Wake-on-LAN</button>
                )}
              </div>
            ) : (
              <div className="empty">select a device to inspect it</div>
            )}
          </div>
        </div>
      )}

      {tab === 'changes' && (
        <div className="main" style={{ gridTemplateColumns: '1fr' }}>
          <div className="panel">
            <h2>Changes since the previous scan</h2>
            <div className="scroll changes">
              {changes.length === 0 ? (
                <div className="empty">no changes yet — run at least two scans</div>
              ) : (
                <ul>
                  {changes.map((c, i) => (
                    <li key={i}>
                      <span className={`pill ${c.kind === 'new' ? 'new' : c.kind === 'missing' ? 'missing' : 'changed'}`}>
                        {c.kind}
                      </span>{' '}
                      <span className="ip">{c.ip}</span> <span className="dim">{c.detail}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="statusbar">
        <span className={`dot ${scanning ? 'scanning' : coreReady ? 'on' : ''}`} />
        <span style={{ flex: 1 }}>{status}</span>
        <span>
          {progress.total ? `${progress.done}/${progress.total} probed` : ''}
        </span>
        <button onClick={() => exportFile('csv')} disabled={hosts.length === 0}>
          CSV
        </button>
        <button onClick={() => exportFile('json')} disabled={hosts.length === 0}>
          JSON
        </button>
        <button onClick={() => exportFile('html')} disabled={hosts.length === 0}>
          HTML
        </button>
        <button onClick={() => exportFile('xml')} disabled={hosts.length === 0}>
          Nmap XML
        </button>
      </div>
    </div>
  )
}
