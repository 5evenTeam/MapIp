import { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { EventSource } from 'eventsource'

type Core = { url: string | null; token: string | null }
type Host = { ip: string; hostname: string; mac: string; vendor: string; ports: any[] }

function App() {
  const [core, setCore] = useState<Core>({ url: null, token: null })
  const [hosts, setHosts] = useState<Host[]>([])
  const [progress, setProgress] = useState<{ done: number; total: number }>({ done: 0, total: 0 })
  const [status, setStatus] = useState('connecting to core...')

  useEffect(() => {
    const tick = setInterval(async () => {
      const c = await (window as any).api.getCore()
      setCore(c)
    }, 500)
    return () => clearInterval(tick)
  }, [])

  const start = async () => {
    if (!core.url || !core.token) return
    setStatus('starting scan...')
    setHosts([])
    const res = await fetch(core.url + '/api/interfaces')
    const ints = await res.json().catch(() => ({}))
    const cidr = ints.primary_cidr
    const r = await fetch(core.url + '/api/scan', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + core.token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ cidr, port_scan: true, enrich: true, timeout_ms: 1500 }),
    })
    const j = await r.json()
    const es = new EventSource(core.url + '/api/scan/' + j.id + '/events?token=' + core.token)
    es.onmessage = (ev: any) => {
      try {
        const d = JSON.parse(ev.data)
        if (d.type === 'progress') setProgress({ done: d.done, total: d.total })
        if (d.type === 'host') setHosts(h => [...h, d.host].sort((a,b) => a.ip.localeCompare(b.ip)))
        if (d.type === 'done') setStatus('done')
      } catch (e) {}
    }
    es.onerror = () => setStatus('stream error')
  }

  return (
    <div style={{ fontFamily: 'ui-monospace, Menlo, monospace', background: '#0b0f14', color: '#c9d1d9', padding: 16, minHeight: '100vh' }}>
      <h1 style={{ color: '#58a6ff', fontSize: 18 }}>MapIp — Network Host Mapper (NOT geolocation)</h1>
      <p style={{ color: '#8b949e' }}>Maps hosts on your own network. It does not geolocate IP addresses.</p>
      <button onClick={start} style={{ background: '#238636', color: 'white', border: 'none', padding: '6px 10px', cursor: 'pointer' }}>Scan local subnet (with ports)</button>
      <p style={{ color: '#f0883e' }}>{progress.done}/{progress.total} probed   {status}</p>
      <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: 16 }}>
        <thead>
          <tr style={{ color: '#f0883e' }}>
            <th style={{ textAlign: 'left', borderBottom: '1px solid #21262d', padding: 6 }}>IP</th>
            <th style={{ textAlign: 'left', borderBottom: '1px solid #21262d', padding: 6 }}>Hostname</th>
            <th style={{ textAlign: 'left', borderBottom: '1px solid #21262d', padding: 6 }}>MAC</th>
            <th style={{ textAlign: 'left', borderBottom: '1px solid #21262d', padding: 6 }}>Vendor</th>
            <th style={{ textAlign: 'left', borderBottom: '1px solid #21262d', padding: 6 }}>Ports</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map(h => (
            <tr key={h.ip}>
              <td style={{ borderBottom: '1px solid #21262d', padding: 6 }}>{h.ip}</td>
              <td style={{ borderBottom: '1px solid #21262d', padding: 6 }}>{h.hostname || '-'}</td>
              <td style={{ borderBottom: '1px solid #21262d', padding: 6 }}>{h.mac || '-'}</td>
              <td style={{ borderBottom: '1px solid #21262d', padding: 6 }}>{h.vendor || '-'}</td>
              <td style={{ borderBottom: '1px solid #21262d', padding: 6 }}>{(h.ports||[]).map(p => p.port + (p.service?'/'+p.service:'')).join(' ') || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const root = createRoot(document.getElementById('root')!)
root.render(<App />)
