export type Core = { url: string | null; token: string | null }

export type Port = {
  port: number
  proto: string
  state: string
  service: string
  banner: string
}

export type Names = {
  mdns: string
  llmnr: string
  netbios: string
  ssdp: string
  snmp: string
  dhcp: string
}

export type Host = {
  ip: string
  hostname: string
  mac: string
  vendor: string
  ttl: number
  os: string
  alive: boolean
  rtt_ms: number
  ports: Port[] | null
  names: Names
  first_seen: string
  last_seen: string
}

export type Change = { ip: string; kind: string; detail: string }

export type ScanEvent = {
  type: 'snapshot' | 'progress' | 'host' | 'done'
  host?: Host
  done?: number
  total?: number
  text?: string
}

export type ScanRequest = {
  targets?: string[]
  cidr?: string
  ports?: number[]
  port_scan?: boolean
  enrich?: boolean
  timeout_ms?: number
}

export type Iface = { name: string; address: string; cidr: string; private: boolean }

declare global {
  interface Window {
    api: { getCore: () => Promise<Core> }
  }
}

export function getCore(): Promise<Core> {
  return window.api.getCore()
}

function headers(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
}

function requireCore(core: Core): { url: string; token: string } {
  if (!core.url) throw new Error('core address not available yet')
  if (!core.token) throw new Error('core token not available yet')
  return { url: core.url, token: core.token }
}

export async function getJSON<T>(core: Core, path: string): Promise<T> {
  const { url, token } = requireCore(core)
  const res = await fetch(url + path, { headers: headers(token) })
  if (!res.ok) throw new Error(`${path} returned ${res.status}`)
  return (await res.json()) as T
}

export async function postJSON<T>(core: Core, path: string, body: unknown): Promise<T> {
  const { url, token } = requireCore(core)
  const res = await fetch(url + path, {
    method: 'POST',
    headers: headers(token),
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`${path} returned ${res.status}`)
  return (await res.json()) as T
}

export function startScan(core: Core, req: ScanRequest): Promise<{ id: string; total: number; targets: string[] }> {
  return postJSON(core, '/api/scan', req)
}

export function cancelScan(core: Core, id: string): Promise<unknown> {
  return postJSON(core, `/api/scan/${id}/cancel`, {})
}

export function getInterfaces(core: Core): Promise<{ interfaces: Iface[]; primary_cidr: string }> {
  return getJSON(core, '/api/interfaces')
}

export function getDiff(core: Core): Promise<{ before?: string; after?: string; changes: Change[] }> {
  return getJSON(core, '/api/diff')
}

export function wake(core: Core, mac: string): Promise<unknown> {
  return postJSON(core, '/api/wol', { mac })
}

export function exportURL(core: Core, format: string): string {
  const { url, token } = requireCore(core)
  return `${url}/api/export?format=${format}&token=${token}`
}

export function streamScan(
  core: Core,
  id: string,
  onEvent: (event: ScanEvent) => void,
  onError: () => void,
): () => void {
  const { url, token } = requireCore(core)
  const source = new EventSource(`${url}/api/scan/${id}/events?token=${token}`)

  source.onmessage = (message) => {
    try {
      onEvent(JSON.parse(message.data) as ScanEvent)
    } catch {
      // malformed frames are ignored; the stream stays open
    }
  }
  source.onerror = () => {
    source.close()
    onError()
  }

  return () => source.close()
}
