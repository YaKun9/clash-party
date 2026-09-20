import { mkdir, readFile, stat } from 'fs/promises'
import { isIP } from 'net'
import { dirname } from 'path'
import { atomicWriteFile, WriteQueue } from '../utils/safeFile'

const MAX_AGE_MS = 168 * 60 * 60 * 1000
const MAX_ENTRIES = 5000
const MAX_FILE_BYTES = 8 * 1024 * 1024

export interface IpPurityRecord {
  ip: string
  sourceKey: string
  score: number
  checkedAt: number
  scamalytics?: IProxyPurityProviderScamalytics
  proxycheck?: IProxyPurityProviderProxyCheck
}

interface NodeExitMapping {
  scope: string
  proxy: string
  ip: string
  probedAt: number
}

function object(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function score(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100
}

export function canonicalExitIp(value: unknown): string {
  if (typeof value !== 'string' || !isIP(value.trim())) throw new Error('Invalid exit IP')
  const ip = value.trim()
  return isIP(ip) === 6 ? new URL(`http://[${ip}]/`).hostname.slice(1, -1) : ip
}

export function ipPurityCacheMs(hours: unknown): number {
  const value = typeof hours === 'number' && Number.isFinite(hours) ? hours : 24
  return Math.max(0.25, Math.min(168, value)) * 60 * 60 * 1000
}

function fresh(at: unknown, ttl: number): at is number {
  return (
    typeof at === 'number' &&
    Number.isFinite(at) &&
    at > 0 &&
    at <= Date.now() &&
    Date.now() - at < ttl
  )
}

function decodeRecord(value: unknown): IpPurityRecord | undefined {
  if (
    !object(value) ||
    typeof value.sourceKey !== 'string' ||
    !/^[a-f0-9]{64}$/.test(value.sourceKey) ||
    !score(value.score) ||
    !fresh(value.checkedAt, MAX_AGE_MS)
  )
    return undefined
  let ip: string
  try {
    ip = canonicalExitIp(value.ip)
  } catch {
    return undefined
  }
  const result: IpPurityRecord = {
    ip,
    sourceKey: value.sourceKey,
    score: value.score,
    checkedAt: value.checkedAt
  }
  if (object(value.scamalytics) && score(value.scamalytics.score)) {
    result.scamalytics = { score: value.scamalytics.score }
    if (typeof value.scamalytics.risk === 'string') {
      result.scamalytics.risk = value.scamalytics.risk.slice(0, 128)
    }
  }
  if (object(value.proxycheck) && score(value.proxycheck.riskScore)) {
    const provider = value.proxycheck
    const parsed: IProxyPurityProviderProxyCheck = { riskScore: provider.riskScore as number }
    for (const key of ['proxy', 'vpn', 'tor', 'hosting', 'compromised', 'anonymous'] as const) {
      if (typeof provider[key] === 'boolean') parsed[key] = provider[key]
    }
    for (const key of ['networkType', 'provider', 'country'] as const) {
      if (typeof provider[key] === 'string') parsed[key] = provider[key].slice(0, 256)
    }
    if (score(provider.confidence)) parsed.confidence = provider.confidence
    result.proxycheck = parsed
  }
  return result.scamalytics || result.proxycheck ? result : undefined
}

// Only successful, sanitized IP results and last-probed mappings are persisted.
// Provider credentials, raw responses, errors and pending/failed tasks are excluded.
export class IpPurityCache {
  private readonly ips = new Map<string, IpPurityRecord>()
  private readonly nodes = new Map<string, NodeExitMapping>()
  private readonly writes = new WriteQueue()
  private loading?: Promise<void>

  constructor(private readonly filePath: () => string) {}

  load(): Promise<void> {
    if (!this.loading) this.loading = this.read()
    return this.loading
  }

  private async read(): Promise<void> {
    try {
      if ((await stat(this.filePath())).size > MAX_FILE_BYTES) return
      const value: unknown = JSON.parse(await readFile(this.filePath(), 'utf8'))
      if (!object(value) || value.version !== 1 || !object(value.byIp) || !object(value.nodes))
        return
      for (const [key, raw] of Object.entries(value.byIp).slice(-MAX_ENTRIES)) {
        const entry = decodeRecord(raw)
        if (entry && canonicalExitIp(key) === entry.ip) this.ips.set(entry.ip, entry)
      }
      for (const raw of Object.values(value.nodes).slice(-MAX_ENTRIES)) {
        if (
          !object(raw) ||
          typeof raw.scope !== 'string' ||
          raw.scope.length > 1024 ||
          typeof raw.proxy !== 'string' ||
          raw.proxy.length > 1024 ||
          typeof raw.ip !== 'string' ||
          !fresh(raw.probedAt, MAX_AGE_MS)
        )
          continue
        let ip: string
        try {
          ip = canonicalExitIp(raw.ip)
        } catch {
          continue
        }
        if (!this.ips.has(ip)) continue
        const mapping = { scope: raw.scope, proxy: raw.proxy, ip, probedAt: raw.probedAt }
        this.nodes.set(this.nodeKey(mapping.scope, mapping.proxy), mapping)
      }
    } catch (error) {
      this.ips.clear()
      this.nodes.clear()
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        console.warn('IP purity cache could not be read; starting with an empty cache')
      }
    }
  }

  nodeKey(scope: string, proxy: string): string {
    return JSON.stringify([scope, proxy])
  }

  getIp(ip: string, sourceKey: string, ttl: number): IpPurityRecord | undefined {
    const entry = this.ips.get(canonicalExitIp(ip))
    return entry && entry.sourceKey === sourceKey && fresh(entry.checkedAt, ttl) ? entry : undefined
  }

  setIp(entry: IpPurityRecord): void {
    const sanitized = decodeRecord(entry)
    if (!sanitized) throw new Error('Invalid IP purity cache record')
    this.ips.delete(sanitized.ip)
    this.ips.set(sanitized.ip, sanitized)
  }

  remember(scope: string, proxy: string, ip: string): void {
    const key = this.nodeKey(scope, proxy)
    this.nodes.delete(key)
    this.nodes.set(key, { scope, proxy, ip: canonicalExitIp(ip), probedAt: Date.now() })
  }

  forget(scope: string, proxy: string): void {
    this.nodes.delete(this.nodeKey(scope, proxy))
  }

  result(
    scope: string,
    proxy: string,
    sourceKey: string,
    ttl: number
  ): IProxyPurityResult | undefined {
    const node = this.nodes.get(this.nodeKey(scope, proxy))
    if (!node || !fresh(node.probedAt, ttl)) return undefined
    const entry = this.getIp(node.ip, sourceKey, ttl)
    if (!entry) return undefined
    return {
      proxy,
      ip: entry.ip,
      score: entry.score,
      checkedAt: entry.checkedAt,
      scamalytics: entry.scamalytics,
      proxycheck: entry.proxycheck
    }
  }

  results(scope: string, sourceKey: string, ttl: number): Record<string, IProxyPurityResult> {
    const entries: [string, IProxyPurityResult][] = []
    for (const node of this.nodes.values()) {
      if (node.scope !== scope) continue
      const result = this.result(scope, node.proxy, sourceKey, ttl)
      if (result) entries.push([node.proxy, result])
    }
    return Object.fromEntries(entries)
  }

  async save(): Promise<void> {
    await this.load()
    await this.writes.run(async () => {
      // Snapshot inside the queue, not before it: a later clear must win over
      // any earlier pending write. Cache hits never extend checkedAt/probedAt.
      for (const [ip, entry] of this.ips) {
        if (!fresh(entry.checkedAt, MAX_AGE_MS)) this.ips.delete(ip)
      }
      while (this.ips.size > MAX_ENTRIES) this.ips.delete(this.ips.keys().next().value!)
      for (const [key, node] of this.nodes) {
        if (!this.ips.has(node.ip) || !fresh(node.probedAt, MAX_AGE_MS)) this.nodes.delete(key)
      }
      while (this.nodes.size > MAX_ENTRIES) this.nodes.delete(this.nodes.keys().next().value!)
      const value = {
        version: 1,
        byIp: Object.fromEntries(this.ips),
        nodes: Object.fromEntries(this.nodes)
      }
      await mkdir(dirname(this.filePath()), { recursive: true })
      await atomicWriteFile(this.filePath(), JSON.stringify(value), { mode: 0o600 })
    })
  }

  async clear(): Promise<void> {
    await this.load()
    this.ips.clear()
    this.nodes.clear()
    await this.save()
  }
}
