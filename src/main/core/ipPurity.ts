import axios from 'axios'
import { getAppConfig, getProfileConfig } from '../config'
import { createHash } from 'crypto'
import { join } from 'path'
import { dataDir } from '../utils/dirs'
import {
  IpPurityCache,
  canonicalExitIp,
  ipPurityCacheMs,
  type IpPurityRecord
} from './ipPurityCache'
import { getAxios } from './mihomoApi'
import { ensureIpPurityPort, ipPurityGroupName, IP_PURITY_CONCURRENCY } from './ipPurityRuntime'
import { IpPurityPool } from './ipPurityPool'

const EGRESS_IP_URL = 'https://api.ipify.org?format=json'
const PROXYCHECK_API = 'https://proxycheck.io/v3'

interface ProxyCheckV3Response {
  status?: string
  [ip: string]: unknown
}

interface CheckContext {
  config: IAppConfig
  scope: string
  sourceKey: string
  ttl: number
  generation: number
}

interface PendingCheck {
  scope: string
  proxy: string
  generation: number
  promise: Promise<IProxyPurityResult>
}

const cache = new IpPurityCache(() => join(dataDir(), 'ip-purity-cache.json'))
const pendingChecks = new Map<string, PendingCheck>()
const failedChecks = new Map<string, { scope: string; proxy: string }>()
const purityPool = new IpPurityPool(IP_PURITY_CONCURRENCY)
const providerRequests = new Map<string, Promise<IpPurityRecord>>()
let cacheGeneration = 0

async function context(generation = cacheGeneration): Promise<CheckContext> {
  const [config, profile] = await Promise.all([getAppConfig(), getProfileConfig()])
  await cache.load()
  // Persist a fingerprint only, never credentials or endpoint URLs.
  // Changing providers/credentials cannot reuse the old combined score.
  const sourceKey = createHash('sha256')
    .update(
      JSON.stringify([
        config.ipPurityProxycheckApiKey ?? '',
        config.ipPurityScamalyticsEndpoint ?? '',
        config.ipPurityScamalyticsApiKey ?? ''
      ])
    )
    .digest('hex')
  return {
    config,
    sourceKey,
    generation,
    scope: JSON.stringify([profile.current ?? 'default', sourceKey]),
    ttl: ipPurityCacheMs(config.ipPurityCacheHours)
  }
}

async function persistCache(): Promise<void> {
  try {
    await cache.save()
  } catch {
    // A disk error must not turn a valid API response into a network timeout.
    console.warn('IP purity result is in memory but could not be saved locally')
  }
}

function buildScamalyticsUrl(endpoint: string, key: string, ip: string): string {
  const encodedIp = encodeURIComponent(ip)
  const encodedKey = encodeURIComponent(key)
  if (endpoint.includes('{ip}') || endpoint.includes('{key}')) {
    return endpoint.replaceAll('{ip}', encodedIp).replaceAll('{key}', encodedKey)
  }

  const url = new URL(endpoint)
  url.searchParams.set('ip', ip)
  if (key) url.searchParams.set('key', key)
  return url.toString()
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return undefined
}

function asScore(value: unknown): number | undefined {
  const score = asNumber(value)
  // Missing, malformed and out-of-range values are not valid zero-risk results.
  return score !== undefined && score >= 0 && score <= 100 ? score : undefined
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined
}

function parseScamalytics(data: unknown): IProxyPurityProviderScamalytics | undefined {
  if (!data || typeof data !== 'object') return undefined
  const obj = data as Record<string, unknown>
  const nested =
    obj.scamalytics && typeof obj.scamalytics === 'object'
      ? (obj.scamalytics as Record<string, unknown>)
      : obj

  const score = asScore(
    nested.scamalytics_score ?? nested.score ?? nested.fraud_score ?? obj.score ?? obj.fraud_score
  )
  if (score === undefined) return undefined

  const risk =
    typeof nested.scamalytics_risk === 'string'
      ? nested.scamalytics_risk
      : typeof nested.risk === 'string'
        ? nested.risk
        : undefined

  return { score, risk }
}

function parseProxyCheck(ip: string, data: unknown): IProxyPurityProviderProxyCheck | undefined {
  if (!data || typeof data !== 'object') return undefined
  const root = data as ProxyCheckV3Response
  if (root.status && root.status !== 'ok' && root.status !== 'warning') return undefined
  const entry = root[ip]
  if (!entry || typeof entry !== 'object') return undefined

  const obj = entry as Record<string, unknown>
  const detections =
    obj.detections && typeof obj.detections === 'object'
      ? (obj.detections as Record<string, unknown>)
      : {}
  const network =
    obj.network && typeof obj.network === 'object' ? (obj.network as Record<string, unknown>) : {}
  const location =
    obj.location && typeof obj.location === 'object'
      ? (obj.location as Record<string, unknown>)
      : {}

  const riskScore = asScore(detections.risk ?? detections.risk_score ?? obj.risk_score ?? obj.risk)
  if (riskScore === undefined) return undefined

  return {
    riskScore,
    confidence: asNumber(detections.confidence),
    proxy: asBoolean(detections.proxy),
    vpn: asBoolean(detections.vpn),
    tor: asBoolean(detections.tor),
    hosting: asBoolean(detections.hosting),
    compromised: asBoolean(detections.compromised),
    anonymous: asBoolean(detections.anonymous),
    networkType: typeof network.type === 'string' ? network.type : undefined,
    provider:
      typeof network.provider === 'string'
        ? network.provider
        : typeof network.organisation === 'string'
          ? network.organisation
          : undefined,
    country:
      typeof location.country_name === 'string'
        ? location.country_name
        : typeof obj.country === 'string'
          ? obj.country
          : undefined
  }
}

function adjustedProxyCheckRisk(value: IProxyPurityProviderProxyCheck): number {
  let risk = value.riskScore

  // ProxyCheck intentionally gives VPN/hosting networks a non-zero baseline.
  // For a proxy client this is expected, so reduce those baseline-only penalties.
  if (!value.compromised && !value.tor && !value.proxy) {
    if (value.vpn && risk <= 50) risk *= 0.55
    else if (value.hosting && risk <= 33) risk *= 0.5
  }

  return risk
}

function calculatePurityScore(
  scamalytics?: IProxyPurityProviderScamalytics,
  proxycheck?: IProxyPurityProviderProxyCheck
): number {
  const risks: number[] = []
  if (scamalytics) risks.push(scamalytics.score)
  if (proxycheck) risks.push(adjustedProxyCheckRisk(proxycheck))
  if (risks.length === 0) throw new Error('No IP purity provider returned a valid score')

  const averageRisk = risks.reduce((sum, value) => sum + value, 0) / risks.length
  return Math.max(0, Math.min(100, Math.round(100 - averageRisk)))
}

async function discoverExitIp(proxy: string, slot: number): Promise<string> {
  const instance = await getAxios()
  const port = await ensureIpPurityPort(slot)

  await instance.put(`/proxies/${encodeURIComponent(ipPurityGroupName(slot))}`, { name: proxy })

  const response = await axios.get<{ ip?: string }>(EGRESS_IP_URL, {
    timeout: 10000,
    proxy: {
      protocol: 'http',
      host: '127.0.0.1',
      port
    }
  })

  const ip = response.data?.ip?.trim()
  return canonicalExitIp(ip)
}

async function performProviderQuery(ip: string, ctx: CheckContext): Promise<IpPurityRecord> {
  const config = ctx.config
  const warnings: string[] = []
  let scamalytics: IProxyPurityProviderScamalytics | undefined
  let proxycheck: IProxyPurityProviderProxyCheck | undefined

  const requests: Promise<void>[] = []

  if (config.ipPurityScamalyticsEndpoint) {
    requests.push(
      axios
        .get<unknown>(
          buildScamalyticsUrl(
            config.ipPurityScamalyticsEndpoint,
            config.ipPurityScamalyticsApiKey ?? '',
            ip
          ),
          { timeout: 10000 }
        )
        .then((response) => {
          scamalytics = parseScamalytics(response.data)
          if (!scamalytics) warnings.push('Scamalytics returned an unsupported response')
        })
        .catch((error: unknown) => {
          warnings.push(`Scamalytics: ${error instanceof Error ? error.message : 'request failed'}`)
        })
    )
  }

  requests.push(
    axios
      .get<unknown>(`${PROXYCHECK_API}/${encodeURIComponent(ip)}`, {
        timeout: 10000,
        params: config.ipPurityProxycheckApiKey
          ? { key: config.ipPurityProxycheckApiKey }
          : undefined
      })
      .then((response) => {
        proxycheck = parseProxyCheck(ip, response.data)
        if (!proxycheck) warnings.push('proxycheck.io returned an unsupported response')
      })
      .catch((error: unknown) => {
        warnings.push(`proxycheck.io: ${error instanceof Error ? error.message : 'request failed'}`)
      })
  )

  await Promise.all(requests)

  if (!scamalytics && !proxycheck) {
    throw new Error(warnings[0] || 'No IP purity provider returned a result')
  }
  return {
    ip,
    sourceKey: ctx.sourceKey,
    checkedAt: Date.now(),
    score: calculatePurityScore(scamalytics, proxycheck),
    scamalytics,
    proxycheck
  }
}

type BatchLookups = Map<string, Promise<IpPurityRecord>>

function queryProviders(
  ip: string,
  ctx: CheckContext,
  force: boolean,
  batch?: BatchLookups
): Promise<IpPurityRecord> {
  // A manual group refresh queries each IP once, including nodes that
  // start after an earlier worker has completed. Failed lookups also
  // stay deduplicated within that batch, but can be retried next time.
  const shared = batch?.get(ip)
  if (shared) return shared
  const key = `${ctx.generation}:${ctx.sourceKey}:${ip}`
  let request = providerRequests.get(key)
  if (!request) {
    const cached = !force ? cache.getIp(ip, ctx.sourceKey, ctx.ttl) : undefined
    if (cached) return Promise.resolve(cached)
    request = performProviderQuery(ip, ctx)
      .then((entry) => {
        if (ctx.generation === cacheGeneration) cache.setIp(entry)
        return entry
      })
      .finally(() => {
        if (providerRequests.get(key) === request) providerRequests.delete(key)
      })
    providerRequests.set(key, request)
  }
  batch?.set(ip, request)
  return request
}

async function checkProxyPurity(
  proxy: string,
  ctx: CheckContext,
  slot: number,
  force: boolean,
  batch?: BatchLookups
): Promise<IProxyPurityResult> {
  if (ctx.config.ipPurityEnabled === false) throw new Error('IP purity checking is disabled')
  if (ctx.generation !== cacheGeneration)
    throw new Error('IP purity cache was cleared; start a new check')
  const restored = !force ? cache.result(ctx.scope, proxy, ctx.sourceKey, ctx.ttl) : undefined
  if (restored) return restored
  // Manual refresh always re-probes: the same node name may now use a
  // different exit. Cache reads/page mounts never perform this probe.
  const ip = await discoverExitIp(proxy, slot)
  if (ctx.generation !== cacheGeneration)
    throw new Error('IP purity cache was cleared; start a new check')
  const entry = await queryProviders(ip, ctx, force, batch)
  if (ctx.generation === cacheGeneration) {
    cache.remember(ctx.scope, proxy, ip)
    await persistCache()
  }
  return {
    proxy,
    ip,
    checkedAt: entry.checkedAt,
    score: entry.score,
    scamalytics: entry.scamalytics,
    proxycheck: entry.proxycheck
  }
}

function startCheck(
  proxy: string,
  ctx: CheckContext,
  force: boolean,
  batch?: BatchLookups
): Promise<IProxyPurityResult> {
  if (typeof proxy !== 'string' || !proxy || proxy.length > 1024) {
    return Promise.reject(new Error('Invalid node name'))
  }
  const nodeKey = cache.nodeKey(ctx.scope, proxy)
  const key = `${ctx.generation}:${nodeKey}`
  const pending = pendingChecks.get(key)
  if (pending) return pending.promise
  failedChecks.delete(nodeKey)
  const promise = purityPool
    .run((slot) => checkProxyPurity(proxy, ctx, slot, force, batch))
    .catch(async (error: unknown) => {
      if (ctx.generation === cacheGeneration) {
        cache.forget(ctx.scope, proxy)
        failedChecks.set(nodeKey, { scope: ctx.scope, proxy })
        await persistCache()
      }
      throw error
    })
    .finally(() => {
      if (pendingChecks.get(key)?.promise === promise) pendingChecks.delete(key)
    })
  pendingChecks.set(key, { scope: ctx.scope, proxy, generation: ctx.generation, promise })
  return promise
}

// IPC snapshot: local disk/memory only; no node probes or provider requests.
export async function getProxyPurityState(): Promise<{
  results: Record<string, IProxyPurityResult>
  checking: string[]
  failed: string[]
}> {
  const ctx = await context()
  if (ctx.config.ipPurityEnabled === false) return { results: {}, checking: [], failed: [] }
  return {
    results: cache.results(ctx.scope, ctx.sourceKey, ctx.ttl),
    checking: [...pendingChecks.values()]
      .filter((task) => task.scope === ctx.scope && task.generation === cacheGeneration)
      .map((task) => task.proxy),
    failed: [...failedChecks.values()]
      .filter((task) => task.scope === ctx.scope)
      .map((task) => task.proxy)
  }
}

export async function mihomoProxyPurity(proxy: string, force = false): Promise<IProxyPurityResult> {
  const ctx = await context()
  return await startCheck(proxy, ctx, force)
}

export async function mihomoGroupPurity(proxies: string[]): Promise<void> {
  if (!Array.isArray(proxies) || proxies.length > 5000) throw new Error('Invalid node batch')
  const ctx = await context()
  const batch: BatchLookups = new Map()
  await Promise.allSettled(
    [...new Set(proxies)].map((proxy) => startCheck(proxy, ctx, true, batch))
  )
}

export async function clearProxyPurityCache(): Promise<void> {
  cacheGeneration++
  failedChecks.clear()
  await cache.clear()
}
