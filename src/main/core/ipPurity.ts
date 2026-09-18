import axios from 'axios'
import { getAppConfig } from '../config'
import { getAxios } from './mihomoApi'
import { ensureIpPurityPort, ipPurityGroupName, IP_PURITY_CONCURRENCY } from './ipPurityRuntime'
import { IpPurityPool } from './ipPurityPool'

const EGRESS_IP_URL = 'https://api.ipify.org?format=json'
const PROXYCHECK_API = 'https://proxycheck.io/v3'

interface ProxyCheckV3Response {
  status?: string
  [ip: string]: unknown
}

interface CachedPurity {
  result: IProxyPurityResult
  expiresAt: number
}

const proxyCache = new Map<string, CachedPurity>()
const pendingChecks = new Map<string, Promise<IProxyPurityResult>>()
// Last-attempt display state only: failures never prevent an explicit retry.
const failedChecks = new Set<string>()
let cacheGeneration = 0
const ipProviderCache = new Map<
  string,
  {
    expiresAt: number
    scamalytics?: IProxyPurityProviderScamalytics
    proxycheck?: IProxyPurityProviderProxyCheck
    warnings?: string[]
  }
>()

const purityPool = new IpPurityPool(IP_PURITY_CONCURRENCY)
const providerRequests = new Map<string, ReturnType<typeof performProviderQuery>>()

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
  if (!ip) throw new Error('Failed to resolve node exit IP')
  return ip
}

async function performProviderQuery(
  ip: string,
  cacheMs: number,
  generation: number
): Promise<{
  scamalytics?: IProxyPurityProviderScamalytics
  proxycheck?: IProxyPurityProviderProxyCheck
  warnings: string[]
}> {
  const now = Date.now()
  const cached = ipProviderCache.get(ip)
  if (cached && cached.expiresAt > now) {
    return {
      scamalytics: cached.scamalytics,
      proxycheck: cached.proxycheck,
      warnings: cached.warnings ?? []
    }
  }

  const config = await getAppConfig()
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

  // Clearing the cache must not be undone by an older in-flight request.
  // Failed lookups are not valid cached results and must remain retryable.
  if (generation === cacheGeneration && (scamalytics || proxycheck)) {
    ipProviderCache.set(ip, {
      expiresAt: now + cacheMs,
      scamalytics,
      proxycheck,
      warnings
    })
  }

  return { scamalytics, proxycheck, warnings }
}

// Simultaneous nodes with the same exit IP share one in-flight lookup.
// Include the cache generation so clearing/retrying cannot reuse an old request.
function queryProviders(
  ip: string,
  cacheMs: number,
  generation: number
): ReturnType<typeof performProviderQuery> {
  const key = `${generation}:${ip}`
  const pending = providerRequests.get(key)
  if (pending) return pending
  const request = performProviderQuery(ip, cacheMs, generation).finally(() => {
    if (providerRequests.get(key) === request) providerRequests.delete(key)
  })
  providerRequests.set(key, request)
  return request
}

async function checkProxyPurity(
  proxy: string,
  generation: number,
  slot: number
): Promise<IProxyPurityResult> {
  const config = await getAppConfig()
  if (config.ipPurityEnabled === false) {
    throw new Error('IP purity checking is disabled')
  }
  if (generation !== cacheGeneration) {
    throw new Error('IP purity cache was cleared; start a new check')
  }

  const cacheHours = Math.max(0.25, Math.min(168, config.ipPurityCacheHours ?? 24))
  const cacheMs = cacheHours * 60 * 60 * 1000
  const now = Date.now()
  const cached = proxyCache.get(proxy)
  if (cached && cached.expiresAt > now) return cached.result

  const ip = await discoverExitIp(proxy, slot)
  const providers = await queryProviders(ip, cacheMs, generation)

  if (!providers.scamalytics && !providers.proxycheck) {
    throw new Error(providers.warnings[0] || 'No IP purity provider returned a result')
  }
  const score = calculatePurityScore(providers.scamalytics, providers.proxycheck)

  const result: IProxyPurityResult = {
    proxy,
    ip,
    score,
    checkedAt: Date.now(),
    scamalytics: providers.scamalytics,
    proxycheck: providers.proxycheck,
    warnings: providers.warnings.length > 0 ? providers.warnings : undefined
  }

  if (generation === cacheGeneration) {
    proxyCache.set(proxy, { result, expiresAt: Date.now() + cacheMs })
  }
  return result
}

// Read-only IPC snapshot: restoring a page must never spend a provider API request.
export async function getProxyPurityState(): Promise<{
  results: Record<string, IProxyPurityResult>
  checking: string[]
  failed: string[]
}> {
  const now = Date.now()
  const entries: [string, IProxyPurityResult][] = []
  for (const [proxy, cached] of proxyCache) {
    if (cached.expiresAt > now) entries.push([proxy, cached.result])
    else proxyCache.delete(proxy)
  }
  return {
    results: Object.fromEntries(entries),
    checking: [...pendingChecks.keys()],
    failed: [...failedChecks]
  }
}

export function mihomoProxyPurity(proxy: string): Promise<IProxyPurityResult> {
  const pending = pendingChecks.get(proxy)
  if (pending) return pending

  failedChecks.delete(proxy)
  const generation = cacheGeneration
  const run = purityPool
    .run((slot) => checkProxyPurity(proxy, generation, slot))
    .catch((error: unknown) => {
      if (generation === cacheGeneration) {
        // Never encode a failed attempt as a zero purity score. Keep the marker
        // across route changes, without caching the failure as an API response.
        proxyCache.delete(proxy)
        failedChecks.add(proxy)
      }
      throw error
    })
    .finally(() => {
      if (pendingChecks.get(proxy) === run) pendingChecks.delete(proxy)
    })
  pendingChecks.set(proxy, run)
  return run
}

export function clearProxyPurityCache(): void {
  cacheGeneration++
  proxyCache.clear()
  ipProviderCache.clear()
  failedChecks.clear()
}
