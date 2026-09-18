import axios from 'axios'
import { getAppConfig } from '../config'
import { getAxios } from './mihomoApi'
import { ensureIpPurityPort, IP_PURITY_GROUP_NAME } from './ipPurityRuntime'

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
const ipProviderCache = new Map<
  string,
  {
    expiresAt: number
    scamalytics?: IProxyPurityProviderScamalytics
    proxycheck?: IProxyPurityProviderProxyCheck
    warnings?: string[]
  }
>()

// Purity checks share one hidden selector/listener, so selection + request are serialized.
let purityQueue: Promise<void> = Promise.resolve()

function enqueue<T>(task: () => Promise<T>): Promise<T> {
  const run = purityQueue.then(task, task)
  purityQueue = run.then(
    () => undefined,
    () => undefined
  )
  return run
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
  if (typeof value === 'string') {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return undefined
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

  const score = asNumber(
    nested.scamalytics_score ?? nested.score ?? nested.fraud_score ?? obj.score ?? obj.fraud_score
  )
  if (score === undefined) return undefined

  const risk =
    typeof nested.scamalytics_risk === 'string'
      ? nested.scamalytics_risk
      : typeof nested.risk === 'string'
        ? nested.risk
        : undefined

  return {
    score: Math.max(0, Math.min(100, score)),
    risk
  }
}

function parseProxyCheck(ip: string, data: unknown): IProxyPurityProviderProxyCheck | undefined {
  if (!data || typeof data !== 'object') return undefined
  const root = data as ProxyCheckV3Response
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

  const riskScore = asNumber(detections.risk ?? detections.risk_score ?? obj.risk_score ?? obj.risk)
  if (riskScore === undefined) return undefined

  return {
    riskScore: Math.max(0, Math.min(100, riskScore)),
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
  if (risks.length === 0) return 0

  const averageRisk = risks.reduce((sum, value) => sum + value, 0) / risks.length
  return Math.max(0, Math.min(100, Math.round(100 - averageRisk)))
}

async function discoverExitIp(proxy: string): Promise<string> {
  const instance = await getAxios()
  const port = await ensureIpPurityPort()

  await instance.put(`/proxies/${encodeURIComponent(IP_PURITY_GROUP_NAME)}`, { name: proxy })

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

async function queryProviders(
  ip: string,
  cacheMs: number
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

  ipProviderCache.set(ip, {
    expiresAt: now + cacheMs,
    scamalytics,
    proxycheck,
    warnings
  })

  return { scamalytics, proxycheck, warnings }
}

async function checkProxyPurity(proxy: string): Promise<IProxyPurityResult> {
  const config = await getAppConfig()
  if (config.ipPurityEnabled === false) {
    throw new Error('IP purity checking is disabled')
  }

  const cacheHours = Math.max(0.25, Math.min(168, config.ipPurityCacheHours ?? 24))
  const cacheMs = cacheHours * 60 * 60 * 1000
  const now = Date.now()
  const cached = proxyCache.get(proxy)
  if (cached && cached.expiresAt > now) return cached.result

  const ip = await discoverExitIp(proxy)
  const providers = await queryProviders(ip, cacheMs)
  const score = calculatePurityScore(providers.scamalytics, providers.proxycheck)

  if (!providers.scamalytics && !providers.proxycheck) {
    throw new Error(providers.warnings[0] || 'No IP purity provider returned a result')
  }

  const result: IProxyPurityResult = {
    proxy,
    ip,
    score,
    checkedAt: Date.now(),
    scamalytics: providers.scamalytics,
    proxycheck: providers.proxycheck,
    warnings: providers.warnings.length > 0 ? providers.warnings : undefined
  }

  proxyCache.set(proxy, { result, expiresAt: Date.now() + cacheMs })
  return result
}

export async function mihomoProxyPurity(proxy: string): Promise<IProxyPurityResult> {
  return await enqueue(() => checkProxyPurity(proxy))
}

export function clearProxyPurityCache(): void {
  proxyCache.clear()
  ipProviderCache.clear()
}
