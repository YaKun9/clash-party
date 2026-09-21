import axios from 'axios'
import { createHash } from 'crypto'
import { canonicalExitIp } from './ipPurityCache'
import { purityNumber, purityObject, purityScore, sanitizePurityDetails } from '../../shared/ipPurityScore'

const timeout = 10000
const requestOptions = { timeout, maxRedirects: 0, maxContentLength: 1024 * 1024 }
const cooldowns = new Map<string, number>()

function sameIp(actual: unknown, expected: string): boolean {
  try { return canonicalExitIp(actual) === canonicalExitIp(expected) } catch { return false }
}

export function parseAbuseIPDB(ip: string, raw: unknown): IProxyPurityProviderAbuseIPDB | undefined {
  const root = purityObject(raw)
  if (root.errors) return undefined
  const data = purityObject(root.data)
  if (!sameIp(data.ipAddress, ip)) return undefined
  return sanitizePurityDetails({ abuseipdb: { ...data, maxAgeInDays: 90 } }).abuseipdb
}

export function parseIpapi(ip: string, raw: unknown): IProxyPurityProviderIpapi | undefined {
  const data = purityObject(raw)
  if (data.error || !sameIp(data.ip, ip)) return undefined
  const company = purityObject(data.company)
  const asn = purityObject(data.asn)
  const location = purityObject(data.location)
  return sanitizePurityDetails({ ipapi: {
    isAbuser: data.is_abuser,
    isDatacenter: data.is_datacenter,
    isVpn: data.is_vpn,
    isProxy: data.is_proxy,
    isTor: data.is_tor,
    isMobile: data.is_mobile,
    asn: asn.asn ?? data.asn_num,
    organization: asn.org ?? data.asn_org,
    company: company.name ?? data.company_name,
    networkType: company.type ?? asn.type,
    country: location.country,
    countryCode: location.country_code ?? data.cc,
    region: location.state,
    city: location.city
  } }).ipapi
}

function parseScamalytics(raw: unknown): IProxyPurityProviderScamalytics | undefined {
  const data = purityObject(raw)
  if (data.error || data.errors) return undefined
  const nested = data.scamalytics ? purityObject(data.scamalytics) : data
  return sanitizePurityDetails({ scamalytics: {
    score: nested.scamalytics_score ?? nested.score ?? nested.fraud_score ?? data.score ?? data.fraud_score,
    risk: nested.scamalytics_risk ?? nested.risk
  } }).scamalytics
}

function parseProxycheck(ip: string, raw: unknown): IProxyPurityProviderProxyCheck | undefined {
  const data = purityObject(raw)
  if (data.status && !['ok', 'warning'].includes(String(data.status))) return undefined
  const entry = purityObject(data[ip])
  const detections = purityObject(entry.detections)
  const network = purityObject(entry.network)
  const location = purityObject(entry.location)
  return sanitizePurityDetails({ proxycheck: {
    riskScore: detections.risk ?? detections.risk_score ?? entry.risk_score ?? entry.risk,
    confidence: detections.confidence,
    proxy: detections.proxy,
    vpn: detections.vpn,
    tor: detections.tor,
    hosting: detections.hosting,
    compromised: detections.compromised,
    anonymous: detections.anonymous,
    networkType: network.type,
    provider: network.provider ?? network.organisation,
    country: location.country_name ?? location.country ?? entry.country
  } }).proxycheck
}

function scamalyticsUrl(endpoint: string, key: string, ip: string): string {
  const hasTemplate = endpoint.includes('{ip}') || endpoint.includes('{key}')
  const url = new URL(endpoint.replaceAll('{ip}', encodeURIComponent(ip)).replaceAll('{key}', encodeURIComponent(key)))
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Invalid endpoint')
  if (!hasTemplate) {
    url.searchParams.set('ip', ip)
    if (key) url.searchParams.set('key', key)
  }
  return url.toString()
}

// Only status enums cross IPC or reach the disk cache. Never propagate an
// Axios error/config, response body, endpoint URL, or credential to the UI.
export async function queryPuritySources(ip: string, config: IAppConfig): Promise<IpPurityDetails> {
  const details: IpPurityDetails = { sourceStatus: {} }
  const sourceIdentity = createHash('sha256').update(JSON.stringify([
    config.ipPurityProxycheckApiKey ?? '', config.ipPurityScamalyticsEndpoint ?? '',
    config.ipPurityScamalyticsApiKey ?? '', config.ipPurityAbuseIPDBApiKey ?? '',
    config.ipPurityIpapiApiKey ?? ''
  ])).digest('hex')

  async function run<T>(source: IpPuritySource, configured: boolean, fetch: () => Promise<{ data: unknown }>, parse: (data: unknown) => T | undefined, assign: (data: T) => void): Promise<void> {
    if (!configured) { details.sourceStatus![source] = 'unconfigured'; return }
    const key = `${sourceIdentity}:${source}`
    if ((cooldowns.get(key) ?? 0) > Date.now()) {
      details.sourceStatus![source] = 'rate_limited'
      return
    }
    try {
      const response = await fetch()
      const parsed = parse(response.data)
      if (!parsed) { details.sourceStatus![source] = 'invalid'; return }
      assign(parsed)
      details.sourceStatus![source] = 'ok'
    } catch (error: unknown) {
      const exception = purityObject(error)
      const response = purityObject(exception.response)
      const status = purityNumber(response.status)
      let state: IpPuritySourceStatus = 'error'
      if (status === 429) {
        state = 'rate_limited'
        const retry = purityNumber(purityObject(response.headers)['retry-after'])
        if (cooldowns.size > 32) cooldowns.clear()
        cooldowns.set(key, Date.now() + Math.max(60, Math.min(86400, retry ?? 60)) * 1000)
      } else if (status === 401 || status === 403) state = 'unauthorized'
      else if (['ECONNABORTED', 'ETIMEDOUT', 'ERR_CANCELED'].includes(String(exception.code))) state = 'timeout'
      details.sourceStatus![source] = state
    }
  }

  await Promise.all([
    run('proxycheck', true,
      () => axios.get(`https://proxycheck.io/v3/${encodeURIComponent(ip)}`, { ...requestOptions, params: { key: config.ipPurityProxycheckApiKey || undefined } }),
      (raw) => parseProxycheck(ip, raw), (value) => { details.proxycheck = value }),
    run('scamalytics', !!config.ipPurityScamalyticsEndpoint,
      () => axios.get(scamalyticsUrl(config.ipPurityScamalyticsEndpoint!, config.ipPurityScamalyticsApiKey ?? '', ip), requestOptions),
      parseScamalytics, (value) => { details.scamalytics = value }),
    run('abuseipdb', !!config.ipPurityAbuseIPDBApiKey?.trim(),
      () => axios.get('https://api.abuseipdb.com/api/v2/check', { ...requestOptions,
        headers: { Accept: 'application/json', Key: config.ipPurityAbuseIPDBApiKey!.trim() },
        params: { ipAddress: ip, maxAgeInDays: 90 }
      }),
      (raw) => parseAbuseIPDB(ip, raw), (value) => { details.abuseipdb = value }),
    run('ipapi', !!config.ipPurityIpapiApiKey?.trim(),
      () => axios.post('https://api.ipapi.is/', { q: ip, key: config.ipPurityIpapiApiKey!.trim() }, requestOptions),
      (raw) => parseIpapi(ip, raw), (value) => { details.ipapi = value })
  ])
  return details
}
