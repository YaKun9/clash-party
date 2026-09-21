// Versioned, client-side heuristic. These weights are not calibrated probabilities.
// Keep this shared by main-process computation and the renderer explanation.
export const IP_PURITY_SCORE_VERSION = 'weighted-risk-v2'
export const IP_PURITY_WEIGHTS: Record<IpPuritySource, number> = {
  abuseipdb: 40,
  scamalytics: 25,
  proxycheck: 20,
  ipapi: 15
}
export const IP_PURITY_SOURCES = Object.keys(IP_PURITY_WEIGHTS) as IpPuritySource[]

export function purityObject(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

export function purityNumber(value: unknown): number | undefined {
  if (typeof value !== 'number' && (typeof value !== 'string' || !value.trim())) return undefined
  const number = Number(value)
  return Number.isFinite(number) ? number : undefined
}

export function purityScore(value: unknown): number | undefined {
  const number = purityNumber(value)
  return number !== undefined && number >= 0 && number <= 100 ? number : undefined
}

function count(value: unknown): number | undefined {
  const number = purityNumber(value)
  return number !== undefined && Number.isSafeInteger(number) && number >= 0 ? number : undefined
}

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim().slice(0, 256) : undefined
}

export function sanitizePurityDetails(value: unknown): IpPurityDetails {
  const source = purityObject(value)
  const result: IpPurityDetails = {}
  const scam = purityObject(source.scamalytics)
  const scamScore = purityScore(scam.score)
  if (scamScore !== undefined) result.scamalytics = { score: scamScore, risk: text(scam.risk) }

  const pc = purityObject(source.proxycheck)
  const pcScore = purityScore(pc.riskScore)
  if (pcScore !== undefined) {
    const parsed: IProxyPurityProviderProxyCheck = { riskScore: pcScore }
    for (const key of ['proxy', 'vpn', 'tor', 'hosting', 'compromised', 'anonymous'] as const) {
      if (typeof pc[key] === 'boolean') parsed[key] = pc[key]
    }
    for (const key of ['networkType', 'provider', 'country'] as const) parsed[key] = text(pc[key])
    parsed.confidence = purityScore(pc.confidence)
    result.proxycheck = parsed
  }

  const abuse = purityObject(source.abuseipdb)
  const abuseScore = purityScore(abuse.abuseConfidenceScore)
  if (abuseScore !== undefined) {
    const days = count(abuse.maxAgeInDays)
    const parsed: IProxyPurityProviderAbuseIPDB = {
      abuseConfidenceScore: abuseScore,
      maxAgeInDays: days !== undefined && days >= 1 && days <= 365 ? days : 90,
      totalReports: count(abuse.totalReports),
      numDistinctUsers: count(abuse.numDistinctUsers),
      usageType: text(abuse.usageType),
      isp: text(abuse.isp),
      countryCode: text(abuse.countryCode)
    }
    const reported = text(abuse.lastReportedAt)
    if (reported && Number.isFinite(Date.parse(reported))) parsed.lastReportedAt = reported
    if (typeof abuse.isTor === 'boolean') parsed.isTor = abuse.isTor
    result.abuseipdb = parsed
  }

  const ip = purityObject(source.ipapi)
  const parsedIp: IProxyPurityProviderIpapi = {}
  for (const key of ['isAbuser', 'isDatacenter', 'isVpn', 'isProxy', 'isTor', 'isMobile'] as const) {
    if (typeof ip[key] === 'boolean') parsedIp[key] = ip[key]
  }
  for (const key of ['organization', 'company', 'networkType', 'country', 'countryCode', 'region', 'city'] as const) {
    const field = text(ip[key])
    if (field) parsedIp[key] = field
  }
  const asn = count(ip.asn)
  if (asn !== undefined) parsedIp.asn = asn
  if (Object.keys(parsedIp).length) result.ipapi = parsedIp

  const statuses = purityObject(source.sourceStatus)
  const allowed: IpPuritySourceStatus[] = ['ok', 'unconfigured', 'timeout', 'rate_limited', 'unauthorized', 'invalid', 'error']
  if (source.sourceStatus !== undefined) {
    result.sourceStatus = {}
    for (const key of IP_PURITY_SOURCES) {
      const status = statuses[key]
      if (typeof status === 'string' && allowed.includes(status as IpPuritySourceStatus)) {
        result.sourceStatus[key] = status as IpPuritySourceStatus
      }
    }
  }
  return result
}

export function proxycheckWeightedRisk(value: IProxyPurityProviderProxyCheck): number {
  const risk = value.riskScore
  if (value.compromised) return Math.max(90, risk)
  if (value.tor) return Math.max(60, risk)
  // ProxyCheck's Proxy baseline already saturates at 100: its numeric result
  // alone cannot distinguish a proxy label from abuse. Preserve the raw score
  // in details and bound its contribution; other abuse signals override this.
  if (value.proxy) return Math.min(25, risk)
  if (value.vpn) return risk <= 50 ? risk * 0.3 : 15 + (risk - 50) * 1.7
  if (value.hosting) return risk <= 33 ? risk * 10 / 33 : 10 + (risk - 33) * 90 / 67
  return risk
}

export function ipapiWeightedRisk(value: IProxyPurityProviderIpapi): number | undefined {
  // ipapi.is has no per-IP fraud score. These are local signal weights, NOT
  // company.abuser_score or asn.abuser_score (network-wide statistics).
  if (value.isAbuser) return 80
  if (value.isTor) return 60
  if (value.isProxy) return 25
  if (value.isVpn) return 15
  if (value.isDatacenter) return 10
  // Unknown fields cannot establish a clean IP. Only an explicit negative
  // abuse result can contribute zero when no positive attributes are present.
  return value.isAbuser === false ? 0 : undefined
}

export interface IpPurityScorePart {
  source: IpPuritySource
  baseWeight: number
  effectiveWeight: number
  risk: number
  deduction: number
}

export function explainPurityScore(details: IpPurityDetails): {
  score: number | undefined
  parts: IpPurityScorePart[]
  coverage: number
  floorRisk: number
  floorReasons: string[]
  disagreement: boolean
} {
  const risks: Partial<Record<IpPuritySource, number>> = {
    abuseipdb: details.abuseipdb?.abuseConfidenceScore,
    scamalytics: details.scamalytics?.score,
    proxycheck: details.proxycheck ? proxycheckWeightedRisk(details.proxycheck) : undefined,
    ipapi: details.ipapi ? ipapiWeightedRisk(details.ipapi) : undefined
  }
  const valid = IP_PURITY_SOURCES.filter((key) => purityScore(risks[key]) !== undefined)
  const coverage = valid.reduce((sum, key) => sum + IP_PURITY_WEIGHTS[key], 0)
  const parts = valid.map((source) => {
    const effectiveWeight = IP_PURITY_WEIGHTS[source] / coverage
    const risk = risks[source]!
    return { source, baseWeight: IP_PURITY_WEIGHTS[source], effectiveWeight, risk, deduction: effectiveWeight * risk }
  })
  let floorRisk = 0
  const floorReasons: string[] = []
  const floor = (risk: number, reason: string): void => {
    floorRisk = Math.max(floorRisk, risk)
    floorReasons.push(reason)
  }
  if ((details.abuseipdb?.abuseConfidenceScore ?? 0) >= 75) floor(details.abuseipdb!.abuseConfidenceScore, 'abuseipdb')
  if (details.proxycheck?.compromised) floor(90, 'compromised')
  if (details.ipapi?.isAbuser) floor(60, 'ipapi')
  if ((details.scamalytics?.score ?? 0) >= 90) floor(75, 'scamalytics')
  const weightedRisk = parts.reduce((sum, part) => sum + part.deduction, 0)
  return {
    score: coverage ? Math.round(100 - Math.min(100, Math.max(0, weightedRisk, floorRisk))) : undefined,
    parts,
    coverage,
    floorRisk,
    floorReasons,
    disagreement: parts.length > 1 && Math.max(...parts.map((part) => part.risk)) - Math.min(...parts.map((part) => part.risk)) >= 50
  }
}
