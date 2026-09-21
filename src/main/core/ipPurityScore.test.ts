import { describe, expect, it } from 'vitest'
import {
  explainPurityScore,
  ipapiWeightedRisk,
  sanitizePurityDetails
} from '../../shared/ipPurityScore'

const abuse = (risk: number): IProxyPurityProviderAbuseIPDB => ({
  abuseConfidenceScore: risk,
  maxAgeInDays: 90
})

describe('weighted risk v2', () => {
  it.each([
    [{ riskScore: 50, vpn: true }, 85],
    [{ riskScore: 100, proxy: true }, 75],
    [{ riskScore: 33, hosting: true }, 90],
    [{ riskScore: 100, proxy: true, compromised: true }, 0]
  ] as const)('does not treat anonymity baseline as certain abuse: %j', (proxycheck, score) => {
    expect(explainPurityScore({ proxycheck }).score).toBe(score)
  })

  it('normalizes only participating weights, including a real zero result', () => {
    const value = explainPurityScore({
      abuseipdb: abuse(0),
      proxycheck: { riskScore: 100, proxy: true }
    })
    expect(value.coverage).toBe(60)
    expect(value.score).toBe(92)
    expect(value.parts.map((part) => part.effectiveWeight)).toEqual([40 / 60, 20 / 60])
  })

  it('does not substitute missing sources or unknown metadata with zero risk', () => {
    expect(explainPurityScore({}).score).toBeUndefined()
    expect(
      explainPurityScore({ ipapi: { organization: 'Example', isVpn: false } }).score
    ).toBeUndefined()
    expect(explainPurityScore({ proxycheck: { riskScore: 80 } }).score).toBe(20)
    expect(ipapiWeightedRisk({ isAbuser: false })).toBe(0)
  })

  it('gives full weights to all sources and explains the exact total', () => {
    const result = explainPurityScore({
      abuseipdb: abuse(10),
      scamalytics: { score: 20 },
      proxycheck: { riskScore: 50, vpn: true },
      ipapi: { isAbuser: false, isVpn: true }
    })
    expect(result.coverage).toBe(100)
    expect(result.score).toBe(86)
    expect(result.parts.reduce((total, part) => total + part.deduction, 0)).toBe(14.25)
  })

  it('cannot average away serious abuse reports with three low readings', () => {
    const result = explainPurityScore({
      abuseipdb: abuse(95),
      scamalytics: { score: 0 },
      proxycheck: { riskScore: 0 },
      ipapi: { isAbuser: false }
    })
    expect(result.score).toBe(5)
    expect(result.floorRisk).toBe(95)
    expect(result.disagreement).toBe(true)
  })

  it('marks blacklists and compromised hosts without blaming VPN alone', () => {
    expect(explainPurityScore({ abuseipdb: abuse(0), ipapi: { isAbuser: true } }).score).toBe(40)
    expect(
      explainPurityScore({ abuseipdb: abuse(0), proxycheck: { riskScore: 20, compromised: true } })
        .score
    ).toBe(10)
    expect(explainPurityScore({ abuseipdb: abuse(0), scamalytics: { score: 95 } }).score).toBe(25)
  })

  it('does not drop a VPN score discontinuously above its baseline', () => {
    const values = [49, 50, 51, 70, 100].map(
      (riskScore) => explainPurityScore({ proxycheck: { riskScore, vpn: true } }).score!
    )
    expect(values).toEqual([...values].sort((a, b) => b - a))
  })

  it('sanitizes saved source records and never preserves credentials or raw errors', () => {
    const value = sanitizePurityDetails({
      abuseipdb: { ...abuse(0), key: 'SECRET', reports: ['raw'] },
      ipapi: { isAbuser: false, companyAbuserScore: 1, key: 'SECRET' },
      sourceStatus: { abuseipdb: 'ok', ipapi: 'ok', scamalytics: 'SECRET' }
    })
    expect(JSON.stringify(value)).not.toContain('SECRET')
    expect(JSON.stringify(value)).not.toContain('companyAbuserScore')
    expect(value.abuseipdb?.abuseConfidenceScore).toBe(0)
  })
})
