import { beforeEach, describe, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }))
vi.mock('axios', () => ({ default: mocks }))
import { parseAbuseIPDB, parseIpapi, queryPuritySources } from './ipPurityProviders'

const IP = '203.0.113.11'
const config = { ipPurityAbuseIPDBApiKey: 'abuse-secret', ipPurityIpapiApiKey: 'ipapi-secret' }
beforeEach(() => {
  mocks.get.mockReset()
  mocks.post.mockReset()
})

describe('additional IP providers', () => {
  it('uses read-only AbuseIPDB CHECK with a header key and POST body for ipapi.is', async () => {
    mocks.get.mockImplementation(async (url: string) =>
      url.includes('abuseipdb')
        ? { data: { data: { ipAddress: IP, abuseConfidenceScore: 0, totalReports: 0 } } }
        : { data: { [IP]: { detections: { risk: 50, vpn: true } } } }
    )
    mocks.post.mockResolvedValue({
      data: {
        ip: IP,
        is_abuser: false,
        is_vpn: true,
        company: { name: 'Test ISP' },
        asn: { asn: 64500 }
      }
    })
    const result = await queryPuritySources(IP, config)
    const abuseCall = mocks.get.mock.calls.find(([url]) => url.includes('abuseipdb'))!
    expect(abuseCall[0]).toBe('https://api.abuseipdb.com/api/v2/check')
    expect(abuseCall[1].headers.Key).toBe('abuse-secret')
    expect(abuseCall[1].params).toEqual({ ipAddress: IP, maxAgeInDays: 90 })
    expect(mocks.post.mock.calls[0][1]).toEqual({ q: IP, key: 'ipapi-secret' })
    expect(result.abuseipdb?.abuseConfidenceScore).toBe(0)
    expect(result.ipapi?.asn).toBe(64500)
    expect(result.sourceStatus).toEqual({
      abuseipdb: 'ok',
      ipapi: 'ok',
      proxycheck: 'ok',
      scamalytics: 'unconfigured'
    })
    expect(JSON.stringify(result)).not.toContain('secret')
  })

  it('does not request unconfigured optional services', async () => {
    mocks.get.mockResolvedValue({ data: { [IP]: { detections: { risk: 0 } } } })
    const result = await queryPuritySources(IP, {})
    expect(mocks.get).toHaveBeenCalledTimes(1)
    expect(mocks.post).not.toHaveBeenCalled()
    expect(result.sourceStatus?.abuseipdb).toBe('unconfigured')
    expect(result.sourceStatus?.ipapi).toBe('unconfigured')
  })

  it('preserves successful sources when an optional key is rejected; no raw errors escape', async () => {
    mocks.get.mockImplementation(async (url: string) => {
      if (url.includes('abuseipdb')) throw { response: { status: 401 }, message: 'SECRET-URL' }
      return { data: { [IP]: { detections: { risk: 20 } } } }
    })
    mocks.post.mockResolvedValue({ data: { error: 'SECRET-URL' } })
    const result = await queryPuritySources(IP, config)
    expect(result.proxycheck?.riskScore).toBe(20)
    expect(result.sourceStatus?.abuseipdb).toBe('unauthorized')
    expect(result.sourceStatus?.ipapi).toBe('invalid')
    expect(JSON.stringify(result)).not.toContain('SECRET')
  })

  it('backs off after a provider 429 rather than hammering subsequent nodes', async () => {
    mocks.get.mockResolvedValue({ data: { [IP]: { detections: { risk: 0 } } } })
    mocks.post.mockRejectedValue({ response: { status: 429, headers: { 'retry-after': '120' } } })
    const limited = { ipPurityIpapiApiKey: 'quota-test-key' }
    await queryPuritySources(IP, limited)
    const result = await queryPuritySources(IP, limited)
    expect(mocks.post).toHaveBeenCalledTimes(1)
    expect(result.sourceStatus?.ipapi).toBe('rate_limited')
  })

  it('rejects wrong-IP and API-error payloads', () => {
    expect(
      parseAbuseIPDB(IP, { data: { ipAddress: '203.0.113.12', abuseConfidenceScore: 0 } })
    ).toBeUndefined()
    expect(parseIpapi(IP, { ip: '203.0.113.12', is_abuser: false })).toBeUndefined()
    expect(parseIpapi(IP, { error: 'quota exceeded', ip: IP })).toBeUndefined()
    expect(
      parseAbuseIPDB(IP, { errors: [], data: { ipAddress: IP, abuseConfidenceScore: 0 } })
    ).toBeUndefined()
  })

  it('does not confuse network-wide abuse ratios with per-IP risk', () => {
    const result = parseIpapi(IP, {
      ip: IP,
      company: { name: 'Test', abuser_score: '0.99 (High)' },
      asn: { abuser_score: '0.88 (High)' },
      is_abuser: false
    })
    expect(result?.isAbuser).toBe(false)
    expect(JSON.stringify(result)).not.toContain('0.99')
  })

  it.each([null, undefined, '', ' ', -1, 101, NaN])(
    'does not turn invalid abuse score %s into zero',
    (score) => {
      expect(
        parseAbuseIPDB(IP, { data: { ipAddress: IP, abuseConfidenceScore: score } })
      ).toBeUndefined()
    }
  )
})
