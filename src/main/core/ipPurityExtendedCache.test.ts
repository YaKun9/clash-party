import { mkdtemp, readFile, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { expect, it } from 'vitest'
import { IpPurityCache } from './ipPurityCache'

it('restores all four sources and safe statuses after a new cache instance loads', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'purity-four-source-'))
  try {
    const file = () => join(dir, 'cache.json')
    const first = new IpPurityCache(file)
    await first.load()
    const sourceKey = 'a'.repeat(64)
    first.setIp({
      ip: '203.0.113.1',
      sourceKey,
      score: 95,
      checkedAt: Date.now(),
      abuseipdb: { abuseConfidenceScore: 0, totalReports: 0, maxAgeInDays: 90 },
      ipapi: { isAbuser: false, isVpn: true, asn: 64500, country: 'Test' },
      proxycheck: { riskScore: 50, vpn: true },
      sourceStatus: { abuseipdb: 'ok', ipapi: 'ok', proxycheck: 'ok', scamalytics: 'unconfigured' }
    })
    first.remember('profile', 'Node', '203.0.113.1')
    await first.save()
    const second = new IpPurityCache(file)
    await second.load()
    const result = second.result('profile', 'Node', sourceKey, 86400000)
    expect(result?.abuseipdb?.totalReports).toBe(0)
    expect(result?.ipapi?.asn).toBe(64500)
    expect(result?.sourceStatus?.scamalytics).toBe('unconfigured')
    const raw = await readFile(file(), 'utf8')
    expect(raw).not.toContain('ApiKey')
    expect(second.result('profile', 'Node', 'b'.repeat(64), 86400000)).toBeUndefined()
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
