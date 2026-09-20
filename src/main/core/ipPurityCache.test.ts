import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest'
import { mkdtemp, readFile, writeFile, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import {
  IpPurityCache,
  canonicalExitIp,
  ipPurityCacheMs,
  type IpPurityRecord
} from './ipPurityCache'

let directory: string
let filename: string
const IP = '203.0.113.1'
const SOURCE = 'a'.repeat(64)
const HOUR = 60 * 60 * 1000
const create = (): IpPurityCache => new IpPurityCache(() => filename)
const entry = (risk = 10): IpPurityRecord => ({
  ip: IP,
  sourceKey: SOURCE,
  checkedAt: Date.now(),
  score: 100 - risk,
  proxycheck: { riskScore: risk }
})

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'purity-cache-'))
  filename = join(directory, 'ip-purity-cache.json')
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
})
afterEach(async () => {
  vi.useRealTimers()
  await rm(directory, { recursive: true, force: true })
})

describe('disk cache', () => {
  it('restores results after a new instance, without renewing timestamps', async () => {
    const cache = create()
    await cache.load()
    const original = entry()
    cache.setIp(original)
    cache.remember('profile-A', 'A', IP)
    cache.remember('profile-A', 'B', IP)
    await cache.save()
    vi.setSystemTime(Date.now() + HOUR)
    const restarted = create()
    await restarted.load()
    expect(restarted.result('profile-A', 'A', SOURCE, 24 * HOUR)?.checkedAt).toBe(
      original.checkedAt
    )
    expect(restarted.result('profile-A', 'B', SOURCE, 24 * HOUR)?.score).toBe(90)
    expect(Object.keys(JSON.parse(await readFile(filename, 'utf8')).byIp)).toEqual([IP])
  })

  it('applies configured 24/48 hour retention on restored entries', async () => {
    const cache = create()
    await cache.load()
    cache.setIp(entry())
    cache.remember('p', 'A', IP)
    await cache.save()
    vi.setSystemTime(Date.now() + 25 * HOUR)
    const restarted = create()
    await restarted.load()
    expect(restarted.result('p', 'A', SOURCE, ipPurityCacheMs(24))).toBeUndefined()
    expect(restarted.result('p', 'A', SOURCE, ipPurityCacheMs(48))?.score).toBe(90)
    vi.setSystemTime(Date.now() + 23 * HOUR)
    expect(restarted.result('p', 'A', SOURCE, ipPurityCacheMs(48))).toBeUndefined()
  })

  it('does not revive an old node mapping when another node refreshes that IP', async () => {
    const cache = create()
    await cache.load()
    cache.setIp(entry())
    cache.remember('p', 'old', IP)
    vi.setSystemTime(Date.now() + 25 * HOUR)
    cache.setIp(entry())
    cache.remember('p', 'new', IP)
    expect(cache.result('p', 'old', SOURCE, 24 * HOUR)).toBeUndefined()
    expect(cache.result('p', 'new', SOURCE, 24 * HOUR)?.score).toBe(90)
  })

  it('clears disk and memory without earlier queued writes resurrecting entries', async () => {
    const cache = create()
    await cache.load()
    cache.setIp(entry())
    cache.remember('p', 'A', IP)
    const saving = cache.save()
    await cache.clear()
    await saving
    const restarted = create()
    await restarted.load()
    expect(restarted.results('p', SOURCE, 24 * HOUR)).toEqual({})
    expect(JSON.parse(await readFile(filename, 'utf8')).byIp).toEqual({})
  })

  it('recovers from corrupt JSON without preventing future saves', async () => {
    await writeFile(filename, '{broken')
    const cache = create()
    await cache.load()
    expect(cache.results('p', SOURCE, 24 * HOUR)).toEqual({})
    cache.setIp(entry())
    cache.remember('p', 'A', IP)
    await cache.save()
    expect(JSON.parse(await readFile(filename, 'utf8')).version).toBe(1)
  })

  it('preserves valid zero but never accepts missing or out-of-range scores', async () => {
    const cache = create()
    await cache.load()
    cache.setIp(entry(100))
    cache.remember('p', 'A', IP)
    await cache.save()
    const restarted = create()
    await restarted.load()
    expect(restarted.result('p', 'A', SOURCE, 24 * HOUR)?.score).toBe(0)
    expect(() => cache.setIp({ ...entry(), score: -1 })).toThrow()
    expect(() => cache.setIp({ ...entry(), proxycheck: undefined })).toThrow()
  })

  it('does not reuse a combined score after provider configuration changes', async () => {
    const cache = create()
    await cache.load()
    cache.setIp(entry())
    cache.remember('p', 'A', IP)
    expect(cache.result('p', 'A', 'b'.repeat(64), 24 * HOUR)).toBeUndefined()
  })

  it('serializes an allowlist and excludes credentials, raw responses and warnings', async () => {
    const cache = create()
    await cache.load()
    cache.setIp({
      ...entry(),
      apiKey: 'secret',
      warnings: ['secret'],
      raw: { key: 'secret' }
    } as IpPurityRecord)
    await cache.save()
    const saved = await readFile(filename, 'utf8')
    expect(saved).not.toContain('secret')
    expect(saved).not.toContain('warnings')
  })

  it('normalizes IPv6 keys and rejects malformed exit addresses', () => {
    expect(canonicalExitIp('2001:0DB8:0:0:0:0:0:1')).toBe('2001:db8::1')
    expect(() => canonicalExitIp('not an IP')).toThrow()
    expect(ipPurityCacheMs(NaN)).toBe(24 * HOUR)
  })
})
