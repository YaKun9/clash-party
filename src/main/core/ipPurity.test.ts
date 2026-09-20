import { mkdtemp, rm, readFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  httpGet: vi.fn(),
  put: vi.fn(),
  cacheDir: '',
  profile: 'profile-A'
}))
vi.mock('../utils/dirs', () => ({ dataDir: () => mocks.cacheDir }))
vi.mock('axios', () => ({ default: { get: mocks.httpGet } }))
vi.mock('../config', () => ({
  getAppConfig: async () => ({ ipPurityEnabled: true, ipPurityCacheHours: 24 }),
  getProfileConfig: async () => ({ current: mocks.profile })
}))
vi.mock('./mihomoApi', () => ({ getAxios: async () => ({ put: mocks.put }) }))
vi.mock('./ipPurityRuntime', () => ({
  ensureIpPurityPort: async (slot: number) => 17990 + slot,
  ipPurityGroupName: (slot: number) => `test-purity-${slot}`,
  IP_PURITY_CONCURRENCY: 3
}))

import {
  clearProxyPurityCache,
  getProxyPurityState,
  mihomoProxyPurity,
  mihomoGroupPurity
} from './ipPurity'

const IP = '203.0.113.1'
const providerResponse = { data: { [IP]: { detections: { risk: 10 } } } }
const emptyState = { results: {}, checking: [], failed: [] }

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

beforeEach(async () => {
  mocks.cacheDir = await mkdtemp(join(tmpdir(), 'purity-integration-'))
  mocks.profile = 'profile-A'
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
  await clearProxyPurityCache()
  mocks.put.mockReset().mockResolvedValue(undefined)
  mocks.httpGet.mockReset().mockImplementation(async (url: string) => {
    return url.includes('ipify.org') ? { data: { ip: IP } } : providerResponse
  })
})

afterEach(async () => {
  await clearProxyPurityCache()
  await rm(mocks.cacheDir, { recursive: true, force: true })
  vi.useRealTimers()
})

describe('IP purity cache restoration', () => {
  it('reads an empty snapshot without network activity', async () => {
    expect(await getProxyPurityState()).toEqual(emptyState)
    expect(mocks.httpGet).not.toHaveBeenCalled()
    expect(mocks.put).not.toHaveBeenCalled()
  })

  it('restores completed results without additional API calls', async () => {
    const result = await mihomoProxyPurity('Singapore')
    expect(mocks.httpGet).toHaveBeenCalledTimes(2)
    vi.setSystemTime(Date.now() + 60000)
    const expected = { ...emptyState, results: { Singapore: result } }
    expect(await getProxyPurityState()).toEqual(expected)
    expect(await getProxyPurityState()).toEqual(expected)
    expect(await mihomoProxyPurity('Singapore')).toEqual(result)
    expect(mocks.httpGet).toHaveBeenCalledTimes(2)
  })

  it('restores pending state and deduplicates repeated node checks', async () => {
    const started = deferred<void>()
    const response = deferred<typeof providerResponse>()
    mocks.httpGet.mockImplementation(async (url: string) => {
      if (url.includes('ipify.org')) return { data: { ip: IP } }
      started.resolve()
      return response.promise
    })
    const first = mihomoProxyPurity('Singapore')
    const second = mihomoProxyPurity('Singapore')
    await started.promise
    expect((await getProxyPurityState()).checking).toEqual(['Singapore'])
    response.resolve(providerResponse)
    const result = await first
    expect(await second).toEqual(result)
    expect(await getProxyPurityState()).toEqual({ ...emptyState, results: { Singapore: result } })
    expect(mocks.httpGet).toHaveBeenCalledTimes(2)
  })

  it('shares the provider cache for nodes with the same exit IP', async () => {
    await mihomoProxyPurity('Singapore1')
    await mihomoProxyPurity('Singapore2')
    expect(mocks.httpGet).toHaveBeenCalledTimes(3)
    const names = Object.keys((await getProxyPurityState()).results)
    expect(names).toEqual(['Singapore1', 'Singapore2'])
  })

  it('expires results without automatically rechecking the node', async () => {
    await mihomoProxyPurity('Singapore')
    vi.setSystemTime(Date.now() + 24 * 60 * 60 * 1000)
    expect(await getProxyPurityState()).toEqual(emptyState)
    expect(mocks.httpGet).toHaveBeenCalledTimes(2)
    await mihomoProxyPurity('Singapore')
    expect(mocks.httpGet).toHaveBeenCalledTimes(4)
  })

  it('does not restore cleared results on the next page read', async () => {
    await mihomoProxyPurity('Singapore')
    await clearProxyPurityCache()
    expect(await getProxyPurityState()).toEqual(emptyState)
    expect(mocks.httpGet).toHaveBeenCalledTimes(2)
  })

  it('does not resurrect caches after clearing an in-flight check', async () => {
    const started = deferred<void>()
    const response = deferred<typeof providerResponse>()
    mocks.httpGet.mockImplementation(async (url: string) => {
      if (url.includes('ipify.org')) return { data: { ip: IP } }
      started.resolve()
      return response.promise
    })
    const request = mihomoProxyPurity('Singapore1')
    await started.promise
    await clearProxyPurityCache()
    response.resolve(providerResponse)
    await request
    expect(await getProxyPurityState()).toEqual(emptyState)
    await mihomoProxyPurity('Singapore2')
    expect(mocks.httpGet).toHaveBeenCalledTimes(4)
  })

  it('restores failure display state without blocking an explicit retry', async () => {
    mocks.httpGet.mockResolvedValueOnce({ data: { ip: IP } })
    mocks.httpGet.mockRejectedValueOnce(new Error('offline'))
    await expect(mihomoProxyPurity('Singapore')).rejects.toThrow('offline')
    const expected = { ...emptyState, failed: ['Singapore'] }
    expect(await getProxyPurityState()).toEqual(expected)
    expect(await getProxyPurityState()).toEqual(expected)
    expect(mocks.httpGet).toHaveBeenCalledTimes(2)
    await mihomoProxyPurity('Singapore')
    expect((await getProxyPurityState()).results.Singapore.score).toBe(90)
    expect((await getProxyPurityState()).failed).toEqual([])
    expect(mocks.httpGet).toHaveBeenCalledTimes(4)
  })

  it('marks TLS failures inline and allows the next node in the batch to run', async () => {
    mocks.httpGet.mockRejectedValueOnce(
      new Error('Client network socket disconnected before secure TLS connection was established')
    )
    await expect(mihomoProxyPurity('Hong Kong')).rejects.toThrow('TLS')
    await mihomoProxyPurity('Singapore')
    const state = await getProxyPurityState()
    expect(state.failed).toEqual(['Hong Kong'])
    expect(state.results.Singapore.score).toBe(90)
    expect(state.results['Hong Kong']).toBeUndefined()
    expect(state.checking).toEqual([])
  })

  it('clears failed markers together with successful results', async () => {
    mocks.httpGet.mockRejectedValueOnce(new Error('offline'))
    await expect(mihomoProxyPurity('Singapore')).rejects.toThrow()
    await clearProxyPurityCache()
    expect(await getProxyPurityState()).toEqual(emptyState)
  })

  it('does not resurrect failure state after clearing a pending request', async () => {
    const started = deferred<void>()
    const resume = deferred<void>()
    mocks.httpGet.mockImplementationOnce(async () => {
      started.resolve()
      await resume.promise
      throw new Error('late failure')
    })
    const assertion = expect(mihomoProxyPurity('Singapore')).rejects.toThrow('late failure')
    await started.promise
    await clearProxyPurityCache()
    resume.resolve()
    await assertion
    expect(await getProxyPurityState()).toEqual(emptyState)
  })
})

describe('valid zero scores versus missing or failed results', () => {
  it('preserves a real zero purity result when the provider reports risk 100', async () => {
    mocks.httpGet.mockResolvedValueOnce({ data: { ip: IP } })
    mocks.httpGet.mockResolvedValueOnce({
      data: { status: 'ok', [IP]: { detections: { risk: 100, proxy: true } } }
    })
    const result = await mihomoProxyPurity('Proxy')
    expect(result.score).toBe(0)
    expect(result.proxycheck?.riskScore).toBe(100)
    expect((await getProxyPurityState()).failed).toEqual([])
    expect((await getProxyPurityState()).results.Proxy.score).toBe(0)
  })

  it('accepts a numeric zero risk score without treating it as missing', async () => {
    mocks.httpGet.mockResolvedValueOnce({ data: { ip: IP } })
    mocks.httpGet.mockResolvedValueOnce({ data: { [IP]: { detections: { risk: 0 } } } })
    expect((await mihomoProxyPurity('Singapore')).score).toBe(100)
  })

  it.each(['', ' ', null, undefined, -1, 101, 'invalid', NaN, Infinity])(
    'does not fabricate a score for invalid risk %s',
    async (risk) => {
      mocks.httpGet.mockResolvedValueOnce({ data: { ip: IP } })
      mocks.httpGet.mockResolvedValueOnce({ data: { [IP]: { detections: { risk } } } })
      await expect(mihomoProxyPurity('Singapore')).rejects.toThrow('unsupported response')
      expect(await getProxyPurityState()).toEqual({ ...emptyState, failed: ['Singapore'] })
    }
  )

  it('does not accept an API error body as a valid zero risk result', async () => {
    mocks.httpGet.mockResolvedValueOnce({ data: { ip: IP } })
    mocks.httpGet.mockResolvedValueOnce({
      data: { status: 'error', [IP]: { detections: { risk: 0 } } }
    })
    await expect(mihomoProxyPurity('Singapore')).rejects.toThrow('unsupported response')
    expect((await getProxyPurityState()).results).toEqual({})
  })
})

describe('isolated bounded concurrency', () => {
  it('runs three different exits concurrently and queues the fourth without mixing routes', async () => {
    const selected = new Map<number, string>()
    const ipFor = { A: '203.0.113.1', B: '203.0.113.2', C: '203.0.113.3', D: '203.0.113.4' }
    const firstThreeStarted = deferred<void>()
    const release = deferred<void>()
    const ports = new Set<number>()
    let probes = 0
    mocks.put.mockImplementation(async (url: string, body: { name: string }) => {
      const slot = Number(url.slice(-1))
      selected.set(17990 + slot, body.name)
    })
    mocks.httpGet.mockImplementation(
      async (url: string, options?: { proxy?: { port: number } }) => {
        if (url.includes('ipify.org')) {
          const port = options!.proxy!.port
          ports.add(port)
          const node = selected.get(port) as keyof typeof ipFor
          probes++
          if (probes === 3) firstThreeStarted.resolve()
          await release.promise
          // No other task may change this selector while this probe is active.
          expect(selected.get(port)).toBe(node)
          return { data: { ip: ipFor[node] } }
        }
        const ip = decodeURIComponent(url.split('/').pop()!)
        return { data: { [ip]: { detections: { risk: 10 } } } }
      }
    )
    const requests = ['A', 'B', 'C', 'D'].map((proxy) => mihomoProxyPurity(proxy))
    await firstThreeStarted.promise
    expect(probes).toBe(3)
    expect(mocks.put).toHaveBeenCalledTimes(3)
    expect(ports.size).toBe(3)
    expect((await getProxyPurityState()).checking).toHaveLength(4)
    release.resolve()
    const results = await Promise.all(requests)
    expect(results.map((result) => result.ip)).toEqual(Object.values(ipFor))
    expect(mocks.put).toHaveBeenCalledTimes(4)
    expect((await getProxyPurityState()).checking).toEqual([])
  })

  it('deduplicates simultaneous provider requests for a shared exit IP', async () => {
    const lookup = deferred<typeof providerResponse>()
    const started = deferred<void>()
    let lookups = 0
    mocks.httpGet.mockImplementation(async (url: string) => {
      if (url.includes('ipify.org')) return { data: { ip: IP } }
      lookups++
      started.resolve()
      return lookup.promise
    })
    const requests = ['A', 'B', 'C'].map((proxy) => mihomoProxyPurity(proxy))
    await started.promise
    for (let index = 0; index < 30; index++) await Promise.resolve()
    expect(lookups).toBe(1)
    expect(mocks.httpGet).toHaveBeenCalledTimes(4)
    lookup.resolve(providerResponse)
    const results = await Promise.all(requests)
    expect(results.map((result) => result.score)).toEqual([90, 90, 90])
  })
})

describe('persistent cache and explicit refresh integration', () => {
  it('uses one IP record for different nodes and persists before returning', async () => {
    await mihomoProxyPurity('A')
    await mihomoProxyPurity('B')
    const saved = JSON.parse(await readFile(join(mocks.cacheDir, 'ip-purity-cache.json'), 'utf8'))
    expect(Object.keys(saved.byIp)).toEqual([IP])
    expect(Object.keys(saved.nodes)).toHaveLength(2)
    expect(mocks.httpGet).toHaveBeenCalledTimes(3)
  })

  it('manual refresh probes again, bypasses the IP cache and updates every mapped node', async () => {
    await mihomoProxyPurity('A')
    await mihomoProxyPurity('B')
    mocks.httpGet.mockResolvedValueOnce({ data: { ip: IP } })
    mocks.httpGet.mockResolvedValueOnce({ data: { [IP]: { detections: { risk: 30 } } } })
    const result = await mihomoProxyPurity('A', true)
    expect(result.score).toBe(70)
    const state = await getProxyPurityState()
    expect(state.results.A.score).toBe(70)
    expect(state.results.B.score).toBe(70)
    expect(mocks.httpGet).toHaveBeenCalledTimes(5)
  })

  it('a group refresh queries one shared IP only once even after workers finish', async () => {
    await mihomoProxyPurity('A')
    mocks.httpGet.mockClear()
    await mihomoGroupPurity(['A', 'B', 'C', 'D', 'E', 'F', 'A'])
    expect(mocks.httpGet).toHaveBeenCalledTimes(7)
    expect(Object.keys((await getProxyPurityState()).results)).toHaveLength(6)
  })

  it('manual refresh detects a changed exit instead of returning the old node cache', async () => {
    await mihomoProxyPurity('A')
    const nextIp = '203.0.113.9'
    mocks.httpGet.mockResolvedValueOnce({ data: { ip: nextIp } })
    mocks.httpGet.mockResolvedValueOnce({ data: { [nextIp]: { detections: { risk: 20 } } } })
    expect((await mihomoProxyPurity('A', true)).ip).toBe(nextIp)
    expect((await getProxyPurityState()).results.A.ip).toBe(nextIp)
  })

  it('isolates identically named nodes in different profiles but reuses shared IP data', async () => {
    await mihomoProxyPurity('A')
    mocks.profile = 'profile-B'
    expect((await getProxyPurityState()).results).toEqual({})
    await mihomoProxyPurity('A')
    expect(mocks.httpGet).toHaveBeenCalledTimes(3)
    mocks.profile = 'profile-A'
    expect((await getProxyPurityState()).results.A.ip).toBe(IP)
  })
})
