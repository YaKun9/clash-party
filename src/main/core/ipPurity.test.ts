import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ httpGet: vi.fn(), put: vi.fn() }))
vi.mock('axios', () => ({ default: { get: mocks.httpGet } }))
vi.mock('../config', () => ({
  getAppConfig: async () => ({ ipPurityEnabled: true, ipPurityCacheHours: 24 })
}))
vi.mock('./mihomoApi', () => ({ getAxios: async () => ({ put: mocks.put }) }))
vi.mock('./ipPurityRuntime', () => ({
  ensureIpPurityPort: async () => 17990,
  IP_PURITY_GROUP_NAME: 'test-purity'
}))

import { clearProxyPurityCache, getProxyPurityState, mihomoProxyPurity } from './ipPurity'

const IP = '203.0.113.1'
const providerResponse = { data: { [IP]: { detections: { risk: 10 } } } }

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
  clearProxyPurityCache()
  mocks.put.mockReset().mockResolvedValue(undefined)
  mocks.httpGet.mockReset().mockImplementation(async (url: string) => {
    return url.includes('ipify.org') ? { data: { ip: IP } } : providerResponse
  })
})

afterEach(() => {
  vi.useRealTimers()
})

describe('IP purity cache restoration', () => {
  it('reads an empty snapshot without network activity', async () => {
    expect(await getProxyPurityState()).toEqual({ results: {}, checking: [] })
    expect(mocks.httpGet).not.toHaveBeenCalled()
    expect(mocks.put).not.toHaveBeenCalled()
  })

  it('restores completed results without additional API calls', async () => {
    const result = await mihomoProxyPurity('Singapore')
    expect(mocks.httpGet).toHaveBeenCalledTimes(2)
    vi.setSystemTime(Date.now() + 60000)
    expect(await getProxyPurityState()).toEqual({ results: { Singapore: result }, checking: [] })
    expect(await getProxyPurityState()).toEqual({ results: { Singapore: result }, checking: [] })
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
    expect(second).toBe(first)
    await started.promise
    expect((await getProxyPurityState()).checking).toEqual(['Singapore'])
    response.resolve(providerResponse)
    const result = await first
    expect(await getProxyPurityState()).toEqual({ results: { Singapore: result }, checking: [] })
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
    expect(await getProxyPurityState()).toEqual({ results: {}, checking: [] })
    expect(mocks.httpGet).toHaveBeenCalledTimes(2)
    await mihomoProxyPurity('Singapore')
    expect(mocks.httpGet).toHaveBeenCalledTimes(4)
  })

  it('does not restore cleared results on the next page read', async () => {
    await mihomoProxyPurity('Singapore')
    clearProxyPurityCache()
    expect(await getProxyPurityState()).toEqual({ results: {}, checking: [] })
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
    clearProxyPurityCache()
    response.resolve(providerResponse)
    await request
    expect(await getProxyPurityState()).toEqual({ results: {}, checking: [] })
    await mihomoProxyPurity('Singapore2')
    expect(mocks.httpGet).toHaveBeenCalledTimes(4)
  })

  it('does not cache failures or prevent an explicit retry', async () => {
    mocks.httpGet
      .mockResolvedValueOnce({ data: { ip: IP } })
      .mockRejectedValueOnce(new Error('offline'))
    await expect(mihomoProxyPurity('Singapore')).rejects.toThrow('offline')
    expect(await getProxyPurityState()).toEqual({ results: {}, checking: [] })
    await mihomoProxyPurity('Singapore')
    expect((await getProxyPurityState()).results.Singapore.score).toBe(90)
    expect(mocks.httpGet).toHaveBeenCalledTimes(4)
  })
})
