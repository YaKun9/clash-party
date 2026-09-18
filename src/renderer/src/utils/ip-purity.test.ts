import { describe, expect, it } from 'vitest'
import { toProxyPurityResults } from './ip-purity'

const result: IProxyPurityResult = {
  proxy: 'Singapore',
  ip: '203.0.113.1',
  score: 92,
  checkedAt: 1
}

describe('IP purity display state', () => {
  it('does not report untested or pending nodes as timeouts', () => {
    expect(toProxyPurityResults(undefined)).toEqual({})
    expect(toProxyPurityResults({ results: {}, checking: ['Singapore'], failed: [] })).toEqual({})
  })

  it('keeps successful scores separate from inline failures', () => {
    expect(
      toProxyPurityResults({ results: { Singapore: result }, checking: [], failed: ['Hong Kong'] })
    ).toEqual({ Singapore: result, 'Hong Kong': 'timeout' })
  })

  it('preserves valid zero scores instead of replacing them with a timeout', () => {
    const zeroResult = { ...result, score: 0 }
    const state = toProxyPurityResults({
      results: { Singapore: zeroResult },
      checking: [],
      failed: []
    })
    expect(state.Singapore).toEqual(zeroResult)
  })

  it('never fabricates a purity score for a failed check', () => {
    const state = toProxyPurityResults({ results: {}, checking: [], failed: ['Singapore'] })
    expect(state.Singapore).toBe('timeout')
  })

  it('supports arbitrary node names without mutating object prototypes', () => {
    const state = toProxyPurityResults({ results: {}, checking: [], failed: ['__proto__'] })
    expect(Object.hasOwn(state, '__proto__')).toBe(true)
    expect(state['__proto__']).toBe('timeout')
    expect(Object.getPrototypeOf(state)).toBe(Object.prototype)
  })
})
