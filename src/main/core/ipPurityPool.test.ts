import { describe, expect, it } from 'vitest'
import { IpPurityPool } from './ipPurityPool'
import {
  ensureIpPurityPort,
  injectIpPurityRuntime,
  isIpPurityGroup,
  ipPurityGroupName
} from './ipPurityRuntime'

describe('IP purity worker pool and runtime', () => {
  it('releases a slot after a synchronous failure', async () => {
    const pool = new IpPurityPool(1)
    await expect(
      pool.run(() => {
        throw new Error('failed')
      })
    ).rejects.toThrow('failed')
    expect(await pool.run(async (slot) => slot)).toBe(0)
  })

  it('allocates distinct reusable loopback ports', async () => {
    const ports = await Promise.all([0, 1, 2].map(ensureIpPurityPort))
    expect(new Set(ports).size).toBe(3)
    expect(await ensureIpPurityPort(1)).toBe(ports[1])
    await expect(ensureIpPurityPort(3)).rejects.toThrow('Invalid')
  })

  it('injects three isolated listeners without duplicating or replacing user groups', async () => {
    const profile = {
      'proxy-groups': [{ name: 'User choice', type: 'select' }],
      listeners: []
    } as unknown as IMihomoConfig
    await injectIpPurityRuntime(profile, true)
    await injectIpPurityRuntime(profile, true)
    const config = profile as unknown as {
      'proxy-groups': { name: string }[]
      listeners: { listen: string; port: number; proxy: string }[]
    }
    expect(config['proxy-groups'].map((group) => group.name)).toEqual([
      'User choice',
      ...[0, 1, 2].map(ipPurityGroupName)
    ])
    expect(config.listeners).toHaveLength(3)
    expect(config.listeners.every((listener) => listener.listen === '127.0.0.1')).toBe(true)
    expect(new Set(config.listeners.map((listener) => listener.port)).size).toBe(3)
    expect(config.listeners.every((listener) => isIpPurityGroup(listener.proxy))).toBe(true)
    await injectIpPurityRuntime(profile, false)
    expect(config['proxy-groups']).toEqual([{ name: 'User choice', type: 'select' }])
    expect(config.listeners).toEqual([])
  })
})
