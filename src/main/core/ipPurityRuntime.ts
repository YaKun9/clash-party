import { createServer, type Server } from 'net'

export const IP_PURITY_CONCURRENCY = 3
export const IP_PURITY_GROUP_NAME = '__clash_party_internal_ip_purity__'
export const IP_PURITY_LISTENER_NAME = '__clash_party_internal_ip_purity_listener__'

export function ipPurityGroupName(slot: number): string {
  return slot === 0 ? IP_PURITY_GROUP_NAME : `${IP_PURITY_GROUP_NAME}${slot}`
}

function listenerName(slot: number): string {
  return slot === 0 ? IP_PURITY_LISTENER_NAME : `${IP_PURITY_LISTENER_NAME}${slot}`
}

const slots = Array.from({ length: IP_PURITY_CONCURRENCY }, (_, index) => index)
const groupNames = new Set(slots.map(ipPurityGroupName))
const listenerNames = new Set(slots.map(listenerName))
let portsPromise: Promise<number[]> | null = null

export function isIpPurityGroup(name: string): boolean {
  return groupNames.has(name)
}

async function allocatePorts(): Promise<number[]> {
  const servers: Server[] = []
  try {
    const ports: number[] = []
    // Keep earlier sockets open until all ports have been allocated, so
    // the OS cannot hand the same ephemeral port to two workers.
    for (const _slot of slots) {
      const server = createServer()
      server.unref()
      servers.push(server)
      ports.push(
        await new Promise<number>((resolve, reject) => {
          server.once('error', reject)
          server.listen(0, '127.0.0.1', () => {
            const address = server.address()
            if (!address || typeof address === 'string') {
              reject(new Error('Failed to allocate IP purity listener port'))
              return
            }
            resolve(address.port)
          })
        })
      )
    }
    return ports
  } finally {
    await Promise.all(
      servers.map(
        (server) =>
          new Promise<void>((resolve) => {
            server.close(() => resolve())
          })
      )
    )
  }
}

export async function ensureIpPurityPort(slot = 0): Promise<number> {
  if (!Number.isInteger(slot) || slot < 0 || slot >= IP_PURITY_CONCURRENCY) {
    throw new Error('Invalid IP purity worker slot')
  }
  if (!portsPromise) {
    portsPromise = allocatePorts().catch((error) => {
      portsPromise = null
      throw error
    })
  }
  return (await portsPromise)[slot]
}

export async function injectIpPurityRuntime(
  profile: IMihomoConfig,
  enabled: boolean
): Promise<void> {
  const runtime = profile as unknown as {
    'proxy-groups'?: Record<string, unknown>[]
    listeners?: Record<string, unknown>[]
  }
  const groups = Array.isArray(runtime['proxy-groups']) ? runtime['proxy-groups'] : []
  const listeners = Array.isArray(runtime.listeners) ? runtime.listeners : []
  runtime['proxy-groups'] = groups.filter((group) => !groupNames.has(String(group?.name)))
  runtime.listeners = listeners.filter((listener) => !listenerNames.has(String(listener?.name)))
  if (!enabled) return

  const ports = await Promise.all(slots.map(ensureIpPurityPort))
  for (const slot of slots) {
    runtime['proxy-groups'].push({
      name: ipPurityGroupName(slot),
      type: 'select',
      'include-all': true,
      hidden: true
    })
    runtime.listeners.push({
      name: listenerName(slot),
      type: 'mixed',
      port: ports[slot],
      listen: '127.0.0.1',
      proxy: ipPurityGroupName(slot),
      udp: false,
      users: []
    })
  }
}
