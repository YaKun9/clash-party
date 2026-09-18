import { createServer } from 'net'

export const IP_PURITY_GROUP_NAME = '__clash_party_internal_ip_purity__'
export const IP_PURITY_LISTENER_NAME = '__clash_party_internal_ip_purity_listener__'

let purityPortPromise: Promise<number> | null = null

async function allocateFreePort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server = createServer()
    server.unref()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (!address || typeof address === 'string') {
        server.close()
        reject(new Error('Failed to allocate IP purity listener port'))
        return
      }

      const port = address.port
      server.close((error) => {
        if (error) reject(error)
        else resolve(port)
      })
    })
  })
}

export function ensureIpPurityPort(): Promise<number> {
  if (!purityPortPromise) {
    purityPortPromise = allocateFreePort().catch((error) => {
      purityPortPromise = null
      throw error
    })
  }
  return purityPortPromise
}
