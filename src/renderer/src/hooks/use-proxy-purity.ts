import { useCallback, useMemo } from 'react'
import useSWR from 'swr'
import { mihomoProxyPurity, mihomoGroupPurity } from '@renderer/utils/ipc'
import {
  getProxyPurityState,
  toProxyPurityResults,
  type ProxyPurityDisplayResult
} from '@renderer/utils/ip-purity'

export function useProxyPurity(): {
  purityResults: Record<string, ProxyPurityDisplayResult>
  purityChecking: Set<string>
  onProxyPurity: (proxy: IMihomoProxy | IMihomoGroup) => Promise<void>
  onProxiesPurity: (proxies: (IMihomoProxy | IMihomoGroup)[]) => Promise<void>
} {
  const { data, mutate } = useSWR('proxyPurityState', getProxyPurityState, {
    // Always restore from the authoritative cache after a route remount/renderer reload.
    revalidateOnMount: true,
    revalidateOnFocus: true,
    dedupingInterval: 0,
    refreshInterval: (state) => (state?.checking.length ? 500 : 30000)
  })

  const refresh = useCallback(async (): Promise<void> => {
    // Passing data also updates SWR if this page unmounts while a check is in flight.
    await mutate(getProxyPurityState(), { revalidate: false })
  }, [mutate])

  const onProxyPurity = useCallback(
    async (proxy: IMihomoProxy | IMihomoGroup): Promise<void> => {
      const request = mihomoProxyPurity(proxy.name, true)
      // The main process owns pending state and deduplicates repeated node requests.
      void refresh().catch(console.error)
      try {
        await request
      } catch {
        // The main process records a per-node timeout. Do not produce one toast
        // per failure (especially during group checks), or stop the batch.
      } finally {
        // Read the cache instead of merging the returned result: a clear during the
        // request must not be undone by a stale completion in an unmounted page.
        await refresh().catch(console.error)
      }
    },
    [refresh]
  )

  const onProxiesPurity = useCallback(
    async (proxies: (IMihomoProxy | IMihomoGroup)[]): Promise<void> => {
      const request = mihomoGroupPurity(
        proxies.filter((proxy) => !('all' in proxy)).map((proxy) => proxy.name)
      )
      void refresh().catch(console.error)
      try {
        await request
      } catch {
        /* Per-node errors stay inline. */
      } finally {
        await refresh().catch(console.error)
      }
    },
    [refresh]
  )

  const purityResults = useMemo(() => toProxyPurityResults(data), [data])
  const purityChecking = useMemo(() => new Set(data?.checking ?? []), [data?.checking])
  return { purityResults, purityChecking, onProxyPurity, onProxiesPurity }
}
