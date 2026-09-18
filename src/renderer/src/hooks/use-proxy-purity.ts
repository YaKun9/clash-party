import { useCallback, useMemo } from 'react'
import useSWR from 'swr'
import { mihomoProxyPurity } from '@renderer/utils/ipc'
import { getProxyPurityState } from '@renderer/utils/ip-purity'
import { toast } from '@renderer/components/base/toast'

const EMPTY_RESULTS: Record<string, IProxyPurityResult> = {}

export function useProxyPurity(): {
  purityResults: Record<string, IProxyPurityResult>
  purityChecking: Set<string>
  onProxyPurity: (proxy: IMihomoProxy | IMihomoGroup) => Promise<void>
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
      const request = mihomoProxyPurity(proxy.name)
      // The main process owns pending state and deduplicates repeated node requests.
      void refresh().catch(console.error)
      try {
        await request
      } catch (error) {
        toast.error(String(error))
      } finally {
        // Read the cache instead of merging the returned result: a clear during the
        // request must not be undone by a stale completion in an unmounted page.
        await refresh().catch(console.error)
      }
    },
    [refresh]
  )

  const purityChecking = useMemo(() => new Set(data?.checking ?? []), [data?.checking])
  return { purityResults: data?.results ?? EMPTY_RESULTS, purityChecking, onProxyPurity }
}
