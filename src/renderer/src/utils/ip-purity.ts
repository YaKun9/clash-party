export type ProxyPurityDisplayResult = IProxyPurityResult | 'timeout'

export interface ProxyPurityState {
  results: Record<string, IProxyPurityResult>
  checking: string[]
  failed: string[]
}

// Failures are display state, not successful results with a fabricated zero score.
export function toProxyPurityResults(
  state: ProxyPurityState | undefined
): Record<string, ProxyPurityDisplayResult> {
  const failures = (state?.failed ?? []).map((proxy) => [proxy, 'timeout'] as const)
  return Object.fromEntries([...Object.entries(state?.results ?? {}), ...failures])
}

// This channel only reads main-process memory; it never performs a node/API check.
export async function getProxyPurityState(): Promise<ProxyPurityState> {
  const response = await window.electron.ipcRenderer.invoke('getProxyPurityState')
  if (response && typeof response === 'object' && 'invokeError' in response) {
    throw new Error(String(response.invokeError))
  }
  return response as ProxyPurityState
}
