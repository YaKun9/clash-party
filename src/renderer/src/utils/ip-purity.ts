export interface ProxyPurityState {
  results: Record<string, IProxyPurityResult>
  checking: string[]
}

// This channel only reads main-process memory; it never performs a node/API check.
export async function getProxyPurityState(): Promise<ProxyPurityState> {
  const response = await window.electron.ipcRenderer.invoke('getProxyPurityState')
  if (response && typeof response === 'object' && 'invokeError' in response) {
    throw new Error(String(response.invokeError))
  }
  return response as ProxyPurityState
}
