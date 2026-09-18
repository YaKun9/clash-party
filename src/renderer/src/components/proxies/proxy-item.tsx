import { Button, Card, CardBody, Tooltip } from '@heroui/react'
import { mihomoUnfixedProxy } from '@renderer/utils/ipc'
import type { ProxyPurityDisplayResult } from '@renderer/utils/ip-purity'
import React, { useMemo, useState, useCallback } from 'react'
import { FaMapPin } from 'react-icons/fa6'
import { useTranslation } from 'react-i18next'
import { KeyedMutator } from 'swr'

interface Props {
  mutateProxies: KeyedMutator<IMihomoMixedGroup[]>
  onProxyDelay: (proxy: IMihomoProxy | IMihomoGroup, url?: string) => Promise<IMihomoDelay>
  proxyDisplayMode: 'simple' | 'full'
  proxy: IMihomoProxy | IMihomoGroup
  group: IMihomoMixedGroup
  onSelect: (group: string, proxy: string) => void
  selected: boolean
  isGroupTesting?: boolean
  purity?: ProxyPurityDisplayResult
  purityChecking?: boolean
  onPurity?: (proxy: IMihomoProxy | IMihomoGroup) => void
}

// Keep both metrics equally readable and prevent narrow cards from shrinking them.
const METRIC_BUTTON_CLASS = 'h-6 min-w-0 shrink-0 px-2 text-sm font-normal tabular-nums'

function delayColor(delay: number): 'primary' | 'success' | 'warning' | 'danger' {
  if (delay === -1) return 'primary'
  if (delay === 0) return 'danger'
  if (delay < 500) return 'success'
  return 'warning'
}

const ProxyItemBase: React.FC<Props> = (props) => {
  const { t } = useTranslation()
  const {
    mutateProxies,
    proxyDisplayMode,
    group,
    proxy,
    selected,
    onSelect,
    onProxyDelay,
    isGroupTesting = false,
    purity,
    purityChecking = false,
    onPurity
  } = props

  const delay = useMemo(() => {
    if (proxy.history.length > 0) {
      return proxy.history[proxy.history.length - 1].delay
    }
    return -1
  }, [proxy.history])

  const [loading, setLoading] = useState(false)

  const isLoading = loading || isGroupTesting

  const delayText = useMemo(() => {
    if (delay === -1) return t('proxies.delay.test')
    if (delay === 0) return t('proxies.delay.timeout')
    return delay.toString()
  }, [delay, t])

  const onDelay = useCallback((): void => {
    setLoading(true)
    onProxyDelay(proxy, group.testUrl).finally(() => {
      mutateProxies()
      setLoading(false)
    })
  }, [proxy, group.testUrl, onProxyDelay, mutateProxies])

  const fixed = useMemo(() => group.fixed && group.fixed === proxy.name, [group.fixed, proxy.name])

  const purityColor = useMemo((): 'primary' | 'success' | 'warning' | 'danger' => {
    if (purity === 'timeout') return 'danger'
    if (!purity) return 'primary'
    if (purity.score >= 85) return 'success'
    if (purity.score >= 65) return 'warning'
    return 'danger'
  }, [purity])

  const purityText = useMemo(() => {
    if (purity === 'timeout') return t('proxies.delay.timeout')
    return purity ? `${t('proxies.purity.short')}${purity.score}` : t('proxies.purity.check')
  }, [purity, t])

  const purityTooltip = useMemo(() => {
    if (purity === 'timeout') {
      return `${t('proxies.purity.score')}: ${t('proxies.delay.timeout')}\n${t('proxies.purity.clickToCheck')}`
    }
    if (!purity) return t('proxies.purity.clickToCheck')
    const parts = [
      `${t('proxies.purity.ip')}: ${purity.ip}`,
      `${t('proxies.purity.score')}: ${purity.score}`
    ]
    if (purity.scamalytics) {
      parts.push(`Scamalytics: ${purity.scamalytics.score}/100`)
    }
    if (purity.proxycheck) {
      parts.push(`proxycheck.io: ${purity.proxycheck.riskScore}/100`)
      if (purity.proxycheck.vpn) parts.push('VPN')
      if (purity.proxycheck.proxy) parts.push('Proxy')
      if (purity.proxycheck.tor) parts.push('Tor')
      if (purity.proxycheck.compromised) parts.push('Compromised')
    }
    return parts.join('\n')
  }, [purity, t])

  const purityButton =
    onPurity && !('all' in proxy) ? (
      <Tooltip content={<span className="whitespace-pre-line text-sm">{purityTooltip}</span>}>
        <Button
          size="sm"
          variant="light"
          color={purityColor}
          isLoading={purityChecking}
          isDisabled={purityChecking}
          aria-label={`${t('proxies.purity.score')}: ${purityText}`}
          onPress={() => onPurity(proxy)}
          className={METRIC_BUTTON_CLASS}
          data-metric="purity"
        >
          {purityText}
        </Button>
      </Tooltip>
    ) : null

  const delayButton = (
    <Button
      size="sm"
      title={proxy.type}
      aria-label={`${t('proxies.delay.test')}: ${delayText}`}
      isLoading={isLoading}
      isDisabled={isLoading}
      color={delayColor(delay)}
      onPress={onDelay}
      variant="light"
      className={METRIC_BUTTON_CLASS}
      data-metric="delay"
    >
      {delayText}
    </Button>
  )

  const metrics = (
    <div
      className="ml-auto flex shrink-0 items-center"
      data-proxy-metrics
      onClick={(event) => event.stopPropagation()}
      onPointerDown={(event) => event.stopPropagation()}
      onKeyDown={(event) => event.stopPropagation()}
    >
      {purityButton}
      {delayButton}
    </div>
  )

  return (
    <Card
      as="div"
      onPress={() => onSelect(group.name, proxy.name)}
      isPressable
      fullWidth
      shadow="sm"
      className={`${
        fixed
          ? 'bg-secondary/30 border-r-2 border-r-secondary border-l-2 border-l-secondary'
          : selected
            ? 'bg-primary/30 border-r-2 border-r-primary border-l-2 border-l-primary'
            : 'bg-content2'
      }`}
      radius="sm"
    >
      <CardBody className="p-1">
        {proxyDisplayMode === 'full' ? (
          <div className="flex flex-col gap-1">
            <div className="flex justify-between items-center pl-1">
              <div className="text-ellipsis overflow-hidden whitespace-nowrap">
                <div className="flag-emoji inline" title={proxy.name}>
                  {proxy.name}
                </div>
              </div>
              {fixed && (
                <Button
                  isIconOnly
                  title={t('proxies.unpin')}
                  color="danger"
                  onPress={async () => {
                    await mihomoUnfixedProxy(group.name)
                    mutateProxies()
                  }}
                  variant="light"
                  className="h-5 p-0 text-sm"
                >
                  <FaMapPin className="text-md le" />
                </Button>
              )}
            </div>
            <div className="flex items-center gap-1 pl-1">
              <div className="flex min-w-0 flex-1 gap-1 items-center overflow-hidden">
                <div className="shrink-0 text-foreground-400 text-xs bg-default-100 px-1 rounded-md">
                  {proxy.type}
                </div>
                {['tfo', 'udp', 'xudp', 'mptcp', 'smux'].map(
                  (protocol) =>
                    proxy[protocol as keyof IMihomoProxy] && (
                      <div
                        key={protocol}
                        className="shrink-0 text-foreground-400 text-xs bg-default-100 px-1 rounded-md"
                      >
                        {protocol}
                      </div>
                    )
                )}
              </div>
              {metrics}
            </div>
          </div>
        ) : (
          <div className="flex justify-between items-center pl-1">
            <div className="min-w-0 text-ellipsis overflow-hidden whitespace-nowrap">
              <div className="flag-emoji inline" title={proxy.name}>
                {proxy.name}
              </div>
            </div>
            <div className="flex shrink-0 justify-end items-center gap-1">
              {fixed && (
                <Button
                  isIconOnly
                  title={t('proxies.unpin')}
                  color="danger"
                  onPress={async () => {
                    await mihomoUnfixedProxy(group.name)
                    mutateProxies()
                  }}
                  variant="light"
                  className="h-5 p-0 text-sm"
                >
                  <FaMapPin className="text-md le" />
                </Button>
              )}
              {metrics}
            </div>
          </div>
        )}
      </CardBody>
    </Card>
  )
}

const ProxyItem = React.memo(ProxyItemBase, (prevProps, nextProps) => {
  // 必要时重新渲染
  return (
    prevProps.proxy.name === nextProps.proxy.name &&
    prevProps.proxy.history === nextProps.proxy.history &&
    prevProps.selected === nextProps.selected &&
    prevProps.proxyDisplayMode === nextProps.proxyDisplayMode &&
    prevProps.group.fixed === nextProps.group.fixed &&
    prevProps.isGroupTesting === nextProps.isGroupTesting &&
    prevProps.purity === nextProps.purity &&
    prevProps.purityChecking === nextProps.purityChecking &&
    prevProps.onPurity === nextProps.onPurity
  )
})

ProxyItem.displayName = 'ProxyItem'

export default ProxyItem
