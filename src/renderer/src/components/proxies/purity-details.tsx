import React from 'react'
import { useTranslation } from 'react-i18next'
import { FiShield, FiGlobe, FiClock, FiAlertCircle } from 'react-icons/fi'
import {
  explainPurityScore,
  IP_PURITY_SOURCES,
  ipapiWeightedRisk
} from '../../../../shared/ipPurityScore'

const names: Record<IpPuritySource, string> = {
  abuseipdb: 'AbuseIPDB',
  scamalytics: 'Scamalytics',
  proxycheck: 'proxycheck.io',
  ipapi: 'ipapi.is'
}

const PurityDetails: React.FC<{ result: IProxyPurityResult }> = ({ result }) => {
  const { t, i18n } = useTranslation()
  const label = (key: string): string => t(`proxies.purity.details.${key}`)
  const explanation = explainPurityScore(result)
  const pc = result.proxycheck
  const ip = result.ipapi
  const abuse = result.abuseipdb
  const level = result.score >= 85 ? 'low' : result.score >= 65 ? 'medium' : 'high'
  const colors =
    level === 'low'
      ? 'bg-success/10 text-success'
      : level === 'medium'
        ? 'bg-warning/10 text-warning'
        : 'bg-danger/10 text-danger'
  const validSources = IP_PURITY_SOURCES.filter((source) => !!result[source]).length
  const limited = !abuse && !result.scamalytics && ip?.isAbuser === undefined
  const date = (value: number | string | undefined): string => {
    if (value === undefined || !Number.isFinite(new Date(value).getTime())) return '—'
    return new Date(value).toLocaleString(i18n.language, {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    })
  }
  const state = (value: boolean | undefined): string =>
    value === true ? label('yes') : value === false ? label('no') : label('unknown')
  const flags = (items: Array<[string, boolean | undefined]>): React.ReactNode => (
    <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-xs text-foreground-500">
      {items.map(([name, value]) => (
        <span key={name}>
          {name}{' '}
          <span className={value === true ? 'font-medium text-warning' : ''}>{state(value)}</span>
        </span>
      ))}
    </div>
  )
  const region =
    [ip?.country ?? pc?.country ?? abuse?.countryCode, ip?.region, ip?.city]
      .filter(Boolean)
      .join(' · ') || '—'
  const organization = ip?.organization ?? ip?.company ?? pc?.provider ?? abuse?.isp ?? '—'
  const network = ip?.networkType ?? pc?.networkType ?? abuse?.usageType ?? '—'

  return (
    <section
      className="select-text overflow-y-auto text-left text-sm text-foreground"
      style={{ width: 410, maxWidth: 'calc(100vw - 32px)', maxHeight: 'min(78vh, 660px)' }}
      aria-label={label('title')}
    >
      <header className="border-b border-divider p-4">
        <div className="mb-3 flex items-center justify-between gap-2">
          <span className="flex items-center gap-2 font-semibold">
            <FiShield className="text-primary" />
            {label('title')}
          </span>
          <span className="rounded-full bg-default-100 px-2 py-1 text-[11px] text-foreground-500">
            {label('experimental')}
          </span>
        </div>
        <div className="flex items-center gap-4">
          <div
            className={`flex h-20 w-20 shrink-0 flex-col items-center justify-center rounded-2xl ${colors}`}
          >
            <span className="text-3xl font-semibold tabular-nums leading-none">{result.score}</span>
            <span className="mt-1 text-[11px]">/ 100</span>
          </div>
          <div className="min-w-0 flex-1">
            <div className="font-semibold">{limited ? label('limited') : label(level)}</div>
            <div className="mt-1 text-xs leading-relaxed text-foreground-500">
              {label('higherBetter')}
            </div>
            <div className="mt-2 text-xs text-foreground-500">
              {label('sources')} <b className="tabular-nums text-foreground">{validSources}/4</b> ·{' '}
              {label('coverage')} {explanation.coverage}%
            </div>
          </div>
        </div>
        <div className="mt-3 truncate text-xs text-foreground-500" title={result.proxy}>
          {result.proxy}
        </div>
        <div className="mt-1 break-all font-mono text-base font-medium tracking-wide">
          {result.ip}
        </div>
      </header>

      <div className="border-b border-divider bg-content2/40 px-4 py-3">
        <div className="mb-2 flex items-center gap-2 text-xs font-semibold">
          <FiGlobe />
          {label('network')}
        </div>
        <dl className="grid grid-cols-[60px_1fr] gap-x-3 gap-y-1.5 text-xs">
          <dt className="text-foreground-500">{label('location')}</dt>
          <dd className="break-words">{region}</dd>
          <dt className="text-foreground-500">ASN</dt>
          <dd className="break-words">
            {ip?.asn !== undefined ? `AS${ip.asn} · ` : ''}
            {organization}
          </dd>
          <dt className="text-foreground-500">{label('type')}</dt>
          <dd className="break-words">{network}</dd>
        </dl>
      </div>

      <div className="px-4 py-3">
        <div className="mb-2 flex justify-between text-xs font-semibold">
          <span>{label('evidence')}</span>
          <span className="font-normal text-foreground-500">{label('rawRisk')}</span>
        </div>
        <div className="space-y-2">
          {IP_PURITY_SOURCES.map((source) => {
            const value = result[source]
            const part = explanation.parts.find((item) => item.source === source)
            const status = value ? 'ok' : (result.sourceStatus?.[source] ?? 'unconfigured')
            const raw =
              source === 'abuseipdb'
                ? abuse?.abuseConfidenceScore
                : source === 'scamalytics'
                  ? result.scamalytics?.score
                  : source === 'proxycheck'
                    ? pc?.riskScore
                    : undefined
            const local = source === 'ipapi' && ip ? ipapiWeightedRisk(ip) : undefined
            return (
              <div
                key={source}
                className="rounded-xl border border-divider bg-content1 px-3 py-2.5"
                data-purity-source={source}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium">{names[source]}</span>
                  {value ? (
                    <span className="text-xs font-semibold tabular-nums">
                      {raw !== undefined ? `${raw}/100` : label('attributes')}
                    </span>
                  ) : (
                    <span className="text-xs text-foreground-500">{label(`status.${status}`)}</span>
                  )}
                </div>
                {part && (
                  <div className="mt-1 flex justify-between gap-2 text-[11px] text-foreground-500">
                    <span>
                      {label(source === 'ipapi' ? 'localRisk' : 'adjustedRisk')}{' '}
                      {part.risk.toFixed(1)}
                    </span>
                    <span>
                      {label('weight')} {(part.effectiveWeight * 100).toFixed(1)}% ·{' '}
                      {label('deduction')} {part.deduction.toFixed(1)}
                    </span>
                  </div>
                )}
                {source === 'abuseipdb' && abuse && (
                  <>
                    <div className="mt-1.5 grid grid-cols-2 gap-2 text-xs">
                      <span>
                        {label('reports')} {abuse.totalReports ?? '—'} / {abuse.maxAgeInDays}
                        {label('days')}
                      </span>
                      <span>
                        {label('reporters')} {abuse.numDistinctUsers ?? '—'}
                      </span>
                    </div>
                    <div className="mt-1 text-[11px] text-foreground-500">
                      {label('lastReport')} {date(abuse.lastReportedAt)}
                    </div>
                  </>
                )}
                {source === 'proxycheck' &&
                  pc &&
                  flags([
                    ['VPN', pc.vpn],
                    ['Proxy', pc.proxy],
                    ['Tor', pc.tor],
                    [label('hosting'), pc.hosting],
                    [label('compromised'), pc.compromised]
                  ])}
                {source === 'ipapi' && ip && (
                  <>
                    {flags([
                      [label('abuser'), ip.isAbuser],
                      ['VPN', ip.isVpn],
                      ['Proxy', ip.isProxy],
                      ['Tor', ip.isTor],
                      [label('hosting'), ip.isDatacenter]
                    ])}
                    {local === undefined && (
                      <p className="mt-1 text-[11px] text-foreground-500">
                        {label('metadataOnly')}
                      </p>
                    )}
                  </>
                )}
                {source === 'scamalytics' && result.scamalytics?.risk && (
                  <p className="mt-1 text-xs text-foreground-500">{result.scamalytics.risk}</p>
                )}
              </div>
            )
          })}
        </div>
        {(limited || explanation.disagreement || explanation.floorReasons.length > 0) && (
          <div className="mt-3 flex gap-2 rounded-lg bg-warning/10 p-2.5 text-xs leading-relaxed text-warning">
            <FiAlertCircle className="mt-0.5 shrink-0" />
            <div>
              {limited && <p>{label('limitedNote')}</p>}
              {explanation.disagreement && <p>{label('disagreement')}</p>}
              {explanation.floorReasons.length > 0 && (
                <p>
                  {label('guard')} {explanation.floorRisk}/100 (
                  {explanation.floorReasons
                    .map((source) => names[source as IpPuritySource] ?? label(source))
                    .join(', ')}
                  )
                </p>
              )}
            </div>
          </div>
        )}
      </div>

      <footer className="border-t border-divider px-4 py-3 text-[11px] leading-relaxed text-foreground-500">
        <div className="mb-1 flex items-center gap-1.5">
          <FiClock />
          {label('checkedAt')} {date(result.checkedAt)} · {label('localCache')}
        </div>
        <p>{label('disclaimer')}</p>
        <p className="mt-1">{label('refreshHint')}</p>
      </footer>
    </section>
  )
}

export default PurityDetails
