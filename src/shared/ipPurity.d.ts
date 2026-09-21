type IpPuritySource = 'abuseipdb' | 'scamalytics' | 'proxycheck' | 'ipapi'
type IpPuritySourceStatus =
  'ok' | 'unconfigured' | 'timeout' | 'rate_limited' | 'unauthorized' | 'invalid' | 'error'

interface IProxyPurityProviderAbuseIPDB {
  abuseConfidenceScore: number
  totalReports?: number
  numDistinctUsers?: number
  lastReportedAt?: string
  maxAgeInDays: number
  usageType?: string
  isp?: string
  countryCode?: string
  isTor?: boolean
}

interface IProxyPurityProviderIpapi {
  isAbuser?: boolean
  isDatacenter?: boolean
  isVpn?: boolean
  isProxy?: boolean
  isTor?: boolean
  isMobile?: boolean
  asn?: number
  organization?: string
  company?: string
  networkType?: string
  country?: string
  countryCode?: string
  region?: string
  city?: string
}

interface IpPurityDetails {
  scamalytics?: IProxyPurityProviderScamalytics
  proxycheck?: IProxyPurityProviderProxyCheck
  abuseipdb?: IProxyPurityProviderAbuseIPDB
  ipapi?: IProxyPurityProviderIpapi
  sourceStatus?: Partial<Record<IpPuritySource, IpPuritySourceStatus>>
}

interface IProxyPurityResult extends IpPurityDetails {}

interface IAppConfig {
  ipPurityAbuseIPDBApiKey?: string
  ipPurityIpapiApiKey?: string
}
