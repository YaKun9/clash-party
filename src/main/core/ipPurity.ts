import axios from 'axios'
import { queryPuritySources } from './ipPurityProviders'
import { explainPurityScore, IP_PURITY_SCORE_VERSION } from '../../shared/ipPurityScore'
import { getAppConfig, getProfileConfig } from '../config'
import { createHash } from 'crypto'
import { join } from 'path'
import { dataDir } from '../utils/dirs'
import {
  IpPurityCache,
  canonicalExitIp,
  ipPurityCacheMs,
  type IpPurityRecord
} from './ipPurityCache'
import { getAxios } from './mihomoApi'
import { ensureIpPurityPort, ipPurityGroupName, IP_PURITY_CONCURRENCY } from './ipPurityRuntime'
import { IpPurityPool } from './ipPurityPool'

const EGRESS_IP_URL = 'https://api.ipify.org?format=json'
interface CheckContext {
  config: IAppConfig
  scope: string
  sourceKey: string
  ttl: number
  generation: number
}

interface PendingCheck {
  scope: string
  proxy: string
  generation: number
  promise: Promise<IProxyPurityResult>
}

const cache = new IpPurityCache(() => join(dataDir(), 'ip-purity-cache.json'))
const pendingChecks = new Map<string, PendingCheck>()
const failedChecks = new Map<string, { scope: string; proxy: string }>()
const purityPool = new IpPurityPool(IP_PURITY_CONCURRENCY)
const providerRequests = new Map<string, Promise<IpPurityRecord>>()
let cacheGeneration = 0

async function context(generation = cacheGeneration): Promise<CheckContext> {
  const [config, profile] = await Promise.all([getAppConfig(), getProfileConfig()])
  await cache.load()
  // Persist a fingerprint only, never credentials or endpoint URLs.
  // Changing providers/credentials cannot reuse the old combined score.
  const sourceKey = createHash('sha256')
    .update(
      JSON.stringify([
        config.ipPurityProxycheckApiKey ?? '',
        config.ipPurityScamalyticsEndpoint ?? '',
        config.ipPurityScamalyticsApiKey ?? '',
        config.ipPurityAbuseIPDBApiKey ?? '',
        config.ipPurityIpapiApiKey ?? '',
        IP_PURITY_SCORE_VERSION
      ])
    )
    .digest('hex')
  return {
    config,
    sourceKey,
    generation,
    scope: JSON.stringify([profile.current ?? 'default', sourceKey]),
    ttl: ipPurityCacheMs(config.ipPurityCacheHours)
  }
}

async function persistCache(): Promise<void> {
  try {
    await cache.save()
  } catch {
    // A disk error must not turn a valid API response into a network timeout.
    console.warn('IP purity result is in memory but could not be saved locally')
  }
}

async function discoverExitIp(proxy: string, slot: number): Promise<string> {
  const instance = await getAxios()
  const port = await ensureIpPurityPort(slot)

  await instance.put(`/proxies/${encodeURIComponent(ipPurityGroupName(slot))}`, { name: proxy })

  const response = await axios.get<{ ip?: string }>(EGRESS_IP_URL, {
    timeout: 10000,
    proxy: {
      protocol: 'http',
      host: '127.0.0.1',
      port
    }
  })

  const ip = response.data?.ip?.trim()
  return canonicalExitIp(ip)
}

async function performProviderQuery(ip: string, ctx: CheckContext): Promise<IpPurityRecord> {
  const details = await queryPuritySources(ip, ctx.config)
  const explanation = explainPurityScore(details)
  if (explanation.score === undefined) {
    throw new Error(
      'No IP purity provider returned a valid score: unsupported response or unavailable service'
    )
  }
  return {
    ip,
    sourceKey: ctx.sourceKey,
    checkedAt: Date.now(),
    score: explanation.score,
    ...details
  }
}

type BatchLookups = Map<string, Promise<IpPurityRecord>>

function queryProviders(
  ip: string,
  ctx: CheckContext,
  force: boolean,
  batch?: BatchLookups
): Promise<IpPurityRecord> {
  // A manual group refresh queries each IP once, including nodes that
  // start after an earlier worker has completed. Failed lookups also
  // stay deduplicated within that batch, but can be retried next time.
  const shared = batch?.get(ip)
  if (shared) return shared
  const key = `${ctx.generation}:${ctx.sourceKey}:${ip}`
  let request = providerRequests.get(key)
  if (!request) {
    const cached = !force ? cache.getIp(ip, ctx.sourceKey, ctx.ttl) : undefined
    if (cached) return Promise.resolve(cached)
    request = performProviderQuery(ip, ctx)
      .then((entry) => {
        if (ctx.generation === cacheGeneration) cache.setIp(entry)
        return entry
      })
      .finally(() => {
        if (providerRequests.get(key) === request) providerRequests.delete(key)
      })
    providerRequests.set(key, request)
  }
  batch?.set(ip, request)
  return request
}

async function checkProxyPurity(
  proxy: string,
  ctx: CheckContext,
  slot: number,
  force: boolean,
  batch?: BatchLookups
): Promise<IProxyPurityResult> {
  if (ctx.config.ipPurityEnabled === false) throw new Error('IP purity checking is disabled')
  if (ctx.generation !== cacheGeneration)
    throw new Error('IP purity cache was cleared; start a new check')
  const restored = !force ? cache.result(ctx.scope, proxy, ctx.sourceKey, ctx.ttl) : undefined
  if (restored) return restored
  // Manual refresh always re-probes: the same node name may now use a
  // different exit. Cache reads/page mounts never perform this probe.
  const ip = await discoverExitIp(proxy, slot)
  if (ctx.generation !== cacheGeneration)
    throw new Error('IP purity cache was cleared; start a new check')
  const entry = await queryProviders(ip, ctx, force, batch)
  if (ctx.generation === cacheGeneration) {
    cache.remember(ctx.scope, proxy, ip)
    await persistCache()
  }
  return {
    proxy,
    ip,
    checkedAt: entry.checkedAt,
    score: entry.score,
    scamalytics: entry.scamalytics,
    proxycheck: entry.proxycheck,
    abuseipdb: entry.abuseipdb,
    ipapi: entry.ipapi,
    sourceStatus: entry.sourceStatus
  }
}

function startCheck(
  proxy: string,
  ctx: CheckContext,
  force: boolean,
  batch?: BatchLookups
): Promise<IProxyPurityResult> {
  if (typeof proxy !== 'string' || !proxy || proxy.length > 1024) {
    return Promise.reject(new Error('Invalid node name'))
  }
  const nodeKey = cache.nodeKey(ctx.scope, proxy)
  const key = `${ctx.generation}:${nodeKey}`
  const pending = pendingChecks.get(key)
  if (pending) return pending.promise
  failedChecks.delete(nodeKey)
  const promise = purityPool
    .run((slot) => checkProxyPurity(proxy, ctx, slot, force, batch))
    .catch(async (error: unknown) => {
      if (ctx.generation === cacheGeneration) {
        cache.forget(ctx.scope, proxy)
        failedChecks.set(nodeKey, { scope: ctx.scope, proxy })
        await persistCache()
      }
      throw error
    })
    .finally(() => {
      if (pendingChecks.get(key)?.promise === promise) pendingChecks.delete(key)
    })
  pendingChecks.set(key, { scope: ctx.scope, proxy, generation: ctx.generation, promise })
  return promise
}

// IPC snapshot: local disk/memory only; no node probes or provider requests.
export async function getProxyPurityState(): Promise<{
  results: Record<string, IProxyPurityResult>
  checking: string[]
  failed: string[]
}> {
  const ctx = await context()
  if (ctx.config.ipPurityEnabled === false) return { results: {}, checking: [], failed: [] }
  return {
    results: cache.results(ctx.scope, ctx.sourceKey, ctx.ttl),
    checking: [...pendingChecks.values()]
      .filter((task) => task.scope === ctx.scope && task.generation === cacheGeneration)
      .map((task) => task.proxy),
    failed: [...failedChecks.values()]
      .filter((task) => task.scope === ctx.scope)
      .map((task) => task.proxy)
  }
}

export async function mihomoProxyPurity(proxy: string, force = false): Promise<IProxyPurityResult> {
  const ctx = await context()
  return await startCheck(proxy, ctx, force)
}

export async function mihomoGroupPurity(proxies: string[]): Promise<void> {
  if (!Array.isArray(proxies) || proxies.length > 5000) throw new Error('Invalid node batch')
  const ctx = await context()
  const batch: BatchLookups = new Map()
  await Promise.allSettled(
    [...new Set(proxies)].map((proxy) => startCheck(proxy, ctx, true, batch))
  )
}

export async function clearProxyPurityCache(): Promise<void> {
  cacheGeneration++
  failedChecks.clear()
  await cache.clear()
}
