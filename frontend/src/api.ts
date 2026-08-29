import createClient, { type Middleware } from 'openapi-fetch'
import type { paths } from './generated/openapi'
import type {
  AdminDevice,
  ApiErrorDetail,
  AuthConfig,
  LoginResult,
  Principal,
  Role,
} from './types'

const configuredBase = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, '') ?? ''
const API_ORIGIN = configuredBase.endsWith('/api/v1')
  ? configuredBase.slice(0, -'/api/v1'.length)
  : configuredBase
export const api = createClient<paths>({ baseUrl: API_ORIGIN })
let bearer: string | null = null
let expiryTimer: number | undefined
let expiryCleanupTimer: number | undefined
let bearerExpiresAt: number | null = null
let sessionGeneration = 0
let logoutRequest: {
  generation: number
  promise: Promise<{ status: 'logged_out' }>
} | null = null
const SESSION_EXIT_BARRIER_MESSAGE = '原因：安全退出或锁定正在进行；影响：新的平台请求已停止；下一步：请等待当前操作完成后再继续。'
const STALE_SESSION_RESPONSE_MESSAGE = '原因：登录会话已变化；影响：旧会话的迟到响应已丢弃，不会用于当前页面；下一步：请在当前会话重新执行操作。'

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly traceId?: string,
    readonly code?: string,
    readonly recoveryHint?: string,
  ) {
    super(message)
  }
}

export function clearSession() {
  sessionGeneration += 1
  bearer = null
  bearerExpiresAt = null
  if (expiryTimer !== undefined) window.clearTimeout(expiryTimer)
  if (expiryCleanupTimer !== undefined) window.clearTimeout(expiryCleanupTimer)
  expiryTimer = undefined
  expiryCleanupTimer = undefined
}

export function setBearer(value: string, expiresIn?: number) {
  sessionGeneration += 1
  bearer = value
  bearerExpiresAt = expiresIn && expiresIn > 0
    ? Date.now() + expiresIn * 1000
    : null
  if (expiryTimer !== undefined) window.clearTimeout(expiryTimer)
  if (expiryCleanupTimer !== undefined) window.clearTimeout(expiryCleanupTimer)
  expiryTimer = undefined
  expiryCleanupTimer = undefined
  if (expiresIn && expiresIn > 0) {
    const ttlMs = expiresIn * 1000
    const cleanupLeadMs = Math.min(30_000, Math.max(250, Math.floor(ttlMs * 0.2)))
    const cleanupDelayMs = ttlMs - cleanupLeadMs
    if (cleanupDelayMs >= 250) {
      expiryCleanupTimer = window.setTimeout(() => {
        expiryCleanupTimer = undefined
        window.dispatchEvent(new Event('platform:auth-expiring'))
      }, cleanupDelayMs)
    }
    expiryTimer = window.setTimeout(() => {
      clearSession()
      window.dispatchEvent(new Event('platform:auth-expired'))
    }, ttlMs)
  }
}

export function getSessionRemainingSeconds(): number | null {
  if (bearerExpiresAt === null) return null
  return Math.max(0, Math.ceil((bearerExpiresAt - Date.now()) / 1000))
}

const authMiddleware: Middleware = {
  onRequest({ request }) {
    if (
      logoutRequest?.generation === sessionGeneration
      && new URL(request.url).pathname !== '/api/v1/auth/logout'
    ) {
      throw new ApiError(
        SESSION_EXIT_BARRIER_MESSAGE,
        409,
        undefined,
        'session_exit_pending',
      )
    }
    if (!request.headers.has('Accept')) request.headers.set('Accept', 'application/json')
    if (bearer) request.headers.set('Authorization', `Bearer ${bearer}`)
    return request
  },
}
api.use(authMiddleware)

export type ClientResult<T> = {
  data?: T
  error?: unknown
  response: Response
}

function errorEnvelope(value: unknown): Partial<ApiErrorDetail> {
  if (!value || typeof value !== 'object') return {}
  const record = value as Record<string, unknown>
  const nested = record.error
  const candidate = nested && typeof nested === 'object'
    ? nested as Record<string, unknown>
    : record
  return {
    code: typeof candidate.code === 'string' ? candidate.code : undefined,
    message: typeof candidate.message === 'string' ? candidate.message : undefined,
    recovery_hint: typeof candidate.recovery_hint === 'string' ? candidate.recovery_hint : undefined,
    trace_id: typeof candidate.trace_id === 'string' ? candidate.trace_id : undefined,
    details: candidate.details,
  }
}

function assertCurrentSessionGeneration(operationGeneration: number): void {
  if (operationGeneration !== sessionGeneration) {
    throw new ApiError(
      STALE_SESSION_RESPONSE_MESSAGE,
      409,
      undefined,
      'stale_session_response',
    )
  }
}

export async function unwrap<T>(
  operation: Promise<ClientResult<T>>,
  allowStaleSuccess = false,
): Promise<T> {
  const operationGeneration = sessionGeneration
  const { data, error, response } = await operation
  if (!allowStaleSuccess || !response.ok) {
    assertCurrentSessionGeneration(operationGeneration)
  }
  if (response.ok && data !== undefined) return data
  const envelope = errorEnvelope(error)
  const code = typeof envelope.code === 'string' ? envelope.code : undefined
  const safeMessages: Record<string, string> = {
    unauthorized: '登录已失效，请重新登录。',
    forbidden: '当前账号无权执行此操作。',
    not_found: '资源不存在或已被回收。',
    conflict: '当前资源状态已变化，请刷新后继续。',
    service_unavailable: '平台依赖暂不可用，请稍后重试。',
    validation_error: '请求字段不符合要求，请检查后重试。',
  }
  if (response.status === 401 && operationGeneration === sessionGeneration) {
    clearSession()
    window.dispatchEvent(new Event('platform:auth-expired'))
  }
  throw new ApiError(
    safeMessages[code ?? ''] ?? '请求未完成，请稍后重试。',
    response.status,
    response.headers.get('X-Trace-Id') ?? (
      typeof envelope.trace_id === 'string' ? envelope.trace_id : undefined
    ),
    code,
    typeof envelope.recovery_hint === 'string' ? envelope.recovery_hint : undefined,
  )
}

export async function guardCurrentSessionResponse<T>(
  operation: Promise<ClientResult<T>>,
): Promise<ClientResult<T>> {
  const operationGeneration = sessionGeneration
  const result = await operation
  assertCurrentSessionGeneration(operationGeneration)
  return result
}

const roles = new Set<Role>([
  'operator',
  'ops_admin',
  'security_auditor',
  'platform_admin',
  'worker_service',
])

export async function login(values: {
  tenant_id: string
  email: string
  password: string
  device_id: string
}): Promise<LoginResult> {
  const result = await unwrap(api.POST('/api/v1/auth/login', { body: values }))
  setBearer(result.access_token, result.expires_in)
  return result
}

export async function getAuthConfig(): Promise<AuthConfig> {
  const result = await unwrap(api.GET('/api/v1/auth/config'))
  if (result.mode !== 'local' && result.mode !== 'oidc') {
    throw new ApiError('平台身份配置无效。', 500)
  }
  return {
    ...result,
    mode: result.mode,
    issuer: result.issuer ?? null,
    client_id: result.client_id ?? null,
    audience: result.audience ?? null,
    desktop_client_id: result.desktop_client_id ?? null,
  }
}

export async function getMe(): Promise<Principal> {
  const result = await unwrap(api.GET('/api/v1/me'))
  if (!roles.has(result.role as Role)) {
    throw new ApiError('平台返回了未知角色。', 500)
  }
  return { ...result, role: result.role as Role }
}

export function logoutSession(): Promise<{ status: 'logged_out' }> {
  const requestGeneration = sessionGeneration
  if (logoutRequest?.generation === requestGeneration) return logoutRequest.promise

  const request = (async () => {
    if (!bearer) throw new ApiError('登录已失效，请重新登录。', 401)
    try {
      const result = await unwrap(api.POST('/api/v1/auth/logout', {
        cache: 'no-store',
      }), true)
      if (result.status !== 'logged_out') {
        throw new ApiError('平台安全退出响应无效。', 502)
      }
      return { status: 'logged_out' as const }
    } catch (error) {
      if (!(error instanceof ApiError)) {
        throw new ApiError('无法连接平台完成安全退出。', 0)
      }
      throw new ApiError(
        error.code === 'service_unavailable'
          ? '平台依赖暂不可用，安全退出未确认。'
          : '平台尚未确认安全退出。',
        error.status,
        error.traceId,
        error.code,
        error.recoveryHint,
      )
    }
  })()

  const trackedRequest = request.finally(() => {
    if (logoutRequest?.promise === trackedRequest) logoutRequest = null
  })
  logoutRequest = { generation: requestGeneration, promise: trackedRequest }
  return trackedRequest
}

export const revokeCurrentDevice = (deviceId: string): Promise<AdminDevice> =>
  unwrap(api.POST('/api/v1/devices/{device_id}/revoke', {
    params: { path: { device_id: deviceId } },
    cache: 'no-store',
  }))
