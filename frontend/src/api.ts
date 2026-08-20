import createClient, { type Middleware } from 'openapi-fetch'
import type { paths } from './generated/openapi'
import type {
  AdminUser,
  AdminDevice,
  AuditEvent,
  AuthConfig,
  CardCreate,
  CardSummary,
  DashboardSummary,
  LoginResult,
  MailboxSummary,
  MailboxCreate,
  Principal,
  Role,
  TaskSummary,
  UploadPolicyStatus,
  UploadPolicyDeployment,
  UploadPolicyVersion,
  UploadSummary,
} from './types'

const configuredBase = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, '') ?? ''
const API_ORIGIN = configuredBase.endsWith('/api/v1')
  ? configuredBase.slice(0, -'/api/v1'.length)
  : configuredBase
const api = createClient<paths>({ baseUrl: API_ORIGIN })
let bearer: string | null = null
let expiryTimer: number | undefined

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
  bearer = null
  if (expiryTimer !== undefined) window.clearTimeout(expiryTimer)
  expiryTimer = undefined
}

export function setBearer(value: string, expiresIn?: number) {
  bearer = value
  if (expiryTimer !== undefined) window.clearTimeout(expiryTimer)
  if (expiresIn && expiresIn > 0) {
    expiryTimer = window.setTimeout(() => {
      clearSession()
      window.dispatchEvent(new Event('platform:auth-expired'))
    }, expiresIn * 1000)
  }
}

const authMiddleware: Middleware = {
  onRequest({ request }) {
    request.headers.set('Accept', 'application/json')
    if (bearer) request.headers.set('Authorization', `Bearer ${bearer}`)
    return request
  },
}
api.use(authMiddleware)

type ClientResult<T> = {
  data?: T
  error?: unknown
  response: Response
}

function errorEnvelope(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object') return {}
  const record = value as Record<string, unknown>
  const nested = record.error
  return nested && typeof nested === 'object'
    ? nested as Record<string, unknown>
    : record
}

async function unwrap<T>(operation: Promise<ClientResult<T>>): Promise<T> {
  const { data, error, response } = await operation
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
  if (response.status === 401) {
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

export const getDashboardSummary = (): Promise<DashboardSummary> =>
  unwrap(api.GET('/api/v1/dashboard/summary'))
export const listMailboxes = (): Promise<MailboxSummary[]> =>
  unwrap(api.GET('/api/v1/mailboxes'))
export const listTasks = (): Promise<TaskSummary[]> =>
  unwrap(api.GET('/api/v1/tasks', { params: { query: { limit: 50 } } }))
export const closeTask = (taskId: string): Promise<TaskSummary> =>
  unwrap(api.POST('/api/v1/tasks/{task_id}/close', {
    params: { path: { task_id: taskId } },
  }))
export const listUsers = (): Promise<AdminUser[]> =>
  unwrap(api.GET('/api/v1/admin/users'))
export const listDevices = (): Promise<AdminDevice[]> =>
  unwrap(api.GET('/api/v1/admin/devices'))
export const revokeDevice = (deviceId: string): Promise<AdminDevice> =>
  unwrap(api.POST('/api/v1/admin/devices/{device_id}/revoke', {
    params: { path: { device_id: deviceId } },
  }))
export const listCards = (): Promise<CardSummary[]> =>
  unwrap(api.GET('/api/v1/admin/cards'))
export const createCard = (payload: CardCreate): Promise<CardSummary> =>
  unwrap(api.POST('/api/v1/admin/cards', { body: payload }))
export const updateCardState = (cardId: string, isActive: boolean): Promise<CardSummary> =>
  unwrap(api.PATCH('/api/v1/admin/cards/{card_id}', {
    params: { path: { card_id: cardId } },
    body: { is_active: isActive },
  }))
export const createMailbox = (payload: MailboxCreate): Promise<MailboxSummary> =>
  unwrap(api.POST('/api/v1/admin/mailboxes', { body: payload }))
export const updateMailboxState = (
  mailboxId: string,
  isActive: boolean,
): Promise<MailboxSummary> => unwrap(api.PATCH('/api/v1/admin/mailboxes/{mailbox_id}', {
  params: { path: { mailbox_id: mailboxId } },
  body: { is_active: isActive },
}))
export const rotateMailboxSecret = (
  mailboxId: string,
  secretRef: string,
): Promise<MailboxSummary> => unwrap(api.POST(
  '/api/v1/admin/mailboxes/{mailbox_id}/secret-rotations',
  {
    params: { path: { mailbox_id: mailboxId } },
    body: { secret_ref: secretRef },
  },
))
export const listUploads = (): Promise<UploadSummary[]> =>
  unwrap(api.GET('/api/v1/admin/uploads'))
export const getUploadPolicyStatus = (): Promise<UploadPolicyStatus> =>
  unwrap(api.GET('/api/v1/admin/policies/upload'))
export const listUploadPolicyVersions = (): Promise<UploadPolicyVersion[]> =>
  unwrap(api.GET('/api/v1/admin/policies/upload/versions'))
export const registerUploadPolicyVersion = (
  payload: { version: string; change_note: string },
): Promise<UploadPolicyVersion> => unwrap(api.POST('/api/v1/admin/policies/upload/versions', {
  body: payload,
}))
export const approveUploadPolicyVersion = (policyId: string): Promise<UploadPolicyVersion> =>
  unwrap(api.POST('/api/v1/admin/policies/upload/versions/{policy_id}/approve', {
    params: { path: { policy_id: policyId } },
  }))
export const deployUploadPolicyVersion = (
  policyId: string,
  rolloutPercent: number,
): Promise<UploadPolicyDeployment> => unwrap(api.POST(
  '/api/v1/admin/policies/upload/versions/{policy_id}/deploy',
  {
    params: { path: { policy_id: policyId } },
    body: { rollout_percent: rolloutPercent },
  },
))
export const rollbackUploadPolicy = (): Promise<UploadPolicyDeployment> =>
  unwrap(api.POST('/api/v1/admin/policies/upload/rollback'))

export const listAuditEvents = (filters?: {
  traceId?: string
  userId?: string
  entityId?: string
  eventType?: string
}): Promise<AuditEvent[]> => unwrap(api.GET('/api/v1/admin/audit', {
  params: {
    query: {
      trace_id: filters?.traceId?.trim() || undefined,
      user_id: filters?.userId?.trim() || undefined,
      entity_id: filters?.entityId?.trim() || undefined,
      event_type: filters?.eventType?.trim() || undefined,
      limit: 200,
    },
  },
}))

export const cancelUploadJob = (jobId: string): Promise<UploadSummary> =>
  unwrap(api.POST('/api/v1/upload-jobs/{job_id}/cancel', {
    params: { path: { job_id: jobId } },
  }))

export const reconcileUploadJob = (
  jobId: string,
  payload: { status: 'succeeded' | 'failed' | 'unknown'; external_ref?: string; error_code?: string },
): Promise<UploadSummary> => unwrap(api.POST('/api/v1/upload-jobs/{job_id}/reconcile', {
  params: { path: { job_id: jobId } },
  body: payload,
}))

export const disableUser = (userId: string): Promise<AdminUser> =>
  unwrap(api.POST('/api/v1/admin/users/{user_id}/disable', {
    params: { path: { user_id: userId } },
  }))
