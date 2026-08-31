import type { components } from './generated/openapi'

type ApiSchemas = components['schemas']

export type ApiErrorDetail = ApiSchemas['ApiErrorDetail']

export type Role = 'operator' | 'ops_admin' | 'security_auditor' | 'platform_admin' | 'worker_service'
export type ManagedUserRole = Exclude<Role, 'worker_service'>

export type Principal = Omit<ApiSchemas['MeResponse'], 'role'> & {
  role: Role
}

export type LoginResult = ApiSchemas['TokenResponse']

export type AuthConfig = ApiSchemas['AuthConfigResponse'] & {
  mode: 'local' | 'oidc'
  issuer: string | null
  client_id: string | null
  audience: string | null
  desktop_client_id?: string | null
}

export type DashboardSummary = ApiSchemas['DashboardSummaryResponse']

export type TaskSummary = ApiSchemas['TaskResponse']
export type TaskTimeline = ApiSchemas['TaskTimelineResponse']

export type AdminUser = ApiSchemas['AdminUserResponse']
export type AdminDevice = ApiSchemas['AdminDeviceResponse']

export type RoleChangeRequest = ApiSchemas['AdminRoleChangeResponse']

export type AuditEvent = ApiSchemas['AdminAuditResponse']

export type AuditFilters = {
  taskId?: string
  cardId?: string
  traceId?: string
  actorId?: string
  userId?: string
  deviceId?: string
  entityType?: string
  entityId?: string
  eventType?: string
  action?: string
  result?: string
  createdFrom?: string
  createdTo?: string
}

export type CardSummary = ApiSchemas['AdminCardResponse']
export type CardPage = ApiSchemas['AdminCardPageResponse']
export type CardImportItem = ApiSchemas['AdminCardImportItem']
export type CardAllocationSummary = ApiSchemas['AdminCardAllocationResponse']
export type CardEventSummary = ApiSchemas['AdminCardEventResponse']
export type CardTimeline = ApiSchemas['AdminCardTimelineResponse']
export type PoolImportReceipt = ApiSchemas['PoolImportReceiptResponse']

export type MailboxSummary = ApiSchemas['MailboxStatusResponse']
export type MailboxPage = ApiSchemas['MailboxPageResponse']
export type MailboxImportItem = ApiSchemas['AdminMailboxImportItem']

export type UploadSummary = Pick<
  ApiSchemas['AdminUploadResponse'],
  | 'id' | 'task_id' | 'business_name' | 'status' | 'phase' | 'phase_sequence'
  | 'phase_updated_at' | 'policy_version' | 'trace_id' | 'external_ref'
  | 'error_code' | 'created_at' | 'updated_at'
>

export type UploadPolicyStatus = ApiSchemas['UploadPolicyStatusResponse']
export type UploadPolicyVersion = ApiSchemas['UploadPolicyVersionResponse']
export type UploadPolicyDeployment = ApiSchemas['UploadPolicyDeploymentResponse']
export type OperationalPolicyStatus = ApiSchemas['OperationalPolicyStatusResponse']
export type OperationalPolicyDeployment = ApiSchemas['OperationalPolicyDeploymentResponse']
export type MailPolicyVersion = ApiSchemas['MailPolicyVersionResponse']
export type CardPolicyVersion = ApiSchemas['CardPolicyVersionResponse']
