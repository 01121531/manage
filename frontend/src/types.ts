import type { components } from './generated/openapi'

type ApiSchemas = components['schemas']

export type Role = 'operator' | 'ops_admin' | 'security_auditor' | 'platform_admin' | 'worker_service'

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

export type AdminUser = ApiSchemas['AdminUserResponse']
export type AdminDevice = ApiSchemas['AdminDeviceResponse']

export type AuditEvent = ApiSchemas['AdminAuditResponse']

export type CardSummary = ApiSchemas['AdminCardResponse']
export type CardCreate = ApiSchemas['AdminCardCreate']

export type MailboxSummary = ApiSchemas['MailboxStatusResponse']
export type MailboxCreate = ApiSchemas['AdminMailboxCreate']

export type UploadSummary = Pick<
  ApiSchemas['AdminUploadResponse'],
  'id' | 'task_id' | 'business_name' | 'status' | 'policy_version' | 'created_at'
>

export type UploadPolicyStatus = ApiSchemas['UploadPolicyStatusResponse']
export type UploadPolicyVersion = ApiSchemas['UploadPolicyVersionResponse']
export type UploadPolicyDeployment = ApiSchemas['UploadPolicyDeploymentResponse']
