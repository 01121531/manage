import { ApiError, api, guardCurrentSessionResponse, unwrap } from './api'
import type {
  AdminDevice,
  AdminUser,
  AuditEvent,
  AuditFilters,
  CardAllocationSummary,
  CardImportItem,
  CardPolicyVersion,
  CardSummary,
  CardTimeline,
  DashboardSummary,
  MailboxImportItem,
  MailboxSummary,
  MailPolicyVersion,
  ManagedUserRole,
  OperationalPolicyDeployment,
  OperationalPolicyStatus,
  PoolImportReceipt,
  RoleChangeRequest,
  TaskSummary,
  TaskTimeline,
  UploadPolicyDeployment,
  UploadPolicyStatus,
  UploadPolicyVersion,
  UploadSummary,
} from './types'

export const getDashboardSummary = (): Promise<DashboardSummary> =>
  unwrap(api.GET('/api/v1/dashboard/summary'))
export const listMailboxes = (): Promise<MailboxSummary[]> =>
  unwrap(api.GET('/api/v1/mailboxes'))
export type TaskListFilters = {
  status?: string
  user_id?: string
  trace_id?: string
}

export const listTasks = (filters: TaskListFilters = {}): Promise<TaskSummary[]> => {
  const query = { limit: 50, ...filters }
  return unwrap(api.GET('/api/v1/tasks', { params: { query } }))
}
export const getTaskTimeline = (taskId: string): Promise<TaskTimeline> =>
  unwrap(api.GET('/api/v1/tasks/{task_id}/timeline', {
    params: { path: { task_id: taskId } },
  }))
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
export const getCardTimeline = (
  cardId: string,
  page: { allocationsCursor?: string; eventsCursor?: string } = {},
): Promise<CardTimeline> =>
  unwrap(api.GET('/api/v1/admin/cards/{card_id}/timeline', {
    params: {
      path: { card_id: cardId },
      query: {
        allocations_cursor: page.allocationsCursor,
        events_cursor: page.eventsCursor,
      },
    },
  }))
export const recycleCardAllocation = (
  cardId: string,
  allocationId: string,
  reasonCode: string,
): Promise<CardAllocationSummary> => unwrap(api.POST(
  '/api/v1/admin/cards/{card_id}/allocations/{allocation_id}/recycle',
  {
    params: { path: { card_id: cardId, allocation_id: allocationId } },
    body: { reason_code: reasonCode },
  },
))
export const importCards = (
  payload: CardImportItem[],
  idempotencyKey: string,
  receiptToken: string,
): Promise<PoolImportReceipt> => unwrap(api.POST('/api/v1/admin/cards/imports', {
  params: { header: {
    'Idempotency-Key': idempotencyKey,
    'Secure-Import-Receipt': receiptToken,
  } },
  body: payload,
}))
export const updateCardState = (cardId: string, isActive: boolean): Promise<CardSummary> =>
  unwrap(api.PATCH('/api/v1/admin/cards/{card_id}', {
    params: { path: { card_id: cardId } },
    body: { is_active: isActive },
  }))
export const quarantineCard = (cardId: string, reasonCode: string): Promise<CardSummary> =>
  unwrap(api.POST('/api/v1/admin/cards/{card_id}/quarantine', {
    params: { path: { card_id: cardId } },
    body: { reason_code: reasonCode },
  }))
export const releaseCardQuarantine = (cardId: string): Promise<CardSummary> =>
  unwrap(api.POST('/api/v1/admin/cards/{card_id}/release-quarantine', {
    params: { path: { card_id: cardId } },
  }))
export const importMailboxes = (
  payload: MailboxImportItem[],
  idempotencyKey: string,
  receiptToken: string,
): Promise<PoolImportReceipt> => unwrap(api.POST('/api/v1/admin/mailboxes/imports', {
  params: { header: {
    'Idempotency-Key': idempotencyKey,
    'Secure-Import-Receipt': receiptToken,
  } },
  body: payload,
}))
export const updateMailboxState = (
  mailboxId: string,
  isActive: boolean,
): Promise<MailboxSummary> => unwrap(api.PATCH('/api/v1/admin/mailboxes/{mailbox_id}', {
  params: { path: { mailbox_id: mailboxId } },
  body: { is_active: isActive },
}))
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

export const getMailPolicyStatus = (): Promise<OperationalPolicyStatus> =>
  unwrap(api.GET('/api/v1/admin/policies/mail'))
export const listMailPolicyVersions = (): Promise<MailPolicyVersion[]> =>
  unwrap(api.GET('/api/v1/admin/policies/mail/versions'))
export const registerMailPolicyVersion = (
  payload: {
    version: string
    change_note: string
    session_ttl_seconds: number
    code_ttl_seconds: number
    poll_interval_seconds: number
  },
): Promise<MailPolicyVersion> => unwrap(api.POST('/api/v1/admin/policies/mail/versions', { body: payload }))
export const approveMailPolicyVersion = (policyId: string): Promise<MailPolicyVersion> =>
  unwrap(api.POST('/api/v1/admin/policies/mail/versions/{policy_id}/approve', {
    params: { path: { policy_id: policyId } },
  }))
export const deployMailPolicyVersion = (
  policyId: string,
  rolloutPercent: number,
): Promise<OperationalPolicyDeployment> => unwrap(api.POST(
  '/api/v1/admin/policies/mail/versions/{policy_id}/deploy',
  { params: { path: { policy_id: policyId } }, body: { rollout_percent: rolloutPercent } },
))
export const rollbackMailPolicy = (): Promise<OperationalPolicyDeployment> =>
  unwrap(api.POST('/api/v1/admin/policies/mail/rollback'))

export const getCardPolicyStatus = (): Promise<OperationalPolicyStatus> =>
  unwrap(api.GET('/api/v1/admin/policies/card'))
export const listCardPolicyVersions = (): Promise<CardPolicyVersion[]> =>
  unwrap(api.GET('/api/v1/admin/policies/card/versions'))
export const registerCardPolicyVersion = (
  payload: {
    version: string
    change_note: string
    lease_ttl_seconds: number
    reveal_ttl_seconds: number
    allocation_order: 'oldest_available'
    selection_rules: Array<{
      task_type: string
      pool_key: string
      region: string
      brands: string[]
      minimum_validity_days: number
      allocation_order: 'oldest_available' | 'expiry_soonest'
    }>
  },
): Promise<CardPolicyVersion> => unwrap(api.POST('/api/v1/admin/policies/card/versions', { body: payload }))
export const approveCardPolicyVersion = (policyId: string): Promise<CardPolicyVersion> =>
  unwrap(api.POST('/api/v1/admin/policies/card/versions/{policy_id}/approve', {
    params: { path: { policy_id: policyId } },
  }))
export const deployCardPolicyVersion = (
  policyId: string,
  rolloutPercent: number,
): Promise<OperationalPolicyDeployment> => unwrap(api.POST(
  '/api/v1/admin/policies/card/versions/{policy_id}/deploy',
  { params: { path: { policy_id: policyId } }, body: { rollout_percent: rolloutPercent } },
))
export const rollbackCardPolicy = (): Promise<OperationalPolicyDeployment> =>
  unwrap(api.POST('/api/v1/admin/policies/card/rollback'))

const auditQuery = (filters?: AuditFilters) => ({
  task_id: filters?.taskId?.trim() || undefined,
  card_id: filters?.cardId?.trim() || undefined,
  trace_id: filters?.traceId?.trim() || undefined,
  actor_id: filters?.actorId?.trim() || undefined,
  user_id: filters?.userId?.trim() || undefined,
  device_id: filters?.deviceId?.trim() || undefined,
  entity_type: filters?.entityType?.trim() || undefined,
  entity_id: filters?.entityId?.trim() || undefined,
  event_type: filters?.eventType?.trim() || undefined,
  action: filters?.action?.trim() || undefined,
  result: filters?.result?.trim() || undefined,
  created_from: filters?.createdFrom?.trim() || undefined,
  created_to: filters?.createdTo?.trim() || undefined,
})

export const listAuditEvents = (filters?: AuditFilters): Promise<AuditEvent[]> =>
  unwrap(api.GET('/api/v1/admin/audit', {
    params: {
      query: {
        ...auditQuery(filters),
        limit: 200,
      },
    },
  }))

export async function downloadAuditEvents(filters?: AuditFilters): Promise<void> {
  const { data, error, response } = await guardCurrentSessionResponse(api.GET(
    '/api/v1/admin/audit/export',
    {
      params: { query: { ...auditQuery(filters), limit: 5000 } },
      headers: { Accept: 'text/csv' },
      cache: 'no-store',
      parseAs: 'text',
    },
  ))
  if (!response.ok) {
    await unwrap(Promise.resolve({ data: undefined, error, response }))
    return
  }
  if (typeof data !== 'string' || !response.headers.get('Content-Type')?.toLowerCase().startsWith('text/csv')) {
    throw new ApiError('审计导出响应格式异常，请稍后重试。', response.status)
  }

  const blob = new Blob([data], { type: 'text/csv;charset=utf-8' })
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = objectUrl
  link.download = `audit-redacted-${new Date().toISOString().replaceAll(':', '-')}.csv`
  link.hidden = true
  document.body.appendChild(link)
  try {
    link.click()
  } finally {
    link.remove()
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0)
  }
}

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

export const batchDisableUsers = (userIds: string[]): Promise<AdminUser[]> =>
  unwrap(api.POST('/api/v1/admin/users/batch-disable', {
    body: { user_ids: userIds },
  }))

export const createRoleChangeRequest = (
  userId: string,
  role: ManagedUserRole,
): Promise<RoleChangeRequest> => unwrap(api.POST('/api/v1/admin/users/{user_id}/role-change-requests', {
  params: { path: { user_id: userId } },
  body: { role },
}))

export const listRoleChangeRequests = (): Promise<RoleChangeRequest[]> =>
  unwrap(api.GET('/api/v1/admin/role-change-requests', {
    params: { query: { status: 'pending' } },
  }))

export const approveRoleChangeRequest = (
  requestId: string,
): Promise<RoleChangeRequest> => unwrap(api.POST(
  '/api/v1/admin/role-change-requests/{role_change_id}/approve',
  { params: { path: { role_change_id: requestId } } },
))
