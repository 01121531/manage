import { useEffect, useState } from 'react'
import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  ExclamationCircleOutlined,
  LoadingOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { Alert, Button, Card, Empty, Spin, Table, Tag, Typography } from 'antd'
import type { TableColumnsType } from 'antd'
import type { CardSummary, MailboxSummary, ManagedUserRole } from '../types'

const { Title, Text } = Typography

export const roleNames: Record<string, string> = {
  operator: '操作员',
  ops_admin: '运营管理员',
  security_auditor: '安全审计员',
  platform_admin: '平台管理员',
  worker_service: '后台服务',
}

export const managedUserRoles: ManagedUserRole[] = [
  'operator', 'ops_admin', 'security_auditor', 'platform_admin',
]

const statusColor: Record<string, string> = {
  active: 'green', available: 'green', succeeded: 'green', success: 'green', enabled: 'green',
  queued: 'blue', running: 'processing', allocated: 'orange', unknown: 'gold',
  initializing: 'processing', waiting: 'processing', code_ready: 'green', consumed: 'green',
  busy: 'processing', ready: 'green', not_configured: 'gold',
  draft: 'default', approved: 'blue', retired: 'default',
  disabled: 'red', failed: 'red', error: 'red', denied: 'red', revoked: 'red', cancelled: 'red', expired: 'default',
  created: 'processing', closed: 'default', completed: 'green', released: 'default',
}

export const terminalTaskStatuses = new Set(['closed', 'expired', 'cancelled', 'completed'])

export function StatusTag({ value }: { value: string }) {
  const icon = ['active', 'available', 'succeeded', 'success', 'enabled', 'code_ready', 'consumed', 'ready', 'completed'].includes(value) ? <CheckCircleOutlined />
    : ['running', 'queued', 'initializing', 'waiting', 'busy', 'created', 'allocated'].includes(value) ? <LoadingOutlined />
      : ['failed', 'error', 'denied', 'unknown', 'revoked', 'cancelled', 'disabled'].includes(value) ? <ExclamationCircleOutlined /> : <ClockCircleOutlined />
  return <Tag icon={icon} color={statusColor[value] ?? 'default'}>{value}</Tag>
}

export function CardStatusTag({ value }: { value: CardSummary['status'] }) {
  const presentation = {
    available: { color: 'green', icon: <CheckCircleOutlined />, label: '可用' },
    allocated: { color: 'orange', icon: <ClockCircleOutlined />, label: '已分配' },
    disabled: { color: 'red', icon: <ExclamationCircleOutlined />, label: '已停用' },
    quarantined: { color: 'magenta', icon: <SafetyCertificateOutlined />, label: '已隔离' },
  }[value]
  return <Tag color={presentation.color} icon={presentation.icon}>{presentation.label}</Tag>
}

export const cardQuarantineReasonNames: Record<string, string> = {
  suspected_compromise: '疑似信息泄露',
  provider_dispute: '提供方争议',
  invalid_card: '卡资源失效',
  compliance_review: '合规复核',
}

export const cardAllocationReasonNames: Record<string, string> = {
  task_assigned: '任务自动分配',
  manual_reassignment: '人工重新分配',
  operator_request: '业务方请求',
  duplicate_allocation: '重复租约',
  incident_response: '事件处置',
  user_released: '用户主动释放',
  task_completed: '任务完成',
  task_closed: '任务关闭',
  lease_expired: '租约到期',
  admin_card_disabled: '卡资源停用',
  card_quarantined: '卡资源隔离',
}

export const cardEventActionNames: Record<string, string> = {
  'card.created': '卡资源已登记',
  'card.enabled': '卡资源已启用',
  'card.disabled': '卡资源已停用',
  'card.quarantined': '卡资源已隔离',
  'card.quarantine_released': '隔离已解除',
  'card.revealed': '敏感字段已揭示',
  'allocation.allocated': '租约已分配',
  'allocation.released': '租约已释放',
  'allocation.expired': '租约已到期',
}

export function maskedStateLabel(state: Record<string, unknown>): string {
  const cardStatus = typeof state.card_status === 'string'
    ? state.card_status
    : typeof state.status === 'string'
      ? state.status
      : undefined
  const allocationStatus = typeof state.allocation_status === 'string'
    ? state.allocation_status
    : undefined
  return [cardStatus, allocationStatus].filter(Boolean).join(' / ') || '—'
}

export function MailboxHealthTag({ value }: { value: MailboxSummary['health_status'] }) {
  if (value === 'healthy') {
    return <Tag icon={<CheckCircleOutlined />} color="green">正常</Tag>
  }
  if (value === 'unavailable') {
    return <Tag icon={<ExclamationCircleOutlined />} color="red">异常</Tag>
  }
  return <Tag icon={<ClockCircleOutlined />} color="gold">未检测</Tag>
}

export function SemanticStateTag({ tone, label }: { tone: 'positive' | 'negative' | 'pending'; label: string }) {
  if (tone === 'positive') return <Tag icon={<CheckCircleOutlined />} color="green">{label}</Tag>
  if (tone === 'negative') return <Tag icon={<ExclamationCircleOutlined />} color="red">{label}</Tag>
  return <Tag icon={<ClockCircleOutlined />} color="gold">{label}</Tag>
}

export function BooleanStateTag({ value, trueLabel, falseLabel }: {
  value: boolean
  trueLabel: string
  falseLabel: string
}) {
  return <SemanticStateTag tone={value ? 'positive' : 'negative'} label={value ? trueLabel : falseLabel} />
}

export function formatLocalDateTime(value: string): string {
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

export function compareTableText(left: unknown, right: unknown): number {
  return String(left ?? '').localeCompare(String(right ?? ''), 'zh-CN')
}

export function compareTableDate(left: string | null | undefined, right: string | null | undefined): number {
  const leftTime = left ? Date.parse(left) : 0
  const rightTime = right ? Date.parse(right) : 0
  return leftTime - rightTime
}

export const mailboxHealthErrorNames: Record<string, string> = {
  connector_not_configured: '连接器未配置',
  connector_unavailable: '连接器不可用',
}
export function statusRows(values: Record<string, number>) {
  return Object.entries(values).map(([status, count]) => ({ status, count }))
}

export const taskEventNames: Record<string, string> = {
  'task.created': '任务已创建',
  'task.closed': '任务已关闭',
  'task.expired': '任务已过期',
  'mail_session.created': '邮箱会话已绑定',
  'mail_session.watermark_initialized': '邮箱水位已初始化',
  'mail_session.code_ready': '验证码已到达',
  'mail_session.code_consumed': '验证码已安全获取',
  'mail_session.revoked': '邮箱会话已撤销',
  'card.allocated': '卡已分配',
  'card.released': '卡租约已释放',
  'card.revealed': '卡号已临时揭示',
  'upload.queued': '上传已排队',
  'upload.preflight_started': '上传预检已开始',
  'upload.provider_submit_started': '已到达外部提交边界',
  'upload.provider_result_received': '已收到外部明确结果',
  'upload.reconciliation_started': '外部结果核对已开始',
  'upload.reconciliation_result_received': '已收到核对结果',
  'upload.succeeded': '上传已完成',
  'upload.failed': '上传失败',
  'upload.unknown': '上传结果待人工核对',
  'upload.cancelled': '上传已取消',
}

export const uploadPhaseNames: Record<string, string> = {
  queued: '等待处理',
  worker_preflight: '服务端预检',
  provider_submit: '外部提交',
  provider_result: '外部结果已返回',
  reconciliation_check: '人工核对中',
  reconciliation_result: '核对结果已确认',
  legacy_unclassified: '历史阶段未分类',
}


export function PageHeading({ title, description }: { title: string; description: string }) {
  return <div className="page-heading"><div><Title level={2}>{title}</Title><Text type="secondary">{description}</Text></div></div>
}

export function PlaceholderPage({ title, description, notice }: { title: string; description: string; notice: string }) {
  return <><PageHeading title={title} description={description} /><Card><Empty description={notice} /></Card></>
}

export function RemoteTable<T extends object>({ loader, columns, empty }: {
  loader: () => Promise<T[]>
  columns: TableColumnsType<T>
  empty: string
}) {
  const [rows, setRows] = useState<T[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [retryGeneration, setRetryGeneration] = useState(0)
  useEffect(() => {
    let alive = true
    setLoading(true)
    setError(undefined)
    loader().then((items) => { if (alive) setRows(items) }).catch((reason) => {
      if (alive) setError(reason instanceof Error ? reason.message : '读取失败')
    }).finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [loader, retryGeneration])
  if (loading) return <div className="centered"><Spin /></div>
  if (error) return <Alert
    type="warning"
    showIcon
    message="数据暂不可用"
    description={`原因：${error}；影响：当前列表未加载；下一步：检查网络后重新加载数据。`}
    action={<Button onClick={() => setRetryGeneration((value) => value + 1)}>重新加载数据</Button>}
  />
  return <Table columns={columns} dataSource={rows} rowKey={(row) => String((row as { id: string }).id)} locale={{ emptyText: <Empty description={empty} /> }} scroll={{ x: 760 }} />
}
