import { useEffect, useRef, useState } from 'react'
import { Alert, App as AntApp, Button, Card, Empty, Input, Select, Space, Spin, Table, Typography } from 'antd'
import type { TableColumnsType } from 'antd'
import { importMailboxes, listMailboxes, updateMailboxState } from '../admin-api'
import { ApiError } from '../api'
import type { MailboxImportItem, MailboxSummary, PoolImportReceipt } from '../types'
import { PoolImportValidationError, assertPoolImportReceiptBound, readMailboxPoolImportJson, shouldRetainPoolImportForRetry } from '../pool-import'
import { useScopedConfirm } from '../useScopedConfirm'
import { useViewActionScope } from '../useViewActionScope'
import { BooleanStateTag, MailboxHealthTag, StatusTag, compareTableText, formatLocalDateTime, mailboxHealthErrorNames } from './shared'

const { Title, Text } = Typography
const mailboxImportUnknownMessage = '原因：平台未返回可验证的邮箱池导入回执。影响：本批可能已原子导入，不能按本次错误选择新安全包或推断失败。下一步：恢复上下文已保留，请使用“同一批次核验”确认真实结果。'

function mailboxImportFailureMessage(error: unknown, retainedForRetry: boolean, fallback: string): string {
  if (error instanceof PoolImportValidationError) return error.message
  if (retainedForRetry) return mailboxImportUnknownMessage
  return error instanceof ApiError ? error.message : fallback
}

export default function MailboxesPage({ canManage }: { canManage: boolean }) {
  const { message } = AntApp.useApp()
  const confirm = useScopedConfirm()
  const beginViewAction = useViewActionScope()
  const [rows, setRows] = useState<MailboxSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [mailboxListError, setMailboxListError] = useState<string>()
  const [mailboxSearch, setMailboxSearch] = useState('')
  const [committedMailboxSearch, setCommittedMailboxSearch] = useState('')
  const [mailboxStatusFilter, setMailboxStatusFilter] = useState<MailboxSummary['status']>()
  const [mailboxHealthFilter, setMailboxHealthFilter] = useState<MailboxSummary['health_status']>()
  const [mailboxCursor, setMailboxCursor] = useState<string>()
  const [mailboxCursorHistory, setMailboxCursorHistory] = useState<string[]>([])
  const [mailboxTotalCount, setMailboxTotalCount] = useState(0)
  const [mailboxHasMore, setMailboxHasMore] = useState(false)
  const [mailboxNextCursor, setMailboxNextCursor] = useState<string>()
  const [mailboxRefresh, setMailboxRefresh] = useState(0)
  const [saving, setSaving] = useState(false)
  const mailboxImportInputRef = useRef<HTMLInputElement>(null)
  const mailboxImportPendingRef = useRef(false)
  const mailboxImportRetryRef = useRef<{
    payload: MailboxImportItem[]
    idempotencyKey: string
    contextToken: string
    receiptToken: string
  } | null>(null)
  const [mailboxImportRetryAvailable, setMailboxImportRetryAvailable] = useState(false)
  const [lastMailboxImportReceipt, setLastMailboxImportReceipt] = useState<PoolImportReceipt>()
  const [mailboxActionKey, setMailboxActionKey] = useState<string | null>(null)
  const [mailboxActionPending, setMailboxActionPending] = useState(false)
  const mailboxActionRef = useRef<{
    key: string
    mailboxId: string
    kind: 'state'
    pending: boolean
  } | null>(null)
  const mailboxActionRefreshRef = useRef<NonNullable<typeof mailboxActionRef.current> | null>(null)
  const mailboxListGenerationRef = useRef(0)

  function failClosedMailboxList() {
    setMailboxListError(
      '原因：平台未能读取邮箱连接器真实状态。'
      + '影响：旧连接器记录和所有变更入口已隐藏，活动取码会话与密钥轮换状态无法安全确认。'
      + '下一步：请重新获取真实状态；成功前不要登记、启停或轮换邮箱连接器。',
    )
  }

  function invalidateMailboxList() {
    mailboxListGenerationRef.current += 1
    setLoading(true)
    setMailboxListError(undefined)
    setRows([])
    setMailboxTotalCount(0)
    setMailboxHasMore(false)
    setMailboxNextCursor(undefined)
  }

  useEffect(() => {
    const controller = new AbortController()
    const generation = mailboxListGenerationRef.current + 1
    mailboxListGenerationRef.current = generation
    setLoading(true)
    setMailboxListError(undefined)
    setRows([])
    setMailboxTotalCount(0)
    setMailboxHasMore(false)
    setMailboxNextCursor(undefined)
    listMailboxes({
      q: committedMailboxSearch || undefined,
      status: mailboxStatusFilter,
      health_status: mailboxHealthFilter,
      cursor: mailboxCursor,
    }, controller.signal).then((page) => {
      if (mailboxListGenerationRef.current !== generation) return
      setRows(page.items)
      setMailboxTotalCount(page.total_count)
      setMailboxHasMore(page.has_more)
      setMailboxNextCursor(page.next_cursor ?? undefined)
    }).catch(() => {
      if (mailboxListGenerationRef.current === generation) failClosedMailboxList()
    }).finally(() => {
      if (mailboxListGenerationRef.current === generation) {
        setLoading(false)
        const action = mailboxActionRefreshRef.current
        if (action !== null) {
          mailboxActionRefreshRef.current = null
          releaseMailboxAction(action)
        }
      }
    })
    return () => {
      controller.abort()
      if (mailboxListGenerationRef.current === generation) {
        mailboxListGenerationRef.current += 1
      }
    }
  }, [committedMailboxSearch, mailboxCursor, mailboxHealthFilter, mailboxRefresh, mailboxStatusFilter])

  useEffect(() => {
    const normalized = mailboxSearch.trim().toLocaleLowerCase()
    if (normalized === committedMailboxSearch) return
    invalidateMailboxList()
    setMailboxCursor(undefined)
    setMailboxCursorHistory([])
    const timer = window.setTimeout(() => setCommittedMailboxSearch(normalized), 300)
    return () => window.clearTimeout(timer)
  }, [committedMailboxSearch, mailboxSearch])

  async function importMailboxFile(file: File | undefined) {
    if (!file || mailboxImportPendingRef.current || mailboxImportRetryRef.current !== null) return
    const isCurrent = beginViewAction()
    mailboxImportPendingRef.current = true
    setSaving(true)
    try {
      const bundle = await readMailboxPoolImportJson(file)
      const taskTypes = Array.from(new Set(bundle.items.map((item) => item.task_type))).sort(compareTableText)
      const confirmed = await new Promise<boolean>((resolve) => {
        let settled = false
        const settle = (value: boolean) => {
          if (settled) return
          settled = true
          resolve(value)
        }
        confirm({
          title: '确认导入邮箱池安全包？',
          content: <Space direction="vertical" size={8}>
            <Text>文件：{file.name}</Text>
            <Text>格式：安全包 v{bundle.schema_version} / 邮箱池</Text>
            <Text>脱敏资源：{bundle.items.length} 条</Text>
            <Text>服务端路由：{taskTypes.slice(0, 5).join('、')}{taskTypes.length > 5 ? ` 等 ${taskTypes.length} 个路由` : ''}</Text>
            <Text type="warning">整批原子导入：任一条校验失败时，本批 0 条入池。确认后才会发送掩码地址和路由元数据；邮箱账号、密码和收据内容不会显示。</Text>
          </Space>,
          okText: `确认导入 ${bundle.items.length} 条`,
          cancelText: '取消',
          onOk: () => settle(true),
          onCancel: () => settle(false),
          afterClose: () => settle(false),
        })
      })
      if (!confirmed || !isCurrent()) return
      const batch = {
        payload: bundle.items,
        contextToken: bundle.context_token,
        receiptToken: bundle.receipt_token,
        idempotencyKey: bundle.submission_key,
      }
      mailboxImportRetryRef.current = batch
      setMailboxImportRetryAvailable(true)
      const receipt = await importMailboxes(
        batch.payload, batch.idempotencyKey, batch.contextToken, batch.receiptToken,
      )
      if (!isCurrent()) return
      await assertPoolImportReceiptBound(
        receipt, 'mailbox', batch.payload, batch.idempotencyKey,
      )
      mailboxImportRetryRef.current = null
      setMailboxImportRetryAvailable(false)
      setLastMailboxImportReceipt(receipt)
      message.success(`已向邮箱池登记 ${receipt.imported_count} 条资源引用。`)
      await refreshMailboxRows(isCurrent, true)
    } catch (error) {
      if (!isCurrent()) return
      const retainedForRetry = mailboxImportRetryRef.current !== null && shouldRetainPoolImportForRetry(error)
      if (!retainedForRetry) {
        mailboxImportRetryRef.current = null
        setMailboxImportRetryAvailable(false)
      }
      message.error(mailboxImportFailureMessage(error, retainedForRetry, '邮箱池引用清单登记失败'))
    } finally {
      if (mailboxImportInputRef.current) mailboxImportInputRef.current.value = ''
      mailboxImportPendingRef.current = false
      if (!isCurrent()) return
      setSaving(false)
    }
  }

  function discardMailboxImportRetry() {
    mailboxImportRetryRef.current = null
    setMailboxImportRetryAvailable(false)
    message.info('已从当前页面内存清除上次邮箱池引用清单。')
  }

  async function retryMailboxImport() {
    const batch = mailboxImportRetryRef.current
    if (!batch || mailboxImportPendingRef.current) return
    const isCurrent = beginViewAction()
    mailboxImportPendingRef.current = true
    setSaving(true)
    try {
      const receipt = await importMailboxes(
        batch.payload, batch.idempotencyKey, batch.contextToken, batch.receiptToken,
      )
      if (!isCurrent()) return
      await assertPoolImportReceiptBound(
        receipt, 'mailbox', batch.payload, batch.idempotencyKey,
      )
      mailboxImportRetryRef.current = null
      setMailboxImportRetryAvailable(false)
      setLastMailboxImportReceipt(receipt)
      message.success(`已确认邮箱池引用清单，共 ${receipt.imported_count} 条资源。`)
      await refreshMailboxRows(isCurrent, true)
    } catch (error) {
      if (!isCurrent()) return
      const retainedForRetry = mailboxImportRetryRef.current !== null && shouldRetainPoolImportForRetry(error)
      if (!retainedForRetry) {
        mailboxImportRetryRef.current = null
        setMailboxImportRetryAvailable(false)
      }
      message.error(mailboxImportFailureMessage(error, retainedForRetry, '邮箱池引用清单重试失败'))
    } finally {
      mailboxImportPendingRef.current = false
      if (!isCurrent()) return
      setSaving(false)
    }
  }

  function reserveMailboxAction(kind: 'state', mailboxId: string) {
    if (mailboxActionRef.current !== null) return null
    const action = { key: `${kind}:${mailboxId}`, mailboxId, kind, pending: false }
    mailboxActionRef.current = action
    setMailboxActionKey(action.key)
    setMailboxActionPending(false)
    return action
  }

  function releaseMailboxAction(action: {
    key: string
    mailboxId: string
    kind: 'state'
    pending: boolean
  }) {
    if (mailboxActionRef.current !== action) return
    mailboxActionRef.current = null
    setMailboxActionKey(null)
    setMailboxActionPending(false)
  }

  function refreshMailboxRows(isCurrent?: () => boolean, firstPage = false) {
    if (isCurrent && !isCurrent()) return
    invalidateMailboxList()
    if (firstPage) {
      setMailboxCursor(undefined)
      setMailboxCursorHistory([])
    }
    setMailboxRefresh((value) => value + 1)
  }

  async function changeState(
    action: NonNullable<typeof mailboxActionRef.current>,
    row: MailboxSummary,
    isActive: boolean,
  ) {
    if (mailboxActionRef.current !== action || action.pending) return
    const isCurrent = beginViewAction()
    action.pending = true
    setMailboxActionPending(true)
    try {
      await updateMailboxState(row.id, isActive)
      if (!isCurrent()) return
      message.success(isActive ? '邮箱连接器已启用。' : '邮箱连接器已停用，活动会话已撤销。')
    } catch {
      if (!isCurrent()) return
      message.error(
        '原因：平台未能确认邮箱连接器状态变更结果。'
        + '影响：变更可能已经生效，页面不会按失败响应推断最终状态。'
        + '下一步：正在重新获取真实状态；完成前不要登记、启停或轮换，仅当目标状态仍未生效才从同一行重试。',
      )
    } finally {
      if (!isCurrent()) return
      mailboxActionRefreshRef.current = action
      refreshMailboxRows(isCurrent)
    }
  }

  function confirmDisableMailbox(row: MailboxSummary) {
    const action = reserveMailboxAction('state', row.id)
    if (!action) return
    confirm({
      title: `确认停用邮箱 ${row.email_masked}？`,
      content: <Space direction="vertical" size={8}>
        <Text>掩码邮箱：{row.email_masked}</Text>
        <Text>连接器 ID：{row.id}</Text>
        <Text>活动会话：{row.active_session_count}</Text>
        <Text type="danger">活动取码会话将立即撤销，尚未消费的验证码会被擦除。</Text>
      </Space>,
      okText: '停用并撤销会话',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onCancel: () => {
        if (!action.pending) releaseMailboxAction(action)
      },
      onOk: () => changeState(action, row, false),
    })
  }

  function enableMailbox(row: MailboxSummary) {
    const action = reserveMailboxAction('state', row.id)
    if (!action) return
    void changeState(action, row, true)
  }

  const unavailableRows = rows.filter((row) => row.health_status === 'unavailable')

  function resetMailboxQueryPage() {
    invalidateMailboxList()
    setMailboxCursor(undefined)
    setMailboxCursorHistory([])
  }

  function changeMailboxStatusFilter(value: MailboxSummary['status'] | undefined) {
    if (value === mailboxStatusFilter) return
    resetMailboxQueryPage()
    setMailboxStatusFilter(value)
  }

  function changeMailboxHealthFilter(value: MailboxSummary['health_status'] | undefined) {
    if (value === mailboxHealthFilter) return
    resetMailboxQueryPage()
    setMailboxHealthFilter(value)
  }

  function showNextMailboxPage() {
    if (loading || !mailboxHasMore || !mailboxNextCursor) return
    invalidateMailboxList()
    setMailboxCursorHistory((history) => [...history, mailboxCursor ?? ''])
    setMailboxCursor(mailboxNextCursor)
  }

  function showPreviousMailboxPage() {
    if (loading || mailboxCursorHistory.length === 0) return
    const previous = mailboxCursorHistory[mailboxCursorHistory.length - 1]
    invalidateMailboxList()
    setMailboxCursorHistory((history) => history.slice(0, -1))
    setMailboxCursor(previous || undefined)
  }

  const columns: TableColumnsType<MailboxSummary> = [
    { title: '邮箱资源 ID', dataIndex: 'id', render: (value: string) => <Text code copyable={{ text: value }}>{value}</Text> },
    { title: '邮箱', dataIndex: 'email_masked' },
    { title: '连接器', dataIndex: 'connector_type' },
    { title: '服务端路由键', dataIndex: 'task_type' },
    { title: '容量状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: '健康', dataIndex: 'health_status', render: (value, row) => <Space direction="vertical" size={0}>
      <MailboxHealthTag value={value} />
      {row.last_error_code ? <Text type="danger">{mailboxHealthErrorNames[row.last_error_code] ?? '连接器异常'}</Text> : null}
    </Space> },
    { title: '上次检测', dataIndex: 'last_checked_at', render: (value: string | null) => value ?? '尚未检测' },
    { title: '等待会话', dataIndex: 'active_session_count' },
    {
      title: '启用', dataIndex: 'is_active',
      render: (value: boolean) => <BooleanStateTag value={value} trueLabel="是" falseLabel="否" />,
    },
    { title: '创建时间', dataIndex: 'created_at' },
    ...(canManage ? [{ title: '操作', render: (_: unknown, row: MailboxSummary) => <Space>
      <Button
        danger={row.is_active}
        loading={mailboxActionPending && mailboxActionKey === `state:${row.id}`}
        disabled={saving || mailboxActionKey !== null}
        aria-label={`${row.is_active ? '停用' : '启用'}邮箱 ${row.email_masked}（${row.id}）`}
        onClick={() => row.is_active ? confirmDisableMailbox(row) : enableMailbox(row)}
      >{row.is_active ? '停用' : '启用'}</Button>
    </Space> }] : []),
  ]
  return <>
    <div className="page-heading"><div><Title level={2}>邮箱池管理</Title><Text type="secondary">邮箱资源独立于信用卡池管理；页面只显示连接状态与掩码地址，源邮箱账号和密码不进入浏览器。</Text></div>{canManage && !loading && !mailboxListError ? <Space>
      <input ref={mailboxImportInputRef} hidden type="file" accept=".json,application/json" onChange={(event) => { void importMailboxFile(event.currentTarget.files?.[0]) }} />
      <Button type="primary" loading={saving} disabled={mailboxActionKey !== null || mailboxImportRetryAvailable} onClick={() => mailboxImportInputRef.current?.click()}>导入邮箱池安全包 JSON</Button>
    </Space> : null}</div>
    <Alert className="section-card" type="info" showIcon message="这里只接收独立安全导入器生成的邮箱池安全包" description="邮箱账号、密码和令牌不进入浏览器或普通 API；安全包只含 m***@example.invalid 这类脱敏元数据和短期 Vault Transit 签名收据，密钥引用由服务端固定派生。单条资源也使用同一安全导入流程。" />
    {mailboxImportRetryAvailable && mailboxImportRetryRef.current ? <Alert
      className="section-card"
      type="warning"
      showIcon
      message="上次邮箱池导入结果尚未确认"
      description={<Space direction="vertical" size={4}>
        <Text>平台可能已完成导入。不要选择新安全包；请使用同一批次核验，或明确放弃当前页面内存中的恢复上下文。</Text>
        <Text>稳定提交键：</Text><Text code copyable>{mailboxImportRetryRef.current.idempotencyKey}</Text>
      </Space>}
      action={<Space wrap>
        <Button disabled={saving} onClick={() => { void retryMailboxImport() }}>使用同一批次核验邮箱池导入</Button>
        <Button disabled={saving} onClick={discardMailboxImportRetry}>明确放弃本次核验</Button>
      </Space>}
    /> : null}
    {lastMailboxImportReceipt ? <Alert
      className="section-card"
      type="success"
      showIcon
      message={`最近一次邮箱池导入已确认：${lastMailboxImportReceipt.imported_count} 条`}
      description={<Space wrap>
        <Text>平台导入回执 ID：</Text><Text code copyable>{lastMailboxImportReceipt.id}</Text>
        <Text>Trace ID：</Text><Text code copyable>{lastMailboxImportReceipt.trace_id}</Text>
        <Text>状态：{lastMailboxImportReceipt.status} / Transit key v{lastMailboxImportReceipt.key_version}</Text>
        <Text>清单摘要：</Text><Text code copyable>{lastMailboxImportReceipt.ordered_manifest_digest}</Text>
        <Text>安全收据指纹：</Text><Text code copyable>{lastMailboxImportReceipt.secure_receipt_fingerprint}</Text>
        <Text>时间：{formatLocalDateTime(lastMailboxImportReceipt.created_at)}</Text>
      </Space>}
    /> : null}
    {unavailableRows.length > 0 ? <Alert
      style={{ marginBottom: 16 }}
      type="error"
      showIcon
      message={`本页有 ${unavailableRows.length} 个邮箱连接器不可用`}
      description="取码可能延迟或失败。请检查 Mail Worker、连接器配置和密钥引用，必要时轮换密钥或停用连接器。"
    /> : null}
    <Card>{loading ? <div className="centered"><Spin /></div> : mailboxListError ? <Alert
      type="warning"
      showIcon
      message="邮箱连接器列表暂不可用"
      description={mailboxListError}
      action={<Button onClick={() => { void refreshMailboxRows() }}>重新获取邮箱连接器真实状态</Button>}
    /> : <Space direction="vertical" size={16} className="full-width">
      <Space wrap>
        <Input
          allowClear
          disabled={saving || mailboxActionKey !== null}
          aria-label="搜索邮箱池"
          placeholder="搜索掩码邮箱、连接器或服务端路由键"
          value={mailboxSearch}
          onChange={(event) => setMailboxSearch(event.currentTarget.value)}
          style={{ width: 320 }}
        />
        <Select<MailboxSummary['status']>
          allowClear
          disabled={saving || mailboxActionKey !== null}
          aria-label="按邮箱容量状态筛选"
          placeholder="全部容量状态"
          value={mailboxStatusFilter}
          options={[
            { label: '可用', value: 'available' },
            { label: '忙碌', value: 'busy' },
            { label: '已停用', value: 'disabled' },
          ]}
          onChange={changeMailboxStatusFilter}
          style={{ minWidth: 160 }}
        />
        <Select<MailboxSummary['health_status']>
          allowClear
          disabled={saving || mailboxActionKey !== null}
          aria-label="按邮箱健康状态筛选"
          placeholder="全部健康状态"
          value={mailboxHealthFilter}
          options={[
            { label: '正常', value: 'healthy' },
            { label: '异常', value: 'unavailable' },
            { label: '未检测', value: 'unknown' },
          ]}
          onChange={changeMailboxHealthFilter}
          style={{ minWidth: 160 }}
        />
        <Text type="secondary" role="status" aria-live="polite">第 {mailboxCursorHistory.length + 1} 页，显示 {rows.length} / 匹配 {mailboxTotalCount} 个邮箱</Text>
      </Space>
      <Table pagination={false} columns={columns} dataSource={rows} rowKey="id" locale={{ emptyText: <Empty description="没有符合条件的邮箱连接器" /> }} scroll={{ x: 1380 }} />
      <Space>
        <Button disabled={loading || mailboxCursorHistory.length === 0} onClick={showPreviousMailboxPage}>上一页</Button>
        <Button disabled={loading || !mailboxHasMore || !mailboxNextCursor} onClick={showNextMailboxPage}>下一页</Button>
      </Space>
    </Space>}</Card>
  </>
}
