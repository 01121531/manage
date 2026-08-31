import { useEffect, useMemo, useRef, useState } from 'react'
import { Alert, App as AntApp, Button, Card, Empty, Input, Select, Space, Spin, Table, Typography } from 'antd'
import type { TableColumnsType } from 'antd'
import { importMailboxes, listMailboxes, updateMailboxState } from '../admin-api'
import type { MailboxImportItem, MailboxSummary, PoolImportReceipt } from '../types'
import { readMailboxPoolImportJson, shouldRetainPoolImportForRetry } from '../pool-import'
import { useScopedConfirm } from '../useScopedConfirm'
import { useViewActionScope } from '../useViewActionScope'
import { BooleanStateTag, MailboxHealthTag, StatusTag, compareTableDate, compareTableText, formatLocalDateTime, mailboxHealthErrorNames } from './shared'

const { Title, Text } = Typography

export default function MailboxesPage({ canManage }: { canManage: boolean }) {
  const { message } = AntApp.useApp()
  const confirm = useScopedConfirm()
  const beginViewAction = useViewActionScope()
  const [rows, setRows] = useState<MailboxSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [mailboxListError, setMailboxListError] = useState<string>()
  const [mailboxSearch, setMailboxSearch] = useState('')
  const [mailboxStatusFilter, setMailboxStatusFilter] = useState<MailboxSummary['status']>()
  const [mailboxHealthFilter, setMailboxHealthFilter] = useState<MailboxSummary['health_status']>()
  const [saving, setSaving] = useState(false)
  const mailboxImportInputRef = useRef<HTMLInputElement>(null)
  const mailboxImportPendingRef = useRef(false)
  const mailboxImportRetryRef = useRef<{
    payload: MailboxImportItem[]
    idempotencyKey: string
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
  const mailboxListGenerationRef = useRef(0)
  const mailboxListPendingRef = useRef(false)

  function failClosedMailboxList() {
    setMailboxListError(
      '原因：平台未能读取邮箱连接器真实状态。'
      + '影响：旧连接器记录和所有变更入口已隐藏，活动取码会话与密钥轮换状态无法安全确认。'
      + '下一步：请重新获取真实状态；成功前不要登记、启停或轮换邮箱连接器。',
    )
  }

  useEffect(() => {
    let alive = true
    const generation = mailboxListGenerationRef.current + 1
    mailboxListGenerationRef.current = generation
    setLoading(true)
    setMailboxListError(undefined)
    setRows([])
    listMailboxes().then((items) => {
      if (alive && mailboxListGenerationRef.current === generation) setRows(items)
    }).catch(() => {
      if (alive && mailboxListGenerationRef.current === generation) failClosedMailboxList()
    }).finally(() => {
      if (alive && mailboxListGenerationRef.current === generation) setLoading(false)
    })
    return () => { alive = false }
  }, [])

  async function importMailboxFile(file: File | undefined) {
    if (!file || mailboxImportPendingRef.current) return
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
        receiptToken: bundle.receipt_token,
        idempotencyKey: crypto.randomUUID(),
      }
      mailboxImportRetryRef.current = batch
      setMailboxImportRetryAvailable(true)
      const receipt = await importMailboxes(
        batch.payload, batch.idempotencyKey, batch.receiptToken,
      )
      if (!isCurrent()) return
      if (receipt.pool_type !== 'mailbox' || receipt.imported_count !== batch.payload.length) {
        throw new Error('平台返回的邮箱池导入回执绑定无效；请使用同一批次重试核对。')
      }
      mailboxImportRetryRef.current = null
      setMailboxImportRetryAvailable(false)
      setLastMailboxImportReceipt(receipt)
      message.success(`已向邮箱池登记 ${receipt.imported_count} 条资源引用。`)
      await refreshMailboxRows(isCurrent)
    } catch (error) {
      if (!isCurrent()) return
      if (!shouldRetainPoolImportForRetry(error)) {
        mailboxImportRetryRef.current = null
        setMailboxImportRetryAvailable(false)
      }
      message.error(error instanceof Error ? error.message : '邮箱池引用清单登记失败')
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
        batch.payload, batch.idempotencyKey, batch.receiptToken,
      )
      if (!isCurrent()) return
      if (receipt.pool_type !== 'mailbox' || receipt.imported_count !== batch.payload.length) {
        throw new Error('平台返回的邮箱池导入回执绑定无效；请使用同一批次重试核对。')
      }
      mailboxImportRetryRef.current = null
      setMailboxImportRetryAvailable(false)
      setLastMailboxImportReceipt(receipt)
      message.success(`已确认邮箱池引用清单，共 ${receipt.imported_count} 条资源。`)
      await refreshMailboxRows(isCurrent)
    } catch (error) {
      if (!isCurrent()) return
      if (!shouldRetainPoolImportForRetry(error)) {
        mailboxImportRetryRef.current = null
        setMailboxImportRetryAvailable(false)
      }
      message.error(error instanceof Error ? error.message : '邮箱池引用清单重试失败')
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

  async function refreshMailboxRows(isCurrent?: () => boolean) {
    if (isCurrent && !isCurrent()) return
    if (mailboxListPendingRef.current) return
    mailboxListPendingRef.current = true
    const generation = mailboxListGenerationRef.current + 1
    mailboxListGenerationRef.current = generation
    setLoading(true)
    setMailboxListError(undefined)
    setRows([])
    try {
      const items = await listMailboxes()
      if (isCurrent && !isCurrent()) return
      if (mailboxListGenerationRef.current === generation) setRows(items)
    } catch {
      if (isCurrent && !isCurrent()) return
      if (mailboxListGenerationRef.current === generation) failClosedMailboxList()
    } finally {
      if (isCurrent && !isCurrent()) return
      if (mailboxListGenerationRef.current === generation) {
        mailboxListPendingRef.current = false
        setLoading(false)
      }
    }
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
        + '下一步：已刷新真实状态；若目标状态未生效，可从同一入口重试。',
      )
    } finally {
      if (!isCurrent()) return
      await refreshMailboxRows(isCurrent)
      if (!isCurrent()) return
      releaseMailboxAction(action)
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
  const filteredRows = useMemo(() => {
    const query = mailboxSearch.trim().toLocaleLowerCase()
    return rows.filter((row) => {
      if (mailboxStatusFilter && row.status !== mailboxStatusFilter) return false
      if (mailboxHealthFilter && row.health_status !== mailboxHealthFilter) return false
      if (!query) return true
      return [row.email_masked, row.connector_type, row.task_type]
        .some((value) => value.toLocaleLowerCase().includes(query))
    })
  }, [mailboxHealthFilter, mailboxSearch, mailboxStatusFilter, rows])
  const columns: TableColumnsType<MailboxSummary> = [
    { title: '邮箱', dataIndex: 'email_masked', sorter: (left, right) => compareTableText(left.email_masked, right.email_masked) },
    { title: '连接器', dataIndex: 'connector_type', sorter: (left, right) => compareTableText(left.connector_type, right.connector_type) },
    { title: '服务端路由键', dataIndex: 'task_type', sorter: (left, right) => compareTableText(left.task_type, right.task_type) },
    { title: '容量状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: '健康', dataIndex: 'health_status', render: (value, row) => <Space direction="vertical" size={0}>
      <MailboxHealthTag value={value} />
      {row.last_error_code ? <Text type="danger">{mailboxHealthErrorNames[row.last_error_code] ?? '连接器异常'}</Text> : null}
    </Space> },
    { title: '上次检测', dataIndex: 'last_checked_at', render: (value: string | null) => value ?? '尚未检测' },
    { title: '等待会话', dataIndex: 'active_session_count', sorter: (left, right) => left.active_session_count - right.active_session_count },
    {
      title: '启用', dataIndex: 'is_active',
      render: (value: boolean) => <BooleanStateTag value={value} trueLabel="是" falseLabel="否" />,
    },
    { title: '创建时间', dataIndex: 'created_at', sorter: (left, right) => compareTableDate(left.created_at, right.created_at) },
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
      {mailboxImportRetryAvailable ? <>
        <Button disabled={saving} onClick={() => { void retryMailboxImport() }}>重试上次邮箱池引用清单</Button>
        <Button disabled={saving} onClick={discardMailboxImportRetry}>放弃并清除上次邮箱池引用清单</Button>
      </> : null}
      <Button type="primary" loading={saving} disabled={mailboxActionKey !== null} onClick={() => mailboxImportInputRef.current?.click()}>导入邮箱池安全包 JSON</Button>
    </Space> : null}</div>
    <Alert className="section-card" type="info" showIcon message="这里只接收独立安全导入器生成的邮箱池安全包" description="邮箱账号、密码和令牌不进入浏览器或普通 API；安全包只含 m***@example.invalid 这类脱敏元数据和短期 Vault Transit 签名收据，密钥引用由服务端固定派生。单条资源也使用同一安全导入流程。" />
    {lastMailboxImportReceipt ? <Alert
      className="section-card"
      type="success"
      showIcon
      message={`最近一次邮箱池导入已确认：${lastMailboxImportReceipt.imported_count} 条`}
      description={<Space wrap>
        <Text>回执 ID：</Text><Text code copyable>{lastMailboxImportReceipt.id}</Text>
        <Text>Trace ID：</Text><Text code copyable>{lastMailboxImportReceipt.trace_id}</Text>
        <Text>时间：{formatLocalDateTime(lastMailboxImportReceipt.created_at)}</Text>
      </Space>}
    /> : null}
    {unavailableRows.length > 0 ? <Alert
      style={{ marginBottom: 16 }}
      type="error"
      showIcon
      message={`有 ${unavailableRows.length} 个邮箱连接器不可用`}
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
          aria-label="搜索邮箱池"
          placeholder="搜索掩码邮箱、连接器或服务端路由键"
          value={mailboxSearch}
          onChange={(event) => setMailboxSearch(event.currentTarget.value)}
          style={{ width: 320 }}
        />
        <Select<MailboxSummary['status']>
          allowClear
          aria-label="按邮箱容量状态筛选"
          placeholder="全部容量状态"
          value={mailboxStatusFilter}
          options={[
            { label: '可用', value: 'available' },
            { label: '忙碌', value: 'busy' },
            { label: '已停用', value: 'disabled' },
          ]}
          onChange={setMailboxStatusFilter}
          style={{ minWidth: 160 }}
        />
        <Select<MailboxSummary['health_status']>
          allowClear
          aria-label="按邮箱健康状态筛选"
          placeholder="全部健康状态"
          value={mailboxHealthFilter}
          options={[
            { label: '正常', value: 'healthy' },
            { label: '异常', value: 'unavailable' },
            { label: '未检测', value: 'unknown' },
          ]}
          onChange={setMailboxHealthFilter}
          style={{ minWidth: 160 }}
        />
        <Text type="secondary" role="status" aria-live="polite">显示 {filteredRows.length} / 共 {rows.length} 个邮箱</Text>
      </Space>
      <Table columns={columns} dataSource={filteredRows} rowKey="id" locale={{ emptyText: <Empty description="没有符合条件的邮箱连接器" /> }} scroll={{ x: 1220 }} />
    </Space>}</Card>
  </>
}
