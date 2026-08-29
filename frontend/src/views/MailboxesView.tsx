import { useEffect, useRef, useState } from 'react'
import { Alert, App as AntApp, Button, Card, Descriptions, Empty, Form, Input, Modal, Space, Spin, Table, Typography } from 'antd'
import type { TableColumnsType } from 'antd'
import { createMailbox, listMailboxes, rotateMailboxSecret, updateMailboxState } from '../admin-api'
import type { MailboxCreate, MailboxSummary } from '../types'
import { useScopedConfirm } from '../useScopedConfirm'
import { useViewActionScope } from '../useViewActionScope'
import { BooleanStateTag, MailboxHealthTag, StatusTag, compareTableDate, compareTableText, mailboxHealthErrorNames } from './shared'

const { Title, Text } = Typography

export default function MailboxesPage({ canManage }: { canManage: boolean }) {
  const { message } = AntApp.useApp()
  const confirm = useScopedConfirm()
  const beginViewAction = useViewActionScope()
  const [rows, setRows] = useState<MailboxSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [mailboxListError, setMailboxListError] = useState<string>()
  const [createOpen, setCreateOpen] = useState(false)
  const [rotateTarget, setRotateTarget] = useState<MailboxSummary | null>(null)
  const [saving, setSaving] = useState(false)
  const mailboxCreatePendingRef = useRef(false)
  const [mailboxActionKey, setMailboxActionKey] = useState<string | null>(null)
  const [mailboxActionPending, setMailboxActionPending] = useState(false)
  const mailboxActionRef = useRef<{
    key: string
    mailboxId: string
    kind: 'state' | 'rotation'
    pending: boolean
  } | null>(null)
  const mailboxListGenerationRef = useRef(0)
  const mailboxListPendingRef = useRef(false)
  const [createForm] = Form.useForm<MailboxCreate>()
  const [rotateForm] = Form.useForm<{ secret_ref: string }>()

  function failClosedMailboxList() {
    rotateForm.resetFields()
    setRotateTarget(null)
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
  }, [rotateForm])

  async function submitMailbox(values: MailboxCreate) {
    if (mailboxCreatePendingRef.current) return
    const isCurrent = beginViewAction()
    mailboxCreatePendingRef.current = true
    setSaving(true)
    try {
      await createMailbox(values)
      if (!isCurrent()) return
      message.success('邮箱连接器已登记。')
      createForm.resetFields()
      setCreateOpen(false)
      await refreshMailboxRows(isCurrent)
    } catch (error) {
      if (!isCurrent()) return
      message.error(error instanceof Error ? error.message : '邮箱连接器登记失败')
    } finally {
      if (!isCurrent()) return
      mailboxCreatePendingRef.current = false
      setSaving(false)
    }
  }

  function closeCreateMailbox() {
    createForm.resetFields()
    setCreateOpen(false)
  }

  function closeSecretRotation() {
    const action = mailboxActionRef.current
    if (action?.pending) return
    rotateForm.resetFields()
    setRotateTarget(null)
    if (action?.kind === 'rotation') releaseMailboxAction(action)
  }

  function reserveMailboxAction(kind: 'state' | 'rotation', mailboxId: string) {
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
    kind: 'state' | 'rotation'
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

  async function submitRotation(values: { secret_ref: string }) {
    if (!rotateTarget) return
    const action = mailboxActionRef.current
      ?? reserveMailboxAction('rotation', rotateTarget.id)
    if (
      !action
      || action.kind !== 'rotation'
      || action.mailboxId !== rotateTarget.id
      || action.pending
    ) return
    const isCurrent = beginViewAction()
    action.pending = true
    setMailboxActionPending(true)
    setSaving(true)
    try {
      await rotateMailboxSecret(rotateTarget.id, values.secret_ref)
      if (!isCurrent()) return
      message.success('密钥引用已轮换。')
      rotateForm.resetFields()
      setRotateTarget(null)
    } catch {
      if (!isCurrent()) return
      message.error(
        '原因：平台未能确认邮箱密钥引用轮换结果。'
        + '影响：新引用可能已经生效，页面不会按失败响应推断最终状态。'
        + '下一步：已刷新连接器真实状态；可核对后从同一入口重试。',
      )
    } finally {
      if (!isCurrent()) return
      await refreshMailboxRows(isCurrent)
      if (!isCurrent()) return
      setSaving(false)
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

  function openSecretRotation(row: MailboxSummary) {
    const action = reserveMailboxAction('rotation', row.id)
    if (!action) return
    rotateForm.resetFields()
    setRotateTarget(row)
  }

  const unavailableRows = rows.filter((row) => row.health_status === 'unavailable')
  const columns: TableColumnsType<MailboxSummary> = [
    { title: '邮箱', dataIndex: 'email_masked', sorter: (left, right) => compareTableText(left.email_masked, right.email_masked) },
    { title: '连接器', dataIndex: 'connector_type', sorter: (left, right) => compareTableText(left.connector_type, right.connector_type) },
    { title: '服务端路由键', dataIndex: 'task_type', sorter: (left, right) => compareTableText(left.task_type, right.task_type) },
    { title: '容量状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: '健康', dataIndex: 'health_status', filters: [
      { text: '正常', value: 'healthy' },
      { text: '异常', value: 'unavailable' },
      { text: '未检测', value: 'unknown' },
    ], onFilter: (value, row) => row.health_status === value, render: (value, row) => <Space direction="vertical" size={0}>
      <MailboxHealthTag value={value} />
      {row.last_error_code ? <Text type="danger">{mailboxHealthErrorNames[row.last_error_code] ?? '连接器异常'}</Text> : null}
    </Space> },
    { title: '上次检测', dataIndex: 'last_checked_at', render: (value: string | null) => value ?? '尚未检测' },
    { title: '等待会话', dataIndex: 'active_session_count', sorter: (left, right) => left.active_session_count - right.active_session_count },
    {
      title: '启用', dataIndex: 'is_active',
      filters: [{ text: '是', value: 'active' }, { text: '否', value: 'disabled' }],
      onFilter: (value, row) => (row.is_active ? 'active' : 'disabled') === value,
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
      <Button
        loading={mailboxActionPending && mailboxActionKey === `rotation:${row.id}`}
        disabled={saving || mailboxActionKey !== null}
        aria-label={`轮换邮箱密钥引用 ${row.email_masked}（${row.id}）`}
        onClick={() => openSecretRotation(row)}
      >轮换密钥引用</Button>
    </Space> }] : []),
  ]
  return <>
    <div className="page-heading"><div><Title level={2}>邮箱连接器</Title><Text type="secondary">只显示连接状态与掩码地址，源邮箱账号和密码不进入浏览器。</Text></div>{canManage && !loading && !mailboxListError ? <Button type="primary" disabled={saving || mailboxActionKey !== null} onClick={() => setCreateOpen(true)}>登记邮箱连接器</Button> : null}</div>
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
    /> : <Table columns={columns} dataSource={rows} rowKey="id" locale={{ emptyText: <Empty description="暂无邮箱连接器" /> }} scroll={{ x: 1220 }} />}</Card>
    <Modal title="登记邮箱连接器" open={createOpen} onCancel={closeCreateMailbox} onOk={() => createForm.submit()} confirmLoading={saving} okText="登记" cancelText="取消" destroyOnHidden>
      <Form form={createForm} layout="vertical" onFinish={submitMailbox} requiredMark="optional">
        <Form.Item label="掩码邮箱" name="email_masked" extra="必须使用掩码地址，例如 m***@example.invalid。" rules={[{ required: true }, { pattern: /^[^@]*\*[^@]*@[^@]+$/, message: '请输入包含 * 的掩码邮箱' }]}><Input autoComplete="off" placeholder="m***@example.invalid" /></Form.Item>
        <Form.Item label="连接器类型" name="connector_type" rules={[{ required: true }, { pattern: /^[a-z][a-z0-9_-]*$/, message: '仅允许小写字母、数字、横线和下划线' }]}><Input placeholder="http" /></Form.Item>
        <Form.Item label="服务端路由键" name="task_type" initialValue="mail_code" extra="由服务端按任务类型选择邮箱池，普通客户端不能指定连接器或邮箱。" rules={[{ required: true }, { pattern: /^[a-z][a-z0-9_-]*$/, message: '仅允许小写字母、数字、横线和下划线' }]}><Input autoComplete="off" placeholder="mail_code" /></Form.Item>
        <Form.Item label="密钥引用" name="secret_ref" extra="生产必须使用 vault://secret/mailboxes/；env:// 仅限开发/测试。请勿填写邮箱账号或密码。" rules={[{ required: true }, { pattern: /^(vault:\/\/secret\/mailboxes\/|env:\/\/)[A-Za-z0-9][A-Za-z0-9._/-]*$/, message: '生产使用 vault://secret/mailboxes/；env:// 仅限开发/测试' }]}><Input.Password autoComplete="new-password" visibilityToggle={false} placeholder="vault://secret/mailboxes/mail-001" /></Form.Item>
      </Form>
    </Modal>
    <Modal title={rotateTarget ? `轮换邮箱密钥引用 ${rotateTarget.email_masked}` : '轮换邮箱密钥引用'} open={rotateTarget !== null} onCancel={closeSecretRotation} onOk={() => rotateForm.submit()} confirmLoading={saving} okText="确认轮换" cancelText="取消" destroyOnHidden>
      {rotateTarget ? <Descriptions size="small" column={1}>
        <Descriptions.Item label="掩码邮箱">{rotateTarget.email_masked}</Descriptions.Item>
        <Descriptions.Item label="连接器 ID">{rotateTarget.id}</Descriptions.Item>
      </Descriptions> : null}
      <Alert type="warning" showIcon message="仅更新密钥引用" description="新凭据应已预先写入服务端密钥管理器；审计只记录轮换动作，不记录引用值。" />
      <Form className="modal-form" form={rotateForm} layout="vertical" onFinish={submitRotation}>
        <Form.Item label="新密钥引用" name="secret_ref" extra="生产必须使用 vault://secret/mailboxes/；env:// 仅限开发/测试。" rules={[{ required: true }, { pattern: /^(vault:\/\/secret\/mailboxes\/|env:\/\/)[A-Za-z0-9][A-Za-z0-9._/-]*$/, message: '生产使用 vault://secret/mailboxes/；env:// 仅限开发/测试' }]}><Input.Password autoComplete="new-password" visibilityToggle={false} placeholder="vault://secret/mailboxes/mail-001-v2" /></Form.Item>
      </Form>
    </Modal>
  </>
}
