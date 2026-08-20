import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AuditOutlined,
  BankOutlined,
  CloudUploadOutlined,
  DashboardOutlined,
  LockOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  LoadingOutlined,
  MailOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  TeamOutlined,
  UnorderedListOutlined,
} from '@ant-design/icons'
import {
  Alert,
  App as AntApp,
  Button,
  Card,
  Col,
  Descriptions,
  Empty,
  Form,
  Input,
  InputNumber,
  Layout,
  Menu,
  Modal,
  Row,
  Space,
  Spin,
  Statistic,
  Table,
  Tag,
  Select,
  Steps,
  Typography,
} from 'antd'
import type { MenuProps, TableColumnsType } from 'antd'
import { ApiError, approveUploadPolicyVersion, cancelUploadJob, clearSession, closeTask, createCard, createMailbox, deployUploadPolicyVersion, disableUser, getAuthConfig, getDashboardSummary, getMe, getUploadPolicyStatus, listAuditEvents, listCards, listDevices, listMailboxes, listTasks, listUploadPolicyVersions, listUploads, listUsers, login, reconcileUploadJob, registerUploadPolicyVersion, revokeDevice, rollbackUploadPolicy, rotateMailboxSecret, setBearer, updateCardState, updateMailboxState } from './api'
import { createOidcManager } from './oidc'
import type { UserManager } from 'oidc-client-ts'
import type { AdminDevice, AdminUser, AuditEvent, AuthConfig, CardCreate, CardSummary, DashboardSummary, MailboxCreate, MailboxSummary, Principal, TaskSummary, UploadPolicyStatus, UploadPolicyVersion, UploadSummary } from './types'

const { Header, Content, Sider } = Layout
const { Title, Text, Paragraph } = Typography

type ViewKey = 'dashboard' | 'tasks' | 'cards' | 'mailboxes' | 'uploads' | 'users' | 'audit' | 'policies'

const menuItems: MenuProps['items'] = [
  { key: 'dashboard', icon: <DashboardOutlined />, label: '工作台' },
  { key: 'tasks', icon: <UnorderedListOutlined />, label: '任务中心' },
  { key: 'cards', icon: <BankOutlined />, label: '卡池管理' },
  { key: 'mailboxes', icon: <MailOutlined />, label: '邮箱连接器' },
  { key: 'uploads', icon: <CloudUploadOutlined />, label: 'Sub2 上传' },
  { key: 'users', icon: <TeamOutlined />, label: '用户与权限' },
  { key: 'audit', icon: <AuditOutlined />, label: '审计中心' },
  { key: 'policies', icon: <SettingOutlined />, label: '策略配置' },
]

const roleViews: Record<string, ReadonlySet<ViewKey>> = {
  operator: new Set(['dashboard', 'tasks', 'mailboxes']),
  ops_admin: new Set(['dashboard', 'tasks', 'cards', 'mailboxes', 'users', 'policies']),
  security_auditor: new Set(['dashboard', 'uploads', 'audit']),
  platform_admin: new Set(['dashboard', 'tasks', 'cards', 'mailboxes', 'uploads', 'users', 'audit', 'policies']),
  worker_service: new Set(['dashboard']),
}

const roleNames: Record<string, string> = {
  operator: '操作员',
  ops_admin: '运营管理员',
  security_auditor: '安全审计员',
  platform_admin: '平台管理员',
  worker_service: '后台服务',
}

const statusColor: Record<string, string> = {
  active: 'green', available: 'green', succeeded: 'green', enabled: 'green',
  queued: 'blue', running: 'processing', allocated: 'orange', unknown: 'gold',
  initializing: 'processing', code_ready: 'green',
  busy: 'processing', ready: 'green', not_configured: 'gold',
  draft: 'default', approved: 'blue', retired: 'default',
  disabled: 'red', failed: 'red', revoked: 'red', expired: 'default',
  created: 'processing', closed: 'default',
}

function StatusTag({ value }: { value: string }) {
  const icon = value === 'succeeded' || value === 'available' ? <CheckCircleOutlined />
    : value === 'running' || value === 'queued' ? <LoadingOutlined />
      : value === 'failed' || value === 'unknown' || value === 'revoked' ? <ExclamationCircleOutlined /> : undefined
  return <Tag icon={icon} color={statusColor[value] ?? 'default'}>{value}</Tag>
}

function LoginScreen({ authConfig, oidcManager, onReady }: {
  authConfig: AuthConfig
  oidcManager: UserManager | null
  onReady: (principal: Principal) => void
}) {
  const { message } = AntApp.useApp()
  const [loading, setLoading] = useState(false)

  async function submit(values: { tenant_id: string; email: string; password: string; device_id: string }) {
    setLoading(true)
    try {
      await login(values)
      onReady(await getMe())
    } catch (error) {
      const detail = error instanceof ApiError && error.traceId ? `（追踪号：${error.traceId}）` : ''
      message.error(`${error instanceof Error ? error.message : '登录失败'}${detail}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="login-shell">
      <section className="login-intro">
        <div className="brand-mark"><SafetyCertificateOutlined /></div>
        <Text className="eyebrow">SECURE OPERATIONS</Text>
        <Title>验证码业务平台</Title>
        <Paragraph>统一管理任务、卡分配、邮箱取码和 Sub2 上传。敏感上游配置只保留在服务端。</Paragraph>
        <Space direction="vertical" size={12}>
          <Text><LockOutlined /> 设备绑定会话</Text>
          <Text><AuditOutlined /> 全链路操作审计</Text>
          <Text><BankOutlined /> 卡信息按人分配与追溯</Text>
        </Space>
      </section>
      <Card className="login-card" bordered={false}>
        <Text className="eyebrow">运营控制台</Text>
        <Title level={2}>登录平台</Title>
        <Paragraph type="secondary">{authConfig.mode === 'oidc' ? '通过统一身份中心完成 PKCE 安全登录。' : '本地账号仅用于开发与联调环境。'}</Paragraph>
        {authConfig.mode === 'oidc' ? (
          <Button
            type="primary"
            size="large"
            block
            icon={<SafetyCertificateOutlined />}
            onClick={() => oidcManager?.signinRedirect()}
            disabled={!oidcManager}
          >统一身份登录</Button>
        ) : <Form layout="vertical" onFinish={submit} requiredMark="optional">
          <Form.Item label="租户" name="tenant_id" rules={[{ required: true, message: '请输入租户标识' }]}>
            <Input autoComplete="organization" placeholder="tenant-a" />
          </Form.Item>
          <Form.Item label="平台账号" name="email" rules={[{ required: true }, { type: 'email' }]}>
            <Input autoComplete="username" placeholder="name@example.com" />
          </Form.Item>
          <Form.Item label="平台密码" name="password" rules={[{ required: true, message: '请输入平台密码' }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Form.Item label="设备标识" name="device_id" rules={[{ required: true }]}>
            <Input autoComplete="off" placeholder="ops-console-01" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={loading} block size="large">安全登录</Button>
        </Form>}
      </Card>
    </main>
  )
}

function statusRows(values: Record<string, number>) {
  return Object.entries(values).map(([status, count]) => ({ status, count }))
}

function buildTaskLifecycle(task: TaskSummary): {
  current: number
  status: 'error' | 'process'
  items: { title: string; description: string }[]
} {
  const terminal = ['closed', 'completed', 'cancelled', 'expired'].includes(task.status)
  const errored = ['cancelled', 'expired'].includes(task.status)
  const current = terminal ? 4 : task.status === 'active' ? 2 : 1
  return {
    current,
    status: errored ? 'error' : 'process',
    items: [
      { title: '创建任务', description: task.created_at },
      { title: '等待验证码', description: '平台代取邮箱验证码' },
      { title: '卡分配', description: '按人绑定并留痕' },
      { title: 'Sub2 上传', description: '由平台统一提交' },
      { title: '关闭收尾', description: task.closed_at ?? '等待关闭' },
    ],
  }
}

function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary>()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  useEffect(() => {
    let alive = true
    setLoading(true)
    getDashboardSummary().then((value) => {
      if (alive) {
        setSummary(value)
        setError(undefined)
      }
    }).catch(() => {
      if (alive) setError('运行摘要暂不可用，请稍后刷新。')
    }).finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [])
  const statusColumns: TableColumnsType<{ status: string; count: number }> = [
    { title: '状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: '数量', dataIndex: 'count', align: 'right' },
  ]
  if (loading) return <div className="centered"><Spin /></div>
  if (error || !summary) return <Alert type="warning" showIcon message="工作台暂不可用" description={error ?? '未读取到运行摘要'} />
  return <>
    <PageHeading title="工作台" description="关注正在运行的业务与需要人工处理的异常。" />
    {summary.unknown_uploads > 0 ? <Alert
      className="section-card"
      type="warning"
      showIcon
      message="存在需要人工核对的 Sub2 上传"
      description="这些任务的外部结果不明确，平台不会自动重试；请到 Sub2 上传页和审计中心核对。"
    /> : null}
    <Row gutter={[16, 16]}>
      <Col xs={24} md={12} xl={6}><Card><Statistic title="进行中任务" value={summary.active_tasks} /></Card></Col>
      <Col xs={24} md={12} xl={6}><Card><Statistic title="已分配卡" value={summary.allocated_cards} /></Card></Col>
      <Col xs={24} md={12} xl={6}><Card><Statistic title="等待上传" value={summary.queued_uploads} /></Card></Col>
      <Col xs={24} md={12} xl={6}><Card><Statistic title="需人工核对" value={summary.unknown_uploads} valueStyle={{ color: summary.unknown_uploads > 0 ? '#b86b11' : undefined }} /></Card></Col>
    </Row>
    <Card className="section-card" title="当前运行情况">
      <Descriptions size="small" column={{ xs: 1, md: 2 }}>
        <Descriptions.Item label="统计范围">{summary.scope === 'tenant' ? '当前租户' : '我的任务'}</Descriptions.Item>
        <Descriptions.Item label="生成时间">{summary.generated_at}</Descriptions.Item>
        <Descriptions.Item label="等待验证码邮箱">{summary.waiting_mail_sessions}</Descriptions.Item>
      </Descriptions>
      <Row gutter={[16, 16]} className="section-card">
        <Col xs={24} lg={12}>
          <Table
            size="small"
            columns={statusColumns}
            dataSource={statusRows(summary.task_statuses)}
            rowKey="status"
            pagination={false}
            locale={{ emptyText: <Empty description="暂无任务状态" /> }}
          />
        </Col>
        <Col xs={24} lg={12}>
          <Table
            size="small"
            columns={statusColumns}
            dataSource={statusRows(summary.upload_statuses)}
            rowKey="status"
            pagination={false}
            locale={{ emptyText: <Empty description="暂无上传状态" /> }}
          />
        </Col>
      </Row>
    </Card>
  </>
}

function PageHeading({ title, description }: { title: string; description: string }) {
  return <div className="page-heading"><div><Title level={2}>{title}</Title><Text type="secondary">{description}</Text></div></div>
}

function PlaceholderPage({ title, description, notice }: { title: string; description: string; notice: string }) {
  return <><PageHeading title={title} description={description} /><Card><Empty description={notice} /></Card></>
}

function RemoteTable<T extends object>({ loader, columns, empty }: {
  loader: () => Promise<T[]>
  columns: TableColumnsType<T>
  empty: string
}) {
  const [rows, setRows] = useState<T[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  useEffect(() => {
    let alive = true
    loader().then((items) => { if (alive) setRows(items) }).catch((reason) => {
      if (alive) setError(reason instanceof Error ? reason.message : '读取失败')
    }).finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [loader])
  if (loading) return <div className="centered"><Spin /></div>
  if (error) return <Alert type="warning" showIcon message="数据暂不可用" description={error} />
  return <Table columns={columns} dataSource={rows} rowKey={(row) => String((row as { id: string }).id)} locale={{ emptyText: <Empty description={empty} /> }} scroll={{ x: 760 }} />
}

function UsersPage() {
  const { message } = AntApp.useApp()
  const columns: TableColumnsType<AdminUser> = [
    { title: '账号', dataIndex: 'email' },
    { title: '角色', dataIndex: 'role', render: (role: string) => roleNames[role] ?? role },
    { title: '状态', dataIndex: 'is_active', render: (active: boolean) => <StatusTag value={active ? 'active' : 'disabled'} /> },
    { title: '创建时间', dataIndex: 'created_at' },
    { title: '操作', render: (_, row) => <Button danger disabled={!row.is_active} onClick={async () => {
      try { await disableUser(row.id); message.success('用户已停用，请刷新列表') }
      catch (error) { message.error(error instanceof Error ? error.message : '操作失败') }
    }}>停用</Button> },
  ]
  const deviceColumns: TableColumnsType<AdminDevice> = [
    { title: '设备名称', dataIndex: 'name' },
    { title: '设备 ID', dataIndex: 'id' },
    { title: '所属用户', dataIndex: 'user_id' },
    { title: '状态', dataIndex: 'revoked_at', render: (value: string | null) => <StatusTag value={value ? 'revoked' : 'active'} /> },
    { title: '创建时间', dataIndex: 'created_at' },
    { title: '操作', render: (_, row) => <Button danger disabled={row.revoked_at !== null} onClick={async () => {
      try { await revokeDevice(row.id); message.success('设备已撤销，请刷新列表') }
      catch (error) { message.error(error instanceof Error ? error.message : '设备撤销失败') }
    }}>撤销设备</Button> },
  ]
  return <><PageHeading title="用户与权限" description="按角色授予最小权限，并支持即时停用账号或撤销设备。" />
    <Card title="用户"><RemoteTable loader={listUsers} columns={columns} empty="暂无用户" /></Card>
    <Card className="section-card" title="设备"><RemoteTable loader={listDevices} columns={deviceColumns} empty="暂无设备" /></Card>
  </>
}

function CardsPage({ canManage }: { canManage: boolean }) {
  const { message } = AntApp.useApp()
  const [rows, setRows] = useState<CardSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [refresh, setRefresh] = useState(0)
  const [createOpen, setCreateOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const [form] = Form.useForm<CardCreate>()
  useEffect(() => {
    let alive = true
    setLoading(true)
    listCards().then((items) => { if (alive) setRows(items) })
      .catch(() => { if (alive) message.warning('卡资源列表暂不可用。') })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [message, refresh])

  async function submitCard(values: CardCreate) {
    setSaving(true)
    try {
      await createCard(values)
      message.success('卡资源已登记。')
      form.resetFields()
      setCreateOpen(false)
      setRefresh((value) => value + 1)
    } catch (error) {
      message.error(error instanceof Error ? error.message : '卡资源登记失败')
    } finally {
      setSaving(false)
    }
  }

  function closeCreateCard() {
    form.resetFields()
    setCreateOpen(false)
  }

  async function changeState(row: CardSummary, isActive: boolean) {
    try {
      await updateCardState(row.id, isActive)
      message.success(isActive ? '卡资源已启用。' : '卡资源已停用，活动租约已释放。')
      setRefresh((value) => value + 1)
    } catch (error) {
      message.error(error instanceof Error ? error.message : '卡资源状态更新失败')
    }
  }

  const columns: TableColumnsType<CardSummary> = [
    { title: '提供方引用', dataIndex: 'provider_ref' },
    { title: '品牌', dataIndex: 'brand' },
    { title: '尾号', dataIndex: 'last4', render: (value: string) => `•••• ${value}` },
    { title: '有效期', render: (_, row) => row.expiry_month && row.expiry_year ? `${String(row.expiry_month).padStart(2, '0')}/${row.expiry_year}` : '—' },
    { title: '状态', dataIndex: 'is_active', render: (value: boolean) => <StatusTag value={value ? 'available' : 'disabled'} /> },
    ...(canManage ? [{ title: '操作', render: (_: unknown, row: CardSummary) => row.is_active ? <Button danger onClick={() => {
      Modal.confirm({
        title: '确认停用该卡资源？',
        content: '停用会立即释放活动租约，并取消尚未执行的关联上传；运行中的上传将转为待人工核对。',
        okText: '停用并释放',
        okButtonProps: { danger: true },
        cancelText: '取消',
        onOk: () => changeState(row, false),
      })
    }}>停用</Button> : <Button onClick={() => changeState(row, true)}>启用</Button> }] : []),
  ]
  return <>
    <div className="page-heading"><div><Title level={2}>卡池管理</Title><Text type="secondary">登记接口不接收 PAN/CVV；PAN 保存在 Vault 且仅经 step-up 揭示，CVV 默认不返回。</Text></div>{canManage ? <Button type="primary" onClick={() => setCreateOpen(true)}>登记卡资源</Button> : null}</div>
    <Alert className="section-card" type="info" showIcon message="敏感卡信息必须保存在服务端密钥管理器" description="生产环境必须填写 vault://secret/cards/ 引用；env:// 仅限开发和测试。停用会释放活动租约，取消排队上传，并将运行中上传转为待人工核对。" />
    <Card className="section-card"><Table loading={loading} columns={columns} dataSource={rows} rowKey="id" locale={{ emptyText: <Empty description="暂无卡资源" /> }} scroll={{ x: 900 }} /></Card>
    <Modal title="登记卡资源" open={createOpen} onCancel={closeCreateCard} onOk={() => form.submit()} confirmLoading={saving} okText="登记" cancelText="取消" destroyOnHidden>
      <Form form={form} layout="vertical" onFinish={submitCard} requiredMark="optional">
        <Form.Item label="提供方引用" name="provider_ref" rules={[{ required: true }, { max: 160 }]}><Input autoComplete="off" placeholder="provider-card-001" /></Form.Item>
        <Row gutter={12}>
          <Col span={12}><Form.Item label="品牌" name="brand" rules={[{ required: true }, { max: 40 }]}><Input placeholder="VISA" /></Form.Item></Col>
          <Col span={12}><Form.Item label="尾号" name="last4" rules={[{ required: true }, { pattern: /^\d{4}$/, message: '必须是 4 位数字' }]}><Input inputMode="numeric" maxLength={4} placeholder="4242" /></Form.Item></Col>
          <Col span={12}><Form.Item label="有效期月份" name="expiry_month" dependencies={['expiry_year']} rules={[({ getFieldValue }) => ({ validator(_, value) { return (value == null) === (getFieldValue('expiry_year') == null) ? Promise.resolve() : Promise.reject(new Error('月份和年份须同时填写')) } })]}><InputNumber min={1} max={12} className="full-width" placeholder="12" /></Form.Item></Col>
          <Col span={12}><Form.Item label="有效期年份" name="expiry_year" dependencies={['expiry_month']} rules={[({ getFieldValue }) => ({ validator(_, value) { return (value == null) === (getFieldValue('expiry_month') == null) ? Promise.resolve() : Promise.reject(new Error('月份和年份须同时填写')) } })]}><InputNumber min={2000} max={9999} className="full-width" placeholder="2030" /></Form.Item></Col>
        </Row>
        <Form.Item label="密钥引用" name="secret_ref" extra="生产必须使用 vault://secret/cards/；env:// 仅限开发/测试。请勿粘贴卡号或安全码。" rules={[{ required: true }, { pattern: /^(vault:\/\/secret\/cards\/|env:\/\/)[A-Za-z0-9][A-Za-z0-9._/-]*$/, message: '生产使用 vault://secret/cards/；env:// 仅限开发/测试' }]}><Input.Password autoComplete="new-password" visibilityToggle={false} placeholder="vault://secret/cards/provider-card-001" /></Form.Item>
      </Form>
    </Modal>
  </>
}

function MailboxesPage({ canManage }: { canManage: boolean }) {
  const { message } = AntApp.useApp()
  const [rows, setRows] = useState<MailboxSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [refresh, setRefresh] = useState(0)
  const [createOpen, setCreateOpen] = useState(false)
  const [rotateTarget, setRotateTarget] = useState<MailboxSummary | null>(null)
  const [saving, setSaving] = useState(false)
  const [createForm] = Form.useForm<MailboxCreate>()
  const [rotateForm] = Form.useForm<{ secret_ref: string }>()
  useEffect(() => {
    let alive = true
    setLoading(true)
    listMailboxes().then((items) => { if (alive) setRows(items) })
      .catch(() => { if (alive) message.warning('邮箱连接器列表暂不可用。') })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [message, refresh])

  async function submitMailbox(values: MailboxCreate) {
    setSaving(true)
    try {
      await createMailbox(values)
      message.success('邮箱连接器已登记。')
      createForm.resetFields()
      setCreateOpen(false)
      setRefresh((value) => value + 1)
    } catch (error) {
      message.error(error instanceof Error ? error.message : '邮箱连接器登记失败')
    } finally { setSaving(false) }
  }

  function closeCreateMailbox() {
    createForm.resetFields()
    setCreateOpen(false)
  }

  function closeSecretRotation() {
    rotateForm.resetFields()
    setRotateTarget(null)
  }

  async function changeState(row: MailboxSummary, isActive: boolean) {
    try {
      await updateMailboxState(row.id, isActive)
      message.success(isActive ? '邮箱连接器已启用。' : '邮箱连接器已停用，活动会话已撤销。')
      setRefresh((value) => value + 1)
    } catch (error) {
      message.error(error instanceof Error ? error.message : '邮箱状态更新失败')
    }
  }

  async function submitRotation(values: { secret_ref: string }) {
    if (!rotateTarget) return
    setSaving(true)
    try {
      await rotateMailboxSecret(rotateTarget.id, values.secret_ref)
      message.success('密钥引用已轮换。')
      rotateForm.resetFields()
      setRotateTarget(null)
      setRefresh((value) => value + 1)
    } catch (error) {
      message.error(error instanceof Error ? error.message : '密钥引用轮换失败')
    } finally { setSaving(false) }
  }

  const columns: TableColumnsType<MailboxSummary> = [
    { title: '邮箱', dataIndex: 'email_masked' },
    { title: '连接器', dataIndex: 'connector_type' },
    { title: '状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: '等待会话', dataIndex: 'active_session_count' },
    { title: '启用', dataIndex: 'is_active', render: (value: boolean) => value ? '是' : '否' },
    { title: '创建时间', dataIndex: 'created_at' },
    ...(canManage ? [{ title: '操作', render: (_: unknown, row: MailboxSummary) => <Space>
      {row.is_active ? <Button danger onClick={() => Modal.confirm({ title: '确认停用邮箱连接器？', content: '活动取码会话将立即撤销，尚未消费的验证码会被擦除。', okText: '停用并撤销会话', okButtonProps: { danger: true }, cancelText: '取消', onOk: () => changeState(row, false) })}>停用</Button> : <Button onClick={() => changeState(row, true)}>启用</Button>}
      <Button onClick={() => setRotateTarget(row)}>轮换密钥引用</Button>
    </Space> }] : []),
  ]
  return <>
    <div className="page-heading"><div><Title level={2}>邮箱连接器</Title><Text type="secondary">只显示连接状态与掩码地址，源邮箱账号和密码不进入浏览器。</Text></div>{canManage ? <Button type="primary" onClick={() => setCreateOpen(true)}>登记邮箱连接器</Button> : null}</div>
    <Card><Table loading={loading} columns={columns} dataSource={rows} rowKey="id" locale={{ emptyText: <Empty description="暂无邮箱连接器" /> }} scroll={{ x: 980 }} /></Card>
    <Modal title="登记邮箱连接器" open={createOpen} onCancel={closeCreateMailbox} onOk={() => createForm.submit()} confirmLoading={saving} okText="登记" cancelText="取消" destroyOnHidden>
      <Form form={createForm} layout="vertical" onFinish={submitMailbox} requiredMark="optional">
        <Form.Item label="掩码邮箱" name="email_masked" extra="必须使用掩码地址，例如 m***@example.com。" rules={[{ required: true }, { pattern: /^[^@]*\*[^@]*@[^@]+$/, message: '请输入包含 * 的掩码邮箱' }]}><Input autoComplete="off" placeholder="m***@example.com" /></Form.Item>
        <Form.Item label="连接器类型" name="connector_type" rules={[{ required: true }, { pattern: /^[a-z][a-z0-9_-]*$/, message: '仅允许小写字母、数字、横线和下划线' }]}><Input placeholder="http" /></Form.Item>
        <Form.Item label="密钥引用" name="secret_ref" extra="生产必须使用 vault://secret/mailboxes/；env:// 仅限开发/测试。请勿填写邮箱账号或密码。" rules={[{ required: true }, { pattern: /^(vault:\/\/secret\/mailboxes\/|env:\/\/)[A-Za-z0-9][A-Za-z0-9._/-]*$/, message: '生产使用 vault://secret/mailboxes/；env:// 仅限开发/测试' }]}><Input.Password autoComplete="new-password" visibilityToggle={false} placeholder="vault://secret/mailboxes/mail-001" /></Form.Item>
      </Form>
    </Modal>
    <Modal title="轮换密钥引用" open={rotateTarget !== null} onCancel={closeSecretRotation} onOk={() => rotateForm.submit()} confirmLoading={saving} okText="确认轮换" cancelText="取消" destroyOnHidden>
      <Alert type="warning" showIcon message="仅更新密钥引用" description="新凭据应已预先写入服务端密钥管理器；审计只记录轮换动作，不记录引用值。" />
      <Form className="modal-form" form={rotateForm} layout="vertical" onFinish={submitRotation}>
        <Form.Item label="新密钥引用" name="secret_ref" extra="生产必须使用 vault://secret/mailboxes/；env:// 仅限开发/测试。" rules={[{ required: true }, { pattern: /^(vault:\/\/secret\/mailboxes\/|env:\/\/)[A-Za-z0-9][A-Za-z0-9._/-]*$/, message: '生产使用 vault://secret/mailboxes/；env:// 仅限开发/测试' }]}><Input.Password autoComplete="new-password" visibilityToggle={false} placeholder="vault://secret/mailboxes/mail-001-v2" /></Form.Item>
      </Form>
    </Modal>
  </>
}

function TasksPage() {
  const { message } = AntApp.useApp()
  const [rows, setRows] = useState<TaskSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [refresh, setRefresh] = useState(0)
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null)
  useEffect(() => {
    let alive = true
    setLoading(true)
    listTasks().then((items) => {
      if (alive) {
        setRows(items)
        setSelectedTaskId((current) => current && items.some((item) => item.id === current) ? current : items[0]?.id ?? null)
      }
    })
      .catch(() => { if (alive) message.warning('任务列表暂不可用，请稍后刷新。') })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [message, refresh])
  const selectedTask = rows.find((row) => row.id === selectedTaskId) ?? rows[0] ?? null
  const lifecycle = selectedTask ? buildTaskLifecycle(selectedTask) : null
  const columns: TableColumnsType<TaskSummary> = [
    { title: '任务', dataIndex: 'id', render: (value: string) => value.slice(0, 12) },
    { title: '类型', dataIndex: 'type' },
    { title: '状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: '过期时间', dataIndex: 'expires_at', render: (value: string | null) => value ?? '—' },
    { title: '创建时间', dataIndex: 'created_at' },
    { title: 'trace_id', dataIndex: 'trace_id', ellipsis: true },
    { title: '操作', render: (_, row) => <Button
      danger
      disabled={['closed', 'expired', 'cancelled', 'completed'].includes(row.status)}
      onClick={async () => {
        try {
          await closeTask(row.id)
          message.success('任务已关闭并释放资源。')
          setRefresh((value) => value + 1)
        } catch (error) {
          message.error(error instanceof Error ? error.message : '任务关闭失败')
        }
      }}
    >关闭任务</Button> },
  ]
  return <><PageHeading title="任务中心" description="查看任务生命周期与资源归属；关闭任务会回收卡租约和邮箱会话。" /><Card>
    {loading ? <div className="centered"><Spin /></div> : <Table
      columns={columns}
      dataSource={rows}
      rowKey="id"
      locale={{ emptyText: <Empty description="暂无任务" /> }}
      scroll={{ x: 980 }}
      rowClassName={(row) => (row.id === selectedTaskId ? 'task-row-selected' : '')}
      onRow={(row) => ({
        onClick: () => setSelectedTaskId(row.id),
      })}
    />}
    {selectedTask && lifecycle ? <Card className="task-detail-card" title="任务详情" size="small">
      <Descriptions column={{ xs: 1, md: 2 }}>
        <Descriptions.Item label="任务标识">{selectedTask.id}</Descriptions.Item>
        <Descriptions.Item label="trace_id">{selectedTask.trace_id}</Descriptions.Item>
        <Descriptions.Item label="主状态"><StatusTag value={selectedTask.status} /></Descriptions.Item>
        <Descriptions.Item label="任务类型">{selectedTask.type}</Descriptions.Item>
        <Descriptions.Item label="幂等键">{selectedTask.idempotency_key}</Descriptions.Item>
        <Descriptions.Item label="客户端引用">{selectedTask.client_reference ?? '—'}</Descriptions.Item>
        <Descriptions.Item label="过期时间">{selectedTask.expires_at ?? '—'}</Descriptions.Item>
        <Descriptions.Item label="关闭时间">{selectedTask.closed_at ?? '—'}</Descriptions.Item>
        <Descriptions.Item label="设备">{selectedTask.device_id}</Descriptions.Item>
        <Descriptions.Item label="创建时间">{selectedTask.created_at}</Descriptions.Item>
      </Descriptions>
      <div className="task-lifecycle">
        <Text type="secondary">生命周期概览</Text>
        <Steps current={lifecycle.current} status={lifecycle.status} items={lifecycle.items} />
      </div>
    </Card> : null}
  </Card></>
}

function UploadsPage() {
  const { message } = AntApp.useApp()
  const [rows, setRows] = useState<UploadSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [refresh, setRefresh] = useState(0)
  const [reconcileTarget, setReconcileTarget] = useState<UploadSummary | null>(null)
  const [saving, setSaving] = useState(false)
  const [form] = Form.useForm<{ status: 'succeeded' | 'failed'; external_ref?: string; error_code?: string }>()
  useEffect(() => {
    let alive = true
    setLoading(true)
    listUploads().then((items) => {
      if (alive) setRows(items)
    }).catch(() => {
      if (alive) message.warning('上传列表暂不可用，请稍后刷新。')
    }).finally(() => {
      if (alive) setLoading(false)
    })
    return () => { alive = false }
  }, [message, refresh])
  const columns: TableColumnsType<UploadSummary> = [
    { title: '上传标识', dataIndex: 'id' },
    { title: '任务', dataIndex: 'task_id' },
    { title: '业务名称', dataIndex: 'business_name' },
    { title: '状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: '策略版本', dataIndex: 'policy_version' },
    { title: '创建时间', dataIndex: 'created_at' },
    { title: '操作', render: (_, row) => <Space>
      <Button
        disabled={!['queued', 'running'].includes(row.status)}
        onClick={async () => {
          try {
            await cancelUploadJob(row.id)
            message.success('已请求取消上传。')
            setRefresh((value) => value + 1)
          } catch (error) {
            message.error(error instanceof Error ? error.message : '取消失败')
          }
        }}
      >取消</Button>
      <Button
        type="primary"
        disabled={row.status !== 'unknown'}
        onClick={() => {
          form.resetFields()
          form.setFieldsValue({ status: 'failed' })
          setReconcileTarget(row)
        }}
      >复核</Button>
    </Space> },
  ]
  return <>
    <PageHeading title="Sub2 上传" description="平台代为提交；超时结果进入人工核对，不盲目重试。" />
    <Card>
      {loading ? <div className="centered"><Spin /></div> : <Table
        columns={columns}
        dataSource={rows}
        rowKey="id"
        locale={{ emptyText: <Empty description="暂无上传记录" /> }}
        scroll={{ x: 1040 }}
      />}
    </Card>
    <Modal
      open={reconcileTarget !== null}
      title="复核 unknown 上传"
      okText="提交复核"
      cancelText="取消"
      confirmLoading={saving}
      onCancel={() => {
        if (!saving) setReconcileTarget(null)
      }}
      onOk={async () => {
        if (!reconcileTarget) return
        try {
          const values = await form.validateFields()
          if (!values) return
          setSaving(true)
          await reconcileUploadJob(reconcileTarget.id, values)
          message.success('复核结果已提交。')
          setReconcileTarget(null)
          setRefresh((value) => value + 1)
        } catch (error) {
          if (error && typeof error === 'object' && 'errorFields' in error) {
            return
          }
          message.error(error instanceof Error ? error.message : '复核提交失败')
        } finally {
          setSaving(false)
        }
      }}
    >
      <Form form={form} layout="vertical" initialValues={{ status: 'failed' }}>
        <Form.Item label="复核结果" name="status" rules={[{ required: true }]}>
          <Select
            options={[
              { value: 'failed', label: '失败' },
              { value: 'succeeded', label: '成功' },
            ]}
          />
        </Form.Item>
        <Form.Item
          label="外部编号"
          name="external_ref"
          dependencies={['status']}
          rules={[({ getFieldValue }) => ({
            validator(_, value) {
              if (getFieldValue('status') === 'succeeded' && !String(value ?? '').trim()) {
                return Promise.reject(new Error('成功复核需要填写外部编号'))
              }
              return Promise.resolve()
            },
          })]}
        >
          <Input placeholder="Sub2 外部编号" />
        </Form.Item>
        <Form.Item label="错误码" name="error_code">
          <Input placeholder="例如 manual_review_needed" />
        </Form.Item>
      </Form>
    </Modal>
  </>
}

function AuditPage() {
  const [filters, setFilters] = useState({ traceId: '', userId: '', entityId: '', eventType: '' })
  const [applied, setApplied] = useState(filters)
  const loader = useCallback(() => listAuditEvents(applied), [applied])
  const columns: TableColumnsType<AuditEvent> = [
    { title: '时间', dataIndex: 'created_at' },
    { title: '动作', dataIndex: 'event_type' },
    { title: '操作者', dataIndex: 'user_id', render: (value) => value ?? '系统' },
    { title: '对象', render: (_, row) => `${row.entity_type}${row.entity_id ? ` / ${row.entity_id}` : ''}` },
    { title: '追踪号', dataIndex: 'trace_id', render: (value) => value ?? '—' },
  ]
  return <><PageHeading title="审计中心" description="按操作者、对象、动作和 trace_id 定位全链路记录。" /><Card>
    <Space wrap className="section-card">
      <Input placeholder="trace_id" value={filters.traceId} onChange={(event) => setFilters({ ...filters, traceId: event.target.value })} />
      <Input placeholder="操作者 user_id" value={filters.userId} onChange={(event) => setFilters({ ...filters, userId: event.target.value })} />
      <Input placeholder="对象 entity_id" value={filters.entityId} onChange={(event) => setFilters({ ...filters, entityId: event.target.value })} />
      <Input placeholder="动作 event_type" value={filters.eventType} onChange={(event) => setFilters({ ...filters, eventType: event.target.value })} />
      <Button type="primary" onClick={() => setApplied({ ...filters })}>检索</Button>
      <Button onClick={() => { const empty = { traceId: '', userId: '', entityId: '', eventType: '' }; setFilters(empty); setApplied(empty) }}>清空</Button>
    </Space>
    <RemoteTable loader={loader} columns={columns} empty="暂无审计事件" />
  </Card></>
}

function PoliciesPage({ principal }: { principal: Principal }) {
  const { message } = AntApp.useApp()
  const [form] = Form.useForm<{ version: string; change_note: string }>()
  const [policy, setPolicy] = useState<UploadPolicyStatus>()
  const [versions, setVersions] = useState<UploadPolicyVersion[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [refresh, setRefresh] = useState(0)
  const isPlatformAdmin = principal.role === 'platform_admin'
  useEffect(() => {
    let alive = true
    setLoading(true)
    Promise.all([getUploadPolicyStatus(), listUploadPolicyVersions()]).then(([value, policyVersions]) => {
      if (alive) {
        setPolicy(value)
        setVersions(policyVersions)
        setError(undefined)
      }
    }).catch(() => {
      if (alive) setError('策略状态暂不可用，请稍后刷新。')
    }).finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [refresh])

  const perform = async (operation: () => Promise<unknown>, success: string) => {
    try {
      await operation()
      message.success(success)
      setRefresh((value) => value + 1)
    } catch {
      message.error('操作未完成，请刷新状态后重试。')
    }
  }

  if (loading) return <div className="centered"><Spin /></div>
  if (error || !policy) return <Alert type="warning" showIcon message="策略配置暂不可用" description={error ?? '未读取到策略状态'} />
  const columns: TableColumnsType<UploadPolicyVersion> = [
    { title: '版本', dataIndex: 'version' },
    { title: '状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: '变更说明', dataIndex: 'change_note' },
    { title: '创建时间', dataIndex: 'created_at' },
    {
      title: '审批',
      render: (_, row) => row.approved_by ? `已审批 · ${row.approved_by.slice(0, 8)}` : '待审批',
    },
    {
      title: '操作',
      render: (_, row) => !isPlatformAdmin ? '只读' : <Space wrap>
        {row.status === 'draft' ? <Button
          disabled={row.created_by === principal.id}
          onClick={() => perform(() => approveUploadPolicyVersion(row.id), '策略已通过独立审批。')}
        >审批</Button> : null}
        {row.status === 'approved' ? <>
          {policy.governance_configured ? <Button
            onClick={() => perform(() => deployUploadPolicyVersion(row.id, 10), '已开始 10% 灰度。')}
          >灰度 10%</Button> : null}
          <Button type="primary" onClick={() => perform(
            () => deployUploadPolicyVersion(row.id, 100),
            '策略已全量启用。',
          )}>全量启用</Button>
        </> : null}
        {row.status === 'active' && row.version === policy.active_version && policy.previous_version ? <>
          <Button onClick={() => perform(
            () => deployUploadPolicyVersion(row.id, 50),
            '灰度比例已调整为 50%。',
          )}>调整为 50%</Button>
          <Button onClick={() => perform(
            () => deployUploadPolicyVersion(row.id, 100),
            '策略已扩展至 100%。',
          )}>扩展至 100%</Button>
        </> : null}
      </Space>,
    },
  ]
  return <>
    <PageHeading title="策略配置" description="策略快照经独立审批后灰度发布；基础设施密钥与执行参数不进入浏览器。" />
    {policy.status !== 'ready' ? <Alert
      className="section-card"
      type="warning"
      showIcon
      message="上传策略尚未完整配置"
      description="请在服务端完成上传接口、上传密钥和网络路径配置后再开放生产上传。"
    /> : null}
    <Card title="Sub2 上传策略">
      <Descriptions column={{ xs: 1, md: 2 }}>
        <Descriptions.Item label="策略版本">{policy.policy_version}</Descriptions.Item>
        <Descriptions.Item label="整体状态"><StatusTag value={policy.status} /></Descriptions.Item>
        <Descriptions.Item label="服务端托管">{policy.server_managed ? '是' : '否'}</Descriptions.Item>
        <Descriptions.Item label="上传接口">{policy.upload_endpoint_configured ? '已配置' : '未配置'}</Descriptions.Item>
        <Descriptions.Item label="上传密钥">{policy.upload_secret_configured ? '已配置' : '未配置'}</Descriptions.Item>
        <Descriptions.Item label="网络路径">{policy.network_route_configured ? '已配置' : '未配置'}</Descriptions.Item>
        <Descriptions.Item label="治理状态">{policy.governance_configured ? '已启用' : '未启用'}</Descriptions.Item>
        <Descriptions.Item label="当前生效">{policy.active_version ?? '使用服务端默认配置'}</Descriptions.Item>
        <Descriptions.Item label="上一版本">{policy.previous_version ?? '无'}</Descriptions.Item>
        <Descriptions.Item label="灰度比例">{policy.rollout_percent === null ? '未设置' : `${policy.rollout_percent}%`}</Descriptions.Item>
      </Descriptions>
    </Card>
    {isPlatformAdmin ? <Card className="section-card" title="注册服务端策略快照">
      <Alert
        className="section-card"
        type="info"
        showIcon
        message="这里只登记版本和变更说明"
        description="代理、分组、并发、凭据引用均从当前服务端配置生成快照，不允许通过浏览器提交。创建人不能审批自己的版本。"
      />
      <Form
        form={form}
        layout="inline"
        onFinish={(values) => perform(
          async () => {
            await registerUploadPolicyVersion(values)
            form.resetFields()
          },
          '策略快照已登记，等待另一位管理员审批。',
        )}
      >
        <Form.Item name="version" rules={[
          { required: true, message: '请输入版本号' },
          { pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/, message: '仅允许字母、数字、点、横线和下划线' },
        ]}>
          <Input placeholder="例如 sub2-2026.08.1" maxLength={80} />
        </Form.Item>
        <Form.Item name="change_note" rules={[{ required: true, message: '请输入变更说明' }]}>
          <Input placeholder="变更说明" maxLength={500} />
        </Form.Item>
        <Button type="primary" htmlType="submit">登记快照</Button>
      </Form>
    </Card> : null}
    <Card
      className="section-card"
      title="策略版本"
      extra={isPlatformAdmin && policy.previous_version ? <Button danger onClick={() => {
        Modal.confirm({
          title: '确认回滚上传策略？',
          content: `将恢复 ${policy.previous_version}，新任务立即使用上一版本；已排队任务仍使用原快照。`,
          okText: '确认回滚',
          cancelText: '取消',
          onOk: () => perform(rollbackUploadPolicy, '策略已回滚。'),
        })
      }}>回滚上一版本</Button> : null}
    >
      <Table
        columns={columns}
        dataSource={versions}
        rowKey="id"
        pagination={false}
        locale={{ emptyText: <Empty description="尚未登记策略版本" /> }}
        scroll={{ x: 980 }}
      />
    </Card>
  </>
}

function Shell({ principal, onLogout }: { principal: Principal; onLogout: () => void }) {
  const [view, setView] = useState<ViewKey>('dashboard')
  const allowedViews = roleViews[principal.role] ?? roleViews.operator
  const visibleMenuItems = menuItems?.filter((item) => item && allowedViews.has(String(item.key) as ViewKey))
  const content = useMemo(() => ({
    dashboard: <Dashboard />,
    tasks: <TasksPage />,
    cards: <CardsPage canManage={principal.role === 'ops_admin' || principal.role === 'platform_admin'} />,
    mailboxes: <MailboxesPage canManage={principal.role === 'ops_admin' || principal.role === 'platform_admin'} />,
    uploads: <UploadsPage />,
    users: <UsersPage />,
    audit: <AuditPage />,
    policies: <PoliciesPage principal={principal} />,
  })[view], [view, principal])
  return <Layout className="app-shell">
    <Sider width={240} theme="light" className="sidebar" breakpoint="lg" collapsedWidth="0">
      <div className="brand"><SafetyCertificateOutlined /><span>验证码平台</span></div>
      <Menu mode="inline" selectedKeys={[view]} items={visibleMenuItems} onClick={({ key }) => setView(key as ViewKey)} />
    </Sider>
    <Layout>
      <Header className="topbar">
        <div><Text strong>{principal.email}</Text><Tag>{roleNames[principal.role] ?? principal.role}</Tag></div>
        <Button onClick={onLogout}>退出登录</Button>
      </Header>
      <Content className="content">{content}</Content>
    </Layout>
  </Layout>
}

export default function App() {
  const [principal, setPrincipal] = useState<Principal | null>(null)
  const [authConfig, setAuthConfig] = useState<AuthConfig | null>(null)
  const [oidcManager, setOidcManager] = useState<UserManager | null>(null)
  const [startupError, setStartupError] = useState<string>()

  useEffect(() => {
    const handleExpired = () => {
      clearSession()
      setPrincipal(null)
    }
    window.addEventListener('platform:auth-expired', handleExpired)
    return () => window.removeEventListener('platform:auth-expired', handleExpired)
  }, [])

  useEffect(() => {
    let active = true
    async function initialize() {
      try {
        const config = await getAuthConfig()
        if (!active) return
        setAuthConfig(config)
        if (config.mode !== 'oidc') return
        const manager = createOidcManager(config)
        setOidcManager(manager)
        const search = new URLSearchParams(window.location.search)
        if (search.has('code') && search.has('state')) {
          const user = await manager.signinRedirectCallback()
          const expiresIn = user.expires_at ? Math.max(1, user.expires_at - Math.floor(Date.now() / 1000)) : undefined
          setBearer(user.access_token, expiresIn)
          window.history.replaceState({}, document.title, '/')
          setPrincipal(await getMe())
        }
      } catch (error) {
        if (active) setStartupError(error instanceof Error ? error.message : '身份服务初始化失败')
      }
    }
    initialize()
    return () => { active = false }
  }, [])

  async function logout() {
    clearSession()
    setPrincipal(null)
    if (authConfig?.mode === 'oidc' && oidcManager) {
      await oidcManager.signoutRedirect().catch(() => undefined)
    }
  }

  if (startupError) return <AntApp><main className="startup-state"><Alert showIcon type="error" message="控制台无法启动" description={startupError} /></main></AntApp>
  if (!authConfig) return <main className="startup-state"><Spin size="large" /></main>
  return <AntApp>{principal
    ? <Shell principal={principal} onLogout={logout} />
    : <LoginScreen authConfig={authConfig} oidcManager={oidcManager} onReady={setPrincipal} />}
  </AntApp>
}
