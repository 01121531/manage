import { Component, Suspense, lazy, useEffect, useRef, useState, type ReactNode } from 'react'
import {
  AuditOutlined,
  BankOutlined,
  CloudUploadOutlined,
  ClockCircleOutlined,
  DashboardOutlined,
  LaptopOutlined,
  LockOutlined,
  LogoutOutlined,
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
  ConfigProvider,
  Empty,
  Layout,
  Menu,
  Modal,
  Space,
  Spin,
  Tag,
  Typography,
} from 'antd'
import type { MenuProps } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import type { UserManager } from 'oidc-client-ts'
import { getSessionRemainingSeconds } from './api'
import type { Principal } from './types'
import './authenticated.css'

const { Header, Content, Sider } = Layout
const { Text } = Typography

type ViewKey = 'dashboard' | 'tasks' | 'cards' | 'mailboxes' | 'uploads' | 'users' | 'audit' | 'policies'

const menuItems: MenuProps['items'] = [
  { key: 'dashboard', icon: <DashboardOutlined />, label: '工作台' },
  { key: 'tasks', icon: <UnorderedListOutlined />, label: '任务中心' },
  { key: 'cards', icon: <BankOutlined />, label: '卡池管理' },
  { key: 'mailboxes', icon: <MailOutlined />, label: '邮箱池管理' },
  { key: 'uploads', icon: <CloudUploadOutlined />, label: 'Sub2 上传' },
  { key: 'users', icon: <TeamOutlined />, label: '用户与权限' },
  { key: 'audit', icon: <AuditOutlined />, label: '审计中心' },
  { key: 'policies', icon: <SettingOutlined />, label: '策略配置' },
]

const roleViews: Record<string, ReadonlySet<ViewKey>> = {
  operator: new Set(['dashboard', 'tasks']),
  ops_admin: new Set(['dashboard', 'tasks', 'cards', 'mailboxes', 'uploads', 'users', 'policies']),
  security_auditor: new Set(['dashboard', 'uploads', 'audit']),
  platform_admin: new Set(['dashboard', 'cards', 'mailboxes', 'uploads', 'users', 'audit', 'policies']),
  worker_service: new Set(),
}
const noRoleViews: ReadonlySet<ViewKey> = new Set()

const roleNames: Record<string, string> = {
  operator: '操作员',
  ops_admin: '运营管理员',
  security_auditor: '安全审计员',
  platform_admin: '平台管理员',
  worker_service: '后台服务',
}

const DashboardView = lazy(() => import('./views/DashboardView'))
const TasksView = lazy(() => import('./views/TasksView'))
const CardsView = lazy(() => import('./views/CardsView'))
const MailboxesView = lazy(() => import('./views/MailboxesView'))
const UploadsView = lazy(() => import('./views/UploadsView'))
const UsersView = lazy(() => import('./views/UsersView'))
const AuditView = lazy(() => import('./views/AuditView'))
const PoliciesView = lazy(() => import('./views/PoliciesView'))

function ViewLoading() {
  return (
    <section className="centered" role="status" aria-live="polite" aria-busy="true">
      <Space direction="vertical" align="center" size={12}>
        <Spin size="large" />
        <Text>正在加载页面…</Text>
      </Space>
    </section>
  )
}

class ViewLoadBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  render() {
    if (!this.state.failed) return this.props.children
    return (
      <section className="centered">
        <Alert
          type="error"
          showIcon
          message="页面资源加载失败"
          description="原因：页面资源未能完成下载。影响：当前页面暂不可用，当前内存会话尚未改变。下一步：可先切换其他页面，或重新加载控制台后重新登录；重新加载本身不代表服务端资源已经回收。"
          action={<Button onClick={() => window.location.reload()}>重新加载控制台</Button>}
        />
      </section>
    )
  }
}

function ViewContent({ view, principal, oidcManager, roleChangeAcr }: {
  view: ViewKey
  principal: Principal
  oidcManager: UserManager | null
  roleChangeAcr: string | null
}) {
  switch (view) {
    case 'dashboard':
      return <DashboardView principal={principal} />
    case 'tasks':
      return <TasksView principal={principal} />
    case 'cards':
      return <CardsView
        canManage={principal.role === 'ops_admin' || principal.role === 'platform_admin'}
        canReleaseQuarantine={principal.role === 'platform_admin'}
      />
    case 'mailboxes':
      return <MailboxesView canManage={principal.role === 'ops_admin' || principal.role === 'platform_admin'} />
    case 'uploads':
      return <UploadsView principal={principal} />
    case 'users':
      return <UsersView principal={principal} oidcManager={oidcManager} roleChangeAcr={roleChangeAcr} />
    case 'audit':
      return <AuditView />
    case 'policies':
      return <PoliciesView principal={principal} />
  }
}

function formatSessionRemaining(seconds: number | null): string {
  if (seconds === null) return '到期时间未知'
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const remainder = seconds % 60
  return hours > 0
    ? `${hours}:${String(minutes).padStart(2, '0')}:${String(remainder).padStart(2, '0')}`
    : `${String(minutes).padStart(2, '0')}:${String(remainder).padStart(2, '0')}`
}

export default function AuthenticatedShell({ principal, oidcManager, roleChangeAcr, onLock, onLogout, onRevokeCurrentDevice, logoutPending, deviceRevokePending, logoutError }: {
  principal: Principal
  oidcManager: UserManager | null
  roleChangeAcr: string | null
  onLock: () => void
  onLogout: () => void
  onRevokeCurrentDevice: () => Promise<void>
  logoutPending: boolean
  deviceRevokePending: boolean
  logoutError?: { title: string; description: string }
}) {
  const [view, setView] = useState<ViewKey>('dashboard')
  const deviceRevokeDialogRef = useRef<ReturnType<typeof Modal.confirm> | null>(null)
  const [remainingSeconds, setRemainingSeconds] = useState<number | null>(
    () => getSessionRemainingSeconds(),
  )
  useEffect(() => {
    const update = () => setRemainingSeconds(getSessionRemainingSeconds())
    update()
    const timer = window.setInterval(update, 1000)
    return () => window.clearInterval(timer)
  }, [])
  useEffect(() => () => {
    const dialog = deviceRevokeDialogRef.current
    deviceRevokeDialogRef.current = null
    dialog?.destroy()
  }, [])
  const allowedViews = roleViews[principal.role] ?? noRoleViews
  const visibleMenuItems = menuItems?.filter((item) => item && allowedViews.has(String(item.key) as ViewKey))
  const content = allowedViews.has(view)
    ? (
      <ViewLoadBoundary key={view}>
        <Suspense fallback={<ViewLoading />}>
          <ViewContent
            view={view}
            principal={principal}
            oidcManager={oidcManager}
            roleChangeAcr={roleChangeAcr}
          />
        </Suspense>
      </ViewLoadBoundary>
    )
    : <Empty description="当前角色没有可用页面" />
  function confirmCurrentDeviceRevoke() {
    if (deviceRevokeDialogRef.current || logoutPending || deviceRevokePending) return
    const dialog = Modal.confirm({
      title: '确认撤销当前设备？',
      content: <Space direction="vertical" size={8}>
        <Text>当前设备：{principal.device_id}</Text>
        <Text type="danger">撤销后当前设备令牌立即失效，活动任务、卡租约和邮箱会话将进入服务端回收流程。</Text>
        <Text type="secondary">无论服务端确认成功还是响应途中丢失，本地会话都会清除；客户端不会再调用已撤销令牌执行退出。</Text>
      </Space>,
      okText: '撤销设备并清理本地会话',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: onRevokeCurrentDevice,
      onCancel: () => { deviceRevokeDialogRef.current = null },
      afterClose: () => { deviceRevokeDialogRef.current = null },
    })
    deviceRevokeDialogRef.current = dialog
  }
  return <ConfigProvider
    locale={zhCN}
    theme={{
      token: {
        colorPrimary: '#176b87',
        colorInfo: '#176b87',
        colorSuccess: '#17825c',
        colorWarning: '#b86b11',
        colorError: '#c53b3b',
        borderRadius: 8,
        fontFamily: "Inter, 'Microsoft YaHei UI', 'PingFang SC', sans-serif",
      },
    }}
  ><AntApp>
    <a className="skip-link" href="#main-content">跳到主内容</a>
    <Layout className="app-shell">
    <Sider width={240} theme="light" className="sidebar" breakpoint="lg" collapsedWidth="0">
      <div className="brand"><SafetyCertificateOutlined /><span>验证码平台</span></div>
      <Menu mode="inline" selectedKeys={[view]} items={visibleMenuItems} onClick={({ key }) => setView(key as ViewKey)} />
    </Sider>
    <Layout>
      <Header className="topbar">
        <div className="topbar-identity">
          <div className="topbar-primary"><Text strong>{principal.email}</Text><Tag>{roleNames[principal.role] ?? principal.role}</Tag></div>
          <div className="topbar-meta" aria-label="当前安全会话">
            <Tag icon={<TeamOutlined />}>组织 {principal.tenant_id}</Tag>
            <Tag icon={<LaptopOutlined />}>设备 {principal.device_id}</Tag>
            <Tag
              icon={<ClockCircleOutlined />}
              color={remainingSeconds !== null && remainingSeconds <= 60 ? 'warning' : undefined}
            >
              <span
                className="session-timer"
                role="timer"
                aria-label={`会话剩余 ${formatSessionRemaining(remainingSeconds)}`}
              >会话 {formatSessionRemaining(remainingSeconds)}</span>
            </Tag>
          </div>
        </div>
        <div className="topbar-actions">
          <Button
            danger
            icon={<LaptopOutlined />}
            loading={deviceRevokePending}
            disabled={logoutPending || deviceRevokePending}
            onClick={confirmCurrentDeviceRevoke}
          >撤销当前设备</Button>
          <Button icon={<LockOutlined />} disabled={logoutPending || deviceRevokePending} onClick={onLock}>锁定</Button>
          <Button icon={<LogoutOutlined />} loading={logoutPending} disabled={logoutPending || deviceRevokePending} onClick={onLogout}>退出登录</Button>
        </div>
      </Header>
      <Content id="main-content" tabIndex={-1} className="content">
        {logoutError ? <Alert
          className="section-card"
          type="error"
          showIcon
          message={logoutError.title}
          description={logoutError.description}
        /> : null}
        {content}
      </Content>
    </Layout>
  </Layout></AntApp></ConfigProvider>
}
