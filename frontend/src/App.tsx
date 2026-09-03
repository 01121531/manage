import { Component, Suspense, lazy, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import {
  ApiError,
  clearSession,
  getAuthConfig,
  getMe,
  login,
  logoutSession,
  revokeCurrentDevice,
  setBearer,
} from './api'
import type { UserManager } from 'oidc-client-ts'
import type { AuthConfig, Principal } from './types'

function ShieldIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M12 2.5 20 6v5.6c0 4.9-3.3 8.3-8 9.9-4.7-1.6-8-5-8-9.9V6l8-3.5Zm0 2.2L6 7.3v4.3c0 3.7 2.3 6.3 6 7.7 3.7-1.4 6-4 6-7.7V7.3l-6-2.6Zm-1.1 10.5-3-3 1.4-1.4 1.6 1.6 3.8-3.8 1.4 1.4-5.2 5.2Z" />
  </svg>
}

function StatusAlert({ type, title, description, action }: {
  type: 'error' | 'success' | 'warning'
  title: string
  description: string
  action?: ReactNode
}) {
  return <div className={`status-alert status-alert-${type}`} role="alert">
    <span className="status-alert-icon" aria-hidden="true">{type === 'success' ? '✓' : '!'}</span>
    <div className="status-alert-copy">
      <strong>{title}</strong>
      <p>{description}</p>
    </div>
    {action ? <div className="status-alert-action">{action}</div> : null}
  </div>
}

function LoadingState({ label = '正在加载控制台…' }: { label?: string }) {
  return <main className="startup-state" aria-label={label}>
    <div className="startup-loading" role="status" aria-live="polite" aria-busy="true">
      <span className="native-spinner" aria-hidden="true" />
      <span>{label}</span>
    </div>
  </main>
}

function LoginScreen({ authConfig, oidcManager, onReady, sessionNotice }: {
  authConfig: AuthConfig
  oidcManager: UserManager | null
  onReady: (principal: Principal) => void
  sessionNotice?: { type: 'success' | 'warning'; message: string; description: string }
}) {
  const [loading, setLoading] = useState(false)
  const [loginError, setLoginError] = useState<string>()
  const [passwordVisible, setPasswordVisible] = useState(false)
  const loginActionRef = useRef<object | null>(null)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (loginActionRef.current !== null) return
    const fields = new FormData(event.currentTarget)
    const values = {
      tenant_id: String(fields.get('tenant_id') ?? ''),
      email: String(fields.get('email') ?? ''),
      password: String(fields.get('password') ?? ''),
      device_id: String(fields.get('device_id') ?? ''),
    }
    const action = {}
    loginActionRef.current = action
    setLoginError(undefined)
    setLoading(true)
    let bearerIssued = false
    try {
      await login(values)
      bearerIssued = true
      onReady(await getMe())
    } catch (error) {
      if (!bearerIssued) {
        const detail = error instanceof ApiError && error.traceId ? `（追踪号：${error.traceId}）` : ''
        const explicitlyRejected = error instanceof ApiError
          && error.status >= 400
          && error.status < 500
          && error.status !== 408
        setLoginError((explicitlyRejected
          ? '原因：平台明确拒绝了登录请求。影响：未建立可用登录会话。下一步：核对租户、账号、密码和设备标识后重试。'
          : '原因：平台未能确认登录请求结果。影响：浏览器未收到可用令牌，但服务端设备会话可能已经建立。下一步：请使用相同设备标识重试；持续失败请联系管理员核对设备会话。') + detail)
      } else {
        let cleanupConfirmed = false
        try {
          await logoutSession()
          cleanupConfirmed = true
        } catch {
          cleanupConfirmed = false
        } finally {
          clearSession()
        }
        setLoginError(cleanupConfirmed
          ? '原因：平台未能建立可用的控制台身份。影响：刚签发的会话已确认撤销，本地令牌已清除。下一步：检查账号权限或网络后重试。'
          : '原因：平台未能建立可用的控制台身份。影响：本地令牌已清除，但服务端当前设备会话及关联资源未确认回收。下一步：检查网络后重试；持续失败请联系管理员核对当前设备资源。')
      }
    } finally {
      if (loginActionRef.current === action) {
        loginActionRef.current = null
        setLoading(false)
      }
    }
  }

  async function beginOidcLogin() {
    if (!oidcManager || loginActionRef.current !== null) return
    const action = {}
    loginActionRef.current = action
    setLoginError(undefined)
    setLoading(true)
    try {
      await oidcManager.signinRedirect()
    } catch {
      setLoginError('原因：统一身份登录未能启动。影响：浏览器尚未建立平台会话。下一步：检查身份服务和网络后重试。')
    } finally {
      if (loginActionRef.current === action) {
        loginActionRef.current = null
        setLoading(false)
      }
    }
  }

  return (
    <main className="login-shell">
      <section className="login-intro">
        <div className="brand-mark"><ShieldIcon /></div>
        <span className="eyebrow">SECURE OPERATIONS</span>
        <h1>验证码业务平台</h1>
        <p>统一管理任务、卡分配、邮箱取码和 Sub2 上传。敏感上游配置只保留在服务端。</p>
        <ul className="login-features">
          <li><span aria-hidden="true">◆</span>设备绑定会话</li>
          <li><span aria-hidden="true">✓</span>全链路操作审计</li>
          <li><span aria-hidden="true">▣</span>卡信息按人分配与追溯</li>
        </ul>
      </section>
      <section className="login-card" aria-labelledby="login-title">
        <span className="eyebrow">运营控制台</span>
        <h2 id="login-title">登录平台</h2>
        <p className="login-description">{authConfig.mode === 'oidc' ? '通过统一身份中心完成 PKCE 安全登录。' : '本地账号仅用于开发与联调环境。'}</p>
        {sessionNotice ? <StatusAlert
          type={sessionNotice.type}
          title={sessionNotice.message}
          description={sessionNotice.description}
        /> : null}
        {loginError ? <StatusAlert type="error" title="登录未完成" description={loginError} /> : null}
        {authConfig.mode === 'oidc' ? (
          <button
            type="button"
            className={`login-button${loading ? ' ant-btn-loading' : ''}`}
            aria-label="统一身份登录"
            onClick={beginOidcLogin}
            disabled={loading || !oidcManager}
          ><ShieldIcon />{loading ? '正在跳转…' : '统一身份登录'}</button>
        ) : <form className="login-form" onSubmit={submit}>
          <fieldset disabled={loading}>
            <label htmlFor="tenant_id">租户 <span>必填</span></label>
            <input id="tenant_id" name="tenant_id" required autoComplete="organization" placeholder="tenant-a" />
            <label htmlFor="email">平台账号 <span>必填</span></label>
            <input id="email" name="email" required type="email" autoComplete="username" placeholder="name@example.invalid" />
            <label htmlFor="password">平台密码 <span>必填</span></label>
            <div className="password-field">
              <input id="password" name="password" required type={passwordVisible ? 'text' : 'password'} autoComplete="current-password" />
              <button
                type="button"
                className="password-toggle"
                aria-label={passwordVisible ? '隐藏密码' : '显示密码'}
                onClick={() => setPasswordVisible((visible) => !visible)}
              >{passwordVisible ? '隐藏' : '显示'}</button>
            </div>
            <label htmlFor="device_id">设备标识 <span>必填</span></label>
            <input id="device_id" name="device_id" required autoComplete="off" placeholder="ops-console-01" />
            <button className={`login-button${loading ? ' ant-btn-loading' : ''}`} type="submit" aria-label="安全登录" disabled={loading}>
              {loading ? <><span className="button-spinner" aria-hidden="true" />正在登录…</> : '安全登录'}
            </button>
          </fieldset>
        </form>}
      </section>
    </main>
  )
}


const AuthenticatedShell = lazy(() => import('./AuthenticatedShell'))

class ShellLoadBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  render() {
    if (!this.state.failed) return this.props.children
    return <main className="startup-state">
      <StatusAlert
        type="error"
        title="控制台资源加载失败"
        description="原因：登录后控制台资源未能完成下载。影响：当前内存会话尚未改变，但管理页面暂不可用。下一步：重新加载后重新登录；重新加载本身不代表服务端资源已经回收。"
        action={<button className="startup-action" onClick={() => window.location.reload()}>重新加载控制台</button>}
      />
    </main>
  }
}

export default function App() {
  const [principal, setPrincipal] = useState<Principal | null>(null)
  const [authConfig, setAuthConfig] = useState<AuthConfig | null>(null)
  const [oidcManager, setOidcManager] = useState<UserManager | null>(null)
  const [startupError, setStartupError] = useState<string>()
  const [logoutPending, setLogoutPending] = useState(false)
  const [deviceRevokePending, setDeviceRevokePending] = useState(false)
  const [oidcCleanupPending, setOidcCleanupPending] = useState(false)
  const [oidcCleanupError, setOidcCleanupError] = useState(false)
  const [logoutError, setLogoutError] = useState<{ title: string; description: string }>()
  const [sessionNotice, setSessionNotice] = useState<{
    type: 'success' | 'warning'
    message: string
    description: string
  }>()
  const logoutActionRef = useRef<Promise<void> | null>(null)
  const deviceRevokeActionRef = useRef<object | null>(null)
  const oidcCleanupActionRef = useRef<Promise<void> | null>(null)
  const sessionGenerationRef = useRef(0)

  function clearOidcUser(manager: UserManager | null = oidcManager) {
    if (!manager) return Promise.resolve()
    if (oidcCleanupActionRef.current) return oidcCleanupActionRef.current
    setOidcCleanupPending(true)
    setOidcCleanupError(false)
    let action: Promise<void>
    action = Promise.resolve()
      .then(() => manager.removeUser())
      .catch(() => { setOidcCleanupError(true) })
      .finally(() => {
        if (oidcCleanupActionRef.current === action) {
          oidcCleanupActionRef.current = null
          setOidcCleanupPending(false)
        }
      })
    oidcCleanupActionRef.current = action
    return action
  }

  useEffect(() => {
    const handleExpiring = () => startSessionExpiryCleanup()
    const handleExpired = () => {
      const cleanupWasPending = logoutActionRef.current !== null
      const deviceRevokeWasPending = deviceRevokeActionRef.current !== null
      sessionGenerationRef.current += 1
      logoutActionRef.current = null
      setLogoutPending(false)
      deviceRevokeActionRef.current = null
      setDeviceRevokePending(false)
      clearSession()
      setPrincipal(null)
      setLogoutError(undefined)
      void clearOidcUser()
      setSessionNotice({
        type: 'warning',
        message: '平台会话已到期，本地登录状态已清除',
        description: deviceRevokeWasPending
          ? '当前设备撤销请求未能在令牌有效期内确认。撤销与当前设备关联资源的最终状态仍需核对；请使用其他有效设备重新登录后查看设备和任务中心，不能把响应缺失视为撤销成功或失败。'
          : cleanupWasPending
            ? '到期前的服务端清理请求未能在令牌有效期内确认。平台任务、邮箱会话、卡租约和待处理出站事件的回收状态仍需核对；请重新登录后查看任务中心，或联系管理员按 trace_id 检查。'
            : '平台未确认到期前已回收当前设备资源。任务、邮箱会话、卡租约和待处理出站事件可能仍需等待服务端 TTL 或补偿流程；请重新登录后核对，不能视为已经回收。',
      })
    }
    window.addEventListener('platform:auth-expiring', handleExpiring)
    window.addEventListener('platform:auth-expired', handleExpired)
    return () => {
      window.removeEventListener('platform:auth-expiring', handleExpiring)
      window.removeEventListener('platform:auth-expired', handleExpired)
    }
  }, [authConfig, oidcManager])

  useEffect(() => {
    let active = true
    async function initialize() {
      try {
        const config = await getAuthConfig()
        if (!active) return
        if (config.mode !== 'oidc') {
          setAuthConfig(config)
          return
        }
        const { createOidcManager } = await import('./oidc')
        if (!active) return
        const manager = createOidcManager(config)
        const search = new URLSearchParams(window.location.search)
        if (search.has('code') && search.has('state')) {
          const user = await manager.signinRedirectCallback()
          if (!active) {
            await manager.removeUser().catch(() => undefined)
            return
          }
          const expiresIn = user.expires_at ? Math.max(1, user.expires_at - Math.floor(Date.now() / 1000)) : undefined
          const generation = sessionGenerationRef.current + 1
          sessionGenerationRef.current = generation
          setBearer(user.access_token, expiresIn)
          window.history.replaceState({}, document.title, '/')
          setSessionNotice(undefined)
          try {
            const profile = await getMe()
            if (sessionGenerationRef.current !== generation) {
              await manager.removeUser().catch(() => undefined)
              if (active) {
                setAuthConfig(config)
                setOidcManager(manager)
              }
              return
            }
            if (!active) throw new Error('OIDC callback is no longer active')
            setAuthConfig(config)
            setOidcManager(manager)
            setPrincipal(profile)
          } catch {
            let cleanupConfirmed = false
            try {
              await logoutSession()
              cleanupConfirmed = true
            } catch {
              // The callback bearer is still cleared locally below.
            } finally {
              if (sessionGenerationRef.current === generation) clearSession()
            }
            if (!active) {
              await manager.removeUser().catch(() => undefined)
              return
            }
            if (sessionGenerationRef.current !== generation) {
              await manager.removeUser().catch(() => undefined)
              setAuthConfig(config)
              setOidcManager(manager)
              return
            }
            setAuthConfig(config)
            setOidcManager(manager)
            setPrincipal(null)
            setStartupError(cleanupConfirmed
              ? '原因：平台未能建立可用的控制台身份。影响：刚签发的 OIDC 会话已确认撤销，本地令牌与身份缓存已清除。下一步：请重新发起统一身份登录。'
              : '原因：平台未能建立可用的控制台身份。影响：本地令牌与身份缓存已清除，但服务端当前设备会话及关联资源未确认回收。下一步：检查网络后重新发起统一身份登录；持续失败请联系管理员核对当前设备资源。')
            await clearOidcUser(manager)
          }
          return
        }
        setAuthConfig(config)
        setOidcManager(manager)
      } catch {
        if (active) setStartupError(
          '原因：身份服务配置或本地认证组件未能安全初始化。'
          + '影响：控制台未建立登录会话，也不会继续加载管理资源。'
          + '下一步：检查网络后重新加载控制台；持续失败请联系管理员核对身份服务。',
        )
      }
    }
    initialize()
    return () => { active = false }
  }, [])

  function startSessionExpiryCleanup() {
    if (logoutActionRef.current || deviceRevokeActionRef.current) return
    const generation = sessionGenerationRef.current
    setLogoutPending(true)
    setLogoutError(undefined)
    const action: Promise<void> = logoutSession().then(async () => {
      if (sessionGenerationRef.current !== generation) return
      clearSession()
      setPrincipal(null)
      setSessionNotice({
        type: 'success',
        message: '会话到期前已完成安全清理',
        description: '平台已确认回收当前设备关联的任务、邮箱会话、卡租约和待处理资源；本地令牌已清除，请重新登录后继续。',
      })
      await clearOidcUser()
    }).catch((error: unknown) => {
      if (sessionGenerationRef.current !== generation) return
      const detail = error instanceof Error ? error.message : '平台未能确认到期前安全清理。'
      setLogoutError({
        title: '会话到期前安全清理未完成',
        description: `原因：${detail} `
          + '影响：当前令牌在最终到期前仍保持登录，但平台尚未确认任务、邮箱会话、卡租约和待处理出站事件已回收。 '
          + '下一步：保持页面打开等待本地会话到期；到期后重新登录核对任务中心，不能把本次失败视为服务端已回收。',
      })
    }).finally(() => {
      if (logoutActionRef.current === action) {
        logoutActionRef.current = null
        setLogoutPending(false)
      }
    })
    logoutActionRef.current = action
  }

  function exitSession(intent: 'logout' | 'lock') {
    if (logoutActionRef.current || deviceRevokeActionRef.current) return
    const generation = sessionGenerationRef.current
    setLogoutPending(true)
    setLogoutError(undefined)
    setSessionNotice(undefined)
    const action: Promise<void> = logoutSession().then(async () => {
      if (sessionGenerationRef.current !== generation) return
      clearSession()
      setPrincipal(null)
      if (intent === 'lock') {
        setSessionNotice({
          type: 'success',
          message: '控制台已安全锁定',
          description: '平台已确认撤销当前设备会话并回收关联资源；本地身份已清除，请重新登录后继续。',
        })
        await clearOidcUser()
      } else if (authConfig?.mode === 'oidc' && oidcManager) {
        await oidcManager.signoutRedirect().catch(() => clearOidcUser())
      }
    }).catch((error: unknown) => {
      if (sessionGenerationRef.current !== generation) return
      const detail = error instanceof Error ? error.message : '平台暂时无法确认退出。'
      const actionName = intent === 'lock' ? '锁定' : '退出'
      setLogoutError({
        title: intent === 'lock' ? '安全锁定未完成' : '安全退出未完成',
        description: `原因：${detail} `
          + `影响：您仍保持登录，平台不会显示${actionName}成功。 `
          + `下一步：检查网络后再次点击“${intent === 'lock' ? '锁定' : '退出登录'}”。`,
      })
    }).finally(() => {
      if (logoutActionRef.current === action) {
        logoutActionRef.current = null
        setLogoutPending(false)
      }
    })
    logoutActionRef.current = action
  }

  function logout() {
    exitSession('logout')
  }

  function lock() {
    exitSession('lock')
  }

  async function revokeCurrentDeviceSession() {
    if (!principal || logoutActionRef.current || deviceRevokeActionRef.current) return
    const action = {}
    const generation = sessionGenerationRef.current
    const deviceId = principal.device_id
    let terminalOutcome: 'confirmed' | 'ambiguous' | undefined
    deviceRevokeActionRef.current = action
    setDeviceRevokePending(true)
    setLogoutError(undefined)
    setSessionNotice(undefined)
    try {
      await revokeCurrentDevice(deviceId)
      terminalOutcome = 'confirmed'
    } catch (error) {
      const explicitlyRejected = error instanceof ApiError
        && error.status >= 400
        && error.status < 500
        && error.status !== 408
        && error.code !== 'stale_session_response'
      if (explicitlyRejected) {
        if (sessionGenerationRef.current === generation) {
          setLogoutError({
            title: '当前设备撤销未完成',
            description: '原因：平台明确拒绝了本次撤销请求。影响：当前会话仍保持登录，本次请求未被视为已撤销。下一步：核对设备状态与操作权限后再次点击“撤销当前设备”。',
          })
        }
      } else {
        terminalOutcome = 'ambiguous'
      }
    } finally {
      if (terminalOutcome && sessionGenerationRef.current === generation) {
        sessionGenerationRef.current += 1
        clearSession()
        setPrincipal(null)
        setSessionNotice(terminalOutcome === 'confirmed' ? {
          type: 'success',
          message: '当前设备已撤销',
          description: '平台已确认撤销当前设备及其会话；本地令牌已经清除，不会再使用已撤销令牌调用退出接口。',
        } : {
          type: 'warning',
          message: '当前设备撤销结果待核对',
          description: '原因：撤销请求的最终响应未能安全确认。影响：本地令牌已按安全终态清除，不会再次用于退出或其他平台请求。下一步：重新登录后核对设备与任务状态；持续不一致时联系管理员。',
        })
        await clearOidcUser()
      }
      if (deviceRevokeActionRef.current === action) {
        deviceRevokeActionRef.current = null
        setDeviceRevokePending(false)
      }
    }
  }

  function loginReady(profile: Principal) {
    sessionGenerationRef.current += 1
    setLogoutError(undefined)
    setOidcCleanupError(false)
    setSessionNotice(undefined)
    setPrincipal(profile)
  }

  if (!principal && oidcCleanupError) return <main className="startup-state">
    <StatusAlert
      type="error"
      title="本地身份清理未完成"
      description="原因：浏览器未能确认旧的统一身份缓存已清除。影响：平台访问令牌已清除，但旧 OIDC 身份缓存未确认清除，新的统一身份登录入口暂不可用。下一步：点击“重试本地清理”；持续失败请重新加载或关闭当前平台页面，或联系管理员。"
      action={<button className="startup-action" onClick={() => { void clearOidcUser() }}>重试本地清理</button>}
    />
  </main>
  if (!principal && oidcCleanupPending) return <LoadingState label="正在清理本地身份，请稍候…" />
  if (startupError) return <main className="startup-state">
    <StatusAlert
      type="error"
      title="控制台无法启动"
      description={startupError}
      action={<button className="startup-action" onClick={() => window.location.reload()}>重新加载控制台</button>}
    />
  </main>
  if (!authConfig) return <LoadingState />
  return principal
    ? <ShellLoadBoundary>
      <Suspense fallback={<LoadingState label="正在加载管理控制台…" />}>
        <AuthenticatedShell
          principal={principal}
          oidcManager={oidcManager}
          roleChangeAcr={authConfig.admin_role_change_acr ?? null}
          onLock={lock}
          onLogout={logout}
          onRevokeCurrentDevice={revokeCurrentDeviceSession}
          logoutPending={logoutPending}
          deviceRevokePending={deviceRevokePending}
          logoutError={logoutError}
        />
      </Suspense>
    </ShellLoadBoundary>
    : deviceRevokePending || logoutPending || oidcCleanupPending
      ? <LoadingState label="正在清理本地身份，请稍候…" />
      : <LoginScreen
      authConfig={authConfig}
      oidcManager={oidcManager}
      onReady={loginReady}
      sessionNotice={sessionNotice}
    />
}
