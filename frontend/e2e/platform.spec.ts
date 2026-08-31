import { expect, test } from '@playwright/test'
import type { Page, Route } from '@playwright/test'

async function supportsDevelopmentModuleProbes(page: Page): Promise<boolean> {
  return page.locator('script[type="module"][src^="/src/"]').count().then((count) => count > 0)
}

async function delayNextOidcUserCleanup(page: Page): Promise<boolean> {
  if (!await supportsDevelopmentModuleProbes(page)) return false
  await page.evaluate(async () => {
    const oidcModulePath = '/src/oidc.ts'
    const oidc = await import(/* @vite-ignore */ oidcModulePath)
    const sample = oidc.createOidcManager({
      mode: 'oidc',
      issuer: 'https://prototype.example.invalid/realms/platform',
      client_id: 'web-console',
      desktop_client_id: 'desktop-client',
      audience: 'email-platform',
    })
    const prototype = Object.getPrototypeOf(sample) as { removeUser: () => Promise<void> }
    const originalRemoveUser = prototype.removeUser
    prototype.removeUser = function delayedRemoveUser(this: unknown) {
      return new Promise<void>((resolve) => {
        const browserWindow = window as typeof window & { releaseOidcUserCleanup?: () => Promise<void> }
        browserWindow.releaseOidcUserCleanup = async () => {
          prototype.removeUser = originalRemoveUser
          delete browserWindow.releaseOidcUserCleanup
          await originalRemoveUser.call(this)
          resolve()
        }
      })
    }
  })
  return true
}

async function releaseOidcUserCleanup(page: Page) {
  const released = await page.evaluate(async () => {
    const browserWindow = window as typeof window & { releaseOidcUserCleanup?: () => Promise<void> }
    const release = browserWindow.releaseOidcUserCleanup
    if (!release) return false
    await release()
    return true
  })
  expect(released).toBe(true)
}

async function failNextOidcUserCleanup(page: Page): Promise<boolean> {
  if (!await supportsDevelopmentModuleProbes(page)) return false
  await page.evaluate(async () => {
    const oidcModulePath = '/src/oidc.ts'
    const oidc = await import(/* @vite-ignore */ oidcModulePath)
    const sample = oidc.createOidcManager({
      mode: 'oidc',
      issuer: 'https://prototype.example.invalid/realms/platform',
      client_id: 'web-console',
      desktop_client_id: 'desktop-client',
      audience: 'email-platform',
    })
    const prototype = Object.getPrototypeOf(sample) as { removeUser: () => Promise<void> }
    const originalRemoveUser = prototype.removeUser
    prototype.removeUser = async function rejectedRemoveUser() {
      prototype.removeUser = originalRemoveUser
      throw new Error('raw oidc storage cleanup detail')
    }
  })
  return true
}

async function failNextOidcUserCleanupAfterNavigation(page: Page): Promise<boolean> {
  if (!await supportsDevelopmentModuleProbes(page)) return false
  await page.route('**/src/oidc.ts*', async (route) => {
    const response = await route.fetch()
    let body = await response.text()
    const constructorStart = 'return new UserManager({'
    const moduleEnd = '  });\n}\n\n//# sourceMappingURL'
    if (!body.includes(constructorStart) || !body.includes(moduleEnd)) {
      throw new Error('unable to install cross-navigation OIDC cleanup probe')
    }
    body = body
      .replace(constructorStart, 'const manager = new UserManager({')
      .replace(moduleEnd, `  });
  const originalRemoveUser = manager.removeUser.bind(manager);
  manager.removeUser = async () => {
    manager.removeUser = originalRemoveUser;
    throw new Error("raw oidc storage cleanup detail");
  };
  return manager;
}

//# sourceMappingURL`)
    await route.fulfill({ response, body })
  }, { times: 1 })
  return true
}

function isOidcRuntimeRequest(path: string): boolean {
  return path === '/src/oidc.ts'
    || path.startsWith('/node_modules/.vite/deps/oidc-client-ts')
    || /^\/assets\/oidc-[^/]+\.js$/.test(path)
}

function isAuthenticatedShellRequest(path: string): boolean {
  return path === '/src/AuthenticatedShell.tsx'
    || /^\/assets\/authenticated-shell-[^/]+\.js$/.test(path)
}

function isAuthenticatedShellStylesheetRequest(path: string): boolean {
  return path === '/src/authenticated.css'
    || /^\/assets\/authenticated-[^/]+\.css$/.test(path)
}

function isAdministratorUiRequest(path: string): boolean {
  return path.startsWith('/node_modules/.vite/deps/antd')
    || path.startsWith('/node_modules/.vite/deps/@ant-design_icons')
    || /^\/assets\/(?:antd-components|zh_CN|FastColor)-[^/]+\.js$/.test(path)
}

function isAdministratorApiRequest(path: string): boolean {
  return path === '/src/admin-api.ts'
    || /^\/assets\/admin-api-[^/]+\.js$/.test(path)
}

function isGenericVendorRequest(path: string): boolean {
  return /^\/assets\/vendor-[^/]+\.js$/.test(path)
}

async function exerciseOidcCallbackIdentityFailure(
  page: Page,
  cleanupStatus: 200 | 503,
  failLocalCleanup = false,
) {
  const issuer = 'https://callback-identity.example.invalid/realms/platform'
  const accessToken = `oidc-callback-access-${cleanupStatus}`
  const identityAuthorizations: string[] = []
  const cleanupAuthorizations: string[] = []
  let nonce = ''

  const fulfillJson = (route: Route, value: unknown, status = 200) => route.fulfill({
    status,
    contentType: 'application/json',
    headers: { 'access-control-allow-origin': '*' },
    body: JSON.stringify(value),
  })
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (path === '/api/v1/auth/config') {
      return fulfillJson(route, {
        mode: 'oidc', issuer, client_id: 'web-console',
        desktop_client_id: 'desktop-client', audience: 'email-platform',
      })
    }
    if (path === '/api/v1/me') {
      identityAuthorizations.push(request.headers().authorization ?? '')
      return fulfillJson(route, { error: { code: 'service_unavailable', message: 'sensitive upstream detail' } }, 503)
    }
    if (path === '/api/v1/auth/logout') {
      cleanupAuthorizations.push(request.headers().authorization ?? '')
      return cleanupStatus === 200
        ? fulfillJson(route, { status: 'logged_out' })
        : fulfillJson(route, { error: { code: 'service_unavailable', message: 'sensitive cleanup detail' } }, 503)
    }
    return fulfillJson(route, { error: { code: 'not_found', message: 'not found' } }, 404)
  })
  await page.route(`${issuer}/.well-known/openid-configuration`, async (route) => fulfillJson(route, {
    issuer,
    authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
    token_endpoint: `${issuer}/protocol/openid-connect/token`,
    jwks_uri: `${issuer}/protocol/openid-connect/certs`,
  }))
  await page.route(`${issuer}/protocol/openid-connect/auth**`, async (route) => {
    const requestUrl = new URL(route.request().url())
    const state = requestUrl.searchParams.get('state') ?? ''
    nonce = requestUrl.searchParams.get('nonce') ?? ''
    return route.fulfill({
      status: 302,
      headers: { location: `http://127.0.0.1:5173/callback?code=fixture-code&state=${encodeURIComponent(state)}` },
      body: '',
    })
  })
  await page.route(`${issuer}/protocol/openid-connect/token`, async (route) => {
    const now = Math.floor(Date.now() / 1000)
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url')
    const idToken = `${encode({ alg: 'none', typ: 'JWT' })}.${encode({
      iss: issuer,
      sub: 'oidc-callback-user',
      aud: 'web-console',
      exp: now + 900,
      iat: now,
      nonce,
    })}.fixture`
    return fulfillJson(route, {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      scope: 'openid profile email',
      id_token: idToken,
    })
  })

  await page.goto('/')
  const cleanupFailureProbe = failLocalCleanup && await failNextOidcUserCleanupAfterNavigation(page)
  await page.getByRole('button', { name: '统一身份登录' }).click()
  if (cleanupFailureProbe) {
    const cleanupFailure = page.getByRole('alert').filter({ hasText: '本地身份清理未完成' })
    await expect(cleanupFailure).toContainText('平台访问令牌已清除，但旧 OIDC 身份缓存未确认清除')
    await expect(cleanupFailure).toContainText('下一步：点击“重试本地清理”')
    await expect(cleanupFailure).not.toContainText('刚签发的 OIDC 会话已确认撤销')
    await expect(page.getByText('控制台无法启动')).toHaveCount(0)
    await expect(page.getByRole('button', { name: '统一身份登录' })).toHaveCount(0)
    await expect(page.getByText('raw oidc storage cleanup detail')).toHaveCount(0)
    await cleanupFailure.getByRole('button', { name: '重试本地清理' }).click()
  }
  await expect(page.getByText('控制台无法启动')).toBeVisible()
  await expect(page.getByRole('button', { name: '重新加载控制台' })).toBeVisible()
  expect(cleanupAuthorizations).toEqual([`Bearer ${accessToken}`])
  if (cleanupStatus === 200) {
    await expect(page.getByText('刚签发的 OIDC 会话已确认撤销，本地令牌与身份缓存已清除')).toBeVisible()
  } else {
    await expect(page.getByText('本地令牌与身份缓存已清除，但服务端当前设备会话及关联资源未确认回收')).toBeVisible()
  }
  await expect(page.getByText('sensitive upstream detail')).toHaveCount(0)
  await expect(page.getByText('sensitive cleanup detail')).toHaveCount(0)

  if (await supportsDevelopmentModuleProbes(page)) {
    await page.evaluate(async () => {
      const apiModulePath = '/src/api.ts'
      const api = await import(/* @vite-ignore */ apiModulePath)
      await api.getMe().catch(() => undefined)
    })
    await expect.poll(() => identityAuthorizations.length).toBe(2)
    expect(identityAuthorizations).toEqual([`Bearer ${accessToken}`, ''])
  } else {
    expect(identityAuthorizations).toEqual([`Bearer ${accessToken}`])
  }
}


test('worker and unknown roles fail closed without operator navigation', async ({ browser }) => {
  for (const role of ['worker_service', 'unexpected_role']) {
    const context = await browser.newContext()
    const page = await context.newPage()
    const requestedPaths: string[] = []

    await page.route('**/api/v1/**', async (route) => {
      const request = route.request()
      const path = new URL(request.url()).pathname
      requestedPaths.push(path)
      const fulfill = (value: unknown) => route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(value),
      })
      if (path === '/api/v1/auth/config') {
        return fulfill({
          mode: 'local', issuer: null, client_id: null,
          desktop_client_id: null, audience: null,
        })
      }
      if (path === '/api/v1/auth/login') {
        return fulfill({ access_token: `token-${role}`, expires_in: 900, token_type: 'bearer' })
      }
      if (path === '/api/v1/me') {
        return fulfill({
          id: `${role}-user`, tenant_id: 'tenant-1', email: `${role}@example.invalid`,
          device_id: `${role}-device`, role,
        })
      }
      return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' })
    })

    await page.goto('/')
    await page.getByLabel('租户').fill('tenant-1')
    await page.getByLabel('平台账号').fill(`${role}@example.invalid`)
    await page.getByLabel('平台密码').fill('development-password')
    await page.getByLabel('设备标识').fill(`${role}-device`)
    await page.getByRole('button', { name: '安全登录' }).click()

    if (role === 'worker_service') {
      await expect(page.getByText('当前角色没有可用页面')).toBeVisible()
    } else {
      await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible()
    }
    for (const label of ['工作台', '任务中心', '卡池管理', '邮箱池管理', 'Sub2 上传', '用户与权限', '审计中心', '策略配置']) {
      await expect(page.getByText(label, { exact: true })).toHaveCount(0)
    }
    expect(requestedPaths).not.toContain('/api/v1/dashboard/summary')
    await context.close()
  }
})

test('browser loads the authenticated shell and only the active view after login', async ({ page }) => {
  const viewModules: string[] = []
  const shellModules: string[] = []
  const shellStylesheets: string[] = []
  const administratorUiModules: string[] = []
  const administratorApiModules: string[] = []
  const genericVendorModules: string[] = []
  page.on('request', (request) => {
    const path = new URL(request.url()).pathname
    if (isAuthenticatedShellRequest(path)) shellModules.push(path)
    if (isAuthenticatedShellStylesheetRequest(path)) shellStylesheets.push(path)
    if (isAdministratorUiRequest(path)) administratorUiModules.push(path)
    if (isAdministratorApiRequest(path)) administratorApiModules.push(path)
    if (isGenericVendorRequest(path)) genericVendorModules.push(path)
    const development = path.match(/^\/src\/views\/([A-Za-z]+View)\.tsx$/)
    const production = path.match(/^\/assets\/([A-Za-z]+View)-[^/]+\.js$/)
    const viewName = development?.[1] ?? production?.[1]
    if (viewName) viewModules.push(viewName)
  })
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown) => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: 'lazy-view-token', expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'lazy-view-admin', tenant_id: 'tenant-1', email: 'lazy-view@example.invalid',
        device_id: 'lazy-view-device', role: 'platform_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-28T00:00:00Z', today_started_at: '2026-08-28T00:00:00Z',
        today_tasks: 0, pending_exceptions: 0, available_cards: 1,
        today_succeeded_uploads: 0, today_completed_uploads: 0, unavailable_mailboxes: 0,
        active_tasks: 0, allocated_cards: 0, waiting_mail_sessions: 0,
        queued_uploads: 0, unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {}, recent_tasks: [],
      })
    }
    if (path === '/api/v1/admin/audit') return fulfill([])
    return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' })
  })

  await page.goto('/')
  expect(shellModules).toEqual([])
  expect(shellStylesheets).toEqual([])
  expect(viewModules).toEqual([])
  expect(administratorUiModules).toEqual([])
  expect(administratorApiModules).toEqual([])
  expect(genericVendorModules).toEqual([])
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('lazy-view@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('lazy-view-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByRole('heading', { name: '工作台' })).toBeVisible()
  expect([...new Set(shellModules)]).toHaveLength(1)
  expect([...new Set(shellStylesheets)]).toHaveLength(1)
  expect(administratorUiModules.length).toBeGreaterThan(0)
  expect([...new Set(administratorApiModules)]).toHaveLength(1)
  expect(genericVendorModules).toEqual([])
  expect([...new Set(viewModules)]).toEqual(['DashboardView'])

  await page.getByText('审计中心', { exact: true }).click()
  await expect(page.getByRole('heading', { name: '审计中心' })).toBeVisible()
  expect([...new Set(viewModules)]).toEqual(['DashboardView', 'AuditView'])
})

test('authenticated shell download failure exposes a safe recovery action', async ({ page }) => {
  let shellModuleRejected = false
  await page.route(/\/(?:src\/AuthenticatedShell\.tsx|assets\/authenticated-shell-[^/]+\.js)$/, async (route) => {
    shellModuleRejected = true
    await route.abort('failed')
  })
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    const fulfill = (value: unknown) => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: 'shell-error-token', expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'shell-error-user', tenant_id: 'tenant-1', email: 'shell-error@example.invalid',
        device_id: 'shell-error-device', role: 'operator',
      })
    }
    return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' })
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('shell-error@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('shell-error-device')
  await page.getByRole('button', { name: '安全登录' }).click()

  await expect(page.getByRole('alert').filter({ hasText: '控制台资源加载失败' })).toBeVisible()
  await expect(page.getByRole('button', { name: '重新加载控制台' })).toBeVisible()
  expect(shellModuleRejected).toBe(true)
})

test('OIDC runtime loads only after auth config selects OIDC mode', async ({ browser }) => {
  for (const mode of ['local', 'oidc'] as const) {
    const context = await browser.newContext()
    const page = await context.newPage()
    let authConfigCompleted = false
    const oidcRequests: Array<{ path: string; afterConfig: boolean }> = []

    page.on('request', (request) => {
      const path = new URL(request.url()).pathname
      if (isOidcRuntimeRequest(path)) {
        oidcRequests.push({ path, afterConfig: authConfigCompleted })
      }
    })
    await page.route('**/api/v1/**', async (route) => {
      const path = new URL(route.request().url()).pathname
      if (path !== '/api/v1/auth/config') {
        return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' })
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mode === 'oidc' ? {
          mode,
          issuer: 'https://lazy-oidc.example.invalid/realms/platform',
          client_id: 'web-console',
          desktop_client_id: 'desktop-client',
          audience: 'email-platform',
        } : {
          mode,
          issuer: null,
          client_id: null,
          desktop_client_id: null,
          audience: null,
        }),
      })
      authConfigCompleted = true
    })

    await page.goto('/')
    await expect(page.getByRole('button', {
      name: mode === 'oidc' ? '统一身份登录' : '安全登录',
    })).toBeEnabled()
    await page.waitForLoadState('networkidle')

    if (mode === 'local') {
      expect(oidcRequests).toEqual([])
    } else {
      expect(oidcRequests.length).toBeGreaterThan(0)
      expect(oidcRequests.every(({ afterConfig }) => afterConfig)).toBe(true)
    }
    await context.close()
  }
})

test('lightweight local login preserves native validation and keyboard focus order', async ({ page }) => {
  let loginRequests = 0
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/v1/auth/config') {
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null }),
      })
    }
    if (path === '/api/v1/auth/login') loginRequests += 1
    return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' })
  })

  await page.goto('/')
  const tenant = page.getByLabel('租户')
  const email = page.getByLabel('平台账号')
  const password = page.getByLabel('平台密码')
  const device = page.getByLabel('设备标识')
  const loginButton = page.getByRole('button', { name: '安全登录' })

  await expect(tenant).toHaveAttribute('autocomplete', 'organization')
  await expect(email).toHaveAttribute('type', 'email')
  await expect(email).toHaveAttribute('autocomplete', 'username')
  await expect(password).toHaveAttribute('autocomplete', 'current-password')
  await loginButton.click()
  await expect(tenant).toBeFocused()
  expect(loginRequests).toBe(0)

  await tenant.fill('tenant-1')
  await email.fill('invalid-email')
  await password.fill('development-password')
  await device.fill('keyboard-device')
  await loginButton.click()
  await expect(email).toBeFocused()
  expect(loginRequests).toBe(0)

  await tenant.focus()
  await page.keyboard.press('Tab')
  await expect(email).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(password).toBeFocused()
  await page.keyboard.press('Tab')
  const passwordToggle = page.getByRole('button', { name: '显示密码' })
  await expect(passwordToggle).toBeFocused()
  await passwordToggle.press('Enter')
  await expect(password).toHaveAttribute('type', 'text')
  await expect(page.getByRole('button', { name: '隐藏密码' })).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(device).toBeFocused()
})

test('lazy view download failure exposes a safe recovery action', async ({ page }) => {
  let dashboardModuleRejected = false
  await page.route(/\/(?:src\/views\/DashboardView\.tsx|assets\/DashboardView-[^/]+\.js)$/, async (route) => {
    dashboardModuleRejected = true
    await route.abort('failed')
  })
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    const fulfill = (value: unknown) => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: 'lazy-error-token', expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'lazy-error-user', tenant_id: 'tenant-1', email: 'lazy-error@example.invalid',
        device_id: 'lazy-error-device', role: 'operator',
      })
    }
    return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' })
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('lazy-error@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('lazy-error-device')
  await page.getByRole('button', { name: '安全登录' }).click()

  await expect(page.getByRole('alert').filter({ hasText: '页面资源加载失败' })).toBeVisible()
  await expect(page.getByRole('button', { name: '重新加载控制台' })).toBeVisible()
  expect(dashboardModuleRejected).toBe(true)
})

test('administrator API download failure exposes a safe recovery action', async ({ page }) => {
  let administratorApiRejected = false
  await page.route(/\/(?:src\/admin-api\.ts|assets\/admin-api-[^/]+\.js)$/, async (route) => {
    administratorApiRejected = true
    await route.abort('failed')
  })
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    const fulfill = (value: unknown) => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: 'admin-api-error-token', expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'admin-api-error-user', tenant_id: 'tenant-1', email: 'admin-api-error@example.invalid',
        device_id: 'admin-api-error-device', role: 'operator',
      })
    }
    return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' })
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('admin-api-error@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('admin-api-error-device')
  await page.getByRole('button', { name: '安全登录' }).click()

  await expect(page.getByRole('alert').filter({ hasText: '页面资源加载失败' })).toBeVisible()
  await expect(page.getByRole('button', { name: '重新加载控制台' })).toBeVisible()
  expect(administratorApiRejected).toBe(true)
})

test('dashboard presents chapter nine metrics recent tasks and fixed safe risks', async ({ page }) => {
  const accessValue = 'dashboard-chapter-nine-access'
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'dashboard-admin', tenant_id: 'tenant-1', email: 'dashboard-admin@example.invalid',
        device_id: 'dashboard-device', role: 'platform_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant',
        generated_at: '2026-08-25T12:00:00Z',
        today_started_at: '2026-08-25T00:00:00Z',
        today_tasks: 7,
        pending_exceptions: 3,
        available_cards: 0,
        today_succeeded_uploads: 3,
        today_completed_uploads: 4,
        unavailable_mailboxes: 1,
        active_tasks: 2,
        allocated_cards: 2,
        waiting_mail_sessions: 1,
        queued_uploads: 0,
        unknown_uploads: 2,
        task_statuses: { created: 2 },
        mail_session_statuses: { waiting: 1 },
        card_allocation_statuses: { active: 2 },
        upload_statuses: { succeeded: 3, failed: 1, unknown: 2 },
        recent_tasks: [{
          id: 'task-recent-safe',
          type: 'card_checkout',
          status: 'created',
          trace_id: 'trace-recent-safe',
          created_at: '2026-08-25T11:00:00Z',
          expires_at: '2026-08-25T11:30:00Z',
          secret_ref: 'vault://cards/private-dashboard',
          pan: '4111111111111111',
          raw_error: 'Bearer provider-secret',
        }],
        secret_ref: 'vault://mailboxes/private-dashboard',
        raw_error: 'SENSITIVE_PROVIDER_BODY',
      })
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('dashboard-admin@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('dashboard-device')
  await page.getByRole('button', { name: '安全登录' }).click()

  const metrics = page.getByRole('region', { name: '工作台关键指标' })
  await expect(metrics).toContainText('今日任务')
  await expect(metrics).toContainText('待处理异常')
  await expect(metrics).toContainText('上传成功率')
  await expect(metrics).toContainText('75%')
  await expect(metrics).toContainText('卡池可用')
  const recent = page.getByRole('region', { name: '最近任务' })
  await expect(recent).toContainText('task-recent-safe')
  await expect(recent).toContainText('trace-recent-safe')
  const risks = page.getByRole('region', { name: '工作台风险提示' })
  await expect(risks).toContainText('2 个上传结果需要人工核对')
  await expect(risks).toContainText('1 个邮箱连接器不可用')
  await expect(risks).toContainText('卡池暂无可用卡')
  for (const secret of [
    'vault://cards/private-dashboard',
    'vault://mailboxes/private-dashboard',
    '4111111111111111',
    'Bearer provider-secret',
    'SENSITIVE_PROVIDER_BODY',
  ]) {
    await expect(page.getByText(secret, { exact: false })).toHaveCount(0)
  }
  await page.setViewportSize({ width: 768, height: 900 })
  await expect(metrics).toBeVisible()
  await expect(recent).toBeVisible()
  await expect(risks).toBeVisible()
  await expect.poll(() => page.evaluate(
    () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
  )).toBe(true)
})

test('platform admin quarantines and explicitly releases a card before enabling it', async ({ page }) => {
  const accessValue = 'card-quarantine-access'
  let card = {
    id: 'card-quarantine', tenant_id: 'tenant-1', provider_ref: 'provider-quarantine',
    brand: 'VISA', last4: '4242', expiry_month: null, expiry_year: null,
    status: 'allocated', quarantine_reason_code: null, quarantined_at: null,
    is_active: true, created_at: '2026-08-24T00:00:00Z',
  }
  const quarantineBodies: unknown[] = []
  let releaseQuarantine = () => undefined
  const quarantineGate = new Promise<void>((resolve) => { releaseQuarantine = resolve })
  let cardListRequests = 0
  let enableAttempts = 0
  let releaseLateEnable = () => undefined
  const lateEnableGate = new Promise<void>((resolve) => { releaseLateEnable = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'platform-user', tenant_id: 'tenant-1', email: 'platform@example.invalid',
        device_id: 'platform-device', role: 'platform_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-24T00:00:00Z', active_tasks: 0,
        allocated_cards: 1, waiting_mail_sessions: 0, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: { active: 1 }, upload_statuses: {},
      })
    }
    if (path === '/api/v1/admin/cards' && request.method() === 'GET') {
      cardListRequests += 1
      return fulfill([card])
    }
    if (path === '/api/v1/admin/cards/card-quarantine/quarantine' && request.method() === 'POST') {
      const body = request.postDataJSON()
      quarantineBodies.push(body)
      expect(body).toEqual({ reason_code: 'suspected_compromise' })
      expect(JSON.stringify(body)).not.toContain('secret')
      await quarantineGate
      card = {
        ...card,
        status: 'quarantined',
        quarantine_reason_code: 'suspected_compromise',
        quarantined_at: '2026-08-24T00:01:00Z',
        is_active: false,
      }
      return fulfill(card)
    }
    if (path === '/api/v1/admin/cards/card-quarantine/release-quarantine' && request.method() === 'POST') {
      card = {
        ...card,
        status: 'disabled',
        quarantine_reason_code: null,
        quarantined_at: null,
        is_active: false,
      }
      return fulfill(card)
    }
    if (path === '/api/v1/admin/cards/card-quarantine' && request.method() === 'PATCH') {
      expect(request.postDataJSON()).toEqual({ is_active: true })
      enableAttempts += 1
      if (enableAttempts === 1) {
        await lateEnableGate
        return fulfill({ error: { code: 'service_unavailable', message: 'late card enable detail' } }, 503)
      }
      card = { ...card, status: 'available', is_active: true }
      return fulfill(card)
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('platform@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('platform-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('卡池管理', { exact: true }).click()

  const row = page.getByRole('row').filter({ hasText: 'provider-quarantine' })
  await expect(row.getByText('已分配')).toBeVisible()
  await expect(row.locator('.anticon-loading')).toHaveCount(0)
  await row.getByRole('button', { name: /隔\s*离/ }).click()
  const dialog = page.getByRole('dialog', { name: '隔离卡 provider-quarantine' })
  await dialog.getByRole('combobox').click()
  await page.getByText('疑似信息泄露', { exact: true }).click()
  const confirm = dialog.getByRole('button', { name: /隔离并回收/ })
  await confirm.click()
  try {
    await expect.poll(() => quarantineBodies).toHaveLength(1)
    await expect(confirm).toHaveClass(/ant-btn-loading/)
    await confirm.dispatchEvent('click')
    expect(quarantineBodies).toHaveLength(1)
  } finally {
    releaseQuarantine()
  }

  await expect(row.getByText('已隔离')).toBeVisible()
  await expect(row.getByRole('button', { name: /启用卡/ })).toHaveCount(0)
  await row.getByRole('button', { name: /解除隔离卡 provider-quarantine/ }).click()
  await page.getByRole('dialog', { name: '确认解除卡 provider-quarantine 的隔离？' })
    .getByRole('button', { name: '解除隔离', exact: true }).click()
  await expect(row.getByText('已停用')).toBeVisible()
  const enableCard = row.getByRole('button', {
    name: '启用卡 provider-quarantine（•••• 4242，card-quarantine）', exact: true,
  })
  const lateEnableResponse = page.waitForResponse((response) => (
    new URL(response.url()).pathname === '/api/v1/admin/cards/card-quarantine'
  ))
  await enableCard.click()
  let listsBeforeLateEnable = 0
  try {
    await expect.poll(() => enableAttempts).toBe(1)
    await expect(enableCard).toBeDisabled()
    await expect(enableCard).toHaveClass(/ant-btn-loading/)
    await page.getByRole('menuitem', { name: /工作台/ }).click()
    await expect(page.getByRole('heading', { name: '工作台', exact: true })).toBeVisible()
    const lockButton = page.getByRole('button', { name: '锁定' })
    await lockButton.focus()
    await expect(lockButton).toBeFocused()
    listsBeforeLateEnable = cardListRequests
  } finally {
    releaseLateEnable()
  }
  await lateEnableResponse
  await page.evaluate(() => new Promise<void>((resolve) => {
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => resolve()))
  }))
  await page.waitForTimeout(300)
  expect(cardListRequests).toBe(listsBeforeLateEnable)
  await expect(page.getByText(/影响：平台可能已完成卡状态切换和关联资源回收/)).toHaveCount(0)
  await expect(page.getByRole('button', { name: '锁定' })).toBeFocused()
  await page.getByRole('menuitem', { name: /卡池管理/ }).click()
  await expect(enableCard).toBeEnabled()
  await enableCard.click()
  await expect(row.getByText('可用')).toBeVisible()
  expect(enableAttempts).toBe(2)
})

test('ops admin reads masked card history and recycles one exact allocation', async ({ page }) => {
  const accessValue = 'card-timeline-access'
  const card = {
    id: 'card-timeline', tenant_id: 'tenant-1', provider_ref: 'provider-timeline',
    brand: 'VISA', last4: '4242', expiry_month: 12, expiry_year: 2030,
    status: 'allocated', quarantine_reason_code: null, quarantined_at: null,
    is_active: true, created_at: '2026-08-24T00:00:00Z',
  }
  let allocation = {
    id: 'allocation-timeline', card_id: card.id, card_masked: '**** **** **** 4242',
    brand: 'VISA', user_id: 'operator-user', task_id: 'task-timeline',
    device_id: 'operator-device', status: 'active', expires_at: '2026-08-24T00:30:00Z',
    released_at: null as string | null, release_reason_code: null as string | null,
    trace_id: 'trace-timeline', created_at: '2026-08-24T00:01:00Z',
  }
  const recycleBodies: unknown[] = []

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'ops-user', tenant_id: 'tenant-1', email: 'ops@example.invalid',
        device_id: 'ops-device', role: 'ops_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-24T00:00:00Z', active_tasks: 0,
        allocated_cards: allocation.status === 'active' ? 1 : 0,
        waiting_mail_sessions: 0, queued_uploads: 0, unknown_uploads: 0,
        task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: { [allocation.status]: 1 }, upload_statuses: {},
      })
    }
    if (path === '/api/v1/admin/cards' && request.method() === 'GET') {
      return fulfill([{ ...card, status: allocation.status === 'active' ? 'allocated' : 'available' }])
    }
    if (path === '/api/v1/admin/cards/card-timeline/timeline' && request.method() === 'GET') {
      const eventsCursor = new URL(request.url()).searchParams.get('events_cursor')
      if (eventsCursor === 'event-page-2') {
        return fulfill({
          card: { ...card, status: allocation.status === 'active' ? 'allocated' : 'available' },
          allocations: [allocation],
          events: [{
            id: 'event-created', card_id: card.id, allocation_id: null,
            actor_id: 'ops-user', action: 'card.created', reason_code: null,
            before_masked: {}, after_masked: { card_status: 'available' },
            trace_id: 'trace-created', created_at: '2026-08-24T00:00:00Z',
          }],
          allocations_has_more: false, events_has_more: false,
          allocations_next_cursor: null, events_next_cursor: null,
        })
      }
      return fulfill({
        card: { ...card, status: allocation.status === 'active' ? 'allocated' : 'available' },
        allocations: [allocation],
        events: [{
          id: 'event-allocated', card_id: card.id, allocation_id: allocation.id,
          actor_id: 'operator-user', action: 'allocation.allocated', reason_code: null,
          before_masked: { card_status: 'available' },
          after_masked: { card_status: 'allocated', allocation_status: 'active' },
          trace_id: 'trace-timeline', created_at: '2026-08-24T00:01:00Z',
        }],
        allocations_has_more: false, events_has_more: true,
        allocations_next_cursor: null, events_next_cursor: 'event-page-2',
      })
    }
    if (
      path === '/api/v1/admin/cards/card-timeline/allocations/allocation-timeline/recycle'
      && request.method() === 'POST'
    ) {
      const body = request.postDataJSON()
      recycleBodies.push(body)
      expect(body).toEqual({ reason_code: 'manual_reassignment' })
      allocation = {
        ...allocation,
        status: 'released',
        released_at: '2026-08-24T00:05:00Z',
        release_reason_code: 'manual_reassignment',
      }
      return fulfill(allocation)
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('ops@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('ops-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('卡池管理', { exact: true }).click()

  const row = page.getByRole('row').filter({ hasText: 'provider-timeline' })
  await row.getByRole('button', { name: /查看卡 provider-timeline.*分配历史/ }).click()
  const history = page.locator('.ant-card').filter({
    has: page.getByText('卡片分配历史', { exact: true }),
  })
  await expect(history.getByText('allocation-timeline', { exact: true }).first()).toBeVisible()
  await expect(history.getByText('状态：available → allocated / active')).toBeVisible()
  await expect(history.getByText(/操作者：\s*operator-user/)).toBeVisible()
  await history.getByRole('button', { name: '加载更早状态事件' }).click()
  await expect(history.getByText('卡资源已登记')).toBeVisible()
  await expect(history.getByRole('button', { name: '加载更早状态事件' })).toHaveCount(0)
  await expect(history).not.toContainText('vault://')
  await expect(history).not.toContainText('4111111111111111')
  await history.getByRole('button', { name: /回收活动租约 allocation-timeline/ }).click()
  const dialog = page.getByRole('dialog', { name: '回收租约 allocation-timeline' })
  await dialog.getByLabel('选择活动租约回收原因').click()
  await page.getByText('人工重新分配', { exact: true }).click()
  await dialog.getByRole('button', { name: '确认回收' }).click()

  await expect.poll(() => recycleBodies).toEqual([{ reason_code: 'manual_reassignment' }])
  await expect(history.getByText('人工重新分配', { exact: true })).toBeVisible()
  await expect(history.getByRole('button', { name: /回收活动租约/ })).toHaveCount(0)
})

test('OIDC callback compensates and requires local cleanup before recovery when identity lookup fails', async ({ page }) => {
  await exerciseOidcCallbackIdentityFailure(page, 200, true)
})

test('OIDC callback clears local state when identity compensation is not confirmed', async ({ page }) => {
  await exerciseOidcCallbackIdentityFailure(page, 503)
})

test('login is single-flight and clears partially issued bearers after identity failure', async ({ page }) => {
  const accessValues = ['partial-access-1', 'partial-access-2', 'ready-access-3']
  const loginAuthorizations: string[] = []
  const cleanupAuthorizations: string[] = []
  let loginRequests = 0
  let releaseFirstLogin = () => undefined
  const firstLoginGate = new Promise<void>((resolve) => { releaseFirstLogin = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      loginAuthorizations.push(request.headers().authorization ?? '')
      const requestIndex = loginRequests
      loginRequests += 1
      if (requestIndex === 0) await firstLoginGate
      return fulfill({ access_token: accessValues[requestIndex], expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      const authorization = request.headers().authorization ?? ''
      if (authorization !== `Bearer ${accessValues[2]}`) {
        return fulfill({ error: { code: 'service_unavailable', message: 'identity unavailable' } }, 503)
      }
      return fulfill({
        id: 'ready-user', tenant_id: 'tenant-1', email: 'ready@example.invalid',
        device_id: 'login-device', role: 'operator',
      })
    }
    if (path === '/api/v1/auth/logout') {
      const authorization = request.headers().authorization ?? ''
      cleanupAuthorizations.push(authorization)
      if (authorization === `Bearer ${accessValues[0]}`) return fulfill({ status: 'logged_out' })
      return fulfill({ error: { code: 'service_unavailable', message: 'cleanup unavailable' } }, 503)
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'own', generated_at: '2026-08-20T00:00:00Z',
        active_tasks: 0, allocated_cards: 0, waiting_mail_sessions: 0,
        queued_uploads: 0, unknown_uploads: 0,
        task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('ready@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('login-device')
  const loginButton = page.getByRole('button', { name: '安全登录' })
  await loginButton.evaluate((button) => {
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
  })
  try {
    await expect.poll(() => loginRequests).toBe(1)
    await expect(loginButton).toBeDisabled()
    await expect(loginButton).toHaveClass(/ant-btn-loading/)
    await expect(page.getByLabel('平台账号')).toBeDisabled()
  } finally {
    releaseFirstLogin()
  }

  await expect(page.getByText('刚签发的会话已确认撤销，本地令牌已清除')).toBeVisible()
  await expect(loginButton).toBeEnabled()
  expect(cleanupAuthorizations).toEqual([`Bearer ${accessValues[0]}`])

  await loginButton.click()
  await expect(page.getByText('本地令牌已清除，但服务端当前设备会话及关联资源未确认回收')).toBeVisible()
  await expect(loginButton).toBeEnabled()
  expect(cleanupAuthorizations).toEqual([
    `Bearer ${accessValues[0]}`,
    `Bearer ${accessValues[1]}`,
  ])

  await loginButton.click()
  await expect(page.getByText('ready@example.invalid')).toBeVisible()
  expect(loginRequests).toBe(3)
  expect(loginAuthorizations).toEqual(['', '', ''])
})

test('OIDC login disables duplicate redirect starts while discovery is pending', async ({ page }) => {
  const issuer = 'https://identity.example.invalid/realms/platform'
  let discoveryRequests = 0
  let releaseDiscovery = () => undefined
  const discoveryGate = new Promise<void>((resolve) => { releaseDiscovery = resolve })

  await page.route('**/api/v1/auth/config', async (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      mode: 'oidc', issuer, client_id: 'web-console',
      desktop_client_id: 'desktop-client', audience: 'email-platform',
    }),
  }))
  await page.route(`${issuer}/.well-known/openid-configuration`, async (route) => {
    discoveryRequests += 1
    await discoveryGate
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        issuer,
        authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
        token_endpoint: `${issuer}/protocol/openid-connect/token`,
        jwks_uri: `${issuer}/protocol/openid-connect/certs`,
      }),
    })
  })
  await page.route(`${issuer}/protocol/openid-connect/auth**`, async (route) => route.fulfill({
    status: 200,
    contentType: 'text/html',
    body: '<main>Identity provider fixture</main>',
  }))

  await page.goto('/')
  const oidcButton = page.getByRole('button', { name: '统一身份登录' })
  await expect(oidcButton).toBeEnabled()
  await oidcButton.evaluate((button) => {
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
  })
  try {
    await expect.poll(() => discoveryRequests).toBe(1)
    await expect(oidcButton).toBeDisabled()
    await expect(oidcButton).toHaveClass(/ant-btn-loading/)
    await oidcButton.dispatchEvent('click')
    expect(discoveryRequests).toBe(1)
  } finally {
    releaseDiscovery()
  }
  await expect(page.getByText('Identity provider fixture')).toBeVisible()
})


test('operator login keeps bearer in memory and exposes task trace', async ({ page }) => {
  const accessValue = ['fixture', 'access', 'value'].join('-')
  const taskTrace = '00000000-0000-0000-0000-000000000042'
  const protectedPaths: string[] = []
  let taskStatus = 'created'
  let taskListRequests = 0
  let timelineRequests = 0
  let closeRequests = 0
  let releaseClose = () => undefined
  const closeGate = new Promise<void>((resolve) => { releaseClose = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      headers: { 'X-Trace-Id': taskTrace },
      body: JSON.stringify(value),
    })

    if (path === '/api/v1/auth/config') {
      return fulfill({
        mode: 'local', issuer: null, client_id: null,
        desktop_client_id: null, audience: null,
      })
    }
    if (path === '/api/v1/auth/login') {
      expect(request.method()).toBe('POST')
      expect(Object.keys(request.postDataJSON()).sort()).toEqual([
        'device_id', 'email', 'password', 'tenant_id',
      ])
      return fulfill({
        access_token: accessValue,
        expires_in: 900,
        token_type: 'bearer',
      })
    }

    protectedPaths.push(path)
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'user-1', tenant_id: 'tenant-1', email: 'operator@example.invalid',
        device_id: 'device-1', role: 'operator',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'own', generated_at: '2026-08-20T00:00:00Z',
        active_tasks: 1, allocated_cards: 1, waiting_mail_sessions: 1,
        queued_uploads: 0, unknown_uploads: 0,
        task_statuses: { created: 1 }, mail_session_statuses: { waiting: 1 },
        card_allocation_statuses: { active: 1 }, upload_statuses: {},
      })
    }
    if (path === '/api/v1/auth/logout') {
      return fulfill({ status: 'logged_out' })
    }
    if (path === '/api/v1/tasks') {
      expect(url.searchParams.get('limit')).toBe('50')
      taskListRequests += 1
      return fulfill([{
        id: 'task-1', tenant_id: 'tenant-1', user_id: 'user-1',
        device_id: 'device-1', type: 'mail_code', idempotency_key: 'request-1',
        client_reference: null, trace_id: taskTrace, status: taskStatus,
        expires_at: '2026-08-20T01:00:00Z', closed_at: taskStatus === 'closed' ? '2026-08-20T00:06:00Z' : null,
        created_at: '2026-08-20T00:00:00Z',
      }])
    }
    if (path === '/api/v1/tasks/task-1/timeline') {
      timelineRequests += 1
      const advanced = timelineRequests >= 2
      return fulfill({
        task: {
          id: 'task-1', tenant_id: 'tenant-1', user_id: 'user-1',
          device_id: 'device-1', type: 'mail_code', idempotency_key: 'request-1',
          client_reference: null, trace_id: taskTrace, status: taskStatus,
          expires_at: '2026-08-20T01:00:00Z', closed_at: taskStatus === 'closed' ? '2026-08-20T00:06:00Z' : null,
          created_at: '2026-08-20T00:00:00Z',
        },
        workbench_step: advanced ? 'uploading' : 'waiting_code',
        mail_session: {
          id: 'mail-1', email_masked: 'm***@example.invalid', status: advanced ? 'consumed' : 'waiting',
          expires_at: '2026-08-20T00:30:00Z', consumed_at: advanced ? '2026-08-20T00:03:00Z' : null,
          created_at: '2026-08-20T00:01:00Z',
          code: '654321',
        },
        card_allocations: [{
          id: 'allocation-1', card_masked: '**** **** **** 4242', brand: 'VISA',
          status: 'active', expires_at: '2026-08-20T00:30:00Z', released_at: null,
          created_at: '2026-08-20T00:01:00Z',
          pan: '4111111111111111', secret_ref: 'vault://cards/operator-private',
        }],
        uploads: advanced ? [{
          id: 'upload-1', business_name: 'Operator Store', status: 'unknown',
          policy_version: 'policy-v1', external_ref: null, error_code: 'external_unknown',
          created_at: '2026-08-20T00:04:00Z', updated_at: '2026-08-20T00:05:00Z',
        }] : [],
        events: [{
          id: 'event-1', event_type: 'task.created', action: 'task_create',
          result: 'success', entity_type: 'task', entity_id: 'task-1',
          policy_version: null, created_at: '2026-08-20T00:00:00Z',
          details: { raw_secret: 'must-never-render-in-task-timeline' },
        }, ...(advanced ? [{
          id: 'event-2', event_type: 'upload.unknown', action: 'upload_unknown',
          result: 'unknown', entity_type: 'upload_job', entity_id: 'upload-1',
          policy_version: 'policy-v1', created_at: '2026-08-20T00:05:00Z',
        }] : [])],
      })
    }
    if (path === '/api/v1/tasks/task-1/close' && request.method() === 'POST') {
      closeRequests += 1
      await closeGate
      taskStatus = 'closed'
      return fulfill({
        id: 'task-1', tenant_id: 'tenant-1', user_id: 'user-1',
        device_id: 'device-1', type: 'mail_code', idempotency_key: 'request-1',
        client_reference: null, trace_id: taskTrace, status: 'closed',
        expires_at: '2026-08-20T01:00:00Z', closed_at: '2026-08-20T00:06:00Z',
        created_at: '2026-08-20T00:00:00Z',
      })
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('operator@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('device-1')
  await page.getByRole('button', { name: '安全登录' }).click()

  await expect(page.getByText('operator@example.invalid')).toBeVisible()
  await expect(page.getByText('操作员')).toBeVisible()
  await expect(page.getByText('设备 device-1')).toBeVisible()
  await expect(page.getByText('Sub2 上传', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('timer')).toContainText('会话')
  await expect(page.getByRole('button', { name: '锁定' })).toBeVisible()
  await expect(page.getByRole('button', { name: '退出登录' })).toBeVisible()
  await page.getByText('任务中心', { exact: true }).click()
  const progress = page.getByRole('region', { name: '当前任务进度' })
  for (const step of ['已登录', '已分配卡', '等待验证码', '已获取', '上传中', '完成']) {
    await expect(progress).toContainText(step)
  }
  await expect(progress.locator('[aria-current="step"]')).toHaveText('等待验证码')
  const resources = page.getByRole('region', { name: '当前任务资源' })
  await expect(resources).toContainText('m***@example.invalid')
  await expect(resources).toContainText('**** **** **** 4242')
  const recovery = page.getByRole('region', { name: '上传与恢复' })
  await expect(recovery).toContainText(taskTrace)
  await expect(recovery).toContainText('尚未提交上传')
  await expect(progress.locator('[aria-current="step"]')).toHaveText('上传中', { timeout: 7_500 })
  await expect.poll(() => taskListRequests).toBeGreaterThanOrEqual(2)
  await expect.poll(() => timelineRequests).toBeGreaterThanOrEqual(2)
  await expect(recovery).toContainText('上传结果待人工核对')
  await expect(recovery).toContainText('平台不会自动重试')
  await expect(recovery).not.toContainText('上传失败')
  await expect(recovery).not.toContainText('立即重试')
  const history = page.getByRole('region', { name: '任务历史与安全提示' })
  await expect(history).toContainText('task-1')
  await expect(history).toContainText('超时、失焦、锁定或注销后')
  await expect(page.locator('.content .ant-btn-primary:visible')).toHaveCount(0)
  const closeCurrentTask = page.getByRole('button', { name: '关闭当前任务并清理资源' })
  await expect(closeCurrentTask).toBeVisible()
  await closeCurrentTask.focus()
  await expect(closeCurrentTask).toBeFocused()
  expect((await closeCurrentTask.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(44)
  await expect(page.getByText('任务已创建')).toBeVisible()
  await expect(history).toContainText('上传结果待人工核对')
  for (const hidden of [
    'must-never-render-in-task-timeline',
    '654321',
    '4111111111111111',
    'vault://cards/operator-private',
    'policy-v1',
    'Sub2 登录',
    '代理 ID',
    '并发',
  ]) {
    await expect(page.locator('body')).not.toContainText(hidden)
  }
  await page.setViewportSize({ width: 375, height: 812 })
  await expect(progress).toBeVisible()
  await expect(resources).toBeVisible()
  await expect(recovery).toBeVisible()
  await expect(history).toBeVisible()
  await expect.poll(() => page.evaluate(
    () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
  )).toBe(true)
  await page.setViewportSize({ width: 768, height: 900 })
  await expect(progress).toBeVisible()
  await expect(resources).toBeVisible()
  await expect(recovery).toBeVisible()
  await expect(history).toBeVisible()
  await expect.poll(() => page.evaluate(
    () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
  )).toBe(true)

  const browserStorage = await page.evaluate(() => ({
    local: Object.values(localStorage),
    session: Object.values(sessionStorage),
  }))
  expect(JSON.stringify(browserStorage)).not.toContain(accessValue)
  expect(protectedPaths).toContain('/api/v1/me')
  expect(protectedPaths).toContain('/api/v1/tasks')
  expect(protectedPaths).toContain('/api/v1/tasks/task-1/timeline')

  await closeCurrentTask.click()
  const closeDialog = page.getByRole('dialog', { name: '确认关闭任务 task-1？' })
  await expect(closeDialog).toContainText('卡租约会释放，邮箱会话和未消费验证码会立即清理')
  const confirmClose = closeDialog.getByRole('button', { name: '关闭任务并回收资源' })
  await confirmClose.click()
  try {
    await expect.poll(() => closeRequests).toBe(1)
    await expect(closeCurrentTask).toBeDisabled()
    await expect(confirmClose).toHaveClass(/ant-btn-loading/)
    await confirmClose.dispatchEvent('click')
    expect(closeRequests).toBe(1)
  } finally {
    releaseClose()
  }
  await expect(progress).toContainText('当前设备没有进行中任务')
  expect(closeRequests).toBe(1)

  await page.getByRole('button', { name: '锁定' }).click()
  await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible()
  expect(protectedPaths).toContain('/api/v1/auth/logout')
  await expect(page.getByText('设备 device-1')).not.toBeVisible()
})

test('current-device revoke handles confirmed, rejected, uncertain HTTP, and transport outcomes without logout', async ({ browser }) => {
  for (const outcome of ['confirmed', 'rejected', 'request-timeout', 'server-error', 'ambiguous'] as const) {
    const context = await browser.newContext()
    const page = await context.newPage()
    const revokeRequests: string[] = []
    let logoutRequests = 0
    let releaseRevoke = () => undefined
    const revokeGate = new Promise<void>((resolve) => { releaseRevoke = resolve })

    await page.route('**/api/v1/**', async (route) => {
      const request = route.request()
      const path = new URL(request.url()).pathname
      const fulfill = (value: unknown, status = 200) => route.fulfill({
        status,
        contentType: 'application/json',
        body: JSON.stringify(value),
      })
      if (path === '/api/v1/auth/config') {
        return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
      }
      if (path === '/api/v1/auth/login') {
        return fulfill({ access_token: `device-${outcome}-bearer`, expires_in: 900, token_type: 'bearer' })
      }
      if (path === '/api/v1/me') {
        return fulfill({
          id: `user-${outcome}`, tenant_id: 'tenant-1', email: `${outcome}@example.invalid`,
          device_id: `device-${outcome}`, role: 'operator',
        })
      }
      if (path === '/api/v1/dashboard/summary') {
        return fulfill({
          scope: 'own', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
          allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
          unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
          card_allocation_statuses: {}, upload_statuses: {},
        })
      }
      if (path === `/api/v1/devices/device-${outcome}/revoke`) {
        expect(request.method()).toBe('POST')
        expect(request.headers().authorization).toBe(`Bearer device-${outcome}-bearer`)
        revokeRequests.push(path)
        await revokeGate
        if (outcome === 'ambiguous') return route.abort('failed')
        if (outcome === 'request-timeout') {
          return fulfill({
            error: {
              code: 'request_timeout',
              message: 'raw internal route detail',
              recovery_hint: 'raw internal recovery detail',
            },
          }, 408)
        }
        if (outcome === 'server-error') {
          return fulfill({
            error: {
              code: 'service_unavailable',
              message: 'raw internal route detail',
              recovery_hint: 'raw internal recovery detail',
            },
          }, 503)
        }
        if (outcome === 'rejected') {
          return fulfill({
            error: {
              code: 'forbidden',
              message: 'raw internal route detail',
              recovery_hint: 'raw internal recovery detail',
            },
          }, 403)
        }
        return fulfill({
          id: `device-${outcome}`, tenant_id: 'tenant-1', user_id: `user-${outcome}`,
          name: `device-${outcome}`, last_seen_at: '2026-08-20T00:00:00Z',
          revoked_at: '2026-08-20T00:01:00Z', created_at: '2026-08-19T00:00:00Z',
        })
      }
      if (path === '/api/v1/auth/logout') {
        logoutRequests += 1
        return fulfill({ status: 'logged_out' })
      }
      return fulfill({ error: { code: 'not_found', message: 'raw internal route detail' } }, 404)
    })

    await page.goto('/')
    await page.getByLabel('租户').fill('tenant-1')
    await page.getByLabel('平台账号').fill(`${outcome}@example.invalid`)
    await page.getByLabel('平台密码').fill('development-password')
    await page.getByLabel('设备标识').fill(`device-${outcome}`)
    await page.getByRole('button', { name: '安全登录' }).click()

    const revokeButton = page.getByRole('button', { name: '撤销当前设备' })
    await expect(revokeButton).toBeVisible()
    expect((await revokeButton.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(44)
    await revokeButton.evaluate((button) => {
      button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
      button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    })
    const revokeDialog = page.getByRole('dialog', { name: '确认撤销当前设备？' })
    await expect(revokeDialog).toHaveCount(1)
    await expect(revokeDialog).toContainText(`device-${outcome}`)
    await expect(revokeDialog).toContainText('不会再调用已撤销令牌执行退出')
    const confirmRevoke = revokeDialog.getByRole('button', { name: '撤销设备并清理本地会话' })
    await confirmRevoke.click()
    try {
      await expect.poll(() => revokeRequests).toHaveLength(1)
      await expect(revokeButton).toBeDisabled()
      await expect(confirmRevoke).toHaveClass(/ant-btn-loading/)
      await confirmRevoke.dispatchEvent('click')
      expect(revokeRequests).toHaveLength(1)
    } finally {
      releaseRevoke()
    }

    if (outcome === 'rejected') {
      await expect(revokeButton).toBeVisible()
      await expect(revokeButton).toBeEnabled()
      await expect(page.getByText('当前设备撤销未完成')).toBeVisible()
      await expect(page.getByRole('button', { name: '安全登录' })).not.toBeVisible()
    } else {
      await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible()
      await expect(page.getByText(outcome === 'confirmed'
        ? '当前设备已撤销'
        : '当前设备撤销结果待核对')).toBeVisible()
    }
    await expect(page.locator('body')).not.toContainText('raw internal route detail')
    await expect(page.locator('body')).not.toContainText('raw internal recovery detail')
    expect(logoutRequests).toBe(0)
    expect(revokeRequests).toHaveLength(1)
    await context.close()
  }
})

test('hard expiry retires an old device revoke without letting its late outcome unlock a new revoke', async ({ browser }) => {
  for (const oldOutcome of ['confirmed', 'rejected', 'ambiguous'] as const) {
    const context = await browser.newContext()
    const page = await context.newPage()
    let loginAttempts = 0
    let revokeAttempts = 0
    let oldRevokeCompleted = false
    let releaseOldRevoke = () => undefined
    let releaseNewRevoke = () => undefined
    const oldRevokeGate = new Promise<void>((resolve) => { releaseOldRevoke = resolve })
    const newRevokeGate = new Promise<void>((resolve) => { releaseNewRevoke = resolve })

    await page.route('**/api/v1/**', async (route) => {
      const request = route.request()
      const path = new URL(request.url()).pathname
      const fulfill = (value: unknown, status = 200) => route.fulfill({
        status,
        contentType: 'application/json',
        body: JSON.stringify(value),
      })
      if (path === '/api/v1/auth/config') {
        return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
      }
      if (path === '/api/v1/auth/login') {
        const generation = loginAttempts === 0 ? 'old' : 'new'
        loginAttempts += 1
        return fulfill({ access_token: `${generation}-${oldOutcome}-revoke-bearer`, expires_in: 900, token_type: 'bearer' })
      }
      if (path === '/api/v1/me') {
        const generation = request.headers().authorization?.includes('new-') ? 'new' : 'old'
        return fulfill({
          id: `${generation}-${oldOutcome}-user`, tenant_id: 'tenant-1',
          email: `${generation}-${oldOutcome}@example.invalid`,
          device_id: `${generation}-${oldOutcome}-device`, role: 'operator',
        })
      }
      if (path === '/api/v1/dashboard/summary') {
        return fulfill({
          scope: 'own', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
          allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
          unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
          card_allocation_statuses: {}, upload_statuses: {},
        })
      }
      if (/\/api\/v1\/devices\/(?:old|new)-.+-device\/revoke/.test(path)) {
        revokeAttempts += 1
        const attempt = revokeAttempts
        expect(request.method()).toBe('POST')
        expect(request.headers().authorization).toBe(
          `Bearer ${attempt === 1 ? 'old' : 'new'}-${oldOutcome}-revoke-bearer`,
        )
        if (attempt === 1) {
          await oldRevokeGate
          oldRevokeCompleted = true
          if (oldOutcome === 'ambiguous') return route.abort('failed')
          if (oldOutcome === 'rejected') {
            return fulfill({ error: { code: 'forbidden', message: 'stale revoke rejection detail' } }, 403)
          }
        } else {
          await newRevokeGate
        }
        const generation = attempt === 1 ? 'old' : 'new'
        return fulfill({
          id: `${generation}-${oldOutcome}-device`, tenant_id: 'tenant-1',
          user_id: `${generation}-${oldOutcome}-user`, name: `${generation} device`,
          last_seen_at: '2026-08-20T00:00:00Z', revoked_at: '2026-08-20T00:01:00Z',
          created_at: '2026-08-19T00:00:00Z',
        })
      }
      return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
    })

    const signIn = async (generation: 'old' | 'new') => {
      await page.getByLabel('租户').fill('tenant-1')
      await page.getByLabel('平台账号').fill(`${generation}-${oldOutcome}@example.invalid`)
      await page.getByLabel('平台密码').fill('development-password')
      await page.getByLabel('设备标识').fill(`${generation}-${oldOutcome}-device`)
      await page.getByRole('button', { name: '安全登录' }).click()
      await expect(page.getByText(`${generation}-${oldOutcome}@example.invalid`)).toBeVisible()
    }
    const startRevoke = async () => {
      await page.getByRole('button', { name: '撤销当前设备' }).click()
      const dialog = page.getByRole('dialog', { name: '确认撤销当前设备？' })
      const confirm = dialog.getByRole('button', { name: '撤销设备并清理本地会话' })
      await confirm.click()
      return confirm
    }

    try {
      await page.goto('/')
      await signIn('old')
      await startRevoke()
      await expect.poll(() => revokeAttempts).toBe(1)

      await page.evaluate(() => window.dispatchEvent(new Event('platform:auth-expired')))
      await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible()
      await expect(page.getByRole('dialog', { name: '确认撤销当前设备？' })).toHaveCount(0)
      await expect(page.getByRole('alert')).toContainText('当前设备撤销请求未能在令牌有效期内确认')
      await expect(page.getByText(`old-${oldOutcome}@example.invalid`)).toHaveCount(0)

      await signIn('new')
      const newConfirm = await startRevoke()
      await expect.poll(() => revokeAttempts).toBe(2)
      const newRevokeButton = page.getByRole('button', { name: '撤销当前设备' })
      const newLockButton = page.getByRole('button', { name: '锁定' })
      const newLogoutButton = page.getByRole('button', { name: '退出登录' })
      await expect(newRevokeButton).toBeDisabled()
      await expect(newLockButton).toBeDisabled()
      await expect(newLogoutButton).toBeDisabled()
      await expect(newConfirm).toHaveClass(/ant-btn-loading/)

      releaseOldRevoke()
      await expect.poll(() => oldRevokeCompleted).toBe(true)
      await expect(page.getByText(`new-${oldOutcome}@example.invalid`)).toBeVisible()
      await expect(newRevokeButton).toBeDisabled()
      await expect(newLockButton).toBeDisabled()
      await expect(newLogoutButton).toBeDisabled()
      await expect(newConfirm).toHaveClass(/ant-btn-loading/)
      await expect(page.getByText('当前设备已撤销')).toHaveCount(0)
      await expect(page.getByText('当前设备撤销未完成')).toHaveCount(0)
      await expect(page.getByText('当前设备撤销结果待核对')).toHaveCount(0)
      await expect(page.locator('body')).not.toContainText('stale revoke rejection detail')

      releaseNewRevoke()
      await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible()
      await expect(page.getByText('当前设备已撤销')).toBeVisible()
      expect(revokeAttempts).toBe(2)
    } finally {
      releaseOldRevoke()
      releaseNewRevoke()
      await context.close()
    }
  }
})

test('OIDC exits keep login unreachable until old user cleanup finishes', async ({ page }) => {
  const issuer = 'https://device-revoke-oidc.example.invalid/realms/platform'
  const accessToken = 'oidc-device-revoke-access'
  let nonce = ''
  let logoutRequests = 0

  const fulfillJson = (route: Route, value: unknown, status = 200) => route.fulfill({
    status,
    contentType: 'application/json',
    headers: { 'access-control-allow-origin': '*' },
    body: JSON.stringify(value),
  })
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (path === '/api/v1/auth/config') {
      return fulfillJson(route, {
        mode: 'oidc', issuer, client_id: 'web-console',
        desktop_client_id: 'desktop-client', audience: 'email-platform',
      })
    }
    if (path === '/api/v1/me') {
      return fulfillJson(route, {
        id: 'oidc-revoke-user', tenant_id: 'tenant-1', email: 'oidc-revoke@example.invalid',
        device_id: 'oidc-revoke-device', role: 'operator',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfillJson(route, {
        scope: 'own', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
        allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/auth/logout') {
      logoutRequests += 1
      expect(request.method()).toBe('POST')
      expect(request.headers().authorization).toBe(`Bearer ${accessToken}`)
      return fulfillJson(route, { status: 'logged_out' })
    }
    if (path === '/api/v1/devices/oidc-revoke-device/revoke') {
      expect(request.method()).toBe('POST')
      expect(request.headers().authorization).toBe(`Bearer ${accessToken}`)
      return fulfillJson(route, {
        id: 'oidc-revoke-device', tenant_id: 'tenant-1', user_id: 'oidc-revoke-user',
        name: 'OIDC revoke device', last_seen_at: '2026-08-20T00:00:00Z',
        revoked_at: '2026-08-20T00:01:00Z', created_at: '2026-08-19T00:00:00Z',
      })
    }
    return fulfillJson(route, { error: { code: 'not_found', message: 'not found' } }, 404)
  })
  await page.route(`${issuer}/.well-known/openid-configuration`, async (route) => fulfillJson(route, {
    issuer,
    authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
    token_endpoint: `${issuer}/protocol/openid-connect/token`,
    jwks_uri: `${issuer}/protocol/openid-connect/certs`,
  }))
  await page.route(`${issuer}/protocol/openid-connect/auth**`, async (route) => {
    const requestUrl = new URL(route.request().url())
    const state = requestUrl.searchParams.get('state') ?? ''
    nonce = requestUrl.searchParams.get('nonce') ?? ''
    return route.fulfill({
      status: 302,
      headers: { location: `http://127.0.0.1:5173/callback?code=fixture-code&state=${encodeURIComponent(state)}` },
      body: '',
    })
  })
  await page.route(`${issuer}/protocol/openid-connect/token`, async (route) => {
    const now = Math.floor(Date.now() / 1000)
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url')
    const idToken = `${encode({ alg: 'none', typ: 'JWT' })}.${encode({
      iss: issuer,
      sub: 'oidc-revoke-user',
      aud: 'web-console',
      exp: now + 900,
      iat: now,
      nonce,
    })}.fixture`
    return fulfillJson(route, {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      scope: 'openid profile email',
      id_token: idToken,
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '统一身份登录' }).click()
  await expect(page.getByRole('button', { name: '撤销当前设备' })).toBeVisible()

  let developmentProbe = await failNextOidcUserCleanup(page)
  await page.getByRole('button', { name: '锁定' }).click()
  if (developmentProbe) {
    const cleanupFailure = page.getByRole('alert').filter({ hasText: '本地身份清理未完成' })
    await expect(cleanupFailure).toContainText('平台访问令牌已清除，但旧 OIDC 身份缓存未确认清除')
    await expect(cleanupFailure).toContainText('下一步：点击“重试本地清理”')
    await expect(page.getByText('控制台已安全锁定')).toHaveCount(0)
    await expect(page.getByText('本地身份已清除')).toHaveCount(0)
    await expect(page.getByRole('button', { name: '统一身份登录' })).toHaveCount(0)
    await expect(page.getByText('raw oidc storage cleanup detail')).toHaveCount(0)
    await cleanupFailure.getByRole('button', { name: '重试本地清理' }).click()
  }
  await expect(page.getByRole('button', { name: '统一身份登录' })).toBeVisible()
  await expect(page.getByText('控制台已安全锁定')).toBeVisible()

  await page.getByRole('button', { name: '统一身份登录' }).click()
  await expect(page.getByRole('button', { name: '撤销当前设备' })).toBeVisible()
  developmentProbe = await delayNextOidcUserCleanup(page)
  await page.getByRole('button', { name: '锁定' }).click()
  if (developmentProbe) {
    await expect(page.getByRole('main', { name: '正在清理本地身份' })).toBeVisible()
    await expect(page.getByRole('button', { name: '统一身份登录' })).toHaveCount(0)
    await releaseOidcUserCleanup(page)
  }
  await expect(page.getByRole('button', { name: '统一身份登录' })).toBeVisible()
  await expect(page.getByText('控制台已安全锁定')).toBeVisible()

  await page.getByRole('button', { name: '统一身份登录' }).click()
  await expect(page.getByRole('button', { name: '撤销当前设备' })).toBeVisible()
  developmentProbe = await delayNextOidcUserCleanup(page)
  await page.evaluate(() => window.dispatchEvent(new Event('platform:auth-expiring')))
  if (developmentProbe) {
    await expect(page.getByRole('main', { name: '正在清理本地身份' })).toBeVisible()
    await expect(page.getByRole('button', { name: '统一身份登录' })).toHaveCount(0)
    await releaseOidcUserCleanup(page)
  }
  await expect(page.getByRole('button', { name: '统一身份登录' })).toBeVisible()
  await expect(page.getByText('会话到期前已完成安全清理')).toBeVisible()

  await page.getByRole('button', { name: '统一身份登录' }).click()
  await expect(page.getByRole('button', { name: '撤销当前设备' })).toBeVisible()
  developmentProbe = await delayNextOidcUserCleanup(page)
  await page.evaluate(() => window.dispatchEvent(new Event('platform:auth-expired')))
  if (developmentProbe) {
    await expect(page.getByRole('main', { name: '正在清理本地身份' })).toBeVisible()
    await expect(page.getByRole('button', { name: '统一身份登录' })).toHaveCount(0)
    await releaseOidcUserCleanup(page)
  }
  await expect(page.getByRole('button', { name: '统一身份登录' })).toBeVisible()
  await expect(page.getByText('平台会话已到期，本地登录状态已清除')).toBeVisible()

  await page.getByRole('button', { name: '统一身份登录' }).click()
  const revokeButton = page.getByRole('button', { name: '撤销当前设备' })
  await expect(revokeButton).toBeVisible()
  developmentProbe = await delayNextOidcUserCleanup(page)

  await revokeButton.click()
  await page.getByRole('dialog', { name: '确认撤销当前设备？' })
    .getByRole('button', { name: '撤销设备并清理本地会话' }).click()
  if (developmentProbe) {
    await expect(page.getByRole('main', { name: '正在清理本地身份' })).toBeVisible()
    await expect(page.getByRole('button', { name: '统一身份登录' })).toHaveCount(0)
    await releaseOidcUserCleanup(page)
  }
  await expect(page.getByRole('button', { name: '统一身份登录' })).toBeVisible()
  await expect(page.getByText('当前设备已撤销')).toBeVisible()
  expect(logoutRequests).toBe(3)
})

test('logout keeps the session until server cleanup succeeds and is single-flight', async ({ page }) => {
  const accessValue = 'logout-barrier-access'
  const logoutAuthorizations: string[] = []
  let logoutAttempts = 0
  let releaseFirstAttempt = () => undefined
  let releaseSecondAttempt = () => undefined
  const firstAttemptGate = new Promise<void>((resolve) => { releaseFirstAttempt = resolve })
  const secondAttemptGate = new Promise<void>((resolve) => { releaseSecondAttempt = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      headers: { 'X-Trace-Id': 'logout-trace' },
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({
        mode: 'local', issuer: null, client_id: null,
        desktop_client_id: null, audience: null,
      })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'user-1', tenant_id: 'tenant-1', email: 'operator@example.invalid',
        device_id: 'device-1', role: 'operator',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'own', generated_at: '2026-08-20T00:00:00Z',
        active_tasks: 0, allocated_cards: 0, waiting_mail_sessions: 0,
        queued_uploads: 0, unknown_uploads: 0,
        task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/auth/logout' && request.method() === 'POST') {
      logoutAttempts += 1
      logoutAuthorizations.push(request.headers().authorization ?? '')
      if (logoutAttempts === 1) {
        await firstAttemptGate
        return fulfill({
          error: {
            code: 'service_unavailable',
            message: 'cleanup unavailable',
            recovery_hint: '请检查平台网络。',
          },
        }, 503)
      }
      await secondAttemptGate
      return fulfill({ status: 'logged_out' })
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('operator@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('device-1')
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByText('operator@example.invalid')).toBeVisible()

  const logoutButton = page.getByRole('button', { name: '退出登录' })
  const lockButton = page.getByRole('button', { name: '锁定' })
  await logoutButton.evaluate((button) => {
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
  })
  try {
    await expect.poll(() => logoutAttempts).toBe(1)
    await expect(logoutButton).toBeDisabled()
    await expect(logoutButton).toHaveClass(/ant-btn-loading/)
    await expect(lockButton).toBeDisabled()
    await expect(page.getByText('operator@example.invalid')).toBeVisible()
  } finally {
    releaseFirstAttempt()
  }

  await expect(page.getByText('安全退出未完成')).toBeVisible()
  const logoutFailure = page.getByRole('alert').filter({ hasText: '安全退出未完成' })
  await expect(logoutFailure).toContainText('原因：平台依赖暂不可用，安全退出未确认。')
  await expect(logoutFailure).toContainText('影响：您仍保持登录')
  await expect(logoutFailure).toContainText('下一步：检查网络后再次点击“退出登录”')
  await expect(page.getByText('operator@example.invalid')).toBeVisible()
  await expect(logoutButton).toBeEnabled()
  await expect(lockButton).toBeEnabled()

  await logoutButton.click()
  try {
    await expect.poll(() => logoutAttempts).toBe(2)
    await expect(logoutButton).toBeDisabled()
    await expect(lockButton).toBeDisabled()
    await expect(page.getByText('operator@example.invalid')).toBeVisible()
  } finally {
    releaseSecondAttempt()
  }

  await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible()
  await expect(page.getByText('operator@example.invalid')).toHaveCount(0)
  expect(logoutAttempts).toBe(2)
  expect(logoutAuthorizations).toEqual([
    `Bearer ${accessValue}`,
    `Bearer ${accessValue}`,
  ])
})

test('lock keeps the session until server cleanup succeeds and is single-flight', async ({ page }) => {
  const accessValue = 'lock-barrier-access'
  const logoutAuthorizations: string[] = []
  let logoutAttempts = 0
  let releaseFirstAttempt = () => undefined
  let releaseSecondAttempt = () => undefined
  const firstAttemptGate = new Promise<void>((resolve) => { releaseFirstAttempt = resolve })
  const secondAttemptGate = new Promise<void>((resolve) => { releaseSecondAttempt = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      headers: { 'X-Trace-Id': 'lock-trace' },
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({
        mode: 'local', issuer: null, client_id: null,
        desktop_client_id: null, audience: null,
      })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'user-1', tenant_id: 'tenant-1', email: 'operator@example.invalid',
        device_id: 'device-1', role: 'operator',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'own', generated_at: '2026-08-20T00:00:00Z',
        active_tasks: 1, allocated_cards: 1, waiting_mail_sessions: 1,
        queued_uploads: 0, unknown_uploads: 0,
        task_statuses: { created: 1 }, mail_session_statuses: { waiting: 1 },
        card_allocation_statuses: { active: 1 }, upload_statuses: {},
      })
    }
    if (path === '/api/v1/auth/logout' && request.method() === 'POST') {
      logoutAttempts += 1
      logoutAuthorizations.push(request.headers().authorization ?? '')
      if (logoutAttempts === 1) {
        await firstAttemptGate
        return fulfill({
          error: {
            code: 'service_unavailable',
            message: 'cleanup unavailable',
            recovery_hint: '请检查平台网络。',
          },
        }, 503)
      }
      await secondAttemptGate
      return fulfill({ status: 'logged_out' })
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('operator@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('device-1')
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByText('operator@example.invalid')).toBeVisible()

  const lockButton = page.getByRole('button', { name: '锁定' })
  const logoutButton = page.getByRole('button', { name: '退出登录' })
  await lockButton.evaluate((button) => {
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
  })
  try {
    await expect.poll(() => logoutAttempts).toBe(1)
    await expect(lockButton).toBeDisabled()
    await expect(logoutButton).toBeDisabled()
    await expect(page.getByText('operator@example.invalid')).toBeVisible()
  } finally {
    releaseFirstAttempt()
  }

  await expect(page.getByText('安全锁定未完成')).toBeVisible()
  const lockFailure = page.getByRole('alert').filter({ hasText: '安全锁定未完成' })
  await expect(lockFailure).toContainText('原因：平台依赖暂不可用，安全退出未确认。')
  await expect(lockFailure).toContainText('影响：您仍保持登录，平台不会显示锁定成功')
  await expect(lockFailure).toContainText('下一步：检查网络后再次点击“锁定”')
  await expect(page.getByText('operator@example.invalid')).toBeVisible()
  await expect(lockButton).toBeEnabled()
  await expect(logoutButton).toBeEnabled()

  await lockButton.click()
  try {
    await expect.poll(() => logoutAttempts).toBe(2)
    await expect(lockButton).toBeDisabled()
    await expect(logoutButton).toBeDisabled()
    await expect(page.getByText('operator@example.invalid')).toBeVisible()
  } finally {
    releaseSecondAttempt()
  }

  await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible()
  await expect(page.getByText('控制台已安全锁定')).toBeVisible()
  await expect(page.getByText('operator@example.invalid')).toHaveCount(0)
  expect(logoutAttempts).toBe(2)
  expect(logoutAuthorizations).toEqual([
    `Bearer ${accessValue}`,
    `Bearer ${accessValue}`,
  ])
})

test('hard expiry retires old cleanup without letting its stale completion unlock a new session action', async ({ page }) => {
  const accessValues = ['expiry-old-access', 'expiry-new-access']
  const logoutAuthorizations: string[] = []
  let loginAttempts = 0
  let logoutAttempts = 0
  let completedLogouts = 0
  let releaseOldCleanup = () => undefined
  let releaseNewCleanup = () => undefined
  const oldCleanupGate = new Promise<void>((resolve) => { releaseOldCleanup = resolve })
  const newCleanupGate = new Promise<void>((resolve) => { releaseNewCleanup = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      const accessToken = accessValues[loginAttempts]
      loginAttempts += 1
      return fulfill({ access_token: accessToken, expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'expiry-user', tenant_id: 'tenant-1', email: 'expiry@example.invalid',
        device_id: 'expiry-device', role: 'operator',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'own', generated_at: '2026-08-20T00:00:00Z',
        active_tasks: 1, allocated_cards: 1, waiting_mail_sessions: 1,
        queued_uploads: 1, unknown_uploads: 0,
        task_statuses: { created: 1 }, mail_session_statuses: { waiting: 1 },
        card_allocation_statuses: { allocated: 1 }, upload_statuses: { queued: 1 },
      })
    }
    if (path === '/api/v1/auth/logout' && request.method() === 'POST') {
      logoutAttempts += 1
      logoutAuthorizations.push(request.headers().authorization ?? '')
      if (logoutAttempts === 1) {
        await oldCleanupGate
        completedLogouts += 1
        return fulfill({ status: 'logged_out' })
      }
      await newCleanupGate
      completedLogouts += 1
      return fulfill({
        error: {
          code: 'service_unavailable',
          message: 'cleanup unavailable',
        },
      }, 503)
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  const signIn = async () => {
    await page.getByLabel('租户').fill('tenant-1')
    await page.getByLabel('平台账号').fill('expiry@example.invalid')
    await page.getByLabel('平台密码').fill('development-password')
    await page.getByLabel('设备标识').fill('expiry-device')
    await page.getByRole('button', { name: '安全登录' }).click()
    await expect(page.getByText('expiry@example.invalid')).toBeVisible()
  }

  await page.goto('/')
  await signIn()
  await page.evaluate(() => {
    window.dispatchEvent(new Event('platform:auth-expiring'))
    window.dispatchEvent(new Event('platform:auth-expiring'))
  })
  await expect.poll(() => logoutAttempts).toBe(1)
  const logoutButton = page.getByRole('button', { name: '退出登录' })
  const lockButton = page.getByRole('button', { name: '锁定' })
  await expect(logoutButton).toBeDisabled()
  await expect(logoutButton).toHaveClass(/ant-btn-loading/)
  await expect(lockButton).toBeDisabled()
  await page.evaluate(() => window.dispatchEvent(new Event('platform:auth-expired')))
  await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible()
  const expiredWithPendingCleanup = page.getByRole('alert')
  await expect(expiredWithPendingCleanup).toContainText('到期前的服务端清理请求未能在令牌有效期内确认')
  await expect(page.getByText('expiry@example.invalid')).toHaveCount(0)

  await signIn()
  await page.evaluate(() => window.dispatchEvent(new Event('platform:auth-expiring')))
  await expect.poll(() => logoutAttempts).toBe(2)
  await expect(logoutButton).toBeDisabled()
  await expect(logoutButton).toHaveClass(/ant-btn-loading/)
  await expect(lockButton).toBeDisabled()

  releaseOldCleanup()
  await expect.poll(() => completedLogouts).toBe(1)
  await expect(page.getByText('expiry@example.invalid')).toBeVisible()
  await expect(logoutButton).toBeDisabled()
  await expect(logoutButton).toHaveClass(/ant-btn-loading/)
  await expect(lockButton).toBeDisabled()
  await expect(page.getByText('会话到期前已完成安全清理')).toHaveCount(0)

  releaseNewCleanup()
  await expect.poll(() => completedLogouts).toBe(2)
  const cleanupFailure = page.getByRole('alert')
  await expect(cleanupFailure).toContainText('原因：平台依赖暂不可用，安全退出未确认。')
  await expect(cleanupFailure).toContainText('影响：当前令牌在最终到期前仍保持登录')
  await expect(cleanupFailure).toContainText('不能把本次失败视为服务端已回收')
  await expect(page.getByText('expiry@example.invalid')).toBeVisible()
  await expect(logoutButton).toBeEnabled()
  await expect(lockButton).toBeEnabled()

  await page.evaluate(() => window.dispatchEvent(new Event('platform:auth-expired')))
  await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible()
  const expiredNotice = page.getByRole('alert')
  await expect(expiredNotice).toContainText('平台会话已到期，本地登录状态已清除')
  await expect(expiredNotice).toContainText('平台未确认到期前已回收当前设备资源')
  await expect(expiredNotice).toContainText('不能视为已经回收')
  await expect(page.getByText('expiry@example.invalid')).toHaveCount(0)
  expect(logoutAttempts).toBe(2)
  expect(logoutAuthorizations).toEqual([
    `Bearer ${accessValues[0]}`,
    `Bearer ${accessValues[1]}`,
  ])
})

test('view-scoped confirmations do not survive navigation or hard expiry', async ({ page }) => {
  const task = {
    id: 'task-scoped-confirm', tenant_id: 'tenant-1', user_id: 'user-1', device_id: 'device-1',
    type: 'mail_code', idempotency_key: 'scoped-confirm', client_reference: null,
    trace_id: '00000000-0000-0000-0000-000000000163', status: 'created',
    expires_at: '2026-08-20T01:00:00Z', closed_at: null,
    created_at: '2026-08-20T00:00:00Z',
  }
  let closeAttempts = 0
  let releaseClose = () => undefined
  const closeGate = new Promise<void>((resolve) => { releaseClose = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({
        mode: 'local', issuer: null, client_id: null,
        desktop_client_id: null, audience: null,
      })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: 'scoped-confirm-access', expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'user-1', tenant_id: 'tenant-1', email: 'ops-admin@example.invalid',
        device_id: 'device-1', role: 'ops_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'own', generated_at: '2026-08-20T00:00:00Z',
        active_tasks: 1, allocated_cards: 0, waiting_mail_sessions: 0,
        queued_uploads: 0, unknown_uploads: 0,
        task_statuses: { created: 1 }, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/tasks' && request.method() === 'GET') return fulfill([task])
    if (path === `/api/v1/tasks/${task.id}/close` && request.method() === 'POST') {
      closeAttempts += 1
      await closeGate
      return fulfill({ ...task, status: 'closed', closed_at: '2026-08-20T00:10:00Z' })
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('ops-admin@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('device-1')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('任务中心', { exact: true }).click()

  const closeButton = page.getByRole('button', { name: `关闭任务 ${task.id}`, exact: true })
  await expect(closeButton).toBeVisible()
  await closeButton.click()
  let dialog = page.getByRole('dialog', { name: `确认关闭任务 ${task.id}？`, exact: true })
  await expect(dialog).toBeVisible()
  await page.getByText('工作台', { exact: true }).dispatchEvent('click')
  await expect(page.getByRole('heading', { name: '工作台', exact: true })).toBeVisible()
  await expect(dialog).toHaveCount(0)

  await page.getByText('任务中心', { exact: true }).click()
  await expect(closeButton).toBeVisible()
  await closeButton.click()
  dialog = page.getByRole('dialog', { name: `确认关闭任务 ${task.id}？`, exact: true })
  const closeResponse = page.waitForResponse((response) => (
    new URL(response.url()).pathname === `/api/v1/tasks/${task.id}/close`
  ))
  const loginAccount = page.getByLabel('平台账号')
  try {
    await dialog.getByRole('button', { name: '关闭任务并回收资源' }).click()
    await expect.poll(() => closeAttempts).toBe(1)
    await expect(dialog.getByRole('button', { name: '关闭任务并回收资源' })).toHaveClass(/ant-btn-loading/)

    await page.evaluate(() => window.dispatchEvent(new Event('platform:auth-expired')))
    await expect(dialog).toHaveCount(0)
    await expect(loginAccount).toBeVisible()
    await loginAccount.fill('fresh-login@example.invalid')
    await loginAccount.focus()
    await expect(loginAccount).toBeFocused()
  } finally {
    releaseClose()
  }

  await closeResponse
  await page.evaluate(() => new Promise<void>((resolve) => {
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => resolve()))
  }))
  await expect.poll(() => closeAttempts).toBe(1)
  await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible()
  await expect(loginAccount).toHaveValue('fresh-login@example.invalid')
  await expect(loginAccount).toBeFocused()
  await expect(page.getByText('任务已关闭，相关卡租约、邮箱会话和上传资源已回收。')).toHaveCount(0)
})

test('ops admin safely closes tasks with single-flight recovery', async ({ page }) => {
  const accessValue = 'task-close-access'
  const taskTrace = '00000000-0000-0000-0000-000000000043'
  const tasks: Record<string, {
    id: string
    tenant_id: string
    user_id: string
    device_id: string
    type: string
    idempotency_key: string
    client_reference: null
    trace_id: string
    status: string
    expires_at: string
    closed_at: string | null
    created_at: string
  }> = {
    'task-success': {
      id: 'task-success', tenant_id: 'tenant-1', user_id: 'user-1', device_id: 'device-1',
      type: 'mail_code', idempotency_key: 'close-success', client_reference: null,
      trace_id: taskTrace, status: 'created', expires_at: '2026-08-20T01:00:00Z',
      closed_at: null, created_at: '2026-08-20T00:00:00Z',
    },
    'task-retry': {
      id: 'task-retry', tenant_id: 'tenant-1', user_id: 'user-1', device_id: 'device-1',
      type: 'mail_code', idempotency_key: 'close-retry', client_reference: null,
      trace_id: '00000000-0000-0000-0000-000000000044', status: 'created',
      expires_at: '2026-08-20T01:00:00Z', closed_at: null,
      created_at: '2026-08-20T00:01:00Z',
    },
  }
  const closeTaskIds: string[] = []
  const timelineRequests: Record<string, number> = {}
  let taskListRequests = 0
  let retryAttempts = 0
  let releaseSuccessClose = () => undefined
  const successCloseGate = new Promise<void>((resolve) => {
    releaseSuccessClose = resolve
  })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      headers: { 'X-Trace-Id': taskTrace },
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({
        mode: 'local', issuer: null, client_id: null,
        desktop_client_id: null, audience: null,
      })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'user-1', tenant_id: 'tenant-1', email: 'ops-admin@example.invalid',
        device_id: 'device-1', role: 'ops_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'own', generated_at: '2026-08-20T00:00:00Z',
        active_tasks: 2, allocated_cards: 2, waiting_mail_sessions: 2,
        queued_uploads: 2, unknown_uploads: 0,
        task_statuses: { created: 2 }, mail_session_statuses: { waiting: 2 },
        card_allocation_statuses: { active: 2 }, upload_statuses: { queued: 2 },
      })
    }
    if (path === '/api/v1/tasks' && request.method() === 'GET') {
      taskListRequests += 1
      return fulfill(Object.values(tasks))
    }
    const timelineMatch = path.match(/^\/api\/v1\/tasks\/([^/]+)\/timeline$/)
    if (timelineMatch && request.method() === 'GET') {
      const taskId = timelineMatch[1]
      const task = tasks[taskId]
      timelineRequests[taskId] = (timelineRequests[taskId] ?? 0) + 1
      return fulfill({
        task,
        workbench_step: task.status === 'closed' ? 'completed' : 'uploading',
        mail_session: {
          id: `mail-${taskId}`, email_masked: 'm***@example.invalid',
          status: task.status === 'closed' ? 'revoked' : 'consumed',
          expires_at: '2026-08-20T00:30:00Z', consumed_at: '2026-08-20T00:03:00Z',
          created_at: '2026-08-20T00:01:00Z',
        },
        card_allocations: [{
          id: `allocation-${taskId}`, card_masked: '**** **** **** 4242', brand: 'VISA',
          status: task.status === 'closed' ? 'released' : 'active',
          expires_at: '2026-08-20T00:30:00Z',
          released_at: task.status === 'closed' ? task.closed_at : null,
          created_at: '2026-08-20T00:01:00Z',
        }],
        uploads: [{
          id: `upload-${taskId}`, business_name: 'Operator Store',
          status: task.status === 'closed' ? 'cancelled' : 'queued',
          policy_version: 'policy-v1', external_ref: null, error_code: null,
          created_at: '2026-08-20T00:04:00Z', updated_at: '2026-08-20T00:05:00Z',
        }],
        events: task.status === 'closed' ? [{
          id: `event-${taskId}`, event_type: 'task.closed', action: 'task_close',
          result: 'success', entity_type: 'task', entity_id: taskId,
          policy_version: null, created_at: task.closed_at,
        }] : [],
      })
    }
    const closeMatch = path.match(/^\/api\/v1\/tasks\/([^/]+)\/close$/)
    if (closeMatch && request.method() === 'POST') {
      const taskId = closeMatch[1]
      closeTaskIds.push(taskId)
      if (taskId === 'task-success') await successCloseGate
      if (taskId === 'task-retry') {
        retryAttempts += 1
        if (retryAttempts === 1) {
          return fulfill({
            error: { code: 'service_unavailable', message: 'temporary task service failure' },
          }, 503)
        }
      }
      tasks[taskId].status = 'closed'
      tasks[taskId].closed_at = '2026-08-20T00:10:00Z'
      return fulfill(tasks[taskId])
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('ops-admin@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('device-1')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('任务中心', { exact: true }).click()

  const successRow = page.getByRole('row').filter({ hasText: 'task-success' })
  const retryRow = page.getByRole('row').filter({ hasText: 'task-retry' })
  const successCloseButton = successRow.getByRole('button', { name: '关闭任务 task-success', exact: true })
  const retryCloseButton = retryRow.getByRole('button', { name: '关闭任务 task-retry', exact: true })
  await expect(successCloseButton).toBeVisible()
  await expect(retryCloseButton).toBeVisible()
  await expect(page.getByRole('button', { name: '关闭任务', exact: true })).toHaveCount(0)
  await successRow.getByRole('button', { name: '查看任务 task-success 详情', exact: true }).click()
  await expect.poll(() => timelineRequests['task-success'] ?? 0).toBeGreaterThanOrEqual(1)

  await successCloseButton.click()
  let closeDialog = page.getByRole('dialog', { name: '确认关闭任务 task-success？', exact: true })
  await expect(closeDialog).toContainText('任务 ID：task-success')
  await expect(closeDialog).toContainText('任务不可恢复')
  await expect(closeDialog).toContainText('邮箱会话和未消费验证码会立即清理')
  await closeDialog.getByRole('button', { name: /取\s*消/ }).click()
  await expect(closeDialog).toBeHidden()
  expect(closeTaskIds).toEqual([])

  await successCloseButton.click()
  closeDialog = page.getByRole('dialog', { name: '确认关闭任务 task-success？', exact: true })
  const visibleTaskId = (await closeDialog.getByText(/^任务 ID：/).textContent())?.replace('任务 ID：', '') ?? ''
  expect(visibleTaskId).toBe('task-success')
  const confirmClose = closeDialog.getByRole('button', { name: '关闭任务并回收资源' })
  const successCloseResponse = page.waitForResponse((response) => (
    new URL(response.url()).pathname === '/api/v1/tasks/task-success/close'
  ))
  await confirmClose.click()
  try {
    await expect.poll(() => closeTaskIds).toEqual([visibleTaskId])
    const pendingButton = successRow.getByRole('button', { name: '关闭任务 task-success', exact: true })
    await expect(pendingButton).toBeDisabled()
    await expect(pendingButton).toHaveClass(/ant-btn-loading/)
    await expect(retryCloseButton).toBeDisabled()
    await confirmClose.dispatchEvent('click')
    expect(closeTaskIds).toEqual(['task-success'])
    await page.getByText('工作台', { exact: true }).dispatchEvent('click')
    await expect(page.getByRole('heading', { name: '工作台', exact: true })).toBeVisible()
    const workbenchMenuItem = page.getByRole('menuitem', { name: /工作台/ })
    await workbenchMenuItem.focus()
    await expect(workbenchMenuItem).toBeFocused()
  } finally {
    releaseSuccessClose()
  }
  await successCloseResponse
  await page.evaluate(() => new Promise<void>((resolve) => {
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => resolve()))
  }))
  await page.waitForTimeout(300)
  await expect(page.getByText('任务已关闭，相关卡租约、邮箱会话和上传资源已回收。')).toHaveCount(0)
  await expect(page.getByRole('menuitem', { name: /工作台/ })).toBeFocused()
  await page.getByText('任务中心', { exact: true }).click()
  await expect(successRow.getByText('closed')).toBeVisible()
  await expect(successCloseButton).toBeDisabled()
  await expect.poll(() => taskListRequests).toBeGreaterThanOrEqual(2)
  await successRow.getByRole('button', { name: '查看任务 task-success 详情', exact: true }).click()
  await expect.poll(() => timelineRequests['task-success'] ?? 0).toBeGreaterThanOrEqual(2)
  const taskDetail = page.locator('.task-detail-card')
  await expect(taskDetail.getByText('revoked')).toBeVisible()
  await expect(taskDetail.getByText('released')).toBeVisible()
  await expect(taskDetail.getByText('cancelled')).toBeVisible()

  const listsBeforeRetryFailure = taskListRequests
  await retryCloseButton.click()
  closeDialog = page.getByRole('dialog', { name: '确认关闭任务 task-retry？', exact: true })
  await expect(closeDialog).toContainText('任务 ID：task-retry')
  await closeDialog.getByRole('button', { name: '关闭任务并回收资源' }).click()
  const failureNotice = page.getByText(/原因：平台依赖暂不可用，请稍后重试。.*影响：.*下一步：/)
  await expect(failureNotice).toContainText('任务关闭可能已在服务端提交')
  await expect(failureNotice).toContainText('页面不会按失败响应推断最终状态')
  await expect(failureNotice).toContainText('已刷新任务 task-retry 的真实状态')
  await expect(failureNotice).toContainText('仅当该任务仍为非终态时')
  await expect(closeDialog).toBeHidden()
  await expect.poll(() => taskListRequests).toBeGreaterThan(listsBeforeRetryFailure)
  await expect(retryCloseButton).toBeEnabled()
  expect(closeTaskIds.filter((id) => id === 'task-retry')).toHaveLength(1)

  await retryCloseButton.click()
  closeDialog = page.getByRole('dialog', { name: '确认关闭任务 task-retry？', exact: true })
  await closeDialog.getByRole('button', { name: '关闭任务并回收资源' }).click()
  await expect(retryRow.getByText('closed')).toBeVisible()
  expect(closeTaskIds.filter((id) => id === 'task-retry')).toHaveLength(2)
})

test('task filters fail closed without reviving stale rows or actions', async ({ page }) => {
  const makeTask = (id: string, userId: string) => ({
    id, tenant_id: 'tenant-1', user_id: userId, device_id: `device-${userId}`,
    type: 'mail_code', idempotency_key: `key-${id}`, client_reference: null,
    trace_id: `trace-${id}`, status: 'created', expires_at: '2026-08-20T01:00:00Z',
    closed_at: null, created_at: '2026-08-20T00:00:00Z',
  })
  const oldTask = makeTask('task-old-filter-result', 'user-old')
  const lateTask = makeTask('task-late-filter-result', 'user-late')
  const currentTask = makeTask('task-current-filter-result', 'user-current-success')
  const requestedUsers: string[] = []
  let releaseLateRequest = () => undefined
  let lateRequestCompleted = false
  const lateRequestGate = new Promise<void>((resolve) => { releaseLateRequest = resolve })
  let releaseCurrentSuccess = () => undefined
  const currentSuccessGate = new Promise<void>((resolve) => { releaseCurrentSuccess = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: 'task-filter-access', expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'ops-user', tenant_id: 'tenant-1', email: 'ops@example.invalid',
        device_id: 'ops-device', role: 'ops_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 1,
        allocated_cards: 1, waiting_mail_sessions: 1, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: { created: 1 },
        mail_session_statuses: { waiting: 1 }, card_allocation_statuses: { active: 1 },
        upload_statuses: {},
      })
    }
    if (path === '/api/v1/tasks' && request.method() === 'GET') {
      const userId = url.searchParams.get('user_id') ?? ''
      requestedUsers.push(userId)
      if (!userId) return fulfill([oldTask])
      if (userId === 'user-late') {
        await lateRequestGate
        lateRequestCompleted = true
        return fulfill([lateTask])
      }
      if (userId === 'user-current-error') {
        return fulfill({
          error: { code: 'service_unavailable', message: 'task query unavailable' },
        }, 503)
      }
      expect(userId).toBe('user-current-success')
      await currentSuccessGate
      return fulfill([currentTask])
    }
    if (path === `/api/v1/tasks/${currentTask.id}/timeline`) {
      return fulfill({
        error: { code: 'service_unavailable', message: 'timeline unavailable' },
      }, 503)
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('ops@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('ops-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('任务中心', { exact: true }).click()

  await expect(page.getByRole('button', { name: `关闭任务 ${oldTask.id}` })).toBeVisible()
  await page.getByRole('button', { name: `查看任务 ${oldTask.id} 详情` }).click()
  await expect(page.getByText(oldTask.id, { exact: true })).toBeVisible()

  await page.getByLabel('用户 ID').fill('user-late')
  await page.getByRole('button', { name: /^筛\s*选$/ }).click()
  try {
    await expect.poll(() => requestedUsers.includes('user-late')).toBe(true)
    await expect(page.locator('.ant-spin')).toBeVisible()

    await page.getByLabel('用户 ID').fill('user-current-error')
    await page.getByRole('button', { name: /^筛\s*选$/ }).click()
    await expect.poll(() => requestedUsers.includes('user-current-error')).toBe(true)
    const listError = page.getByRole('alert')
    for (const marker of ['原因：', '影响：', '下一步：']) {
      await expect(listError).toContainText(marker)
    }
    await expect(page.getByRole('button', { name: `关闭任务 ${oldTask.id}` })).toHaveCount(0)
    await expect(page.getByText(oldTask.id, { exact: true })).toHaveCount(0)
    await expect(page.getByText('任务详情', { exact: true })).toHaveCount(0)
  } finally {
    releaseLateRequest()
  }

  await expect.poll(() => lateRequestCompleted).toBe(true)
  await expect(page.getByRole('alert')).toContainText('任务列表真实状态刷新失败')
  await expect(page.getByRole('button', { name: `关闭任务 ${lateTask.id}` })).toHaveCount(0)

  await page.getByLabel('用户 ID').fill('user-current-success')
    await page.getByRole('button', { name: /^筛\s*选$/ }).click()
  try {
    await expect.poll(() => requestedUsers.includes('user-current-success')).toBe(true)
    await expect(page.locator('.ant-spin')).toBeVisible()
    await expect(page.getByRole('alert')).toHaveCount(0)
  } finally {
    releaseCurrentSuccess()
  }

  await expect(page.getByRole('button', { name: `关闭任务 ${currentTask.id}` })).toBeVisible()
  await expect(page.getByRole('button', { name: `关闭任务 ${oldTask.id}` })).toHaveCount(0)
  await expect(page.getByText('任务详情', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: `查看任务 ${currentTask.id} 详情` }).click()
  await expect(page.getByText(currentTask.id, { exact: true })).toBeVisible()
})

test('ops admin filters and governs same-tenant cross-device tasks', async ({ page }) => {
  const taskTrace = '00000000-0000-0000-0000-000000000099'
  const task = {
    id: 'task-cross-device', tenant_id: 'tenant-1', user_id: 'operator-user-9',
    device_id: 'desktop-device-9', type: 'mail_code', idempotency_key: 'cross-device-task',
    client_reference: null, trace_id: taskTrace, status: 'created',
    expires_at: '2026-08-20T01:00:00Z', closed_at: null as string | null,
    created_at: '2026-08-20T00:00:00Z',
  }
  const taskListQueries: URLSearchParams[] = []
  let closeRequests = 0

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({
        mode: 'local', issuer: null, client_id: null,
        desktop_client_id: null, audience: null,
      })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: 'ops-task-access', expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'ops-user', tenant_id: 'tenant-1', email: 'ops@example.invalid',
        device_id: 'ops-browser-device', role: 'ops_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z',
        active_tasks: 1, allocated_cards: 1, waiting_mail_sessions: 1,
        queued_uploads: 0, unknown_uploads: 0,
        task_statuses: { created: 1 }, mail_session_statuses: { waiting: 1 },
        card_allocation_statuses: { active: 1 }, upload_statuses: {},
      })
    }
    if (path === '/api/v1/tasks' && request.method() === 'GET') {
      taskListQueries.push(new URLSearchParams(url.search))
      return fulfill([task])
    }
    if (path === `/api/v1/tasks/${task.id}/timeline`) {
      return fulfill({
        task,
        mail_session: {
          id: 'mail-cross-device', email_masked: 'o***@example.invalid', status: 'waiting',
          expires_at: '2026-08-20T00:30:00Z', consumed_at: null,
          created_at: '2026-08-20T00:01:00Z',
        },
        card_allocations: [{
          id: 'allocation-cross-device', card_masked: '**** **** **** 4242', brand: 'VISA',
          status: task.status === 'closed' ? 'released' : 'active',
          expires_at: '2026-08-20T00:30:00Z', released_at: task.closed_at,
          created_at: '2026-08-20T00:01:00Z',
        }],
        uploads: [],
        events: [{
          id: 'event-cross-device', event_type: 'task.created', action: 'task_create',
          result: 'success', entity_type: 'task', entity_id: task.id,
          policy_version: null, created_at: '2026-08-20T00:00:00Z',
          details: {
            pan: '4111111111114242', session_token: 'mail-session-secret',
            secret_ref: 'vault://secret/cards/cross-device',
          },
        }],
      })
    }
    if (path === `/api/v1/tasks/${task.id}/close` && request.method() === 'POST') {
      closeRequests += 1
      task.status = 'closed'
      task.closed_at = '2026-08-20T00:10:00Z'
      return fulfill(task)
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('ops@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('ops-browser-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('任务中心', { exact: true }).click()

  await expect(page.getByRole('columnheader', { name: '用户' })).toBeVisible()
  await expect(page.getByRole('columnheader', { name: '设备' })).toBeVisible()
  await expect(page.getByText('operator-user-9').first()).toBeVisible()
  await expect(page.getByText('desktop-device-9').first()).toBeVisible()
  await page.getByLabel('用户 ID').fill('operator-user-9')
  await page.getByLabel('trace_id').fill(taskTrace)
  await page.getByRole('button', { name: /^筛\s*选$/ }).click()
  await expect.poll(() => taskListQueries.length).toBeGreaterThanOrEqual(2)
  const appliedQuery = taskListQueries.at(-1)
  expect(appliedQuery?.get('user_id')).toBe('operator-user-9')
  expect(appliedQuery?.get('trace_id')).toBe(taskTrace)

  await page.getByRole('button', { name: `查看任务 ${task.id} 详情`, exact: true }).click()
  await expect(page.getByText('o***@example.invalid')).toBeVisible()
  await expect(page.getByText('**** **** **** 4242')).toBeVisible()
  await expect(page.locator('body')).not.toContainText('4111111111114242')
  await expect(page.locator('body')).not.toContainText('mail-session-secret')
  await expect(page.locator('body')).not.toContainText('vault://secret/cards/cross-device')

  const taskRow = page.getByRole('row').filter({ hasText: 'operator-user-9' })
  await taskRow.getByRole('button', { name: `关闭任务 ${task.id}`, exact: true }).click()
  await page.getByRole('dialog', { name: `确认关闭任务 ${task.id}？`, exact: true })
    .getByRole('button', { name: '关闭任务并回收资源' }).click()
  await expect(taskRow.getByText('closed')).toBeVisible()
  expect(closeRequests).toBe(1)
})

test('task details never mix a filtered task with a stale or late timeline', async ({ page }) => {
  const taskA = {
    id: 'task-a', tenant_id: 'tenant-1', user_id: 'user-a', device_id: 'device-a',
    type: 'mail_code', idempotency_key: 'request-a', client_reference: null,
    trace_id: 'trace-a', status: 'created', expires_at: '2026-08-20T01:00:00Z',
    closed_at: null, created_at: '2026-08-20T00:00:00Z',
  }
  const taskB = {
    id: 'task-b', tenant_id: 'tenant-1', user_id: 'user-b', device_id: 'device-b',
    type: 'mail_code', idempotency_key: 'request-b', client_reference: null,
    trace_id: 'trace-b', status: 'created', expires_at: '2026-08-20T01:00:00Z',
    closed_at: null, created_at: '2026-08-20T00:01:00Z',
  }
  const timeline = (task: typeof taskA, prefix: 'a' | 'b', last4: string) => ({
    task,
    mail_session: {
      id: `mail-${prefix}`, email_masked: `${prefix}***@example.invalid`, status: 'waiting',
      expires_at: '2026-08-20T00:30:00Z', consumed_at: null,
      created_at: '2026-08-20T00:01:00Z',
    },
    card_allocations: [{
      id: `allocation-${prefix}`, card_masked: `**** **** **** ${last4}`, brand: 'VISA',
      status: 'active', expires_at: '2026-08-20T00:30:00Z', released_at: null,
      created_at: '2026-08-20T00:01:00Z',
    }],
    uploads: [{
      id: `upload-${prefix}`, business_name: `business-${prefix}`, status: 'queued',
      policy_version: 'policy-v1', external_ref: null, error_code: null,
      created_at: '2026-08-20T00:02:00Z', updated_at: '2026-08-20T00:02:00Z',
    }],
    events: [{
      id: `event-${prefix}`, event_type: 'task.created', action: 'task_create',
      result: 'success', entity_type: 'task', entity_id: task.id,
      policy_version: null, created_at: '2026-08-20T00:00:00Z', details: {},
    }],
  })
  let releaseFirstFilteredList = () => undefined
  const firstFilteredListGate = new Promise<void>((resolve) => { releaseFirstFilteredList = resolve })
  let releaseSecondFilteredList = () => undefined
  const secondFilteredListGate = new Promise<void>((resolve) => { releaseSecondFilteredList = resolve })
  let releaseLateTimelineA = () => undefined
  const lateTimelineAGate = new Promise<void>((resolve) => { releaseLateTimelineA = resolve })
  let filteredListRequests = 0
  let timelineARequests = 0
  let timelineAResponses = 0

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: 'task-detail-isolation-access', expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'ops-user', tenant_id: 'tenant-1', email: 'ops@example.invalid',
        device_id: 'ops-device', role: 'ops_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 2,
        allocated_cards: 2, waiting_mail_sessions: 2, queued_uploads: 2,
        unknown_uploads: 0, task_statuses: { created: 2 },
        mail_session_statuses: { waiting: 2 }, card_allocation_statuses: { active: 2 },
        upload_statuses: { queued: 2 },
      })
    }
    if (path === '/api/v1/tasks' && request.method() === 'GET') {
      if (url.searchParams.get('user_id') === taskB.user_id) {
        const requestIndex = filteredListRequests
        filteredListRequests += 1
        await (requestIndex === 0 ? firstFilteredListGate : secondFilteredListGate)
        return fulfill([taskB])
      }
      return fulfill([taskA, taskB])
    }
    if (path === `/api/v1/tasks/${taskA.id}/timeline`) {
      timelineARequests += 1
      if (timelineARequests === 2) await lateTimelineAGate
      timelineAResponses += 1
      return fulfill(timeline(taskA, 'a', '1111'))
    }
    if (path === `/api/v1/tasks/${taskB.id}/timeline`) {
      return fulfill(timeline(taskB, 'b', '2222'))
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('ops@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('ops-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('任务中心', { exact: true }).click()

  let taskARow = page.getByRole('row').filter({ hasText: taskA.user_id })
  await taskARow.getByRole('button', { name: `查看任务 ${taskA.id} 详情`, exact: true }).click()
  await expect(page.getByText('a***@example.invalid')).toBeVisible()
  await expect(page.getByText('**** **** **** 1111')).toBeVisible()
  await expect(page.getByText('business-a')).toBeVisible()

  await page.getByLabel('用户 ID').fill(taskB.user_id)
  await page.getByRole('button', { name: /^筛\s*选$/ }).click()
  try {
    await expect.poll(() => filteredListRequests).toBe(1)
    await expect(page.getByText('任务详情', { exact: true })).toHaveCount(0)
    await expect(page.getByText('a***@example.invalid')).toHaveCount(0)
    await expect(page.getByText('**** **** **** 1111')).toHaveCount(0)
  } finally {
    releaseFirstFilteredList()
  }

  let taskBRow = page.getByRole('row').filter({ hasText: taskB.user_id })
  await expect(taskBRow).toBeVisible()
  await expect(taskARow).toHaveCount(0)
  await expect(page.getByText('任务详情', { exact: true })).toHaveCount(0)
  await taskBRow.getByRole('button', { name: `查看任务 ${taskB.id} 详情`, exact: true }).click()
  await expect(page.getByText('b***@example.invalid')).toBeVisible()
  await expect(page.getByText('**** **** **** 2222')).toBeVisible()
  await expect(page.getByText('business-b')).toBeVisible()
  await expect(page.getByText('a***@example.invalid')).toHaveCount(0)

  await page.getByRole('button', { name: '清除筛选' }).click()
  await expect(page.getByText('任务详情', { exact: true })).toHaveCount(0)
  taskARow = page.getByRole('row').filter({ hasText: taskA.user_id })
  await expect(taskARow).toBeVisible()
  await taskARow.getByRole('button', { name: `查看任务 ${taskA.id} 详情`, exact: true }).click()
  await expect.poll(() => timelineARequests).toBe(2)

  await page.getByLabel('用户 ID').fill(taskB.user_id)
    await page.getByRole('button', { name: /^筛\s*选$/ }).click()
  try {
    await expect.poll(() => filteredListRequests).toBe(2)
    await expect(page.getByText('任务详情', { exact: true })).toHaveCount(0)
  } finally {
    releaseSecondFilteredList()
  }
  taskBRow = page.getByRole('row').filter({ hasText: taskB.user_id })
  await expect(taskBRow).toBeVisible()
  await expect(page.getByText('任务详情', { exact: true })).toHaveCount(0)

  releaseLateTimelineA()
  await expect.poll(() => timelineAResponses).toBe(2)
  await expect(page.getByText('任务详情', { exact: true })).toHaveCount(0)
  await expect(page.getByText('a***@example.invalid')).toHaveCount(0)

  await taskBRow.getByRole('button', { name: `查看任务 ${taskB.id} 详情`, exact: true }).click()
  await expect(page.getByText('b***@example.invalid')).toBeVisible()
  await expect(page.getByText('**** **** **** 2222')).toBeVisible()
  await expect(page.getByText('business-b')).toBeVisible()
  await expect(page.getByText('a***@example.invalid')).toHaveCount(0)
})

test('audit table isolates stale loads and recovers from the current error', async ({ page }) => {
  const auditActors: string[] = []
  let releaseLateRequest = () => undefined
  let lateRequestCompleted = false
  const lateRequestGate = new Promise<void>((resolve) => { releaseLateRequest = resolve })
  let releaseCurrentSuccess = () => undefined
  const currentSuccessGate = new Promise<void>((resolve) => { releaseCurrentSuccess = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: 'audit-recovery-access', expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'audit-user', tenant_id: 'tenant-1', email: 'auditor@example.invalid',
        device_id: 'audit-device', role: 'security_auditor',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
        allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/admin/audit') {
      const actor = url.searchParams.get('actor_id') ?? ''
      auditActors.push(actor)
      if (!actor) {
        return fulfill({
          error: { code: 'service_unavailable', message: 'audit temporarily unavailable' },
        }, 503)
      }
      if (actor === 'actor-late') {
        await lateRequestGate
        lateRequestCompleted = true
        return fulfill([{
          id: 'audit-late', tenant_id: 'tenant-1', actor_id: actor,
          user_id: 'subject-late', device_id: 'device-late', event_type: 'task_review',
          action: 'audit.late', result: 'success', entity_type: 'task',
          entity_id: 'task-late', trace_id: '00000000-0000-0000-0000-000000000087',
          ip_address: '192.0.2.19', user_agent: 'LateBrowser/1.0',
          policy_version: null, details: {}, created_at: '2026-08-20T00:00:00Z',
        }])
      }
      if (actor === 'actor-current-error') {
        return fulfill({
          error: { code: 'conflict', message: 'current audit query conflict' },
        }, 409)
      }
      expect(actor).toBe('actor-current-success')
      await currentSuccessGate
      return fulfill([{
        id: 'audit-current', tenant_id: 'tenant-1', actor_id: actor,
        user_id: 'subject-1', device_id: 'device-1', event_type: 'task_review',
        action: 'audit.current', result: 'success', entity_type: 'task',
        entity_id: 'task-1', trace_id: '00000000-0000-0000-0000-000000000088',
        ip_address: '192.0.2.20', user_agent: 'SecureBrowser/1.0',
        policy_version: null, details: {}, created_at: '2026-08-20T00:00:00Z',
      }])
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('auditor@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('audit-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('审计中心', { exact: true }).click()

  await expect(page.getByText('数据暂不可用')).toBeVisible()
  await expect(page.getByRole('alert')).toContainText('平台依赖暂不可用，请稍后重试。')
  await page.getByLabel('操作者').fill('actor-late')
  await page.getByRole('button', { name: /检\s*索/ }).click()
  try {
    await expect.poll(() => auditActors.includes('actor-late')).toBe(true)
    await expect(page.locator('.ant-spin')).toBeVisible()
    await expect(page.getByText('数据暂不可用')).toHaveCount(0)

    await page.getByLabel('操作者').fill('actor-current-error')
    await page.getByRole('button', { name: /检\s*索/ }).click()
    await expect.poll(() => auditActors.includes('actor-current-error')).toBe(true)
    await expect(page.getByRole('alert')).toContainText('当前资源状态已变化，请刷新后继续。')
  } finally {
    releaseLateRequest()
  }
  await expect.poll(() => lateRequestCompleted).toBe(true)
  await expect(page.getByRole('alert')).toContainText('当前资源状态已变化，请刷新后继续。')
  await expect(page.getByText('audit.late')).toHaveCount(0)

  await page.getByLabel('操作者').fill('actor-current-success')
  await page.getByRole('button', { name: /检\s*索/ }).click()
  try {
    await expect.poll(() => auditActors.includes('actor-current-success')).toBe(true)
    await expect(page.locator('.ant-spin')).toBeVisible()
    await expect(page.getByText('数据暂不可用')).toHaveCount(0)
  } finally {
    releaseCurrentSuccess()
  }

  await expect(page.getByText('audit.current')).toBeVisible()
  await expect(page.getByText('audit.late')).toHaveCount(0)
  await expect(page.getByText('数据暂不可用')).toHaveCount(0)
})

test('audit action filter is shared by list and export and cleared atomically', async ({ page }) => {
  const listQueries: URLSearchParams[] = []
  const exportQueries: URLSearchParams[] = []
  const taskId = '00000000-0000-0000-0000-000000000041'
  const cardId = '00000000-0000-0000-0000-000000000042'
  const deviceId = '00000000-0000-0000-0000-000000000043'

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({
        mode: 'local', issuer: null, client_id: null,
        desktop_client_id: null, audience: null,
      })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: 'audit-action-access', expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'audit-action-user', tenant_id: 'tenant-1',
        email: 'audit-action@example.invalid', device_id: 'audit-action-device',
        role: 'security_auditor',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
        allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/admin/audit') {
      listQueries.push(new URLSearchParams(url.search))
      return fulfill([])
    }
    if (path === '/api/v1/admin/audit/export') {
      exportQueries.push(new URLSearchParams(url.search))
      return route.fulfill({
        status: 200,
        contentType: 'text/csv',
        headers: { 'Content-Disposition': 'attachment; filename="audit-redacted.csv"' },
        body: 'created_at,action\n2026-08-20T00:00:00Z,task.close\n',
      })
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('audit-action@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('audit-action-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('审计中心', { exact: true }).click()

  await page.getByLabel('动作').fill('task.close')
  await page.getByLabel('任务 ID').fill(taskId)
  await page.getByLabel('卡 ID').fill(cardId)
  await page.getByLabel('设备 ID').fill(deviceId)
  await page.getByRole('button', { name: /检\s*索/ }).click()
  await expect.poll(() => listQueries.some((query) => query.get('action') === 'task.close')).toBe(true)
  const appliedList = [...listQueries].reverse().find(
    (query) => query.get('action') === 'task.close',
  )
  expect(Object.fromEntries(appliedList ?? [])).toMatchObject({
    action: 'task.close',
    task_id: taskId,
    card_id: cardId,
    device_id: deviceId,
    limit: '200',
  })

  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: /导出脱敏 CSV/ }).click()
  await downloadPromise
  await expect.poll(() => exportQueries.length).toBe(1)
  expect(Object.fromEntries(exportQueries[0])).toMatchObject({
    action: 'task.close',
    task_id: taskId,
    card_id: cardId,
    device_id: deviceId,
    limit: '5000',
  })

  const listCountBeforeClear = listQueries.length
  await page.getByRole('button', { name: /清\s*空/ }).click()
  await expect(page.getByLabel('动作')).toHaveValue('')
  await expect(page.getByLabel('任务 ID')).toHaveValue('')
  await expect(page.getByLabel('卡 ID')).toHaveValue('')
  await expect(page.getByLabel('设备 ID')).toHaveValue('')
  await expect.poll(() => listQueries.length).toBeGreaterThan(listCountBeforeClear)
  expect(listQueries.at(-1)?.has('action')).toBe(false)
  expect(listQueries.at(-1)?.has('task_id')).toBe(false)
  expect(listQueries.at(-1)?.has('card_id')).toBe(false)
  expect(listQueries.at(-1)?.has('device_id')).toBe(false)
})

test('security auditor filters and downloads redacted audit evidence', async ({ page }) => {
  const accessValue = 'audit-memory-access'
  const auditTrace = '00000000-0000-0000-0000-000000000077'
  const listQueries: URLSearchParams[] = []
  const exportQueries: URLSearchParams[] = []
  const reconcileRequests: Array<{ jobId: string; body: Record<string, unknown> }> = []
  let releaseFirstExport = () => undefined
  const firstExportGate = new Promise<void>((resolve) => { releaseFirstExport = resolve })

  await page.addInitScript(() => {
    const trackedWindow = window as typeof window & {
      __auditCreateCount?: number
      __auditRevokeCount?: number
    }
    trackedWindow.__auditCreateCount = 0
    trackedWindow.__auditRevokeCount = 0
    const create = URL.createObjectURL.bind(URL)
    const revoke = URL.revokeObjectURL.bind(URL)
    URL.createObjectURL = (object) => {
      trackedWindow.__auditCreateCount = (trackedWindow.__auditCreateCount ?? 0) + 1
      return create(object)
    }
    URL.revokeObjectURL = (url) => {
      trackedWindow.__auditRevokeCount = (trackedWindow.__auditRevokeCount ?? 0) + 1
      revoke(url)
    }
  })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      headers: { 'X-Trace-Id': auditTrace },
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'audit-user', tenant_id: 'tenant-1', email: 'auditor@example.invalid',
        device_id: 'audit-device', role: 'security_auditor',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
        allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/admin/audit/export') {
      expect(request.headers().accept).toBe('text/csv')
      exportQueries.push(new URLSearchParams(url.search))
      if (exportQueries.length === 1) {
        await firstExportGate
        return fulfill({
          error: { code: 'service_unavailable', message: 'sensitive export backend detail' },
        }, 503)
      }
      return route.fulfill({
        status: 200,
        contentType: 'text/csv',
        headers: {
          'Cache-Control': 'no-store',
          'Content-Disposition': 'attachment; filename="audit-redacted.csv"',
        },
        body: 'created_at,actor_id,action,result,policy_version\n2026-08-20T00:00:00Z,actor-1,upload.reconcile,success,policy-v7\n',
      })
    }
    if (path === '/api/v1/admin/audit') {
      listQueries.push(new URLSearchParams(url.search))
      return fulfill([{
        id: 'audit-1', tenant_id: 'tenant-1', actor_id: 'actor-1',
        user_id: 'subject-1', device_id: 'device-1', event_type: 'upload_review',
        action: 'upload.reconcile', result: 'success', entity_type: 'upload_job',
        entity_id: 'upload-1', trace_id: auditTrace, ip_address: '192.0.2.10',
        user_agent: 'SecureBrowser/1.0', policy_version: 'policy-v7',
        details: { raw_secret: 'must-never-render' }, created_at: '2026-08-20T00:00:00Z',
      }])
    }
    if (path === '/api/v1/admin/uploads') {
      return fulfill([{
        id: 'upload-1', task_id: 'task-1', business_name: 'Audited Store',
        status: 'unknown', policy_version: 'policy-v7',
        created_at: '2026-08-20T00:00:00Z',
      }, {
        id: 'upload-queued', task_id: 'task-queued', business_name: 'Queued Store',
        status: 'queued', policy_version: 'policy-v7',
        created_at: '2026-08-20T00:01:00Z',
      }, {
        id: 'upload-running', task_id: 'task-running', business_name: 'Running Store',
        status: 'running', policy_version: 'policy-v7',
        created_at: '2026-08-20T00:02:00Z',
      }])
    }
    const reconcileMatch = path.match(/^\/api\/v1\/upload-jobs\/([^/]+)\/reconcile$/)
    if (reconcileMatch && request.method() === 'POST') {
      reconcileRequests.push({
        jobId: reconcileMatch[1],
        body: request.postDataJSON() as Record<string, unknown>,
      })
      return fulfill({
        id: reconcileMatch[1], task_id: 'task-1', business_name: 'Audited Store',
        status: 'succeeded', policy_version: 'policy-v7',
        created_at: '2026-08-20T00:00:00Z',
      })
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('auditor@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('audit-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  for (const forbiddenView of ['任务中心', '卡池管理', '邮箱池管理', '用户与权限', '策略配置']) {
    await expect(page.getByText(forbiddenView, { exact: true })).toHaveCount(0)
  }
  await page.getByText('Sub2 上传', { exact: true }).click()
  const unknownRow = page.getByRole('row').filter({ hasText: 'Audited Store' })
  const queuedRow = page.getByRole('row').filter({ hasText: 'Queued Store' })
  const runningRow = page.getByRole('row').filter({ hasText: 'Running Store' })
  const auditorReconcile = unknownRow.getByRole('button', {
    name: '复核上传 Audited Store（upload-1，任务 task-1，状态 unknown）', exact: true,
  })
  await expect(auditorReconcile).toHaveCount(1)
  await expect(unknownRow.getByRole('button', { name: /请求取消上传/ })).toHaveCount(0)
  await expect(queuedRow.getByText('只读核对', { exact: true })).toBeVisible()
  await expect(runningRow.getByText('只读核对', { exact: true })).toBeVisible()
  await expect(queuedRow.getByRole('button')).toHaveCount(0)
  await expect(runningRow.getByRole('button')).toHaveCount(0)
  await expect(page.getByRole('button', { name: /请求取消上传/ })).toHaveCount(0)

  await auditorReconcile.click()
  const reconcileDialog = page.getByRole('dialog', { name: '确认上传 Audited Store 的 unknown 终态' })
  await expect(reconcileDialog.getByText('upload-1', { exact: true })).toBeVisible()
  await reconcileDialog.getByLabel('复核结果').click()
  await page.getByText('成功', { exact: true }).last().click()
  await reconcileDialog.getByLabel('外部编号').fill('auditor-confirmed-1')
  await reconcileDialog.getByRole('button', { name: /确认写入复核终态/ }).click()
  await expect.poll(() => reconcileRequests).toEqual([{
    jobId: 'upload-1',
    body: { status: 'succeeded', external_ref: 'auditor-confirmed-1' },
  }])
  await expect(reconcileDialog).toBeHidden()
  await page.getByText('审计中心', { exact: true }).click()

  await expect(page.getByText('upload.reconcile')).toBeVisible()
  await expect(page.getByText('policy-v7')).toBeVisible()
  await expect(page.locator('body')).not.toContainText('must-never-render')

  await page.getByLabel('操作者').fill('actor-1')
  await page.getByLabel('关联用户').fill('subject-1')
  await page.getByLabel('对象类型').fill('upload_job')
  await page.getByLabel('对象 ID').fill('upload-1')
  await page.getByLabel('事件类型').fill('upload_review')
  await page.getByLabel('动作').fill('upload.reconcile')
  await page.getByLabel('结果').fill('success')
  await page.getByLabel('追踪号').fill(auditTrace)
  await page.getByLabel('开始时间').fill('2026-08-19T08:00')
  await page.getByLabel('结束时间').fill('2026-08-20T08:00')
  await page.getByRole('button', { name: /检\s*索/ }).click()

  await expect.poll(() => listQueries.some((query) => query.get('actor_id') === 'actor-1')).toBe(true)
  const appliedQuery = [...listQueries].reverse().find((query) => query.get('actor_id') === 'actor-1')!
  expect(Object.fromEntries(appliedQuery)).toMatchObject({
    actor_id: 'actor-1',
    user_id: 'subject-1',
    entity_type: 'upload_job',
    entity_id: 'upload-1',
    event_type: 'upload_review',
    action: 'upload.reconcile',
    result: 'success',
    trace_id: auditTrace,
    created_from: '2026-08-19T08:00',
    created_to: '2026-08-20T08:00',
    limit: '200',
  })

  const exportButton = page.getByRole('button', { name: /导出脱敏 CSV/ })
  await exportButton.evaluate((button) => {
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
  })
  try {
    await expect.poll(() => exportQueries.length).toBe(1)
    await expect(exportButton).toBeDisabled()
    await expect(exportButton).toHaveClass(/ant-btn-loading/)
    await expect(page.getByLabel('追踪号')).toBeDisabled()
    await expect(page.getByRole('button', { name: /检\s*索/ })).toBeDisabled()
    await expect(page.getByRole('button', { name: /清\s*空/ })).toBeDisabled()
  } finally {
    releaseFirstExport()
  }
  await expect(page.getByText('本次下载未开始，浏览器不会保留不完整报表')).toBeVisible()
  await expect(page.getByText('sensitive export backend detail')).toHaveCount(0)
  await expect(exportButton).toBeEnabled()
  expect(await page.evaluate(() => {
    const trackedWindow = window as typeof window & {
      __auditCreateCount?: number
      __auditRevokeCount?: number
    }
    return [trackedWindow.__auditCreateCount ?? 0, trackedWindow.__auditRevokeCount ?? 0]
  })).toEqual([0, 0])

  const downloadPromise = page.waitForEvent('download')
  await exportButton.click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toMatch(/^audit-redacted-.*\.csv$/)
  await expect.poll(() => exportQueries.length).toBe(2)
  expect(Object.fromEntries(exportQueries[1])).toMatchObject({
    actor_id: 'actor-1', action: 'upload.reconcile', result: 'success',
    entity_type: 'upload_job', limit: '5000',
  })
  await expect.poll(() => page.evaluate(() => (
    window as typeof window & { __auditCreateCount?: number }
  ).__auditCreateCount ?? 0)).toBe(1)
  await expect.poll(() => page.evaluate(() => (
    window as typeof window & { __auditRevokeCount?: number }
  ).__auditRevokeCount ?? 0)).toBe(1)

  const listCountBeforeClear = listQueries.length
  await page.getByRole('button', { name: /清\s*空/ }).click()
  await expect(page.getByLabel('动作')).toHaveValue('')
  await expect.poll(() => listQueries.length).toBeGreaterThan(listCountBeforeClear)
  expect(listQueries.at(-1)?.has('action')).toBe(false)

  const browserStorage = await page.evaluate(() => ({
    local: Object.values(localStorage),
    session: Object.values(sessionStorage),
  }))
  expect(JSON.stringify(browserStorage)).not.toContain(accessValue)
})

test('ops admin safely reconciles unknown uploads with true-state recovery', async ({ page }) => {
  const accessValue = 'upload-reconcile-access'
  let uploads = [{
    id: 'upload-committed', task_id: 'task-committed', business_name: 'Committed Result',
    status: 'unknown', policy_version: 'policy-v7', created_at: '2026-08-20T00:00:00Z',
    secret_ref: 'sub2-secret-token', credential: 'subscriber-credential',
    proxy: 'proxy-internal-7', group: 'group-internal-9', concurrency: 99,
    raw_error: 'raw upstream stack trace',
  }, {
    id: 'upload-retry', task_id: 'task-retry', business_name: 'Retry Result',
    status: 'unknown', policy_version: 'policy-v7', created_at: '2026-08-20T00:01:00Z',
  }, {
    id: 'upload-running', task_id: 'task-running', business_name: 'Running Result',
    status: 'running', policy_version: 'policy-v7', created_at: '2026-08-20T00:02:00Z',
    secret_ref: 'sub2-secret-token', credential: 'subscriber-credential',
    proxy: 'proxy-internal-7', group: 'group-internal-9', concurrency: 99,
    raw_error: 'raw upstream stack trace',
  }, {
    id: 'upload-late', task_id: 'task-late', business_name: 'Late Result',
    status: 'unknown', policy_version: 'policy-v7', created_at: '2026-08-20T00:03:00Z',
  }]
  const reconcileRequests: Array<{ jobId: string; body: Record<string, unknown> }> = []
  const cancelRequests: string[] = []
  let uploadListRequests = 0
  let retryFailures = 1
  let failNextUploadList = false
  let waitForRecoveryList = false
  let releaseRecoveryList = () => undefined
  const recoveryListGate = new Promise<void>((resolve) => {
    releaseRecoveryList = resolve
  })
  let releaseCommittedReconcile = () => undefined
  const committedReconcileGate = new Promise<void>((resolve) => {
    releaseCommittedReconcile = resolve
  })
  let releaseLateReconcile = () => undefined
  const lateReconcileGate = new Promise<void>((resolve) => {
    releaseLateReconcile = resolve
  })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'ops-user', tenant_id: 'tenant-1', email: 'ops@example.invalid',
        device_id: 'ops-device', role: 'ops_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 3,
        allocated_cards: 2, waiting_mail_sessions: 1, queued_uploads: 0,
        unknown_uploads: 2, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/admin/uploads' && request.method() === 'GET') {
      uploadListRequests += 1
      if (failNextUploadList) {
        failNextUploadList = false
        waitForRecoveryList = true
        return fulfill({
          error: { code: 'service_unavailable', message: 'upload refresh unavailable' },
        }, 503)
      }
      if (waitForRecoveryList) {
        waitForRecoveryList = false
        await recoveryListGate
      }
      return fulfill(uploads)
    }
    const reconcileMatch = path.match(/^\/api\/v1\/upload-jobs\/([^/]+)\/reconcile$/)
    if (reconcileMatch && request.method() === 'POST') {
      const jobId = reconcileMatch[1]
      const body = request.postDataJSON() as Record<string, unknown>
      reconcileRequests.push({ jobId, body })
      if (jobId === 'upload-committed') {
        expect(body).toMatchObject({ status: 'succeeded', external_ref: 'sub2-confirmed-1' })
        uploads = uploads.map((upload) => upload.id === jobId ? { ...upload, status: 'succeeded' } : upload)
        await committedReconcileGate
        failNextUploadList = true
        return fulfill({ error: { code: 'service_unavailable', message: 'reconcile response lost' } }, 503)
      }
      if (jobId === 'upload-late') {
        expect(body).toMatchObject({ status: 'failed', error_code: 'late_navigation' })
        await lateReconcileGate
        uploads = uploads.map((upload) => upload.id === jobId ? { ...upload, status: 'failed' } : upload)
        return fulfill(uploads.find((upload) => upload.id === jobId))
      }
      expect(body).toMatchObject({ status: 'failed', error_code: 'manual_not_found' })
      if (jobId === 'upload-retry' && retryFailures > 0) {
        retryFailures -= 1
        return fulfill({ error: { code: 'service_unavailable', message: 'reconcile unavailable' } }, 503)
      }
      uploads = uploads.map((upload) => upload.id === jobId ? { ...upload, status: 'failed' } : upload)
      return fulfill(uploads.find((upload) => upload.id === jobId))
    }
    const cancelMatch = path.match(/^\/api\/v1\/upload-jobs\/([^/]+)\/cancel$/)
    if (cancelMatch && request.method() === 'POST') {
      cancelRequests.push(cancelMatch[1])
      return fulfill({ ...uploads[2], status: 'cancel_pending' })
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('ops@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('ops-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('Sub2 上传', { exact: true }).click()

  const committedRow = page.getByRole('row').filter({ hasText: 'Committed Result' })
  const retryRow = page.getByRole('row').filter({ hasText: 'Retry Result' })
  const runningRow = page.getByRole('row').filter({ hasText: 'Running Result' })
  const committedReconcile = committedRow.getByRole('button', {
    name: '复核上传 Committed Result（upload-committed，任务 task-committed，状态 unknown）', exact: true,
  })
  const retryReconcile = retryRow.getByRole('button', {
    name: '复核上传 Retry Result（upload-retry，任务 task-retry，状态 unknown）', exact: true,
  })
  const runningCancel = runningRow.getByRole('button', {
    name: '请求取消上传 Running Result（upload-running，任务 task-running，状态 running）', exact: true,
  })
  await expect(committedReconcile).toHaveCount(1)
  await expect(retryReconcile).toHaveCount(1)
  await expect(runningCancel).toHaveCount(1)
  await expect(page.locator('.content .ant-btn-primary:visible')).toHaveCount(0)

  await committedReconcile.click()
  let reconcileDialog = page.getByRole('dialog', { name: '确认上传 Committed Result 的 unknown 终态' })
  await expect(reconcileDialog).toContainText('不可逆的人工终态')
  await expect(reconcileDialog).toContainText('释放卡租约和邮箱会话')
  await expect(reconcileDialog.getByText('Committed Result', { exact: true })).toBeVisible()
  const committedVisibleId = await reconcileDialog.getByText('upload-committed', { exact: true }).textContent()
  await expect(reconcileDialog.getByText('task-committed', { exact: true })).toBeVisible()
  await expect(reconcileDialog.getByText('unknown', { exact: true })).toBeVisible()
  for (const sensitive of [
    'sub2-secret-token', 'subscriber-credential', 'proxy-internal-7',
    'group-internal-9', '99', 'raw upstream stack trace',
  ]) {
    await expect(reconcileDialog).not.toContainText(sensitive)
  }
  await reconcileDialog.getByRole('button', { name: /取\s*消/ }).click()
  await expect(reconcileDialog).toBeHidden()
  expect(reconcileRequests).toEqual([])
  await expect(committedReconcile).toBeEnabled()
  await expect(runningCancel).toBeEnabled()

  await committedReconcile.click()
  reconcileDialog = page.getByRole('dialog', { name: '确认上传 Committed Result 的 unknown 终态' })
  await reconcileDialog.getByLabel('复核结果').click()
  await page.getByText('成功', { exact: true }).last().click()
  await reconcileDialog.getByLabel('外部编号').fill('sub2-confirmed-1')
  const confirmCommitted = reconcileDialog.getByRole('button', { name: /确认写入复核终态/ })
  await confirmCommitted.click()
  try {
    await expect.poll(() => reconcileRequests).toHaveLength(1)
    expect(reconcileRequests[0].jobId).toBe(committedVisibleId)
    const pendingReconcile = committedReconcile
    await expect(pendingReconcile).toBeDisabled()
    await expect(pendingReconcile).toHaveClass(/ant-btn-loading/)
    await expect(retryReconcile).toBeDisabled()
    await expect(runningCancel).toBeDisabled()
    await confirmCommitted.dispatchEvent('click')
    await retryReconcile.dispatchEvent('click')
    await runningCancel.dispatchEvent('click')
    expect(reconcileRequests).toHaveLength(1)
    expect(cancelRequests).toEqual([])
  } finally {
    releaseCommittedReconcile()
  }
  await expect(page.getByText(/原因：平台未能确认 unknown 上传复核结果。影响：.*下一步：/).last()).toBeVisible()
  await expect(page.getByText('reconcile response lost')).toHaveCount(0)
  const listError = page.getByRole('alert').filter({ hasText: '上传列表暂不可用' })
  for (const marker of ['原因：', '影响：', '下一步：']) {
    await expect(listError).toContainText(marker)
  }
  await expect(reconcileDialog).toBeHidden()
  await expect.poll(() => uploadListRequests).toBeGreaterThanOrEqual(2)
  await expect(committedRow).toHaveCount(0)
  await expect(retryRow).toHaveCount(0)
  expect(reconcileRequests).toHaveLength(1)

  const retryUploadList = listError.getByRole('button', { name: '重新获取上传真实状态' })
  await retryUploadList.click()
  try {
    await expect.poll(() => uploadListRequests).toBeGreaterThanOrEqual(3)
    await expect(page.locator('.ant-spin')).toBeVisible()
    await expect(page.getByRole('alert').filter({ hasText: '上传列表暂不可用' })).toHaveCount(0)
  } finally {
    releaseRecoveryList()
  }
  await expect(committedRow.getByText('succeeded')).toBeVisible()
  await expect(committedRow.getByRole('button', { name: /复核上传 Committed Result/ })).toHaveCount(0)
  expect(reconcileRequests).toHaveLength(1)

  const listsBeforeRetryFailure = uploadListRequests
  await retryReconcile.click()
  reconcileDialog = page.getByRole('dialog', { name: '确认上传 Retry Result 的 unknown 终态' })
  await expect(reconcileDialog.getByText('Retry Result', { exact: true })).toBeVisible()
  const retryVisibleId = await reconcileDialog.getByText('upload-retry', { exact: true }).textContent()
  await expect(reconcileDialog.getByText('task-retry', { exact: true })).toBeVisible()
  await expect(reconcileDialog.getByText('unknown', { exact: true })).toBeVisible()
  await reconcileDialog.getByLabel('错误码').fill('manual_not_found')
  await reconcileDialog.getByRole('button', { name: /确认写入复核终态/ }).click()
  await expect(page.getByText(/原因：平台未能确认 unknown 上传复核结果。影响：.*下一步：/).last()).toBeVisible()
  await expect(page.getByText('reconcile unavailable')).toHaveCount(0)
  await expect(retryRow.getByText('unknown')).toBeVisible()
  await expect.poll(() => uploadListRequests).toBeGreaterThan(listsBeforeRetryFailure)
  await expect(reconcileDialog.getByRole('button', { name: /确认写入复核终态/ })).toBeEnabled()
  expect(reconcileRequests.filter((item) => item.jobId === 'upload-retry')).toHaveLength(1)
  expect(reconcileRequests.at(-1)?.jobId).toBe(retryVisibleId)

  await reconcileDialog.getByRole('button', { name: /确认写入复核终态/ }).click()
  await expect(reconcileDialog).toBeHidden()
  await expect(retryRow.getByText('failed')).toBeVisible()
  expect(reconcileRequests.filter((item) => item.jobId === 'upload-retry')).toHaveLength(2)

  await runningCancel.click()
  let cancelDialog = page.getByRole('dialog', { name: '确认取消上传 Running Result？' })
  await expect(cancelDialog.getByText('Running Result', { exact: true })).toBeVisible()
  const runningVisibleId = await cancelDialog.getByText('upload-running', { exact: true }).textContent()
  await expect(cancelDialog.getByText('task-running', { exact: true })).toBeVisible()
  await expect(cancelDialog.getByText('running', { exact: true })).toBeVisible()
  for (const sensitive of [
    'sub2-secret-token', 'subscriber-credential', 'proxy-internal-7',
    'group-internal-9', '99', 'raw upstream stack trace',
  ]) {
    await expect(cancelDialog).not.toContainText(sensitive)
  }
  await cancelDialog.getByRole('button', { name: '保留任务' }).click()
  await expect(cancelDialog).toBeHidden()
  expect(cancelRequests).toEqual([])

  await runningCancel.click()
  cancelDialog = page.getByRole('dialog', { name: '确认取消上传 Running Result？' })
  await cancelDialog.getByRole('button', { name: '确认请求取消' }).click()
  await expect.poll(() => cancelRequests).toEqual([runningVisibleId ?? ''])

  const lateRow = page.getByRole('row').filter({ hasText: 'Late Result' })
  const lateReconcile = lateRow.getByRole('button', {
    name: '复核上传 Late Result（upload-late，任务 task-late，状态 unknown）', exact: true,
  })
  await lateReconcile.click()
  reconcileDialog = page.getByRole('dialog', { name: '确认上传 Late Result 的 unknown 终态' })
  await reconcileDialog.getByLabel('错误码').fill('late_navigation')
  const lateResponse = page.waitForResponse((response) => (
    new URL(response.url()).pathname === '/api/v1/upload-jobs/upload-late/reconcile'
  ))
  await reconcileDialog.getByRole('button', { name: /确认写入复核终态/ }).click()
  let listsBeforeLateOutcome = 0
  try {
    await expect.poll(() => reconcileRequests.filter((item) => item.jobId === 'upload-late')).toHaveLength(1)
    await page.getByText('工作台', { exact: true }).dispatchEvent('click')
    await expect(page.getByRole('heading', { name: '工作台', exact: true })).toBeVisible()
    const lockButton = page.getByRole('button', { name: '锁定' })
    await lockButton.focus()
    await expect(lockButton).toBeFocused()
    listsBeforeLateOutcome = uploadListRequests
  } finally {
    releaseLateReconcile()
  }
  await lateResponse
  await page.evaluate(() => new Promise<void>((resolve) => {
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => resolve()))
  }))
  await page.waitForTimeout(300)
  expect(uploadListRequests).toBe(listsBeforeLateOutcome)
  await expect(page.getByText('复核终态已提交，正在刷新上传与任务资源状态。')).toHaveCount(0)
  await expect(page.getByRole('button', { name: '锁定' })).toBeFocused()
  await page.getByText('Sub2 上传', { exact: true }).click()
  await expect(lateRow.getByText('failed')).toBeVisible()
  await expect(lateRow.getByRole('button', { name: /复核上传 Late Result/ })).toHaveCount(0)
  await expect(runningCancel).toBeEnabled()
})

test('platform admin governs upload policies without browser execution details', async ({ page }) => {
  const accessValue = ['admin', 'access', 'value'].join('-')
  const traceId = '00000000-0000-0000-0000-000000000099'
  let versions = [{
    id: 'policy-draft-1', version: 'sub2-2026.08.1', status: 'draft',
    change_note: '待独立审批', created_by: 'user-2', approved_by: null,
    approved_at: null, created_at: '2026-08-20T00:00:00Z',
    secret_ref: 'vault://policy-secret', sub2_token: 'raw-sub2-token',
    proxy: 'proxy-internal-21', group: 'group-internal-22', concurrency: 77,
    raw_error: 'raw policy upstream error',
  }, {
    id: 'policy-draft-other', version: 'sub2-2026.08.2', status: 'draft',
    change_note: '另一待审批版本', created_by: 'user-2', approved_by: null,
    approved_at: null, created_at: '2026-08-20T00:00:10Z',
  }, {
    id: 'policy-approved-1', version: 'sub2-2026.08.0', status: 'approved',
    change_note: '待发布', created_by: 'user-2', approved_by: 'user-3',
    approved_at: '2026-08-20T00:00:30Z', created_at: '2026-08-20T00:00:00Z',
    secret_ref: 'vault://policy-secret', sub2_token: 'raw-sub2-token',
    proxy: 'proxy-internal-21', group: 'group-internal-22', concurrency: 77,
    raw_error: 'raw policy upstream error',
  }, {
    id: 'policy-approved-other', version: 'sub2-2026.07.9', status: 'approved',
    change_note: '另一待发布版本', created_by: 'user-2', approved_by: 'user-3',
    approved_at: '2026-08-20T00:00:20Z', created_at: '2026-08-19T23:59:00Z',
  }]
  let policyListRequests = 0
  const approveRequests: string[] = []
  const deployRequests: Array<{ policyId: string; rollout: number }> = []
  let rollbackRequests = 0
  let rollbackFailures = 1
  let releaseDeploy = () => undefined
  const deployGate = new Promise<void>((resolve) => { releaseDeploy = resolve })
  let policyStatus = {
    policy_version: 'sub2-2026.07.1', status: 'ready', server_managed: true,
    upload_endpoint_configured: true, upload_secret_configured: true,
    network_route_configured: true, governance_configured: true,
    active_version: 'sub2-2026.07.1' as string | null, previous_version: null as string | null, rollout_percent: 100 as number | null,
  }
  const policySummary = page.locator('.ant-card').filter({
    has: page.getByText('Sub2 上传策略', { exact: true }),
  })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      headers: { 'X-Trace-Id': traceId },
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'user-admin', tenant_id: 'tenant-1', email: 'admin@example.invalid',
        device_id: 'device-admin', role: 'platform_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
        allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/admin/policies/upload' && request.method() === 'GET') {
      policyListRequests += 1
      return fulfill(policyStatus)
    }
    if ((path === '/api/v1/admin/policies/mail' || path === '/api/v1/admin/policies/card') && request.method() === 'GET') {
      return fulfill({
        domain: path.endsWith('/mail') ? 'mail' : 'card',
        governance_configured: false,
        active_version: null,
        previous_version: null,
        rollout_percent: null,
      })
    }
    if ((path === '/api/v1/admin/policies/mail/versions' || path === '/api/v1/admin/policies/card/versions') && request.method() === 'GET') {
      return fulfill([])
    }
    if (path === '/api/v1/admin/policies/upload/versions' && request.method() === 'GET') {
      return fulfill(versions)
    }
    if (path === '/api/v1/admin/policies/upload/versions' && request.method() === 'POST') {
      expect(Object.keys(request.postDataJSON()).sort()).toEqual(['change_note', 'version'])
      expect(JSON.stringify(request.postDataJSON())).not.toContain('vault://')
      const body = request.postDataJSON() as { version: string; change_note: string }
      const created = {
        id: 'policy-draft-2', version: body.version, status: 'draft',
        change_note: body.change_note, created_by: 'user-admin', approved_by: null,
        approved_at: null, created_at: '2026-08-20T00:01:00Z',
      }
      versions = [created, ...versions]
      return fulfill(created, 201)
    }
    const approveMatch = path.match(/^\/api\/v1\/admin\/policies\/upload\/versions\/([^/]+)\/approve$/)
    if (approveMatch && request.method() === 'POST') {
      approveRequests.push(approveMatch[1])
      versions = versions.map((item) => item.id === approveMatch[1]
        ? { ...item, status: 'approved', approved_by: 'user-admin', approved_at: '2026-08-20T00:02:00Z' }
        : item)
      return fulfill(versions.find((item) => item.id === approveMatch[1]))
    }
    const deployMatch = path.match(/^\/api\/v1\/admin\/policies\/upload\/versions\/([^/]+)\/deploy$/)
    if (deployMatch && request.method() === 'POST') {
      const body = request.postDataJSON() as { rollout_percent: number }
      deployRequests.push({ policyId: deployMatch[1], rollout: body.rollout_percent })
      expect(deployMatch[1]).toBe('policy-approved-1')
      expect(body).toEqual({ rollout_percent: 100 })
      await deployGate
      policyStatus = {
        ...policyStatus,
        active_version: 'sub2-2026.08.0',
        previous_version: 'sub2-2026.07.1',
        rollout_percent: 100,
      }
      versions = versions.map((item) => item.id === 'policy-approved-1' ? { ...item, status: 'active' } : item)
      return fulfill({ policy_version: 'sub2-2026.08.0', rollout_percent: 100 })
    }
    if (path === '/api/v1/admin/policies/upload/rollback') {
      rollbackRequests += 1
      if (rollbackFailures > 0) {
        rollbackFailures -= 1
        return fulfill({ error: { code: 'temporarily_unavailable', message: 'retry later' } }, 503)
      }
      policyStatus = {
        ...policyStatus,
        active_version: 'sub2-2026.07.1',
        previous_version: 'sub2-2026.08.0',
      }
      return fulfill({ policy_version: 'sub2-2026.07.1', rollout_percent: 100 })
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('admin@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('device-admin')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByRole('menuitem', { name: /策略配置/ }).click()

  await expect(page.getByText(/独立审批/).first()).toBeVisible()
  await expect(page.getByText('邮箱策略', { exact: true })).toBeVisible()
  await expect(page.getByText('卡分配策略', { exact: true })).toBeVisible()
  await expect(page.getByText('sub2-2026.08.1')).toBeVisible()
  await expect(page.locator('.content .ant-btn-primary:visible')).toHaveCount(3)
  await expect(policySummary.locator('.ant-descriptions-item-content .ant-tag .anticon')).toHaveCount(6)
  const approveDraft = page.getByRole('button', {
    name: '审批策略 sub2-2026.08.1（policy-draft-1，状态 draft，目标比例不变）', exact: true,
  })
  const approveOtherDraft = page.getByRole('button', {
    name: '审批策略 sub2-2026.08.2（policy-draft-other，状态 draft，目标比例不变）', exact: true,
  })
  const fullDeploy = page.getByRole('button', {
    name: '全量启用策略 sub2-2026.08.0（policy-approved-1，状态 approved，目标比例 100%）', exact: true,
  })
  const otherFullDeploy = page.getByRole('button', {
    name: '全量启用策略 sub2-2026.07.9（policy-approved-other，状态 approved，目标比例 100%）', exact: true,
  })
  const tenPercentDeploy = page.getByRole('button', {
    name: '开始策略 sub2-2026.08.0 10% 灰度（policy-approved-1，状态 approved，目标比例 10%）', exact: true,
  })
  await expect(approveDraft).toHaveCount(1)
  await expect(approveOtherDraft).toHaveCount(1)
  await expect(fullDeploy).toHaveCount(1)
  await expect(otherFullDeploy).toHaveCount(1)
  await expect(tenPercentDeploy).toHaveCount(1)

  await approveDraft.click()
  let approveDialog = page.getByRole('dialog', { name: '确认审批策略 sub2-2026.08.1？' })
  await expect(approveDialog.getByText('sub2-2026.08.1', { exact: true })).toBeVisible()
  const visibleApproveId = await approveDialog.getByText('policy-draft-1', { exact: true }).textContent()
  await expect(approveDialog.getByText('draft', { exact: true })).toBeVisible()
  await expect(approveDialog.getByText('不变更（审批阶段）', { exact: true })).toBeVisible()
  for (const sensitive of [
    'vault://policy-secret', 'raw-sub2-token', 'proxy-internal-21',
    'group-internal-22', '77', 'raw policy upstream error',
  ]) {
    await expect(approveDialog).not.toContainText(sensitive)
  }
  await approveDialog.getByRole('button', { name: /取\s*消/ }).click()
  await expect(approveDialog).toBeHidden()
  expect(approveRequests).toEqual([])

  await approveDraft.click()
  approveDialog = page.getByRole('dialog', { name: '确认审批策略 sub2-2026.08.1？' })
  await approveDialog.getByRole('button', { name: '确认审批' }).click()
  await expect.poll(() => approveRequests).toEqual([visibleApproveId ?? ''])

  await page.getByPlaceholder('例如 sub2-2026.08.1').fill('sub2-2026.09.1')
  const uploadPolicyForm = page.getByRole('button', { name: '登记快照' }).locator('xpath=ancestor::form')
  await uploadPolicyForm.getByPlaceholder('变更说明').fill('九月灰度版本')
  await uploadPolicyForm.getByRole('button', { name: '登记快照' }).click()
  await expect(page.getByText('sub2-2026.09.1')).toBeVisible()
  await expect(page.locator('body')).not.toContainText('vault://')

  await fullDeploy.click()
  let deployDialog = page.getByRole('dialog', { name: '确认全量启用该策略？' })
  await expect(deployDialog).toContainText('所有新任务')
  await expect(deployDialog.getByText('sub2-2026.08.0', { exact: true })).toBeVisible()
  const visibleDeployId = await deployDialog.getByText('policy-approved-1', { exact: true }).textContent()
  await expect(deployDialog.getByText('approved', { exact: true })).toBeVisible()
  await expect(deployDialog.getByText('100%', { exact: true })).toBeVisible()
  for (const sensitive of [
    'vault://policy-secret', 'raw-sub2-token', 'proxy-internal-21',
    'group-internal-22', '77', 'raw policy upstream error',
  ]) {
    await expect(deployDialog).not.toContainText(sensitive)
  }
  await deployDialog.getByRole('button', { name: /取\s*消/ }).click()
  expect(deployRequests).toEqual([])

  await fullDeploy.click()
  deployDialog = page.getByRole('dialog', { name: '确认全量启用该策略？' })
  const confirmDeploy = deployDialog.getByRole('button', { name: '全量启用策略' })
  const deployResponse = page.waitForResponse((response) => (
    new URL(response.url()).pathname === '/api/v1/admin/policies/upload/versions/policy-approved-1/deploy'
  ))
  let policyListsBeforeLateDeploy = 0
  await confirmDeploy.click()
  await confirmDeploy.dispatchEvent('click')
  await expect.poll(() => deployRequests).toHaveLength(1)
  expect(deployRequests[0]).toEqual({ policyId: visibleDeployId, rollout: 100 })
  await expect(fullDeploy).toBeDisabled()
  await expect(tenPercentDeploy).toBeDisabled()
  await expect(approveOtherDraft).toBeDisabled()
  await expect(page.getByRole('button', { name: '登记快照' })).toBeDisabled()
  await page.getByText('工作台', { exact: true }).dispatchEvent('click')
  await expect(page.getByRole('heading', { name: '工作台', exact: true })).toBeVisible()
  const lockButton = page.getByRole('button', { name: '锁定' })
  await lockButton.focus()
  await expect(lockButton).toBeFocused()
  policyListsBeforeLateDeploy = policyListRequests
  releaseDeploy()
  await deployResponse
  await page.evaluate(() => new Promise<void>((resolve) => {
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => resolve()))
  }))
  await page.waitForTimeout(300)
  expect(policyListRequests).toBe(policyListsBeforeLateDeploy)
  await expect(page.getByText('策略已全量启用。')).toHaveCount(0)
  await expect(page.getByRole('button', { name: '锁定' })).toBeFocused()
  await page.getByRole('menuitem', { name: /策略配置/ }).click()
  await expect(policySummary.getByText('当前生效', { exact: true }).locator('..')).toContainText('sub2-2026.08.0')
  await expect.poll(() => policyListRequests).toBeGreaterThanOrEqual(3)

  const adjustFifty = page.getByRole('button', {
    name: '调整策略 sub2-2026.08.0 至 50%（policy-approved-1，状态 active，目标比例 50%）', exact: true,
  })
  const extendHundred = page.getByRole('button', {
    name: '扩展策略 sub2-2026.08.0 至 100%（policy-approved-1，状态 active，目标比例 100%）', exact: true,
  })
  await expect(adjustFifty).toHaveCount(1)
  await expect(extendHundred).toHaveCount(1)

  const rollback = page.getByRole('button', {
    name: '回滚上传策略（当前 sub2-2026.08.0，目标 sub2-2026.07.1，当前比例 100%）', exact: true,
  })
  await rollback.click()
  let rollbackDialog = page.getByRole('dialog', { name: '确认回滚上传策略？' })
  await expect(rollbackDialog.getByText('sub2-2026.08.0', { exact: true })).toBeVisible()
  await expect(rollbackDialog.getByText('sub2-2026.07.1', { exact: true })).toBeVisible()
  await expect(rollbackDialog.getByText('100%', { exact: true })).toBeVisible()
  await rollbackDialog.getByRole('button', { name: /取\s*消/ }).click()
  await expect(rollbackDialog).toBeHidden()
  expect(rollbackRequests).toBe(0)

  await rollback.click()
  rollbackDialog = page.getByRole('dialog', { name: '确认回滚上传策略？' })
  await rollbackDialog.getByRole('button', { name: '确认回滚' }).click()
  await expect(page.getByText('操作未完成，当前生效策略未确认变更；正在刷新真实状态，刷新后可重试。')).toBeVisible()
  await expect(page.getByText('retry later')).toHaveCount(0)
  await expect(rollback).toBeEnabled()
  expect(rollbackRequests).toBe(1)
  await rollback.click()
  rollbackDialog = page.getByRole('dialog', { name: '确认回滚上传策略？' })
  await rollbackDialog.getByRole('button', { name: '确认回滚' }).click()
  await expect(policySummary.getByText('当前生效', { exact: true }).locator('..')).toContainText('sub2-2026.07.1')
  expect(rollbackRequests).toBe(2)

  const browserStorage = await page.evaluate(() => ({
    local: Object.values(localStorage),
    session: Object.values(sessionStorage),
  }))
  expect(JSON.stringify(browserStorage)).not.toContain(accessValue)
})

test('platform admin confirms user changes and safely revokes devices', async ({ page }) => {
  test.setTimeout(45_000)
  const accessValue = 'user-admin-memory-access'
  let users = [
    { id: 'admin-1', tenant_id: 'tenant-1', email: 'admin@example.invalid', role: 'platform_admin', is_active: true, created_at: '2026-08-20T00:00:00Z' },
    { id: 'operator-1', tenant_id: 'tenant-1', email: 'operator-one@example.invalid', role: 'operator', is_active: true, created_at: '2026-08-20T00:01:00Z' },
    { id: 'operator-2', tenant_id: 'tenant-1', email: 'operator-two@example.invalid', role: 'operator', is_active: true, created_at: '2026-08-20T00:02:00Z' },
    { id: 'operator-3', tenant_id: 'tenant-1', email: 'operator-three@example.invalid', role: 'operator', is_active: true, created_at: '2026-08-20T00:03:00Z' },
  ]
  let devices = [
    { id: 'device-success', tenant_id: 'tenant-1', user_id: 'operator-1', name: 'trusted-ops-device', revoked_at: null, last_seen_at: '2026-08-20T00:04:30Z', created_at: '2026-08-20T00:03:00Z' },
    { id: 'device-retry', tenant_id: 'tenant-1', user_id: 'operator-2', name: 'retry-ops-device', revoked_at: null, last_seen_at: null, created_at: '2026-08-20T00:04:00Z' },
  ]
  const roleBodies: unknown[] = []
  let pendingRoleRequests: Array<Record<string, unknown>> = []
  const singleDisableIds: string[] = []
  const batchBodies: unknown[] = []
  const revokedDeviceIds: string[] = []
  let userListRequests = 0
  let deviceListRequests = 0
  let roleFailures = 1
  let releaseRoleChange = () => undefined
  const roleChangeGate = new Promise<void>((resolve) => { releaseRoleChange = resolve })
  let releaseSingleDisable = () => undefined
  const singleDisableGate = new Promise<void>((resolve) => { releaseSingleDisable = resolve })
  let retryDeviceFailures = 1
  let releaseDeviceRevoke = () => undefined
  const deviceRevokeGate = new Promise<void>((resolve) => { releaseDeviceRevoke = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({ id: 'admin-1', tenant_id: 'tenant-1', email: 'admin@example.invalid', device_id: 'admin-device', role: 'platform_admin' })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
        allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/admin/users' && request.method() === 'GET') {
      userListRequests += 1
      return fulfill(users)
    }
    if (path === '/api/v1/admin/role-change-requests' && request.method() === 'GET') {
      return fulfill(pendingRoleRequests)
    }
    if (path === '/api/v1/admin/devices' && request.method() === 'GET') {
      deviceListRequests += 1
      return fulfill(devices)
    }
    const deviceRevokeMatch = path.match(/^\/api\/v1\/admin\/devices\/([^/]+)\/revoke$/)
    if (deviceRevokeMatch && request.method() === 'POST') {
      const deviceId = deviceRevokeMatch[1]
      revokedDeviceIds.push(deviceId)
      if (deviceId === 'device-success') await deviceRevokeGate
      if (deviceId === 'device-retry' && retryDeviceFailures > 0) {
        retryDeviceFailures -= 1
        return fulfill({ error: { code: 'temporarily_unavailable', message: '设备服务暂不可用' } }, 503)
      }
      devices = devices.map((device) => device.id === deviceId
        ? { ...device, revoked_at: '2026-08-20T00:05:00Z' }
        : device)
      return fulfill(devices.find((device) => device.id === deviceId))
    }
    if (path === '/api/v1/admin/users/operator-1/role-change-requests' && request.method() === 'POST') {
      const body = request.postDataJSON() as { role: string }
      roleBodies.push(body)
      if (roleBodies.length === 1) await roleChangeGate
      if (roleFailures > 0) {
        roleFailures -= 1
        return fulfill({ error: { code: 'service_unavailable', message: '角色服务暂不可用' } }, 503)
      }
      const roleRequest = {
        id: 'role-request-1', tenant_id: 'tenant-1', target_user_id: 'operator-1',
        expected_old_role: 'operator', new_role: body.role, status: 'pending',
        requested_by: 'admin-1', approved_by: null,
        request_trace_id: 'role-request-trace-1', approval_trace_id: null,
        created_at: '2026-08-20T00:05:00Z', expires_at: '2026-08-20T00:20:00Z',
        applied_at: null,
      }
      pendingRoleRequests = [roleRequest]
      return fulfill(roleRequest)
    }
    if (path === '/api/v1/admin/users/operator-1/disable' && request.method() === 'POST') {
      singleDisableIds.push('operator-1')
      await singleDisableGate
      users = users.map((user) => user.id === 'operator-1' ? { ...user, is_active: false } : user)
      return fulfill(users.find((user) => user.id === 'operator-1'))
    }
    if (path === '/api/v1/admin/users/batch-disable' && request.method() === 'POST') {
      const body = request.postDataJSON() as { user_ids: string[] }
      batchBodies.push(body)
      users = users.map((user) => body.user_ids.includes(user.id) ? { ...user, is_active: false } : user)
      return fulfill(users.filter((user) => body.user_ids.includes(user.id)))
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('admin@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('admin-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByRole('menuitem', { name: /用户与权限/ }).click()

  const userCard = page.locator('.ant-card').filter({
    has: page.getByText('用户', { exact: true }),
  })
  await page.setViewportSize({ width: 768, height: 900 })
  await expect(page.locator('.ant-layout-sider')).toHaveClass(/ant-layout-sider-collapsed/)
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true)
  const userTableViewport = userCard.locator('.ant-table-content')
  await expect.poll(() => userTableViewport.evaluate((element) => element.scrollWidth > element.clientWidth)).toBe(true)
  const accountHeader = userCard.getByRole('columnheader', { name: /账号/ })
  await page.keyboard.press('Tab')
  await accountHeader.focus()
  await expect(accountHeader).toBeFocused()
  await expect.poll(() => accountHeader.evaluate((element) => getComputedStyle(element).outlineColor)).toBe('rgb(23, 107, 135)')
  await accountHeader.press('Enter')
  await expect(accountHeader).toHaveAttribute('aria-sort', 'ascending')
  await accountHeader.press('Enter')
  await expect(accountHeader).toHaveAttribute('aria-sort', 'descending')
  await expect(userCard.locator('tbody tr.ant-table-row').first()).toContainText('operator-two@example.invalid')
  const roleHeader = userCard.getByRole('columnheader', { name: /角色/ })
  await roleHeader.locator('.ant-table-filter-trigger').click()
  let roleFilter = page.locator('.ant-table-filter-dropdown:visible')
  await roleFilter.getByText('操作员', { exact: true }).click()
  await roleFilter.getByRole('button', { name: '确 定' }).click()
  await expect(userCard.getByRole('row').filter({ hasText: 'admin@example.invalid' })).toHaveCount(0)
  await expect(userCard.locator('tbody tr.ant-table-row')).toHaveCount(3)
  await roleHeader.locator('.ant-table-filter-trigger').click()
  roleFilter = page.locator('.ant-table-filter-dropdown:visible')
  await roleFilter.getByText('操作员', { exact: true }).click()
  await roleFilter.getByRole('button', { name: '确 定' }).click()
  await expect(userCard.getByRole('row').filter({ hasText: 'admin@example.invalid' })).toHaveCount(1)
  await expect(page.locator('.content .ant-btn-primary:visible')).toHaveCount(0)
  await page.setViewportSize({ width: 1280, height: 900 })
  const firstRow = userCard.getByRole('row').filter({ hasText: 'operator-one@example.invalid' })
  const secondRow = userCard.getByRole('row').filter({ hasText: 'operator-two@example.invalid' })
  const thirdRow = userCard.getByRole('row').filter({ hasText: 'operator-three@example.invalid' })
  const firstDisableButton = firstRow.getByRole('button', { name: '停用用户 operator-one@example.invalid', exact: true })
  const secondDisableButton = secondRow.getByRole('button', { name: '停用用户 operator-two@example.invalid', exact: true })
  const secondCheckbox = secondRow.getByRole('checkbox', { name: '选择用户 operator-two@example.invalid', exact: true })
  const thirdCheckbox = thirdRow.getByRole('checkbox', { name: '选择用户 operator-three@example.invalid', exact: true })
  await expect(firstDisableButton).toHaveCount(1)
  await expect(secondDisableButton).toHaveCount(1)
  await expect(secondCheckbox).toHaveCount(1)
  await expect(thirdCheckbox).toHaveCount(1)
  await secondCheckbox.check()
  const roleSelect = page.getByLabel('申请调整 operator-one@example.invalid 角色', { exact: true })
  const secondRoleSelect = page.getByLabel('申请调整 operator-two@example.invalid 角色', { exact: true })
  await roleSelect.click()
  await page.getByText('安全审计员', { exact: true }).last().click()
  const roleDialog = page.getByRole('dialog', { name: '确认创建角色变更申请？' })
  await expect(roleDialog).toContainText('操作员 → 安全审计员')
  const confirmRole = roleDialog.getByRole('button', { name: '创建申请' })
  const firstRoleResponse = page.waitForResponse((response) => (
    new URL(response.url()).pathname === '/api/v1/admin/users/operator-1/role-change-requests'
  ))
  let userListsBeforeLateRole = 0
  let deviceListsBeforeLateRole = 0
  await confirmRole.click()
  try {
    await expect.poll(() => roleBodies).toEqual([{ role: 'security_auditor' }])
    await expect(roleSelect).toBeDisabled()
    await expect(roleSelect.locator(
      'xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " ant-select ")][1]',
    )).toHaveClass(/ant-select-loading/)
    await expect(secondRoleSelect).toBeDisabled()
    await expect(firstDisableButton).toBeDisabled()
    await expect(secondDisableButton).toBeDisabled()
    await expect(page.getByRole('button', { name: '批量停用 (1)' })).toBeDisabled()
    await expect(firstRow.getByRole('checkbox', { name: '选择用户 operator-one@example.invalid', exact: true })).toBeDisabled()
    await expect(secondCheckbox).toBeDisabled()
    await confirmRole.dispatchEvent('click')
    await confirmRole.dispatchEvent('click')
    expect(roleBodies).toEqual([{ role: 'security_auditor' }])
    await page.getByText('工作台', { exact: true }).dispatchEvent('click')
    await expect(page.getByRole('heading', { name: '工作台', exact: true })).toBeVisible()
    const lockButton = page.getByRole('button', { name: '锁定' })
    await lockButton.focus()
    await expect(lockButton).toBeFocused()
    userListsBeforeLateRole = userListRequests
    deviceListsBeforeLateRole = deviceListRequests
  } finally {
    releaseRoleChange()
  }
  await firstRoleResponse
  await page.evaluate(() => new Promise<void>((resolve) => {
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => resolve()))
  }))
  await page.waitForTimeout(300)
  expect(userListRequests).toBe(userListsBeforeLateRole)
  expect(deviceListRequests).toBe(deviceListsBeforeLateRole)
  await expect(page.getByText(/原因：平台依赖暂不可用，请稍后重试。.*影响：.*下一步：/)).toHaveCount(0)
  await expect(page.getByRole('button', { name: '锁定' })).toBeFocused()
  await expect(roleDialog).toBeHidden()
  await page.getByRole('menuitem', { name: /用户与权限/ }).click()
  await expect.poll(() => userListRequests).toBeGreaterThanOrEqual(2)
  await expect.poll(() => deviceListRequests).toBeGreaterThanOrEqual(2)
  await expect(roleSelect).toBeEnabled()
  await expect(secondRoleSelect).toBeEnabled()
  await expect(page.getByRole('button', { name: '批量停用' })).toBeDisabled()
  await secondCheckbox.check()
  await expect(page.getByRole('button', { name: '批量停用 (1)' })).toBeEnabled()
  expect(roleBodies).toEqual([{ role: 'security_auditor' }])

  await roleSelect.click()
  await page.getByText('安全审计员', { exact: true }).last().click()
  await page.getByRole('dialog', { name: '确认创建角色变更申请？' })
    .getByRole('button', { name: '创建申请' }).click()
  await expect.poll(() => roleBodies).toEqual([
    { role: 'security_auditor' },
    { role: 'security_auditor' },
  ])
  await expect(firstRow).toContainText('操作员')
  await expect(roleSelect).toBeDisabled()
  const pendingRoleCard = page.locator('.ant-card').filter({
    has: page.getByText('待审批角色变更申请', { exact: true }),
  })
  const pendingRoleRow = pendingRoleCard.getByRole('row').filter({ hasText: 'operator-one@example.invalid' })
  await expect(pendingRoleRow).toContainText('操作员 → 安全审计员')
  await expect(pendingRoleRow).toContainText('申请人不能审批')

  await firstDisableButton.click()
  let singleDisableDialog = page.getByRole('dialog', { name: '确认停用用户 operator-one@example.invalid？' })
  let singleTargetList = singleDisableDialog.getByRole('list', { name: '待停用用户列表' })
  await expect(singleTargetList.getByRole('listitem')).toHaveCount(1)
  await expect(singleTargetList.getByRole('listitem')).toHaveText('operator-one@example.invalid（operator-1）')
  await singleDisableDialog.getByRole('button', { name: /取\s*消/ }).click()
  await expect(singleDisableDialog).toBeHidden()
  expect(singleDisableIds).toEqual([])

  await firstDisableButton.click()
  singleDisableDialog = page.getByRole('dialog', { name: '确认停用用户 operator-one@example.invalid？' })
  singleTargetList = singleDisableDialog.getByRole('list', { name: '待停用用户列表' })
  await expect(singleTargetList.getByRole('listitem')).toHaveText('operator-one@example.invalid（operator-1）')
  const submittedSingleVisibleIds = (await singleTargetList.getByRole('listitem').allTextContents())
    .map((value) => value.match(/（([^（）]+)）$/)?.[1])
  const confirmSingleDisable = singleDisableDialog.getByRole('button', { name: '确认停用' })
  await confirmSingleDisable.click()
  try {
    await expect.poll(() => singleDisableIds).toEqual(submittedSingleVisibleIds)
    const pendingSingleDisable = firstDisableButton
    await expect(pendingSingleDisable).toBeDisabled()
    await expect(pendingSingleDisable).toHaveClass(/ant-btn-loading/)
    await expect(secondRoleSelect).toBeDisabled()
    await confirmSingleDisable.dispatchEvent('click')
    expect(singleDisableIds).toEqual(['operator-1'])
  } finally {
    releaseSingleDisable()
  }
  await expect(firstRow.getByText('disabled')).toBeVisible()

  await secondCheckbox.check()
  await thirdCheckbox.check()
  await page.getByRole('button', { name: '批量停用 (2)' }).click()
  let batchDialog = page.getByRole('dialog', { name: '确认批量停用 2 个用户？' })
  await expect(batchDialog).toContainText('回收其活动任务、卡租约和邮箱会话')
  let batchTargetItems = batchDialog.getByRole('list', { name: '待停用用户列表' }).getByRole('listitem')
  await expect(batchTargetItems).toHaveCount(2)
  await expect(batchTargetItems.nth(0)).toHaveText('operator-two@example.invalid（operator-2）')
  await expect(batchTargetItems.nth(1)).toHaveText('operator-three@example.invalid（operator-3）')
  const cancelledVisibleIds = (await batchTargetItems.allTextContents()).map((value) => value.match(/（([^（）]+)）$/)?.[1])
  expect(cancelledVisibleIds).toEqual(['operator-2', 'operator-3'])
  await batchDialog.getByRole('button', { name: /取\s*消/ }).click()
  await expect(batchDialog).toBeHidden()
  expect(batchBodies).toEqual([])

  await page.getByRole('button', { name: '批量停用 (2)' }).click()
  batchDialog = page.getByRole('dialog', { name: '确认批量停用 2 个用户？' })
  batchTargetItems = batchDialog.getByRole('list', { name: '待停用用户列表' }).getByRole('listitem')
  const submittedVisibleIds = (await batchTargetItems.allTextContents()).map((value) => value.match(/（([^（）]+)）$/)?.[1])
  await batchDialog.getByRole('button', { name: '确认停用' }).click()
  await expect.poll(() => batchBodies).toEqual([{ user_ids: submittedVisibleIds }])
  await expect(secondRow.getByText('disabled')).toBeVisible()
  await expect(thirdRow.getByText('disabled')).toBeVisible()
  await expect(page.getByRole('button', { name: '批量停用' })).toBeDisabled()

  const successDeviceRow = page.getByRole('row').filter({ hasText: 'trusted-ops-device' })
  const retryDeviceRow = page.getByRole('row').filter({ hasText: 'retry-ops-device' })
  await expect(successDeviceRow).not.toContainText('2026-08-20T00:04:30Z')
  await expect(retryDeviceRow).toContainText('从未活跃')
  await successDeviceRow.getByRole('button', { name: '撤销设备' }).click()
  let revokeDialog = page.getByRole('dialog', { name: '确认撤销设备？' })
  await expect(revokeDialog).toContainText('device-success')
  await expect(revokeDialog).toContainText('活动任务将取消，卡租约释放，邮箱会话终止')
  await revokeDialog.getByRole('button', { name: /取\s*消/ }).click()
  await expect(revokeDialog).toBeHidden()
  expect(revokedDeviceIds).toEqual([])

  await successDeviceRow.getByRole('button', { name: '撤销设备' }).click()
  revokeDialog = page.getByRole('dialog', { name: '确认撤销设备？' })
  const confirmRevoke = revokeDialog.getByRole('button', { name: '撤销设备并回收资源' })
  await confirmRevoke.click()
  try {
    await expect.poll(() => revokedDeviceIds).toEqual(['device-success'])
    const pendingRowButton = successDeviceRow.getByRole('button', { name: '撤销设备' })
    await expect(pendingRowButton).toBeDisabled()
    await expect(pendingRowButton).toHaveClass(/ant-btn-loading/)
    await confirmRevoke.dispatchEvent('click')
    expect(revokedDeviceIds).toEqual(['device-success'])
  } finally {
    releaseDeviceRevoke()
  }
  await expect(successDeviceRow.getByText('revoked')).toBeVisible()
  await expect(successDeviceRow.getByRole('button', { name: '撤销设备' })).toBeDisabled()
  await expect.poll(() => deviceListRequests).toBeGreaterThanOrEqual(2)

  await retryDeviceRow.getByRole('button', { name: '撤销设备' }).click()
  revokeDialog = page.getByRole('dialog', { name: '确认撤销设备？' })
  await revokeDialog.getByRole('button', { name: '撤销设备并回收资源' }).click()
  await expect(page.getByText('请求未完成，请稍后重试。 已刷新设备状态，如仍为活动可重试。')).toBeVisible()
  await expect(page.getByText('设备服务暂不可用')).toHaveCount(0)
  await expect(revokeDialog).toBeHidden()
  await expect(retryDeviceRow.getByRole('button', { name: '撤销设备' })).toBeEnabled()
  expect(revokedDeviceIds.filter((id) => id === 'device-retry')).toHaveLength(1)

  await retryDeviceRow.getByRole('button', { name: '撤销设备' }).click()
  revokeDialog = page.getByRole('dialog', { name: '确认撤销设备？' })
  await revokeDialog.getByRole('button', { name: '撤销设备并回收资源' }).click()
  await expect(retryDeviceRow.getByText('revoked')).toBeVisible()
  expect(revokedDeviceIds.filter((id) => id === 'device-retry')).toHaveLength(2)
})

test('user true-state refresh fails closed without stale privileged actions', async ({ page }) => {
  const accessValue = 'user-refresh-memory-access'
  const users = [
    { id: 'admin-1', tenant_id: 'tenant-1', email: 'admin@example.invalid', role: 'platform_admin', is_active: true, created_at: '2026-08-20T00:00:00Z' },
    { id: 'operator-1', tenant_id: 'tenant-1', email: 'operator-one@example.invalid', role: 'operator', is_active: true, created_at: '2026-08-20T00:01:00Z' },
  ]
  let userListRequests = 0
  let failNextUserList = false
  let waitForRecoveryList = false
  let releaseRecovery = () => undefined
  const recoveryGate = new Promise<void>((resolve) => { releaseRecovery = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({ id: 'admin-1', tenant_id: 'tenant-1', email: 'admin@example.invalid', device_id: 'admin-device', role: 'platform_admin' })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
        allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/admin/users' && request.method() === 'GET') {
      userListRequests += 1
      if (failNextUserList) {
        failNextUserList = false
        waitForRecoveryList = true
        return fulfill({ error: { code: 'service_unavailable', message: '用户目录暂不可用' } }, 503)
      }
      if (waitForRecoveryList) {
        waitForRecoveryList = false
        await recoveryGate
      }
      return fulfill(users)
    }
    if (path === '/api/v1/admin/role-change-requests' && request.method() === 'GET') {
      return fulfill([])
    }
    if (path === '/api/v1/admin/devices' && request.method() === 'GET') return fulfill([])
    if (path === '/api/v1/admin/users/operator-1/role-change-requests' && request.method() === 'POST') {
      failNextUserList = true
      return fulfill({ error: { code: 'service_unavailable', message: '角色结果未确认' } }, 503)
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('admin@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('admin-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('用户与权限', { exact: true }).click()

  const operatorRow = page.getByRole('row').filter({ hasText: 'operator-one@example.invalid' })
  await expect(operatorRow).toBeVisible()
  const initialUserListRequests = userListRequests
  await operatorRow.getByRole('checkbox', { name: '选择用户 operator-one@example.invalid' }).check()
  await page.getByLabel('申请调整 operator-one@example.invalid 角色').click()
  await page.getByText('安全审计员', { exact: true }).last().click()
  await page.getByRole('dialog', { name: '确认创建角色变更申请？' })
    .getByRole('button', { name: '创建申请' }).click()

  await expect.poll(() => userListRequests).toBeGreaterThan(initialUserListRequests)
  const listAlert = page.getByRole('alert').filter({ hasText: '用户与角色申请列表暂不可用' })
  await expect(listAlert).toContainText('原因：')
  await expect(listAlert).toContainText('影响：')
  await expect(listAlert).toContainText('下一步：')
  await expect(operatorRow).toHaveCount(0)
  await expect(page.getByLabel('申请调整 operator-one@example.invalid 角色')).toHaveCount(0)
  await expect(page.getByRole('button', { name: '停用用户 operator-one@example.invalid' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '批量停用' })).toBeDisabled()

  const failedUserListRequests = userListRequests
  await listAlert.getByRole('button', { name: '重试用户列表' }).click()
  await expect.poll(() => userListRequests).toBeGreaterThan(failedUserListRequests)
  await expect(listAlert).toHaveCount(0)
  await expect(operatorRow).toHaveCount(0)
  releaseRecovery()

  await expect(operatorRow).toBeVisible()
  await expect(page.getByRole('button', { name: '批量停用' })).toBeDisabled()
  await expect(page.getByLabel('申请调整 operator-one@example.invalid 角色')).toBeEnabled()
})

test('card true-state refresh fails closed before privileged actions recover', async ({ page }) => {
  const accessValue = 'card-refresh-access'
  let cards = [{
    id: 'card-refresh', tenant_id: 'tenant-1', provider_ref: 'provider-refresh',
    brand: 'VISA', last4: '4242', expiry_month: null, expiry_year: null,
    status: 'available', quarantine_reason_code: null, quarantined_at: null,
    is_active: true, created_at: '2026-08-20T00:00:00Z',
  }]
  let cardListRequests = 0
  let failNextCardList = false
  let waitForRecoveryList = false
  let releaseRecoveryList = () => undefined
  const recoveryListGate = new Promise<void>((resolve) => { releaseRecoveryList = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'ops-user', tenant_id: 'tenant-1', email: 'ops@example.invalid',
        device_id: 'ops-device', role: 'ops_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
        allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/admin/cards' && request.method() === 'GET') {
      cardListRequests += 1
      if (failNextCardList) {
        failNextCardList = false
        waitForRecoveryList = true
        return fulfill({
          error: { code: 'service_unavailable', message: 'sensitive card inventory detail' },
        }, 503)
      }
      if (waitForRecoveryList) {
        waitForRecoveryList = false
        await recoveryListGate
      }
      return fulfill(cards)
    }
    if (path === '/api/v1/admin/cards/card-refresh' && request.method() === 'PATCH') {
      expect(request.postDataJSON()).toEqual({ is_active: false })
      cards = cards.map((card) => ({ ...card, is_active: false, status: 'disabled' }))
      failNextCardList = true
      return fulfill({
        error: { code: 'service_unavailable', message: 'sensitive card mutation detail' },
      }, 503)
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('ops@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('ops-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('卡池管理', { exact: true }).click()

  const cardRow = page.getByRole('row').filter({ hasText: 'provider-refresh' })
  await cardRow.getByRole('button', {
    name: '停用卡 provider-refresh（•••• 4242，card-refresh）', exact: true,
  }).click()
  const disableDialog = page.getByRole('dialog', { name: '确认停用卡 provider-refresh？' })
  await disableDialog.getByRole('button', { name: /停\s*用并释\s*放/ }).click()

  const listError = page.getByRole('alert').filter({ hasText: '卡资源列表暂不可用' })
  await expect(listError).toContainText('原因：平台未能读取卡资源真实状态。')
  await expect(listError).toContainText('影响：旧卡记录和启用、停用操作已隐藏')
  await expect(listError).toContainText('下一步：请重新获取真实状态')
  await expect(page.getByText('provider-refresh')).toHaveCount(0)
  await expect(page.getByRole('button', { name: /[启停]用卡 provider-refresh/ })).toHaveCount(0)
  await expect(page.locator('body')).not.toContainText('sensitive card inventory detail')
  await expect(page.locator('body')).not.toContainText('sensitive card mutation detail')

  const retry = listError.getByRole('button', { name: '重新获取卡资源真实状态' })
  await retry.click()
  try {
    await expect.poll(() => cardListRequests).toBeGreaterThanOrEqual(3)
    await expect(page.locator('.ant-spin')).toBeVisible()
    await expect(page.getByRole('alert').filter({ hasText: '卡资源列表暂不可用' })).toHaveCount(0)
    await expect(page.getByText('provider-refresh')).toHaveCount(0)
  } finally {
    releaseRecoveryList()
  }
  await expect(cardRow.getByText('已停用')).toBeVisible()
  await expect(cardRow.getByRole('button', {
    name: '启用卡 provider-refresh（•••• 4242，card-refresh）', exact: true,
  })).toHaveCount(1)
})

test('mailbox UI retires direct registration and secret rotation', async ({ page }) => {
  const accessValue = 'mailbox-refresh-access'
  let mailboxes = [{
    id: 'mailbox-refresh', email_masked: 'r***@example.invalid',
    connector_type: 'http', is_active: true, status: 'available',
    health_status: 'healthy', last_checked_at: '2026-08-20T00:00:00Z',
    last_error_code: null, active_session_count: 0,
    created_at: '2026-08-20T00:00:00Z',
  }]
  let mailboxListRequests = 0
  let failNextMailboxList = false
  let waitForRecoveryList = false
  let releaseRecoveryList = () => undefined
  const recoveryListGate = new Promise<void>((resolve) => { releaseRecoveryList = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'ops-user', tenant_id: 'tenant-1', email: 'ops@example.invalid',
        device_id: 'ops-device', role: 'ops_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
        allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/mailboxes' && request.method() === 'GET') {
      mailboxListRequests += 1
      if (failNextMailboxList) {
        failNextMailboxList = false
        waitForRecoveryList = true
        return fulfill({
          error: { code: 'service_unavailable', message: 'sensitive mailbox inventory detail' },
        }, 503)
      }
      if (waitForRecoveryList) {
        waitForRecoveryList = false
        await recoveryListGate
      }
      return fulfill(mailboxes)
    }
    if (path === '/api/v1/admin/mailboxes/mailbox-refresh/secret-rotations' && request.method() === 'POST') {
      expect(request.postDataJSON()).toEqual({ secret_ref: 'vault://secret/mailboxes/recovery-2' })
      mailboxes = mailboxes.map((mailbox) => ({
        ...mailbox, health_status: 'unknown', last_checked_at: null,
      }))
      failNextMailboxList = true
      return fulfill({
        error: { code: 'service_unavailable', message: 'sensitive mailbox rotation detail' },
      }, 503)
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('ops@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('ops-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('邮箱池管理', { exact: true }).click()

  const mailboxRow = page.getByRole('row').filter({ hasText: 'r***@example.invalid' })
  await expect(mailboxRow).toBeVisible()
  await expect(mailboxRow.getByRole('button', {
    name: /轮换邮箱密钥引用/,
  })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '登记邮箱连接器' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '导入邮箱池安全包 JSON' })).toBeVisible()
  return

  await mailboxRow.getByRole('button', {
    name: '轮换邮箱密钥引用 r***@example.invalid（mailbox-refresh）', exact: true,
  }).click()
  const rotationDialog = page.getByRole('dialog', { name: '轮换邮箱密钥引用 r***@example.invalid' })
  const secretInput = rotationDialog.getByLabel('新密钥引用')
  await secretInput.fill('vault://secret/mailboxes/recovery-2')
  await rotationDialog.getByRole('button', { name: /确认\s*轮换/ }).click()

  const listError = page.getByRole('alert').filter({ hasText: '邮箱连接器列表暂不可用' })
  await expect(listError).toContainText('原因：平台未能读取邮箱连接器真实状态。')
  await expect(listError).toContainText('影响：旧连接器记录和所有变更入口已隐藏')
  await expect(listError).toContainText('下一步：请重新获取真实状态')
  await expect(mailboxRow).toHaveCount(0)
  await expect(page.getByRole('button', { name: '登记邮箱连接器' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: /邮箱 .*mailbox-refresh/ })).toHaveCount(0)
  await expect(rotationDialog).toBeHidden()
  await expect(secretInput).toHaveCount(0)
  await expect(page.locator('body')).not.toContainText('vault://secret/mailboxes/recovery-2')
  await expect(page.locator('body')).not.toContainText('sensitive mailbox inventory detail')
  await expect(page.locator('body')).not.toContainText('sensitive mailbox rotation detail')

  const retry = listError.getByRole('button', { name: '重新获取邮箱连接器真实状态' })
  const listsBeforeRecovery = mailboxListRequests
  await retry.evaluate((button) => {
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
  })
  try {
    await expect.poll(() => mailboxListRequests).toBe(listsBeforeRecovery + 1)
    await expect(page.locator('.ant-spin')).toBeVisible()
    await expect(page.getByRole('alert').filter({ hasText: '邮箱连接器列表暂不可用' })).toHaveCount(0)
    await expect(page.getByRole('button', { name: '登记邮箱连接器' })).toHaveCount(0)
  } finally {
    releaseRecoveryList()
  }
  await expect(mailboxRow.getByText('未检测', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: '登记邮箱连接器' })).toHaveCount(1)
  await mailboxRow.getByRole('button', {
    name: '轮换邮箱密钥引用 r***@example.invalid（mailbox-refresh）', exact: true,
  }).click()
  const recoveredDialog = page.getByRole('dialog', { name: '轮换邮箱密钥引用 r***@example.invalid' })
  await expect(recoveredDialog.getByLabel('新密钥引用')).toHaveValue('')
})

test('card and mailbox pools keep masked search and filters separate', async ({ page }) => {
  const accessValue = 'pool-filter-access'
  const cards = [
    {
      id: 'card-cn', tenant_id: 'tenant-1', provider_ref: 'provider-cn',
      pool_key: 'checkout-cn', region: 'CN', brand: 'Visa', last4: '4242',
      expiry_month: 12, expiry_year: 2030, status: 'available',
      quarantine_reason_code: null, quarantined_at: null, is_active: true,
      created_at: '2026-08-20T00:00:00Z', pan: '4111111111111111',
    },
    {
      id: 'card-eu', tenant_id: 'tenant-1', provider_ref: 'provider-eu',
      pool_key: 'checkout-eu', region: 'DE', brand: 'Mastercard', last4: '5454',
      expiry_month: 11, expiry_year: 2031, status: 'allocated',
      quarantine_reason_code: null, quarantined_at: null, is_active: true,
      created_at: '2026-08-19T00:00:00Z',
    },
    {
      id: 'card-held', tenant_id: 'tenant-1', provider_ref: 'provider-held',
      pool_key: 'checkout-cn', region: 'CN', brand: 'Visa', last4: '9999',
      expiry_month: null, expiry_year: null, status: 'quarantined',
      quarantine_reason_code: 'provider_dispute', quarantined_at: '2026-08-20T01:00:00Z',
      is_active: false, created_at: '2026-08-18T00:00:00Z',
    },
  ]
  const mailboxes = [
    {
      id: 'mail-http', email_masked: 'h***@example.invalid', connector_type: 'http',
      task_type: 'signup-cn', is_active: true, status: 'available',
      health_status: 'healthy', last_checked_at: '2026-08-20T00:00:00Z',
      last_error_code: null, active_session_count: 0,
      created_at: '2026-08-20T00:00:00Z', email_raw: 'hidden@example.com',
    },
    {
      id: 'mail-imap', email_masked: 'i***@example.invalid', connector_type: 'imap',
      task_type: 'signup-eu', is_active: true, status: 'busy',
      health_status: 'unavailable', last_checked_at: '2026-08-20T00:00:00Z',
      last_error_code: 'connector_unavailable', active_session_count: 1,
      created_at: '2026-08-19T00:00:00Z', password: 'mailbox-secret-value',
    },
    {
      id: 'mail-disabled', email_masked: 'd***@example.invalid', connector_type: 'http',
      task_type: 'signup-cn', is_active: false, status: 'disabled',
      health_status: 'unknown', last_checked_at: null, last_error_code: null,
      active_session_count: 0, created_at: '2026-08-18T00:00:00Z',
    },
  ]

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'ops-user', tenant_id: 'tenant-1', email: 'ops@example.invalid',
        device_id: 'ops-device', role: 'ops_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
        allocated_cards: 1, waiting_mail_sessions: 1, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/admin/cards') return fulfill(cards)
    if (path === '/api/v1/mailboxes') return fulfill(mailboxes)
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('ops@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('ops-device')
  await page.getByRole('button', { name: '安全登录' }).click()

  await page.getByText('卡池管理', { exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: '显示 3 / 共 3 张卡' })).toBeVisible()
  const cardSearch = page.getByLabel('搜索信用卡池')
  await cardSearch.fill('4242')
  await expect(page.getByText('provider-cn', { exact: true })).toBeVisible()
  await expect(page.getByText('provider-eu', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('status').filter({ hasText: '显示 1 / 共 3 张卡' })).toBeVisible()
  await cardSearch.fill('')
  const cardPoolFilter = page.getByLabel('按卡池筛选')
  await cardPoolFilter.click()
  await page.locator('.ant-select-dropdown:visible .ant-select-item-option')
    .filter({ hasText: 'checkout-eu' }).click()
  await expect(page.getByText('provider-eu', { exact: true })).toBeVisible()
  await expect(page.getByText('provider-cn', { exact: true })).toHaveCount(0)

  await page.getByText('邮箱池管理', { exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: '显示 3 / 共 3 个邮箱' })).toBeVisible()
  const mailboxSearch = page.getByLabel('搜索邮箱池')
  await mailboxSearch.fill('imap')
  await expect(page.getByText('i***@example.invalid', { exact: true })).toBeVisible()
  await expect(page.getByText('h***@example.invalid', { exact: true })).toHaveCount(0)
  await mailboxSearch.fill('')
  const mailboxHealthFilter = page.getByLabel('按邮箱健康状态筛选')
  await mailboxHealthFilter.click()
  await page.locator('.ant-select-dropdown:visible .ant-select-item-option')
    .filter({ hasText: '异常' }).click()
  await expect(page.getByText('i***@example.invalid', { exact: true })).toBeVisible()
  await expect(page.getByText('d***@example.invalid', { exact: true })).toHaveCount(0)
  await expect(page.locator('body')).not.toContainText('4111111111111111')
  await expect(page.locator('body')).not.toContainText('hidden@example.com')
  await expect(page.locator('body')).not.toContainText('mailbox-secret-value')
})

test('mailbox mutations cannot refresh through a replacement session', async ({ page }) => {
  const accessValues = ['mailbox-old-access', 'mailbox-new-access']
  let loginAttempts = 0
  let mailbox = {
    id: 'mailbox-session', email_masked: 's***@example.invalid',
    connector_type: 'http', is_active: true, status: 'available',
    health_status: 'healthy', last_checked_at: '2026-08-20T00:00:00Z',
    last_error_code: null, active_session_count: 1,
    created_at: '2026-08-20T00:00:00Z',
  }
  const mailboxListAuthorizations: string[] = []
  const mailboxStateRequests: Array<{ authorization: string; isActive: boolean }> = []
  let releaseOldMutation = () => undefined
  const oldMutationGate = new Promise<void>((resolve) => { releaseOldMutation = resolve })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      const accessToken = accessValues[loginAttempts]
      loginAttempts += 1
      return fulfill({ access_token: accessToken, expires_in: 900, token_type: 'bearer' })
    }
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'ops-session-user', tenant_id: 'tenant-1', email: 'ops-session@example.invalid',
        device_id: 'ops-session-device', role: 'ops_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
        allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/mailboxes' && request.method() === 'GET') {
      mailboxListAuthorizations.push(request.headers().authorization ?? '')
      return fulfill([mailbox])
    }
    if (path === '/api/v1/admin/mailboxes/mailbox-session' && request.method() === 'PATCH') {
      const isActive = Boolean((request.postDataJSON() as { is_active: boolean }).is_active)
      mailboxStateRequests.push({
        authorization: request.headers().authorization ?? '',
        isActive,
      })
      mailbox = {
        ...mailbox,
        is_active: isActive,
        status: isActive ? 'available' : 'disabled',
        active_session_count: 0,
      }
      if (mailboxStateRequests.length === 1) {
        await oldMutationGate
        return fulfill({ error: { code: 'service_unavailable', message: 'old mailbox response lost' } }, 503)
      }
      return fulfill(mailbox)
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  const signIn = async () => {
    await page.getByLabel('租户').fill('tenant-1')
    await page.getByLabel('平台账号').fill('ops-session@example.invalid')
    await page.getByLabel('平台密码').fill('development-password')
    await page.getByLabel('设备标识').fill('ops-session-device')
    await page.getByRole('button', { name: '安全登录' }).click()
    await expect(page.getByText('ops-session@example.invalid')).toBeVisible()
  }

  await page.goto('/')
  await signIn()
  await page.getByText('邮箱池管理', { exact: true }).click()
  const mailboxRow = page.getByRole('row').filter({ hasText: 's***@example.invalid' })
  const disableMailbox = mailboxRow.getByRole('button', {
    name: '停用邮箱 s***@example.invalid（mailbox-session）', exact: true,
  })
  await disableMailbox.click()
  const disableDialog = page.getByRole('dialog', { name: '确认停用邮箱 s***@example.invalid？' })
  const oldMutationResponse = page.waitForResponse((response) => (
    new URL(response.url()).pathname === '/api/v1/admin/mailboxes/mailbox-session'
  ))
  await disableDialog.getByRole('button', { name: /停\s*用并撤\s*销会\s*话/ }).click()
  let listsBeforeOldOutcome = 0
  try {
    await expect.poll(() => mailboxStateRequests).toEqual([{
      authorization: `Bearer ${accessValues[0]}`,
      isActive: false,
    }])
    await page.evaluate(() => window.dispatchEvent(new Event('platform:auth-expired')))
    await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible()
    await signIn()
    await page.getByText('邮箱池管理', { exact: true }).click()
    const currentEnableMailbox = mailboxRow.getByRole('button', {
      name: '启用邮箱 s***@example.invalid（mailbox-session）', exact: true,
    })
    await expect(currentEnableMailbox).toBeVisible()
    await currentEnableMailbox.focus()
    await expect(currentEnableMailbox).toBeFocused()
    listsBeforeOldOutcome = mailboxListAuthorizations.length
  } finally {
    releaseOldMutation()
  }

  await oldMutationResponse
  await page.evaluate(() => new Promise<void>((resolve) => {
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => resolve()))
  }))
  await page.waitForTimeout(300)
  expect(mailboxListAuthorizations).toHaveLength(listsBeforeOldOutcome)
  await expect(page.getByText(/原因：平台未能确认邮箱连接器状态变更结果。影响：.*下一步：/)).toHaveCount(0)
  const currentEnableMailbox = mailboxRow.getByRole('button', {
    name: '启用邮箱 s***@example.invalid（mailbox-session）', exact: true,
  })
  await expect(currentEnableMailbox).toBeFocused()
  await currentEnableMailbox.click()
  await expect(mailboxRow.getByRole('button', {
    name: '停用邮箱 s***@example.invalid（mailbox-session）', exact: true,
  })).toBeVisible()
  expect(mailboxStateRequests).toEqual([{
    authorization: `Bearer ${accessValues[0]}`,
    isActive: false,
  }, {
    authorization: `Bearer ${accessValues[1]}`,
    isActive: true,
  }])
  expect(mailboxListAuthorizations.filter((value) => value === `Bearer ${accessValues[1]}`).length).toBeGreaterThan(0)
})

test('ops admin imports card and mailbox pools through secure bundles', async ({ page }) => {
  test.setTimeout(60_000)
  const accessValue = 'ops-resource-access'
  let cards: Array<Record<string, unknown>> = []
  let mailboxes: Array<Record<string, unknown>> = [{
    id: 'mailbox-unavailable', email_masked: 'd***@example.invalid',
    connector_type: 'http', task_type: 'password_reset', is_active: true, status: 'available',
    health_status: 'unavailable', last_checked_at: '2026-08-20T00:05:00Z',
    last_error_code: 'connector_unavailable', active_session_count: 0,
    created_at: '2026-08-20T00:00:00Z',
  }, {
    id: 'mailbox-committed', email_masked: 'c***@example.invalid',
    connector_type: 'http', task_type: 'mail_code', is_active: true, status: 'busy',
    health_status: 'healthy', last_checked_at: '2026-08-20T00:06:00Z',
    last_error_code: null, active_session_count: 1,
    created_at: '2026-08-20T00:01:00Z',
  }, {
    id: 'mailbox-retry', email_masked: 'r***@example.invalid',
    connector_type: 'http', task_type: 'mail_code', is_active: true, status: 'available',
    health_status: 'healthy', last_checked_at: '2026-08-20T00:07:00Z',
    last_error_code: null, active_session_count: 0,
    created_at: '2026-08-20T00:02:00Z',
  }]
  const cardStateRequests: Array<{ cardId: string; body: unknown }> = []
  const cardCreateBodies: unknown[] = []
  const cardImportBodies: unknown[] = []
  const cardImportKeys: string[] = []
  const cardImportReceipts: string[] = []
  let cardListRequests = 0
  let releaseCardCreate = () => undefined
  const cardCreateGate = new Promise<void>((resolve) => { releaseCardCreate = resolve })
  let cardTwoFailures = 1
  let releaseCommittedCardFailure = () => undefined
  const committedCardFailureGate = new Promise<void>((resolve) => {
    releaseCommittedCardFailure = resolve
  })
  const mailboxStateRequests: Array<{ mailboxId: string; body: unknown }> = []
  const mailboxRotationRequests: Array<{ mailboxId: string; body: unknown }> = []
  const mailboxCreateBodies: unknown[] = []
  const mailboxImportBodies: unknown[] = []
  const mailboxImportKeys: string[] = []
  const mailboxImportReceipts: string[] = []
  let mailboxCreateFailures = 1
  let releaseMailboxCreate = () => undefined
  const mailboxCreateGate = new Promise<void>((resolve) => { releaseMailboxCreate = resolve })
  let mailboxListRequests = 0
  let mailboxRetryFailures = 1
  let releaseCommittedMailboxFailure = () => undefined
  const committedMailboxFailureGate = new Promise<void>((resolve) => {
    releaseCommittedMailboxFailure = resolve
  })
  let releaseCommittedRotationFailure = () => undefined
  const committedRotationFailureGate = new Promise<void>((resolve) => {
    releaseCommittedRotationFailure = resolve
  })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const fulfill = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
    })
    if (path === '/api/v1/auth/config') {
      return fulfill({ mode: 'local', issuer: null, client_id: null, desktop_client_id: null, audience: null })
    }
    if (path === '/api/v1/auth/login') {
      return fulfill({ access_token: accessValue, expires_in: 900, token_type: 'bearer' })
    }
    expect(request.headers().authorization).toBe(`Bearer ${accessValue}`)
    if (path === '/api/v1/me') {
      return fulfill({
        id: 'ops-user', tenant_id: 'tenant-1', email: 'ops@example.invalid',
        device_id: 'ops-device', role: 'ops_admin',
      })
    }
    if (path === '/api/v1/dashboard/summary') {
      return fulfill({
        scope: 'tenant', generated_at: '2026-08-20T00:00:00Z', active_tasks: 0,
        allocated_cards: 0, waiting_mail_sessions: 0, queued_uploads: 0,
        unknown_uploads: 0, task_statuses: {}, mail_session_statuses: {},
        card_allocation_statuses: {}, upload_statuses: {},
      })
    }
    if (path === '/api/v1/admin/cards' && request.method() === 'GET') {
      cardListRequests += 1
      return fulfill(cards)
    }
    if (path === '/api/v1/admin/cards' && request.method() === 'POST') {
      const body = request.postDataJSON() as Record<string, unknown>
      cardCreateBodies.push(body)
      expect(Object.keys(body).sort()).toEqual(['brand', 'last4', 'pool_key', 'provider_ref', 'region', 'secret_ref'])
      expect(body).not.toHaveProperty('pan')
      expect(body).not.toHaveProperty('cvv')
      await cardCreateGate
      cards = [{
        id: 'card-1', tenant_id: 'tenant-1', provider_ref: body.provider_ref,
        pool_key: body.pool_key, region: body.region,
        brand: body.brand, last4: body.last4, expiry_month: null, expiry_year: null,
        status: 'available', quarantine_reason_code: null, quarantined_at: null,
        is_active: true, created_at: '2026-08-20T00:00:00Z',
      }, {
        id: 'card-2', tenant_id: 'tenant-1', provider_ref: 'provider-safe-2',
        pool_key: 'checkout-cn', region: 'cn-east',
        brand: 'VISA', last4: '5555', expiry_month: null, expiry_year: null,
        status: 'available', quarantine_reason_code: null, quarantined_at: null,
        is_active: true, created_at: '2026-08-20T00:01:00Z',
      }]
      return fulfill(cards[0], 201)
    }
    if (path === '/api/v1/admin/cards/imports' && request.method() === 'POST') {
      const body = request.postDataJSON() as Array<Record<string, unknown>>
      cardImportBodies.push(body)
      cardImportKeys.push(request.headers()['idempotency-key'] ?? '')
      cardImportReceipts.push(request.headers()['secure-import-receipt'] ?? '')
      const imported = body.map((item, index) => ({
        id: `card-import-${index + 1}`, tenant_id: 'tenant-1', provider_ref: item.provider_ref,
        pool_key: item.pool_key, region: item.region, brand: item.brand, last4: item.last4,
        expiry_month: null, expiry_year: null, status: 'available', quarantine_reason_code: null,
        quarantined_at: null, is_active: true, created_at: '2026-08-20T00:00:00Z',
      }))
      if (cardImportBodies.length === 1) {
        cards = [...cards, ...imported]
        return fulfill({ error: { code: 'service_unavailable', message: 'import response lost' } }, 503)
      }
      return fulfill({
        id: 'card-import-receipt', pool_type: 'card', imported_count: body.length,
        trace_id: 'card-import-trace', created_at: '2026-08-20T00:00:00Z',
      })
    }
    const cardStateMatch = path.match(/^\/api\/v1\/admin\/cards\/([^/]+)$/)
    if (cardStateMatch && request.method() === 'PATCH') {
      const cardId = cardStateMatch[1]
      expect(request.postDataJSON()).toEqual({ is_active: false })
      expect(JSON.stringify(request.postDataJSON())).not.toContain('secret')
      cardStateRequests.push({ cardId, body: request.postDataJSON() })
      if (cardId === 'card-1') {
        cards = cards.map((card) => card.id === cardId ? { ...card, is_active: false, status: 'disabled' } : card)
        await committedCardFailureGate
        return fulfill({ error: { code: 'service_unavailable', message: 'card response lost' } }, 503)
      }
      if (cardId === 'card-2' && cardTwoFailures > 0) {
        cardTwoFailures -= 1
        return fulfill({ error: { code: 'service_unavailable', message: 'card update unavailable' } }, 503)
      }
      cards = cards.map((card) => card.id === cardId ? { ...card, is_active: false, status: 'disabled' } : card)
      return fulfill(cards.find((card) => card.id === cardId))
    }
    if (path === '/api/v1/mailboxes' && request.method() === 'GET') {
      mailboxListRequests += 1
      return fulfill(mailboxes)
    }
    if (path === '/api/v1/admin/mailboxes' && request.method() === 'POST') {
      const body = request.postDataJSON() as Record<string, unknown>
      expect(Object.keys(body).sort()).toEqual(['connector_type', 'email_masked', 'secret_ref', 'task_type'])
      mailboxCreateBodies.push(body)
      if (mailboxCreateBodies.length === 1) await mailboxCreateGate
      if (mailboxCreateFailures > 0) {
        mailboxCreateFailures -= 1
        return fulfill({ error: { code: 'service_unavailable', message: 'mailbox create unavailable' } }, 503)
      }
      mailboxes = [{
        id: 'mailbox-1', email_masked: body.email_masked,
        connector_type: body.connector_type, task_type: body.task_type, is_active: true, status: 'available',
        health_status: 'healthy', last_checked_at: '2026-08-20T00:08:00Z', last_error_code: null,
        active_session_count: 0, created_at: '2026-08-20T00:00:00Z',
      }, ...mailboxes]
      return fulfill(mailboxes[0], 201)
    }
    if (path === '/api/v1/admin/mailboxes/imports' && request.method() === 'POST') {
      const body = request.postDataJSON() as Array<Record<string, unknown>>
      mailboxImportBodies.push(body)
      mailboxImportKeys.push(request.headers()['idempotency-key'] ?? '')
      mailboxImportReceipts.push(request.headers()['secure-import-receipt'] ?? '')
      if (mailboxImportBodies.length === 1) {
        return fulfill({ error: { code: 'validation_error', message: 'invalid reference manifest' } }, 422)
      }
      const imported = body.map((item, index) => ({
        id: `mailbox-import-${index + 1}`, email_masked: item.email_masked,
        connector_type: item.connector_type, task_type: item.task_type, is_active: true,
        status: 'available', health_status: 'unknown', last_checked_at: null,
        last_error_code: null, active_session_count: 0, created_at: '2026-08-20T00:00:00Z',
      }))
      mailboxes = [...imported, ...mailboxes]
      return fulfill({
        id: 'mailbox-import-receipt', pool_type: 'mailbox', imported_count: body.length,
        trace_id: 'mailbox-import-trace', created_at: '2026-08-20T00:00:00Z',
      }, 201)
    }
    const mailboxStateMatch = path.match(/^\/api\/v1\/admin\/mailboxes\/([^/]+)$/)
    if (mailboxStateMatch && request.method() === 'PATCH') {
      const mailboxId = mailboxStateMatch[1]
      const body = request.postDataJSON()
      expect(body).toEqual({ is_active: false })
      mailboxStateRequests.push({ mailboxId, body })
      if (mailboxId === 'mailbox-committed') {
        mailboxes = mailboxes.map((mailbox) => mailbox.id === mailboxId ? {
          ...mailbox, is_active: false, status: 'disabled', active_session_count: 0,
        } : mailbox)
        await committedMailboxFailureGate
        return fulfill({ error: { code: 'service_unavailable', message: 'mailbox response lost' } }, 503)
      }
      if (mailboxId === 'mailbox-retry' && mailboxRetryFailures > 0) {
        mailboxRetryFailures -= 1
        return fulfill({ error: { code: 'service_unavailable', message: 'mailbox update unavailable' } }, 503)
      }
      mailboxes = mailboxes.map((mailbox) => mailbox.id === mailboxId ? {
        ...mailbox, is_active: false, status: 'disabled', active_session_count: 0,
      } : mailbox)
      return fulfill(mailboxes.find((mailbox) => mailbox.id === mailboxId))
    }
    const mailboxRotationMatch = path.match(/^\/api\/v1\/admin\/mailboxes\/([^/]+)\/secret-rotations$/)
    if (mailboxRotationMatch && request.method() === 'POST') {
      const mailboxId = mailboxRotationMatch[1]
      const body = request.postDataJSON()
      expect(Object.keys(body)).toEqual(['secret_ref'])
      mailboxRotationRequests.push({ mailboxId, body })
      if (mailboxRotationRequests.length === 1) {
        mailboxes = mailboxes.map((mailbox) => mailbox.id === mailboxId ? {
          ...mailbox, health_status: 'unknown', last_checked_at: null,
        } : mailbox)
        await committedRotationFailureGate
        return fulfill({ error: { code: 'service_unavailable', message: 'rotation response lost' } }, 503)
      }
      return fulfill(mailboxes.find((mailbox) => mailbox.id === mailboxId))
    }
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('ops@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('ops-device')
  await page.getByRole('button', { name: '安全登录' }).click()

  await page.getByText('卡池管理', { exact: true }).click()
  const cardBundleInput = page.locator('input[type="file"][accept*="json"]')
  await cardBundleInput.setInputFiles({
    name: 'malformed-sensitive-input.json', mimeType: 'application/json',
    buffer: Buffer.from('{"raw_sensitive_fragment":"must-not-render"'),
  })
  await expect(page.getByText('导入文件不是有效的安全包 JSON。', { exact: true })).toBeVisible()
  await expect(page.locator('body')).not.toContainText('must-not-render')
  const secureCardItems = [{
    provider_ref: 'provider-imported', pool_key: 'checkout-cn', region: 'cn-east',
    brand: 'VISA', last4: '6060', expiry_month: null, expiry_year: null,
  }]
  await cardBundleInput.setInputFiles({
    name: 'wrong-mailbox-pool.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      schema_version: 1, pool_type: 'mailbox',
      receipt_token: 'epir1.wrong-pool.signature',
      items: [{ email_masked: 'w***@example.invalid', connector_type: 'http', task_type: 'mail_code' }],
    })),
  })
  await expect(page.getByText('该安全包属于邮箱池，不能导入信用卡池。', { exact: true })).toBeVisible()
  expect(cardImportBodies).toEqual([])
  await cardBundleInput.setInputFiles({
    name: 'card-pool-with-secret.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      schema_version: 1, pool_type: 'card',
      receipt_token: 'epir1.card-receipt.signature',
      items: [{ ...secureCardItems[0], pan: '4111111111111111' }],
    })),
  })
  await expect(page.getByText('安全包第 1 条信用卡元数据无效；未发送任何数据。', { exact: true })).toBeVisible()
  expect(cardImportBodies).toEqual([])
  await expect(page.locator('body')).not.toContainText('4111111111111111')
  await cardBundleInput.setInputFiles({
    name: 'card-pool-secure.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      schema_version: 1, pool_type: 'card',
      receipt_token: 'epir1.card-receipt.signature', items: secureCardItems,
    })),
  })
  const cardPreview = page.getByRole('dialog', { name: '确认导入信用卡池安全包？' })
  await expect(cardPreview).toContainText('card-pool-secure.json')
  await expect(cardPreview).toContainText('脱敏资源：1 条')
  await expect(cardPreview).toContainText('目标卡池：checkout-cn')
  expect(cardImportBodies).toEqual([])
  await cardPreview.getByRole('button', { name: '确认导入 1 条' }).click()
  await expect.poll(() => cardImportBodies).toEqual([secureCardItems])
  expect(cardImportReceipts).toEqual(['epir1.card-receipt.signature'])
  await expect(page.getByRole('button', { name: '重试上次信用卡池引用清单' })).toBeVisible()
  await page.getByRole('button', { name: '重试上次信用卡池引用清单' }).click()
  await expect.poll(() => cardImportBodies).toEqual([secureCardItems, secureCardItems])
  expect(cardImportKeys[1]).toBe(cardImportKeys[0])
  expect(cardImportReceipts).toEqual([
    'epir1.card-receipt.signature', 'epir1.card-receipt.signature',
  ])
  await expect(page.getByRole('row').filter({ hasText: 'provider-imported' })).toBeVisible()
  await expect(page.getByText('最近一次信用卡池导入已确认：1 条', { exact: true })).toBeVisible()
  await expect(page.getByText('card-import-receipt', { exact: true })).toBeVisible()
  await expect(page.getByText('card-import-trace', { exact: true })).toBeVisible()
  await expect(page.locator('body')).not.toContainText('epir1.card-receipt.signature')
  await expect(page.getByRole('button', { name: '登记卡资源' })).toHaveCount(0)

  await page.getByText('邮箱池管理', { exact: true }).click()
  const secureMailboxItems = [{
    email_masked: 'i***@example.invalid', connector_type: 'http', task_type: 'mail_code',
  }]
  const mailboxInput = page.locator('input[type="file"][accept*="json"]')
  await mailboxInput.setInputFiles({
    name: 'mailbox-pool-with-secret.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      schema_version: 1, pool_type: 'mailbox',
      receipt_token: 'epir1.mail-receipt.signature',
      items: [{ ...secureMailboxItems[0], password: 'mailbox-secret-value' }],
    })),
  })
  await expect(page.getByText('安全包第 1 条邮箱元数据无效；未发送任何数据。', { exact: true })).toBeVisible()
  expect(mailboxImportBodies).toEqual([])
  await expect(page.locator('body')).not.toContainText('mailbox-secret-value')
  await mailboxInput.setInputFiles({
    name: 'mailbox-pool-cancelled.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      schema_version: 1, pool_type: 'mailbox',
      receipt_token: 'epir1.mail-receipt.signature', items: secureMailboxItems,
    })),
  })
  let mailboxPreview = page.getByRole('dialog', { name: '确认导入邮箱池安全包？' })
  await mailboxPreview.getByRole('button', { name: /取\s*消/ }).click()
  await expect(mailboxPreview).toBeHidden()
  expect(mailboxImportBodies).toEqual([])
  await mailboxInput.setInputFiles({
    name: 'mailbox-pool-secure.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      schema_version: 1, pool_type: 'mailbox',
      receipt_token: 'epir1.mail-receipt.signature', items: secureMailboxItems,
    })),
  })
  mailboxPreview = page.getByRole('dialog', { name: '确认导入邮箱池安全包？' })
  await expect(mailboxPreview).toContainText('mailbox-pool-secure.json')
  await expect(mailboxPreview).toContainText('服务端路由：mail_code')
  expect(mailboxImportBodies).toEqual([])
  await mailboxPreview.getByRole('button', { name: '确认导入 1 条' }).click()
  await expect.poll(() => mailboxImportBodies).toEqual([secureMailboxItems])
  expect(mailboxImportReceipts).toEqual(['epir1.mail-receipt.signature'])
  await expect(page.getByRole('button', { name: '重试上次邮箱池引用清单' })).toHaveCount(0)
  await mailboxInput.setInputFiles({
    name: 'mailbox-pool-secure.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      schema_version: 1, pool_type: 'mailbox',
      receipt_token: 'epir1.mail-receipt.signature', items: secureMailboxItems,
    })),
  })
  mailboxPreview = page.getByRole('dialog', { name: '确认导入邮箱池安全包？' })
  await mailboxPreview.getByRole('button', { name: '确认导入 1 条' }).click()
  await expect.poll(() => mailboxImportBodies).toEqual([
    secureMailboxItems, secureMailboxItems,
  ])
  expect(mailboxImportKeys[1]).not.toBe(mailboxImportKeys[0])
  expect(mailboxImportReceipts).toEqual([
    'epir1.mail-receipt.signature', 'epir1.mail-receipt.signature',
  ])
  await expect(page.getByRole('row').filter({ hasText: 'i***@example.invalid' })).toBeVisible()
  await expect(page.getByText('最近一次邮箱池导入已确认：1 条', { exact: true })).toBeVisible()
  await expect(page.getByText('mailbox-import-receipt', { exact: true })).toBeVisible()
  await expect(page.getByText('mailbox-import-trace', { exact: true })).toBeVisible()
  await expect(page.locator('body')).not.toContainText('epir1.mail-receipt.signature')
  await expect(page.getByRole('button', { name: '登记邮箱连接器' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: /轮换邮箱密钥引用/ })).toHaveCount(0)
  return

  await page.getByText('卡池管理', { exact: true }).click()
  const cardImportPayload = [{
    provider_ref: 'provider-imported', pool_key: 'checkout-cn', region: 'cn-east',
    brand: 'VISA', last4: '6060', secret_ref: 'vault://secret/cards/provider-imported',
  }]
  await page.locator('input[type="file"][accept*="json"]').setInputFiles({
    name: 'card-pool.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(cardImportPayload)),
  })
  await expect.poll(() => cardImportBodies).toEqual([cardImportPayload])
  await expect(page.getByRole('button', { name: '重试上次信用卡池引用清单' })).toBeVisible()
  await expect(page.getByRole('button', { name: '放弃并清除上次信用卡池引用清单' })).toBeVisible()
  await page.getByRole('button', { name: '重试上次信用卡池引用清单' }).click()
  await expect.poll(() => cardImportBodies).toEqual([cardImportPayload, cardImportPayload])
  expect(cardImportKeys[0]).toMatch(/^[0-9a-f-]{36}$/)
  expect(cardImportKeys[1]).toBe(cardImportKeys[0])
  await expect(page.getByRole('button', { name: '重试上次信用卡池引用清单' })).toHaveCount(0)
  await expect(page.getByRole('row').filter({ hasText: 'provider-imported' })).toBeVisible()
  await expect(page.locator('body')).not.toContainText('vault://secret/cards/provider-imported')
  await page.getByRole('button', { name: '登记卡资源' }).click()
  let cardDialog = page.getByRole('dialog', { name: '登记卡资源' })
  await cardDialog.getByLabel('密钥引用').fill('vault://secret/cards/must-clear')
  await cardDialog.getByRole('button', { name: /取\s*消/ }).click()
  await page.getByRole('button', { name: '登记卡资源' }).click()
  cardDialog = page.getByRole('dialog', { name: '登记卡资源' })
  await expect(cardDialog.getByLabel('密钥引用')).toHaveValue('')
  await cardDialog.getByLabel('提供方引用').fill('provider-safe-1')
  await cardDialog.getByLabel('卡池').fill('checkout-cn')
  await cardDialog.getByLabel('地区').fill('cn-east')
  await cardDialog.getByLabel('品牌').fill('VISA')
  await cardDialog.getByLabel('尾号').fill('4242')
  await cardDialog.getByLabel('密钥引用').fill('vault://secret/cards/provider-safe-1')
  const confirmCardCreate = cardDialog.getByRole('button').filter({ hasText: /^登\s*记$/ })
  await confirmCardCreate.click()
  try {
    await expect.poll(() => cardCreateBodies).toHaveLength(1)
    await expect(confirmCardCreate).toHaveClass(/ant-btn-loading/)
    await cardDialog.locator('form').dispatchEvent('submit')
    await cardDialog.locator('form').dispatchEvent('submit')
    expect(cardCreateBodies).toHaveLength(1)
  } finally {
    releaseCardCreate()
  }
  await expect(page.getByText('•••• 4242')).toBeVisible()
  await expect(page.locator('body')).not.toContainText('vault://secret/cards/provider-safe-1')
  const firstCardRow = page.getByRole('row').filter({ hasText: 'provider-safe-1' })
  const secondCardRow = page.getByRole('row').filter({ hasText: 'provider-safe-2' })
  const firstDisableCard = firstCardRow.getByRole('button', {
    name: '停用卡 provider-safe-1（•••• 4242，card-1）', exact: true,
  })
  const secondDisableCard = secondCardRow.getByRole('button', {
    name: '停用卡 provider-safe-2（•••• 5555，card-2）', exact: true,
  })
  await expect(firstDisableCard).toHaveCount(1)
  await expect(secondDisableCard).toHaveCount(1)

  await firstDisableCard.click()
  let disableDialog = page.getByRole('dialog', { name: '确认停用卡 provider-safe-1？' })
  await expect(disableDialog).toContainText('提供方引用：provider-safe-1')
  await expect(disableDialog).toContainText('掩码卡号：•••• 4242')
  await expect(disableDialog).toContainText('卡资源 ID：card-1')
  const visibleCardId = (await disableDialog.getByText('卡资源 ID：card-1', { exact: true }).textContent())
    ?.replace('卡资源 ID：', '')
  expect(visibleCardId).toBe('card-1')
  await expect(disableDialog).not.toContainText('4111111111114242')
  await expect(disableDialog).not.toContainText('999')
  await expect(disableDialog).not.toContainText('vault://secret/cards/provider-safe-1')
  await disableDialog.getByRole('button', { name: /取\s*消/ }).click()
  await expect(disableDialog).toBeHidden()
  expect(cardStateRequests).toEqual([])
  await expect(firstDisableCard).toBeEnabled()
  await expect(secondDisableCard).toBeEnabled()

  await firstDisableCard.click()
  disableDialog = page.getByRole('dialog', { name: '确认停用卡 provider-safe-1？' })
  const confirmCommittedFailure = disableDialog.getByRole('button', { name: /停\s*用并释\s*放/ })
  await confirmCommittedFailure.click()
  try {
    await expect.poll(() => cardStateRequests).toEqual([{
      cardId: visibleCardId, body: { is_active: false },
    }])
    const pendingCardButton = firstDisableCard
    await expect(pendingCardButton).toBeDisabled()
    await expect(pendingCardButton).toHaveClass(/ant-btn-loading/)
    await expect(secondDisableCard).toBeDisabled()
    await confirmCommittedFailure.dispatchEvent('click')
    await confirmCommittedFailure.dispatchEvent('click')
    expect(cardStateRequests).toHaveLength(1)
  } finally {
    releaseCommittedCardFailure()
  }
  await expect(page.getByText(/原因：平台依赖暂不可用，请稍后重试。.*影响：.*下一步：/).last()).toBeVisible()
  await expect(firstCardRow.getByText('已停用')).toBeVisible()
  await expect(firstCardRow.getByRole('button', {
    name: '启用卡 provider-safe-1（•••• 4242，card-1）', exact: true,
  })).toHaveCount(1)
  await expect.poll(() => cardListRequests).toBeGreaterThanOrEqual(3)

  const listsBeforeUnchangedFailure = cardListRequests
  await secondDisableCard.click()
  disableDialog = page.getByRole('dialog', { name: '确认停用卡 provider-safe-2？' })
  await expect(disableDialog).toContainText('掩码卡号：•••• 5555')
  await expect(disableDialog).toContainText('卡资源 ID：card-2')
  await disableDialog.getByRole('button', { name: /停\s*用并释\s*放/ }).click()
  await expect(page.getByText(/原因：平台依赖暂不可用，请稍后重试。.*影响：.*下一步：/).last()).toBeVisible()
  await expect(secondCardRow.getByText('可用')).toBeVisible()
  await expect(secondDisableCard).toBeEnabled()
  await expect.poll(() => cardListRequests).toBeGreaterThan(listsBeforeUnchangedFailure)
  expect(cardStateRequests.filter((item) => item.cardId === 'card-2')).toHaveLength(1)

  await secondDisableCard.click()
  disableDialog = page.getByRole('dialog', { name: '确认停用卡 provider-safe-2？' })
  await disableDialog.getByRole('button', { name: /停\s*用并释\s*放/ }).click()
  await expect(secondCardRow.getByText('已停用')).toBeVisible()
  await expect(secondCardRow.getByRole('button', {
    name: '启用卡 provider-safe-2（•••• 5555，card-2）', exact: true,
  })).toHaveCount(1)
  expect(cardStateRequests.filter((item) => item.cardId === 'card-2')).toHaveLength(2)

  await page.getByText('邮箱池管理', { exact: true }).click()
  const mailboxImportPayload = [{
    email_masked: 'i***@example.invalid', connector_type: 'http', task_type: 'mail_code',
    secret_ref: 'vault://secret/mailboxes/imported-mailbox',
  }]
  await page.locator('input[type="file"][accept*="json"]').setInputFiles({
    name: 'mailbox-pool.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(mailboxImportPayload)),
  })
  await expect.poll(() => mailboxImportBodies).toEqual([mailboxImportPayload])
  expect(mailboxImportKeys[0]).toMatch(/^[0-9a-f-]{36}$/)
  await expect(page.getByRole('button', { name: '重试上次邮箱池引用清单' })).toHaveCount(0)
  await page.locator('input[type="file"][accept*="json"]').setInputFiles({
    name: 'mailbox-pool.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(mailboxImportPayload)),
  })
  await expect.poll(() => mailboxImportBodies).toEqual([mailboxImportPayload, mailboxImportPayload])
  expect(mailboxImportKeys[1]).toMatch(/^[0-9a-f-]{36}$/)
  expect(mailboxImportKeys[1]).not.toBe(mailboxImportKeys[0])
  await expect(page.getByRole('row').filter({ hasText: 'i***@example.invalid' })).toBeVisible()
  await expect(page.locator('body')).not.toContainText('vault://secret/mailboxes/imported-mailbox')
  await expect(page.getByText('有 1 个邮箱连接器不可用')).toBeVisible()
  const unavailableMailboxRow = page.getByRole('row').filter({ hasText: 'd***@example.invalid' })
  await expect(page.getByRole('columnheader', { name: '服务端路由键' })).toBeVisible()
  await expect(unavailableMailboxRow.getByText('password_reset', { exact: true })).toBeVisible()
  await expect(unavailableMailboxRow.getByText('异常')).toBeVisible()
  await expect(unavailableMailboxRow).toContainText('连接器不可用')
  await expect(unavailableMailboxRow).not.toContainText('connector_unavailable')
  await expect(unavailableMailboxRow).toContainText('2026-08-20T00:05:00Z')
  const committedMailboxRow = page.getByRole('row').filter({ hasText: 'c***@example.invalid' })
  const retryMailboxRow = page.getByRole('row').filter({ hasText: 'r***@example.invalid' })
  const committedDisableMailbox = committedMailboxRow.getByRole('button', {
    name: '停用邮箱 c***@example.invalid（mailbox-committed）', exact: true,
  })
  const retryDisableMailbox = retryMailboxRow.getByRole('button', {
    name: '停用邮箱 r***@example.invalid（mailbox-retry）', exact: true,
  })
  const retryRotateMailbox = retryMailboxRow.getByRole('button', {
    name: '轮换邮箱密钥引用 r***@example.invalid（mailbox-retry）', exact: true,
  })
  await expect(committedDisableMailbox).toHaveCount(1)
  await expect(retryDisableMailbox).toHaveCount(1)
  await expect(retryRotateMailbox).toHaveCount(1)
  await expect(unavailableMailboxRow.getByRole('button', {
    name: '停用邮箱 d***@example.invalid（mailbox-unavailable）', exact: true,
  })).toHaveCount(1)

  await committedDisableMailbox.click()
  let disableMailboxDialog = page.getByRole('dialog', { name: '确认停用邮箱 c***@example.invalid？' })
  await expect(disableMailboxDialog).toContainText('掩码邮箱：c***@example.invalid')
  await expect(disableMailboxDialog).toContainText('连接器 ID：mailbox-committed')
  await expect(disableMailboxDialog).toContainText('活动会话：1')
  const visibleDisableId = (await disableMailboxDialog.getByText('连接器 ID：mailbox-committed', { exact: true }).textContent())
    ?.replace('连接器 ID：', '')
  expect(visibleDisableId).toBe('mailbox-committed')
  await disableMailboxDialog.getByRole('button', { name: /取\s*消/ }).click()
  await expect(disableMailboxDialog).toBeHidden()
  expect(mailboxStateRequests).toEqual([])
  await expect(committedDisableMailbox).toBeEnabled()
  await expect(retryRotateMailbox).toBeEnabled()

  await committedDisableMailbox.click()
  disableMailboxDialog = page.getByRole('dialog', { name: '确认停用邮箱 c***@example.invalid？' })
  const confirmCommittedMailbox = disableMailboxDialog.getByRole('button', { name: /停\s*用并撤\s*销会\s*话/ })
  const committedMailboxResponse = page.waitForResponse((response) => (
    new URL(response.url()).pathname === '/api/v1/admin/mailboxes/mailbox-committed'
  ))
  await confirmCommittedMailbox.click()
  let listsBeforeLateMailboxOutcome = 0
  try {
    await expect.poll(() => mailboxStateRequests).toEqual([{
      mailboxId: visibleDisableId, body: { is_active: false },
    }])
    const pendingMailboxButton = committedDisableMailbox
    await expect(pendingMailboxButton).toBeDisabled()
    await expect(pendingMailboxButton).toHaveClass(/ant-btn-loading/)
    await expect(retryDisableMailbox).toBeDisabled()
    await expect(retryRotateMailbox).toBeDisabled()
    await expect(page.getByRole('button', { name: '登记邮箱连接器' })).toBeDisabled()
    await confirmCommittedMailbox.dispatchEvent('click')
    await retryRotateMailbox.dispatchEvent('click')
    expect(mailboxStateRequests).toHaveLength(1)
    expect(mailboxRotationRequests).toEqual([])
    await page.getByText('工作台', { exact: true }).dispatchEvent('click')
    await expect(page.getByRole('heading', { name: '工作台', exact: true })).toBeVisible()
    const lockButton = page.getByRole('button', { name: '锁定' })
    await lockButton.focus()
    await expect(lockButton).toBeFocused()
    listsBeforeLateMailboxOutcome = mailboxListRequests
  } finally {
    releaseCommittedMailboxFailure()
  }
  await committedMailboxResponse
  await page.evaluate(() => new Promise<void>((resolve) => {
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => resolve()))
  }))
  await page.waitForTimeout(300)
  expect(mailboxListRequests).toBe(listsBeforeLateMailboxOutcome)
  await expect(page.getByText(/原因：平台未能确认邮箱连接器状态变更结果。影响：.*下一步：/)).toHaveCount(0)
  await expect(page.getByRole('button', { name: '锁定' })).toBeFocused()
  await page.getByText('邮箱池管理', { exact: true }).click()
  await expect(committedMailboxRow.getByText('disabled')).toBeVisible()
  await expect.poll(() => mailboxListRequests).toBeGreaterThan(listsBeforeLateMailboxOutcome)

  const listsBeforeUnchangedMailboxFailure = mailboxListRequests
  await retryDisableMailbox.click()
  disableMailboxDialog = page.getByRole('dialog', { name: '确认停用邮箱 r***@example.invalid？' })
  await expect(disableMailboxDialog).toContainText('连接器 ID：mailbox-retry')
  await disableMailboxDialog.getByRole('button', { name: /停\s*用并撤\s*销会\s*话/ }).click()
  await expect(page.getByText(/原因：平台未能确认邮箱连接器状态变更结果。影响：.*下一步：/).last()).toBeVisible()
  await expect(retryMailboxRow.getByText('available')).toBeVisible()
  await expect(retryDisableMailbox).toBeEnabled()
  await expect.poll(() => mailboxListRequests).toBeGreaterThan(listsBeforeUnchangedMailboxFailure)
  expect(mailboxStateRequests.filter((item) => item.mailboxId === 'mailbox-retry')).toHaveLength(1)

  await retryDisableMailbox.click()
  disableMailboxDialog = page.getByRole('dialog', { name: '确认停用邮箱 r***@example.invalid？' })
  await disableMailboxDialog.getByRole('button', { name: /停\s*用并撤\s*销会\s*话/ }).click()
  await expect(retryMailboxRow.getByText('disabled')).toBeVisible()
  expect(mailboxStateRequests.filter((item) => item.mailboxId === 'mailbox-retry')).toHaveLength(2)

  await page.getByRole('button', { name: '登记邮箱连接器' }).click()
  let mailboxDialog = page.getByRole('dialog', { name: '登记邮箱连接器' })
  await mailboxDialog.getByLabel('密钥引用').fill('vault://secret/mailboxes/must-clear')
  await mailboxDialog.getByRole('button', { name: /取\s*消/ }).click()
  await page.getByRole('button', { name: '登记邮箱连接器' }).click()
  mailboxDialog = page.getByRole('dialog', { name: '登记邮箱连接器' })
  await expect(mailboxDialog.getByLabel('密钥引用')).toHaveValue('')
  await page.getByLabel('掩码邮箱').fill('m***@example.invalid')
  await page.getByLabel('连接器类型').fill('http')
  await mailboxDialog.getByLabel('服务端路由键').fill('account_recovery')
  await mailboxDialog.getByLabel('密钥引用').fill('vault://secret/mailboxes/managed-1')
  const confirmMailboxCreate = mailboxDialog.getByRole('button').filter({ hasText: /^登\s*记$/ })
  await confirmMailboxCreate.click()
  try {
    await expect.poll(() => mailboxCreateBodies).toHaveLength(1)
    await expect(confirmMailboxCreate).toHaveClass(/ant-btn-loading/)
    await expect(confirmMailboxCreate).toHaveClass(/ant-btn-loading/)
    await mailboxDialog.locator('form').dispatchEvent('submit')
    await mailboxDialog.locator('form').dispatchEvent('submit')
    expect(mailboxCreateBodies).toHaveLength(1)
  } finally {
    releaseMailboxCreate()
  }
  await expect(mailboxDialog).toBeVisible()
  await expect(mailboxDialog.getByLabel('服务端路由键')).toHaveValue('account_recovery')
  await expect(mailboxDialog.getByLabel('密钥引用')).toHaveValue('vault://secret/mailboxes/managed-1')
  await expect(mailboxDialog).not.toContainText('vault://secret/mailboxes/managed-1')
  await expect(confirmMailboxCreate).toBeEnabled()
  await confirmMailboxCreate.click()
  await expect(mailboxDialog).toBeHidden()
  expect(mailboxCreateBodies).toEqual([{
    email_masked: 'm***@example.invalid', connector_type: 'http',
    task_type: 'account_recovery', secret_ref: 'vault://secret/mailboxes/managed-1',
  }, {
    email_masked: 'm***@example.invalid', connector_type: 'http',
    task_type: 'account_recovery', secret_ref: 'vault://secret/mailboxes/managed-1',
  }])
  const managedMailboxRow = page.getByRole('row').filter({ hasText: 'm***@example.invalid' })
  await expect(managedMailboxRow).toBeVisible()
  await expect(managedMailboxRow.getByText('account_recovery', { exact: true })).toBeVisible()
  await expect(managedMailboxRow.getByText('正常')).toBeVisible()
  const managedDisableMailbox = managedMailboxRow.getByRole('button', {
    name: '停用邮箱 m***@example.invalid（mailbox-1）', exact: true,
  })
  const managedRotateMailbox = managedMailboxRow.getByRole('button', {
    name: '轮换邮箱密钥引用 m***@example.invalid（mailbox-1）', exact: true,
  })
  await expect(managedDisableMailbox).toHaveCount(1)
  await expect(managedRotateMailbox).toHaveCount(1)
  await managedRotateMailbox.click()
  let rotationDialog = page.getByRole('dialog', { name: '轮换邮箱密钥引用 m***@example.invalid' })
  await expect(rotationDialog.getByText('m***@example.invalid', { exact: true })).toBeVisible()
  await expect(rotationDialog.getByText('mailbox-1', { exact: true })).toBeVisible()
  const visibleRotationId = await rotationDialog.getByText('mailbox-1', { exact: true }).textContent()
  expect(visibleRotationId).toBe('mailbox-1')
  await rotationDialog.getByLabel('新密钥引用').fill('vault://secret/mailboxes/must-clear')
  await expect(rotationDialog).not.toContainText('vault://secret/mailboxes/must-clear')
  await rotationDialog.getByRole('button', { name: /取\s*消/ }).click()
  await expect(rotationDialog).toBeHidden()
  expect(mailboxRotationRequests).toEqual([])
  await managedRotateMailbox.click()
  rotationDialog = page.getByRole('dialog', { name: '轮换邮箱密钥引用 m***@example.invalid' })
  await expect(rotationDialog.getByLabel('新密钥引用')).toHaveValue('')
  await rotationDialog.getByLabel('新密钥引用').fill('vault://secret/mailboxes/managed-2')
  await expect(rotationDialog).not.toContainText('vault://secret/mailboxes/managed-2')
  const confirmRotation = rotationDialog.getByRole('button', { name: /确认\s*轮换/ })
  await confirmRotation.click()
  const stateRequestCountBeforeRotation = mailboxStateRequests.length
  try {
    await expect.poll(() => mailboxRotationRequests).toHaveLength(1)
    expect(mailboxRotationRequests[0]).toEqual({
      mailboxId: visibleRotationId,
      body: { secret_ref: 'vault://secret/mailboxes/managed-2' },
    })
    const pendingRotationButton = managedRotateMailbox
    await expect(pendingRotationButton).toBeDisabled()
    await expect(pendingRotationButton).toHaveClass(/ant-btn-loading/)
    await expect(managedDisableMailbox).toBeDisabled()
    const committedEnableMailbox = committedMailboxRow.getByRole('button', {
      name: '启用邮箱 c***@example.invalid（mailbox-committed）', exact: true,
    })
    await expect(committedEnableMailbox).toBeDisabled()
    await confirmRotation.dispatchEvent('click')
    await committedEnableMailbox.dispatchEvent('click')
    expect(mailboxRotationRequests).toHaveLength(1)
    expect(mailboxStateRequests).toHaveLength(stateRequestCountBeforeRotation)
  } finally {
    releaseCommittedRotationFailure()
  }
  await expect(page.getByText(/原因：平台未能确认邮箱密钥引用轮换结果。影响：.*下一步：/).last()).toBeVisible()
  await expect(managedMailboxRow.getByText('未检测', { exact: true })).toBeVisible()
  await expect(page.locator('body')).not.toContainText('vault://secret/mailboxes/managed-2')
  await expect(rotationDialog.getByRole('button', { name: /确认\s*轮换/ })).toBeEnabled()
  await rotationDialog.getByRole('button', { name: /确认\s*轮换/ }).click()
  await expect(rotationDialog).toBeHidden()
  expect(mailboxRotationRequests).toHaveLength(2)
})
