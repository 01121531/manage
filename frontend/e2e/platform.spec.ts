import { expect, test } from '@playwright/test'


test('operator login keeps bearer in memory and exposes task trace', async ({ page }) => {
  const accessValue = ['fixture', 'access', 'value'].join('-')
  const taskTrace = '00000000-0000-0000-0000-000000000042'
  const protectedPaths: string[] = []

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
    if (path === '/api/v1/tasks') {
      expect(url.searchParams.get('limit')).toBe('50')
      return fulfill([{
        id: 'task-1', tenant_id: 'tenant-1', user_id: 'user-1',
        device_id: 'device-1', type: 'mail_code', idempotency_key: 'request-1',
        client_reference: null, trace_id: taskTrace, status: 'created',
        expires_at: '2026-08-20T01:00:00Z', closed_at: null,
        created_at: '2026-08-20T00:00:00Z',
      }])
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
  await page.getByText('任务中心', { exact: true }).click()
  await expect(page.getByText(taskTrace).first()).toBeVisible()

  const browserStorage = await page.evaluate(() => ({
    local: Object.values(localStorage),
    session: Object.values(sessionStorage),
  }))
  expect(JSON.stringify(browserStorage)).not.toContain(accessValue)
  expect(protectedPaths).toContain('/api/v1/me')
  expect(protectedPaths).toContain('/api/v1/tasks')
})

test('security auditor filters and downloads redacted audit evidence', async ({ page }) => {
  const accessValue = 'audit-memory-access'
  const auditTrace = '00000000-0000-0000-0000-000000000077'
  const listQueries: URLSearchParams[] = []
  const exportQueries: URLSearchParams[] = []

  await page.addInitScript(() => {
    const trackedWindow = window as typeof window & { __auditRevokeCount?: number }
    trackedWindow.__auditRevokeCount = 0
    const revoke = URL.revokeObjectURL.bind(URL)
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
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('auditor@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('audit-device')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('审计中心', { exact: true }).click()

  await expect(page.getByText('upload.reconcile')).toBeVisible()
  await expect(page.getByText('policy-v7')).toBeVisible()
  await expect(page.locator('body')).not.toContainText('must-never-render')

  await page.getByLabel('操作者').fill('actor-1')
  await page.getByLabel('关联用户').fill('subject-1')
  await page.getByLabel('对象类型').fill('upload_job')
  await page.getByLabel('对象 ID').fill('upload-1')
  await page.getByLabel('事件类型').fill('upload_review')
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
    result: 'success',
    trace_id: auditTrace,
    created_from: '2026-08-19T08:00',
    created_to: '2026-08-20T08:00',
    limit: '200',
  })

  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: /导出脱敏 CSV/ }).click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toMatch(/^audit-redacted-.*\.csv$/)
  await expect.poll(() => exportQueries.length).toBe(1)
  expect(Object.fromEntries(exportQueries[0])).toMatchObject({
    actor_id: 'actor-1', result: 'success', entity_type: 'upload_job', limit: '5000',
  })
  await expect.poll(() => page.evaluate(() => (
    window as typeof window & { __auditRevokeCount?: number }
  ).__auditRevokeCount ?? 0)).toBe(1)

  const browserStorage = await page.evaluate(() => ({
    local: Object.values(localStorage),
    session: Object.values(sessionStorage),
  }))
  expect(JSON.stringify(browserStorage)).not.toContain(accessValue)
})

test('platform admin governs upload policies without browser execution details', async ({ page }) => {
  const accessValue = ['admin', 'access', 'value'].join('-')
  const traceId = '00000000-0000-0000-0000-000000000099'
  let versions = [{
    id: 'policy-draft-1', version: 'sub2-2026.08.1', status: 'draft',
    change_note: '待独立审批', created_by: 'user-2', approved_by: null,
    approved_at: null, created_at: '2026-08-20T00:00:00Z',
  }]

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
      return fulfill({
        policy_version: 'sub2-2026.07.1', status: 'ready', server_managed: true,
        upload_endpoint_configured: true, upload_secret_configured: true,
        network_route_configured: true, governance_configured: true,
        active_version: 'sub2-2026.07.1', previous_version: null, rollout_percent: 100,
      })
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
    return fulfill({ error: { code: 'not_found', message: 'not found' } }, 404)
  })

  await page.goto('/')
  await page.getByLabel('租户').fill('tenant-1')
  await page.getByLabel('平台账号').fill('admin@example.invalid')
  await page.getByLabel('平台密码').fill('development-password')
  await page.getByLabel('设备标识').fill('device-admin')
  await page.getByRole('button', { name: '安全登录' }).click()
  await page.getByText('策略配置', { exact: true }).click()

  await expect(page.getByText(/独立审批/).first()).toBeVisible()
  await expect(page.getByText('sub2-2026.08.1')).toBeVisible()
  await expect(page.getByRole('button', { name: /审\s*批/ })).toBeEnabled()
  await page.getByPlaceholder('例如 sub2-2026.08.1').fill('sub2-2026.09.1')
  await page.getByPlaceholder('变更说明').fill('九月灰度版本')
  await page.getByRole('button', { name: '登记快照' }).click()
  await expect(page.getByText('sub2-2026.09.1')).toBeVisible()
  await expect(page.locator('body')).not.toContainText('vault://')

  const browserStorage = await page.evaluate(() => ({
    local: Object.values(localStorage),
    session: Object.values(sessionStorage),
  }))
  expect(JSON.stringify(browserStorage)).not.toContain(accessValue)
})

test('ops admin safely manages card and mailbox references', async ({ page }) => {
  const accessValue = 'ops-resource-access'
  let cards: Array<Record<string, unknown>> = []
  let mailboxes: Array<Record<string, unknown>> = []

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
    if (path === '/api/v1/admin/cards' && request.method() === 'GET') return fulfill(cards)
    if (path === '/api/v1/admin/cards' && request.method() === 'POST') {
      const body = request.postDataJSON() as Record<string, unknown>
      expect(Object.keys(body).sort()).toEqual(['brand', 'last4', 'provider_ref', 'secret_ref'])
      expect(body).not.toHaveProperty('pan')
      expect(body).not.toHaveProperty('cvv')
      cards = [{
        id: 'card-1', tenant_id: 'tenant-1', provider_ref: body.provider_ref,
        brand: body.brand, last4: body.last4, expiry_month: null, expiry_year: null,
        is_active: true, created_at: '2026-08-20T00:00:00Z',
      }]
      return fulfill(cards[0], 201)
    }
    if (path === '/api/v1/admin/cards/card-1' && request.method() === 'PATCH') {
      expect(request.postDataJSON()).toEqual({ is_active: false })
      expect(JSON.stringify(request.postDataJSON())).not.toContain('secret')
      cards = [{ ...cards[0], is_active: false }]
      return fulfill(cards[0])
    }
    if (path === '/api/v1/mailboxes' && request.method() === 'GET') return fulfill(mailboxes)
    if (path === '/api/v1/admin/mailboxes' && request.method() === 'POST') {
      const body = request.postDataJSON() as Record<string, unknown>
      expect(Object.keys(body).sort()).toEqual(['connector_type', 'email_masked', 'secret_ref'])
      mailboxes = [{
        id: 'mailbox-1', email_masked: body.email_masked,
        connector_type: body.connector_type, is_active: true, status: 'available',
        active_session_count: 0, created_at: '2026-08-20T00:00:00Z',
      }]
      return fulfill(mailboxes[0], 201)
    }
    if (path === '/api/v1/admin/mailboxes/mailbox-1/secret-rotations') {
      expect(Object.keys(request.postDataJSON())).toEqual(['secret_ref'])
      return fulfill(mailboxes[0])
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
  await page.getByRole('button', { name: '登记卡资源' }).click()
  let cardDialog = page.getByRole('dialog', { name: '登记卡资源' })
  await cardDialog.getByLabel('密钥引用').fill('vault://secret/cards/must-clear')
  await cardDialog.getByRole('button', { name: /取\s*消/ }).click()
  await page.getByRole('button', { name: '登记卡资源' }).click()
  cardDialog = page.getByRole('dialog', { name: '登记卡资源' })
  await expect(cardDialog.getByLabel('密钥引用')).toHaveValue('')
  await page.getByLabel('提供方引用').fill('provider-safe-1')
  await page.getByLabel('品牌').fill('VISA')
  await page.getByLabel('尾号').fill('4242')
  await page.getByLabel('密钥引用').fill('vault://secret/cards/provider-safe-1')
  await cardDialog.getByRole('button', { name: /^登\s*记$/ }).click()
  await expect(page.getByText('•••• 4242')).toBeVisible()
  await expect(page.locator('body')).not.toContainText('vault://secret/cards/provider-safe-1')
  await page.getByRole('button', { name: /停\s*用/ }).click()
  const disableDialog = page.getByRole('dialog', { name: '确认停用该卡资源？' })
  await disableDialog.getByRole('button', { name: /停\s*用并释\s*放/ }).click()
  await expect(page.getByText('disabled')).toBeVisible()

  await page.getByText('邮箱连接器', { exact: true }).click()
  await page.getByRole('button', { name: '登记邮箱连接器' }).click()
  let mailboxDialog = page.getByRole('dialog', { name: '登记邮箱连接器' })
  await mailboxDialog.getByLabel('密钥引用').fill('vault://secret/mailboxes/must-clear')
  await mailboxDialog.getByRole('button', { name: /取\s*消/ }).click()
  await page.getByRole('button', { name: '登记邮箱连接器' }).click()
  mailboxDialog = page.getByRole('dialog', { name: '登记邮箱连接器' })
  await expect(mailboxDialog.getByLabel('密钥引用')).toHaveValue('')
  await page.getByLabel('掩码邮箱').fill('m***@example.invalid')
  await page.getByLabel('连接器类型').fill('http')
  await page.getByLabel('密钥引用').fill('vault://secret/mailboxes/managed-1')
  await mailboxDialog.getByRole('button', { name: /^登\s*记$/ }).click()
  await expect(page.getByText('m***@example.invalid')).toBeVisible()
  await page.getByRole('button', { name: '轮换密钥引用' }).click()
  let rotationDialog = page.getByRole('dialog', { name: '轮换密钥引用' })
  await rotationDialog.getByLabel('新密钥引用').fill('vault://secret/mailboxes/must-clear')
  await rotationDialog.getByRole('button', { name: /取\s*消/ }).click()
  await page.getByRole('button', { name: '轮换密钥引用' }).click()
  rotationDialog = page.getByRole('dialog', { name: '轮换密钥引用' })
  await expect(rotationDialog.getByLabel('新密钥引用')).toHaveValue('')
  await rotationDialog.getByLabel('新密钥引用').fill('vault://secret/mailboxes/managed-2')
  await rotationDialog.getByRole('button', { name: /确认\s*轮换/ }).click()
  await expect(page.locator('body')).not.toContainText('vault://secret/mailboxes/managed-2')
})
