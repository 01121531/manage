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
