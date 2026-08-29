import assert from 'node:assert/strict'
import { after, before, beforeEach, test } from 'node:test'

process.env.VITE_API_BASE_URL = 'http://platform.test'

const windowEvents = new EventTarget()
windowEvents.setTimeout = setTimeout
windowEvents.clearTimeout = clearTimeout
globalThis.window = windowEvents

let api
let adminApi
let vite
let fetchHandler
globalThis.fetch = (input, init) => fetchHandler(input, init)

const jsonResponse = (value, status = 200) => new Response(JSON.stringify(value), {
  status,
  headers: { 'content-type': 'application/json' },
})

async function waitFor(check) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (check()) return
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
  assert.fail('condition was not reached')
}

function assertStaleSessionResponse(error) {
  assert.equal(error instanceof api.ApiError, true)
  assert.equal(error.status, 409)
  assert.equal(error.code, 'stale_session_response')
  assert.match(error.message, /原因：/)
  assert.match(error.message, /影响：/)
  assert.match(error.message, /下一步：/)
  assert.doesNotMatch(error.message, /user-A|tenant-A|bearer-A|raw/i)
  return true
}

before(async () => {
  const { createServer } = await import('vite')
  vite = await createServer({
    server: { middlewareMode: true },
    appType: 'custom',
    logLevel: 'silent',
    define: {
      'import.meta.env.VITE_API_BASE_URL': JSON.stringify('http://platform.test'),
    },
  })
  api = await vite.ssrLoadModule('/src/api.ts')
  adminApi = await vite.ssrLoadModule('/src/admin-api.ts')
})

beforeEach(() => {
  api.clearSession()
  fetchHandler = () => Promise.reject(new Error('unexpected request'))
})

after(async () => {
  api.clearSession()
  await vite.close()
})

test('a stale 401 cannot clear the bearer from a newer session generation', async () => {
  let releaseOldRequest
  const oldRequestGate = new Promise((resolve) => { releaseOldRequest = resolve })
  const authorizations = []
  let requestCount = 0

  fetchHandler = async (input) => {
    const request = input instanceof Request ? input : new Request(input)
    authorizations.push(request.headers.get('authorization') ?? '')
    requestCount += 1
    if (requestCount === 1) {
      await oldRequestGate
      return jsonResponse({ error: { code: 'unauthorized' } }, 401)
    }
    return jsonResponse({
      id: 'new-user',
      tenant_id: 'tenant-1',
      email: 'new@example.invalid',
      device_id: 'new-device',
      role: 'operator',
    })
  }

  api.setBearer('generation-a', 60)
  const staleRequest = api.getMe().catch(() => undefined)
  await waitFor(() => requestCount === 1)

  api.setBearer('generation-b', 60)
  releaseOldRequest()
  await staleRequest
  await api.getMe()

  assert.equal(api.getSessionRemainingSeconds() > 0, true)
  assert.equal(authorizations[1], 'Bearer generation-b')
})

test('a stale successful response is rejected after logout and bearer replacement', async () => {
  let releaseOldRequest
  const oldRequestGate = new Promise((resolve) => { releaseOldRequest = resolve })
  const authorizations = []
  let oldRequestStarted = false

  fetchHandler = async (input) => {
    const request = input instanceof Request ? input : new Request(input)
    const path = new URL(request.url).pathname
    const authorization = request.headers.get('authorization') ?? ''
    authorizations.push({ path, authorization })
    if (path === '/api/v1/me' && authorization === 'Bearer bearer-A') {
      oldRequestStarted = true
      await oldRequestGate
      return jsonResponse({
        id: 'user-A',
        tenant_id: 'tenant-A',
        email: 'a@example.invalid',
        device_id: 'device-A',
        role: 'operator',
      })
    }
    if (path === '/api/v1/auth/logout') return jsonResponse({ status: 'logged_out' })
    if (path === '/api/v1/me' && authorization === 'Bearer bearer-B') {
      return jsonResponse({
        id: 'user-B',
        tenant_id: 'tenant-B',
        email: 'b@example.invalid',
        device_id: 'device-B',
        role: 'operator',
      })
    }
    throw new Error(`unexpected request ${path}`)
  }

  api.setBearer('bearer-A', 60)
  const staleRequest = api.getMe()
  await waitFor(() => oldRequestStarted)
  await api.logoutSession()
  api.clearSession()
  api.setBearer('bearer-B', 60)
  releaseOldRequest()

  await assert.rejects(staleRequest, assertStaleSessionResponse)
  const current = await api.getMe()
  assert.equal(current.id, 'user-B')
  assert.equal(authorizations.at(-1).authorization, 'Bearer bearer-B')
})

test('a stale audit export is rejected before creating a download', async () => {
  let releaseOldExport
  const oldExportGate = new Promise((resolve) => { releaseOldExport = resolve })
  const authorizations = []
  let oldExportStarted = false
  let blobUrls = 0
  let appendedLinks = 0
  let clicks = 0
  const originalDocument = globalThis.document
  const originalCreateObjectURL = URL.createObjectURL
  const originalRevokeObjectURL = URL.revokeObjectURL
  globalThis.document = {
    body: { appendChild: () => { appendedLinks += 1 } },
    createElement: () => ({
      click: () => { clicks += 1 },
      remove: () => undefined,
    }),
  }
  URL.createObjectURL = () => {
    blobUrls += 1
    return 'blob:stale-audit'
  }
  URL.revokeObjectURL = () => undefined

  fetchHandler = async (input) => {
    const request = input instanceof Request ? input : new Request(input)
    const path = new URL(request.url).pathname
    const authorization = request.headers.get('authorization') ?? ''
    authorizations.push({ path, authorization })
    if (path === '/api/v1/admin/audit/export') {
      oldExportStarted = true
      await oldExportGate
      return new Response('tenant-A,user-A,raw audit row', {
        status: 200,
        headers: { 'content-type': 'text/csv' },
      })
    }
    if (path === '/api/v1/auth/logout') return jsonResponse({ status: 'logged_out' })
    if (path === '/api/v1/me') {
      return jsonResponse({
        id: 'user-B',
        tenant_id: 'tenant-B',
        email: 'b@example.invalid',
        device_id: 'device-B',
        role: 'operator',
      })
    }
    throw new Error(`unexpected request ${path}`)
  }

  try {
    api.setBearer('bearer-A', 60)
    const staleExport = adminApi.downloadAuditEvents()
    await waitFor(() => oldExportStarted)
    await api.logoutSession()
    api.clearSession()
    api.setBearer('bearer-B', 60)
    releaseOldExport()

    await assert.rejects(staleExport, assertStaleSessionResponse)
    assert.deepEqual({ blobUrls, appendedLinks, clicks }, {
      blobUrls: 0,
      appendedLinks: 0,
      clicks: 0,
    })
    await api.getMe()
    assert.equal(authorizations.at(-1).authorization, 'Bearer bearer-B')
  } finally {
    releaseOldExport()
    if (originalDocument === undefined) delete globalThis.document
    else globalThis.document = originalDocument
    URL.createObjectURL = originalCreateObjectURL
    URL.revokeObjectURL = originalRevokeObjectURL
  }
})

test('logout single-flight is isolated to the bearer generation that started it', async () => {
  let releaseOldLogout
  const oldLogoutGate = new Promise((resolve) => { releaseOldLogout = resolve })
  const authorizations = []

  fetchHandler = async (input) => {
    const request = input instanceof Request ? input : new Request(input)
    const authorization = request.headers.get('authorization') ?? ''
    authorizations.push(authorization)
    if (authorization === 'Bearer generation-a') await oldLogoutGate
    return jsonResponse({ status: 'logged_out' })
  }

  api.setBearer('generation-a', 60)
  const oldLogout = api.logoutSession()
  await waitFor(() => authorizations.length === 1)

  api.setBearer('generation-b', 60)
  const newLogout = api.logoutSession()
  try {
    await waitFor(() => authorizations.length === 2)
  } finally {
    releaseOldLogout()
  }
  await Promise.all([oldLogout, newLogout])

  assert.deepEqual(authorizations, [
    'Bearer generation-a',
    'Bearer generation-b',
  ])
})

test('session exit blocks same-generation requests without blocking or clearing a replacement generation', async () => {
  let releaseLogoutA
  let releaseLogoutB
  const logoutGateA = new Promise((resolve) => { releaseLogoutA = resolve })
  const logoutGateB = new Promise((resolve) => { releaseLogoutB = resolve })
  const requests = []

  fetchHandler = async (input) => {
    const request = input instanceof Request ? input : new Request(input)
    const path = new URL(request.url).pathname
    const authorization = request.headers.get('authorization') ?? ''
    requests.push({ path, authorization })
    if (path === '/api/v1/auth/logout') {
      if (authorization === 'Bearer generation-a') await logoutGateA
      if (authorization === 'Bearer generation-b') await logoutGateB
      return jsonResponse({ status: 'logged_out' })
    }
    return jsonResponse({ id: path.split('/').at(-2), status: 'closed' })
  }

  const assertExitBlocked = async (operation) => {
    await assert.rejects(operation, (error) => {
      assert.equal(error instanceof api.ApiError, true)
      assert.match(error.message, /原因：/)
      assert.match(error.message, /影响：/)
      assert.match(error.message, /下一步：/)
      assert.doesNotMatch(error.message, /internal|raw|generation-a|generation-b/i)
      return true
    })
  }

  api.setBearer('generation-a', 60)
  const logoutA = api.logoutSession()
  await waitFor(() => requests.length === 1)
  try {
    await assertExitBlocked(adminApi.closeTask('blocked-task-a'))
    assert.equal(requests.length, 1)

    api.setBearer('generation-b', 60)
    await adminApi.closeTask('allowed-task-b')
    assert.deepEqual(requests.at(-1), {
      path: '/api/v1/tasks/allowed-task-b/close',
      authorization: 'Bearer generation-b',
    })

    const logoutB = api.logoutSession()
    await waitFor(() => requests.filter(({ path }) => path === '/api/v1/auth/logout').length === 2)
    releaseLogoutA()
    await logoutA

    await assertExitBlocked(adminApi.closeTask('blocked-task-b'))
    assert.equal(requests.some(({ path }) => path.includes('blocked-task-b')), false)

    releaseLogoutB()
    await logoutB
    await adminApi.closeTask('allowed-after-b-exit')
    assert.equal(requests.at(-1).path, '/api/v1/tasks/allowed-after-b-exit/close')
  } finally {
    releaseLogoutA()
    releaseLogoutB()
    await logoutA.catch(() => undefined)
  }
})

test('failed or unauthorized logout releases the barrier for a safe retry', async () => {
  for (const [status, code] of [[503, 'service_unavailable'], [401, 'unauthorized']]) {
    const requests = []
    let logoutAttempts = 0
    fetchHandler = async (input) => {
      const request = input instanceof Request ? input : new Request(input)
      const path = new URL(request.url).pathname
      requests.push(path)
      if (path === '/api/v1/auth/logout') {
        logoutAttempts += 1
        if (logoutAttempts === 1) return jsonResponse({ error: { code, message: 'raw internal failure' } }, status)
        return jsonResponse({ status: 'logged_out' })
      }
      return jsonResponse({ id: 'task-retry', status: 'closed' })
    }

    api.setBearer(`failure-${status}`, 60)
    await assert.rejects(api.logoutSession(), api.ApiError)
    if (status === 401) api.setBearer('recovered-after-401', 60)
    await adminApi.closeTask(`retry-after-${status}`)
    await api.logoutSession()

    assert.deepEqual(requests, [
      '/api/v1/auth/logout',
      `/api/v1/tasks/retry-after-${status}/close`,
      '/api/v1/auth/logout',
    ])
    api.clearSession()
  }
})

test('owned-device revoke uses the generated owner path and current bearer', async () => {
  const requests = []
  fetchHandler = async (input) => {
    const request = input instanceof Request ? input : new Request(input)
    requests.push({
      method: request.method,
      path: new URL(request.url).pathname,
      authorization: request.headers.get('authorization'),
    })
    return jsonResponse({
      id: 'device-owned',
      tenant_id: 'tenant-1',
      user_id: 'user-1',
      name: 'owned-device',
      last_seen_at: '2026-08-20T00:00:00Z',
      revoked_at: '2026-08-20T00:01:00Z',
      created_at: '2026-08-19T00:00:00Z',
    })
  }

  api.setBearer('owned-device-bearer', 60)
  const result = await api.revokeCurrentDevice('device-owned')

  assert.equal(result.id, 'device-owned')
  assert.deepEqual(requests, [{
    method: 'POST',
    path: '/api/v1/devices/device-owned/revoke',
    authorization: 'Bearer owned-device-bearer',
  }])
})
