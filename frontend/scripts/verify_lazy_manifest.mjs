import { readFileSync, statSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

export const MAX_EAGER_APPLICATION_BYTES = 24 * 1024
export const MAX_EAGER_JAVASCRIPT_BYTES = 256 * 1024
export const MAX_EAGER_CSS_BYTES = 5 * 1024
export const MAX_DEFERRED_ADMIN_API_BYTES = 8 * 1024
export const MAX_DEFERRED_SHELL_JAVASCRIPT_BYTES = 640 * 1024
export const MAX_DEFERRED_SHELL_CSS_BYTES = 4 * 1024
export const AUTHENTICATED_SHELL_ENTRY = 'src/AuthenticatedShell.tsx'
export const ADMIN_API_CHUNK_NAME = 'admin-api'
export const OIDC_ENTRY = 'src/oidc.ts'

export const EXPECTED_VIEW_ENTRIES = [
  'src/views/DashboardView.tsx',
  'src/views/TasksView.tsx',
  'src/views/CardsView.tsx',
  'src/views/MailboxesView.tsx',
  'src/views/UploadsView.tsx',
  'src/views/UsersView.tsx',
  'src/views/AuditView.tsx',
  'src/views/PoliciesView.tsx',
]

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

function collectStaticClosure(manifest, entryKey) {
  const pending = [entryKey]
  const keys = new Set()
  while (pending.length > 0) {
    const key = pending.pop()
    if (keys.has(key)) continue
    const item = manifest[key]
    assert(item, `manifest static import is missing: ${key}`)
    keys.add(key)
    pending.push(...(item.imports ?? []))
  }
  return keys
}

function collectCssFiles(manifest, keys) {
  return new Set([...keys].flatMap((key) => manifest[key].css ?? []))
}

export function verifyLazyManifest({ manifest, html, assetBytes }) {
  const entry = manifest['index.html']
  assert(entry?.isEntry === true, 'Vite manifest is missing the index.html entry')

  const eagerKeys = collectStaticClosure(manifest, 'index.html')
  assert(
    ![...eagerKeys].some((key) => manifest[key]?.name === 'vendor'),
    'generic vendor chunk leaked unrelated dependencies into the eager closure',
  )
  const appShellKeys = [...eagerKeys].filter((key) => manifest[key]?.name === 'app-shell')
  assert(appShellKeys.length === 1, `expected one eager app-shell chunk, found ${appShellKeys.length}`)
  const authenticatedShell = manifest[AUTHENTICATED_SHELL_ENTRY]
  assert(
    authenticatedShell?.isDynamicEntry === true,
    `${AUTHENTICATED_SHELL_ENTRY} is not a dynamic entry`,
  )
  assert(
    authenticatedShell.name === 'authenticated-shell',
    `${AUTHENTICATED_SHELL_ENTRY} is not isolated in the authenticated-shell chunk`,
  )
  assert(
    typeof authenticatedShell.file === 'string' && authenticatedShell.file.endsWith('.js'),
    `${AUTHENTICATED_SHELL_ENTRY} has no JavaScript output`,
  )
  assert(!eagerKeys.has(AUTHENTICATED_SHELL_ENTRY), 'authenticated shell leaked into the eager static closure')
  assert(!html.includes(authenticatedShell.file), 'authenticated shell was eagerly referenced by index.html')
  const dynamicOwners = [...eagerKeys].filter((key) => (manifest[key].dynamicImports ?? []).length > 0)
  assert(
    dynamicOwners.length === 1 && dynamicOwners[0] === appShellKeys[0],
    `eager lazy entries must be owned only by app-shell: ${JSON.stringify(dynamicOwners)}`,
  )
  const dynamicImports = manifest[appShellKeys[0]].dynamicImports ?? []
  const expectedDynamicEntries = [AUTHENTICATED_SHELL_ENTRY, OIDC_ENTRY]
  assert(
    dynamicImports.length === expectedDynamicEntries.length
      && expectedDynamicEntries.every((key) => dynamicImports.includes(key)),
    `app-shell dynamic entries changed: ${JSON.stringify(dynamicImports)}`,
  )

  const shellDynamicImports = authenticatedShell.dynamicImports ?? []
  assert(
    shellDynamicImports.length === EXPECTED_VIEW_ENTRIES.length
      && EXPECTED_VIEW_ENTRIES.every((key) => shellDynamicImports.includes(key)),
    `authenticated-shell dynamic view entries changed: ${JSON.stringify(shellDynamicImports)}`,
  )

  const shellStaticKeys = collectStaticClosure(manifest, AUTHENTICATED_SHELL_ENTRY)
  const deferredShellKeys = [...shellStaticKeys].filter((key) => !eagerKeys.has(key))
  for (const key of deferredShellKeys) {
    assert(!html.includes(manifest[key].file), `${key} was eagerly referenced by index.html`)
  }
  const eagerCssFiles = collectCssFiles(manifest, eagerKeys)
  const shellCssFiles = collectCssFiles(manifest, shellStaticKeys)
  const leakedShellCssFiles = [...shellCssFiles].filter((file) => eagerCssFiles.has(file))
  assert(
    leakedShellCssFiles.length === 0,
    `authenticated shell stylesheet leaked into eager CSS: ${JSON.stringify(leakedShellCssFiles)}`,
  )
  const deferredShellCssFiles = [...shellCssFiles].filter((file) => !eagerCssFiles.has(file))
  assert(deferredShellCssFiles.length > 0, 'authenticated shell stylesheet is missing')
  for (const file of deferredShellCssFiles) {
    assert(!html.includes(file), `authenticated shell stylesheet was eagerly referenced by index.html: ${file}`)
  }

  const viewFiles = new Set()
  const adminApiEntries = Object.entries(manifest)
    .filter(([, item]) => item?.name === ADMIN_API_CHUNK_NAME)
  assert(adminApiEntries.length === 1, 'shared administrator API chunk is missing')
  const [adminApiKey, adminApi] = adminApiEntries[0]
  assert(
    typeof adminApi.file === 'string' && adminApi.file.endsWith('.js'),
    'shared administrator API chunk has no JavaScript output',
  )
  assert(!eagerKeys.has(adminApiKey), 'administrator API chunk leaked into the eager static closure')
  assert(!html.includes(adminApi.file), 'administrator API chunk was eagerly referenced by index.html')
  const adminApiBytes = assetBytes(adminApi.file)
  assert(
    adminApiBytes <= MAX_DEFERRED_ADMIN_API_BYTES,
    `deferred administrator API exceeds ${MAX_DEFERRED_ADMIN_API_BYTES} bytes: ${adminApiBytes}`,
  )
  for (const key of EXPECTED_VIEW_ENTRIES) {
    const view = manifest[key]
    assert(view?.isDynamicEntry === true, `${key} is not a dynamic entry`)
    assert(typeof view.file === 'string' && view.file.endsWith('.js'), `${key} has no JavaScript output`)
    assert(!eagerKeys.has(key), `${key} leaked into the eager static closure`)
    assert(!viewFiles.has(view.file), `${key} does not have a distinct view chunk`)
    assert(!html.includes(view.file), `${key} was eagerly referenced by index.html`)
    assert(
      collectStaticClosure(manifest, key).has(adminApiKey),
      `${key} does not use the shared administrator API chunk`,
    )
    viewFiles.add(view.file)
  }

  const oidc = manifest[OIDC_ENTRY]
  assert(oidc?.isDynamicEntry === true, `${OIDC_ENTRY} is not a dynamic entry`)
  assert(oidc.name === 'oidc', `${OIDC_ENTRY} is not isolated in the oidc chunk`)
  assert(typeof oidc.file === 'string' && oidc.file.endsWith('.js'), `${OIDC_ENTRY} has no JavaScript output`)
  assert(!eagerKeys.has(OIDC_ENTRY), 'OIDC runtime leaked into the eager static closure')
  assert(!viewFiles.has(oidc.file), 'OIDC runtime shares a chunk with a lazy view')
  assert(oidc.file !== authenticatedShell.file, 'OIDC runtime shares the authenticated-shell chunk')
  assert(!html.includes(oidc.file), 'OIDC runtime was eagerly referenced by index.html')

  const shared = Object.values(manifest).find((item) => item?.name === 'shared')
  assert(shared?.file, 'lazy view shared chunk is missing')
  assert(
    ![...eagerKeys].some((key) => manifest[key].file === shared.file),
    'lazy view shared chunk leaked into the eager static closure',
  )
  assert(!html.includes(shared.file), 'lazy view shared chunk was eagerly referenced by index.html')

  const applicationKeys = new Set(['index.html', ...appShellKeys])
  const applicationBytes = [...applicationKeys]
    .reduce((total, key) => total + assetBytes(manifest[key].file), 0)
  assert(
    applicationBytes <= MAX_EAGER_APPLICATION_BYTES,
    `eager application code exceeds ${MAX_EAGER_APPLICATION_BYTES} bytes: ${applicationBytes}`,
  )

  const eagerBytes = [...eagerKeys]
    .reduce((total, key) => total + assetBytes(manifest[key].file), 0)
  assert(
    eagerBytes <= MAX_EAGER_JAVASCRIPT_BYTES,
    `eager JavaScript closure exceeds ${MAX_EAGER_JAVASCRIPT_BYTES} bytes: ${eagerBytes}`,
  )

  const eagerCssBytes = [...eagerCssFiles]
    .reduce((total, file) => total + assetBytes(file), 0)
  assert(
    eagerCssBytes <= MAX_EAGER_CSS_BYTES,
    `eager CSS exceeds ${MAX_EAGER_CSS_BYTES} bytes: ${eagerCssBytes}`,
  )

  const deferredShellBytes = deferredShellKeys
    .reduce((total, key) => total + assetBytes(manifest[key].file), 0)
  assert(
    deferredShellBytes <= MAX_DEFERRED_SHELL_JAVASCRIPT_BYTES,
    `deferred authenticated shell exceeds ${MAX_DEFERRED_SHELL_JAVASCRIPT_BYTES} bytes: ${deferredShellBytes}`,
  )

  const deferredShellCssBytes = deferredShellCssFiles
    .reduce((total, file) => total + assetBytes(file), 0)
  assert(
    deferredShellCssBytes <= MAX_DEFERRED_SHELL_CSS_BYTES,
    `deferred authenticated shell CSS exceeds ${MAX_DEFERRED_SHELL_CSS_BYTES} bytes: ${deferredShellCssBytes}`,
  )

  return {
    applicationBytes,
    eagerCssBytes,
    eagerCssFiles: eagerCssFiles.size,
    eagerBytes,
    eagerChunks: eagerKeys.size,
    shellChunks: 1,
    adminApiChunks: 1,
    adminApiBytes,
    deferredShellBytes,
    deferredShellCssBytes,
    deferredShellCssFiles: deferredShellCssFiles.length,
    deferredShellChunks: deferredShellKeys.length,
    oidcChunks: 1,
    viewChunks: viewFiles.size,
  }
}

function verifyBuildOutput() {
  const scriptDirectory = dirname(fileURLToPath(import.meta.url))
  const frontendRoot = resolve(scriptDirectory, '..')
  const distRoot = resolve(frontendRoot, 'dist')
  const manifest = JSON.parse(readFileSync(resolve(distRoot, '.vite', 'manifest.json'), 'utf8'))
  const html = readFileSync(resolve(distRoot, 'index.html'), 'utf8')
  const result = verifyLazyManifest({
    manifest,
    html,
    assetBytes: (file) => statSync(resolve(distRoot, file)).size,
  })
  process.stdout.write(
    `Lazy manifest verified: ${result.viewChunks} view chunks, ${result.shellChunks} authenticated shell, `
      + `${result.adminApiChunks} deferred administrator API chunk, `
      + `${result.deferredShellChunks} deferred shell chunks, ${result.oidcChunks} lazy OIDC chunk, `
      + `${result.eagerChunks} eager chunks, `
      + `application=${result.applicationBytes} bytes, eager=${result.eagerBytes} bytes, `
      + `admin-api=${result.adminApiBytes} bytes, `
      + `eager-css=${result.eagerCssBytes} bytes/${result.eagerCssFiles} file(s), `
      + `deferred-shell=${result.deferredShellBytes} bytes, `
      + `deferred-shell-css=${result.deferredShellCssBytes} bytes/${result.deferredShellCssFiles} file(s).\n`,
  )
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : undefined
if (invokedPath === import.meta.url) verifyBuildOutput()
