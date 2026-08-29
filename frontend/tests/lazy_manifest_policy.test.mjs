import assert from 'node:assert/strict'
import test from 'node:test'

import {
  AUTHENTICATED_SHELL_ENTRY,
  EXPECTED_VIEW_ENTRIES,
  OIDC_ENTRY,
  MAX_DEFERRED_SHELL_CSS_BYTES,
  MAX_DEFERRED_SHELL_JAVASCRIPT_BYTES,
  MAX_DEFERRED_ADMIN_API_BYTES,
  MAX_EAGER_CSS_BYTES,
  MAX_EAGER_APPLICATION_BYTES,
  MAX_EAGER_JAVASCRIPT_BYTES,
  verifyLazyManifest,
} from '../scripts/verify_lazy_manifest.mjs'

function fixture() {
  const manifest = {
    'index.html': {
      file: 'assets/index.js',
      isEntry: true,
      imports: ['_app-shell.js', '_openapi-fetch.js'],
      css: ['assets/login.css'],
    },
    '_app-shell.js': {
      file: 'assets/app-shell.js',
      name: 'app-shell',
      dynamicImports: [AUTHENTICATED_SHELL_ENTRY, OIDC_ENTRY],
    },
    '_openapi-fetch.js': { file: 'assets/openapi-fetch.js', name: 'openapi-fetch' },
    '_admin-api.js': { file: 'assets/admin-api.js', name: 'admin-api' },
    '_shared.js': { file: 'assets/shared.js', name: 'shared' },
    '_shell-ui.js': { file: 'assets/shell-ui.js', name: 'shell-ui' },
  }
  EXPECTED_VIEW_ENTRIES.forEach((key, index) => {
    manifest[key] = {
      file: `assets/view-${index}.js`,
      isDynamicEntry: true,
      imports: ['_admin-api.js'],
    }
  })
  manifest[OIDC_ENTRY] = {
    file: 'assets/oidc.js',
    isDynamicEntry: true,
    name: 'oidc',
  }
  manifest[AUTHENTICATED_SHELL_ENTRY] = {
    file: 'assets/authenticated-shell.js',
    isDynamicEntry: true,
    name: 'authenticated-shell',
    css: ['assets/authenticated-shell.css'],
    imports: ['_shell-ui.js'],
    dynamicImports: [...EXPECTED_VIEW_ENTRIES],
  }
  return {
    manifest,
    html: '<script type="module" src="/assets/index.js"></script>',
    assetBytes: (file) => file.endsWith('.css')
      || file === 'assets/openapi-fetch.js'
      || file === 'assets/admin-api.js'
      ? 1
      : MAX_EAGER_APPLICATION_BYTES / 2,
  }
}

test('accepts eight lazy views and a lazy OIDC runtime at the exact application budget', () => {
  assert.deepEqual(verifyLazyManifest(fixture()), {
    applicationBytes: MAX_EAGER_APPLICATION_BYTES,
    eagerCssBytes: 1,
    eagerCssFiles: 1,
    eagerBytes: MAX_EAGER_APPLICATION_BYTES + 1,
    eagerChunks: 3,
    shellChunks: 1,
    adminApiChunks: 1,
    adminApiBytes: 1,
    deferredShellBytes: MAX_EAGER_APPLICATION_BYTES,
    deferredShellCssBytes: 1,
    deferredShellCssFiles: 1,
    deferredShellChunks: 2,
    oidcChunks: 1,
    viewChunks: 8,
  })
})

test('rejects a missing view dynamic entry', () => {
  const value = fixture()
  value.manifest[AUTHENTICATED_SHELL_ENTRY].dynamicImports.pop()
  assert.throws(() => verifyLazyManifest(value), /authenticated-shell dynamic view entries changed/)
})

test('rejects a missing OIDC dynamic entry', () => {
  const value = fixture()
  value.manifest['_app-shell.js'].dynamicImports = value.manifest['_app-shell.js'].dynamicImports
    .filter((key) => key !== OIDC_ENTRY)
  assert.throws(() => verifyLazyManifest(value), /app-shell dynamic entries changed/)
})

test('rejects a missing authenticated shell dynamic entry', () => {
  const value = fixture()
  value.manifest['_app-shell.js'].dynamicImports = value.manifest['_app-shell.js'].dynamicImports
    .filter((key) => key !== AUTHENTICATED_SHELL_ENTRY)
  assert.throws(() => verifyLazyManifest(value), /app-shell dynamic entries changed/)
})

test('rejects an OIDC runtime referenced eagerly by the generated HTML', () => {
  const value = fixture()
  value.html += '<link rel="modulepreload" href="/assets/oidc.js">'
  assert.throws(() => verifyLazyManifest(value), /OIDC runtime was eagerly referenced by index\.html/)
})

test('rejects an OIDC runtime leaked into the static closure', () => {
  const value = fixture()
  value.manifest['index.html'].imports.push(OIDC_ENTRY)
  assert.throws(() => verifyLazyManifest(value), /OIDC runtime leaked into the eager static closure/)
})

test('rejects an authenticated shell leaked into the static closure', () => {
  const value = fixture()
  value.manifest['index.html'].imports.push(AUTHENTICATED_SHELL_ENTRY)
  assert.throws(() => verifyLazyManifest(value), /authenticated shell leaked into the eager static closure/)
})

test('rejects an authenticated shell referenced eagerly by the generated HTML', () => {
  const value = fixture()
  value.html += '<link rel="modulepreload" href="/assets/authenticated-shell.js">'
  assert.throws(() => verifyLazyManifest(value), /authenticated shell was eagerly referenced by index\.html/)
})

test('rejects a missing authenticated shell stylesheet', () => {
  const value = fixture()
  delete value.manifest[AUTHENTICATED_SHELL_ENTRY].css
  assert.throws(
    () => verifyLazyManifest(value),
    /authenticated shell stylesheet is missing/,
  )
})

test('rejects an authenticated shell stylesheet leaked into the eager entry', () => {
  const value = fixture()
  value.manifest['index.html'].css.push('assets/authenticated-shell.css')
  assert.throws(
    () => verifyLazyManifest(value),
    /authenticated shell stylesheet leaked into eager CSS/,
  )
})

test('rejects eager CSS one byte over 5 KiB', () => {
  const value = fixture()
  value.assetBytes = (file) => file === 'assets/login.css' ? MAX_EAGER_CSS_BYTES + 1 : 0
  assert.throws(
    () => verifyLazyManifest(value),
    /eager CSS exceeds 5120 bytes: 5121/,
  )
})

test('rejects deferred authenticated shell CSS one byte over 4 KiB', () => {
  const value = fixture()
  value.assetBytes = (file) => file === 'assets/authenticated-shell.css'
    ? MAX_DEFERRED_SHELL_CSS_BYTES + 1
    : 0
  assert.throws(
    () => verifyLazyManifest(value),
    /deferred authenticated shell CSS exceeds 4096 bytes: 4097/,
  )
})

test('rejects a generic eager vendor chunk that can absorb lazy dependencies', () => {
  const value = fixture()
  value.manifest['_openapi-fetch.js'].name = 'vendor'
  assert.throws(
    () => verifyLazyManifest(value),
    /generic vendor chunk leaked unrelated dependencies into the eager closure/,
  )
})

test('rejects a missing shared administrator API chunk', () => {
  const value = fixture()
  delete value.manifest['_admin-api.js']
  for (const key of EXPECTED_VIEW_ENTRIES) value.manifest[key].imports = []
  assert.throws(
    () => verifyLazyManifest(value),
    /shared administrator API chunk is missing/,
  )
})

test('rejects the administrator API chunk leaked into the eager closure', () => {
  const value = fixture()
  value.manifest['index.html'].imports.push('_admin-api.js')
  assert.throws(
    () => verifyLazyManifest(value),
    /administrator API chunk leaked into the eager static closure/,
  )
})

test('rejects the deferred administrator API chunk one byte over 8 KiB', () => {
  const value = fixture()
  value.assetBytes = (file) => file === 'assets/admin-api.js' ? MAX_DEFERRED_ADMIN_API_BYTES + 1 : 0
  assert.throws(
    () => verifyLazyManifest(value),
    /deferred administrator API exceeds 8192 bytes: 8193/,
  )
})

test('rejects a deferred authenticated shell one byte over budget', () => {
  const value = fixture()
  value.assetBytes = (file) => file === 'assets/authenticated-shell.js'
    ? MAX_DEFERRED_SHELL_JAVASCRIPT_BYTES
    : file === 'assets/shell-ui.js' ? 1 : 0
  assert.throws(() => verifyLazyManifest(value), /deferred authenticated shell exceeds 655360 bytes: 655361/)
})

test('rejects a view chunk referenced eagerly by the generated HTML', () => {
  const value = fixture()
  value.html += '<link rel="modulepreload" href="/assets/view-0.js">'
  assert.throws(() => verifyLazyManifest(value), /was eagerly referenced by index\.html/)
})

test('rejects an application entry one byte over budget', () => {
  const value = fixture()
  value.assetBytes = (file) => file === 'assets/app-shell.js'
    ? MAX_EAGER_APPLICATION_BYTES / 2 + 1
    : file === 'assets/index.js' ? MAX_EAGER_APPLICATION_BYTES / 2 : 0
  assert.throws(() => verifyLazyManifest(value), /eager application code exceeds 24576 bytes: 24577/)
})

test('rejects an eager closure one byte over 256 KiB', () => {
  const value = fixture()
  value.assetBytes = (file) => file === 'assets/openapi-fetch.js'
    ? MAX_EAGER_JAVASCRIPT_BYTES
    : file.startsWith('assets/view-') || file === 'assets/shared.js' ? 0 : 1
  assert.throws(
    () => verifyLazyManifest(value),
    /eager JavaScript closure exceeds 262144 bytes: 262146/,
  )
})
