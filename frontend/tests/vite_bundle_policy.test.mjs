import assert from 'node:assert/strict'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { before, test } from 'node:test'

import { loadConfigFromFile } from 'vite'

const frontendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const budgetBytes = 500 * 1024
let config
let manualChunks
let budgetPlugin

before(async () => {
  const loaded = await loadConfigFromFile(
    { command: 'build', mode: 'production' },
    path.join(frontendRoot, 'vite.config.ts'),
  )
  assert.notEqual(loaded, null)
  config = loaded.config
  manualChunks = config.build.rollupOptions.output.manualChunks
  budgetPlugin = config.plugins.find(
    (plugin) => plugin?.name === 'enforce-javascript-chunk-budget',
  )
})

test('chunk policy isolates reviewed families without merging unrelated lazy dependencies', () => {
  assert.equal(manualChunks('C:/app/node_modules/antd/es/button/index.js'), undefined)
  assert.equal(manualChunks('C:/app/node_modules/@ant-design/icons/es/index.js'), undefined)
  assert.equal(manualChunks('C:/app/node_modules/@ant-design/cssinjs/es/index.js'), undefined)
  assert.equal(manualChunks('C:/app/node_modules/rc-util/es/index.js'), 'antd-components')
  assert.equal(manualChunks('C:/app/node_modules/@rc-component/table/es/index.js'), 'antd-components')
  assert.equal(manualChunks('C:/app/node_modules/rc-table/es/index.js'), 'antd-components')
  assert.equal(manualChunks('C:/app/node_modules/react-dom/client.js'), 'react-runtime')
  assert.equal(manualChunks('C:/app/node_modules/oidc-client-ts/dist/index.js'), 'oidc')
  assert.equal(manualChunks('C:/app/node_modules/openapi-fetch/dist/index.js'), undefined)
  assert.equal(manualChunks('C:/app/node_modules/dayjs/dayjs.min.js'), undefined)
  assert.equal(manualChunks('C:/app/src/App.tsx'), 'app-shell')
  assert.equal(manualChunks('C:/app/src/api.ts'), 'app-shell')
  assert.equal(manualChunks('C:/app/src/admin-api.ts'), 'admin-api')
  assert.equal(manualChunks('C:/app/src/oidc.ts'), 'oidc')
  assert.equal(manualChunks('C:/app/src/AuthenticatedShell.tsx'), 'authenticated-shell')
  assert.equal(manualChunks('C:/app/src/views/DashboardView.tsx'), undefined)
  assert.equal(manualChunks('C:\\app\\src\\App.tsx'), 'app-shell')
  assert.equal(config.build.rollupOptions.output.onlyExplicitManualChunks, true)
})

test('javascript chunk budget accepts the exact limit and rejects one extra byte', () => {
  const hook = budgetPlugin.generateBundle
  const generateBundle = typeof hook === 'function' ? hook : hook.handler
  const context = {
    error(message) {
      throw new Error(message)
    },
  }
  const chunk = (bytes) => ({
    type: 'chunk',
    fileName: 'assets/test.js',
    code: 'x'.repeat(bytes),
  })

  assert.doesNotThrow(() => generateBundle.call(
    context,
    {},
    { 'assets/test.js': chunk(budgetBytes) },
  ))
  assert.throws(
    () => generateBundle.call(
      context,
      {},
      { 'assets/test.js': chunk(budgetBytes + 1) },
    ),
    /JavaScript chunk budget exceeded \(512000 bytes\): assets\/test\.js=512001/,
  )
})

test('non-javascript build assets do not consume the javascript budget', () => {
  const hook = budgetPlugin.generateBundle
  const generateBundle = typeof hook === 'function' ? hook : hook.handler
  assert.doesNotThrow(() => generateBundle.call(
    { error(message) { throw new Error(message) } },
    {},
    {
      'assets/large.css': {
        type: 'asset',
        fileName: 'assets/large.css',
        names: [],
        originalFileNames: [],
        needsCodeReference: false,
        source: 'x'.repeat(budgetBytes + 1),
      },
    },
  ))
})

test('administrator UI modules are rejected from the eager static closure', () => {
  const hook = budgetPlugin.generateBundle
  const generateBundle = typeof hook === 'function' ? hook : hook.handler
  const context = { error(message) { throw new Error(message) } }
  const entry = {
    type: 'chunk',
    fileName: 'assets/index.js',
    code: '',
    isEntry: true,
    imports: ['assets/ui.js'],
    modules: {},
  }
  const ui = {
    type: 'chunk',
    fileName: 'assets/ui.js',
    code: '',
    isEntry: false,
    imports: [],
    modules: { 'C:/app/node_modules/antd/es/button/index.js': {} },
  }

  assert.throws(
    () => generateBundle.call(context, {}, { 'assets/index.js': entry, 'assets/ui.js': ui }),
    /Administrator UI runtime leaked into eager JavaScript: assets\/ui\.js/,
  )
  entry.imports = []
  assert.doesNotThrow(
    () => generateBundle.call(context, {}, { 'assets/index.js': entry, 'assets/ui.js': ui }),
  )
})
