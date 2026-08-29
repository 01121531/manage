import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import type { OutputChunk } from 'rollup'

export const MAX_JAVASCRIPT_CHUNK_BYTES = 500 * 1024

export function vendorChunk(id: string): string | undefined {
  const normalized = id.split('\\').join('/')
  const has = (fragment: string) => normalized.indexOf(fragment) !== -1
  if (
    normalized.slice(-12) === '/src/App.tsx'
    || normalized.slice(-11) === '/src/api.ts'
  ) return 'app-shell'
  if (normalized.slice(-17) === '/src/admin-api.ts') return 'admin-api'
  if (normalized.slice(-12) === '/src/oidc.ts') return 'oidc'
  if (normalized.slice(-27) === '/src/AuthenticatedShell.tsx') return 'authenticated-shell'
  if (!has('/node_modules/')) return undefined
  if (
    has('/node_modules/react/')
    || has('/node_modules/react-dom/')
    || has('/node_modules/react-router')
    || has('/node_modules/scheduler/')
  ) return 'react-runtime'
  if (has('/node_modules/oidc-client-ts/')) return 'oidc'
  const isAntDesignRuntime = (
    has('/node_modules/@rc-component/')
    || has('/node_modules/rc-')
    || has('/node_modules/@ant-design/')
    || has('/node_modules/antd/')
  )
  if (isAntDesignRuntime) {
    if (has('/node_modules/@rc-component/') || has('/node_modules/rc-')) return 'antd-components'
    return undefined
  }
  return undefined
}

function enforceChunkBudget(): Plugin {
  return {
    name: 'enforce-javascript-chunk-budget',
    generateBundle(_options, bundle) {
      const oversized: Array<{ name: string, bytes: number }> = []
      for (const fileName in bundle) {
        const output = bundle[fileName]
        if (output.type !== 'chunk') continue
        const bytes = new TextEncoder().encode(output.code).byteLength
        if (bytes > MAX_JAVASCRIPT_CHUNK_BYTES) {
          oversized.push({ name: output.fileName, bytes })
        }
      }
      oversized.sort((left, right) => right.bytes - left.bytes)
      if (oversized.length > 0) {
        const summary = oversized
          .map((output) => `${output.name}=${output.bytes}`)
          .join(', ')
        this.error(
          `JavaScript chunk budget exceeded (${MAX_JAVASCRIPT_CHUNK_BYTES} bytes): ${summary}`,
        )
      }

      const chunks: Record<string, OutputChunk> = {}
      const pending: string[] = []
      for (const fileName in bundle) {
        const output = bundle[fileName]
        if (output.type !== 'chunk') continue
        chunks[output.fileName] = output
        if (output.isEntry) pending.push(output.fileName)
      }
      const eagerFiles: Record<string, true> = {}
      const eagerOrder: string[] = []
      while (pending.length > 0) {
        const fileName = pending.pop()
        if (!fileName || eagerFiles[fileName]) continue
        const chunk = chunks[fileName]
        if (!chunk) continue
        eagerFiles[fileName] = true
        eagerOrder.push(fileName)
        pending.push(...chunk.imports)
      }
      const leakedFiles = eagerOrder.filter((fileName) => {
        const chunk = chunks[fileName]
        return chunk && Object.keys(chunk.modules).some((id) => {
          const normalized = id.split('\\').join('/')
          return normalized.indexOf('/node_modules/antd/') !== -1
            || normalized.indexOf('/node_modules/@ant-design/') !== -1
            || normalized.indexOf('/node_modules/@rc-component/') !== -1
            || normalized.indexOf('/node_modules/rc-') !== -1
        })
      }).sort()
      if (leakedFiles.length > 0) {
        this.error(`Administrator UI runtime leaked into eager JavaScript: ${leakedFiles.join(', ')}`)
      }
    },
  }
}

export default defineConfig({
  plugins: [react(), enforceChunkBudget()],
  build: {
    manifest: true,
    rollupOptions: {
      output: {
        manualChunks: vendorChunk,
        onlyExplicitManualChunks: true,
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8000',
    },
  },
})
