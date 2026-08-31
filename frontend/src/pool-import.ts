const MAX_POOL_IMPORT_BYTES = 256 * 1024
const MAX_POOL_IMPORT_ITEMS = 100

export async function readPoolImportJson<T>(file: File): Promise<T[]> {
  if (file.size > MAX_POOL_IMPORT_BYTES) {
    throw new Error('导入文件不能超过 256 KiB。')
  }
  const parsed: unknown = JSON.parse(await file.text())
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > MAX_POOL_IMPORT_ITEMS) {
    throw new Error('导入文件必须是包含 1 至 100 条记录的 JSON 数组。')
  }
  return parsed as T[]
}

export function shouldRetainPoolImportForRetry(error: unknown): boolean {
  if (!error || typeof error !== 'object') return true
  const candidate = error as { status?: unknown; code?: unknown }
  if (typeof candidate.status !== 'number') return true
  return candidate.status === 0
    || candidate.status >= 500
    || candidate.code === 'stale_session_response'
}
