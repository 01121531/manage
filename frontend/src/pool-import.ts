const MAX_POOL_IMPORT_BYTES = 256 * 1024
const MAX_POOL_IMPORT_ITEMS = 100
const MAX_RECEIPT_TOKEN_LENGTH = 12 * 1024
const RECEIPT_TOKEN_PATTERN = /^epir1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/

export type PoolImportBundle<T> = {
  receipt_token: string
  items: T[]
}

export async function readPoolImportJson<T>(file: File): Promise<PoolImportBundle<T>> {
  if (file.size > MAX_POOL_IMPORT_BYTES) {
    throw new Error('导入文件不能超过 256 KiB。')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(await file.text())
  } catch {
    throw new Error('导入文件不是有效的安全包 JSON。')
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('导入文件必须是安全导入器生成的 JSON 对象。')
  }
  const keys = Object.keys(parsed)
  const candidate = parsed as { receipt_token?: unknown; items?: unknown }
  if (
    keys.length !== 2
    || !keys.includes('receipt_token')
    || !keys.includes('items')
    || typeof candidate.receipt_token !== 'string'
    || candidate.receipt_token.length < 1
    || candidate.receipt_token.length > MAX_RECEIPT_TOKEN_LENGTH
    || !RECEIPT_TOKEN_PATTERN.test(candidate.receipt_token)
    || !Array.isArray(candidate.items)
    || candidate.items.length < 1
    || candidate.items.length > MAX_POOL_IMPORT_ITEMS
  ) {
    throw new Error('导入包必须包含有效收据和 1 至 100 条脱敏元数据。')
  }
  return { receipt_token: candidate.receipt_token, items: candidate.items as T[] }
}

export function shouldRetainPoolImportForRetry(error: unknown): boolean {
  if (!error || typeof error !== 'object') return true
  const candidate = error as { status?: unknown; code?: unknown }
  if (typeof candidate.status !== 'number') return true
  return candidate.status === 0
    || candidate.status >= 500
    || candidate.code === 'stale_session_response'
}
