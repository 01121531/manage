import type { CardImportItem, MailboxImportItem, PoolImportReceipt } from './types'

const MAX_POOL_IMPORT_BYTES = 256 * 1024
const MAX_POOL_IMPORT_ITEMS = 100
const MAX_RECEIPT_TOKEN_LENGTH = 12 * 1024
const IMPORT_CONTEXT_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43,128}$/
const RECEIPT_TOKEN_PATTERN = /^epir1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/
const ROUTING_VALUE_PATTERN = /^[a-z0-9][a-z0-9._-]{0,79}$/
const CONNECTOR_VALUE_PATTERN = /^[a-z][a-z0-9_-]{0,79}$/
const PROVIDER_REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/
const CARD_BRAND_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$/
const MASKED_EMAIL_PATTERN = /^[a-z0-9]\*{3}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/
const SUBMISSION_KEY_PATTERN = /^spi:([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/

export type PoolImportBundle<T> = {
  schema_version: 3
  pool_type: 'card' | 'mailbox'
  submission_key: string
  context_token: string
  receipt_token: string
  items: T[]
}

type JsonObject = Record<string, unknown>

export class PoolImportValidationError extends Error {}

function isJsonObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function hasExactKeys(value: JsonObject, required: string[], optional: string[] = []): boolean {
  const keys = Object.keys(value)
  const allowed = new Set([...required, ...optional])
  return required.every((key) => keys.includes(key)) && keys.every((key) => allowed.has(key))
}

function containsPanLikeDigits(value: string): boolean {
  return value.split(/[A-Za-z]+/).some((candidate) => {
    const digitCount = candidate.replace(/\D/g, '').length
    return digitCount >= 12 && digitCount <= 19
  })
}

function parseCardItem(value: unknown, index: number): CardImportItem {
  const invalid = () => new PoolImportValidationError(`安全包第 ${index + 1} 条信用卡元数据无效；未发送任何数据。`)
  if (!isJsonObject(value) || !hasExactKeys(
    value,
    ['provider_ref', 'pool_key', 'region', 'brand', 'last4'],
    ['expiry_month', 'expiry_year'],
  )) throw invalid()
  const { provider_ref, pool_key, region, brand, last4, expiry_month, expiry_year } = value
  const expiryIsAbsent = expiry_month === undefined && expiry_year === undefined
  const expiryIsNull = expiry_month === null && expiry_year === null
  const expiryIsValid = typeof expiry_month === 'number'
    && Number.isInteger(expiry_month)
    && expiry_month >= 1
    && expiry_month <= 12
    && typeof expiry_year === 'number'
    && Number.isInteger(expiry_year)
    && expiry_year >= 2000
    && expiry_year <= 9999
  if (
    typeof provider_ref !== 'string'
    || !PROVIDER_REF_PATTERN.test(provider_ref)
    || containsPanLikeDigits(provider_ref)
    || typeof pool_key !== 'string'
    || !ROUTING_VALUE_PATTERN.test(pool_key)
    || typeof region !== 'string'
    || !ROUTING_VALUE_PATTERN.test(region)
    || typeof brand !== 'string'
    || !CARD_BRAND_PATTERN.test(brand)
    || containsPanLikeDigits(brand)
    || typeof last4 !== 'string'
    || !/^\d{4}$/.test(last4)
    || (!expiryIsAbsent && !expiryIsNull && !expiryIsValid)
  ) throw invalid()
  return {
    provider_ref,
    pool_key,
    region,
    brand,
    last4,
    ...(expiryIsAbsent ? {} : { expiry_month, expiry_year }),
  }
}

function parseMailboxItem(value: unknown, index: number): MailboxImportItem {
  const invalid = () => new PoolImportValidationError(`安全包第 ${index + 1} 条邮箱元数据无效；未发送任何数据。`)
  if (!isJsonObject(value) || !hasExactKeys(
    value,
    ['email_masked', 'connector_type', 'task_type'],
  )) throw invalid()
  const { email_masked, connector_type, task_type } = value
  if (
    typeof email_masked !== 'string'
    || email_masked.length > 320
    || !MASKED_EMAIL_PATTERN.test(email_masked)
    || typeof connector_type !== 'string'
    || !CONNECTOR_VALUE_PATTERN.test(connector_type)
    || typeof task_type !== 'string'
    || !CONNECTOR_VALUE_PATTERN.test(task_type)
  ) throw invalid()
  return { email_masked, connector_type, task_type }
}

async function readPoolImportJson<T>(
  file: File,
  expectedPoolType: 'card' | 'mailbox',
  parseItem: (value: unknown, index: number) => T,
): Promise<PoolImportBundle<T>> {
  if (file.size > MAX_POOL_IMPORT_BYTES) {
    throw new PoolImportValidationError('导入文件不能超过 256 KiB。')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(await file.text())
  } catch {
    throw new PoolImportValidationError('导入文件不是有效的安全包 JSON。')
  }
  if (!isJsonObject(parsed)) {
    throw new PoolImportValidationError('导入文件必须是安全导入器生成的 JSON 对象。')
  }
  const keys = Object.keys(parsed)
  const candidate = parsed as {
    schema_version?: unknown
    pool_type?: unknown
    submission_key?: unknown
    context_token?: unknown
    receipt_token?: unknown
    items?: unknown
  }
  if (
    keys.length !== 6
    || !keys.includes('schema_version')
    || !keys.includes('pool_type')
    || !keys.includes('submission_key')
    || !keys.includes('context_token')
    || !keys.includes('receipt_token')
    || !keys.includes('items')
    || candidate.schema_version !== 3
    || (candidate.pool_type !== 'card' && candidate.pool_type !== 'mailbox')
    || typeof candidate.submission_key !== 'string'
    || !/^spi:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(candidate.submission_key)
    || typeof candidate.context_token !== 'string'
    || !IMPORT_CONTEXT_TOKEN_PATTERN.test(candidate.context_token)
    || typeof candidate.receipt_token !== 'string'
    || candidate.receipt_token.length < 1
    || candidate.receipt_token.length > MAX_RECEIPT_TOKEN_LENGTH
    || !RECEIPT_TOKEN_PATTERN.test(candidate.receipt_token)
    || !Array.isArray(candidate.items)
    || candidate.items.length < 1
    || candidate.items.length > MAX_POOL_IMPORT_ITEMS
  ) {
    throw new PoolImportValidationError('导入包必须包含格式版本、池类型、有效收据和 1 至 100 条脱敏元数据。')
  }
  if (candidate.pool_type !== expectedPoolType) {
    throw new PoolImportValidationError(expectedPoolType === 'card'
      ? '该安全包属于邮箱池，不能导入信用卡池。'
      : '该安全包属于信用卡池，不能导入邮箱池。')
  }
  return {
    schema_version: 3,
    pool_type: expectedPoolType,
    submission_key: candidate.submission_key,
    context_token: candidate.context_token,
    receipt_token: candidate.receipt_token,
    items: candidate.items.map(parseItem),
  }
}

export const readCardPoolImportJson = (file: File) => readPoolImportJson(
  file, 'card', parseCardItem,
)

export const readMailboxPoolImportJson = (file: File) => readPoolImportJson(
  file, 'mailbox', parseMailboxItem,
)

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (isJsonObject(value)) {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    )).join(',')}}`
  }
  const encoded = JSON.stringify(value)
  if (encoded === undefined) throw new Error('unsupported canonical value')
  return encoded
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(value),
  )
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

export async function assertPoolImportReceiptBound(
  receipt: PoolImportReceipt,
  expectedPoolType: 'card' | 'mailbox',
  expectedItems: CardImportItem[] | MailboxImportItem[],
  submissionKey: string,
): Promise<void> {
  const label = expectedPoolType === 'card' ? '信用卡池' : '邮箱池'
  const invalid = () => new PoolImportValidationError(`平台返回的${label}导入回执绑定无效；请使用同一批次重试核对。`)
  const submissionMatch = SUBMISSION_KEY_PATTERN.exec(submissionKey)
  if (
    typeof receipt.id !== 'string'
    || receipt.id.trim().length === 0
    || receipt.status !== 'committed'
    || receipt.pool_type !== expectedPoolType
    || receipt.imported_count !== expectedItems.length
    || !submissionMatch
    || typeof receipt.secure_receipt_fingerprint !== 'string'
    || !SHA256_HEX_PATTERN.test(receipt.secure_receipt_fingerprint)
    || typeof receipt.ordered_manifest_digest !== 'string'
    || !SHA256_HEX_PATTERN.test(receipt.ordered_manifest_digest)
    || !Number.isInteger(receipt.key_version)
    || receipt.key_version < 1
    || typeof receipt.consumed_at !== 'string'
    || !Number.isFinite(Date.parse(receipt.consumed_at))
    || typeof receipt.trace_id !== 'string'
    || receipt.trace_id.trim().length === 0
    || typeof receipt.created_at !== 'string'
    || !Number.isFinite(Date.parse(receipt.created_at))
  ) throw invalid()

  let expectedFingerprint = ''
  let expectedManifestDigest = ''
  try {
    const normalizedItems: unknown[] = expectedPoolType === 'card'
      ? (expectedItems as CardImportItem[]).map((item) => ({
          ...item,
          expiry_month: item.expiry_month ?? null,
          expiry_year: item.expiry_year ?? null,
        }))
      : expectedItems
    const digests = await Promise.all([
      sha256Hex(submissionMatch[1]),
      sha256Hex(
        `email-platform:pool-import-manifest:v2\0${expectedPoolType}\0${canonicalJson(normalizedItems)}`,
      ),
    ])
    expectedFingerprint = digests[0]
    expectedManifestDigest = digests[1]
  } catch {
    throw invalid()
  }
  if (
    receipt.secure_receipt_fingerprint !== expectedFingerprint
    || receipt.ordered_manifest_digest !== expectedManifestDigest
  ) {
    throw invalid()
  }
}

export function shouldRetainPoolImportForRetry(error: unknown): boolean {
  if (!error || typeof error !== 'object') return true
  const candidate = error as { status?: unknown; code?: unknown }
  if (typeof candidate.status !== 'number') return true
  return candidate.status === 0
    || candidate.status >= 500
    || candidate.code === 'stale_session_response'
}
