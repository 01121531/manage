import { useEffect, useRef, useState } from 'react'
import { Alert, App as AntApp, Button, Card, Descriptions, Empty, Input, Modal, Space, Spin, Table, Select, Timeline, Typography } from 'antd'
import type { TableColumnsType } from 'antd'
import { getCardTimeline, importCards, listCards, quarantineCard, recycleCardAllocation, releaseCardQuarantine, updateCardState } from '../admin-api'
import { ApiError } from '../api'
import type { CardAllocationSummary, CardEventSummary, CardImportItem, CardSummary, CardTimeline, PoolImportReceipt } from '../types'
import { PoolImportValidationError, assertPoolImportReceiptBound, readCardPoolImportJson, shouldRetainPoolImportForRetry } from '../pool-import'
import { useScopedConfirm } from '../useScopedConfirm'
import { CardStatusTag, StatusTag, cardAllocationReasonNames, cardEventActionNames, cardQuarantineReasonNames, compareTableText, formatLocalDateTime, maskedStateLabel } from './shared'

const { Title, Text } = Typography
const cardImportUnknownMessage = '原因：平台未返回可验证的信用卡池导入回执。影响：本批可能已原子导入，不能按本次错误选择新安全包或推断失败。下一步：恢复上下文已保留，请使用“同一批次核验”确认真实结果。'
const cardTimelineBindingError = '平台返回的卡片历史绑定关系无效。'

function cardImportFailureMessage(error: unknown, retainedForRetry: boolean, fallback: string): string {
  if (error instanceof PoolImportValidationError) return error.message
  if (retainedForRetry) return cardImportUnknownMessage
  return error instanceof ApiError ? error.message : fallback
}

function safeCardTimelineError(error: unknown, fallback: string): string {
  if (error instanceof ApiError) return error.message
  if (error instanceof Error && error.message === cardTimelineBindingError) return error.message
  return fallback
}

export default function CardsPage({ canManage, canReleaseQuarantine }: {
  canManage: boolean
  canReleaseQuarantine: boolean
}) {
  const { message } = AntApp.useApp()
  const confirm = useScopedConfirm()
  const [rows, setRows] = useState<CardSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [cardListError, setCardListError] = useState<string>()
  const [cardSearch, setCardSearch] = useState('')
  const [committedCardSearch, setCommittedCardSearch] = useState('')
  const [cardPoolInput, setCardPoolInput] = useState('')
  const [cardPoolFilter, setCardPoolFilter] = useState<string>()
  const [cardStatusFilter, setCardStatusFilter] = useState<CardSummary['status']>()
  const [cardCursor, setCardCursor] = useState<string>()
  const [cardCursorHistory, setCardCursorHistory] = useState<string[]>([])
  const [cardTotalCount, setCardTotalCount] = useState(0)
  const [cardHasMore, setCardHasMore] = useState(false)
  const [cardNextCursor, setCardNextCursor] = useState<string>()
  const [refresh, setRefresh] = useState(0)
  const [saving, setSaving] = useState(false)
  const [quarantineTarget, setQuarantineTarget] = useState<CardSummary | null>(null)
  const [quarantineReason, setQuarantineReason] = useState<string>()
  const [quarantineSaving, setQuarantineSaving] = useState(false)
  const cardImportInputRef = useRef<HTMLInputElement>(null)
  const cardImportPendingRef = useRef(false)
  const cardImportRetryRef = useRef<{
    payload: CardImportItem[]
    idempotencyKey: string
    contextToken: string
    receiptToken: string
  } | null>(null)
  const [cardImportRetryAvailable, setCardImportRetryAvailable] = useState(false)
  const [lastCardImportReceipt, setLastCardImportReceipt] = useState<PoolImportReceipt>()
  const [cardActionId, setCardActionId] = useState<string | null>(null)
  const cardActionRef = useRef<{ cardId: string; pending: boolean } | null>(null)
  const cardActionRefreshRef = useRef<{ cardId: string; pending: boolean } | null>(null)
  const [selectedCardId, setSelectedCardId] = useState<string | null>(null)
  const [cardTimeline, setCardTimeline] = useState<CardTimeline | null>(null)
  const [timelineLoading, setTimelineLoading] = useState(false)
  const [timelinePageLoading, setTimelinePageLoading] = useState<'allocations' | 'events' | null>(null)
  const [timelineError, setTimelineError] = useState<string>()
  const [timelineRefresh, setTimelineRefresh] = useState(0)
  const timelineGenerationRef = useRef(0)
  const timelinePagePendingRef = useRef(false)
  const [recycleTarget, setRecycleTarget] = useState<CardAllocationSummary | null>(null)
  const [recycleReason, setRecycleReason] = useState<string>()
  const [recycleSaving, setRecycleSaving] = useState(false)
  const cardListGenerationRef = useRef(0)
  const recycleRefreshRef = useRef<{
    action: { cardId: string; pending: boolean }
    cardListGeneration: number
    timelineGeneration: number
    cardListSettled: boolean
    timelineSettled: boolean
  } | null>(null)

  function settleRecycleRefresh(
    kind: 'card-list' | 'timeline',
    generation: number,
    cardListFailed = false,
  ) {
    const barrier = recycleRefreshRef.current
    if (!barrier) return
    if (kind === 'card-list' && barrier.cardListGeneration === generation) {
      barrier.cardListSettled = true
      if (cardListFailed) barrier.timelineSettled = true
    }
    if (kind === 'timeline' && barrier.timelineGeneration === generation) {
      barrier.timelineSettled = true
    }
    if (!barrier.cardListSettled || !barrier.timelineSettled) return
    recycleRefreshRef.current = null
    releaseCardAction(barrier.action)
  }

  function invalidateCardList(clearSelection = true) {
    cardListGenerationRef.current += 1
    setLoading(true)
    setCardListError(undefined)
    setRows([])
    setCardTotalCount(0)
    setCardHasMore(false)
    setCardNextCursor(undefined)
    if (clearSelection) {
      setSelectedCardId(null)
      setCardTimeline(null)
    }
  }

  function refreshCardsFromServer(firstPage = false) {
    invalidateCardList(false)
    if (firstPage) {
      setCardCursor(undefined)
      setCardCursorHistory([])
    }
    setRefresh((value) => value + 1)
  }

  useEffect(() => {
    const controller = new AbortController()
    const generation = cardListGenerationRef.current + 1
    let failed = false
    cardListGenerationRef.current = generation
    setLoading(true)
    setCardListError(undefined)
    setRows([])
    setCardTotalCount(0)
    setCardHasMore(false)
    setCardNextCursor(undefined)
    listCards({
      q: committedCardSearch || undefined,
      pool_key: cardPoolFilter,
      status: cardStatusFilter,
      cursor: cardCursor,
    }, controller.signal).then((page) => {
      if (cardListGenerationRef.current !== generation) return
      setRows(page.items)
      setCardTotalCount(page.total_count)
      setCardHasMore(page.has_more)
      setCardNextCursor(page.next_cursor ?? undefined)
    })
      .catch(() => {
        if (cardListGenerationRef.current === generation) {
          failed = true
          setSelectedCardId(null)
          setCardTimeline(null)
          setCardListError(
            '原因：平台未能读取卡资源真实状态。'
            + '影响：旧卡记录和启用、停用操作已隐藏，卡租约与关联上传状态无法安全确认。'
            + '下一步：请重新获取真实状态；成功前不要重复启用或停用卡资源。',
          )
        }
      })
      .finally(() => {
        if (cardListGenerationRef.current === generation) {
          setLoading(false)
          const action = cardActionRefreshRef.current
          if (action !== null) {
            cardActionRefreshRef.current = null
            releaseCardAction(action)
          }
          settleRecycleRefresh('card-list', generation, failed)
        }
      })
    return () => {
      controller.abort()
      if (cardListGenerationRef.current === generation) {
        cardListGenerationRef.current += 1
      }
    }
  }, [cardCursor, cardPoolFilter, cardStatusFilter, committedCardSearch, refresh])

  useEffect(() => {
    const normalized = cardSearch.trim().toLocaleLowerCase()
    if (normalized === committedCardSearch) return
    invalidateCardList()
    setCardCursor(undefined)
    setCardCursorHistory([])
    const timer = window.setTimeout(() => setCommittedCardSearch(normalized), 300)
    return () => window.clearTimeout(timer)
  }, [cardSearch, committedCardSearch])

  useEffect(() => {
    if (!selectedCardId) {
      setCardTimeline(null)
      setTimelineError(undefined)
      setTimelineLoading(false)
      setTimelinePageLoading(null)
      return
    }
    let alive = true
    const generation = timelineGenerationRef.current + 1
    timelineGenerationRef.current = generation
    setTimelineLoading(true)
    setTimelineError(undefined)
    setCardTimeline(null)
    getCardTimeline(selectedCardId).then((result) => {
      const mismatched = result.card.id !== selectedCardId
        || result.allocations.some((item) => item.card_id !== selectedCardId)
        || result.events.some((item) => item.card_id !== selectedCardId)
      if (mismatched) throw new Error(cardTimelineBindingError)
      if (alive && timelineGenerationRef.current === generation) setCardTimeline(result)
    }).catch((error) => {
      if (alive && timelineGenerationRef.current === generation) {
        const reason = safeCardTimelineError(error, '平台未能读取卡片历史。')
        setTimelineError(
          `原因：${reason} `
          + '影响：旧分配历史和回收入口已隐藏，当前租约状态无法安全确认。 '
          + '下一步：请重新获取真实历史；成功前不要回收租约。',
        )
      }
    }).finally(() => {
      if (alive && timelineGenerationRef.current === generation) {
        setTimelineLoading(false)
        settleRecycleRefresh('timeline', generation)
      }
    })
    return () => {
      alive = false
      timelineGenerationRef.current += 1
    }
  }, [refresh, selectedCardId, timelineRefresh])

  async function importCardFile(file: File | undefined) {
    if (!file || cardImportPendingRef.current || cardImportRetryRef.current !== null) return
    cardImportPendingRef.current = true
    setSaving(true)
    try {
      const bundle = await readCardPoolImportJson(file)
      const poolKeys = Array.from(new Set(bundle.items.map((item) => item.pool_key))).sort(compareTableText)
      const confirmed = await new Promise<boolean>((resolve) => {
        let settled = false
        const settle = (value: boolean) => {
          if (settled) return
          settled = true
          resolve(value)
        }
        confirm({
          title: '确认导入信用卡池安全包？',
          content: <Space direction="vertical" size={8}>
            <Text>文件：{file.name}</Text>
            <Text>格式：安全包 v{bundle.schema_version} / 信用卡池</Text>
            <Text>脱敏资源：{bundle.items.length} 条</Text>
            <Text>目标卡池：{poolKeys.slice(0, 5).join('、')}{poolKeys.length > 5 ? ` 等 ${poolKeys.length} 个卡池` : ''}</Text>
            <Text type="warning">整批原子导入：任一条校验失败时，本批 0 条入池。确认后才会发送脱敏元数据；PAN/CVV 和收据内容不会显示。</Text>
          </Space>,
          okText: `确认导入 ${bundle.items.length} 条`,
          cancelText: '取消',
          onOk: () => settle(true),
          onCancel: () => settle(false),
          afterClose: () => settle(false),
        })
      })
      if (!confirmed) return
      const batch = {
        payload: bundle.items,
        contextToken: bundle.context_token,
        receiptToken: bundle.receipt_token,
        idempotencyKey: bundle.submission_key,
      }
      cardImportRetryRef.current = batch
      setCardImportRetryAvailable(true)
      const receipt = await importCards(
        batch.payload, batch.idempotencyKey, batch.contextToken, batch.receiptToken,
      )
      await assertPoolImportReceiptBound(
        receipt, 'card', batch.payload, batch.idempotencyKey,
      )
      cardImportRetryRef.current = null
      setCardImportRetryAvailable(false)
      setLastCardImportReceipt(receipt)
      message.success(`已向信用卡池登记 ${receipt.imported_count} 条资源引用。`)
      refreshCardsFromServer(true)
    } catch (error) {
      const retainedForRetry = cardImportRetryRef.current !== null && shouldRetainPoolImportForRetry(error)
      if (!retainedForRetry) {
        cardImportRetryRef.current = null
        setCardImportRetryAvailable(false)
      }
      message.error(cardImportFailureMessage(error, retainedForRetry, '信用卡池引用清单登记失败'))
    } finally {
      if (cardImportInputRef.current) cardImportInputRef.current.value = ''
      cardImportPendingRef.current = false
      setSaving(false)
    }
  }

  function discardCardImportRetry() {
    cardImportRetryRef.current = null
    setCardImportRetryAvailable(false)
    message.info('已从当前页面内存清除上次信用卡池引用清单。')
  }

  async function retryCardImport() {
    const batch = cardImportRetryRef.current
    if (!batch || cardImportPendingRef.current) return
    cardImportPendingRef.current = true
    setSaving(true)
    try {
      const receipt = await importCards(
        batch.payload, batch.idempotencyKey, batch.contextToken, batch.receiptToken,
      )
      await assertPoolImportReceiptBound(
        receipt, 'card', batch.payload, batch.idempotencyKey,
      )
      cardImportRetryRef.current = null
      setCardImportRetryAvailable(false)
      setLastCardImportReceipt(receipt)
      message.success(`已确认信用卡池引用清单，共 ${receipt.imported_count} 条资源。`)
      refreshCardsFromServer(true)
    } catch (error) {
      const retainedForRetry = cardImportRetryRef.current !== null && shouldRetainPoolImportForRetry(error)
      if (!retainedForRetry) {
        cardImportRetryRef.current = null
        setCardImportRetryAvailable(false)
      }
      message.error(cardImportFailureMessage(error, retainedForRetry, '信用卡池引用清单重试失败'))
    } finally {
      cardImportPendingRef.current = false
      setSaving(false)
    }
  }

  function reserveCardAction(cardId: string) {
    if (cardActionRef.current !== null) return null
    const action = { cardId, pending: false }
    cardActionRef.current = action
    setCardActionId(cardId)
    return action
  }

  function releaseCardAction(action: { cardId: string; pending: boolean }) {
    if (cardActionRef.current !== action) return
    cardActionRef.current = null
    setCardActionId(null)
  }

  async function changeState(
    action: { cardId: string; pending: boolean },
    row: CardSummary,
    isActive: boolean,
  ) {
    if (cardActionRef.current !== action || action.pending) return
    action.pending = true
    try {
      const updated = await updateCardState(row.id, isActive)
      const expectedStatus = isActive ? 'available' : 'disabled'
      if (
        updated.id !== row.id
        || updated.tenant_id !== row.tenant_id
        || updated.provider_ref !== row.provider_ref
        || updated.last4 !== row.last4
        || updated.is_active !== isActive
        || updated.status !== expectedStatus
        || updated.quarantine_reason_code !== null
        || updated.quarantined_at !== null
      ) throw new Error('card state response binding mismatch')
      message.success(isActive ? '卡资源已启用。' : '卡资源已停用，活动租约已释放。')
    } catch {
      message.error(
        '原因：平台未能确认卡资源状态变更结果。'
        + '影响：状态切换与关联资源回收可能已经生效，页面不会按失败响应推断最终状态。'
        + '下一步：正在重新获取卡资源真实状态；重新获取完成前不要重复操作，仅当目标状态仍未生效时才从同一行重试。',
      )
    } finally {
      cardActionRefreshRef.current = action
      refreshCardsFromServer()
    }
  }

  function confirmDisableCard(row: CardSummary) {
    const action = reserveCardAction(row.id)
    if (!action) return
    confirm({
      title: `确认停用卡 ${row.provider_ref}？`,
      content: <Space direction="vertical" size={8}>
        <Text>提供方引用：{row.provider_ref}</Text>
        <Text>掩码卡号：•••• {row.last4}</Text>
        <Text>卡资源 ID：{row.id}</Text>
        <Text type="danger">停用会立即释放活动租约，并取消尚未执行的关联上传；运行中的上传将转为待人工核对。</Text>
      </Space>,
      okText: '停用并释放',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onCancel: () => {
        if (!action.pending) releaseCardAction(action)
      },
      onOk: () => changeState(action, row, false),
    })
  }

  function enableCard(row: CardSummary) {
    const action = reserveCardAction(row.id)
    if (!action) return
    void changeState(action, row, true)
  }

  function openQuarantine(row: CardSummary) {
    const action = reserveCardAction(row.id)
    if (!action) return
    setQuarantineReason(undefined)
    setQuarantineTarget(row)
  }

  function closeQuarantine() {
    const action = cardActionRef.current
    if (action?.pending) return
    setQuarantineTarget(null)
    setQuarantineReason(undefined)
    if (action) releaseCardAction(action)
  }

  async function confirmQuarantine() {
    const action = cardActionRef.current
    const row = quarantineTarget
    if (!action || action.pending || !row || !quarantineReason) return
    action.pending = true
    setQuarantineSaving(true)
    try {
      const updated = await quarantineCard(row.id, quarantineReason)
      if (
        updated.id !== row.id
        || updated.tenant_id !== row.tenant_id
        || updated.provider_ref !== row.provider_ref
        || updated.last4 !== row.last4
        || updated.status !== 'quarantined'
        || updated.is_active
        || updated.quarantine_reason_code !== quarantineReason
        || updated.quarantined_at === null
      ) throw new Error('card quarantine response binding mismatch')
      message.success('卡资源已隔离，活动租约及关联资源已回收。')
      setQuarantineTarget(null)
      setQuarantineReason(undefined)
    } catch {
      setQuarantineTarget(null)
      setQuarantineReason(undefined)
      message.error(
        '原因：平台未能确认卡资源隔离结果。'
        + '影响：隔离与关联资源回收可能已经生效，页面不会按失败响应推断最终状态。'
        + '下一步：已关闭本次确认并正在重新获取卡资源真实状态；完成前不得执行其他卡治理，仅当刷新后该卡仍未隔离时才重新发起。',
      )
    } finally {
      setQuarantineSaving(false)
      if (cardActionRef.current === action) {
        cardActionRefreshRef.current = action
        refreshCardsFromServer()
      }
    }
  }

  function confirmReleaseQuarantine(row: CardSummary) {
    const action = reserveCardAction(row.id)
    if (!action) return
    confirm({
      title: `确认解除卡 ${row.provider_ref} 的隔离？`,
      content: <Space direction="vertical" size={8}>
        <Text>掩码卡号：•••• {row.last4}</Text>
        <Text>卡资源 ID：{row.id}</Text>
        <Text type="warning">解除隔离后卡资源仍保持停用，必须另行启用才会重新进入分配池。</Text>
      </Space>,
      okText: '解除隔离',
      cancelText: '取消',
      onCancel: () => {
        if (!action.pending) releaseCardAction(action)
      },
      onOk: async () => {
        if (action.pending) return
        action.pending = true
        try {
          const updated = await releaseCardQuarantine(row.id)
          if (
            updated.id !== row.id
            || updated.tenant_id !== row.tenant_id
            || updated.provider_ref !== row.provider_ref
            || updated.status !== 'disabled'
            || updated.is_active
            || updated.quarantine_reason_code !== null
            || updated.quarantined_at !== null
          ) throw new Error('card quarantine release response binding mismatch')
          message.success('隔离已解除；卡资源仍处于停用状态。')
        } catch {
          message.error(
            '原因：平台未能确认解除隔离结果。'
            + '影响：解除可能已经生效；页面不会按失败响应推断最终状态。'
            + '下一步：正在重新获取卡资源真实状态；完成前不得执行其他卡治理，仅当刷新后该卡仍为已隔离时才重试。',
          )
        } finally {
          if (cardActionRef.current === action) {
            cardActionRefreshRef.current = action
            refreshCardsFromServer()
          }
        }
      },
    })
  }

  function openCardTimeline(row: CardSummary) {
    if (selectedCardId === row.id) {
      setTimelineRefresh((value) => value + 1)
      return
    }
    setSelectedCardId(row.id)
  }

  async function loadOlderCardTimeline(kind: 'allocations' | 'events') {
    if (!selectedCardId || !cardTimeline || timelinePagePendingRef.current) return
    const cursor = kind === 'allocations'
      ? cardTimeline.allocations_next_cursor
      : cardTimeline.events_next_cursor
    if (!cursor) return
    const generation = timelineGenerationRef.current
    timelinePagePendingRef.current = true
    setTimelinePageLoading(kind)
    try {
      const result = await getCardTimeline(selectedCardId, kind === 'allocations'
        ? { allocationsCursor: cursor }
        : { eventsCursor: cursor })
      const mismatched = result.card.id !== selectedCardId
        || result.allocations.some((item) => item.card_id !== selectedCardId)
        || result.events.some((item) => item.card_id !== selectedCardId)
      if (mismatched) throw new Error(cardTimelineBindingError)
      if (timelineGenerationRef.current !== generation) return
      setCardTimeline((current) => {
        if (!current || current.card.id !== selectedCardId) return current
        if (kind === 'allocations') {
          const known = new Set(current.allocations.map((item) => item.id))
          return {
            ...current,
            card: result.card,
            allocations: [
              ...current.allocations,
              ...result.allocations.filter((item) => !known.has(item.id)),
            ],
            allocations_has_more: result.allocations_has_more,
            allocations_next_cursor: result.allocations_next_cursor,
          }
        }
        const known = new Set(current.events.map((item) => item.id))
        return {
          ...current,
          card: result.card,
          events: [
            ...current.events,
            ...result.events.filter((item) => !known.has(item.id)),
          ],
          events_has_more: result.events_has_more,
          events_next_cursor: result.events_next_cursor,
        }
      })
    } catch (error) {
      if (timelineGenerationRef.current === generation) {
        message.error(safeCardTimelineError(error, '更早的卡片历史读取失败'))
      }
    } finally {
      timelinePagePendingRef.current = false
      if (timelineGenerationRef.current === generation) setTimelinePageLoading(null)
    }
  }

  function openRecycleAllocation(allocation: CardAllocationSummary) {
    const action = reserveCardAction(allocation.card_id)
    if (!action) return
    setRecycleReason(undefined)
    setRecycleTarget(allocation)
  }

  function closeRecycleAllocation() {
    const action = cardActionRef.current
    if (action?.pending) return
    setRecycleTarget(null)
    setRecycleReason(undefined)
    if (action) releaseCardAction(action)
  }

  async function confirmRecycleAllocation() {
    const action = cardActionRef.current
    const allocation = recycleTarget
    if (!action || action.pending || !allocation || !recycleReason) return
    if (action.cardId !== allocation.card_id) {
      closeRecycleAllocation()
      return
    }
    action.pending = true
    setRecycleSaving(true)
    try {
      const updated = await recycleCardAllocation(allocation.card_id, allocation.id, recycleReason)
      if (
        updated.id !== allocation.id
        || updated.card_id !== allocation.card_id
        || updated.card_masked !== allocation.card_masked
        || updated.task_id !== allocation.task_id
        || updated.user_id !== allocation.user_id
        || updated.status !== 'released'
        || updated.release_reason_code !== recycleReason
        || updated.released_at === null
      ) throw new Error('card allocation recycle response binding mismatch')
      message.success('活动租约已回收；关联排队上传已取消。')
      setRecycleTarget(null)
      setRecycleReason(undefined)
    } catch {
      setRecycleTarget(null)
      setRecycleReason(undefined)
      message.error(
        '原因：平台未能确认活动租约回收结果。'
        + '影响：回收屏障与关联排队上传取消可能已经生效，页面不会按失败响应推断最终状态。'
        + '下一步：已关闭本次确认并重新获取卡片历史；仅当该租约仍为活动状态时，才从同一记录重新发起。',
      )
    } finally {
      setRecycleSaving(false)
      refreshCardsFromServer()
      if (cardActionRef.current === action) {
        recycleRefreshRef.current = {
          action,
          cardListGeneration: cardListGenerationRef.current + 1,
          timelineGeneration: timelineGenerationRef.current + 2,
          cardListSettled: false,
          timelineSettled: false,
        }
      }
    }
  }

  function resetCardQueryPage() {
    invalidateCardList()
    setCardCursor(undefined)
    setCardCursorHistory([])
  }

  function applyCardPoolFilter(value: string) {
    const normalized = value.trim().toLocaleLowerCase()
    if (normalized && !/^[a-z0-9][a-z0-9._-]{0,79}$/.test(normalized)) {
      message.error('卡池键只能包含小写字母、数字、点、下划线或连字符。')
      return
    }
    if ((normalized || undefined) === cardPoolFilter) return
    resetCardQueryPage()
    setCardPoolFilter(normalized || undefined)
  }

  function changeCardStatusFilter(value: CardSummary['status'] | undefined) {
    if (value === cardStatusFilter) return
    resetCardQueryPage()
    setCardStatusFilter(value)
  }

  function showNextCardPage() {
    if (loading || !cardHasMore || !cardNextCursor) return
    invalidateCardList()
    setCardCursorHistory((history) => [...history, cardCursor ?? ''])
    setCardCursor(cardNextCursor)
  }

  function showPreviousCardPage() {
    if (loading || cardCursorHistory.length === 0) return
    const previous = cardCursorHistory[cardCursorHistory.length - 1]
    invalidateCardList()
    setCardCursorHistory((history) => history.slice(0, -1))
    setCardCursor(previous || undefined)
  }

  const columns: TableColumnsType<CardSummary> = [
    { title: '卡资源 ID', dataIndex: 'id', render: (value: string) => <Text code copyable={{ text: value }}>{value}</Text> },
    { title: '提供方引用', dataIndex: 'provider_ref' },
    { title: '卡池', dataIndex: 'pool_key' },
    { title: '地区', dataIndex: 'region' },
    { title: '品牌', dataIndex: 'brand' },
    { title: '尾号', dataIndex: 'last4', render: (value: string) => `•••• ${value}` },
    { title: '有效期', render: (_, row) => row.expiry_month && row.expiry_year ? `${String(row.expiry_month).padStart(2, '0')}/${row.expiry_year}` : '—' },
    {
      title: '状态', dataIndex: 'status',
      render: (value: CardSummary['status']) => <CardStatusTag value={value} />,
    },
    { title: '隔离原因', dataIndex: 'quarantine_reason_code', render: (value: string | null) => value ? (cardQuarantineReasonNames[value] ?? '其他受控原因') : '—' },
    { title: '操作', render: (_: unknown, row: CardSummary) => <Space wrap>
      <Button
        disabled={cardActionId !== null}
        aria-label={`查看卡 ${row.provider_ref}（•••• ${row.last4}，${row.id}）的分配历史`}
        onClick={() => openCardTimeline(row)}
      >分配历史</Button>
      {canManage && row.status === 'quarantined' ? (canReleaseQuarantine ? <Button
        loading={cardActionId === row.id}
        disabled={cardActionId !== null}
        aria-label={`解除隔离卡 ${row.provider_ref}（•••• ${row.last4}，${row.id}）`}
        onClick={() => confirmReleaseQuarantine(row)}
      >解除隔离</Button> : null) : canManage ? <>
        <Button
          danger={row.status === 'available' || row.status === 'allocated'}
          loading={cardActionId === row.id}
          disabled={cardActionId !== null}
          aria-label={`${row.status === 'disabled' ? '启用' : '停用'}卡 ${row.provider_ref}（•••• ${row.last4}，${row.id}）`}
          onClick={() => row.status === 'disabled' ? enableCard(row) : confirmDisableCard(row)}
        >{row.status === 'disabled' ? '启用' : '停用'}</Button>
        <Button danger disabled={cardActionId !== null} aria-label={`隔离卡 ${row.provider_ref}（•••• ${row.last4}，${row.id}）`} onClick={() => openQuarantine(row)}>隔离</Button>
      </> : null}
    </Space> },
  ]
  const allocationColumns: TableColumnsType<CardAllocationSummary> = [
    { title: '租约 ID', dataIndex: 'id', render: (value: string) => <Text code copyable>{value}</Text> },
    { title: '任务 ID', dataIndex: 'task_id', render: (value: string) => <Text code copyable>{value}</Text> },
    { title: '状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: '分配时间', dataIndex: 'created_at', render: formatLocalDateTime },
    { title: '到期时间', dataIndex: 'expires_at', render: formatLocalDateTime },
    { title: '释放时间', dataIndex: 'released_at', render: (value: string | null) => value ? formatLocalDateTime(value) : '—' },
    { title: '释放原因', dataIndex: 'release_reason_code', render: (value: string | null) => value ? (cardAllocationReasonNames[value] ?? '其他受控原因') : '—' },
    ...(canManage ? [{
      title: '租约操作',
      render: (_: unknown, allocation: CardAllocationSummary) => allocation.status === 'active' && allocation.released_at === null ? <Button
        danger
        loading={cardActionId === allocation.card_id}
        disabled={cardActionId !== null}
        aria-label={`回收活动租约 ${allocation.id}，卡 ${allocation.card_masked}`}
        onClick={() => openRecycleAllocation(allocation)}
      >回收租约</Button> : '—',
    }] : []),
  ]
  return <>
    <div className="page-heading"><div><Title level={2}>卡池管理</Title><Text type="secondary">卡资源由管理员手动登记并独立于邮箱池管理；登记接口不接收 PAN/CVV，PAN 保存在 Vault 且仅经 step-up 揭示，CVV 默认不返回。</Text></div>{canManage ? <Space>
      <input ref={cardImportInputRef} hidden type="file" accept=".json,application/json" onChange={(event) => { void importCardFile(event.currentTarget.files?.[0]) }} />
      <Button type="primary" loading={saving} disabled={loading || cardListError !== undefined || cardActionId !== null || cardImportRetryAvailable} onClick={() => cardImportInputRef.current?.click()}>导入信用卡池安全包 JSON</Button>
    </Space> : null}</div>
    <Alert className="section-card" type="info" showIcon message="这里只接收独立安全导入器生成的卡池安全包" description="PAN/CVV 不进入浏览器或普通 API；安全包只含脱敏元数据和短期 Vault Transit 签名收据，密钥引用由服务端固定派生。单条资源也使用同一安全导入流程。" />
    {cardImportRetryAvailable && cardImportRetryRef.current ? <Alert
      className="section-card"
      type="warning"
      showIcon
      message="上次信用卡池导入结果尚未确认"
      description={<Space direction="vertical" size={4}>
        <Text>平台可能已完成导入。不要选择新安全包；请使用同一批次核验，或明确放弃当前页面内存中的恢复上下文。</Text>
        <Text>稳定提交键：</Text><Text code copyable>{cardImportRetryRef.current.idempotencyKey}</Text>
      </Space>}
      action={<Space wrap>
        <Button disabled={saving} onClick={() => { void retryCardImport() }}>使用同一批次核验信用卡池导入</Button>
        <Button disabled={saving} onClick={discardCardImportRetry}>明确放弃本次核验</Button>
      </Space>}
    /> : null}
    {lastCardImportReceipt ? <Alert
      className="section-card"
      type="success"
      showIcon
      message={`最近一次信用卡池导入已确认：${lastCardImportReceipt.imported_count} 条`}
      description={<Space wrap>
        <Text>平台导入回执 ID：</Text><Text code copyable>{lastCardImportReceipt.id}</Text>
        <Text>Trace ID：</Text><Text code copyable>{lastCardImportReceipt.trace_id}</Text>
        <Text>状态：{lastCardImportReceipt.status} / Transit key v{lastCardImportReceipt.key_version}</Text>
        <Text>清单摘要：</Text><Text code copyable>{lastCardImportReceipt.ordered_manifest_digest}</Text>
        <Text>安全收据指纹：</Text><Text code copyable>{lastCardImportReceipt.secure_receipt_fingerprint}</Text>
        <Text>时间：{formatLocalDateTime(lastCardImportReceipt.created_at)}</Text>
      </Space>}
    /> : null}
    <Card className="section-card">{loading ? <div className="centered"><Spin /></div> : cardListError ? <Alert
      type="warning"
      showIcon
      message="卡资源列表暂不可用"
      description={cardListError}
      action={<Button onClick={() => refreshCardsFromServer()}>重新获取卡资源真实状态</Button>}
    /> : <Space direction="vertical" size={16} className="full-width">
      <Space wrap>
        <Input
          allowClear
          disabled={saving || cardActionId !== null}
          aria-label="搜索信用卡池"
          placeholder="搜索提供方引用、卡池、地区、品牌或尾号"
          value={cardSearch}
          onChange={(event) => setCardSearch(event.currentTarget.value)}
          style={{ width: 320 }}
        />
        <Input.Search
          disabled={saving || cardActionId !== null}
          aria-label="按卡池筛选"
          placeholder="输入精确卡池键后回车"
          value={cardPoolInput}
          enterButton="应用卡池"
          onChange={(event) => {
            const value = event.currentTarget.value
            setCardPoolInput(value)
            if (!value) applyCardPoolFilter('')
          }}
          onSearch={applyCardPoolFilter}
          style={{ width: 280 }}
        />
        <Select<CardSummary['status']>
          allowClear
          disabled={saving || cardActionId !== null}
          aria-label="按卡状态筛选"
          placeholder="全部状态"
          value={cardStatusFilter}
          options={[
            { label: '可用', value: 'available' },
            { label: '已分配', value: 'allocated' },
            { label: '已停用', value: 'disabled' },
            { label: '已隔离', value: 'quarantined' },
          ]}
          onChange={changeCardStatusFilter}
          style={{ minWidth: 140 }}
        />
        <Text type="secondary" role="status" aria-live="polite">第 {cardCursorHistory.length + 1} 页，显示 {rows.length} / 匹配 {cardTotalCount} 张卡</Text>
      </Space>
      <Table pagination={false} columns={columns} dataSource={rows} rowKey="id" locale={{ emptyText: <Empty description="没有符合条件的卡资源" /> }} scroll={{ x: 1280 }} />
      <Space>
        <Button disabled={loading || cardCursorHistory.length === 0} onClick={showPreviousCardPage}>上一页</Button>
        <Button disabled={loading || !cardHasMore || !cardNextCursor} onClick={showNextCardPage}>下一页</Button>
      </Space>
    </Space>}</Card>
    {selectedCardId ? <Card
      className="section-card"
      title="卡片分配历史"
      extra={<Button aria-label="关闭卡片分配历史" onClick={() => setSelectedCardId(null)}>关闭</Button>}
    >
      <div role="status" aria-live="polite">
        {timelineLoading ? <div className="centered"><Spin tip="正在读取卡片真实历史" /></div> : null}
      </div>
      {!timelineLoading && timelineError ? <Alert
        type="warning"
        showIcon
        message="卡片历史暂不可用"
        description={timelineError}
        action={<Button onClick={() => setTimelineRefresh((value) => value + 1)}>重新获取真实历史</Button>}
      /> : null}
      {!timelineLoading && !timelineError && cardTimeline ? <Space direction="vertical" size={16} className="full-width">
        <Descriptions bordered size="small" column={{ xs: 1, sm: 2, lg: 4 }}>
          <Descriptions.Item label="提供方引用">{cardTimeline.card.provider_ref}</Descriptions.Item>
          <Descriptions.Item label="掩码卡号">•••• {cardTimeline.card.last4}</Descriptions.Item>
          <Descriptions.Item label="品牌">{cardTimeline.card.brand}</Descriptions.Item>
          <Descriptions.Item label="当前状态"><CardStatusTag value={cardTimeline.card.status} /></Descriptions.Item>
        </Descriptions>
        <div>
          <Title level={4}>租约记录</Title>
          {cardTimeline.allocations_has_more ? <Alert
            className="section-card"
            type="info"
            showIcon
            message={`已加载 ${cardTimeline.allocations.length} 条租约记录，仍有更早历史`}
            action={<Button
              loading={timelinePageLoading === 'allocations'}
              disabled={timelinePageLoading !== null || !cardTimeline.allocations_next_cursor}
              onClick={() => loadOlderCardTimeline('allocations')}
            >加载更早租约记录</Button>}
          /> : null}
          <Table
            size="small"
            columns={allocationColumns}
            dataSource={cardTimeline.allocations}
            rowKey="id"
            pagination={false}
            locale={{ emptyText: <Empty description="暂无租约记录" /> }}
            scroll={{ x: 1400 }}
          />
        </div>
        <div>
          <Title level={4}>状态事件</Title>
          {cardTimeline.events_has_more ? <Alert
            className="section-card"
            type="info"
            showIcon
            message={`已加载 ${cardTimeline.events.length} 条状态事件，仍有更早历史`}
            action={<Button
              loading={timelinePageLoading === 'events'}
              disabled={timelinePageLoading !== null || !cardTimeline.events_next_cursor}
              onClick={() => loadOlderCardTimeline('events')}
            >加载更早状态事件</Button>}
          /> : null}
          {cardTimeline.events.length ? <Timeline items={cardTimeline.events.map((event: CardEventSummary) => ({
            color: event.action.includes('quarantined') || event.action.includes('disabled') ? 'red' : 'blue',
            children: <Space direction="vertical" size={4}>
              <Text strong>{cardEventActionNames[event.action] ?? event.action}</Text>
              <Text type="secondary">{formatLocalDateTime(event.created_at)}</Text>
              <Text>状态：{maskedStateLabel(event.before_masked)} → {maskedStateLabel(event.after_masked)}</Text>
              {event.reason_code ? <Text>原因：{cardAllocationReasonNames[event.reason_code] ?? cardQuarantineReasonNames[event.reason_code] ?? '其他受控原因'}</Text> : null}
              <Text type="secondary">操作者：<Text code>{event.actor_id ?? '系统服务'}</Text></Text>
              {event.allocation_id ? <Text type="secondary">租约：<Text code>{event.allocation_id}</Text></Text> : null}
              <Text type="secondary">Trace ID：<Text code copyable>{event.trace_id}</Text></Text>
            </Space>,
          }))} /> : <Empty description="暂无状态事件" />}
        </div>
      </Space> : null}
    </Card> : null}
    <Modal
      title={quarantineTarget ? `隔离卡 ${quarantineTarget.provider_ref}` : '隔离卡资源'}
      open={quarantineTarget !== null}
      onCancel={closeQuarantine}
      onOk={confirmQuarantine}
      okText="隔离并回收"
      okButtonProps={{ danger: true, disabled: !quarantineReason }}
      confirmLoading={quarantineSaving}
      cancelText="取消"
      destroyOnHidden
    >
      {quarantineTarget ? <Space direction="vertical" size={12} className="full-width">
        <Text>掩码卡号：•••• {quarantineTarget.last4}</Text>
        <Text>卡资源 ID：{quarantineTarget.id}</Text>
        <Text type="danger">隔离会立即阻止新的分配和揭示，释放活动租约，取消排队上传，并将运行中上传转为待人工核对。</Text>
        <Select
          aria-label="选择卡资源隔离原因"
          className="full-width"
          placeholder="选择隔离原因"
          value={quarantineReason}
          onChange={setQuarantineReason}
          options={[
            { value: 'suspected_compromise', label: '疑似信息泄露' },
            { value: 'provider_dispute', label: '提供方争议' },
            { value: 'invalid_card', label: '卡资源失效' },
            { value: 'compliance_review', label: '合规复核' },
          ]}
        />
      </Space> : null}
    </Modal>
    <Modal
      title={recycleTarget ? `回收租约 ${recycleTarget.id}` : '回收活动租约'}
      open={recycleTarget !== null}
      onCancel={closeRecycleAllocation}
      onOk={confirmRecycleAllocation}
      okText="确认回收"
      okButtonProps={{ danger: true, disabled: !recycleReason }}
      confirmLoading={recycleSaving}
      cancelText="取消"
      destroyOnHidden
    >
      {recycleTarget ? <Space direction="vertical" size={12} className="full-width">
        <Text>掩码卡号：{recycleTarget.card_masked}</Text>
        <Text>任务 ID：{recycleTarget.task_id}</Text>
        <Text type="danger">回收会阻止该租约继续使用，并取消仍在排队的关联上传；运行中上传将转为待人工核对。此操作不会影响后来创建的新租约。</Text>
        <Select
          aria-label="选择活动租约回收原因"
          className="full-width"
          placeholder="选择回收原因"
          value={recycleReason}
          onChange={setRecycleReason}
          options={[
            { value: 'manual_reassignment', label: '人工重新分配' },
            { value: 'operator_request', label: '业务方请求' },
            { value: 'duplicate_allocation', label: '重复租约' },
            { value: 'incident_response', label: '事件处置' },
          ]}
        />
      </Space> : null}
    </Modal>
  </>
}
