import { useEffect, useRef, useState } from 'react'
import { Alert, App as AntApp, Button, Card, Col, Descriptions, Empty, Form, Input, InputNumber, Modal, Row, Space, Spin, Table, Select, Timeline, Typography } from 'antd'
import type { TableColumnsType } from 'antd'
import { createCard, getCardTimeline, listCards, quarantineCard, recycleCardAllocation, releaseCardQuarantine, updateCardState } from '../admin-api'
import type { CardAllocationSummary, CardCreate, CardEventSummary, CardSummary, CardTimeline } from '../types'
import { useScopedConfirm } from '../useScopedConfirm'
import { CardStatusTag, StatusTag, cardAllocationReasonNames, cardEventActionNames, cardQuarantineReasonNames, compareTableText, formatLocalDateTime, maskedStateLabel } from './shared'

const { Title, Text } = Typography

export default function CardsPage({ canManage, canReleaseQuarantine }: {
  canManage: boolean
  canReleaseQuarantine: boolean
}) {
  const { message } = AntApp.useApp()
  const confirm = useScopedConfirm()
  const [rows, setRows] = useState<CardSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [cardListError, setCardListError] = useState<string>()
  const [refresh, setRefresh] = useState(0)
  const [createOpen, setCreateOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const [quarantineTarget, setQuarantineTarget] = useState<CardSummary | null>(null)
  const [quarantineReason, setQuarantineReason] = useState<string>()
  const [quarantineSaving, setQuarantineSaving] = useState(false)
  const cardCreatePendingRef = useRef(false)
  const [cardActionId, setCardActionId] = useState<string | null>(null)
  const cardActionRef = useRef<{ cardId: string; pending: boolean } | null>(null)
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
  const [form] = Form.useForm<CardCreate>()

  function refreshCardsFromServer() {
    setLoading(true)
    setCardListError(undefined)
    setRows([])
    setRefresh((value) => value + 1)
  }

  useEffect(() => {
    let alive = true
    setLoading(true)
    setCardListError(undefined)
    setRows([])
    listCards().then((items) => { if (alive) setRows(items) })
      .catch(() => {
        if (alive) {
          setSelectedCardId(null)
          setCardTimeline(null)
          setCardListError(
            '原因：平台未能读取卡资源真实状态。'
            + '影响：旧卡记录和启用、停用操作已隐藏，卡租约与关联上传状态无法安全确认。'
            + '下一步：请重新获取真实状态；成功前不要重复启用或停用卡资源。',
          )
        }
      })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [refresh])

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
      if (mismatched) throw new Error('平台返回的卡片历史绑定关系无效。')
      if (alive && timelineGenerationRef.current === generation) setCardTimeline(result)
    }).catch((error) => {
      if (alive && timelineGenerationRef.current === generation) {
        const reason = error instanceof Error ? error.message : '平台未能读取卡片历史。'
        setTimelineError(
          `原因：${reason} `
          + '影响：旧分配历史和回收入口已隐藏，当前租约状态无法安全确认。 '
          + '下一步：请重新获取真实历史；成功前不要回收租约。',
        )
      }
    }).finally(() => {
      if (alive && timelineGenerationRef.current === generation) setTimelineLoading(false)
    })
    return () => {
      alive = false
      timelineGenerationRef.current += 1
    }
  }, [refresh, selectedCardId, timelineRefresh])

  async function submitCard(values: CardCreate) {
    if (cardCreatePendingRef.current) return
    cardCreatePendingRef.current = true
    setSaving(true)
    try {
      await createCard(values)
      message.success('卡资源已登记。')
      form.resetFields()
      setCreateOpen(false)
      refreshCardsFromServer()
    } catch (error) {
      message.error(error instanceof Error ? error.message : '卡资源登记失败')
    } finally {
      cardCreatePendingRef.current = false
      setSaving(false)
    }
  }

  function closeCreateCard() {
    form.resetFields()
    setCreateOpen(false)
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
      await updateCardState(row.id, isActive)
      message.success(isActive ? '卡资源已启用。' : '卡资源已停用，活动租约已释放。')
    } catch (error) {
      const reason = error instanceof Error ? error.message : '平台未能确认卡资源状态。'
      message.error(
        `原因：${reason} `
        + '影响：平台可能已完成卡状态切换和关联资源回收，页面不会按失败响应推断结果。 '
        + '下一步：已刷新卡资源真实状态；若目标状态未生效，可从同一入口重试。',
      )
    } finally {
      refreshCardsFromServer()
      releaseCardAction(action)
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
      await quarantineCard(row.id, quarantineReason)
      message.success('卡资源已隔离，活动租约及关联资源已回收。')
      setQuarantineTarget(null)
      setQuarantineReason(undefined)
    } catch (error) {
      const reason = error instanceof Error ? error.message : '平台未能确认卡资源隔离状态。'
      message.error(
        `原因：${reason} `
        + '影响：平台可能已完成隔离和关联资源回收，页面不会按失败响应推断结果。 '
        + '下一步：已刷新卡资源真实状态；若仍未隔离，可从同一入口重试。',
      )
    } finally {
      setQuarantineSaving(false)
      refreshCardsFromServer()
      releaseCardAction(action)
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
          await releaseCardQuarantine(row.id)
          message.success('隔离已解除；卡资源仍处于停用状态。')
        } catch (error) {
          message.error(error instanceof Error ? error.message : '解除隔离失败')
        } finally {
          refreshCardsFromServer()
          releaseCardAction(action)
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
      if (mismatched) throw new Error('平台返回的卡片历史绑定关系无效。')
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
        message.error(error instanceof Error ? error.message : '更早的卡片历史读取失败')
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
      await recycleCardAllocation(allocation.card_id, allocation.id, recycleReason)
      message.success('活动租约已回收；关联排队上传已取消。')
      setRecycleTarget(null)
      setRecycleReason(undefined)
    } catch (error) {
      const reason = error instanceof Error ? error.message : '平台未能确认租约回收状态。'
      message.error(
        `原因：${reason} `
        + '影响：回收屏障可能已经生效，页面不会按失败响应推断最终状态。 '
        + '下一步：已重新获取卡片历史；若租约仍为活动状态，可从同一记录重试。',
      )
    } finally {
      setRecycleSaving(false)
      refreshCardsFromServer()
      releaseCardAction(action)
    }
  }

  const columns: TableColumnsType<CardSummary> = [
    { title: '提供方引用', dataIndex: 'provider_ref', sorter: (left, right) => compareTableText(left.provider_ref, right.provider_ref) },
    { title: '卡池', dataIndex: 'pool_key', sorter: (left, right) => compareTableText(left.pool_key, right.pool_key) },
    { title: '地区', dataIndex: 'region', sorter: (left, right) => compareTableText(left.region, right.region) },
    { title: '品牌', dataIndex: 'brand', sorter: (left, right) => compareTableText(left.brand, right.brand) },
    { title: '尾号', dataIndex: 'last4', render: (value: string) => `•••• ${value}` },
    { title: '有效期', render: (_, row) => row.expiry_month && row.expiry_year ? `${String(row.expiry_month).padStart(2, '0')}/${row.expiry_year}` : '—' },
    {
      title: '状态', dataIndex: 'status',
      filters: [
        { text: '可用', value: 'available' },
        { text: '已分配', value: 'allocated' },
        { text: '已停用', value: 'disabled' },
        { text: '已隔离', value: 'quarantined' },
      ],
      onFilter: (value, row) => row.status === value,
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
    <div className="page-heading"><div><Title level={2}>卡池管理</Title><Text type="secondary">登记接口不接收 PAN/CVV；PAN 保存在 Vault 且仅经 step-up 揭示，CVV 默认不返回。</Text></div>{canManage ? <Button type="primary" onClick={() => setCreateOpen(true)}>登记卡资源</Button> : null}</div>
    <Alert className="section-card" type="info" showIcon message="敏感卡信息必须保存在服务端密钥管理器" description="生产环境必须填写 vault://secret/cards/ 引用；env:// 仅限开发和测试。停用会释放活动租约，取消排队上传，并将运行中上传转为待人工核对。" />
    <Card className="section-card">{loading ? <div className="centered"><Spin /></div> : cardListError ? <Alert
      type="warning"
      showIcon
      message="卡资源列表暂不可用"
      description={cardListError}
      action={<Button onClick={refreshCardsFromServer}>重新获取卡资源真实状态</Button>}
    /> : <Table columns={columns} dataSource={rows} rowKey="id" locale={{ emptyText: <Empty description="暂无卡资源" /> }} scroll={{ x: 1100 }} />}</Card>
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
    <Modal title="登记卡资源" open={createOpen} onCancel={closeCreateCard} onOk={() => form.submit()} confirmLoading={saving} okText="登记" cancelText="取消" destroyOnHidden>
      <Form form={form} layout="vertical" onFinish={submitCard} requiredMark="optional">
        <Form.Item label="提供方引用" name="provider_ref" rules={[{ required: true }, { max: 160 }]}><Input autoComplete="off" placeholder="provider-card-001" /></Form.Item>
        <Row gutter={12}>
          <Col span={12}><Form.Item label="卡池" name="pool_key" rules={[{ required: true }, { pattern: /^[a-z0-9][a-z0-9._-]{0,79}$/, message: '使用小写字母、数字、点、横线或下划线' }]}><Input placeholder="checkout-cn" /></Form.Item></Col>
          <Col span={12}><Form.Item label="地区" name="region" rules={[{ required: true }, { pattern: /^[a-z0-9][a-z0-9._-]{0,79}$/, message: '使用小写字母、数字、点、横线或下划线' }]}><Input placeholder="cn-east" /></Form.Item></Col>
        </Row>
        <Row gutter={12}>
          <Col span={12}><Form.Item label="品牌" name="brand" rules={[{ required: true }, { max: 40 }]}><Input placeholder="VISA" /></Form.Item></Col>
          <Col span={12}><Form.Item label="尾号" name="last4" rules={[{ required: true }, { pattern: /^\d{4}$/, message: '必须是 4 位数字' }]}><Input inputMode="numeric" maxLength={4} placeholder="4242" /></Form.Item></Col>
          <Col span={12}><Form.Item label="有效期月份" name="expiry_month" dependencies={['expiry_year']} rules={[({ getFieldValue }) => ({ validator(_, value) { return (value == null) === (getFieldValue('expiry_year') == null) ? Promise.resolve() : Promise.reject(new Error('月份和年份须同时填写')) } })]}><InputNumber min={1} max={12} className="full-width" placeholder="12" /></Form.Item></Col>
          <Col span={12}><Form.Item label="有效期年份" name="expiry_year" dependencies={['expiry_month']} rules={[({ getFieldValue }) => ({ validator(_, value) { return (value == null) === (getFieldValue('expiry_month') == null) ? Promise.resolve() : Promise.reject(new Error('月份和年份须同时填写')) } })]}><InputNumber min={2000} max={9999} className="full-width" placeholder="2030" /></Form.Item></Col>
        </Row>
        <Form.Item label="密钥引用" name="secret_ref" extra="生产必须使用 vault://secret/cards/；env:// 仅限开发/测试。请勿粘贴卡号或安全码。" rules={[{ required: true }, { pattern: /^(vault:\/\/secret\/cards\/|env:\/\/)[A-Za-z0-9][A-Za-z0-9._/-]*$/, message: '生产使用 vault://secret/cards/；env:// 仅限开发/测试' }]}><Input.Password autoComplete="new-password" visibilityToggle={false} placeholder="vault://secret/cards/provider-card-001" /></Form.Item>
      </Form>
    </Modal>
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
