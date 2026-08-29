import { useCallback, useRef, useState } from 'react'
import { DownloadOutlined } from '@ant-design/icons'
import { App as AntApp, Button, Card, Input, Typography } from 'antd'
import type { TableColumnsType } from 'antd'
import { downloadAuditEvents, listAuditEvents } from '../admin-api'
import type { AuditEvent, AuditFilters } from '../types'
import { PageHeading, RemoteTable, StatusTag } from './shared'

const { Text } = Typography

export default function AuditPage() {
  const { message } = AntApp.useApp()
  const emptyFilters: AuditFilters = {
    taskId: '', cardId: '', traceId: '', actorId: '', userId: '', deviceId: '', entityType: '', entityId: '',
    eventType: '', action: '', result: '', createdFrom: '', createdTo: '',
  }
  const [filters, setFilters] = useState<AuditFilters>(emptyFilters)
  const [applied, setApplied] = useState<AuditFilters>(emptyFilters)
  const [exporting, setExporting] = useState(false)
  const exportActionRef = useRef<object | null>(null)
  const loader = useCallback(() => listAuditEvents(applied), [applied])
  const columns: TableColumnsType<AuditEvent> = [
    { title: '时间', dataIndex: 'created_at', width: 190 },
    { title: '动作', dataIndex: 'action', width: 160 },
    { title: '结果', dataIndex: 'result', width: 110, render: (value: string) => <StatusTag value={value} /> },
    { title: '事件类型', dataIndex: 'event_type', width: 170 },
    { title: '操作者', dataIndex: 'actor_id', width: 150, render: (value: string | null) => value ?? '系统' },
    { title: '关联用户', dataIndex: 'user_id', width: 150, render: (value: string | null) => value ?? '—' },
    { title: '对象', render: (_, row) => `${row.entity_type}${row.entity_id ? ` / ${row.entity_id}` : ''}` },
    { title: '策略版本', dataIndex: 'policy_version', width: 130, render: (value: string | null) => value ?? '—' },
    { title: '来源 IP', dataIndex: 'ip_address', width: 140, render: (value: string | null) => value ?? '—' },
    {
      title: '客户端', dataIndex: 'user_agent', width: 220,
      render: (value: string | null) => value
        ? <Text className="audit-user-agent" title={value}>{value}</Text>
        : '—',
    },
    { title: '追踪号', dataIndex: 'trace_id', width: 300 },
  ]

  function updateFilters(next: AuditFilters) {
    if (exportActionRef.current !== null) return
    setFilters(next)
  }

  function applyFilters() {
    if (exportActionRef.current !== null) return
    if (filters.createdFrom && filters.createdTo && filters.createdFrom > filters.createdTo) {
      message.error('开始时间不能晚于结束时间。')
      return
    }
    setApplied({ ...filters })
  }

  async function exportCsv() {
    if (exportActionRef.current !== null) return
    const action = {}
    exportActionRef.current = action
    const exportFilters = { ...applied }
    setExporting(true)
    try {
      await downloadAuditEvents(exportFilters)
      message.success('脱敏审计 CSV 已开始下载。')
    } catch {
      message.error(
        '原因：平台未能生成或传输脱敏审计 CSV。'
        + '影响：本次下载未开始，浏览器不会保留不完整报表。'
        + '下一步：检查网络并确认筛选条件后，从同一入口重试。',
      )
    } finally {
      if (exportActionRef.current === action) {
        exportActionRef.current = null
        setExporting(false)
      }
    }
  }

  return <><PageHeading title="审计中心" description="按任务、卡、用户、设备、追踪号、对象和时间范围定位全链路记录。" /><Card>
    <form className="audit-filter-form" role="search" aria-label="审计事件筛选" onSubmit={(event) => { event.preventDefault(); applyFilters() }}>
      <div className="audit-filter-grid">
        <label><span>任务 ID</span><Input disabled={exporting} placeholder="task_id" value={filters.taskId} onChange={(event) => updateFilters({ ...filters, taskId: event.target.value })} /></label>
        <label><span>卡 ID</span><Input disabled={exporting} placeholder="card_id" value={filters.cardId} onChange={(event) => updateFilters({ ...filters, cardId: event.target.value })} /></label>
        <label><span>追踪号</span><Input disabled={exporting} placeholder="trace_id" value={filters.traceId} onChange={(event) => updateFilters({ ...filters, traceId: event.target.value })} /></label>
        <label><span>操作者</span><Input disabled={exporting} placeholder="actor_id" value={filters.actorId} onChange={(event) => updateFilters({ ...filters, actorId: event.target.value })} /></label>
        <label><span>关联用户</span><Input disabled={exporting} placeholder="user_id" value={filters.userId} onChange={(event) => updateFilters({ ...filters, userId: event.target.value })} /></label>
        <label><span>设备 ID</span><Input disabled={exporting} placeholder="device_id" value={filters.deviceId} onChange={(event) => updateFilters({ ...filters, deviceId: event.target.value })} /></label>
        <label><span>对象类型</span><Input disabled={exporting} placeholder="entity_type" value={filters.entityType} onChange={(event) => updateFilters({ ...filters, entityType: event.target.value })} /></label>
        <label><span>对象 ID</span><Input disabled={exporting} placeholder="entity_id" value={filters.entityId} onChange={(event) => updateFilters({ ...filters, entityId: event.target.value })} /></label>
        <label><span>事件类型</span><Input disabled={exporting} placeholder="event_type" value={filters.eventType} onChange={(event) => updateFilters({ ...filters, eventType: event.target.value })} /></label>
        <label><span>动作</span><Input disabled={exporting} placeholder="action" value={filters.action} onChange={(event) => updateFilters({ ...filters, action: event.target.value })} /></label>
        <label><span>结果</span><Input disabled={exporting} placeholder="result" value={filters.result} onChange={(event) => updateFilters({ ...filters, result: event.target.value })} /></label>
        <label><span>开始时间</span><Input disabled={exporting} type="datetime-local" value={filters.createdFrom} onChange={(event) => updateFilters({ ...filters, createdFrom: event.target.value })} /></label>
        <label><span>结束时间</span><Input disabled={exporting} type="datetime-local" value={filters.createdTo} onChange={(event) => updateFilters({ ...filters, createdTo: event.target.value })} /></label>
      </div>
      <div className="audit-filter-actions">
        <Button type="primary" htmlType="submit" disabled={exporting}>检索</Button>
        <Button disabled={exporting} onClick={() => {
          if (exportActionRef.current !== null) return
          const empty = { ...emptyFilters }
          setFilters(empty)
          setApplied(empty)
        }}>清空</Button>
        <Button icon={<DownloadOutlined />} loading={exporting} disabled={exporting} onClick={exportCsv}>导出脱敏 CSV</Button>
        <Text type="secondary">导出使用当前已应用筛选，且不包含自由格式详情或原始敏感值。</Text>
      </div>
    </form>
    <RemoteTable loader={loader} columns={columns} empty="暂无审计事件" />
  </Card></>
}
