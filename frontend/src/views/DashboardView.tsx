import { useEffect, useState } from 'react'
import { Alert, Button, Card, Col, Descriptions, Empty, Row, Space, Spin, Statistic, Table } from 'antd'
import type { TableColumnsType } from 'antd'
import { getDashboardSummary } from '../admin-api'
import type { DashboardSummary, Principal } from '../types'
import { PageHeading, StatusTag, cardAllocationReasonNames, formatLocalDateTime, statusRows } from './shared'

export default function Dashboard({ principal }: { principal: Principal }) {
  const [summary, setSummary] = useState<DashboardSummary>()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [refreshGeneration, setRefreshGeneration] = useState(0)
  useEffect(() => {
    let alive = true
    setLoading(true)
    setError(undefined)
    getDashboardSummary().then((value) => {
      if (alive) {
        setSummary(value)
        setError(undefined)
      }
    }).catch(() => {
      if (alive) setError('运行摘要暂不可用，请稍后刷新。')
    }).finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [refreshGeneration])
  const statusColumns: TableColumnsType<{ status: string; count: number }> = [
    { title: '状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: '分配原因', dataIndex: 'allocation_reason_code', render: (value: string) => cardAllocationReasonNames[value] ?? '其他受控原因' },
    { title: '数量', dataIndex: 'count', align: 'right' },
  ]
  if (loading) return <div className="centered"><Spin /></div>
  if (error || !summary) return <Alert
    type="warning"
    showIcon
    message="工作台暂不可用"
    description="原因：平台暂未返回运行摘要。影响：当前指标和风险提示不会使用过期数据。下一步：检查网络后从此处重新加载。"
    action={<Button onClick={() => setRefreshGeneration((value) => value + 1)}>重新加载工作台</Button>}
  />
  const todayTasks = summary.today_tasks ?? 0
  const pendingExceptions = summary.pending_exceptions ?? summary.unknown_uploads
  const todaySucceededUploads = summary.today_succeeded_uploads ?? 0
  const todayCompletedUploads = summary.today_completed_uploads ?? 0
  const uploadSuccessRate = todayCompletedUploads > 0
    ? Math.round((todaySucceededUploads / todayCompletedUploads) * 100)
    : null
  const unavailableMailboxes = summary.unavailable_mailboxes ?? 0
  const recentTasks = summary.recent_tasks ?? []
  const tenantScope = summary.scope === 'tenant'
  const riskAlerts = [
    summary.unknown_uploads > 0 ? <Alert
      key="unknown-uploads"
      type="warning"
      showIcon
      message={`${summary.unknown_uploads} 个上传结果需要人工核对`}
      description={principal.role === 'operator'
        ? '请在任务中心记录关联 trace_id，并联系运营管理员核对；平台不会自动重试。'
        : '请到 Sub2 上传页核对外部结果；平台不会自动重试。'}
    /> : null,
    unavailableMailboxes > 0 ? <Alert
      key="unavailable-mailboxes"
      type="error"
      showIcon
      message={`${unavailableMailboxes} 个邮箱连接器不可用`}
      description="相关验证码任务可能无法继续，请检查连接器健康状态并恢复服务。"
    /> : null,
    tenantScope && summary.available_cards === 0 ? <Alert
      key="no-available-cards"
      type="warning"
      showIcon
      message="卡池暂无可用卡"
      description="新任务将无法分配卡，请释放占用、解除隔离或补充可用卡。"
    /> : null,
  ].filter((alert): alert is React.ReactElement => alert !== null)
  return <>
    <PageHeading title="工作台" description="关注正在运行的业务与需要人工处理的异常。" />
    <section aria-label="工作台关键指标">
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} xl={6}><Card><Statistic title="今日任务" value={todayTasks} /></Card></Col>
        <Col xs={24} sm={12} xl={6}><Card><Statistic title="待处理异常" value={pendingExceptions} /></Card></Col>
        <Col xs={24} sm={12} xl={6}><Card><Statistic title="上传成功率" value={uploadSuccessRate ?? '—'} suffix={uploadSuccessRate === null ? undefined : '%'} /></Card></Col>
        <Col xs={24} sm={12} xl={6}><Card><Statistic title="卡池可用" value={summary.available_cards ?? '—'} /></Card></Col>
      </Row>
    </section>
    <section aria-label="工作台风险提示" className="section-card">
      <Space direction="vertical" size="middle" className="full-width">
        {riskAlerts}
      </Space>
    </section>
    <Card className="section-card" title="最近任务">
      <section aria-label="最近任务">
        <Table
          size="small"
          columns={[
            { title: '任务 ID', dataIndex: 'id' },
            { title: '类型', dataIndex: 'type' },
            { title: '状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
            { title: 'Trace ID', dataIndex: 'trace_id' },
            { title: '创建时间', dataIndex: 'created_at', render: formatLocalDateTime },
          ]}
          dataSource={recentTasks}
          rowKey="id"
          pagination={false}
          scroll={{ x: 720 }}
          locale={{ emptyText: <Empty description="暂无最近任务" /> }}
        />
      </section>
    </Card>
    <Card className="section-card" title="当前运行情况">
      <Descriptions size="small" column={{ xs: 1, md: 2 }}>
        <Descriptions.Item label="统计范围">{tenantScope ? '当前租户' : '当前设备'}</Descriptions.Item>
        <Descriptions.Item label="生成时间">{formatLocalDateTime(summary.generated_at)}</Descriptions.Item>
        <Descriptions.Item label="等待验证码邮箱">{summary.waiting_mail_sessions}</Descriptions.Item>
      </Descriptions>
      <Row gutter={[16, 16]} className="section-card">
        <Col xs={24} lg={12}>
          <Table
            size="small"
            columns={statusColumns}
            dataSource={statusRows(summary.task_statuses)}
            rowKey="status"
            pagination={false}
            locale={{ emptyText: <Empty description="暂无任务状态" /> }}
          />
        </Col>
        <Col xs={24} lg={12}>
          <Table
            size="small"
            columns={statusColumns}
            dataSource={statusRows(summary.upload_statuses)}
            rowKey="status"
            pagination={false}
            locale={{ emptyText: <Empty description="暂无上传状态" /> }}
          />
        </Col>
      </Row>
    </Card>
  </>
}
