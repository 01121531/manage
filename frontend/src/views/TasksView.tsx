import { useEffect, useRef, useState } from 'react'
import { CheckCircleOutlined, ClockCircleOutlined, ExclamationCircleOutlined, LoadingOutlined } from '@ant-design/icons'
import { Alert, App as AntApp, Button, Card, Col, Descriptions, Empty, Input, Row, Space, Spin, Steps, Table, Tag, Select, Timeline, Typography } from 'antd'
import type { StepsProps, TableColumnsType } from 'antd'
import { closeTask, getTaskTimeline, listTasks } from '../admin-api'
import type { TaskListFilters } from '../admin-api'
import type { Principal, TaskSummary, TaskTimeline } from '../types'
import { useScopedConfirm } from '../useScopedConfirm'
import { PageHeading, StatusTag, formatLocalDateTime, taskEventNames, terminalTaskStatuses, uploadPhaseNames } from './shared'

const { Text } = Typography

const OPERATOR_TASK_REFRESH_MS = 5_000

function operatorTaskStepItems(task: TaskSummary, timeline: TaskTimeline): NonNullable<StepsProps['items']> {
  const allocation = timeline.card_allocations[timeline.card_allocations.length - 1]
  const mailSession = timeline.mail_session
  const upload = timeline.uploads[timeline.uploads.length - 1]
  const mailReceived = mailSession?.status === 'code_ready' || mailSession?.status === 'consumed'
  const mailConsumed = mailSession?.status === 'consumed' || mailSession?.consumed_at !== null
  const fallbackStep = task.status === 'completed' || upload?.status === 'succeeded' ? 'completed'
    : upload ? 'uploading'
      : mailConsumed ? 'code_received'
        : mailSession ? 'waiting_code'
          : allocation ? 'card_allocated' : 'logged_in'
  const canonicalStep = timeline.workbench_step ?? fallbackStep
  const currentStep = {
    logged_in: 0,
    card_allocated: 1,
    waiting_code: 2,
    code_received: 3,
    uploading: 4,
    completed: 5,
  }[canonicalStep]
  let currentStatus: 'process' | 'finish' | 'error' = 'process'

  if (task.status === 'completed' || upload?.status === 'succeeded') {
    currentStatus = 'finish'
  } else if (upload) {
    currentStatus = upload.status === 'failed' ? 'error' : 'process'
  }

  if (terminalTaskStatuses.has(task.status) && task.status !== 'completed') {
    currentStatus = 'error'
  }

  const descriptions = [
    '当前设备会话有效',
    allocation ? `${allocation.brand} · ${allocation.card_masked}` : '等待平台分配掩码卡',
    mailSession
      ? mailSession.status === 'initializing' ? '邮箱已绑定，正在初始化'
        : mailReceived ? '验证码已到达' : mailSession.status === 'waiting' ? '邮箱已绑定，正在等待' : '邮箱会话已结束'
      : '等待绑定邮箱',
    mailConsumed ? '验证码已安全获取' : mailReceived ? '验证码已到达，等待安全获取' : '尚未获取验证码',
    upload
      ? upload.status === 'unknown' ? '结果待人工核对'
        : upload.status === 'failed' ? '上传已明确失败'
          : upload.status === 'succeeded' ? '上传已确认成功' : '上传作业处理中'
      : '尚未提交上传',
    task.status === 'completed' || upload?.status === 'succeeded'
      ? '任务已完成'
      : terminalTaskStatuses.has(task.status) ? `任务已结束（${task.status}）` : '等待确认终态',
  ]
  const titles = ['已登录', '已分配卡', '等待验证码', '已获取', '上传中', '完成']

  return titles.map((title, index) => {
    const status = index < currentStep ? 'finish'
      : index > currentStep ? 'wait'
        : currentStatus
    return {
      title: <span aria-current={index === currentStep ? 'step' : undefined}>{title}</span>,
      description: descriptions[index],
      status,
    }
  })
}

function operatorMailState(mailSession: TaskTimeline['mail_session']) {
  if (!mailSession) return <Tag icon={<ClockCircleOutlined />}>未绑定</Tag>
  if (mailSession.status === 'code_ready' || mailSession.status === 'consumed') {
    return <Tag color="green" icon={<CheckCircleOutlined />}>已收到验证码</Tag>
  }
  if (mailSession.status === 'initializing') {
    return <Tag color="blue" icon={<LoadingOutlined />}>已绑定</Tag>
  }
  if (mailSession.status === 'waiting') {
    return <Tag color="blue" icon={<LoadingOutlined />}>等待验证码</Tag>
  }
  return <Tag icon={<ClockCircleOutlined />}>会话已结束</Tag>
}

function OperatorTaskWorkbench({
  tasks,
  activeTasks,
  currentTask,
  timeline,
  timelineLoading,
  timelineError,
  closingTaskId,
  onClose,
  onRetryTimeline,
}: {
  tasks: TaskSummary[]
  activeTasks: TaskSummary[]
  currentTask: TaskSummary | null
  timeline: TaskTimeline | undefined
  timelineLoading: boolean
  timelineError: boolean
  closingTaskId: string | null
  onClose: (task: TaskSummary) => void
  onRetryTimeline: () => void
}) {
  const allocation = timeline?.card_allocations[timeline.card_allocations.length - 1]
  const upload = timeline?.uploads[timeline.uploads.length - 1]
  const historyColumns: TableColumnsType<TaskSummary> = [
    { title: '任务 ID', dataIndex: 'id', render: (value: string) => <Text code copyable={{ text: value }}>{value}</Text> },
    { title: '类型', dataIndex: 'type' },
    { title: '状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: 'trace_id', dataIndex: 'trace_id', render: (value: string) => <Text code copyable={{ text: value }}>{value}</Text> },
    { title: '创建时间', dataIndex: 'created_at', render: formatLocalDateTime },
  ]
  const uploadRecovery = !upload ? <Alert
    type="info"
    showIcon
    message="尚未提交上传"
    description="完成验证码获取后，继续从受控客户端提交；此页面不接收 Sub2 内部配置。"
  /> : upload.status === 'unknown' ? <Alert
    type="warning"
    showIcon
    message="上传结果待人工核对"
    description="原因：外部结果不明确。影响：任务保持待核对状态。下一步：记录 trace_id 并联系运营管理员核对；平台不会自动重试。"
  /> : upload.status === 'failed' ? <Alert
    type="error"
    showIcon
    message="上传已明确失败"
    description={`原因：${upload.error_code ?? '上游明确拒绝'}。影响：本次上传未完成。下一步：保留当前 trace_id，并联系运营管理员确认后续处理。`}
  /> : upload.status === 'succeeded' ? <Alert
    type="success"
    showIcon
    message="上传已确认成功"
    description="任务资源将按终态流程回收，无需重复提交。"
  /> : <Alert
    type="info"
    showIcon
    message="上传作业处理中"
    description="平台已受理当前作业，请等待真实终态；请求处理中不要重复提交。"
  />

  return <div className="operator-workbench">
    {activeTasks.length > 1 ? <Alert
      className="section-card"
      type="error"
      showIcon
      message="检测到多个进行中任务"
      description="原因：任务状态与平台单活动任务约束不一致。影响：页面不会静默选择其中一个任务。下一步：请记录任务 ID 并联系运营管理员核对。"
    /> : null}
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={6}>
        <Card className="full-width" title="当前任务进度">
          <section aria-label="当前任务进度">
            {currentTask && timeline ? <Steps
              direction="vertical"
              size="small"
              items={operatorTaskStepItems(currentTask, timeline)}
            /> : currentTask && timelineError ? <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description="任务进度暂不可用"
            /> : currentTask ? <div className="operator-workbench-loading"><Spin /></div> : <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description={activeTasks.length > 1 ? '等待任务状态核对' : '当前设备没有进行中任务'}
            />}
          </section>
        </Card>
      </Col>
      <Col xs={24} md={12} lg={10}>
        <Card className="full-width" title="资源状态">
          <section aria-label="当前任务资源">
            {currentTask && timeline ? <>
              <Descriptions column={1} size="small">
                <Descriptions.Item label="任务 ID">{currentTask.id}</Descriptions.Item>
                <Descriptions.Item label="邮箱状态">
                  <Space wrap>
                    {operatorMailState(timeline.mail_session)}
                    <Text>{timeline.mail_session?.email_masked ?? '未绑定'}</Text>
                  </Space>
                </Descriptions.Item>
                <Descriptions.Item label="卡状态">
                  {allocation ? <Space wrap>
                    <Text>{allocation.brand}</Text>
                    <Text className="tabular-value">{allocation.card_masked}</Text>
                    <StatusTag value={allocation.status} />
                  </Space> : '未分配'}
                </Descriptions.Item>
              </Descriptions>
              <Alert
                className="section-card"
                type="info"
                showIcon
                message="敏感字段保持掩码"
                description="此 Web 工作台不读取或持久化验证码、完整卡号或密钥引用；临时揭示只在受控客户端完成。"
              />
            </> : currentTask && timelineError ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="资源状态暂不可用" />
              : currentTask ? <div className="operator-workbench-loading"><Spin /></div>
                : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无当前任务资源" />}
          </section>
        </Card>
      </Col>
      <Col xs={24} md={12} lg={8}>
        <Card className="full-width" title="上传与恢复">
          <section aria-label="上传与恢复">
            {currentTask ? <Space direction="vertical" size="middle" className="full-width">
              <Descriptions column={1} size="small">
                <Descriptions.Item label="任务状态"><StatusTag value={timeline?.task.status ?? currentTask.status} /></Descriptions.Item>
                <Descriptions.Item label="上传状态">{timeline ? upload ? <StatusTag value={upload.status} /> : '尚未提交' : '读取中'}</Descriptions.Item>
                <Descriptions.Item label="trace_id">
                  <Text className="operator-trace" code copyable={{ text: currentTask.trace_id }}>{currentTask.trace_id}</Text>
                </Descriptions.Item>
              </Descriptions>
              {timelineError ? <Alert
                type="error"
                showIcon
                message="当前资源状态暂不可用"
                description="原因：资源时间线读取失败。影响：页面不会根据旧数据给出恢复动作。下一步：请检查网络后从此处重新加载。"
                action={<Button onClick={onRetryTimeline}>重新加载当前任务资源</Button>}
              /> : timelineLoading || !timeline ? <div className="operator-workbench-loading"><Spin /></div> : uploadRecovery}
              <Button
                danger
                aria-label="关闭当前任务并清理资源"
                loading={closingTaskId === currentTask.id}
                disabled={terminalTaskStatuses.has(currentTask.status) || closingTaskId !== null}
                onClick={() => onClose(currentTask)}
              >关闭任务并清理资源</Button>
            </Space> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无上传状态" />}
          </section>
        </Card>
      </Col>
    </Row>
    <section aria-label="任务历史与安全提示" className="section-card">
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={15}>
          <Card title="任务历史">
            <Table
              size="small"
              columns={historyColumns}
              dataSource={tasks}
              rowKey="id"
              pagination={false}
              scroll={{ x: 720 }}
              locale={{ emptyText: <Empty description="暂无任务历史" /> }}
            />
          </Card>
        </Col>
        <Col xs={24} lg={9}>
          <Card title="操作历史与安全提示">
            <Alert
              type="info"
              showIcon
              message="临时敏感值不会进入此页面"
              description="验证码和完整卡号不写入浏览器存储；超时、失焦、锁定或注销后，受控客户端会清空临时值。"
            />
            <div className="task-lifecycle">
              <Text strong>当前任务事件</Text>
              {timeline?.events.length ? <Timeline items={timeline.events.map((event) => ({
                color: event.result === 'success' ? 'green' : event.result === 'unknown' ? 'orange' : event.result === 'failed' || event.result === 'denied' ? 'red' : 'blue',
                dot: event.result === 'success' ? <CheckCircleOutlined /> : event.result === 'unknown' || event.result === 'failed' || event.result === 'denied' ? <ExclamationCircleOutlined /> : <LoadingOutlined />,
                children: <Space direction="vertical" size={2}>
                  <Space wrap><Text strong>{taskEventNames[event.event_type] ?? event.event_type}</Text><StatusTag value={event.result} /></Space>
                  <Text type="secondary">{formatLocalDateTime(event.created_at)} · {event.entity_type}</Text>
                </Space>,
              }))} /> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无当前任务事件" />}
            </div>
          </Card>
        </Col>
      </Row>
    </section>
  </div>
}

export default function TasksPage({ principal }: { principal: Principal }) {
  const { message } = AntApp.useApp()
  const confirm = useScopedConfirm()
  const [rows, setRows] = useState<TaskSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [taskListError, setTaskListError] = useState<string>()
  const [refresh, setRefresh] = useState(0)
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null)
  const [taskTimeline, setTaskTimeline] = useState<TaskTimeline>()
  const [timelineLoading, setTimelineLoading] = useState(false)
  const [timelineError, setTimelineError] = useState(false)
  const [closingTaskId, setClosingTaskId] = useState<string | null>(null)
  const [draftFilters, setDraftFilters] = useState<TaskListFilters>({})
  const [taskFilters, setTaskFilters] = useState<TaskListFilters>({})
  const taskCloseActionRef = useRef<{ taskId: string; pending: boolean } | null>(null)
  const taskCloseRefreshRef = useRef<{
    action: { taskId: string; pending: boolean }
    waitForTimeline: boolean
    taskListSettled: boolean
    timelineSettled: boolean
  } | null>(null)
  const taskListGenerationRef = useRef(0)
  const timelineRequestGenerationRef = useRef(0)
  const taskListRequestsInFlightRef = useRef(0)
  const timelineRequestsInFlightRef = useRef(0)
  const operatorAutoRefreshPendingRef = useRef(false)
  const taskListLoadedRef = useRef(false)
  const isOpsAdmin = principal.role === 'ops_admin'

  function settleTaskCloseRefresh(
    kind: 'task-list' | 'timeline',
    barrier: NonNullable<typeof taskCloseRefreshRef.current> | null,
  ) {
    if (!barrier || taskCloseRefreshRef.current !== barrier) return
    if (kind === 'task-list') barrier.taskListSettled = true
    if (kind === 'timeline' && barrier.waitForTimeline) barrier.timelineSettled = true
    if (!barrier.taskListSettled || !barrier.timelineSettled) return
    taskCloseRefreshRef.current = null
    if (taskCloseActionRef.current === barrier.action) taskCloseActionRef.current = null
    setClosingTaskId((current) => current === barrier.action.taskId ? null : current)
  }

  function applyTaskFilters(nextFilters: TaskListFilters) {
    taskListLoadedRef.current = false
    setLoading(true)
    setRows([])
    setTaskListError(undefined)
    clearTaskDetail()
    setTaskFilters(nextFilters)
    setRefresh((value) => value + 1)
  }

  function clearTaskDetail() {
    timelineRequestGenerationRef.current += 1
    setSelectedTaskId(null)
    setTaskTimeline(undefined)
    setTimelineError(false)
    setTimelineLoading(false)
  }

  useEffect(() => {
    let alive = true
    const generation = taskListGenerationRef.current + 1
    const closeRefresh = taskCloseRefreshRef.current
    taskListGenerationRef.current = generation
    const showInitialLoading = !taskListLoadedRef.current
    taskListRequestsInFlightRef.current += 1
    if (showInitialLoading) {
      setLoading(true)
      setTaskListError(undefined)
    }
    listTasks(taskFilters).then((items) => {
      if (alive) {
        setRows(items)
        setTaskListError(undefined)
        if (isOpsAdmin) {
          setSelectedTaskId((current) => current && items.some((item) => item.id === current) ? current : null)
        } else {
          const activeItems = items.filter((item) => !terminalTaskStatuses.has(item.status))
          setSelectedTaskId(activeItems.length === 1 ? activeItems[0].id : null)
        }
      }
    })
      .catch(() => {
        if (alive) setTaskListError(
          '原因：任务列表真实状态刷新失败。'
          + '影响：旧任务、详情和操作已隐藏，当前筛选结果与任务终态均无法安全确认。'
          + '下一步：请检查网络后重新应用筛选；在真实状态恢复前不要重复关闭任务。',
        )
      })
      .finally(() => {
        taskListRequestsInFlightRef.current = Math.max(0, taskListRequestsInFlightRef.current - 1)
        taskListLoadedRef.current = true
        if (alive) {
          if (showInitialLoading) setLoading(false)
          settleTaskCloseRefresh('task-list', closeRefresh)
        }
      })
    return () => {
      alive = false
    }
  }, [isOpsAdmin, message, refresh, taskFilters])
  const selectedTask = selectedTaskId
    ? rows.find((row) => row.id === selectedTaskId) ?? null
    : null
  useEffect(() => {
    if (!loading && selectedTaskId !== null && selectedTask === null) clearTaskDetail()
  }, [loading, selectedTask, selectedTaskId])
  useEffect(() => {
    const requestGeneration = timelineRequestGenerationRef.current + 1
    const closeRefresh = taskCloseRefreshRef.current
    timelineRequestGenerationRef.current = requestGeneration
    if (!selectedTaskId) {
      setTaskTimeline(undefined)
      setTimelineError(false)
      setTimelineLoading(false)
      operatorAutoRefreshPendingRef.current = false
      return
    }
    const requestedTaskId = selectedTaskId
    let alive = true
    timelineRequestsInFlightRef.current += 1
    setTaskTimeline(undefined)
    setTimelineError(false)
    setTimelineLoading(true)
    getTaskTimeline(requestedTaskId).then((value) => {
      if (!alive || timelineRequestGenerationRef.current !== requestGeneration) return
      if (value.task.id !== requestedTaskId) {
        setTimelineError(true)
        return
      }
      setTaskTimeline(value)
    }).catch(() => {
      if (alive && timelineRequestGenerationRef.current === requestGeneration) setTimelineError(true)
    }).finally(() => {
      timelineRequestsInFlightRef.current = Math.max(0, timelineRequestsInFlightRef.current - 1)
      operatorAutoRefreshPendingRef.current = false
      if (alive && timelineRequestGenerationRef.current === requestGeneration) {
        setTimelineLoading(false)
        settleTaskCloseRefresh('timeline', closeRefresh)
      }
    })
    return () => {
      alive = false
    }
  }, [selectedTaskId, refresh])
  useEffect(() => {
    if (isOpsAdmin) return
    const timer = window.setInterval(() => {
      if (
        document.visibilityState !== 'visible'
        || taskCloseActionRef.current !== null
        || taskListRequestsInFlightRef.current > 0
        || timelineRequestsInFlightRef.current > 0
        || operatorAutoRefreshPendingRef.current
      ) return
      operatorAutoRefreshPendingRef.current = true
      setRefresh((value) => value + 1)
    }, OPERATOR_TASK_REFRESH_MS)
    return () => {
      window.clearInterval(timer)
      operatorAutoRefreshPendingRef.current = false
    }
  }, [isOpsAdmin])
  const visibleTaskTimeline = selectedTask && taskTimeline?.task.id === selectedTask.id
    ? taskTimeline
    : undefined
  const statusFilters = [...new Set(rows.map((row) => row.status))]
    .sort()
    .map((status) => ({ text: status, value: status }))
  function confirmCloseTask(row: TaskSummary) {
    if (taskCloseActionRef.current) return
    const action = { taskId: row.id, pending: false }
    taskCloseActionRef.current = action
    confirm({
      title: `确认关闭任务 ${action.taskId}？`,
      content: <Space direction="vertical" size={8}>
        <Text>任务 ID：{action.taskId}</Text>
        <Text type="danger">关闭后任务不可恢复，卡租约会释放，邮箱会话和未消费验证码会立即清理。</Text>
        <Text type="secondary">排队上传将取消；运行中上传会转为待取消并保留核对链路。</Text>
      </Space>,
      okText: '关闭任务并回收资源',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onCancel: () => {
        if (taskCloseActionRef.current === action && !action.pending) taskCloseActionRef.current = null
      },
      onOk: async () => {
        if (taskCloseActionRef.current !== action || action.pending) return
        action.pending = true
        setClosingTaskId(action.taskId)
        try {
          const closed = await closeTask(action.taskId)
          if (
            closed.id !== action.taskId
            || closed.tenant_id !== row.tenant_id
            || closed.trace_id !== row.trace_id
            || closed.status !== 'closed'
            || closed.closed_at === null
          ) {
            throw new Error('task close response binding mismatch')
          }
          message.success('任务已关闭，相关卡租约、邮箱会话和上传资源已回收。')
        } catch {
          message.error(
            '原因：平台未能确认任务关闭结果。'
            + '影响：关闭与卡、邮箱、上传资源回收可能已完成，页面不会按失败响应推断最终状态。'
            + `下一步：正在重新获取任务 ${action.taskId} 的真实状态；完成前不要重复关闭，仅当刷新后仍为非终态才重试。`,
          )
        } finally {
          if (taskCloseActionRef.current === action) {
            const waitForTimeline = selectedTaskId === action.taskId
            taskListGenerationRef.current += 1
            taskCloseRefreshRef.current = {
              action,
              waitForTimeline,
              taskListSettled: false,
              timelineSettled: !waitForTimeline,
            }
            setRefresh((value) => value + 1)
          }
        }
      },
    })
  }
  const activeTasks = isOpsAdmin
    ? []
    : rows.filter((task) => !terminalTaskStatuses.has(task.status))
  const operatorCurrentTask = activeTasks.length === 1 ? activeTasks[0] : null
  if (!isOpsAdmin) {
    return <>
      <PageHeading title="当前任务" description="按任务进度、安全资源状态和真实上传结果完成当前业务；未知结果不会自动重试。" />
      {loading ? <div className="centered"><Spin /></div> : taskListError ? <Alert
        type="warning"
        showIcon
        message="当前任务暂不可用"
        description={taskListError}
        action={<Button onClick={() => setRefresh((value) => value + 1)}>重新加载当前任务</Button>}
      /> : <OperatorTaskWorkbench
        tasks={rows}
        activeTasks={activeTasks}
        currentTask={operatorCurrentTask}
        timeline={visibleTaskTimeline}
        timelineLoading={timelineLoading}
        timelineError={timelineError}
        closingTaskId={closingTaskId}
        onClose={confirmCloseTask}
        onRetryTimeline={() => setRefresh((value) => value + 1)}
      />}
    </>
  }
  const ownershipColumns: TableColumnsType<TaskSummary> = isOpsAdmin ? [
    { title: '用户', dataIndex: 'user_id', ellipsis: true },
    { title: '设备', dataIndex: 'device_id', ellipsis: true },
  ] : []
  const columns: TableColumnsType<TaskSummary> = [
    { title: '任务', dataIndex: 'id', render: (value: string) => value.slice(0, 12) },
    { title: '类型', dataIndex: 'type' },
    ...ownershipColumns,
    { title: '状态', dataIndex: 'status', filters: statusFilters, onFilter: (value, row) => row.status === value, render: (value: string) => <StatusTag value={value} /> },
    { title: '过期时间', dataIndex: 'expires_at', render: (value: string | null) => value ?? '—' },
    { title: '创建时间', dataIndex: 'created_at', sorter: (left, right) => left.created_at.localeCompare(right.created_at) },
    { title: 'trace_id', dataIndex: 'trace_id', ellipsis: true, render: (value: string) => <Text code copyable={{ text: value }}>{value}</Text> },
    { title: '操作', render: (_, row) => <Space><Button
      type="link"
      onClick={() => setSelectedTaskId(row.id)}
      aria-label={`查看任务 ${row.id} 详情`}
      aria-pressed={row.id === selectedTaskId}
    >查看详情</Button><Button
      danger
      aria-label={`关闭任务 ${row.id}`}
      loading={closingTaskId === row.id}
      disabled={terminalTaskStatuses.has(row.status) || closingTaskId !== null}
      onClick={() => confirmCloseTask(row)}
    >关闭任务</Button></Space> },
  ]
  return <><PageHeading title="任务中心" description={isOpsAdmin
    ? '按用户和设备追踪同租户任务；关闭任务会回收卡租约和邮箱会话。'
    : '查看任务生命周期与资源归属；关闭任务会回收卡租约和邮箱会话。'} /><Card>
    {isOpsAdmin ? <div role="search" aria-label="任务筛选" style={{ marginBottom: 16 }}><Space wrap>
      <Select
        aria-label="任务状态"
        allowClear
        placeholder="状态"
        value={draftFilters.status}
        style={{ width: 150 }}
        options={['created', 'closed', 'expired', 'cancelled', 'completed'].map((value) => ({ value, label: value }))}
        onChange={(value) => setDraftFilters((current) => ({ ...current, status: value }))}
      />
      <Input
        aria-label="用户 ID"
        placeholder="用户 ID"
        value={draftFilters.user_id ?? ''}
        onChange={(event) => setDraftFilters((current) => ({ ...current, user_id: event.target.value }))}
      />
      <Input
        aria-label="trace_id"
        placeholder="trace_id"
        value={draftFilters.trace_id ?? ''}
        onChange={(event) => setDraftFilters((current) => ({ ...current, trace_id: event.target.value }))}
      />
      <Button type="primary" onClick={() => {
        applyTaskFilters({
          status: draftFilters.status || undefined,
          user_id: draftFilters.user_id?.trim() || undefined,
          trace_id: draftFilters.trace_id?.trim() || undefined,
        })
      }}>筛选</Button>
      <Button onClick={() => {
        setDraftFilters({})
        applyTaskFilters({})
      }}>清除筛选</Button>
    </Space></div> : null}
    {loading ? <div className="centered"><Spin /></div> : taskListError ? <Alert
      type="warning"
      showIcon
      message="任务列表暂不可用"
      description={taskListError}
      action={<Button onClick={() => setRefresh((value) => value + 1)}>重新加载任务列表</Button>}
    /> : <Table
      columns={columns}
      dataSource={rows}
      rowKey="id"
      locale={{ emptyText: <Empty description="暂无任务" /> }}
      scroll={{ x: 980 }}
      rowClassName={(row) => (row.id === selectedTaskId ? 'task-row-selected' : '')}
    />}
    {!loading && !taskListError && selectedTask ? <Card className="task-detail-card" title="任务详情" size="small">
      <Descriptions column={{ xs: 1, md: 2 }}>
        <Descriptions.Item label="任务标识">{selectedTask.id}</Descriptions.Item>
        <Descriptions.Item label="trace_id"><Text code copyable={{ text: selectedTask.trace_id }}>{selectedTask.trace_id}</Text></Descriptions.Item>
        <Descriptions.Item label="归属用户">{selectedTask.user_id}</Descriptions.Item>
        <Descriptions.Item label="归属设备">{selectedTask.device_id}</Descriptions.Item>
        <Descriptions.Item label="主状态"><StatusTag value={selectedTask.status} /></Descriptions.Item>
        <Descriptions.Item label="任务类型">{selectedTask.type}</Descriptions.Item>
        <Descriptions.Item label="幂等键">{selectedTask.idempotency_key}</Descriptions.Item>
        <Descriptions.Item label="客户端引用">{selectedTask.client_reference ?? '—'}</Descriptions.Item>
        <Descriptions.Item label="过期时间">{selectedTask.expires_at ?? '—'}</Descriptions.Item>
        <Descriptions.Item label="关闭时间">{selectedTask.closed_at ?? '—'}</Descriptions.Item>
        <Descriptions.Item label="创建时间">{selectedTask.created_at}</Descriptions.Item>
      </Descriptions>
      {timelineLoading ? <div className="centered"><Spin /></div> : null}
      {timelineError ? <Alert
        type="warning"
        showIcon
        message="资源时间线暂不可用"
        description="原因：资源时间线读取失败。影响：任务主状态仍可查看，但当前不会展示过期资源链。下一步：检查网络后从此处重新加载。"
        action={<Button onClick={() => setRefresh((value) => value + 1)}>重新加载资源时间线</Button>}
      /> : null}
      {visibleTaskTimeline ? <>
        <Descriptions className="task-resource-chain" title="资源链" column={{ xs: 1, md: 2 }}>
          <Descriptions.Item label="邮箱会话">
            {visibleTaskTimeline.mail_session ? <Space wrap><Text>{visibleTaskTimeline.mail_session.email_masked}</Text><StatusTag value={visibleTaskTimeline.mail_session.status} /></Space> : '未分配'}
          </Descriptions.Item>
          <Descriptions.Item label="卡租约">
            {visibleTaskTimeline.card_allocations.length ? <Space wrap>{visibleTaskTimeline.card_allocations.map((allocation) => <Space key={allocation.id}><Text>{allocation.card_masked}</Text><StatusTag value={allocation.status} /></Space>)}</Space> : '未分配'}
          </Descriptions.Item>
          <Descriptions.Item label="上传任务" span={2}>
            {visibleTaskTimeline.uploads.length ? <Space wrap>{visibleTaskTimeline.uploads.map((upload) => <Space key={upload.id}><Text>{upload.business_name}</Text><StatusTag value={upload.status} /><Text>{uploadPhaseNames[upload.phase] ?? '未知阶段'} · #{upload.phase_sequence} · {formatLocalDateTime(upload.phase_updated_at)}</Text></Space>)}</Space> : '尚未提交'}
          </Descriptions.Item>
        </Descriptions>
        <div className="task-lifecycle">
          <Text strong>真实事件时间线</Text>
          {visibleTaskTimeline.events.length ? <Timeline items={visibleTaskTimeline.events.map((event) => ({
            color: event.result === 'success' ? 'green' : event.result === 'unknown' ? 'orange' : event.result === 'failed' || event.result === 'denied' ? 'red' : 'blue',
            dot: event.result === 'success' ? <CheckCircleOutlined /> : event.result === 'unknown' || event.result === 'failed' || event.result === 'denied' ? <ExclamationCircleOutlined /> : <LoadingOutlined />,
            children: <Space direction="vertical" size={2}>
              <Space wrap><Text strong>{taskEventNames[event.event_type] ?? event.event_type}</Text><StatusTag value={event.result} /></Space>
              <Text type="secondary">{event.created_at} · {event.entity_type}{event.policy_version ? ` · ${event.policy_version}` : ''}{event.phase ? ` · ${uploadPhaseNames[event.phase] ?? '未知阶段'}${event.phase_sequence ? ` #${event.phase_sequence}` : ''}` : ''}</Text>
            </Space>,
          }))} /> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无任务事件" />}
        </div>
      </> : null}
    </Card> : null}
  </Card></>
}
