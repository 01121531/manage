import { useEffect, useRef, useState } from 'react'
import { Alert, App as AntApp, Button, Card, Descriptions, Empty, Form, Input, Modal, Space, Spin, Table, Select, Typography } from 'antd'
import type { TableColumnsType } from 'antd'
import { cancelUploadJob, listUploads, reconcileUploadJob } from '../admin-api'
import type { Principal, UploadSummary } from '../types'
import { useScopedConfirm } from '../useScopedConfirm'
import { useViewActionScope } from '../useViewActionScope'
import { PageHeading, StatusTag, compareTableDate, compareTableText, formatLocalDateTime, uploadPhaseNames } from './shared'

const { Text } = Typography

export default function UploadsPage({ principal }: { principal: Principal }) {
  const { message } = AntApp.useApp()
  const confirm = useScopedConfirm()
  const beginViewAction = useViewActionScope()
  const [rows, setRows] = useState<UploadSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [uploadListError, setUploadListError] = useState<string>()
  const [refresh, setRefresh] = useState(0)
  const [reconcileTarget, setReconcileTarget] = useState<UploadSummary | null>(null)
  const [saving, setSaving] = useState(false)
  const [cancelingUploadId, setCancelingUploadId] = useState<string | null>(null)
  const cancelActionRef = useRef<{ jobId: string; pending: boolean } | null>(null)
  const [reconcilingUploadId, setReconcilingUploadId] = useState<string | null>(null)
  const [reconcilePending, setReconcilePending] = useState(false)
  const reconcileActionRef = useRef<{ jobId: string; pending: boolean } | null>(null)
  const canCancel = principal.role === 'ops_admin' || principal.role === 'platform_admin'
  const canReconcile = canCancel || principal.role === 'security_auditor'
  const [form] = Form.useForm<{ status: 'succeeded' | 'failed'; external_ref?: string; error_code?: string }>()
  useEffect(() => {
    let alive = true
    setLoading(true)
    setUploadListError(undefined)
    listUploads().then((items) => {
      if (alive) setRows(items)
    }).catch(() => {
      if (alive) {
        setReconcileTarget(null)
        form.resetFields()
        setUploadListError(
          '原因：上传真实状态刷新失败。'
          + '影响：旧上传记录、复核弹窗和操作已隐藏，unknown 终态与关联任务资源均无法安全确认。'
          + '下一步：请重新获取真实状态并核对 Sub2 外部结果；确认前切勿重复取消或复核。',
        )
      }
    }).finally(() => {
      if (alive) setLoading(false)
    })
    return () => { alive = false }
  }, [form, refresh])

  const performCancel = async (row: UploadSummary) => {
    if (!canCancel || !['queued', 'running'].includes(row.status)) return
    if (cancelActionRef.current?.pending || reconcileActionRef.current !== null) return
    const action = { jobId: row.id, pending: true }
    const isCurrent = beginViewAction()
    cancelActionRef.current = action
    setCancelingUploadId(row.id)
    try {
      const updated = await cancelUploadJob(row.id)
      const expectedStatus = row.status === 'queued' ? 'cancelled' : 'cancel_pending'
      if (
        updated.id !== row.id
        || updated.task_id !== row.task_id
        || updated.status !== expectedStatus
      ) {
        throw new Error('upload cancel response binding mismatch')
      }
      if (!isCurrent()) return
      if (updated.status === 'cancelled') {
        message.success('上传任务已取消，正在刷新状态。')
      } else {
        message.success('停止请求已提交；任务可能仍为 cancel_pending，正在刷新状态，请核对最终结果。')
      }
    } catch {
      if (!isCurrent()) return
      message.error(
        '原因：平台未能确认上传取消结果。'
        + '影响：取消、待取消或 unknown 状态可能已经生效；页面不会按失败响应推断最终状态。'
        + '下一步：正在重新获取上传真实状态；完成前不得重复取消，仅当刷新后仍在排队或运行时才可重试，unknown 请先复核。',
      )
    } finally {
      if (!isCurrent()) return
      await refreshUploadRows(isCurrent)
      if (!isCurrent()) return
      if (cancelActionRef.current === action) cancelActionRef.current = null
      setCancelingUploadId((current) => current === row.id ? null : current)
    }
  }

  const confirmCancel = (row: UploadSummary) => {
    if (!canCancel || !['queued', 'running'].includes(row.status)) return
    if (cancelActionRef.current?.pending || reconcileActionRef.current !== null) return
    const isQueued = row.status === 'queued'
    confirm({
      title: `确认取消上传 ${row.business_name}？`,
      content: <Space direction="vertical" size={8}>
        <Descriptions size="small" column={1}>
          <Descriptions.Item label="业务名称">{row.business_name}</Descriptions.Item>
          <Descriptions.Item label="上传 ID">{row.id}</Descriptions.Item>
          <Descriptions.Item label="任务 ID">{row.task_id}</Descriptions.Item>
          <Descriptions.Item label="当前状态"><StatusTag value={row.status} /></Descriptions.Item>
        </Descriptions>
        <Text type="secondary">
          {isQueued
            ? '该任务仍在排队，确认后将直接取消；平台会刷新状态供你核对。'
            : '该任务正在运行，确认后只会请求停止，结果可能为 cancel_pending；刷新后仍需核对最终状态。'}
        </Text>
      </Space>,
      okText: '确认请求取消',
      okButtonProps: { danger: true },
      cancelText: '保留任务',
      onOk: () => performCancel(row),
    })
  }

  const reserveReconcileAction = (jobId: string) => {
    if (!canReconcile || cancelActionRef.current !== null || reconcileActionRef.current !== null) return null
    const action = { jobId, pending: false }
    reconcileActionRef.current = action
    setReconcilingUploadId(jobId)
    setReconcilePending(false)
    return action
  }

  const releaseReconcileAction = (action: { jobId: string; pending: boolean }) => {
    if (reconcileActionRef.current !== action) return
    reconcileActionRef.current = null
    setReconcilingUploadId(null)
    setReconcilePending(false)
  }

  const openReconcile = (row: UploadSummary) => {
    if (!canReconcile || row.status !== 'unknown') return
    const action = reserveReconcileAction(row.id)
    if (!action) return
    form.resetFields()
    form.setFieldsValue({ status: 'failed' })
    setReconcileTarget(row)
  }

  const closeReconcile = () => {
    const action = reconcileActionRef.current
    if (action?.pending) return
    form.resetFields()
    setReconcileTarget(null)
    if (action) releaseReconcileAction(action)
  }

  const refreshUploadRows = async (isCurrent: () => boolean, reconciledJobId?: string) => {
    if (!isCurrent()) return
    setLoading(true)
    setUploadListError(undefined)
    try {
      const items = await listUploads()
      if (!isCurrent()) return
      setRows(items)
      if (reconciledJobId) {
        setReconcileTarget((current) => {
          if (current?.id !== reconciledJobId) return current
          const refreshed = items.find((item) => item.id === reconciledJobId)
          return refreshed?.status === 'unknown' ? refreshed : null
        })
      }
    } catch {
      if (!isCurrent()) return
      setReconcileTarget(null)
      form.resetFields()
      setUploadListError(
        '原因：上传真实状态刷新失败。'
        + '影响：旧上传记录、复核弹窗和操作已隐藏，unknown 终态与关联任务资源均无法安全确认。'
        + '下一步：请重新获取真实状态并核对 Sub2 外部结果；确认前切勿重复取消或复核。',
      )
    } finally {
      if (isCurrent()) setLoading(false)
    }
  }

  const submitReconcile = async () => {
    const target = reconcileTarget
    if (!canReconcile || !target || target.status !== 'unknown') return
    const action = reconcileActionRef.current ?? reserveReconcileAction(target.id)
    if (!action || action.jobId !== target.id || action.pending) return
    let values: { status: 'succeeded' | 'failed'; external_ref?: string; error_code?: string }
    try {
      values = await form.validateFields()
    } catch {
      return
    }
    const isCurrent = beginViewAction()
    action.pending = true
    setReconcilePending(true)
    setSaving(true)
    try {
      const updated = await reconcileUploadJob(target.id, values)
      if (
        updated.id !== target.id
        || updated.task_id !== target.task_id
        || updated.status !== values.status
      ) {
        throw new Error('upload reconciliation response binding mismatch')
      }
      if (!isCurrent()) return
      message.success('复核终态已提交，正在刷新上传与任务资源状态。')
      form.resetFields()
      setReconcileTarget(null)
    } catch {
      if (!isCurrent()) return
      message.error(
        '原因：平台未能确认 unknown 上传复核结果。'
        + '影响：复核终态可能已经写入；成功终态还可能已关闭任务并释放卡与邮箱资源。'
        + '下一步：已刷新真实状态；仅当仍为 unknown 且已核对 Sub2 外部结果时，才可从同一入口重试。',
      )
    } finally {
      if (!isCurrent()) return
      await refreshUploadRows(isCurrent, target.id)
      if (!isCurrent()) return
      setSaving(false)
      releaseReconcileAction(action)
    }
  }

  const columns: TableColumnsType<UploadSummary> = [
    { title: '上传标识', dataIndex: 'id', render: (value: string) => <Text code copyable={{ text: value }}>{value}</Text> },
    { title: '任务', dataIndex: 'task_id', render: (value: string) => <Text code copyable={{ text: value }}>{value}</Text> },
    { title: '业务名称', dataIndex: 'business_name', sorter: (left, right) => compareTableText(left.business_name, right.business_name) },
    {
      title: '状态', dataIndex: 'status',
      filters: ['queued', 'running', 'succeeded', 'failed', 'unknown', 'cancelled'].map((value) => ({ text: value, value })),
      onFilter: (value, row) => row.status === value,
      render: (value: string) => <StatusTag value={value} />,
    },
    {
      title: '执行阶段', dataIndex: 'phase',
      filters: Object.entries(uploadPhaseNames).map(([value, text]) => ({ value, text })),
      onFilter: (value, row) => row.phase === value,
      render: (value: string, row) => <Space direction="vertical" size={0}>
        <Text>{uploadPhaseNames[value] ?? '未知阶段'} · #{row.phase_sequence}</Text>
        <Text type="secondary">{formatLocalDateTime(row.phase_updated_at)}</Text>
      </Space>,
    },
    { title: '策略版本', dataIndex: 'policy_version' },
    { title: '错误分类', dataIndex: 'error_code', render: (value: string | null) => value ?? '—' },
    { title: 'trace_id', dataIndex: 'trace_id', render: (value: string) => <Text code copyable={{ text: value }}>{value}</Text> },
    { title: '创建时间', dataIndex: 'created_at', sorter: (left, right) => compareTableDate(left.created_at, right.created_at) },
    { title: '操作', render: (_, row) => {
      const showReconcile = canReconcile && row.status === 'unknown'
      if (!canCancel && !showReconcile) return <Text type="secondary">只读核对</Text>
      return <Space>
        {canCancel ? <Button
          danger
          aria-label={`请求取消上传 ${row.business_name}（${row.id}，任务 ${row.task_id}，状态 ${row.status}）`}
          loading={cancelingUploadId === row.id}
          disabled={cancelingUploadId !== null || reconcilingUploadId !== null || saving || !['queued', 'running'].includes(row.status)}
          onClick={() => confirmCancel(row)}
        >请求取消</Button> : null}
        {showReconcile ? <Button
          aria-label={`复核上传 ${row.business_name}（${row.id}，任务 ${row.task_id}，状态 ${row.status}）`}
          loading={reconcilePending && reconcilingUploadId === row.id}
          disabled={cancelingUploadId !== null || reconcilingUploadId !== null || saving || row.status !== 'unknown'}
          onClick={() => openReconcile(row)}
        >复核</Button> : null}
      </Space>
    } },
  ]
  return <>
    <PageHeading title="Sub2 上传" description="平台代为提交；超时结果进入人工核对，不盲目重试。" />
    <Card>
      {loading ? <div className="centered"><Spin /></div> : uploadListError ? <Alert
        type="warning"
        showIcon
        message="上传列表暂不可用"
        description={uploadListError}
        action={<Button onClick={() => setRefresh((value) => value + 1)}>重新获取上传真实状态</Button>}
      /> : <Table
        columns={columns}
        dataSource={rows}
        rowKey="id"
        locale={{ emptyText: <Empty description="暂无上传记录" /> }}
        scroll={{ x: 1040 }}
      />}
    </Card>
    <Modal
      open={reconcileTarget !== null}
      title={reconcileTarget ? `确认上传 ${reconcileTarget.business_name} 的 unknown 终态` : '确认 unknown 上传终态'}
      okText="确认写入复核终态"
      cancelText="取消"
      confirmLoading={saving}
      cancelButtonProps={{ disabled: reconcilePending }}
      closable={!reconcilePending}
      maskClosable={!reconcilePending}
      onCancel={closeReconcile}
      onOk={submitReconcile}
    >
      {reconcileTarget ? <Descriptions size="small" column={1}>
        <Descriptions.Item label="业务名称">{reconcileTarget.business_name}</Descriptions.Item>
        <Descriptions.Item label="上传 ID">{reconcileTarget.id}</Descriptions.Item>
        <Descriptions.Item label="任务 ID">{reconcileTarget.task_id}</Descriptions.Item>
        <Descriptions.Item label="当前状态"><StatusTag value={reconcileTarget.status} /></Descriptions.Item>
      </Descriptions> : null}
      <Alert
        className="section-card"
        type="warning"
        showIcon
        message="此操作会写入不可逆的人工终态"
        description="确认成功会完成关联任务并释放卡租约和邮箱会话；确认失败会结束 unknown 核对。提交前必须先核对 Sub2 外部结果，不能凭超时响应猜测。"
      />
      <Form form={form} layout="vertical" initialValues={{ status: 'failed' }}>
        <Form.Item label="复核结果" name="status" rules={[{ required: true }]}>
          <Select
            options={[
              { value: 'failed', label: '失败' },
              { value: 'succeeded', label: '成功' },
            ]}
          />
        </Form.Item>
        <Form.Item
          label="外部编号"
          name="external_ref"
          dependencies={['status']}
          rules={[({ getFieldValue }) => ({
            validator(_, value) {
              if (getFieldValue('status') === 'succeeded' && !String(value ?? '').trim()) {
                return Promise.reject(new Error('成功复核需要填写外部编号'))
              }
              return Promise.resolve()
            },
          })]}
        >
          <Input placeholder="Sub2 外部编号" />
        </Form.Item>
        <Form.Item label="错误码" name="error_code">
          <Input placeholder="例如 manual_review_needed" />
        </Form.Item>
      </Form>
    </Modal>
  </>
}
