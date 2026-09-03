import { useEffect, useRef, useState } from 'react'
import { Alert, App as AntApp, Button, Card, Descriptions, Empty, Form, Input, InputNumber, Select, Space, Spin, Table, Typography } from 'antd'
import type { TableColumnsType } from 'antd'
import { approveCardPolicyVersion, approveMailPolicyVersion, approveUploadPolicyVersion, deployCardPolicyVersion, deployMailPolicyVersion, deployUploadPolicyVersion, getCardPolicyStatus, getMailPolicyStatus, getUploadPolicyStatus, listCardPolicyVersions, listMailPolicyVersions, listUploadPolicyVersions, registerCardPolicyVersion, registerMailPolicyVersion, registerUploadPolicyVersion, rollbackCardPolicy, rollbackMailPolicy, rollbackUploadPolicy } from '../admin-api'
import type { CardPolicyVersion, MailPolicyVersion, OperationalPolicyStatus, Principal, UploadPolicyStatus, UploadPolicyVersion } from '../types'
import { useScopedConfirm } from '../useScopedConfirm'
import { BooleanStateTag, PageHeading, SemanticStateTag, StatusTag } from './shared'

const { Text } = Typography

type GovernedPolicyVersion = MailPolicyVersion | CardPolicyVersion
type GovernedPolicyForm = {
  version: string
  change_note: string
  session_ttl_seconds?: number
  code_ttl_seconds?: number
  poll_interval_seconds?: number
  lease_ttl_seconds?: number
  reveal_ttl_seconds?: number
  task_type?: string
  pool_key?: string
  region?: string
  brands?: string
  minimum_validity_days?: number
  card_allocation_order?: 'oldest_available' | 'expiry_soonest'
}

function OperationalPolicyPanel({ domain, principal }: {
  domain: 'mail' | 'card'
  principal: Principal
}) {
  const { message } = AntApp.useApp()
  const confirm = useScopedConfirm()
  const [form] = Form.useForm<GovernedPolicyForm>()
  const [status, setStatus] = useState<OperationalPolicyStatus>()
  const [versions, setVersions] = useState<GovernedPolicyVersion[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [refresh, setRefresh] = useState(0)
  const [pending, setPending] = useState<string | null>(null)
  const pendingRef = useRef<{ key: string; pending: boolean } | null>(null)
  const pendingRefreshRef = useRef<{ key: string; pending: boolean } | null>(null)
  const isPlatformAdmin = principal.role === 'platform_admin'
  const title = domain === 'mail' ? '邮箱策略' : '卡分配策略'

  useEffect(() => {
    let alive = true
    setLoading(true)
    setError(undefined)
    setError(undefined)
    const statusRequest = domain === 'mail' ? getMailPolicyStatus() : getCardPolicyStatus()
    const versionsRequest = domain === 'mail' ? listMailPolicyVersions() : listCardPolicyVersions()
    Promise.all([statusRequest, versionsRequest]).then(([nextStatus, nextVersions]) => {
      if (!alive) return
      setStatus(nextStatus)
      setVersions(nextVersions)
      setError(undefined)
    }).catch(() => {
      if (alive) setError(`${title}状态暂不可用，请稍后刷新。`)
    }).finally(() => {
      if (!alive) return
      setLoading(false)
      const action = pendingRefreshRef.current
      if (action !== null) {
        pendingRefreshRef.current = null
        if (pendingRef.current === action) pendingRef.current = null
        setPending((current) => current === action.key ? null : current)
      }
    })
    return () => { alive = false }
  }, [domain, refresh, title])

  const perform = async (key: string, operation: () => Promise<unknown>, success: string) => {
    if (pendingRef.current?.pending) return
    const action = { key, pending: true }
    pendingRef.current = action
    setPending(key)
    try {
      await operation()
      message.success(success)
    } catch {
      message.error('操作未完成，生产策略未确认变更；正在刷新真实状态。')
    } finally {
      if (pendingRef.current === action) {
        pendingRefreshRef.current = action
        setRefresh((value) => value + 1)
      }
    }
  }

  const approve = (policyId: string) => domain === 'mail'
    ? approveMailPolicyVersion(policyId)
    : approveCardPolicyVersion(policyId)
  const deploy = (policyId: string, percent: number) => domain === 'mail'
    ? deployMailPolicyVersion(policyId, percent)
    : deployCardPolicyVersion(policyId, percent)
  const rollback = () => domain === 'mail' ? rollbackMailPolicy() : rollbackCardPolicy()
  const register = (values: GovernedPolicyForm) => {
    if (domain === 'mail') {
      return registerMailPolicyVersion({
        version: values.version,
        change_note: values.change_note,
        session_ttl_seconds: values.session_ttl_seconds ?? 600,
        code_ttl_seconds: values.code_ttl_seconds ?? 60,
        poll_interval_seconds: values.poll_interval_seconds ?? 5,
      })
    }
    return registerCardPolicyVersion({
      version: values.version,
      change_note: values.change_note,
      lease_ttl_seconds: values.lease_ttl_seconds ?? 1_800,
      reveal_ttl_seconds: values.reveal_ttl_seconds ?? 60,
      allocation_order: 'oldest_available',
      selection_rules: [{
        task_type: values.task_type ?? 'card_checkout',
        pool_key: values.pool_key ?? 'legacy-unclassified',
        region: values.region ?? 'legacy-unclassified',
        brands: (values.brands ?? '').split(',').map((value) => value.trim().toUpperCase()).filter(Boolean),
        minimum_validity_days: values.minimum_validity_days ?? 0,
        allocation_order: values.card_allocation_order ?? 'oldest_available',
      }],
    })
  }
  const confirmDeploy = (row: GovernedPolicyVersion, percent: number) => confirm({
    title: `确认将 ${row.version} 发布到 ${percent}%？`,
    content: '仅新建任务参与确定性灰度；已创建的邮箱会话或卡分配继续使用已固化快照。',
    okText: percent === 100 ? '全量发布' : `灰度 ${percent}%`,
    cancelText: '取消',
    onOk: () => perform(`deploy-${percent}:${row.id}`, () => deploy(row.id, percent), `${title}已发布到 ${percent}%。`),
  })

  if (loading) return <Card className="section-card" title={title}><Spin /></Card>
  if (error || !status) return <Alert
    className="section-card"
    type="warning"
    showIcon
    message={`${title}暂不可用`}
    description={`原因：平台暂未返回${title}状态。影响：当前不展示过期版本或发布操作。下一步：检查网络后从此处重新加载。`}
    action={<Button onClick={() => setRefresh((value) => value + 1)}>重新加载{title}</Button>}
  />
  const columns: TableColumnsType<GovernedPolicyVersion> = [
    { title: '版本', dataIndex: 'version' },
    { title: '状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: '执行参数', render: (_, row) => 'session_ttl_seconds' in row
      ? `会话 ${row.session_ttl_seconds}s / 验证码 ${row.code_ttl_seconds}s / 轮询 ${row.poll_interval_seconds}s`
      : `租约 ${row.lease_ttl_seconds}s / 展示 ${row.reveal_ttl_seconds}s / ${row.selection_rules.length} 条选卡规则` },
    { title: '变更说明', dataIndex: 'change_note' },
    { title: '审批人', render: (_, row) => row.approved_by?.slice(0, 8) ?? '待审批' },
    {
      title: '操作',
      render: (_, row) => !isPlatformAdmin ? '只读' : <Space wrap>
        {row.status === 'draft' ? <Button
          disabled={pending !== null || row.created_by === principal.id}
          loading={pending === `approve:${row.id}`}
          onClick={() => perform(`approve:${row.id}`, () => approve(row.id), `${title}已通过独立审批。`)}
        >审批</Button> : null}
        {row.status === 'approved' ? <>
          {status.governance_configured ? <Button disabled={pending !== null} onClick={() => confirmDeploy(row, 10)}>灰度 10%</Button> : null}
          <Button disabled={pending !== null} onClick={() => confirmDeploy(row, 100)}>全量发布</Button>
        </> : null}
        {row.status === 'active' && row.version === status.active_version && status.previous_version ? <>
          <Button disabled={pending !== null} onClick={() => confirmDeploy(row, 50)}>调整为 50%</Button>
          <Button disabled={pending !== null} onClick={() => confirmDeploy(row, 100)}>扩展至 100%</Button>
        </> : null}
      </Space>,
    },
  ]
  return <Card
    className="section-card"
    title={title}
    extra={isPlatformAdmin && status.previous_version ? <Button
      danger
      disabled={pending !== null}
      loading={pending === 'rollback'}
      onClick={() => confirm({
        title: `确认回滚${title}？`,
        content: `将从 ${status.active_version ?? '当前版本'} 回滚到 ${status.previous_version}，新任务立即生效。`,
        okText: '确认回滚',
        okButtonProps: { danger: true },
        cancelText: '取消',
        onOk: () => perform('rollback', async () => {
          const rolledBack = await rollback()
          if (
            rolledBack.domain !== domain
            || rolledBack.active_version !== status.previous_version
            || rolledBack.previous_version !== status.active_version
          ) throw new Error('operational policy rollback response binding mismatch')
        }, `${title}已回滚。`),
      })}
    >回滚上一版本</Button> : null}
  >
    <Descriptions column={{ xs: 1, md: 3 }}>
      <Descriptions.Item label="治理状态"><BooleanStateTag value={status.governance_configured} trueLabel="已启用" falseLabel="使用服务端默认值" /></Descriptions.Item>
      <Descriptions.Item label="当前生效">{status.active_version ?? '服务端默认值'}</Descriptions.Item>
      <Descriptions.Item label="灰度比例">{status.rollout_percent === null ? '未设置' : `${status.rollout_percent}%`}</Descriptions.Item>
    </Descriptions>
    {isPlatformAdmin ? <Form
      className="section-card"
      form={form}
      layout="inline"
      initialValues={domain === 'mail'
        ? { session_ttl_seconds: 600, code_ttl_seconds: 60, poll_interval_seconds: 5 }
        : { lease_ttl_seconds: 1_800, reveal_ttl_seconds: 60, task_type: 'card_checkout', minimum_validity_days: 0, card_allocation_order: 'oldest_available' }}
      onFinish={(values) => perform('register', async () => {
        await register(values)
        form.resetFields()
      }, `${title}草稿已登记，等待另一位管理员审批。`)}
    >
      <Form.Item name="version" rules={[{ required: true, message: '请输入版本号' }, { pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/, message: '版本号格式不正确' }]}>
        <Input placeholder={domain === 'mail' ? 'mail-2026.08.1' : 'card-2026.08.1'} maxLength={80} />
      </Form.Item>
      <Form.Item name="change_note" rules={[{ required: true, message: '请输入变更说明' }]}><Input placeholder="变更说明" maxLength={500} /></Form.Item>
      {domain === 'mail' ? <>
        <Form.Item label="会话(s)" name="session_ttl_seconds" rules={[{ required: true }]}><InputNumber min={60} max={3_600} /></Form.Item>
        <Form.Item label="验证码(s)" name="code_ttl_seconds" rules={[{ required: true }]}><InputNumber min={30} max={300} /></Form.Item>
        <Form.Item label="轮询(s)" name="poll_interval_seconds" rules={[{ required: true }]}><InputNumber min={1} max={60} /></Form.Item>
      </> : <>
        <Form.Item label="租约(s)" name="lease_ttl_seconds" rules={[{ required: true }]}><InputNumber min={60} max={86_400} /></Form.Item>
        <Form.Item label="展示(s)" name="reveal_ttl_seconds" rules={[{ required: true }]}><InputNumber min={30} max={300} /></Form.Item>
        <Form.Item label="任务类型" name="task_type" rules={[{ required: true }]}><Input placeholder="card_checkout" /></Form.Item>
        <Form.Item label="卡池" name="pool_key" rules={[{ required: true }]}><Input placeholder="checkout-cn" /></Form.Item>
        <Form.Item label="地区" name="region" rules={[{ required: true }]}><Input placeholder="cn-east" /></Form.Item>
        <Form.Item label="品牌(逗号分隔)" name="brands"><Input placeholder="VISA,MASTERCARD" /></Form.Item>
        <Form.Item label="最短有效(日)" name="minimum_validity_days" rules={[{ required: true }]}><InputNumber min={0} max={3_650} /></Form.Item>
        <Form.Item label="排序" name="card_allocation_order" rules={[{ required: true }]}><Select style={{ width: 150 }} options={[{ value: 'oldest_available', label: '最早入池' }, { value: 'expiry_soonest', label: '有效期最短优先' }]} /></Form.Item>
      </>}
      <Button type="primary" htmlType="submit" disabled={pending !== null} loading={pending === 'register'}>登记草稿</Button>
    </Form> : null}
    <Table columns={columns} dataSource={versions} rowKey="id" pagination={false} locale={{ emptyText: <Empty description={`尚未登记${title}`} /> }} scroll={{ x: 980 }} />
  </Card>
}

export default function PoliciesPage({ principal }: { principal: Principal }) {
  const { message } = AntApp.useApp()
  const confirm = useScopedConfirm()
  const [form] = Form.useForm<{ version: string; change_note: string }>()
  const [policy, setPolicy] = useState<UploadPolicyStatus>()
  const [versions, setVersions] = useState<UploadPolicyVersion[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()
  const [refresh, setRefresh] = useState(0)
  const [pendingPolicyAction, setPendingPolicyAction] = useState<string | null>(null)
  const policyActionRef = useRef<{ key: string; pending: boolean } | null>(null)
  const policyActionRefreshRef = useRef<{ key: string; pending: boolean } | null>(null)
  const isPlatformAdmin = principal.role === 'platform_admin'
  useEffect(() => {
    let alive = true
    setLoading(true)
    Promise.all([getUploadPolicyStatus(), listUploadPolicyVersions()]).then(([value, policyVersions]) => {
      if (alive) {
        setPolicy(value)
        setVersions(policyVersions)
        setError(undefined)
      }
    }).catch(() => {
      if (alive) setError('策略状态暂不可用，请稍后刷新。')
    }).finally(() => {
      if (!alive) return
      setLoading(false)
      const action = policyActionRefreshRef.current
      if (action !== null) {
        policyActionRefreshRef.current = null
        if (policyActionRef.current === action) policyActionRef.current = null
        setPendingPolicyAction((current) => current === action.key ? null : current)
      }
    })
    return () => { alive = false }
  }, [refresh])

  const perform = async (key: string, operation: () => Promise<unknown>, success: string) => {
    if (policyActionRef.current?.pending) return
    const action = { key, pending: true }
    policyActionRef.current = action
    setPendingPolicyAction(key)
    try {
      await operation()
      message.success(success)
    } catch {
      message.error(
        '原因：平台未能确认策略操作结果。'
        + '影响：登记、审批、灰度或全量发布、回滚可能已经生效；页面不会按失败响应推断最终状态。'
        + '下一步：正在刷新策略真实状态；请以刷新后的版本、状态和比例为准，仅当原目标未达成且原动作仍可用时重试。',
      )
    } finally {
      if (policyActionRef.current === action) {
        policyActionRefreshRef.current = action
        setRefresh((value) => value + 1)
      }
    }
  }

  const confirmPolicyChange = (
    key: string,
    title: string,
    description: string,
    okText: string,
    target: UploadPolicyVersion,
    rollout: string,
    operation: () => Promise<unknown>,
    success: string,
  ) => {
    if (policyActionRef.current?.pending) return
    confirm({
      title,
      content: <Space direction="vertical" size={8}>
        <Descriptions size="small" column={1}>
          <Descriptions.Item label="策略版本">{target.version}</Descriptions.Item>
          <Descriptions.Item label="策略 ID">{target.id}</Descriptions.Item>
          <Descriptions.Item label="当前状态"><StatusTag value={target.status} /></Descriptions.Item>
          <Descriptions.Item label="目标灰度比例">{rollout}</Descriptions.Item>
        </Descriptions>
        <Text type="secondary">{description}</Text>
      </Space>,
      okText,
      okButtonProps: { danger: key === 'rollback' },
      cancelText: '取消',
      onOk: () => perform(key, operation, success),
    })
  }

  const deployBoundUploadPolicy = async (row: UploadPolicyVersion, rolloutPercent: number) => {
    const deployed = await deployUploadPolicyVersion(row.id, rolloutPercent)
    if (deployed.active_version !== row.version || deployed.rollout_percent !== rolloutPercent) {
      throw new Error('upload policy deployment response binding mismatch')
    }
  }

  if (loading) return <div className="centered"><Spin /></div>
  if (error || !policy) return <Alert
    type="warning"
    showIcon
    message="Sub2 上传策略暂不可用"
    description="原因：平台暂未返回上传策略状态。影响：当前不展示过期版本或发布操作。下一步：检查网络后从此处重新加载。"
    action={<Button onClick={() => setRefresh((value) => value + 1)}>重新加载 Sub2 上传策略</Button>}
  />
  const columns: TableColumnsType<UploadPolicyVersion> = [
    { title: '版本', dataIndex: 'version' },
    { title: '状态', dataIndex: 'status', render: (value: string) => <StatusTag value={value} /> },
    { title: '变更说明', dataIndex: 'change_note' },
    { title: '创建时间', dataIndex: 'created_at' },
    {
      title: '审批',
      render: (_, row) => row.approved_by
        ? <SemanticStateTag tone="positive" label={`已审批 · ${row.approved_by.slice(0, 8)}`} />
        : <SemanticStateTag tone="pending" label="待审批" />,
    },
    {
      title: '操作',
      render: (_, row) => !isPlatformAdmin ? '只读' : <Space wrap>
        {row.status === 'draft' ? <Button
          aria-label={`审批策略 ${row.version}（${row.id}，状态 ${row.status}，目标比例不变）`}
          loading={pendingPolicyAction === `approve:${row.id}`}
          disabled={pendingPolicyAction !== null || row.created_by === principal.id}
          onClick={() => confirmPolicyChange(
            `approve:${row.id}`,
            `确认审批策略 ${row.version}？`,
            '审批后该版本可进入灰度或全量发布；本次审批不改变当前生产流量。',
            '确认审批',
            row,
            '不变更（审批阶段）',
            async () => {
              const approved = await approveUploadPolicyVersion(row.id)
              if (
                approved.id !== row.id
                || approved.version !== row.version
                || approved.status !== 'approved'
                || approved.approved_by !== principal.id
                || approved.approved_at === null
              ) throw new Error('upload policy approval response binding mismatch')
            },
            '策略已通过独立审批。',
          )}
        >审批</Button> : null}
        {row.status === 'approved' ? <>
          {policy.governance_configured ? <Button
            aria-label={`开始策略 ${row.version} 10% 灰度（${row.id}，状态 ${row.status}，目标比例 10%）`}
            loading={pendingPolicyAction === `deploy-10:${row.id}`}
            disabled={pendingPolicyAction !== null}
            onClick={() => confirmPolicyChange(
              `deploy-10:${row.id}`,
              '确认开始 10% 灰度？',
              `新任务将有 10% 使用策略 ${row.version}；已排队任务仍使用原策略快照。`,
              '开始 10% 灰度',
              row,
              '10%',
              () => deployBoundUploadPolicy(row, 10),
              '已开始 10% 灰度。',
            )}
          >灰度 10%</Button> : null}
          <Button
            aria-label={`全量启用策略 ${row.version}（${row.id}，状态 ${row.status}，目标比例 100%）`}
            loading={pendingPolicyAction === `deploy-100:${row.id}`}
            disabled={pendingPolicyAction !== null}
            onClick={() => confirmPolicyChange(
              `deploy-100:${row.id}`,
              '确认全量启用该策略？',
              `确认后所有新任务将使用策略 ${row.version}；已排队任务仍使用原策略快照。`,
              '全量启用策略',
              row,
              '100%',
              () => deployBoundUploadPolicy(row, 100),
              '策略已全量启用。',
            )}
          >全量启用</Button>
        </> : null}
        {row.status === 'active' && row.version === policy.active_version && policy.previous_version ? <>
          <Button
            aria-label={`调整策略 ${row.version} 至 50%（${row.id}，状态 ${row.status}，目标比例 50%）`}
            loading={pendingPolicyAction === `deploy-50:${row.id}`}
            disabled={pendingPolicyAction !== null}
            onClick={() => confirmPolicyChange(
              `deploy-50:${row.id}`,
              '确认调整至 50% 灰度？',
              `新任务将有 50% 使用策略 ${row.version}；已排队任务仍使用原策略快照。`,
              '调整至 50%',
              row,
              '50%',
              () => deployBoundUploadPolicy(row, 50),
              '灰度比例已调整为 50%。',
            )}
          >调整为 50%</Button>
          <Button
            aria-label={`扩展策略 ${row.version} 至 100%（${row.id}，状态 ${row.status}，目标比例 100%）`}
            loading={pendingPolicyAction === `deploy-100:${row.id}`}
            disabled={pendingPolicyAction !== null}
            onClick={() => confirmPolicyChange(
              `deploy-100:${row.id}`,
              '确认扩展至 100%？',
              `确认后所有新任务将使用策略 ${row.version}；已排队任务仍使用原策略快照。`,
              '扩展至 100%',
              row,
              '100%',
              () => deployBoundUploadPolicy(row, 100),
              '策略已扩展至 100%。',
            )}
          >扩展至 100%</Button>
        </> : null}
      </Space>,
    },
  ]
  return <>
    <PageHeading title="策略配置" description="邮箱、卡分配与 Sub2 策略均采用不可变快照、独立审批、确定性灰度和一键回滚。" />
    <OperationalPolicyPanel domain="mail" principal={principal} />
    <OperationalPolicyPanel domain="card" principal={principal} />
    {policy.status !== 'ready' ? <Alert
      className="section-card"
      type="warning"
      showIcon
      message="上传策略尚未完整配置"
      description="请在服务端完成上传接口、上传密钥、网络路径以及 unknown 状态/幂等核对能力后再开放生产上传。"
    /> : null}
    <Card title="Sub2 上传策略">
      <Descriptions column={{ xs: 1, md: 2 }}>
        <Descriptions.Item label="策略版本">{policy.policy_version}</Descriptions.Item>
        <Descriptions.Item label="整体状态"><StatusTag value={policy.status} /></Descriptions.Item>
        <Descriptions.Item label="服务端托管"><BooleanStateTag value={policy.server_managed} trueLabel="是" falseLabel="否" /></Descriptions.Item>
        <Descriptions.Item label="上传接口"><BooleanStateTag value={policy.upload_endpoint_configured} trueLabel="已配置" falseLabel="未配置" /></Descriptions.Item>
        <Descriptions.Item label="上传密钥"><BooleanStateTag value={policy.upload_secret_configured} trueLabel="已配置" falseLabel="未配置" /></Descriptions.Item>
        <Descriptions.Item label="网络路径"><BooleanStateTag value={policy.network_route_configured} trueLabel="已配置" falseLabel="未配置" /></Descriptions.Item>
        <Descriptions.Item label="状态/幂等核对"><BooleanStateTag value={policy.unknown_reconciliation_configured} trueLabel="已配置" falseLabel="未配置" /></Descriptions.Item>
        <Descriptions.Item label="治理状态"><BooleanStateTag value={policy.governance_configured} trueLabel="已启用" falseLabel="未启用" /></Descriptions.Item>
        <Descriptions.Item label="当前生效">{policy.active_version ?? '使用服务端默认配置'}</Descriptions.Item>
        <Descriptions.Item label="上一版本">{policy.previous_version ?? '无'}</Descriptions.Item>
        <Descriptions.Item label="灰度比例">{policy.rollout_percent === null ? '未设置' : `${policy.rollout_percent}%`}</Descriptions.Item>
      </Descriptions>
    </Card>
    {isPlatformAdmin ? <Card className="section-card" title="注册服务端策略快照">
      <Alert
        className="section-card"
        type="info"
        showIcon
        message="这里只登记版本和变更说明"
        description="代理、分组、并发、凭据引用均从当前服务端配置生成快照，不允许通过浏览器提交。创建人不能审批自己的版本。"
      />
      <Form
        form={form}
        layout="inline"
        onFinish={(values) => perform(
          'register',
          async () => {
            const created = await registerUploadPolicyVersion(values)
            if (
              !created.id
              || created.version !== values.version
              || created.change_note !== values.change_note
              || created.status !== 'draft'
              || created.created_by !== principal.id
            ) throw new Error('upload policy registration response binding mismatch')
            form.resetFields()
          },
          '策略快照已登记，等待另一位管理员审批。',
        )}
      >
        <Form.Item name="version" rules={[
          { required: true, message: '请输入版本号' },
          { pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/, message: '仅允许字母、数字、点、横线和下划线' },
        ]}>
          <Input placeholder="例如 sub2-2026.08.1" maxLength={80} />
        </Form.Item>
        <Form.Item name="change_note" rules={[{ required: true, message: '请输入变更说明' }]}>
          <Input placeholder="变更说明" maxLength={500} />
        </Form.Item>
        <Button type="primary" htmlType="submit" loading={pendingPolicyAction === 'register'} disabled={pendingPolicyAction !== null}>登记快照</Button>
      </Form>
    </Card> : null}
    <Card
      className="section-card"
      title="策略版本"
      extra={isPlatformAdmin && policy.previous_version ? <Button
        danger
        aria-label={`回滚上传策略（当前 ${policy.active_version ?? '未设置'}，目标 ${policy.previous_version}，当前比例 ${policy.rollout_percent === null ? '未设置' : `${policy.rollout_percent}%`}）`}
        loading={pendingPolicyAction === 'rollback'}
        disabled={pendingPolicyAction !== null}
        onClick={() => {
          if (policyActionRef.current?.pending) return
          const currentVersion = policy.active_version ?? '未设置'
          const targetVersion = policy.previous_version
          const currentRollout = policy.rollout_percent === null ? '未设置' : `${policy.rollout_percent}%`
          confirm({
            title: '确认回滚上传策略？',
            content: <Space direction="vertical" size={8}>
              <Descriptions size="small" column={1}>
                <Descriptions.Item label="当前版本">{currentVersion}</Descriptions.Item>
                <Descriptions.Item label="目标版本">{targetVersion}</Descriptions.Item>
                <Descriptions.Item label="当前灰度比例">{currentRollout}</Descriptions.Item>
              </Descriptions>
              <Text type="secondary">将恢复目标版本，新任务立即使用上一版本；已排队任务仍使用原快照。</Text>
            </Space>,
            okText: '确认回滚',
            okButtonProps: { danger: true },
            cancelText: '取消',
            onOk: () => perform('rollback', async () => {
              const rolledBack = await rollbackUploadPolicy()
              if (
                rolledBack.active_version !== targetVersion
                || rolledBack.previous_version !== currentVersion
              ) throw new Error('upload policy rollback response binding mismatch')
            }, '策略已回滚。'),
          })
        }}
      >回滚上一版本</Button> : null}
    >
      <Table
        columns={columns}
        dataSource={versions}
        rowKey="id"
        pagination={false}
        locale={{ emptyText: <Empty description="尚未登记策略版本" /> }}
        scroll={{ x: 980 }}
      />
    </Card>
  </>
}
