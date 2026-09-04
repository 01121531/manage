import { useEffect, useRef, useState } from 'react'
import { Alert, App as AntApp, Button, Card, Descriptions, Empty, Space, Table, Select, Typography } from 'antd'
import type { TableColumnsType } from 'antd'
import { approveRoleChangeRequest, batchDisableUsers, createRoleChangeRequest, disableUser, listDevices, listRoleChangeRequests, listUsers, revokeDevice } from '../admin-api'
import type { UserManager } from 'oidc-client-ts'
import type { AdminDevice, AdminUser, ManagedUserRole, Principal, RoleChangeRequest } from '../types'
import { useScopedConfirm } from '../useScopedConfirm'
import { useViewActionScope } from '../useViewActionScope'
import { RemoteTable, StatusTag, compareTableDate, compareTableText, formatLocalDateTime, managedUserRoles, roleNames } from './shared'

const { Title, Text } = Typography

function matchesDisabledUserReceipt(receipt: AdminUser, target: AdminUser) {
  return receipt.id === target.id
    && receipt.tenant_id === target.tenant_id
    && receipt.email === target.email
    && receipt.role === target.role
    && receipt.created_at === target.created_at
    && !receipt.is_active
}

function matchesPendingRoleRequestReceipt(
  receipt: RoleChangeRequest,
  target: AdminUser,
  role: ManagedUserRole,
  principal: Principal,
) {
  const createdAt = Date.parse(receipt.created_at)
  const expiresAt = Date.parse(receipt.expires_at)
  return receipt.id.trim().length > 0
    && receipt.tenant_id === principal.tenant_id
    && receipt.target_user_id === target.id
    && receipt.expected_old_role === target.role
    && receipt.new_role === role
    && receipt.status === 'pending'
    && receipt.requested_by === principal.id
    && receipt.approved_by === null
    && receipt.approval_trace_id === null
    && receipt.applied_at === null
    && receipt.request_trace_id.trim().length > 0
    && Number.isFinite(createdAt)
    && Number.isFinite(expiresAt)
    && expiresAt > createdAt
}

function matchesAppliedRoleRequestReceipt(
  receipt: RoleChangeRequest,
  request: RoleChangeRequest,
  principal: Principal,
) {
  if (receipt.applied_at === null || receipt.approval_trace_id === null) return false
  const createdAt = Date.parse(receipt.created_at)
  const expiresAt = Date.parse(receipt.expires_at)
  const appliedAt = Date.parse(receipt.applied_at)
  return receipt.id === request.id
    && receipt.tenant_id === request.tenant_id
    && receipt.tenant_id === principal.tenant_id
    && receipt.target_user_id === request.target_user_id
    && receipt.expected_old_role === request.expected_old_role
    && receipt.new_role === request.new_role
    && receipt.requested_by === request.requested_by
    && receipt.created_at === request.created_at
    && receipt.expires_at === request.expires_at
    && receipt.request_trace_id === request.request_trace_id
    && receipt.status === 'applied'
    && receipt.approved_by === principal.id
    && receipt.approval_trace_id.trim().length > 0
    && Number.isFinite(createdAt)
    && Number.isFinite(expiresAt)
    && Number.isFinite(appliedAt)
    && appliedAt >= createdAt
    && appliedAt <= expiresAt
}

export default function UsersPage({ principal, oidcManager, roleChangeAcr }: {
  principal: Principal
  oidcManager: UserManager | null
  roleChangeAcr: string | null
}) {
  const { message } = AntApp.useApp()
  const confirm = useScopedConfirm()
  const beginViewAction = useViewActionScope()
  const [rows, setRows] = useState<AdminUser[]>([])
  const [loading, setLoading] = useState(true)
  const [userListError, setUserListError] = useState<string>()
  const [refresh, setRefresh] = useState(0)
  const [deviceRefresh, setDeviceRefresh] = useState(0)
  const [revokingDeviceId, setRevokingDeviceId] = useState<string | null>(null)
  const deviceActionRef = useRef<{ deviceId: string; pending: boolean } | null>(null)
  const deviceActionRefreshRef = useRef<{ deviceId: string; pending: boolean } | null>(null)
  const [userActionKey, setUserActionKey] = useState<string | null>(null)
  const userActionRef = useRef<{ key: string; pending: boolean } | null>(null)
  const userActionRefreshRef = useRef<{
    action: { key: string; pending: boolean }
    usersSettled: boolean
    devicesSettled: boolean
  } | null>(null)
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([])
  const [roleRequests, setRoleRequests] = useState<RoleChangeRequest[]>([])
  const isPlatformAdmin = principal.role === 'platform_admin'
  const canDisable = (row: AdminUser) => row.is_active
    && row.id !== principal.id
    && (isPlatformAdmin || row.role !== 'platform_admin')
  useEffect(() => {
    let alive = true
    setLoading(true)
    setUserListError(undefined)
    setRows([])
    setSelectedUserIds([])
    Promise.all([
      listUsers(),
      isPlatformAdmin ? listRoleChangeRequests() : Promise.resolve([]),
    ]).then(([items, requests]) => {
      if (alive) {
        setRows(items)
        setRoleRequests(requests)
      }
    })
      .catch(() => {
        if (alive) {
          setUserListError('平台未能读取用户与角色申请真实状态。')
        }
      })
      .finally(() => {
        if (!alive) return
        setLoading(false)
        settleUserActionRefresh('users')
      })
    return () => { alive = false }
  }, [isPlatformAdmin, refresh])

  function refreshUsersFromServer() {
    setLoading(true)
    setUserListError(undefined)
    setRows([])
    setRoleRequests([])
    setSelectedUserIds([])
    setRefresh((value) => value + 1)
  }

  function reserveUserAction(key: string) {
    if (userActionRef.current !== null || deviceActionRef.current !== null) return null
    const action = { key, pending: false }
    userActionRef.current = action
    setUserActionKey(key)
    return action
  }

  function releaseUserAction(action: { key: string; pending: boolean }) {
    if (userActionRef.current !== action) return
    userActionRef.current = null
    setUserActionKey(null)
  }

  function settleUserActionRefresh(source: 'users' | 'devices') {
    const refreshAction = userActionRefreshRef.current
    if (refreshAction === null) return
    if (source === 'users') refreshAction.usersSettled = true
    else refreshAction.devicesSettled = true
    if (!refreshAction.usersSettled || !refreshAction.devicesSettled) return
    userActionRefreshRef.current = null
    releaseUserAction(refreshAction.action)
  }

  async function runUserAction(
    action: { key: string; pending: boolean },
    operation: () => Promise<unknown>,
    success: string,
  ) {
    if (userActionRef.current !== action || action.pending) return
    action.pending = true
    const isCurrent = beginViewAction()
    try {
      await operation()
      if (!isCurrent()) return false
      message.success(success)
      return true
    } catch {
      if (!isCurrent()) return false
      message.error(
        '原因：平台未能确认用户治理操作结果。'
        + '影响：用户状态、角色申请或审批可能已经变更，相关会话与活动资源也可能已回收；页面不会按失败响应推断最终状态。'
        + '下一步：正在重新读取用户、待审批申请和设备真实状态；仅当目标动作仍可用时，才从同一对象入口重试。',
      )
      return false
    } finally {
      if (isCurrent()) {
        userActionRefreshRef.current = {
          action,
          usersSettled: false,
          devicesSettled: false,
        }
        refreshUsersFromServer()
        setDeviceRefresh((value) => value + 1)
      }
    }
  }

  function confirmDisable(userIds: string[]) {
    const targets = userIds.map((id) => rows.find((row) => row.id === id))
    if (targets.some((target) => target === undefined)) {
      message.error('用户列表已变化，请刷新后重新选择。')
      return
    }
    const targetUsers = targets as AdminUser[]
    const finalUserIds = targetUsers.map((target) => target.id)
    const key = `disable:${[...finalUserIds].sort().join(',')}`
    const action = reserveUserAction(key)
    if (!action) return
    confirm({
      title: finalUserIds.length === 1
        ? `确认停用用户 ${targetUsers[0].email}？`
        : `确认批量停用 ${finalUserIds.length} 个用户？`,
      content: <Space direction="vertical" size={8} style={{ width: '100%' }}>
        <Text>请核对待停用用户：</Text>
        <ul
          aria-label="待停用用户列表"
          style={{ maxHeight: 220, margin: 0, overflowY: 'auto', paddingInlineStart: 24, width: '100%' }}
        >
          {targetUsers.map((target) => <li key={target.id}>{target.email}（{target.id}）</li>)}
        </ul>
        <Text type="danger">停用会立即使现有会话失效，并回收其活动任务、卡租约和邮箱会话。</Text>
      </Space>,
      okText: '确认停用',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onCancel: () => {
        if (!action.pending) releaseUserAction(action)
      },
      onOk: () => runUserAction(
        action,
        async () => {
          if (finalUserIds.length === 1) {
            const updated = await disableUser(finalUserIds[0])
            if (!matchesDisabledUserReceipt(updated, targetUsers[0])) {
              throw new Error('user disable response binding mismatch')
            }
            return
          }
          const updated = await batchDisableUsers(finalUserIds)
          const expectedIds = new Set(finalUserIds)
          const targetsById = new Map(targetUsers.map((user) => [user.id, user]))
          const returnedIds = new Set(updated.map((user) => user.id))
          if (
            updated.length !== expectedIds.size
            || returnedIds.size !== expectedIds.size
            || updated.some((user) => {
              const target = targetsById.get(user.id)
              return target === undefined || !matchesDisabledUserReceipt(user, target)
            })
          ) throw new Error('batch user disable response binding mismatch')
        },
        finalUserIds.length === 1 ? '用户已停用。' : `已停用 ${finalUserIds.length} 个用户。`,
      ).then((succeeded) => {
        if (succeeded) {
          setSelectedUserIds((current) => current.filter((id) => !finalUserIds.includes(id)))
        }
      }),
    })
  }

  function confirmRoleChange(row: AdminUser, role: ManagedUserRole) {
    if (role === row.role) return
    const action = reserveUserAction(`role-request:${row.id}`)
    if (!action) return
    confirm({
      title: '确认创建角色变更申请？',
      content: <Space direction="vertical" size={8}>
        <Text>{row.email}：{roleNames[row.role] ?? row.role} → {roleNames[role] ?? role}</Text>
        <Text type="secondary">本次只创建申请，不会立即改变权限。另一位平台管理员必须在申请创建后重新完成 MFA，才能审批生效。</Text>
      </Space>,
      okText: '创建申请',
      cancelText: '取消',
      onCancel: () => {
        if (!action.pending) releaseUserAction(action)
      },
      onOk: () => runUserAction(
        action,
        async () => {
          const request = await createRoleChangeRequest(row.id, role)
          if (!matchesPendingRoleRequestReceipt(request, row, role, principal)) {
            throw new Error('role change request response binding mismatch')
          }
        },
        '角色变更申请已创建，等待另一位平台管理员完成 fresh MFA 后审批。',
      ),
    })
  }

  function beginFreshMfa(request: RoleChangeRequest) {
    if (request.requested_by === principal.id) return
    if (!oidcManager || !roleChangeAcr) {
      message.error('当前会话不是 OIDC 会话，无法完成 fresh MFA；请通过统一身份登录后重试。')
      return
    }
    const action = reserveUserAction(`mfa-role:${request.id}`)
    if (!action) return
    action.pending = true
    void oidcManager.signinRedirect({
      prompt: 'login',
      acr_values: roleChangeAcr,
    }).catch(() => {
      message.error('fresh MFA 未能启动；申请仍保持待审批，请检查身份服务后重试。')
      refreshUsersFromServer()
    }).finally(() => releaseUserAction(action))
  }

  function confirmRoleRequestApproval(request: RoleChangeRequest) {
    const action = reserveUserAction(`approve-role:${request.id}`)
    if (!action) return
    const target = rows.find((row) => row.id === request.target_user_id)
    confirm({
      title: '确认审批角色变更申请？',
      content: <Space direction="vertical" size={8}>
        <Descriptions size="small" column={1}>
          <Descriptions.Item label="目标用户">{target?.email ?? request.target_user_id}</Descriptions.Item>
          <Descriptions.Item label="角色变更">{roleNames[request.expected_old_role]} → {roleNames[request.new_role]}</Descriptions.Item>
          <Descriptions.Item label="申请人">{request.requested_by}</Descriptions.Item>
          <Descriptions.Item label="创建时间">{formatLocalDateTime(request.created_at)}</Descriptions.Item>
          <Descriptions.Item label="到期时间">{formatLocalDateTime(request.expires_at)}</Descriptions.Item>
        </Descriptions>
        <Text type="danger">审批 Bearer 必须来自本申请创建后的 fresh MFA；前端不会代替服务端判断 MFA 是否合格。</Text>
      </Space>,
      okText: '审批并应用角色',
      cancelText: '取消',
      onCancel: () => {
        if (!action.pending) releaseUserAction(action)
      },
      onOk: () => runUserAction(
        action,
        async () => {
          const approved = await approveRoleChangeRequest(request.id)
          if (!matchesAppliedRoleRequestReceipt(approved, request, principal)) {
            throw new Error('role change approval response binding mismatch')
          }
        },
        '角色变更已由独立管理员审批并应用。',
      ),
    })
  }

  function confirmRevokeDevice(row: AdminDevice) {
    if (deviceActionRef.current !== null || userActionRef.current !== null) return
    deviceActionRef.current = { deviceId: row.id, pending: false }
    confirm({
      title: '确认撤销设备？',
      content: <Space direction="vertical" size={8}>
        <Text>设备：{row.name}（{row.id}）</Text>
        <Text>所属用户：{row.user_id}</Text>
        <Text type="danger">撤销后该设备会话立即失效，活动任务将取消，卡租约释放，邮箱会话终止；此操作不可撤销。</Text>
      </Space>,
      okText: '撤销设备并回收资源',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onCancel: () => {
        if (!deviceActionRef.current?.pending) deviceActionRef.current = null
      },
      onOk: async () => {
        const action = deviceActionRef.current
        if (action?.deviceId !== row.id || action.pending) return
        action.pending = true
        setRevokingDeviceId(row.id)
        try {
          const updated = await revokeDevice(row.id)
          if (
            updated.id !== row.id
            || updated.tenant_id !== principal.tenant_id
            || updated.user_id !== row.user_id
            || updated.name !== row.name
            || updated.created_at !== row.created_at
            || updated.revoked_at === null
          ) {
            throw new Error('device revoke response binding mismatch')
          }
          message.success('设备已撤销，相关会话与活动资源已回收。')
        } catch {
          message.error(
            '原因：平台未能确认设备撤销结果。'
            + '影响：设备可能已被撤销，关联会话和活动资源也可能已回收；页面不会按失败响应推断最终状态。'
            + '下一步：正在重新获取设备真实状态；完成前不得重复设备或用户治理，仅当刷新后目标仍活动才重试。',
          )
        } finally {
          if (deviceActionRef.current === action) {
            deviceActionRefreshRef.current = action
            setDeviceRefresh((value) => value + 1)
          }
        }
      },
    })
  }

  const columns: TableColumnsType<AdminUser> = [
    { title: '账号', dataIndex: 'email', sorter: (left, right) => compareTableText(left.email, right.email) },
    {
      title: '角色', dataIndex: 'role',
      filters: managedUserRoles.map((role) => ({ text: roleNames[role], value: role })),
      onFilter: (value, row) => row.role === value,
      render: (role: string, row) => isPlatformAdmin && row.id !== principal.id && managedUserRoles.includes(role as ManagedUserRole)
        ? <Select
          aria-label={`申请调整 ${row.email} 角色`}
          value={role as ManagedUserRole}
          className="role-select"
          loading={userActionKey === `role-request:${row.id}`}
          disabled={userActionKey !== null || revokingDeviceId !== null || roleRequests.some((request) => request.target_user_id === row.id)}
          options={managedUserRoles.map((value) => ({ value, label: roleNames[value] }))}
          onChange={(value: ManagedUserRole) => confirmRoleChange(row, value)}
        />
        : roleNames[role] ?? role,
    },
    {
      title: '状态', dataIndex: 'is_active',
      filters: [{ text: '启用', value: 'active' }, { text: '停用', value: 'disabled' }],
      onFilter: (value, row) => (row.is_active ? 'active' : 'disabled') === value,
      render: (active: boolean) => <StatusTag value={active ? 'active' : 'disabled'} />,
    },
    { title: '创建时间', dataIndex: 'created_at', sorter: (left, right) => compareTableDate(left.created_at, right.created_at) },
    { title: '操作', render: (_, row) => <Button
      danger
      loading={userActionKey === `disable:${row.id}`}
      disabled={!canDisable(row) || userActionKey !== null || revokingDeviceId !== null}
      aria-label={`停用用户 ${row.email}`}
      onClick={() => confirmDisable([row.id])}
    >停用</Button> },
  ]
  const roleRequestColumns: TableColumnsType<RoleChangeRequest> = [
    {
      title: '目标用户',
      dataIndex: 'target_user_id',
      render: (userId: string) => rows.find((row) => row.id === userId)?.email ?? userId,
    },
    {
      title: '角色变更',
      render: (_, row) => `${roleNames[row.expected_old_role]} → ${roleNames[row.new_role]}`,
    },
    { title: '申请人', dataIndex: 'requested_by' },
    {
      title: '审批人',
      dataIndex: 'approved_by',
      render: (value: string | null) => value ?? '待另一位管理员',
    },
    { title: '创建时间', dataIndex: 'created_at', sorter: (left, right) => compareTableDate(left.created_at, right.created_at), render: formatLocalDateTime },
    { title: '到期时间', dataIndex: 'expires_at', sorter: (left, right) => compareTableDate(left.expires_at, right.expires_at), render: formatLocalDateTime },
    {
      title: '操作',
      render: (_, row) => row.requested_by === principal.id
        ? <Text type="secondary">申请人不能审批</Text>
        : <Space wrap>
          <Button
            aria-label={`为角色申请 ${row.id} 重新完成 MFA`}
            loading={userActionKey === `mfa-role:${row.id}`}
            disabled={userActionKey !== null || revokingDeviceId !== null || !oidcManager || !roleChangeAcr}
            onClick={() => beginFreshMfa(row)}
          >重新 MFA 登录</Button>
          <Button
            aria-label={`审批角色申请 ${row.id}（要求申请后 fresh MFA）`}
            loading={userActionKey === `approve-role:${row.id}`}
            disabled={userActionKey !== null || revokingDeviceId !== null}
            onClick={() => confirmRoleRequestApproval(row)}
          >审批（要求 fresh MFA）</Button>
        </Space>,
    },
  ]
  const deviceColumns: TableColumnsType<AdminDevice> = [
    { title: '设备名称', dataIndex: 'name', sorter: (left, right) => compareTableText(left.name, right.name) },
    { title: '设备 ID', dataIndex: 'id', render: (value: string) => <Text code copyable={{ text: value }}>{value}</Text> },
    { title: '所属用户', dataIndex: 'user_id', render: (value: string) => <Text code copyable={{ text: value }}>{value}</Text> },
    {
      title: '状态', dataIndex: 'revoked_at',
      filters: [{ text: '活动', value: 'active' }, { text: '已撤销', value: 'revoked' }],
      onFilter: (value, row) => (row.revoked_at ? 'revoked' : 'active') === value,
      render: (value: string | null) => <StatusTag value={value ? 'revoked' : 'active'} />,
    },
    { title: '最后活跃', dataIndex: 'last_seen_at', sorter: (left, right) => compareTableDate(left.last_seen_at, right.last_seen_at), render: (value: string | null) => value ? formatLocalDateTime(value) : '从未活跃' },
    { title: '创建时间', dataIndex: 'created_at', sorter: (left, right) => compareTableDate(left.created_at, right.created_at) },
    { title: '操作', render: (_, row) => <Button
      danger
      loading={revokingDeviceId === row.id}
      disabled={row.revoked_at !== null || revokingDeviceId !== null || userActionKey !== null}
      onClick={() => confirmRevokeDevice(row)}
    >撤销设备</Button> },
  ]
  const selectedDisableKey = `disable:${[...selectedUserIds].sort().join(',')}`
  return <><div className="page-heading"><div><Title level={2}>用户与权限</Title><Text type="secondary">按角色授予最小权限；角色变更需要四眼审批和申请后的 fresh MFA，停用会回收活动资源。</Text></div><Button
    danger
    loading={selectedUserIds.length > 0 && userActionKey === selectedDisableKey}
    disabled={selectedUserIds.length === 0 || userActionKey !== null || revokingDeviceId !== null}
    onClick={() => confirmDisable(selectedUserIds)}
  >批量停用{selectedUserIds.length > 0 ? ` (${selectedUserIds.length})` : ''}</Button></div>
    {userListError ? <Alert
      className="section-card"
      type="error"
      showIcon
      message="用户与角色申请列表暂不可用"
      description={`原因：${userListError} 影响：无法确认用户角色、启用状态和待审批申请，已隐藏相关操作。 下一步：请重试；读取成功前不要重复执行用户变更。`}
      action={<Button aria-label="重试用户列表" onClick={refreshUsersFromServer}>重试</Button>}
    /> : null}
    <Card title="用户">{userListError ? null : <Table
        loading={loading}
        columns={columns}
        dataSource={rows}
        rowKey="id"
        rowSelection={{
          selectedRowKeys: selectedUserIds,
          onChange: (keys) => setSelectedUserIds(keys.map(String)),
          getCheckboxProps: (row) => ({
            'aria-label': `选择用户 ${row.email}`,
            disabled: !canDisable(row) || userActionKey !== null || revokingDeviceId !== null,
          }),
        }}
        locale={{ emptyText: <Empty description="暂无用户" /> }}
        scroll={{ x: 900 }}
      />}</Card>
    {isPlatformAdmin && !userListError ? <Card className="section-card" title="待审批角色变更申请">
      <Alert
        className="section-card"
        type="info"
        showIcon
        message="审批必须由另一位平台管理员完成"
        description="审批人需要在申请创建后重新完成 MFA，再使用新会话审批；申请人不能审批自己的申请。"
      />
      <Table
        loading={loading}
        columns={roleRequestColumns}
        dataSource={roleRequests}
        rowKey="id"
        locale={{ emptyText: <Empty description="暂无待审批角色申请" /> }}
        scroll={{ x: 1100 }}
      />
    </Card> : null}
    <Card className="section-card" title="设备"><RemoteTable
      key={deviceRefresh}
      loader={listDevices}
      columns={deviceColumns}
      empty="暂无设备"
      onSettled={() => {
        settleUserActionRefresh('devices')
        const action = deviceActionRefreshRef.current
        if (action === null) return
        deviceActionRefreshRef.current = null
        if (deviceActionRef.current === action) deviceActionRef.current = null
        setRevokingDeviceId((current) => current === action.deviceId ? null : current)
      }}
    /></Card>
  </>
}
