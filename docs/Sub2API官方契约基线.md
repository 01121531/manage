# Sub2API 官方契约基线

本项目以目标后台页面显示的 `v0.1.169` 为部署兼容基线。对应 Sub2API 官方标签为
[`v0.1.169`](https://github.com/Wei-Shaw/sub2api/tree/v0.1.169)，解引用提交为
`26d894ef4f50645a4bf1030e378ac892f17d0223`。官方仓库当前 `main` 仅作为升级参考，
不能替代目标部署的构建和运行配置证明。`ai1.aisb.shop` 不是官方 README 声明的官方域名，
因此以下源码结论不得自动提升为该目标的生产验收结论。

## 官方流程与仓库能力边界

官方 Web 流程与遗留 OAuth 工具呈现以下调用顺序：

1. `POST /api/v1/admin/openai/generate-auth-url`
2. `POST /api/v1/admin/openai/exchange-code`
3. `POST /api/v1/admin/accounts`

`redirect_uri` 若存在，必须在前两步保持相同。第三步使用由 OAuth `session_id` 的 SHA-256
摘要生成的稳定 `Idempotency-Key`；摘要不会暴露原始会话值。官方账号创建 handler 会将幂等键
与管理员主体、HTTP 方法、路由和请求载荷指纹绑定，成功重放返回
`X-Idempotency-Replayed: true`。

仓库中的管理 Adapter 只提供上述管理控制面调用原语和按 account ID
的只读探针；当前没有平台任务、持久化状态机或 Worker 调度器把 OAuth 生成/兑换
与后续账户创建串成运行链。因此这里是能力和安全边界，不是已完成 OAuth
两阶段任务链或端到端开户的声明。

不把 `POST /api/v1/admin/openai/create-from-oauth` 作为失败回退：授权码兑换成功后会删除
OAuth session，而且该组合端点没有官方幂等包装或按 operation/key 查询的恢复接口。创建成功但
响应丢失时必须标记为结果不确定并人工核对，不能再次自动创建。

## 鉴权与幂等运行边界

- 官方管理员中间件优先接受 `x-api-key`，并兼容管理员 JWT Bearer；正式服务端 Adapter 应从
  Secret Manager/Vault 读取独立管理 API key，不复制浏览器 Cookie 或 JWT。
- 官方默认幂等配置为 observe-only，默认记录 TTL 为 24 小时。只有目标部署确认 coordinator、
  store、observe-only 开关和 TTL 后，才能把源码能力视为目标运行保证。
- `GET /api/v1/admin/accounts/{id}` 可在已取得 account ID 后做本地落库复核；OpenAI quota/usage
  还依赖上游网络，只能作为可选凭据探测，不能推翻账号已经创建的事实。

## 与通用上传 Adapter 的隔离

`platform/uploads.py` 的通用 Sub2 上传载荷包含业务名、卡 secret 解引用结果和平台任务字段；
Sub2API 官方账号管理合同不接收 PAN，也不返回通用上传 Adapter 所需的
`external_ref`。因此账号管理路由不得配置为通用上传 URL，现有 ai1 控制面
出站拒绝必须保留。仓库为管理控制面另设服务端 Adapter，并继续由版本化
服务端策略控制代理、分组和并发。

仓库中的 `platform/sub2_admin.py` 已提供该独立边界：只允许精确的 HTTPS
`/api/v1/admin` 基址和显式 allowlist origin，只从 SecretResolver 解引用 `x-api-key`，不发送
Bearer、Cookie、Origin/Referer 或卡字段；实现 generate、exchange、带幂等键的通用账户创建及
按 account ID 回读。下发的 OAuth URL 还必须精确属于
`https://auth.openai.com/oauth/authorize` 且只包含一个非空 `state`；兑换结果会保留官方
`chatgpt_account_is_fedramp` 身份标志。兑换和创建的网络失败、409/429/5xx 统一进入 unknown，
不自动重复消费授权码或创建账号。

对应运行配置为 `PLATFORM_SUB2_ADMIN_BASE_URL`、`PLATFORM_SUB2_ADMIN_API_KEY_REF`、
`PLATFORM_SUB2_ADMIN_PROXY_ID` 和 `PLATFORM_SUB2_ADMIN_MODEL_MAPPING_FILE`。正式环境的 key
配置只允许 `vault://` 引用；工厂创建 Adapter 时不提前解引用，便于 Vault 原地轮换。模型映射
来自有界、稳定、拒绝重复键的服务端 JSON 策略文件，不能由客户端覆盖。按源方案，
这些输入只接入既有 `worker-sub2`，并与 API 及 `worker-mail` 隔离；方案不要求另建
provisioning Worker。现有 `UploadJob` 执行链仍走供应商无关的 `Sub2Adapter`
（运行时为 `HttpSub2Adapter` 或失败关闭实现），不会调用管理 Adapter；也不得为方便
接线而扩大 API 进程的 Vault 权限。

替换管理员 key 写入 Vault 后，应从相同 `worker-sub2` 运行边界执行
`python scripts/probe_sub2_admin.py`。该探针固定只读请求账户列表第一页的一条记录，
丢弃响应中的账户数据，只输出连接和鉴权两个布尔结果；不得把 key 写入命令行、日志或仓库。

## 仍需目标环境提供

- 实际 build SHA/tag 与管理员 API key 的权限、轮换和吊销证明；
- 幂等 coordinator/store、observe-only 与 TTL 的真实配置及脱敏重放样例；
- 兑换、创建成功/拒绝/超时响应，以及响应丢失后的人工核对运行手册；
- quota 成功形状与其是否参与业务准入的明确约定。

本文件不包含 token、Cookie、OAuth code/state/session、账号标识、邮箱或卡数据，且
`production_acceptance=false`。
