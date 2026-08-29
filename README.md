# 邮箱验证码助手

## 平台化迁移状态

当前已完成平台账号、设备绑定、幂等任务、脱敏审计、服务端邮箱会话、卡租约和
Sub2 上传作业边界：
`platform/` 是后端 API，`platform_client.py` 是 EXE 的安全 HTTP 边界，
`platform_desktop.py` 是默认启动窗口。旧邮箱直连和客户端 Sub2 代码仍保留在源码中
供迁移期回归，但默认 EXE 不再启动它们，不应继续扩散部署。

平台后端的启动、配置、首个用户创建与 API 契约见
[`platform/README.md`](platform/README.md)。真实邮箱、Secret Manager 和 Sub2 HTTP 适配器仍需按实际接口配置后部署。
本地和 CI 质量门禁使用 [`scripts/quality_gate.ps1`](scripts/quality_gate.ps1)，
覆盖平台测试、EXE/客户端测试、迁移 SQL、Compose 环境变量、轻量密钥扫描和前端构建。
另有 [`./.github/workflows/security.yml`](.github/workflows/security.yml) 作为 PR/推送时的
CI 安全门禁，会额外跑 release 锁、signoff 模板和依赖审计。

轻量密钥扫描会在遍历时剪枝既有忽略目录，并将每个候选文件限制为 16 MiB 的单次稳定
普通文件读取；空文件及既有非 UTF-8 二进制保持跳过。超限、链接/reparse、非普通打开对象、
读取漂移或遍历失败都会以固定且不含底层系统错误的结果关闭质量门。Windows `.exe` 文件名
投影出的执行位不视为权限漂移，实际读写模式变化仍会被拒绝。
[`./.github/workflows/ci.yml`](.github/workflows/ci.yml) 在质量门禁通过后使用独立
Windows Runner 和锁定的 [`requirements-desktop-build.txt`](requirements-desktop-build.txt)
真实执行 `build.ps1`，再次检查 EXE 归档与 SHA-256，并按提交 SHA 上传 14 天保留的
构建制品。CI 与 Tag Release 还会在 PostgreSQL 16 服务上真实执行 Alembic 在线
`upgrade head`，校验仓库只有一个迁移 head 且数据库 `alembic_version` 与其一致；
迁移门禁失败时不会生成 Windows 制品、推送容器或发布 GitHub Release。
普通 CI 使用的所有第三方 GitHub Actions 也固定到仓库批准的完整 commit SHA，
任何 tag、短 SHA、未知 SHA 或未知外部 Action 都会使结构门禁失败。

`frontend/` 是 React + TypeScript + Ant Design 运营控制台，包含工作台、任务、卡池、
邮箱连接器、Sub2 上传、用户权限、审计和策略入口。生产认证使用 Keycloak OIDC
Authorization Code + PKCE；访问令牌只保存在页面内存，浏览器刷新后需要重新认证。
Sub2 策略入口只登记服务端配置快照的版本和变更说明，采用双人审批、灰度发布和
可审计回滚；审批、灰度、全量启用和回滚共享 single-flight 状态，变更期间其他入口禁用，
成功或失败都会刷新服务端真实状态。浏览器不会接收代理、分组、并发或凭据引用。
上传取消同样采用明确影响确认和 single-flight：queued 可直接取消，running 仅请求停止并需
刷新核对；操作期间取消与人工核对入口统一禁用，失败后也会刷新服务端真实状态再允许重试。
核心运营表支持键盘可达的列排序和状态筛选；状态同时使用文字、图标和颜色表达。管理台在
768px 宽度下收起侧栏，页面不产生横向溢出，宽表仅在自身容器内滚动，并保留高对比焦点环。
本地开发可运行 `cd frontend; npm install; npm run dev`，生产构建用 `npm run build`。
生产构建将仓库入口固定为显式 `app-shell`，保留 React 与经审查的 RC runtime 边界，其余依赖交由真实模块图拆分，
将 OIDC 客户端隔离为条件式动态入口，并让 Ant Design 按真实静态/动态模块图分配；任一 JavaScript chunk 超过 500 KiB 会直接失败，
Rollup 输出门禁还会按模块归属拒绝 Ant Design、`@ant-design` 或 RC runtime 进入入口静态闭包，不允许通过改名 chunk 或抬高 warning 阈值掩盖回归。登录后管理 Shell 和八个管理页面均采用独立动态入口；构建会
校验 authenticated shell 只由应用入口动态持有、八个 view chunk 只由 authenticated shell 动态持有且互异、
八个页面共享的管理 API wrapper 固定为独立延迟 chunk、OIDC 为独立动态入口、上述动态代码均未进入 HTML eager closure、共享 view chunk 仍为惰性加载、入口加
app-shell 不超过 24 KiB、管理 API chunk 不超过 8 KiB、完整 eager JavaScript closure 不超过 256 KiB、eager closure 不得包含泛化 `vendor` chunk，未认证 CSS 不超过 5 KiB，且登录后 Shell 的静态延迟闭包不超过 640 KiB、专用 CSS 不超过 4 KiB。未认证页面使用轻量原生登录控件，不会请求 authenticated
shell、管理 API wrapper、管理端 UI runtime 或管理台专用样式；身份建立后才加载导航、专用样式和当前角色允许的首页。local 模式不会请求 OIDC runtime；只有认证配置确认
`mode=oidc` 后才下载该 chunk 并建立 manager。该门禁证明登录后 Shell、管理端 UI runtime、页面业务代码、OIDC 和部分页面专用
UI runtime 按需下载；React 和树摇后的类型安全认证/session API core 仍会预加载，管理 API wrapper 随首个授权页面下载，
不宣称登录后默认 Dashboard 或 OIDC 登录流程最终所需的总字节同步减少。
后端接口变化后运行 `cd frontend; npm run generate:api` 更新自动生成的 TypeScript
契约；质量门禁会执行 `npm run check:api`，契约过期时直接失败。
浏览器回归使用 `cd frontend; npm run test:e2e`；CI 会安装 Chromium 并验证登录、
角色菜单、四眼角色变更申请、任务 trace_id、高风险设备撤销与任务关闭的确认/单次提交、
失败后的真实状态恢复，以及 access token 不写入浏览器持久化存储。
阶段验收、真实环境缺口和下一轮输入统一维护在
[`docs/实施进度与待确认事项.md`](docs/实施进度与待确认事项.md)。
方案第 1-11 章的逐项证据与缺口分类保存在
[`deploy/plan-requirement-inventory.json`](deploy/plan-requirement-inventory.json)，可用
`python scripts/verify_plan_requirements.py` 校验源文档摘要、51 项闭合清单、证据路径和非生产边界。
T149 对源方案、需求库存、阶段矩阵、完成账本和 T140–T148 入口的权威复核见
[`deploy/plan-completion-audit-t149.md`](deploy/plan-completion-audit-t149.md)；该审计明确冻结继续叠加
离线签署断言层，真实 Sub2 契约仍是首个外部输入缺口。
源方案 DOCX 只通过 5 MiB 有界稳定普通文件读取一次，并从同一份字节计算登记 SHA-256；
空文件、超限、链接/reparse、非普通文件、读取漂移或命名替换均按固定“源文档不可用”失败。

规模或合规要求提高后的 Kubernetes 拆分路径已提供 fail-closed Kustomize 基线，见
[`deploy/kubernetes/README.md`](deploy/kubernetes/README.md)。它将 API、Web、Mail Worker、
Sub2 Worker 和 release-bound Alembic Job 分开，并固定外部 Secret、内部 TLS、最小权限
ServiceAccount、扩缩容、默认拒绝网络策略与 schema 门禁。`base/` 使用不可拉取的占位镜像和
`.example.invalid` 地址，禁止直接部署；必须由目标环境 overlay 替换镜像摘要、接入外部
Secret/入口/数据服务并完成 server-side dry-run 与真实集群验收。本机仓库证据始终是
`production_acceptance=false`。同一质量门还会交叉核对 Kubernetes 与 Compose 的启动命令、
环境键、方案第 13 章容量默认、API/Worker 的服务端 Sub2 策略输入、发布镜像库存和严格目标
intake 依赖，避免两套部署路径演变成互相矛盾的事实源。

生产 Web/API 已提供独立的双槽发布预检与执行路径，见
[`deploy/runbooks/rolling-release.md`](deploy/runbooks/rolling-release.md)。它在稳定 Edge 后
启动 inactive 槽、校验精确 TLS/发布身份/OCI digest，并用单个 canonical 路由文件原子切换
API 与 Web；失败时先切回并证明旧身份。成功后默认保留旧槽，Worker 仍为单实例路径，
因此本地与 CI 证据始终是 `production_acceptance=false`，不能当作整个平台零停机验收。
执行阶段会在共享锁内首先重验活动路由，并在迁移前、切换后核对两个 Worker 仍使用已认证
源镜像摘要；计划生成后发生的外部路由变化会在任何 Docker 命令前失败关闭。
活动路由与仓库内 blue/green canonical 模板统一使用 16 KiB 有界稳定快照；内容和文件模式
来自同一个经前后校验的文件描述符，链接/reparse、非普通文件、超限、形状或模式漂移都会
失败关闭。真正切流前还会确认当前路由仍是预期来源槽，避免长预检期间的替换被静默覆盖。

发布前内部 TLS 到期检查与公共 Edge TLS 预检也统一使用稳定 PEM 输入：内部 CA bundle 和
Edge fullchain 上限为 256 KiB，单张内部叶证书及所有私钥上限为 64 KiB。解析、证书指纹和
公钥匹配只消费同一次稳定读取的字节；链接/reparse、非普通文件、超限或读取漂移均以既有
脱敏错误失败，不改变 SAN、有效期、信任链或私钥匹配规则。

上述两条 TLS 预检及 Vault token sink 预检读取的生产 `.env`/inventory 也统一限制为
64 KiB，并只从同一个稳定普通文件快照执行严格 UTF-8 解析。恰好位于上限的有效清单保持
可用；超限、链接/reparse 祖先、非普通打开对象或读取中路径替换均按各入口既有脱敏错误
失败，不改变变量白名单、证书/私钥验证、Vault sink 权限或发布/回滚顺序。

EXE 的 OIDC 公共配置与当前 API schema 共用字段集合测试，滚动窗口仍兼容上一版不含
`admin_role_change_acr` 的响应。Sub2 Worker 只把审核过的 PAN/有效期字段投影到上游请求，
Card Vault 中存在的 CVV、PIN、token 或未知字段不会因密钥对象扩展而自动出站。

Windows EXE 同样优先使用系统浏览器 Authorization Code + PKCE（S256），回调只监听
`127.0.0.1` 的随机本地端口；浏览器回调受限时可显式选择设备代码登录，界面会保留可聚焦、
可复制的短登录网址与设备代码，并在取消、过期或终态后安全清理。access token
仅保存在进程内存，refresh token 通过当前 Windows 用户的 DPAPI 加密保存并在到期前轮换；
登录后可使用独立“锁定”入口冻结当前工作。锁定会停止轮询和连续粘贴、清除临时验证码与
卡详情并使在途回调失效，但保留主会话；解锁必须经过 `prompt=login`、`max_age=0` 的隔离
PKCE 重新认证，且租户、用户和设备必须与锁定前一致。
启动时可恢复安全会话，退出登录会同步清除本地 refresh token，并后台撤销旧 refresh token。
平台注销会持久化精确 Bearer 摘要；OIDC 令牌含合法 `sid` 时，还会持久化
`issuer + sid` 的域分离 SHA-256 摘要，使同一身份会话刷新出的其他 access token 在平台侧
一并失效。原始 `sid` 不进入数据库、响应或审计；缺少 `sid` 的提供方保持精确 token 撤销兼容。
身份恢复或重新登录后，EXE 会先读取本设备最新任务，再决定是否开放“创建邮箱任务”。发现
非终态任务时不会自动轮换邮箱 capability，而是展示“接管活动任务”和“关闭活动任务”两个
明确动作；显式接管会重新核对严格 timeline 投影，复用原卡租约、轮换现有邮箱 capability，
并继续验证码或原上传作业轮询。`unknown`/`cancel_pending` 上传保持只读核对态，禁止接管、
关闭或重复提交。
已登录桌面端可打开“任务记录 / trace_id”，仅加载当前账号最近 50 条任务；Web 任务中心同步展示 trace_id，供管理员查询审计链。
验证码与完整卡号只在受控 EXE 中短时出现：验证码到达后显示并复制，卡号必须先确认并通过浏览器 MFA，随后在独立“临时卡详情”行显示 PAN + 有效期且不含 CVV。两者会在服务端截止时间或本地 60 秒上限、失焦、锁定、注销、任务切换、任务终态和关窗时清除；一次性验证码读取若超时或断连会进入“读取结果待核对”，不会自动重试。Web 始终只接收掩码值。
新任务仍在服务端创建邮箱会话或卡租约时，如果用户锁定、注销、切换任务或关闭窗口，客户端会
取消当前创建事务，并使用创建前捕获的短期 access token 在后台补偿关闭晚到的任务。该补偿不
保存 refresh token、每个任务至多执行一次，正常被界面接纳的任务不会被误关；窗口关闭仅做有界
等待，未结束的非守护线程会继续完成有界请求和资源回收。
桌面端对平台 API 与 OIDC discovery/token/revocation 的成功及错误 JSON 响应统一执行 64 KiB
有界读取和全层级唯一 key 解析；恰好位于上限的合法响应保持可用，超限、重复 key 或无效 UTF-8
均按原有脱敏协议错误处理，不改变平台 `trace_id`、OAuth 安全错误码或一次性操作不自动重试边界。

服务端从 Vault 读取 KV v1/v2 秘密时同样只请求 64 KiB+1 字节，并对返回字节执行严格 UTF-8
和全层级唯一 key 解析；恰好 64 KiB 的合法响应保持可用，超限、重复 `data` key、无效 UTF-8
或响应声明的非 UTF-8 charset 均以固定脱敏错误关闭，不会把秘密正文带入异常。

服务端 Mail 与 Sub2 HTTP 适配器复用同一严格 JSON 字节解析边界：两条链路保留 64 KiB+1
有界读取与禁止重定向，忽略响应 charset 元数据并只接受严格 UTF-8、全层级唯一 key；恰好
64 KiB 的合法响应仍可用，重复 key 或无效 UTF-8 只产生固定脱敏错误，不改变 Mail
watermark/waiting/code 投影或 Sub2 确定拒绝、结果不明且不自动重试的分类。

服务端对本地 HS256 与 OIDC RS256 Bearer JWT 统一执行 compact-token 预检：令牌总长最多
8 KiB，header/payload/signature 解码后分别最多 2/6/1 KiB，并要求规范 Base64URL、严格
UTF-8 和全层级唯一 JSON key。恰好 8 KiB 的签名有效令牌仍可用；超限、重复 claim、
无效编码或过深 JSON 在 HMAC/JWKS 前以固定认证错误关闭，不会暴露令牌正文或解析 cause。

服务端读取历史审计 `details_json` 与卡事件 `before_masked`/`after_masked` 时按 UTF-8 字节
执行 64 KiB 上限和全层级唯一 JSON key 解析；恰好 64 KiB 的 legacy 行保持兼容，超限、
重复 key、无效文本或过深结构统一降级为 `{}`。写入脱敏、卡字段白名单、append-only 与
租户隔离保持不变，历史脏行不会把 PAN、凭据或歧义状态带入管理响应和 CSV。

仓库发布快照 verifier 与前端版本 JSON 读取复用 64 KiB 稳定文件边界：拒绝超限、重复
JSON key、链接/reparse、非普通文件及读取中路径/句柄漂移；恰好 64 KiB 的合法快照保持
可验。公开 verify CLI 与 committed snapshot verifier 对无效输入只输出固定
`release-manifest-invalid`，既有版本、迁移 head、镜像集合及 stale mismatch 对账不变。

发布快照装配的其余仓库源输入也复用 64 KiB 稳定文件边界：backend 版本源、Compose
清单及全部 migration 候选都会拒绝超限、链接/reparse、非普通文件和读取漂移；Compose
YAML 在所有 mapping 层级拒绝重复 key。恰好 64 KiB 的合法源仍可读取，既有版本、迁移
head、十一服务镜像集合、第三方 digest 占位以及 committed snapshot 字节保持不变。

生产 Compose 静态检查统一复用 `scripts/external_yaml.py` 的 64 KiB 稳定唯一键 YAML
边界：十三个 Compose 消费者及发布清单拒绝超限、无效 UTF-8、链接/reparse、非普通
文件、读取漂移和任意层级重复 mapping key；支持测试 mutation 的文本注入入口也使用同一
唯一键解析。既有服务、网络、Secret、TLS、镜像、日志和 verifier 成功输出保持不变。

剩余 raw Compose 与非统一 YAML 仓库输入也已接入同一边界：回滚变量库存、目标平台
对齐、Chapter 13 默认决策会先验证生产 Compose 再使用原始文本；Prometheus 配置、
Kubernetes 多文档清单和 rolling Compose 分别使用唯一键单文档、全量多文档及“解析值 +
精确源文本”加载。64 KiB 上限、稳定读取和全层级重复 key 拒绝不会改变 66 个 Compose
输入变量、四个 Kubernetes 工作负载、blue/green 拓扑或既有 verifier 输出。

CI、Security、Tag Release 和容器供应链四个工作流 verifier 也统一使用该 64 KiB 稳定
唯一键 YAML 边界；CI/Release 的测试文本注入采用同一 parser，避免 mutation 检查与真实
文件路径语义分叉。超限、无效 UTF-8、链接/reparse、读取漂移及顶层/嵌套重复 key 均
fail closed，checkout 凭据、CodeQL、完整依赖审计、镜像扫描/签名/证明和发布顺序不变。

Edge/Web Nginx 的三个静态 verifier 统一使用 64 KiB 稳定文本边界读取 Dockerfile、配置模板、
渲染/校验脚本、环境示例及 blue/green canonical route；恰好位于上限的严格 UTF-8 文本保持
可读，超限、无效 UTF-8、链接/reparse、非普通对象或读取漂移均以固定脱敏结果失败。TLS、
上游白名单、安全头、无查询参数日志和双槽路由规则及既有成功输出不变。

备份/恢复工具 verifier 对 PostgreSQL、Redis、Vault、审计归档、输出策略、Docker 环境门禁、
恢复 readiness、README 和两份运行手册也统一使用 64 KiB 稳定文本快照。十一项资产各读取一次，
动态 verifier 模块直接编译同一份已认证源码，并在一次性依赖注册后恢复导入状态；超限、无效
UTF-8、链接/reparse、非普通对象或读取漂移以固定脱敏结果失败。schema-v5 recovery set、HMAC、
写一次输出、恢复顺序、命令面和既有成功输出保持不变。

内部 TLS 静态 verifier 对环境示例、Prometheus/Alertmanager TLS 服务配置、Edge/Web Nginx 配置、
证书到期监控脚本和轮换运行手册同样统一使用 64 KiB 稳定文本快照。七项资产各读取一次，到期
监控 contract 直接编译同一份已认证脚本源码；超限、无效 UTF-8、链接/reparse、非普通对象、
读取漂移及装载异常只产生固定脱敏结果。Compose/Prometheus 继续使用唯一键稳定 YAML 边界，
九个证书身份、SAN/CA/私钥隔离、TLS 1.2+、监控阈值、轮换规则和既有成功输出保持不变。

运行时 Secret verifier 对环境示例、PostgreSQL runtime role 初始化与 PostgreSQL/Redis 健康检查
脚本、平台配置和 Alembic 环境脚本统一使用 64 KiB 稳定文本边界。默认校验时六项资产各读取一次；
测试或静态 mutation 显式注入文本时只读取仍缺失的默认项，完整注入保持零文件读取。超限、无效
UTF-8、链接/reparse、非普通对象或读取漂移只产生固定脱敏结果；Compose 继续使用唯一键稳定
YAML，外部绝对路径、只读 fail-closed bind、禁止 inline credential 和既有成功输出保持不变。

Vault 隔离 verifier 对环境示例、API/Mail/Sub2 三份 HCL policy 和 AppRole/audit 两份配置脚本
统一使用 64 KiB 稳定文本快照，六项资产各读取一次。超限、无效 UTF-8、链接/reparse、非普通
对象或读取漂移只产生固定脱敏结果；生产 Compose 继续使用唯一键稳定 YAML 边界，三服务 token
目录隔离、policy path/capability 白名单、AppRole 结构化状态核验、双审计设备和既有成功输出不变。

目标平台 inventory verifier 对仓库环境契约的默认 `.env.example` 读取也使用 64 KiB 稳定文本
边界；默认入口只读取一次，显式注入环境文本时保持零文件读取。超限、无效 UTF-8、链接/reparse、
非普通对象或读取漂移继续映射为固定 alignment 错误；inventory 的唯一键稳定 JSON、Compose 的
唯一键稳定 YAML、闭 schema、九个 TLS consumer、strict intake 绑定和既有 CLI 退出码保持不变。

Chapter 13 默认决策 verifier 对 Keycloak realm 使用 64 KiB 稳定唯一键 JSON 快照，对环境示例
使用 64 KiB 稳定文本快照；默认入口两项各读取一次，完整文本注入零读取，部分注入只读取缺失项。
默认和注入 realm 均拒绝任意层级重复 key；超限、无效 UTF-8、链接/reparse、非普通对象或读取
漂移只产生既有固定错误。两套 S256 PKCE client、并发默认 10、容量 100/10 和成功输出不变。

Chapter 14 MVI verifier 对质量门脚本使用 64 KiB 稳定文本边界；默认入口读取一次，显式 gate
文本注入保持零文件读取。超限、无效 UTF-8、链接/reparse、非普通对象或读取漂移继续映射为固定
不可用错误；九个 MVI check、资源终态、持久化面、三条 verifier 命令、target execution 外部
边界、`production_acceptance=false` 和既有成功输出保持不变。

CI workflow verifier 对质量门脚本也使用 64 KiB 稳定文本边界；默认入口读取一次，显式
`quality_gate_text` 注入保持零文件读取。超限、无效 UTF-8、链接/reparse、非普通对象或读取
漂移继续映射为固定 `CI workflow is invalid`，CI 唯一键 YAML、最小 token 权限、外部 action
SHA、PostgreSQL 在线迁移、浏览器 E2E、Phase 6 证据和 Windows 制品依赖链保持不变。

Compose 环境 verifier 对 `.env.example` 和 PostgreSQL runtime-role 初始化脚本使用 64 KiB
稳定文本边界；默认入口两项各读取一次，完整 `env_text`/`init_text` 注入零读取，部分注入只读取
缺失项。超限、无效 UTF-8、链接/reparse、非普通对象或读取漂移统一映射为固定加载错误；生产
Compose 继续使用唯一键稳定 YAML，66 项环境变量、Keycloak 独立数据库角色和成功输出不变。

Container hardening verifier 对 PostgreSQL runtime-role 初始化脚本使用 64 KiB 稳定文本边界，
默认入口读取一次。超限、无效 UTF-8、链接/reparse、非普通对象或读取漂移只输出固定
`Cannot inspect container hardening assets`；生产 Compose 的唯一键稳定 YAML、migrate/API/双
worker/Web 只读文件系统、cap-drop、no-new-privileges、迁移依赖和数据库最小权限保持不变。

Container supply-chain verifier 对 API、Web 与 edge 三份 Dockerfile 各执行一次 64 KiB 稳定文本
读取。超限、无效 UTF-8、链接/reparse、非普通对象或读取漂移统一映射为固定
`container-supply-chain-error: Cannot inspect container supply-chain assets`；基础镜像 SHA-256
固定、build→scan→SBOM→sign→attest→release 顺序、CI/Windows 制品依赖和成功输出保持不变。

Deploy-release verifier 保留两份 Compose 的 64 KiB 唯一键稳定 YAML，并对生产/开发环境示例、
部署执行器与第三方镜像扫描器四项文本资产各执行一次 64 KiB 稳定读取。超限、无效 UTF-8、
链接/reparse、非普通对象或读取漂移统一映射为固定 `deploy-release-assets-error: Cannot inspect
deployment assets`；不可变镜像、目标 intake/rollback 前置门、内部 TLS smoke 和 write-once
证据顺序保持不变。

Desktop-package verifier 对 `build.ps1` 和从 `app.py` 可达的九个本地 Python 模块使用 256 KiB
稳定文本边界；同一模块的 AST 导入分析与 legacy 标记扫描共用一次源码快照。超限、无效 UTF-8、
链接/reparse、非普通对象、读取漂移或 AST 失败统一映射为固定 `desktop-package-error: Cannot
inspect desktop package sources`；公开可达图仍返回路径映射，platform-only、Windows 发布目录和
EXE archive 检查保持不变。

HTTP error-boundary verifier 对 `platform/errors.py`、`platform/app.py`、`platform/auth.py` 和
`platform/api/v1/routes.py` 各使用一次 256 KiB 稳定文本读取，并直接把四份快照交给现有 AST
契约检查。超限、无效 UTF-8、链接/reparse、非普通对象或读取漂移统一映射为固定
`http-error-boundary-read: Cannot inspect HTTP error boundary sources`，AST 失败只报告稳定源码
标签；统一错误 envelope、允许响应头、Bearer 精确比较及普通路由 literal detail 约束保持不变。

Keycloak realm verifier 除了以 64 KiB 唯一键稳定 JSON 读取 realm，也对 `frontend/src/oidc.ts`
执行一次 64 KiB 稳定文本读取。OIDC 源码超限、无效 UTF-8、链接/reparse、非普通对象或读取漂移
统一映射为固定 `Keycloak OIDC client source is invalid`；realm 与源码故障仍可区分，浏览器 MFA、
Desktop PKCE/Device Flow、Web 精确 redirect/origin 以及前端 runtime redirect 检查保持不变。

Kubernetes portability verifier 对 `deploy/kubernetes/README.md` 使用一次 64 KiB 稳定文本读取，
并与既有唯一键稳定 YAML/JSON 输入共同验证 portability 基线。runbook 超限、无效 UTF-8、链接/
reparse、非普通对象或读取漂移继续固定映射为 `Kubernetes portability runbook is unavailable`；
base 禁止直用、external Secret、schema gate、server-side dry-run、target intake/Phase 0 和三域契约
标记检查保持不变。

Monitoring-assets verifier 在既有 Compose、Prometheus、Alertmanager 与告警规则唯一键稳定 YAML
之外，对 `.env.example` 执行一次 64 KiB 稳定文本读取。环境示例超限、无效 UTF-8、链接/reparse、
非普通对象或读取漂移统一映射为固定 `Monitoring asset load failed: Cannot inspect monitoring
environment example`；YAML 结构错误仍保留原有诊断，生产 Alertmanager 外部挂载、非占位接收端、
watchdog/page 路由和可选 promtool/amtool 检查保持不变。

OpenAPI client 新鲜度 verifier 对临时生成和仓库内已提交的 schema、TypeScript 四份制品分别执行
一次 256 KiB 稳定文本读取，再复用快照进行 CRLF 归一化和双制品比较。任一制品超限、无效 UTF-8、
链接/reparse、非普通对象或读取漂移统一映射为固定 `Cannot inspect OpenAPI contract artifacts`；
运行时 schema 导出、`openapi-typescript` 生成、stale 提示和成功输出保持不变。

Phase 6 evidence-output verifier 对演练、培训证据和共享输出策略三份 Python 合同源码分别执行
一次 64 KiB 稳定文本读取，再把快照交给原有 AST 检查。任一源码超限、无效 UTF-8、链接/
reparse、非普通对象或读取漂移继续映射为固定 `phase6-evidence-output-error: required file cannot
be read`；纯文本注入验证、写一次预检、fsync、hard-link 发布、发布后校验和 AST 策略诊断保持不变。

Chapter 13 默认决策、Chapter 14 MVI contract、阶段验收矩阵、完成账本和 Chapters 1–11
需求清单也统一使用 64 KiB 稳定唯一键 JSON 边界；完成账本对 Chapter 13/14 补充源的内部
读取采用同一入口。超限、无效 UTF-8、链接/reparse、读取漂移及任意层级重复 key 均
fail closed，闭 schema、完整性摘要、7 个阶段、Chapters 12–14、50 项需求库存和
`production_acceptance=false` 保持不变。

其余普通仓库 JSON 配置入口也已统一到该 64 KiB 边界：Keycloak realm verifier 与
PCI/OIDC 决策对齐共用同一 realm 读取语义；Kubernetes portability 对发布清单、目标 intake
requirements 和 external Secret contract 的读取，以及 migration compatibility baseline
读取，都会拒绝超限、无效 UTF-8、链接/reparse、读取漂移和任意层级重复 key。MFA、OIDC
audience/audit、Kubernetes 镜像/Secret/schema、迁移历史摘要和既有成功输出保持不变。

Migration compatibility verifier 对每个 Alembic Python 候选也只执行一次 64 KiB 稳定读取，
再从同一份字节同时计算已评审 SHA-256、解析 revision 链和检查 expand-only AST；已评审
expansion 的操作扫描直接复用该 AST。超限、链接/reparse、非普通文件、无效 UTF-8 和读取
形状漂移统一 fail closed，0001–0028 历史摘要、0017 compatibility baseline 与成功输出不变。

Forward deployment 与 rollback plan 的清单摘要现在也来自 verifier 已认证的同一次稳定读取：
当前/回滚 container release manifest、PostgreSQL 双库 backup manifest 和 Redis recovery manifest
不会再在验证后通过路径二次读取。共享 JSON loader 可同时返回解析值与原始稳定字节，三个默认
verifier 返回值保持兼容；release/commit/migration head、双库 recovery-set/HMAC、五分钟恢复点
偏差、证据摘要与 `production_acceptance=false` 合同不变。

设备成功登录和有效 Bearer 活动会记录最后活跃时间；活动写入使用独立短事务并按 60 秒节流，
不会提交业务请求事务。失败登录、无效凭据和已撤销设备不会更新该时间，管理台以本地可读时间
展示，尚无成功活动的设备显示“从未活跃”。

### Windows 在线更新

正式 EXE 启动后会在后台检查仓库 `01121531/manage` 的最新 GitHub Release，也可点击
“检查更新”手动检查。客户端只接受该仓库 `releases/` 下的 HTTPS 清单和安装包；下载后
会以 64 KiB 上限和全层级唯一 JSON key 解析清单，并严格核对版本、大小与 SHA-256，
校验失败不会修改现有程序。校验成功后，由当前 EXE
复制出的临时更新器等待主进程退出，以同目录临时文件完成原子替换并重新启动；替换前会
保留同目录回滚副本。新版本只有在主窗口构造完成、首次空闲回调到达且经过稳定窗口后才
确认成功；在此之前若进程退出或 30 秒内未就绪，会原子恢复旧 EXE 并重启旧版本，且通知
只包含固定安全结果码，不回显启动异常。启动就绪标记只在解析后的更新缓存目录内创建，
不会预先解析 marker 叶节点，并以 32-byte 稳定普通文件读取核对原始 ASCII token；链接/reparse
或读取中形状漂移不会确认新版。回滚通知只从更新缓存中的非链接普通文件稳定读取，
上限为 256 字节；重复 key、链接/reparse 路径或读取中形状漂移均不展示内容，且任何读取尝试后
仍执行一次性删除。确认成功后才清理回滚副本。

创建线上版本时，先同步修改 [`app_version.py`](app_version.py) 的 `APP_VERSION`，提交后
推送同名语义版本标签（例如 `v0.1.0`）。
[`release.yml`](.github/workflows/release.yml) 会重新运行完整门禁、构建并检查不含旧直连
模块的 Windows EXE，生成 `update-manifest.json`，再把固定名称的 EXE 与清单发布到
GitHub Release。清单生成器只接受 1–200 MiB 的非链接普通 EXE，并从同一个稳定文件
描述符按 1 MiB 分块派生大小与 SHA-256；空文件、超限、链接/reparse、非普通文件、
读取中截断/追加、命名替换或形状/模式漂移都会以固定错误停止且不创建清单。生产分发前
仍建议为 EXE 配置组织的 Authenticode 代码签名证书；当前
更新信任边界是官方仓库 HTTPS、固定 Release 路径及清单 SHA-256。

### 当前平台模式使用

1. 按 [`platform/README.md`](platform/README.md) 启动后端并创建平台用户与设备。
2. 在 EXE 所在机器设置 `PLATFORM_BASE_URL`；远程地址必须使用 HTTPS。
3. 启动 EXE，点击“平台登录”，再点击“新建邮箱任务”。平台会分配邮箱会话和卡租约，只返回脱敏邮箱与掩码卡。
4. 验证码只通过平台会话返回；需要卡详情时点击“揭示卡号”并完成浏览器 MFA。临时值会按界面提示自动清理。填写业务名称并点击“提交上传”后，EXE 只创建上传作业；外部平台 Token、代理、分组和并发均由服务端策略提供。

## 旧版剪贴板流程（迁移参考）

旧版曾识别剪贴板中的 `邮箱----密码`、`邮箱:密码` 和带卡号的表格记录。
该流程仅保留用于迁移期单元测试，不是默认 EXE 入口，也不应在生产运行；新平台模式不会从剪贴板读取邮箱密码。

## OpenAI OAuth 授权（待迁移，默认关闭）

OAuth 旧管理端流程尚未迁移到平台。以下历史实现不应继续使用；正式版应由平台服务端统一持有上传配置、代理、分组和并发策略，EXE 不得接收管理 Token。

旧版操作说明已移除出默认文档：平台模式不从剪贴板读取邮箱密码，不直连旧邮件反代，也不打开客户端 OAuth 管理窗。平台邮箱连接器和 Sub2 上传由服务端配置与审计，EXE 只接收脱敏邮箱和一次性验证码。

## 旧邮件反代（迁移遗留，不在平台模式使用）

仓库历史上提供了宝塔/Nginx 可用的安全反代模板
[`deploy/nginx/email111.6ltd.ltd.location.conf`](deploy/nginx/email111.6ltd.ltd.location.conf)
和离线诊断凭据的一键验证脚本 `deploy/verify-mail-proxy.ps1`。模板启用上游
SNI 与证书校验，并彻底关闭邮件响应缓存；部署前在服务器运行
`sh deploy/find-ca-bundle.sh` 确认系统 CA 证书路径。模板默认采用宝塔常见的
CentOS/RHEL/AlmaLinux 路径 `/etc/pki/tls/certs/ca-bundle.crt`；检测到其他路径时，
需要同步修改 `proxy_ssl_trusted_certificate`，不要通过关闭
`proxy_ssl_verify` 绕过校验。

平台模式不会访问该地址；部署或修改历史 Nginx 配置时可通过以下命令做离线验证：

```powershell
.\deploy\verify-mail-proxy.ps1
```

验证脚本仅使用 `.invalid` 测试账号，不会读取或发送真实邮箱凭据；不要把它配置为
新平台 EXE 的出站地址。

随机地址使用 Oregon、Delaware、Montana、New Hampshire 的城市和邮编模板，仅用于测试，不保证是真实或可投递地址，也不代表具体交易一定免税。

## 构建

要求 Windows、Python 3.12 和 PyInstaller：

```powershell
.\build.ps1
```

脚本会先运行离线单元测试，再生成正式发行物
`release\windows\邮箱验证码助手.exe` 及对应 `.sha256` 清单。如果目标 EXE
正在运行，会自动使用 `-new`（或递增后缀）生成新文件，不会终止现有进程。
构建会显式排除 `legacy_app`、`admin_oauth`、`oauth_dialog`，并读取最终
PyInstaller 归档验证平台模块存在、旧直连模块不存在。历史 `dist\` 目录不是正式
发行目录，其中可能有迁移前构建和旧配置旁文件，不应复制给用户。测试不访问真实
邮箱或管理端接口。

平台化改造提交前建议先运行完整门禁：

```powershell
.\scripts\quality_gate.ps1
```

该脚本不生成 EXE；它用于快速证明后端、桌面客户端、前端、迁移和配置边界仍保持一致。
