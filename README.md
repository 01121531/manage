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
[`./.github/workflows/ci.yml`](.github/workflows/ci.yml) 在质量门禁通过后使用独立
Windows Runner 和锁定的 [`requirements-desktop-build.txt`](requirements-desktop-build.txt)
真实执行 `build.ps1`，再次检查 EXE 归档与 SHA-256，并按提交 SHA 上传 14 天保留的
构建制品。

`frontend/` 是 React + TypeScript + Ant Design 运营控制台，包含工作台、任务、卡池、
邮箱连接器、Sub2 上传、用户权限、审计和策略入口。生产认证使用 Keycloak OIDC
Authorization Code + PKCE；访问令牌只保存在页面内存，浏览器刷新后需要重新认证。
Sub2 策略入口只登记服务端配置快照的版本和变更说明，采用双人审批、灰度发布和
可审计回滚；浏览器不会接收代理、分组、并发或凭据引用。
本地开发可运行 `cd frontend; npm install; npm run dev`，生产构建用 `npm run build`。
后端接口变化后运行 `cd frontend; npm run generate:api` 更新自动生成的 TypeScript
契约；质量门禁会执行 `npm run check:api`，契约过期时直接失败。
浏览器回归使用 `cd frontend; npm run test:e2e`；CI 会安装 Chromium 并验证登录、
角色菜单、任务 trace_id，以及 access token 不写入浏览器持久化存储。
阶段验收、真实环境缺口和下一轮输入统一维护在
[`docs/实施进度与待确认事项.md`](docs/实施进度与待确认事项.md)。

Windows EXE 同样优先使用系统浏览器 Authorization Code + PKCE（S256），回调只监听
`127.0.0.1` 的随机本地端口；浏览器回调受限时可显式选择设备代码登录。access token
仅保存在进程内存，refresh token 通过当前 Windows 用户的 DPAPI 加密保存并在到期前轮换；
启动时可恢复安全会话，退出登录会同步清除本地 refresh token，并后台撤销旧 refresh token。
已登录桌面端可打开“任务记录 / trace_id”，仅加载当前账号最近 50 条任务；Web 任务中心同步展示 trace_id，供管理员查询审计链。

### Windows 在线更新

正式 EXE 启动后会在后台检查仓库 `01121531/manage` 的最新 GitHub Release，也可点击
“检查更新”手动检查。客户端只接受该仓库 `releases/` 下的 HTTPS 清单和安装包；下载后
会严格核对版本、大小与 SHA-256，校验失败不会修改现有程序。校验成功后，由当前 EXE
复制出的临时更新器等待主进程退出，以同目录临时文件完成原子替换并重新启动；替换前会
保留同目录回滚副本，若新版本无法启动会立即原子恢复旧 EXE，成功启动后才清理回滚副本。

创建线上版本时，先同步修改 [`app_version.py`](app_version.py) 的 `APP_VERSION`，提交后
推送同名语义版本标签（例如 `v0.1.0`）。
[`release.yml`](.github/workflows/release.yml) 会重新运行完整门禁、构建并检查不含旧直连
模块的 Windows EXE，生成 `update-manifest.json`，再把固定名称的 EXE 与清单发布到
GitHub Release。生产分发前仍建议为 EXE 配置组织的 Authenticode 代码签名证书；当前
更新信任边界是官方仓库 HTTPS、固定 Release 路径及清单 SHA-256。

### 当前平台模式使用

1. 按 [`platform/README.md`](platform/README.md) 启动后端并创建平台用户与设备。
2. 在 EXE 所在机器设置 `PLATFORM_BASE_URL`；远程地址必须使用 HTTPS。
3. 启动 EXE，点击“平台登录”，再点击“新建邮箱任务”。平台会分配邮箱会话和卡租约，只返回脱敏邮箱与掩码卡。
4. 验证码只通过平台会话返回。填写业务名称并点击“提交上传”后，EXE 只创建上传作业；Sub2 Token、代理、分组、并发和卡原文均由服务端策略提供。

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
