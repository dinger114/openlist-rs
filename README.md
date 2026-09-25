# OpenList-rs

用 Rust 重写的 OpenList 最小可用版

## 功能

- **单二进制**：Vue 面板编译期嵌入 exe（rust-embed），分发只需一个文件
- 文件浏览：分页拉取、面包屑导航、文件夹/文件列表（大小、修改时间）
- **视频在线播放**：浏览器内直接播放（后端流式代理，支持 Range 拖动进度）
- 下载：后端代理流式下载（转发 Range，支持断点续传），文件名正确编码
- **面板登录鉴权**：用户名密码（argon2id 哈希存储）+ HttpOnly 会话 Cookie（7 天，滑动续期）；登录失败按 IP 限速（连错 5 次锁 60 秒，翻倍上限 15 分钟）
- 夸克 `__puus` cookie 滚动更新自动回写；123 网盘 401 自动重登；123 列表接口 700ms 限速（对齐 Go 版）
- **WebDAV 服务**：`/dav` 端点，访达 / 资源管理器 / rclone 可直接挂载（面板账号 Basic 认证；读写按驱动能力，只读存储写操作回 403）
- **存储启用/禁用**：管理页每张存储卡片附有开关，关闭后该存储从网盘列表隐藏，不影响配置数据
- **多存储驱动**：夸克 / UC / 夸克Open / 夸克TV / UC TV、123网盘 / 123Open / 123Link、阿里云盘（旧）/ 阿里云盘Open / 阿里分享、115网盘 / 115Open / 115分享、百度网盘、天翼云盘、移动云盘、迅雷、蓝奏云、蓝奏云优创 / 飞鸡盘、Terabox、OneDrive / OneDrive分享 / OneDriveAPP、Google Drive / Google Photo、Dropbox、PikPak / PikPak分享、Yandex.Disk、S3 / BunnyCDN、SFTP、FTP、SMB、WebDAV、AList v3、OpenList 挂载 / OpenList 分享、Seafile、可道云 KodBox、Cloudreve V4、虚拟存储（测试）等

## 启动参数

```
openlist.exe [OPTIONS] [COMMAND]

  -a, --addr <ADDR>      监听地址，默认 127.0.0.1（仅本机）；要局域网访问用 0.0.0.0
  -p, --port <PORT>      监听端口，默认 5244
  -d, --dir <PATH>       数据目录，默认 data（数据库与加密密钥存放于此）

Commands:
  reset-user   重置面板账号为 admin，密码随机生成替换并打印到终端
  set-account  交互式设置面板登录用户名
  set-password 交互式设置面板登录密码
```

面板鉴权始终启用。账号密码持久化在加密数据库中：

- **首次启动**：自动初始化为 `admin` + 随机 8 位密码，密码打印到终端并写入数据库
- **之后启动**：直接读取数据库中的账号密码，不再生成、不再打印
- **密码以 argon2id 哈希存储**（`$argon2id$…`，官方默认参数 m=19MiB/t=2/p=1）：即使库文件与 `openlist.key` 同时泄漏，也拿不到明文密码。老版本留在线库里的**明文**密码会在启动时自动升级为哈希 —— 密码本身不变，用户不用重设
- 忘记密码时用 `reset-user` 重置（admin + 新随机密码），或用 `set-account` / `set-password` 交互式修改
- 面板「设置」页也可在线修改账号和密码（保存后所有会话失效，需重新登录）

示例：

```
# 首次启动：打印随机密码（默认 127.0.0.1:5244，数据目录 data）
openlist-rs.exe

# 局域网开放 + 指定端口和数据目录
openlist-rs.exe -a 0.0.0.0 -p 8080 -d D:\olm

# 忘记密码：重置为 admin + 新随机密码
openlist-rs.exe reset-user -d D:\olm

# 交互式修改用户名 / 密码
openlist-rs.exe set-account
openlist-rs.exe set-password
```

- 账号数据持久化到 `<数据目录>/openlist.redb`（redb 嵌入式数据库），写入前用 AES-256-GCM 加密
- 加密密钥为首次启动自动生成的随机 32 字节，存于 `<数据目录>/openlist.key`（Unix 下权限 0600）
  - **密钥与数据库需一起保管**：只拷贝数据库、丢失密钥文件或两者不配套时，数据无法解密（启动会明确报错）
- 从旧的 JSON 版升级：把原来的 `config.json` 放进数据目录即可，首次启动自动导入（原文件保留，确认后手动删除）
- 会话保存在内存中，重启服务后需重新登录；会话 7 天不用即失效（每次使用滑动续期），后台每 10 分钟清扫过期会话

## 运行

启动后访问 `http://<addr>:<port>`（默认 http://127.0.0.1:5244；要让局域网/别的设备访问需显式 `-a 0.0.0.0`，此时启动会打印提醒）。

## 开发

```
# 后端（需要 x86_64-pc-windows-gnu 工具链 + MinGW，本机配置见 ~/.cargo/config.toml）
cargo run

# 前端（另开终端）
cd web
npm install
npm run dev     # 开发模式，/api 代理到 5299
npm run build   # 产物输出 web/dist/，cargo 编译时嵌入
```

## OpenList 官方 API 兼容层（TVBox / AList 客户端接入）

实现 AList 协议三个核心端点，NovaTV 等客户端可直接把它当 OpenList 服务器添加：

| 端点 | 说明 |
|---|---|
| POST `/api/auth/login` | `{username,password,otp_code}` → `data.token` |
| GET `/api/me` | 返回当前用户（`username`/`base_path`/`role`/`permission`）；无 token 时 `code 401` + `Guest user is disabled, login please`（本服务无 guest 概念） |
| POST `/api/fs/list` | `{path,page,per_page,...}` + `Authorization: <token>` 头 |
| POST `/api/fs/get` | 返回 `raw_url`（指向本服务 `/p` 代理） |
| GET `/d/{*path}` / `/p/{*path}` | 官方同款下载/代理路径，支持 Range；**必须带 `?sign=` 链接签名**（或有效面板会话） |

`/d`、`/p` 的签名与官方 `pkg/sign` 逐字一致：`sign = base64url(HMAC-SHA256(密钥, "路径:过期时间")) + ":" + 过期时间`（过期时间 `0` = 不过期），密钥由数据目录的 `openlist.key` 派生。客户端不用自己算 —— `/api/fs/get` 返回的 `raw_url` 已带签名，`data.sign` 字段也可直接用来拼 `/d`、`/p` 链接（目录为空串）。之所以用链接签名而不是鉴权头：播放器/TVBox 播视频时带不了 `Authorization`。

路径规则：根目录 `/` 下列出各账号文件夹（以备注名命名），进入即浏览对应网盘。响应结构与 OpenList 4.2.6 对齐（HTTP 200 + `{code,message,data}`、`type` 枚举 0未知/1文件夹/2视频/3音频、`raw_url` 为绝对地址）。

NovaTV 接入：设置里添加 OpenList → 服务器地址填本服务地址 → 用户名密码填启动参数里的面板账号。

未实现的端点（如 `/api/fs/dirs`、`/api/fs/search`）返回 JSON 404 `{code,message,data}`，不会掉进前端兜底 —— 客户端把 `index.html` 当 JSON 解析只会报出与真实原因无关的类型错误。

## WebDAV 服务

把已挂载的存储按 WebDAV 协议暴露给访达 / Windows 资源管理器 / rclone / davfs2 等客户端：

```
http://<面板地址>/dav
```

- **鉴权**：面板账号 + 登录密码（HTTP Basic），或面板会话 Cookie；失败按 IP 限速（与面板登录同一套）。`OPTIONS` 免鉴权。
- **根目录**：与兼容层一致 —— `/dav/` 下列出各存储（以备注名命名）。
- **支持的方法**：`OPTIONS`、`PROPFIND`（Depth 0/1）、`HEAD`、`GET`（含 Range）、`PUT`、`MKCOL`、`DELETE`、`MOVE`、`COPY`、`LOCK`/`UNLOCK`、`PROPPATCH`（属性只读）。
- **下载策略**：与面板一致 —— 账号开了「服务器代理」或驱动要求代理时经本服务中转（支持 Range），否则 302 跳真实直链由客户端直连。
- **已知限制**：
  - 只读存储（如网易云音乐）可浏览、下载、播放，写操作返回 403；
  - `Depth: infinity` 按 1 处理（响应带 `X-DAV-Truncated: 1`），单次 PROPFIND 上限 2 万条；
  - 锁只发/回收 token，不做 `If:` 头强制校验，重启后锁失效；
  - 无多用户 / 权限 / 配额属性，DAV 属性不持久化（`PROPPATCH` 一律 403）；
  - 明文 HTTP 下 Basic 凭据可被抓包，建议仅在可信内网使用或反代 HTTPS。

挂载方式：访达「前往 → 连接服务器」、Windows「映射网络驱动器」，命令行 `rclone lsd dav: --webdav-url http://<面板地址>/dav`。面板「设置」页有地址与 rclone 命令的一键复制。

## API（自有面板接口）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/auth/status` | 查询是否启用鉴权（鉴权始终启用） |
| POST | `/api/login` | 面板登录 `{username, password}`，成功设置会话 Cookie；失败次数过多返回 429 + Retry-After |
| POST | `/api/logout` | 退出登录 |
| GET | `/api/web/user` | 当前面板登录用户名（设置页回填） |
| POST | `/api/web/settings` | 修改面板用户名/密码 `{username?, password?}`，成功后清空全部会话 |
| GET | `/api/accounts` | 列出账号（含 `enabled` 状态） |
| POST | `/api/accounts` | 添加账号 |
| PUT | `/api/accounts/{id}` | 编辑账号凭据（重新验证） |
| PATCH | `/api/accounts/{id}/enabled` | 切换启用/禁用 `{enabled: bool}`（不重验证） |
| DELETE | `/api/accounts/{id}` | 删除账号 |
| GET | `/api/files?account=&fid=` | 列目录（fid 默认 `0` = 根目录） |
| GET | `/api/download?account=&fid=&...` | 取直链（返回 url + 是否需代理） |
| GET | `/api/stream?account=&fid=&name=&...&disp=inline` | 代理流式下载；`disp=inline` 用于在线播放 |

## 架构

```
openlist-rs/
├── src/
│   ├── main.rs           CLI 参数（clap）+ 路由组装
│   ├── state.rs          AppState（配置/驱动缓存/会话/路径索引）
│   ├── auth.rs           面板鉴权：中间件 + login/logout/status
│   ├── api.rs            自有面板 API（账号/文件/流式代理）
│   ├── compat.rs         OpenList 官方 API 兼容层（AList 协议）
│   ├── assets.rs         rust-embed 嵌入 web/dist + SPA 静态服务
│   ├── config.rs         账号持久化（redb + AES-256-GCM）+ 统一文件模型 Entry
│   └── drivers/
│       ├── mod.rs              Driver 枚举（所有驱动统一入口）
│       ├── quark.rs            夸克（cookie 模式）
│       ├── quark_open.rs       夸克 Open API
│       ├── quark_uc_tv.rs      夸克TV / UC TV
│       ├── pan123.rs           123网盘（cookie 模式）
│       ├── pan123_open.rs      123 Open API
│       ├── link123.rs          123Link 直链
│       ├── aliyundrive.rs      阿里云盘（旧版 token）
│       ├── aliyundrive_open.rs 阿里云盘 Open API
│       ├── aliyundrive_share.rs阿里云盘分享（只读）
│       ├── pan115.rs           115网盘（cookie 模式）
│       ├── pan115_open.rs      115 Open API
│       ├── pan115_share.rs     115 分享（只读）
│       └── ...                 百度、天翼、移动、迅雷、蓝奏云、OneDrive、Google Drive、S3、SFTP 等
├── web/                  Vue 3 + Vite 面板（登录页 / 文件浏览 / 视频播放器）
└── .github/workflows/release.yml   手动触发（Actions → release → 填 version）构建 Linux amd64/arm64 发布
```

## 发布

在 Actions 页面手动触发 `release` 工作流（填 `version` 输入，如 `v0.1.0`），构建 Linux 静态二进制（musl，TLS 用 rustls，无 openssl 依赖）：

```
# 不在仓库里执行的等价操作：Actions → release → Run workflow，version 填 v0.1.0
```

产物：`openlist-rs-linux-amd64.tar.gz` / `openlist-rs-linux-arm64.tar.gz`（附 sha256）。

> 直接 `git push` 标签不会触发发布；`ci` 工作流在每次 push / PR 时跑 `cargo check` + `cargo clippy -D warnings` + `cargo test`。
