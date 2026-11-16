# openlist-rs 代码审计报告

- **审计对象**：`/Volumes/mac/mimo/openlist-rs`（Rust 重写的 OpenList/AList，单二进制 + rust-embed 内嵌 Vue 面板）
- **规模**：Rust 43,901 行（55 个文件，其中 48 个驱动）、前端约 7.5k 行
- **基线**：`cargo clippy --all-targets` 零告警；`cargo test` 185 passed / 0 failed
- **方法**：源码逐行阅读 + **实际启动二进制做动态验证**（`-p 5299`，临时数据目录），关键结论均标注证据等级
- **证据等级**：`[实测]` 跑起来复现过；`[读码]` 代码路径已逐行确认；`[旁证]` 由分项审计给出、主审抽查过

> 本项目此前已合入过一轮安全审计（commit `7a7562b` P0、`43313b8` P1、`83ff036`/`15f1da3` P2）。本报告是**其后的新一轮**，重点覆盖此前未触及的写侧边界、预览链路、编辑链路与驱动层。

---

## 一、结论摘要

**未发现 P0（未认证 RCE / 直接数据泄露 / 认证绕过）。** 认证与路径解析的骨架是扎实的：令牌常量时间比较且空值不通过、argon2id 落库、`..` 在虚拟路径模型里天然无法解析、WebDAV 的 `Destination` 有正确的同源校验、XML 输出全量转义、全仓库无 TLS 校验关闭、无命令执行、无 `unsafe`。

但存在 **3 个 P1** 与 **16 个 P2**。其中最需要立刻处理的是三条"链路级"问题：

1. **文件内容以 `inline` + 上游 `Content-Type` 在同源返回**，配合 CSP 的 `script-src 'unsafe-inline'`，构成同源 XSS，可直接读走**永久 API 令牌**（等于永久管理员）。
2. **未认证的 `/api/login` 继承了全局 8GB 请求体上限**，单请求即可让进程缓冲 8GB 内存。
3. **`edit_account` 用请求体整体覆盖凭据**，导致 SFTP 主机密钥钉扎在每次编辑时被静默清空——而"验证新凭据"这一步本身就是在未钉扎状态下完成的。

| 级别 | 数量 | 主题 |
|---|---|---|
| P0 | 0 | — |
| P1 | 3 | 同源 XSS 偷令牌、未认证内存耗尽、编辑清空 SFTP 钉扎 |
| P2 | 16 | panic/越界/提权/凭据外泄/边界失效/无界资源 |
| P3 | 20+ | 加固项、工程卫生、文档与代码不一致 |

### 修复状态（本轮已实施并实测）

| 项 | 状态 | 落地位置 |
|---|---|---|
| P1-1 同源 XSS | ✅ 已修 | `api.rs` `file_response_meta`/`FILE_CSP`；`main.rs` CSP 不再覆盖；`FilesView.vue` iframe sandbox |
| P1-2 登录体 8GB | ✅ 已修 | `main.rs` 路由级 `BODY_LIMIT_JSON`(64KB) / `BODY_LIMIT_UPLOAD`(8GB) |
| P1-3 编辑清空凭据 | ✅ 已修 | `config.rs::merge_credential` + `edit_account` 合并式写入 |
| P2-1 分页溢出 panic | ✅ 已修 | `compat.rs::page_bounds`（saturating） |
| P2-2 软链逃逸 | ✅ 已修 | `local.rs::resolve_real` + 双层 `ensure_inside_root` + 列表过滤 |
| P2-3 令牌读端提权 | ✅ 已修 | `auth.rs::confirm_password`；`/api/web/token`、`token/reset`、`accounts/{id}/secret` 需口令（**令牌寿命不变**） |
| P2-4 备份恢复 | ✅ 已修 | `backup.rs` 需口令 + 先落盘后改内存 |
| P2-5 重定向凭据重放/SSRF | ✅ 已修 | `api.rs::is_private_host` + 同源才转发头 + `Url::join` |
| P2-6 `enabled` 未生效 | ✅ 已修 | `state.rs::get_driver` 统一拦截 + 切换时清缓存/索引 |
| P2-7 索引无界/不失效 | ✅ 已修 | `invalidate_index_account` 接入编辑/删除/切换 |
| P2-8 名称 TOCTOU | ✅ 已修 | 增/改在同一临界区 + 失败回滚 |
| P2-9 SFTP 钉扎失效 | ✅ 已修 | `sftp.rs` 指纹改 `RwLock`，TOFU 后就地钉扎 |
| P2-10 UTF-8 切片 panic | ✅ 已修 | 13 处 `truncate` 改 `truncate_bytes`；`lanzou::remove_notes` 按 char；`s3` 时间解析用 `get()` |
| P2-11 写侧边界逃逸 | ✅ 已修 | `drivers::validate_name` 接入 SFTP/FTP/WebDAV |
| P2-12 FTP 无界内存 | ✅ 已修 | 有界行读取 + LIST 上限 + `open_stream` 流式落盘 |
| P2-13 第三方 refresh token | ⏸ 未做 | 需补 client_id/secret + 开关（牵动面板表单，待确认） |
| P2-14 OneDrive nextLink | ✅ 已修 | 同源校验 + 分页上限 + 重试保留原方法 |
| P2-15 无界分页循环 | ✅ 已修 | 7 个驱动加 `MAX_LIST_PAGES=200` |
| P2-16 WebDAV 语义 | ✅ 已修 | `DAV: 1`、Overwrite 先删目标、Depth 拒绝、错误映射 + 质询头 |
| P3 锁中毒 | ✅ 已修 | 300 处 `.lock()` 改 `unwrap_or_else(into_inner)` |
| P3 首启凭据打印 | ✅ 已修 | 非 TTY 不打印明文，改写入数据目录 `initial-credentials.txt`(0600) |
| P3 表单临时文件 | ✅ 已修 | 0600 创建 |
| P3 XML 控制字符 | ✅ 已修 | `xml_escape` 过滤 XML 1.0 非法字符 |
| P3 `default_root_fid` dropbox | ✅ 已修 | 补 `""` 分支 + 测试 |
| P3 未用依赖/元数据 | ✅ 已修 | 删 `tower`/`tower-http`；补 `license`/`description`/`repository`/`readme`/`rust-version`；新增 `LICENSE` |
| P3 账号名不可见字符 | ✅ 已修 | 拒零宽/双向控制字符 + 长度上限 64（NFC 归一化需新依赖，未做） |
| P3 web/dist 陈旧 | ✅ 已修 | `npm run build` 重建并重新嵌入（`index-HAKFLQuJ.js`） |
| P3 CI 漏洞扫描 | ✅ 已修 | `ci.yml` 新增 `cargo audit --deny warnings` |
| P3 `parse_range` 语义 | ✅ 已修 | 不可满足区间回 416 + `Content-Range: bytes */N` |
| P3 前端 URL/DOMPurify | ✅ 已修 | `App.vue::safeUrl` 只放行 http(s)；DOMPurify 禁 `style/form/input` |
| 新发现：SPA 兜底无安全头 | ✅ 已修 | `.fallback()` 移到 `.layer()` 之前（`/` 与静态资源现带 3 个头） |

**产品约束（本报告的修复建议已按其调整）**：
- **永久 API 令牌功能必须保留**——ostrm / TVBox / rclone / WebDAV 客户端只存一次凭据，跟不了会话续期。因此 P2-3 的修法**不缩短令牌寿命、不改令牌格式、不影响任何已注册客户端**，只收紧"从面板读/换令牌"这一步的口令确认。改密是否连带重置令牌列为可选（默认关，会踢掉所有客户端，属产品决策）。
- 本报告不含"移除/缩短令牌有效期"的建议；任何与此冲突的加固项均需先确认产品语义。

---

## 二、P1 高危

### P1-1 同源 XSS：文件按上游 `Content-Type` + `inline` 在同源返回，可窃取永久 API 令牌 `[实测][读码]`

**位置**：`src/api.rs:2485-2511`（`proxy_stream` 的 Content-Type / Content-Disposition）、`src/api.rs:2358`（`get_download` 硬编码 `disp=inline`）、`src/main.rs:62-71`（CSP）、`src/auth.rs:337-339`（`/api/web/token`）

```rust
// src/api.rs:2485
let ctype = if upstream_ctype.is_empty() || upstream_ctype.starts_with("application/octet-stream") {
    content_type_by_ext(&e.name).to_string()   // .html/.htm -> text/html, .svg -> image/svg+xml
} else {
    upstream_ctype.to_string()                 // 上游给什么就用什么，原样透传
};
resp_builder = resp_builder.header(header::CONTENT_TYPE, ctype);
// src/api.rs:2508
format!("{disp}; filename*=UTF-8''{encoded}")
```

```rust
// src/main.rs:68
script-src 'self' 'unsafe-inline';   // 内联 <script> 会执行
```

**实测**（对本地实例，`/p` 与 `/api/stream` 行为一致）：

```
$ curl -D - -o /dev/null http://127.0.0.1:5299/p/t/evil.html -H "Authorization: $TOK"
HTTP/1.1 200 OK
content-type: text/html; charset=utf-8
content-disposition: inline; filename*=UTF-8''evil.html
x-content-type-options: nosniff
content-security-policy: default-src 'self'; ... script-src 'self' 'unsafe-inline'; ...
```

**攻击链**：攻击者把 `evil.html`（或带 `<script>` 的 `.svg`）放进管理员会浏览的挂载点（公开分享、第三方 WebDAV/AList、S3、可写的协作盘）→ 管理员点击该文件 → 页面在**面板同源**下渲染并执行内联 JS → `fetch('/api/web/token')`（Cookie 自动携带）→ 拿到 `openlist-…` 永久令牌 → 之后脱离浏览器即可长期控制。

**触发路径（重要，需与"iframe 已被 XFO 挡住"区分）**：

- **可用**：`web/src/App.vue:1001-1010` 对下载链接 `a.target='_blank'` 后 `.click()`——**顶层导航**，`X-Frame-Options: DENY` 完全不生效；`web/src/components/FilesView.vue:177`「在新窗口打开」同为顶层导航。
- **当前被挡住**：`FilesView.vue:161-166` 的 PDF `<iframe>` 因全局 `X-Frame-Options: DENY`（`main.rs:55`）无法加载——**这本身就是个 bug（PDF 预览是坏的）**，而"修好 PDF 预览"这个最自然的改动（把 XFO 放宽到 `SAMEORIGIN`）会立刻把这条路径变成可利用。该 iframe **没有 `sandbox` 属性**。

**修复**（根因在后端，前端只是放大器）：
1. `/api/stream` 与 `/p` 不要回显上游 `Content-Type`；改为**服务端白名单**（mp4/mkv/webm/mp3/flac/jpg/png/gif/webp/pdf），白名单外一律 `application/octet-stream` + `Content-Disposition: attachment`。
2. 绝不因文件名而派生出 `text/html` / `image/svg+xml`（`content_type_by_ext` 的 `.html`/`.svg` 分支必须改掉）。
3. 在文件服务响应上单独加 `Content-Security-Policy: default-src 'none'; sandbox` 与 `Cross-Origin-Resource-Policy: same-site`。
4. 前端 `<iframe sandbox="">`；根治方案是把预览放到独立源/独立端口。
5. `get_download` 不要对普通下载硬编码 `disp=inline`。

---

### P1-2 未认证请求可让进程缓冲 8GB：`DefaultBodyLimit(8GB)` 覆盖了 `/api/login` `[实测][读码]`

**位置**：`src/main.rs:229-231`（全局 8GB）、`src/auth.rs:183-194`（`login` 的限速在 body 提取**之后**）

```rust
// src/main.rs:229 —— 作用于所有路由，包含未登录的 /api/login
.layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024 * 1024))
```

axum 的 `Json<T>` 提取器会按 `DefaultBodyLimit` 把整个 body 缓冲进内存；`login` 里的 `st.login_limiter.check()` 要等 body 读完、handler 开始执行才跑，**限速完全起不到保护作用**。

**实测**：向 `/api/login` POST 3MB JSON —— 返回 `HTTP 401`（凭据错）而不是 `413`，证明 2MB 的 axum 默认限制确实被这条全局层顶掉了。据此可推：一个未认证者用 `Content-Length: 8GB` 的并发请求即可打爆内存。

**修复**：给 `/api/login`、`/api/auth/login`（以及所有非上传的 JSON 路由）加路由级 `DefaultBodyLimit::max(64 * 1024)`；把 8GB 只留给 `/api/fs/put|form` 和 `/dav` 的 PUT。

---

### P1-3 `edit_account` 用请求体整体覆盖凭据 → SFTP 主机密钥钉扎被静默清除 `[读码][旁证]`

**位置**：`src/api.rs:3061-3064`（`host_key_fingerprint: req.host_key_fingerprint.clone().unwrap_or_default()`）、`src/api.rs:3759-3766`（`acc.cred = cred` 整体替换）、`src/drivers/sftp.rs:129-166`（TOFU 回写）

```rust
// src/api.rs:3759
if let Some(acc) = data.accounts.iter_mut().find(|a| a.id == id) {
    acc.name = new_name.clone();
    acc.root_fid = default_root_fid(driver_kind, &cred);
    acc.cred = cred;                 // ← 整体替换，不做字段合并
    acc.server_proxy = req.server_proxy;
}
```

面板前端从不发送 `host_key_fingerprint`（`grep host_key_fingerprint web/src/` 与 `web/dist` → 0 命中），因此编辑时该字段恒为 `""`。

**后果**（SFTP 账号，任一编辑操作——改名、切代理开关、甚至**会被拒绝**的编辑）：
1. `Driver::new` → `Sftp::validate()` 在 `fingerprint == ""` 下连接 → **盲信任意主机密钥**（`expected: None`）并立即写库；
2. `api.rs:3763` 随即用请求体里的 `""` 覆盖回内存，`api.rs:3766` 落库覆盖 → **钉扎被删除**；
3. 下一次连接又是盲 TOFU。即"验证新凭据"这一步本身在未钉扎状态下完成，MITM 会被接受**并固化为新钉扎**。

同一根因波及 **49 个 match 分支**：`access_token`/`refresh_token`/`device_id`/`captcha_token`/`cookie`/`root_folder_id` 等约 12 个字段被硬编码空值或 `unwrap_or_default()` 抹掉（`api.rs:2772,2785,2800,2820-2822,2871,2945,2974,2987` 等），而这些令牌恰恰是驱动在 `validate()` 里刚刷新并回写的。

**修复**：把编辑当作 **patch**——只覆盖请求里真正提供的字段；至少对 `host_key_fingerprint`、`access_token`、`refresh_token`、`device_id`、`captcha_token`、`cookie`、`root_folder_id` 做"未提供则沿用库内值"，并把"清除钉扎"做成独立的显式操作。校验完成后重新读一次凭据，避免 `validate()` 的回写被覆盖。

---

## 三、P2 中危

### P2-1 分页算术溢出 → 请求处理 panic `[实测]`

**位置**：`src/compat.rs:386-391`

```rust
let start = (((page - 1) * per_page).clamp(0, total)) as usize;
let end = ((page * per_page).clamp(0, total)) as usize;
...
entries[start..end]
```

**实测**：`POST /api/fs/list {"path":"/t","page":922337203685477581,"per_page":10}`（目录内 ≥10 项）→

```
thread 'tokio-rt-worker' panicked at src/compat.rs:389:16: attempt to multiply with overflow
```

debug 版在乘法处炸，release 版（`overflow-checks` 关闭）在切片处炸——已用 `rustc -O` 单独验证：`start=10, end=0` → `slice index starts at 10 but ends at 0`。进程存活（连接被丢弃）。`compat_fs_search` 里有同构代码。

**修复**：用 `u64::try_from` / `checked_mul`，并统一 `start.min(end)` 与 `if start >= end { 空 }` 的兜底。

### P2-2 `local` 驱动跟随符号链接 → 任意主机文件读取（含 `openlist.key`）`[实测]`

**位置**：`src/drivers/local.rs:197-211`（`lexically_inside` 纯词法）、`src/api.rs:2532`（`serve_local_file` 直接 open）

把 `passwd_link -> /etc/passwd` 放进挂载根后：

```
$ curl http://127.0.0.1:5299/p/t3/passwd_link -H "Authorization: $TOK" | wc -c
9350            # /etc/passwd 全文
```

`ensure_inside_root` 只做 `components()` 词法判断、不解析符号链接，而 `File::open`/`is_file()` 会跟随。挂载根常是用户自己填充的目录（rsync、NFS/SMB、解压归档），其中完全可能已有软链。**能读到 `openlist.key` 就等于拿到全部网盘凭据的解密钥匙**。

**修复**：构造时 `root.canonicalize()`，使用时对目标 `canonicalize()` 后再比较；更彻底的做法是对最终分量用 `O_NOFOLLOW` / `openat2(RESOLVE_BENEATH)`，并在 `list_dir` 用 `symlink_metadata` 把软链单独标注或跳过。

### P2-3 会话 → 永久 API 令牌提权（`old_password` 第二道确认被绕过）

> **前提（已与需求方确认）**：令牌"永不过期、重启不失效"的语义**必须保留**——ostrm / TVBox / rclone / WebDAV 客户端只存一次凭据，跟不了会话续期。因此下面**不缩短令牌寿命、不改令牌格式、不影响任何已注册客户端**，只收紧"谁能从面板把它读出来/换掉"。

**位置**：`src/auth.rs:333-339`（`GET /api/web/token` 返回令牌）、`src/auth.rs:345-351`（`reset_api_token`）、`src/auth.rs:326-329`（改密只清会话）

**现状**：`update_web_settings` 特意要求改密时提供 `old_password`（注释明确写"把'拿到会话'与'拿到口令'分开"），但这道控制在令牌面前失效——同一个会话一次 `GET /api/web/token` 就能拿到长期令牌，而且 `clear_sessions()` 只清会话、令牌照旧。于是偷到 Cookie（共享浏览器、XSS、日志泄漏）的攻击者可以：读令牌 → 管理员事后改密 → **令牌依旧有效** → 永久接管，走的还是 `Authorization:` 头，不需要 Cookie。

这是"第二道确认"的自洽性问题，不是令牌设计本身的问题：**令牌该长命，但"复制走一枚长命凭据"这个动作应当和改密同级、需要口令再确认一次。**

**修复（保留功能，仅收口读端）**：
1. `GET /api/web/token` 与 `reset_api_token` 增加 `old_password`（或一次性 re-auth 票据，见第 3 点）。请求体已存在（`POST` 语义更合适，`GET` 可顺手改 `POST`，响应体不会被浏览器/反代缓存）。**客户端侧零影响**——它们用令牌调 `/api/fs/*`，从不读这个端点。
2. 同时把 `POST /api/accounts/{id}/secret`（会吐出全部网盘 Cookie/refresh_token）纳入同一道确认，两者是同一类"长命凭据导出"能力。
3. 面板打开设置页时先 `POST /api/web/re-auth {password}` 换一张有效期 5~10 分钟的短期票据，后续敏感读取凭票据放行——避免每次复制都要敲一遍口令。
4. **改密是否连带轮换令牌：列为可选项，默认关**。开启等于重置令牌（等价于用户手动点"重置令牌"），会造成所有已注册客户端失效，属于产品决策而非安全缺陷；若开启，建议在改密弹窗里明说"将使 N 个客户端令牌失效"，或干脆提供勾选框。**当前不做也接受**，但应在 README 里把"改密不会让已发出的令牌失效"写成显式风险提示。
5. 令牌本身的加固（与上述解耦、可独立落地）：令牌明文只在创建时打印一次（现状正确）；面板侧继续遮罩显示；`Cache-Control: no-store` 已由 `get_account_secret` 采用，令牌端点同样加上。

### P2-4 备份恢复绕过 `old_password`，且"先写内存后落盘"与其自身注释矛盾

**位置**：`src/backup.rs:262-284`

```rust
let save_result = {
    let mut data = st.store.data.lock().unwrap();
    *data = config;          // ← 注释写的是"先验证再写入：save 失败不修改原配置"
    st.store.save(&data)     // ← 但内存已经改了
};
match save_result {
    Ok(())  => { st.reload_auth(); st.clear_sessions(); ... }
    Err(e)  => 500,          // ← 内存=新配置、磁盘=旧配置、auth 未刷新、会话未清
}
```

两处问题：
1. **绕过**：`/api/web/backup/restore` 可以任意设置 `web_user` / `web_pass` / `api_token`，而改密路径刻意要求 `old_password`——恢复路径把这道控制完全绕开了（会话被劫持即可直接换掉管理员口令）。
2. **不一致**：保存失败时内存与磁盘分叉，且 `reload_auth()` 未执行 → `store.data` 是新凭据、`st.auth` 是旧凭据、会话仍然有效。

**修复**：恢复也要求 `old_password`（或一次性确认码）；改为"先构建快照 → `spawn_blocking` 落盘成功 → 再提交到内存并 `reload_auth`"，失败则完全不动内存。

### P2-5 `proxy_stream` 把驱动凭据重放到跨源重定向 + 无约束 SSRF + 相对 Location 未解析

**位置**：`src/api.rs:2422-2462`

```rust
let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap_or_default();
...
for (k, v) in &info.headers { req = req.header(k.as_str(), v.as_str()); }   // Cookie/Authorization/Referer
...
current_url = location;      // 不看来源、不做 URL join
```

reqwest 原本会在跨源（host 或 port 变化）时剥离 `Authorization`/`Cookie`；这里 `Policy::none()` + 手动重贴**正好抵消了这一保护**。任何能影响一跳的来源（CDN、被劫持的中间层、恶意/被控的 AList/WebDAV/分享站、https→http 降级）都能把账号 Cookie/Basic 凭据收走。同时 `location` 未做来源校验 → 可被 302 引向内网/元数据地址；相对 `Location`（`/cdn/file`）不 join 会导致 502。

**修复**：`Url::parse(&current_url)?.join(&location)?`；只允许 http/https；解析 host 后拒绝 loopback/私有/link-local/元数据网段；**源发生变化时丢弃 `info.headers` 里的凭据类头**。

### P2-6 `enabled=false` 只在 3 处生效，其余数据路径全部无视 `[实测]`

**位置**：`src/api.rs:2161`（list）、`2230`（search）、`3835`（offline_tools）、`src/webdav.rs:395`；`compat.rs` **零**处检查

实测：禁用账号后 `/api/fs/list` 仍返回内容，`/p/t5/d/a.txt` 仍 `HTTP 200`。`/api/download`、`/api/stream`、`/d`、`/p`、全部 `/api/fs/*` 写操作、`offline_add` 都不看 `enabled`。管理员的"关闭存储"开关只隐藏了浏览入口。

**修复**：把检查下沉到 `get_driver()` 或 `resolve_path()`，让所有入口自动继承。

### P2-7 兼容层路径索引 `index` 无界增长且编辑/删除不失效

**位置**：`src/state.rs:169`（`HashMap` 无上限/无 TTL）、`src/compat.rs:205,232,242,877`、`src/api.rs:3774-3780`、`src/api.rs:2131`

`resolve_path` 每访问一个路径就永久插入一条；`edit_account` 只清 `list_cache`（`invalidate_account`），`del_account` 连索引都不清。后果：
- 编辑把账号指向更窄的根（如 S3 的 key 前缀）后，**已索引的子路径仍解析到旧 fid**，管理员以为已收窄的边界并未生效；
- 删除后重建同名账号，`/旧名/子路径` 仍指向**旧账号**的 fid；
- 内存无界增长。

**修复**：新增 `invalidate_index_account(&id)`（`retain(|_, v| v.0 != id)`）并在编辑、删除处调用；给索引加容量上限。

### P2-8 账号名称唯一性检查与写入不在同一临界区（TOCTOU）+ 先改后存无回滚

**位置**：`src/api.rs:1462-1470`（检查）vs `1480-1489`（push+save）；`src/api.rs:3746-3758`（编辑同构）

两段临界区分离，并发两个 `POST /api/accounts` 都能通过检查 → 同名账号。而 `resolve_path` 用 `accounts.iter().find(|a| a.name == segs[0])` **恒命中第一个**，第二个账号永久不可寻址（模块注释自己写明了这个后果）。另外 `data.accounts.push(acc)` 在 `save()` **之前**，失败时无回滚——账号"存在于内存、不在磁盘"，且会被后续任意一次不相关的 `save()` 意外落盘。

**修复**：检查+修改+落盘放进同一临界区，失败回滚；把便宜的校验提到昂贵的 `Driver::new()` 网络探测之前。

### P2-9 SFTP 主机密钥钉扎对缓存驱动实例永不生效

**位置**：`src/drivers/sftp.rs:129-135`（`expected` 取自构造时快照）、`src/drivers/sftp.rs:152-166`（TOFU 只写库，**不回写内存字段**）、`src/state.rs:198-218`（驱动进程级缓存）

首次连接后指纹写进了数据库，但 `self.host_key_fingerprint` 内存字段仍是空 → 该实例后续**每次重连都是 `expected: None`（接受任意主机密钥）**，直到进程重启或账号被重新保存。TOFU 的全部价值（防后续 MITM）在运行期不成立。

**修复**：用 `Mutex<String>`/`RwLock` 保存期望指纹，TOFU 成功后立即就地更新；或在每次 `with_sftp` 开始时从 store 读。

### P2-10 驱动层 UTF-8 切片 panic（远端数据可触发）

**位置**：
- `src/drivers/pan115.rs:1348-1353` `format!("{}...", &s[..200])`（`thunder.rs:1278-1288` 是**已修好**的版本，用 `is_char_boundary` 逐字节回退——可作为修法参照）
- `src/drivers/lanzou.rs:85-96` `remove_notes`：`&b[1..3]` / `b[..1]`，正则 `[^:]//.*` 若从 3 字节 CJK 字符起匹配即在字符中间切片
- 另有约 12 个驱动各带一份同样不设防的 `truncate()`：`alist_v3.rs:490`、`cloudreve_v4.rs:755`、`dropbox.rs:525`、`github_releases.rs:464`、`google_photo.rs:426`、`kodbox.rs:358`、`onedrive_app.rs:473`、`onedrive_share.rs:466`、`pikpak.rs:633`、`s3.rs:882`、`seafile.rs:576`、`yandex_disk.rs:477`

这些函数的入参全是**远端响应体**；中文错误体（本应用的主要语言）使第 200 字节落在字符中间的概率很高。`mod.rs:54` 已有安全实现 `truncate_bytes`，直接替换即可。

> 已排除一处误报：`pan139.rs:61-83 parse_personal_time` 的 `&t[19..]` **不会 panic**——`num()` 闭包对 `0..4/5..7/8..10/11..13/14..16/17..19` 全部 `?` 提前返回，保证前 19 字节是 ASCII；时区分支也有 `rb.len() < 6` 与 `starts_with('+'/'-')`（ASCII）保护。

### P2-11 写侧挂载边界逃逸：`rename`/`put` 的 `name` 未校验

**位置**：`src/drivers/sftp.rs:343`（`format!("{parent}/{new_name}")`）、`src/drivers/sftp.rs:437`、`src/drivers/ftp.rs:215-225`、`src/drivers/ftp.rs:311-319`、`src/drivers/webdav.rs:281-285`

读侧的 `fid` 已经走 `normalize_fid`，**写侧的 `name` 没有**：`/api/fs/rename` 只检查 `name` 非空（`compat.rs:944-948`），`/api/fs/form` 直接采用 multipart 的 `filename`（`compat.rs:1182`→`1101`）。对照：`local.rs:110` 拒绝 `/` 和 `\`、`s3.rs:276` 拒绝 `/`、`webdav.rs:230` 拒绝 `/`——说明"该校验"的意图存在，只是这几个驱动漏了。

**影响**：`new_name = "../../etc/foo"` 可把文件移出 `root_path`；`put` 同理可写出挂载范围（SFTP 主机上可覆盖 `~/.ssh/authorized_keys`）。

**修复**：在 `mod.rs` 里给 `Driver::rename/put/mkdir/move/copy` 统一加一层名称校验（拒绝含 `/`、`\`、NUL 以及 `.`/`..` 段），并在 `mod.rs:139-149` 的 `normalize_fid` 里把 `\` 也当分隔符（Windows 上的 SFTP/FTP 服务端会把 `..\..\` 当路径）。

### P2-12 FTP 驱动无界内存

**位置**：`src/drivers/ftp.rs:367-397`（`message` 有上限但**单行** `read_line` 无上限）、`:449-453`（`pasv_list` → `read_to_end`）、`:465-468`（`pasv_retr` → `read_to_end`）、`:320-333`（上传先把整个流读进 `Vec`）

恶意/异常 FTP 服务端可以一个不带 CRLF 的行就把内存打穿；大文件/大目录全部缓冲，而 `open_stream` 最终还要落临时文件——缓冲毫无收益。

**修复**：控制通道用带上限的行读取；数据通道直接流式转发到临时文件/响应。

### P2-13 第三方刷新端点无条件接收 refresh token（无开关）

**位置**：`src/drivers/onedrive.rs:26`、`google_drive.rs:30`、`baidu_netdisk.rs:24`（`api.oplist.org/.../renewapi`），以及 `aliyundrive_open.rs:25`、`yandex_disk.rs:83`、`quark_open.rs:100`、`pan123_open.rs:89`

OneDrive/Google/Baidu 的 `refresh_token()` 把长期 refresh token 放进**URL 查询串**发给第三方，且对应 `Credential` 变体（`config.rs:30,110,129`）只有 refresh/access token，**没有 client_id/secret，也没有 `use_online_api` 开关**。对照 `dropbox.rs` 有 `use_online_api` + 本地 `POST /oauth2/token`（client_id/secret）——证明"可自建"的设计是存在的，只是这几个驱动没提供。

（与上游 AList/OpenList 行为一致，故定 P2 而非 P1；但无退出选项 + 查询串裸露值得修。）

**修复**：补齐 client_id/secret + `use_online_api` 开关，默认走本地刷新；查询串改为 POST body。

### P2-14 OneDrive `@odata.nextLink` 携带 Bearer 跟随任意主机 + 无界分页

**位置**：`src/drivers/onedrive.rs:239-278`（`next_link = resp["@odata.nextLink"]` 直接作为下一次 URL）、`:167-207`（`request()` 无条件加 `Authorization: Bearer`），`onedrive_app.rs:293-299` 同构

恶意的 `@odata.nextLink: https://evil/` 会把 access token 送到任意主机；若反复返回非空 nextLink 则无限循环 + `files` 无界增长。（另：`request()` 的重试把方法硬编码成 `GET`，非 GET 调用会被改写。）

**修复**：nextLink 必须与初始 origin 同源；分页加硬上限。

### P2-15 多个驱动存在无界分页循环（恶意上游可导致无限循环 + OOM）

`pan189.rs:465-547`（仅 `count == 0` 退出）、`pan139.rs:466-524`（仅 cursor 为空退出）、`weiyun.rs:463-549`、`quark.rs:186-238`、`aliyundrive_open.rs:221+`、`google_drive.rs:205+`、`halalcloud_open.rs:394/551`、`s3.rs:144-231` 与 `:344-370`。

对照：`github_releases.rs:339` 有 `max_page` 护栏（可作范例）。

**修复**：统一加"最大页数 / 最大条目数"硬上限并返回明确错误。

### P2-16 WebDAV 的 LOCK 宣称 class 2 但零校验；Depth / Overwrite / 错误映射均有语义错误

**位置**：`src/webdav.rs:99-102`（无条件发 `DAV: 1, 2`）、`:794-805`（LOCK 不做任何强制）、`:867`（UNLOCK 忽略路径、删全局表）、`:816-819`（刷新用子串匹配任意 token）、`:657-744`（MOVE/COPY 忽略 `Depth`、`Overwrite: T` 不先删目标）、`:435-446`（`map_driver_error` 靠子串）

- 全模块**从不读 `If` / `If-Match` / `If-None-Match`** → 锁定形同虚设，并发写可交错损坏，且无丢失更新保护；LOCK 对**不存在的路径**和**只读账号**都返回 200 + token。
- `COPY` 忽略 `Depth: 0`；`Overwrite: T` 时不删目标 → `local.rs` 报"目标已存在" → 表面成 502，目录可能已被部分覆盖。
- 未知账号 → 502（应 404）；上游鉴权失效 → 401 且**不带 `WWW-Authenticate`** → macOS Finder / Windows 资源管理器会不停弹口令框。
- LOCK 表无上限、每操作 O(n)，条目最长存活 7 天。

**修复**：暂只 advertise `DAV: 1`；给 PUT/DELETE/MOVE/COPY 加 `check_locks()`（占用则 423）；UNLOCK/刷新按路径作用域；MOVE/COPY 支持 `Depth` 与 `Overwrite`；驱动返回**类型化错误**再映射状态码。

---

## 四、P3 低危与加固项

**安全加固**
1. `Mutex::lock().unwrap()` 遍布全仓（`grep` 519 处 `unwrap`），且**没有** `CatchPanicLayer`/`catch_unwind`——任一次持锁 panic 会让 `store.data` 永久中毒，之后每个请求都 500，**单次 panic 升级为全站 DoS**。建议 `store.data.lock().unwrap_or_else(|e| e.into_inner())` 或换 `parking_lot`。
2. **阻塞 I/O 在 async 运行期**：`Store::save()`（redb commit + fsync，`config.rs:769-779`）在持有 `store.data` 锁时同步执行，`api.rs` 内 4 处（`1483/2122/3766/3806`）。账号多时每次保存都要全量重新序列化+加密。建议"锁内取快照 → 放锁 → `spawn_blocking` 落盘"。
3. **首次启动把面板密码与 API 令牌打印到 stdout**（`state.rs:96-97,137`）→ 会留在 systemd journal / Docker 日志里。建议只在 TTY 下打印，或写入 0600 的提示文件。
4. `compat_fs_put` 对 `File-Path` 头做 `percent_decode`（`compat.rs:817`）；`compat_fs_form` 把上传内容落到 `std::env::temp_dir()` 的普通权限文件（`compat.rs:1178`），其他本机用户可读，且部分错误路径不清理临时文件。
5. `parse_range`（`api.rs:2621-2655`）语义偏差：不可满足的区间返回 `200`+全量（应 416）、多区间只取第一段、只认小写 `bytes=`。不会 panic，也不会造成头不匹配（已逐分支确认）。
6. WebDAV `xml_escape`（`webdav.rs:225-231`）只转义五个实体，**放过 XML 1.0 非法控制字符**（`0x00-0x08,0x0B,0x0C,0x0E-0x1F` 在 POSIX 文件名里合法）→ 一个这样的文件名就让整个 multistatus 无法解析、整目录列表失败。
7. `validate_account_name`（`api.rs:85-100`）允许 U+202E 双向覆盖、U+200B 零宽、U+FEFF、软连字符，无 NFC 归一化、无长度上限 → 视觉伪装/不可寻址。
8. 前端：`App.vue:1001-1010` 把后端/上游给的 URL 直接赋给 `a.href`，**无 scheme 校验**（上游 `raw_url` 由远端完全控制）。建议 `new URL(url, location.origin)` 后只放行 `https?:`。
9. 前端：`DOMPurify.sanitize(md.parse(...))`（`FilesView.vue:745`）用默认配置，允许 `<style>/<form>/<input>` + CSP 的 `style-src 'unsafe-inline'` 与 `img-src https:` → 恶意 `.md` 可伪造登录框、外带信标。建议 `FORBID_TAGS: ['style','form','input','button','textarea','select']`。
10. WebDAV 接受 Cookie 鉴权（`webdav.rs:156`），GET 可被 `<img>` 驱动；建议 DAV 面只接受显式凭据。
11. Bearer 失败不计入登录限速（`webdav.rs:169` 只在 Basic 分支 `record_failure`）→ 无限次令牌猜测，无全局断路器。
12. `offline_add` 的 `urls` 无数量上限、URL 无 scheme 校验（`api.rs:3894`）、`Running` 任务永不淘汰（`offline.rs:246-260` 只淘汰终态）→ 内存无界 + 让第三方服务替我们抓内网地址。

**正确性**
13. `default_root_fid`（`api.rs:110-165`）缺 `dropbox` 分支，落到 `_ => "0"`，而 Dropbox 是路径型驱动 → `normalize_fid("", "0")` 得到 `"/0"` → 根目录列不出（`409 path/not_found`）。新建的 Dropbox 账号开箱不可用。
14. `copy_tree`（`local.rs:265-281`）递归时用 `Path::is_dir()`（**跟随软链**）。实测：复制一个含自指软链的目录 → 生成 32~76 层嵌套副本后被 `ENAMETOOLONG` 打断，返回 500，**且已写入大量数据**。（注：此项曾被误判为栈溢出致进程 abort，实测不会——路径长度上限先触发；真实影响是"失控复制 + 半成品写入 + 磁盘膨胀"。）
15. `serve_local_file`（`api.rs:2532`）自身不做包含性校验，仅依赖调用方传入驱动派生的路径——建议加注释/`debug_assert`，防止未来新增调用点传入用户输入。
16. `parse_rfc3339_ms`（`s3.rs:857-862`）对远端 `<LastModified>` 用 `s[0..4]` 等硬下标（只检查了长度 19，未检查字符边界）。
17. FTP：`line[0..3]`（`ftp.rs:381-384`）在非 ASCII 前缀时 panic；PASV 端口 `nums[4] * 256` 用 `u16` 会溢出（`ftp.rs:417`）；`cwd_list=true` 时相对 `root_path` 会累积（`ftp.rs:134-143`）。
18. S3：对象 key 未做百分号编码就拼进 URL 与 `x-amz-copy-source`，而签名是对原始 key 算的 → 含空格/`?`/`#`/非 ASCII 的 key 一律 `SignatureDoesNotMatch`（`s3.rs:426-441,566`，正确性问题）。
19. `webdav.rs:129` 用 `strip_prefix` 而非按分量比较 → 根 `/dav/Via` 也会匹配 `/dav/ViaOther/x`；`mod.rs:186 path_under_root` 是正确写法，应复用。
20. `pan115` 的 `lz4_decompress`（`pan115.rs:979-1027`）无输出上限，约 255× 内存放大（小输入 → 大输出）。
21. `net user` 类细节：`percent_decode` 的 `i + 2 < bytes.len()` 边界正确；`constant_time_eq` 仅在长度不等时提前返回（只泄漏长度，可接受）。

**工程与供应链卫生**
22. `Cargo.toml` 声明了 `tower` 与 `tower-http`，但 `src/` 内**零使用**（应为 `cargo-udeps` 能查出的未用直接依赖）。
23. **没有 LICENSE 文件**，`Cargo.toml` 也没有 `license`/`repository`/`description`/`authors`/`rust-version`。
24. `main.rs:227` 注释写"备份恢复单独限 512MB"，代码实际是 `64 * 1024 * 1024`（`main.rs:188`）。
25. README 宣称"结构化日志：替代 eprintln!"，实际 `tracing::*` 只有 10 处，其余仍是 `println!`/`eprintln!`（`main.rs` 11 处、`state.rs` 6、`config.rs` 5、`auth.rs` 4）。
26. CI **没有** `cargo audit` / `cargo deny`；`dependabot-automerge.yml` 会在 CI 绿后自动 squash 合并 minor/patch（策略已在注释中说明，但结合"无漏洞扫描"意味着一次投毒的补丁版本可自动进主干）。
27. `web/dist/` 产物（Nov 15 17:46）比 `web/src/`（Nov 15 20:22）旧 → 内嵌进二进制的面板**比被审计的源码旧**。发布前应重跑 `vite build`。
28. `.DS_Store` 与 `data/`、`target/` 已在 `.gitignore` 中；`git ls-files` 未见误提交（此项通过）。
29. **（实测新发现）SPA 兜底与静态资源完全不带安全响应头**：`.fallback()` 注册在 `.layer()` 之后，axum 不会把层套到 fallback 上，因此 `/`、`/index.html`、任意前端路由都没有 `nosniff`/`X-Frame-Options`/CSP —— 即面板自身的 HTML 不在 CSP 保护范围内。已修复（把 `.fallback()` 移到两个 layer 之前），实测 `/` 与 `/some-spa-route` 现在都带 3 个头。

---

## 五、已验证为"正确"的关键部位（可以放心）

这部分是审计的"反向结论"，同样重要——下列控制是**真的生效**的，不需要返工：

| 部位 | 结论 |
|---|---|
| 静态令牌比较 | `token::matches` 先拒空值再 `constant_time_eq`，修掉了上游 Go 版 `ConstantTimeCompare("","")==1` 的坑（`token.rs:29-34`，有回归测试） |
| 空口令 | `verify_password` 在任何比较前先短路空串（`password.rs:46-51`）；空口令既不能匹配 PHC 串也不能匹配空明文 |
| 口令落库 | `update_web_auth` 是唯一收口，入参无论明文还是 PHC 都只落 argon2id；`reload_auth` 复用同一收口（`config.rs:794-813`、`state.rs:301-304`，有回归测试） |
| 登录限速 | 按 TCP 对端 IP（不信任 `X-Forwarded-For`），5 次→60s 指数退避到 15min + 全局 50 次/60s 断路器，全套单测（`ratelimit.rs`） |
| 路径穿越 | `/p/t/../../../etc/passwd`、`..%2f`、`%2e%2e` **实测全部 404**——`resolve_path` 是逐段按"子项名"匹配，`..` 无法命中，这是比字符串规范化更强的模型 |
| 下载鉴权 | `authorize_download` 在 `resolve_path` **之前**执行（避免路径存在性探测与上游请求放大）；签名绑定完整路径，无法跨文件复用 |
| WebDAV 认证 | 匿名 PROPFIND → 401；Bearer → 207；Basic 真口令 → 207；**把 API 令牌当 Basic 口令 → 401（正确拒绝）**；`Destination` 校验同 host、拒跨账号 MOVE/COPY、只解码一次（无 `%252e` 二次解码绕过） |
| WebDAV XML | 所有插值点均转义，`href_encode` 把 `%` 自身也编码 → 无可注入/无 CRLF 头注入 |
| 存储加密 | AES-256-GCM，nonce 每次随机，`blob.len()` 下界校验，密钥文件 0600；单测覆盖篡改/错钥/短数据 |
| 备份 KDF | v2 用 argon2id；v1 弱 KDF 仅用于读旧文件；空密码视为不加密 |
| 驱动层 TLS | 全仓 `danger_accept_invalid_certs` / `no_verify` **零命中** |
| 驱动层日志 | 九个文件系统/协议驱动**零** `println`/`tracing`；`DownloadInfo` 的 `Debug` 手写脱敏 |
| 密钥/口令隔离 | 列表接口只回 `id/name/driver/enabled/server_proxy`，凭据只在 `POST /api/accounts/{id}/secret`（带 `no-store`）返回 |
| 前端凭据 | 只用 HttpOnly Cookie；localStorage 仅存主题/布局等 UI 偏好；口令从不持久化；API 令牌只在内存 ref 里、遮罩显示、从不写存储 |
| 前端 HTML 注入 | 全仓仅 1 处 `v-html`（`FilesView.vue:204`），内容经 DOMPurify（默认配置会剥 `on*` 与 `javascript:`）；其余错误信息全走 `{{ }}` 插值自动转义 |
| 并发 | 全仓未见 `Mutex` 跨 `.await` 持有；`local` 驱动的同步 FS 全部走 `spawn_blocking`；argon2 走阻塞池 + `Semaphore(2)` |
| 注入类 | 无 `Command::new`、无 `unsafe`、无 SQL/模板引擎；redb 无查询语言 |
| CI | 第三方 Action **全部 pin 到 commit SHA**；`cargo check/clippy -D warnings/test` 全 `--locked`；发布流水线的版本号输入有正则白名单；`pull_request_target` 不 checkout PR 代码 |

---

## 六、修复优先级路线图

**第一批（建议 1~2 天内，都是小改动、大收益）**
1. `/api/login` 等 JSON 路由加 64KB body 上限（P1-2，约 6 行）。
2. 文件服务端 Content-Type 白名单 + 白名单外强制 `attachment`（P1-1 根因，约 20 行）；顺手去掉 `content_type_by_ext` 的 `text/html`/`svg` 分支。
3. `edit_account` 改成字段级 patch，至少保留 `host_key_fingerprint` 与各类 token（P1-3）。
4. 分页 `checked_mul` + `start.min(end)`（P2-1，约 5 行）。
5. 用现成的 `truncate_bytes` 替换 13 份不设防的 `truncate`（P2-10，机械替换）。

**第二批（1 周）**
6. `local` 驱动 `canonicalize` + `copy_tree` 加 visited 集合（P2-2、P3-14）。
7. 把 `enabled` 检查下沉到 `get_driver()`（P2-6，一处改全站生效）。
8. 加 `invalidate_index_account()` 并接入编辑/删除（P2-7）。
9. `proxy_stream`：同源才转发凭据 + `Url::join` + 私网拒绝（P2-5）。
10. **令牌寿命不变**，只给"读/重置令牌"与"备份恢复"加 `old_password`（或 re-auth 票据）确认（P2-3、P2-4）；改密是否连带重置令牌列为可选，默认不动。
11. `mod.rs` 统一名称校验（拒 `/`、`\`、NUL、`.`、`..`）供 `put/rename/mkdir/move/copy` 共用（P2-11）。
12. SFTP 钉扎改为就地更新（P2-9）。

**第三批（1 个月，需要设计取舍）**
13. 驱动层统一"类型化错误"（供 WebDAV/HTTP 映射），顺带修 P2-16 的状态码语义。
14. WebDAV 要么实现 `If:`/锁强制，要么只 advertise `DAV: 1`；`Depth`/`Overwrite` 语义补齐。
15. 全部分页循环加硬上限（P2-14、P2-15）；FTP 控制/数据通道改流式（P2-12）。
16. OneDrive/Google/Baidu 补 client_id/secret + `use_open_api` 开关，默认本地刷新（P2-13）。
17. `store.data` 换非中毒锁 + panic 捕获层；`save()` 移出 async 线程（P3-1、P3-2）。
18. 预览隔离到独立源（模块级根治 XSS 类别，而非逐个堵漏）。

**工程卫生（随手做）**
19. 删 `tower`/`tower-http`；加 LICENSE + `Cargo.toml` 元数据；CI 加 `cargo audit`；修 `main.rs:227` 注释与日志口径；发布前重建 `web/dist`。

---

## 七、审计覆盖说明（诚实披露）

- **完整逐行读过**：`main.rs`、`auth.rs`、`token.rs`、`password.rs`、`ratelimit.rs`、`state.rs`、`sign.rs`、`config.rs`、`assets.rs`、`search.rs`、`offline.rs`、`backup.rs`、`webdav.rs`（分项）、`compat.rs`（分项 + 主审通读）、`drivers/local.rs`、`drivers/sftp.rs`（分项）、`drivers/ftp.rs`（分项）、`drivers/s3.rs`（分项）、`drivers/alist_v3.rs`（分项）、`drivers/mod.rs`（分项）；`api.rs` 由三位分项审计按 1-1520 / 1500-2720 / 2700-4129 分段覆盖。
- **重点抽查、未逐行**：`halalcloud_open.rs`（1610 行，仅读了加密与消息编码辅助函数）、`thunder.rs` 的签名内部（只读到 `truncate` 与测试模块）、`pan115.rs` 的 AES/ECDH 主体（已复核算法正确性但未逐行数完 2024 行）。
- **仅做模式扫描、未逐行**：`terabox.rs`、`cloudreve_v4.rs`、`pikpak.rs`/`pikpak_share.rs`、`google_photo.rs`、`quark_uc_tv.rs`、`openlist_share.rs`、`pan115_open.rs`、`pan115_share.rs`、`seafile.rs`、`kodbox.rs`、`share123.rs`、`pan123.rs`/`pan123_open.rs`、`quark_open.rs`、`yandex_disk.rs`、`aliyundrive.rs`/`aliyundrive_share.rs`、`onedrive_share.rs`、`github_releases.rs`、`link123.rs`、`netease_music.rs`、`virtual_driver.rs`、`smb.rs`。这些文件的风险面（UTF-8 切片、无界循环、日志泄漏）已用全仓 grep + 逐点核对的方式覆盖，但**不排除有局部逻辑缺陷未被发现**。
- **动态验证范围**：仅在**本机回环地址**、**临时数据目录**、**自建 local 账号**上测试，未触碰任何真实网盘凭据，未做任何破坏性操作；测试实例已停止，产物在 `/tmp/oltest`（可删）。
