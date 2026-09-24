<template>
  <div class="page accounts-page">
    <!-- 页头：标题 + 添加按钮 -->
    <div class="accounts-head">
      <h2 class="accounts-title">存储管理</h2>
      <div class="accounts-actions">
        <button class="btn btn-secondary" title="刷新" @click="$emit('refresh')">
          <Icon name="refresh" :size="15" />
          刷新
        </button>
        <div class="view-toggle" role="group" aria-label="布局">
          <button :class="{ active: storageLayout === 'grid' }" title="卡片" @click="storageLayout = 'grid'">
            <Icon name="grid" :size="15" />
          </button>
          <button :class="{ active: storageLayout === 'table' }" title="表格" @click="storageLayout = 'table'">
            <Icon name="list" :size="15" />
          </button>
        </div>
        <button class="btn add-btn" @click="openAdd">
          <Icon name="plus" :size="15" />
          添加
        </button>
      </div>
    </div>

    <!-- 已添加存储：卡片网格 -->
    <section class="card panel">
      <div class="panel-head">
        <Icon name="cloud" :size="18" />
        <h2>已添加存储</h2>
      </div>
      <div class="panel-body">
        <div v-if="accounts.length === 0" class="empty-mini">
          <Icon name="inbox" :size="28" />
          <span>暂无存储，点击右上角“添加”创建</span>
        </div>
        <div v-else-if="storageLayout === 'table'" class="storage-table-wrap">
          <table class="storage-table">
            <thead>
              <tr>
                <th>备注</th>
                <th>驱动</th>
                <th>状态</th>
                <th>代理</th>
                <th class="col-op">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="a in accounts"
                :key="a.id"
                :class="{ disabled: a.enabled === false, editing: editingId === a.id }"
              >
                <td class="col-name">{{ a.name }}</td>
                <td>
                  <span class="badge" :style="badgeStyle(a.driver)">{{ badgeName(a.driver) }}</span>
                </td>
                <td>
                  <span class="status-dot" :class="{ on: a.enabled !== false }"></span>
                  {{ a.enabled !== false ? '已启用' : '已禁用' }}
                </td>
                <td>{{ a.server_proxy ? '是' : '否' }}</td>
                <td class="col-op">
                  <button class="btn btn-sm" @click="startEdit(a)">编辑</button>
                  <button
                    class="btn btn-sm"
                    :class="a.enabled === false ? 'btn-success' : 'btn-warning'"
                    @click="$emit('toggle-enabled', a)"
                  >
                    {{ a.enabled === false ? '启用' : '禁用' }}
                  </button>
                  <button class="btn btn-sm btn-danger-solid" @click="$emit('delete', a)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="storage-grid">
          <div
            v-for="a in accounts"
            :key="a.id"
            class="storage-card"
            :class="{ editing: editingId === a.id, disabled: a.enabled === false }"
          >
            <div class="sc-top">
              <span class="badge" :style="badgeStyle(a.driver)">{{ badgeName(a.driver) }}</span>
              <div class="sc-actions">
                <button
                  class="btn-icon btn-edit-icon"
                  :class="{ active: editingId === a.id }"
                  title="编辑"
                  @click="startEdit(a)"
                >
                  <Icon name="edit" :size="15" />
                </button>
                <button class="btn-icon btn-danger" title="删除" @click="$emit('delete', a)">
                  <Icon name="trash" :size="16" />
                </button>
              </div>
            </div>
            <div class="sc-name" :title="a.name">{{ a.name }}</div>
            <div class="sc-meta">
              <span v-if="a.server_proxy" class="proxy-badge" title="服务器代理已开启">代理</span>
              <span class="sc-id">ID {{ a.id }}</span>
              <span
                class="toggle toggle-sm"
                :class="{ on: a.enabled !== false }"
                :title="a.enabled !== false ? '已启用，点击禁用' : '已禁用，点击启用'"
                @click.stop="$emit('toggle-enabled', a)"
                role="switch"
                :aria-checked="a.enabled !== false"
              >
                <span class="toggle-thumb"></span>
              </span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- 添加 / 编辑存储弹窗 -->
    <div v-if="modalOpen" class="modal-mask" @click.self="closeModal">
      <div class="modal-card">
        <div class="panel-head modal-head">
          <Icon :name="editingId ? 'edit' : 'folder-plus'" :size="18" />
          <h2>{{ editingId ? '编辑存储' : '添加存储' }}</h2>
          <span v-if="editingId && loadingSecret" class="secret-status loading">
            <span class="spin loader-sm"></span>
            正在加载凭据…
          </span>
          <span v-else-if="editingId && secretError" class="secret-status error">
            {{ secretError }}
          </span>
          <button class="modal-close" title="关闭" @click="closeModal">
            <Icon name="x" :size="16" />
          </button>
        </div>
        <div class="panel-body modal-body">
          <div class="field">
            <label>网盘类型</label>
            <select class="input" v-model="form.driver" :disabled="!!editingId">
              <option v-for="d in DRIVERS" :key="d.value" :value="d.value">{{ d.label }}</option>
            </select>
          </div>
          <div class="field">
            <label>备注名（可选）</label>
            <input class="input" v-model="form.name" :placeholder="`如：我的${currentDriverLabel}`" />
          </div>

          <template v-if="form.driver === 'quark' || form.driver === 'quark_uc'">
            <div class="field">
              <label>Cookie</label>
              <textarea
                class="input"
                v-model="form.cookie"
                :placeholder="form.driver === 'quark'
                  ? '登录 pan.quark.cn 后，F12 -> 网络 -> 任意请求 -> 复制请求头里的 Cookie 整段粘贴到这里'
                  : '登录 drive.uc.cn 后，F12 -> 网络 -> 任意请求 -> 复制请求头里的 Cookie 整段粘贴到这里'"
              ></textarea>
            </div>
            <p class="hint-text">
              获取方式：浏览器登录{{ form.driver === 'quark' ? '夸克网盘' : 'UC 网盘' }} → F12 开发者工具 → Network → 刷新 → 任选一个网盘请求 → 复制 Request Headers 中完整的 Cookie 值。
            </p>
          </template>

          <template v-else-if="form.driver === '123pan'">
            <div class="field">
              <label>账号（手机号或邮箱）</label>
              <input class="input" v-model="form.username" placeholder="123 网盘登录账号" />
            </div>
            <div class="field">
              <label>密码</label>
              <input class="input" type="password" v-model="form.password" placeholder="登录密码" />
            </div>
          </template>

          <template v-else-if="form.driver === 'aliyundrive_open'">
            <div class="field">
              <label>RefreshToken</label>
              <textarea class="input" v-model="form.refresh_token" placeholder="阿里云盘开放平台 refresh_token"></textarea>
            </div>
            <p class="hint-text">
              获取方式：登录 aliyun.com 后访问 alipan.com，F12 → 应用 → 本地存储 → token 里的 refresh_token；或使用第三方令牌获取工具。
            </p>
          </template>

          <template v-else-if="form.driver === 'baidu_netdisk'">
            <div class="field">
              <label>RefreshToken</label>
              <textarea class="input" v-model="form.refresh_token" placeholder="百度网盘开放平台 refresh_token"></textarea>
            </div>
            <p class="hint-text">获取方式：使用 OpenList 官方扫码授权工具获取百度网盘 refresh_token 后粘贴到这里。</p>
          </template>

          <template v-else-if="form.driver === 'pan115'">
            <div class="field">
              <label>Cookie</label>
              <textarea class="input" v-model="form.cookie" placeholder="需包含 UID、CID、SEID 三个字段"></textarea>
            </div>
            <p class="hint-text">获取方式：浏览器登录 115.com → F12 → 网络 → 刷新 → 复制 Request Headers 中的完整 Cookie（须含 UID/CID/SEID）。</p>
          </template>

          <template v-else-if="form.driver === 'pan115_open'">
            <div class="field">
              <label>AccessToken</label>
              <textarea class="input" v-model="form.access_token" placeholder="115 开放平台 access_token"></textarea>
            </div>
            <div class="field">
              <label>RefreshToken</label>
              <textarea class="input" v-model="form.refresh_token" placeholder="115 开放平台 refresh_token"></textarea>
            </div>
          </template>

          <template v-else-if="form.driver === 'pan115_share'">
            <div class="field">
              <label>分享码 share_code</label>
              <input class="input" v-model="form.share_code" placeholder="115 分享链接中的 share_code" />
            </div>
            <div class="field">
              <label>提取码 receive_code</label>
              <input class="input" v-model="form.receive_code" placeholder="分享提取码" />
            </div>
            <div class="field">
              <label>Cookie（可选）</label>
              <textarea class="input" v-model="form.cookie" placeholder="可选，含 UID/CID/SEID"></textarea>
            </div>
          </template>

          <template v-else-if="form.driver === 'pan123_open'">
            <div class="field">
              <label>ClientID（开发者凭证，可选）</label>
              <input class="input" v-model="form.client_id" />
            </div>
            <div class="field">
              <label>ClientSecret（可选）</label>
              <input class="input" v-model="form.client_secret" />
            </div>
            <div class="field">
              <label>RefreshToken（在线刷新）</label>
              <textarea class="input" v-model="form.refresh_token"></textarea>
            </div>
            <div class="field">
              <label>AccessToken（可选）</label>
              <textarea class="input" v-model="form.access_token"></textarea>
            </div>
          </template>

          <template v-else-if="form.driver === 'pan123_link'">
            <div class="field">
              <label>直链树 origin_urls</label>
              <textarea class="input" v-model="form.origin_urls" placeholder="Folder:\n  https://vip.123pan.com/..." rows="8"></textarea>
            </div>
            <div class="field">
              <label>PrivateKey（可选，URL 鉴权）</label>
              <input class="input" v-model="form.private_key" />
            </div>
            <div class="field">
              <label>UID</label>
              <input class="input" type="number" v-model.number="form.uid" />
            </div>
          </template>

          <template v-else-if="form.driver === 'aliyundrive'">
            <div class="field">
              <label>RefreshToken</label>
              <textarea class="input" v-model="form.refresh_token" placeholder="旧版阿里云盘 refresh_token（建议改用开放平台）"></textarea>
            </div>
            <p class="hint-text">旧版驱动已废弃，若失败请改用「阿里云盘」开放平台驱动。</p>
          </template>

          <template v-else-if="form.driver === 'aliyundrive_share'">
            <div class="field">
              <label>RefreshToken（任意阿里账号）</label>
              <textarea class="input" v-model="form.refresh_token"></textarea>
            </div>
            <div class="field">
              <label>ShareId</label>
              <input class="input" v-model="form.share_id" placeholder="分享链接中的 share_id" />
            </div>
            <div class="field">
              <label>分享密码（可选）</label>
              <input class="input" v-model="form.share_pwd" />
            </div>
          </template>

          <template v-else-if="form.driver === 'quark_open'">
            <div class="field">
              <label>RefreshToken</label>
              <textarea class="input" v-model="form.refresh_token"></textarea>
            </div>
            <div class="field">
              <label>AppID</label>
              <input class="input" v-model="form.app_id" />
            </div>
            <div class="field">
              <label>SignKey</label>
              <input class="input" v-model="form.sign_key" />
            </div>
          </template>

          <template v-else-if="form.driver === 'quark_tv' || form.driver === 'uc_tv'">
            <div class="field">
              <label>RefreshToken</label>
              <textarea class="input" v-model="form.refresh_token" placeholder="TV 端扫码授权后的 refresh_token"></textarea>
            </div>
            <div class="field">
              <label>DeviceID（可选）</label>
              <input class="input" v-model="form.device_id" />
            </div>
            <div class="field">
              <label>视频链接方式</label>
              <select class="input" v-model="form.link_method">
                <option value="download">download（原画）</option>
                <option value="streaming">streaming（转码）</option>
              </select>
            </div>
          </template>

          <template v-else-if="form.driver === 'thunder'">
            <div class="field">
              <label>账号（手机号或邮箱）</label>
              <input class="input" v-model="form.username" placeholder="迅雷登录账号" />
            </div>
            <div class="field">
              <label>密码</label>
              <input class="input" type="password" v-model="form.password" placeholder="登录密码" />
            </div>
            <p class="hint-text">首次登录可能需要短信验证，验证链接会返回在错误信息中。</p>
          </template>

          <template v-else-if="form.driver === 'lanzou'">
            <div class="field">
              <label>账号（选填，填了则用账号密码登录）</label>
              <input class="input" v-model="form.username" placeholder="蓝奏云登录账号" />
            </div>
            <div class="field">
              <label>密码（选填）</label>
              <input class="input" type="password" v-model="form.password" placeholder="蓝奏云登录密码" />
            </div>
            <div class="field">
              <label>Cookie（账号密码留空时必填）</label>
              <textarea class="input" v-model="form.cookie" placeholder="登录 pc.woozooo.com 后的 cookie；填了账号密码可留空"></textarea>
            </div>
            <p class="hint-text">填账号密码即可，cookie 会自动登录获取（过期自动重登）；也可只填浏览器登录 pc.woozooo.com 后的 cookie（约 15 天有效）。</p>
          </template>

          <template v-else-if="form.driver === 'pan139'">
            <div class="field">
              <label>139 Authorization</label>
              <textarea class="input" v-model="form.authorization" placeholder="base64 编码的 Authorization（同 OpenList 139Yun 的 authorization 字段）"></textarea>
            </div>
            <p class="hint-text">
              获取方式：从 OpenList/Alist 已配置的 139Yun 存储中复制 authorization 字段；或抓包 yun.139.com 请求头里 Authorization（去掉 Basic 前缀）后做 base64 编码。过期后会自动刷新并回写。
            </p>
          </template>

          <template v-else-if="form.driver === 'cloud189'">
            <div class="field">
              <label>账号（手机号或邮箱）</label>
              <input class="input" v-model="form.username" placeholder="天翼云盘登录账号" />
            </div>
            <div class="field">
              <label>密码</label>
              <input class="input" type="password" v-model="form.password" placeholder="登录密码" />
            </div>
            <p class="hint-text">使用天翼云盘账号密码登录；若触发验证码，可先用浏览器登录后重试。</p>
          </template>

          <template v-else-if="form.driver === 'local'">
            <div class="field">
              <label>挂载目录路径</label>
              <input class="input" v-model="form.root_path" placeholder="如：D:\media 或 /mnt/media" />
            </div>
            <p class="hint-text">填写服务器本机上的目录绝对路径，将直接浏览并读取该目录下的文件（支持 Range 断点播放）。</p>
          </template>

          <template v-else-if="form.driver === 'webdav'">
            <div class="field">
              <label>服务器地址</label>
              <input class="input" v-model="form.url" placeholder="如：https://dav.example.com/dav" />
            </div>
            <div class="field">
              <label>用户名（可选）</label>
              <input class="input" v-model="form.username" placeholder="匿名访问可留空" autocomplete="off" />
            </div>
            <div class="field">
              <label>密码（可选）</label>
              <input class="input" type="password" v-model="form.password" placeholder="匿名访问可留空" autocomplete="new-password" />
            </div>
            <div class="field">
              <label>根路径（可选，默认 /）</label>
              <input class="input" v-model="form.root_path" placeholder="/ 默认为服务器根目录" />
            </div>
            <p class="hint-text">仅支持挂载其他 WebDAV 服务器（客户端模式）；下载流量与 Basic Auth 绑定，将经本服务中转。</p>
          </template>

          <template v-else-if="form.driver === '123pan_share'">
            <div class="field">
              <label>ShareKey</label>
              <input class="input" v-model="form.share_key" placeholder="分享链接中的 shareKey" />
            </div>
            <div class="field">
              <label>分享密码（可选）</label>
              <input class="input" v-model="form.share_pwd" placeholder="无密码分享可留空" />
            </div>
            <div class="field">
              <label>AccessToken（可选）</label>
              <input class="input" v-model="form.access_token" placeholder="部分接口需要，可留空" />
            </div>
            <p class="hint-text">只读模式：仅支持浏览与下载分享内容。ShareKey 为分享链接里 key 参数的值。</p>
          </template>

          <template v-else-if="form.driver === 'weiyun'">
            <div class="field">
              <label>Cookie</label>
              <textarea class="input" v-model="form.cookies" placeholder="登录 www.weiyun.com 后的完整 Cookie"></textarea>
            </div>
            <p class="hint-text">获取方式：浏览器登录腾讯微云 → F12 → 网络 → 刷新 → 任选一个请求复制完整 Cookie。支持 QQ / 微信登录的 cookie。</p>
          </template>

          <template v-else-if="form.driver === 'onedrive'">
            <div class="field">
              <label>Region</label>
              <select class="input" v-model="form.region">
                <option value="global">global（国际版）</option>
                <option value="cn">cn（世纪互联）</option>
                <option value="us">us（美国政府版）</option>
                <option value="de">de（德国版）</option>
              </select>
            </div>
            <div class="field">
              <label>账号类型</label>
              <select class="input" v-model="form.is_sharepoint">
                <option :value="false">个人 OneDrive</option>
                <option :value="true">SharePoint 站点</option>
              </select>
            </div>
            <div class="field" v-if="form.is_sharepoint">
              <label>Site ID</label>
              <input class="input" v-model="form.site_id" placeholder="SharePoint 站点 id（GET /v1.0/sites/{hostname}:/path 获取）" />
            </div>
            <div class="field">
              <label>根目录路径（可选，默认 /）</label>
              <input class="input" v-model="form.root_path" placeholder="/ 默认为 OneDrive 根目录" />
            </div>
            <div class="field">
              <label>RefreshToken</label>
              <textarea class="input" v-model="form.refresh_token" placeholder="OneDrive refresh_token"></textarea>
            </div>
            <p class="hint-text">获取方式：从 OpenList/Alist 已配置的 Onedrive 存储中复制 refresh_token 字段。token 过期后会自动刷新并回写。</p>
          </template>

          <template v-else-if="form.driver === 'google_drive'">
            <div class="field">
              <label>RefreshToken</label>
              <textarea class="input" v-model="form.refresh_token" placeholder="Google Drive refresh_token"></textarea>
            </div>
            <div class="field">
              <label>根目录文件夹 ID（可选，默认 root）</label>
              <input class="input" v-model="form.root_folder_id" placeholder="root 表示整个云端硬盘" />
            </div>
            <p class="hint-text">获取方式：从 OpenList/Alist 已配置的 GoogleDrive 存储中复制 refresh_token 字段。下载链接需携带 Bearer 头，将经本服务中转。</p>
          </template>

          <!-- 服务器代理开关 -->
          <div class="field proxy-field">
            <label class="proxy-label">
              <span class="proxy-label-text">
                <span class="proxy-title">服务器代理</span>
                <span class="proxy-desc">开启后下载流量经本服务中转；关闭则直接跳转网盘直链（默认关闭）</span>
              </span>
              <span
                class="toggle"
                :class="{ on: form.server_proxy }"
                @click="form.server_proxy = !form.server_proxy"
                role="switch"
                :aria-checked="form.server_proxy"
              >
                <span class="toggle-thumb"></span>
              </span>
            </label>
          </div>

          <div v-if="error" class="alert alert-error">{{ error }}</div>
          
          <template v-else-if="form.driver === 's3'">
            <div class="field">
              <label>Bucket</label>
              <input class="input" v-model="form.bucket" placeholder="bucket-name" />
            </div>
            <div class="field">
              <label>Endpoint</label>
              <input class="input" v-model="form.endpoint" placeholder="https://s3.amazonaws.com 或 MinIO 地址" />
            </div>
            <div class="field">
              <label>Region</label>
              <input class="input" v-model="form.region" placeholder="us-east-1" />
            </div>
            <div class="field">
              <label>Access Key ID</label>
              <input class="input" v-model="form.access_key_id" />
            </div>
            <div class="field">
              <label>Secret Access Key</label>
              <input class="input" type="password" v-model="form.secret_access_key" />
            </div>
            <div class="field">
              <label>Session Token（可选）</label>
              <input class="input" v-model="form.session_token" />
            </div>
            <div class="field">
              <label>自定义域名 Custom Host（可选）</label>
              <input class="input" v-model="form.custom_host" placeholder="cdn.example.com" />
            </div>
            <div class="field">
              <label>Root Path（可选）</label>
              <input class="input" v-model="form.root_path" placeholder="/" />
            </div>
            <label class="check">
              <input type="checkbox" v-model="form.force_path_style" />
              Force Path Style（MinIO 等需开启）
            </label>
            <p class="hint-text">兼容 AWS S3 / MinIO / 又拍 / 七牛等 S3 API。预签名直链默认 4 小时有效。</p>
          </template>

          <template v-else-if="form.driver === 'sftp'">
            <div class="field">
              <label>地址（host:port）</label>
              <input class="input" v-model="form.address" placeholder="192.168.1.1:22" />
            </div>
            <div class="field">
              <label>用户名</label>
              <input class="input" v-model="form.username" />
            </div>
            <div class="field">
              <label>密码（与私钥二选一）</label>
              <input class="input" type="password" v-model="form.password" />
            </div>
            <div class="field">
              <label>私钥 PEM（可选）</label>
              <textarea class="input" v-model="form.private_key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
            </div>
            <div class="field">
              <label>根目录</label>
              <input class="input" v-model="form.root_path" placeholder="/" />
            </div>
            <p class="hint-text">协议读写将在后续版本完整启用；当前可保存配置并检测端口连通性。</p>
          </template>

          <template v-else-if="form.driver === 'ftp'">
            <div class="field">
              <label>地址（host:port）</label>
              <input class="input" v-model="form.address" placeholder="192.168.1.1:21" />
            </div>
            <div class="field">
              <label>用户名</label>
              <input class="input" v-model="form.username" />
            </div>
            <div class="field">
              <label>密码</label>
              <input class="input" type="password" v-model="form.password" />
            </div>
            <div class="field">
              <label>编码（可选，默认 UTF-8）</label>
              <input class="input" v-model="form.encoding" placeholder="utf-8 / gbk" />
            </div>
            <div class="field">
              <label>根目录</label>
              <input class="input" v-model="form.root_path" placeholder="/" />
            </div>
            <label class="check">
              <input type="checkbox" v-model="form.cwd_list" />
              先 CWD 再 LIST（部分服务器需要）
            </label>
          </template>

          <template v-else-if="form.driver === 'smb'">
            <div class="field">
              <label>地址（host:port）</label>
              <input class="input" v-model="form.address" placeholder="192.168.1.1:445" />
            </div>
            <div class="field">
              <label>用户名</label>
              <input class="input" v-model="form.username" />
            </div>
            <div class="field">
              <label>密码</label>
              <input class="input" type="password" v-model="form.password" />
            </div>
            <div class="field">
              <label>共享名 Share Name</label>
              <input class="input" v-model="form.share_name" placeholder="myshare" />
            </div>
            <div class="field">
              <label>根目录（可选）</label>
              <input class="input" v-model="form.root_path" placeholder="." />
            </div>
            <p class="hint-text">协议读写将在后续版本完整启用；当前可保存配置并检测端口连通性。也可先在系统挂载后用「本机存储」。</p>
          </template>

          <template v-else-if="form.driver === 'alist_v3'">
            <label class="field">
              <span>站点 URL</span>
              <input class="input" v-model="form.url" placeholder="https://alist.example.com" />
            </label>
            <label class="field">
              <span>用户名（可选）</span>
              <input class="input" v-model="form.username" placeholder="留空则使用 Token" />
            </label>
            <label class="field">
              <span>密码（可选）</span>
              <input class="input" type="password" v-model="form.password" />
            </label>
            <label class="field">
              <span>Token（可选）</span>
              <input class="input" v-model="form.token" placeholder="已有 Token 可直接填" />
            </label>
            <label class="field">
              <span>元信息密码</span>
              <input class="input" v-model="form.meta_password" placeholder="目录加密密码，可选" />
            </label>
            <p class="hint-text">挂载另一套 AList / OpenList。优先 Token；否则用用户名密码登录。</p>
          </template>

          <template v-else-if="form.driver === 'github_releases'">
            <label class="field">
              <span>仓库结构</span>
              <textarea class="input" rows="3" v-model="form.repo_structure"
                placeholder="OpenListTeam/OpenList&#10;/frontend:OpenListTeam/OpenList-Frontend"></textarea>
            </label>
            <label class="field">
              <span>GitHub Token（可选）</span>
              <input class="input" v-model="form.token" placeholder="私有库或提高限流" />
            </label>
            <label class="field row">
              <input type="checkbox" v-model="form.show_all_version" />
              <span>显示全部版本</span>
            </label>
            <label class="field row">
              <input type="checkbox" v-model="form.show_source_code" />
              <span>显示源码包</span>
            </label>
            <label class="field">
              <span>GitHub 代理（可选）</span>
              <input class="input" v-model="form.gh_proxy" placeholder="https://ghproxy.net/https://github.com" />
            </label>
            <p class="hint-text">只读挂载 Release 资产。多仓格式：path:org/repo，每行一个。</p>
          </template>

          <template v-else-if="form.driver === 'pikpak'">
            <label class="field"><span>用户名 / 邮箱 / 手机</span>
              <input class="input" v-model="form.username" /></label>
            <label class="field"><span>密码</span>
              <input class="input" type="password" v-model="form.password" /></label>
            <label class="field"><span>Refresh Token（可选）</span>
              <input class="input" v-model="form.refresh_token" placeholder="有则优先使用" /></label>
            <p class="hint-text">优先 refresh_token；失效时用账号密码登录（web 客户端）。</p>
          </template>

          <template v-else-if="form.driver === 'onedrive_share'">
            <label class="field"><span>分享链接</span>
              <input class="input" v-model="form.url" placeholder="https://1drv.ms/... 或 sharepoint.com/..." /></label>
            <label class="field"><span>分享密码（可选）</span>
              <input class="input" type="password" v-model="form.password" /></label>
            <p class="hint-text">只读挂载 OneDrive / SharePoint 分享链接。</p>
          </template>


          <template v-else-if="form.driver === 'pikpak_share'">
            <label class="field">
              <span>分享 ID (share_id)</span>
              <input class="input" v-model="form.share_id" placeholder="分享链接里的 ID" />
            </label>
            <label class="field">
              <span>提取码（可选）</span>
              <input class="input" v-model="form.share_pwd" placeholder="无密码可留空" />
            </label>
            <label class="field">
              <span>平台</span>
              <select class="input" v-model="form.platform">
                <option value="web">web</option>
                <option value="android">android</option>
                <option value="pc">pc</option>
              </select>
            </label>
            <label class="field checkbox">
              <input type="checkbox" v-model="form.use_transcoding_address" />
              <span>使用转码地址</span>
            </label>
          </template>

          <template v-else-if="form.driver === 'onedrive_app'">
            <label class="field">
              <span>区域</span>
              <select class="input" v-model="form.region">
                <option value="global">global</option>
                <option value="cn">cn</option>
                <option value="us">us</option>
                <option value="de">de</option>
              </select>
            </label>
            <label class="field">
              <span>Client ID</span>
              <input class="input" v-model="form.client_id" placeholder="Azure 应用 client_id" />
            </label>
            <label class="field">
              <span>Client Secret</span>
              <input class="input" v-model="form.client_secret" type="password" placeholder="client_secret" />
            </label>
            <label class="field">
              <span>Tenant ID</span>
              <input class="input" v-model="form.tenant_id" placeholder="租户 ID，可留空用 common" />
            </label>
            <label class="field">
              <span>用户邮箱</span>
              <input class="input" v-model="form.email" placeholder="user@tenant.onmicrosoft.com" />
            </label>
            <label class="field">
              <span>根路径</span>
              <input class="input" v-model="form.root_path" placeholder="/" />
            </label>
            <label class="field">
              <span>自定义下载 Host（可选）</span>
              <input class="input" v-model="form.custom_host" placeholder="" />
            </label>
          </template>

          <template v-else-if="form.driver === 'dropbox'">
            <label class="field"><span>Refresh Token</span>
              <input class="input" v-model="form.refresh_token" /></label>
            <label class="field row">
              <input type="checkbox" v-model="form.use_online_api" />
              <span>使用在线刷新 API（推荐）</span>
            </label>
            <label class="field"><span>Client ID（关闭在线刷新时需要）</span>
              <input class="input" v-model="form.client_id" /></label>
            <label class="field"><span>Client Secret</span>
              <input class="input" v-model="form.client_secret" /></label>
            <label class="field"><span>根路径（可选）</span>
              <input class="input" v-model="form.root_path" placeholder="/Apps/..." /></label>
          </template>

          <template v-else-if="form.driver === 'google_photo'">
            <label class="field"><span>Refresh Token</span>
              <input class="input" v-model="form.refresh_token" /></label>
            <label class="field"><span>Client ID（可选，有默认）</span>
              <input class="input" v-model="form.client_id" /></label>
            <label class="field"><span>Client Secret（可选，有默认）</span>
              <input class="input" v-model="form.client_secret" /></label>
            <p class="hint-text">根目录含 all / albums / share_albums。下载走代理。</p>
          </template>

          <template v-else-if="form.driver === 'halalcloud_open'">
            <label class="field"><span>Client ID</span>
              <input class="input" v-model="form.client_id" placeholder="哈拉云开发者 client_id" /></label>
            <label class="field"><span>Client Secret</span>
              <input class="input" v-model="form.client_secret" type="password" /></label>
            <label class="field"><span>Refresh Token</span>
              <textarea class="input" v-model="form.refresh_token" placeholder="推荐：过期自动刷新并回写"></textarea></label>
            <label class="field"><span>Access Token（可选，刷新后自动写回）</span>
              <textarea class="input" v-model="form.access_token"></textarea></label>
            <label class="field"><span>API Host（可选）</span>
              <input class="input" v-model="form.host" placeholder="openapi.2dland.cn" /></label>
            <label class="field"><span>超时（秒，可选）</span>
              <input class="input" type="number" v-model.number="form.timeout" placeholder="60" /></label>
            <label class="field"><span>根路径（可选）</span>
              <input class="input" v-model="form.root_path" placeholder="/" /></label>
          </template>



<div class="modal-actions">
            <button class="btn btn-ghost" @click="closeModal">取消</button>
            <button class="btn" :class="{ 'btn-edit': !!editingId }" :disabled="adding" @click="submit">
              <span v-if="adding" class="spin loader"></span>
              <template v-if="!adding">
                {{ editingId ? '保存修改' : '添加存储' }}
              </template>
              <template v-else>
                {{ editingId ? '保存中…' : '验证中…' }}
              </template>
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, reactive, ref, watch } from 'vue'
import Icon from './Icon.vue'

const props = defineProps({
  accounts: { type: Array, required: true },
  error: { type: String, default: '' },
  adding: { type: Boolean, default: false },
  driverLabels: { type: Object, required: true },
  fetchSecret: { type: Function, default: null }
})
const emit = defineEmits(['add', 'edit', 'delete', 'toggle-enabled', 'refresh'])
const storageLayout = ref(localStorage.getItem('ol-storages-layout') || 'grid')
watch(storageLayout, (v) => {
  try { localStorage.setItem('ol-storages-layout', v) } catch (_) {}
})

const DRIVERS = [
  { value: 'quark', label: '夸克网盘' },
  { value: 'quark_uc', label: 'UC 网盘' },
  { value: '123pan', label: '123 网盘' },
  { value: 'aliyundrive_open', label: '阿里云盘' },
  { value: 'baidu_netdisk', label: '百度网盘' },
  { value: 'pan115', label: '115 网盘' },
  { value: 'thunder', label: '迅雷网盘' },
  { value: 'lanzou', label: '蓝奏云' },
  { value: 'pan139', label: '移动云盘' },
  { value: 'cloud189', label: '天翼云盘' },
  { value: 'local', label: '本机存储' },
  { value: 'webdav', label: 'WebDAV' },
  { value: '123pan_share', label: '123 分享' },
  { value: 'weiyun', label: '腾讯微云' },
  { value: 'onedrive', label: 'OneDrive' },
  { value: 'google_drive', label: 'Google Drive' },
  { value: 's3', label: 'S3' },
  { value: 'sftp', label: 'SFTP' },
  { value: 'ftp', label: 'FTP' },
  { value: 'smb', label: 'SMB' },
  { value: 'alist_v3', label: 'AList V3' },
  { value: 'github_releases', label: 'GitHub Releases' },
  { value: 'pikpak', label: 'PikPak' },
  { value: 'onedrive_share', label: 'OneDrive 分享' },
  { value: 'dropbox', label: 'Dropbox' },
  { value: 'google_photo', label: 'Google Photos' },
  { value: 'pan115_open', label: '115 Open' },
  { value: 'pan115_share', label: '115 分享' },
  { value: 'pan123_open', label: '123 Open' },
  { value: 'pan123_link', label: '123PanLink' },
  { value: 'aliyundrive', label: '阿里云盘(旧)' },
  { value: 'aliyundrive_share', label: '阿里云盘分享' },
  { value: 'quark_open', label: '夸克 Open' },
  { value: 'quark_tv', label: '夸克 TV' },
  { value: 'uc_tv', label: 'UC TV' },
  { value: 'pikpak_share', label: 'PikPak 分享' },
  { value: 'onedrive_app', label: 'OneDrive APP' },
  { value: 'openlist', label: 'OpenList 挂载' },
  { value: 'openlist_share', label: 'OpenList 分享' },
  { value: 'seafile', label: 'Seafile' },
  { value: 'kodbox', label: '可道云 KodBox' },
  { value: 'cloudreve_v4', label: 'Cloudreve V4' },
  { value: 'yandex_disk', label: 'Yandex.Disk' },
  { value: 'terabox', label: 'Terabox' },
  { value: 'ilanzou', label: '蓝奏云优创' },
  { value: 'halalcloud_open', label: '哈拉云' },
  { value: 'bunny', label: 'BunnyCDN' },
  { value: 'virtual', label: '虚拟存储' }
]

// 当前正在编辑的账号 id，null 表示新增模式
const editingId = ref(null)

// 弹窗开关
const modalOpen = ref(false)

const form = reactive({
  driver: 'quark',
  name: '',
  cookie: '',
  username: '',
  password: '',
  refresh_token: '',
  authorization: '',
  root_path: '',
  url: '',
  share_key: '',
  share_pwd: '',
  email: '',
  tenant_id: '',
  use_transcoding_address: false,
  platform: 'web',
  access_token: '',
  cookies: '',
  region: 'global',
  is_sharepoint: false,
  site_id: '',
  root_folder_id: '',
  bucket: '',
  endpoint: '',
  access_key_id: '',
  secret_access_key: '',
  session_token: '',
  custom_host: '',
  host: 'openapi.2dland.cn',
  timeout: 60,
  force_path_style: false,
  sign_url_expire: 4,
  private_key: '',
  passphrase: '',
  ignore_symlink_error: false,
  encoding: '',
  cwd_list: false,
  address: '',
  share_name: '',
  meta_password: '',
  token: '',
  repo_structure: '',
  show_all_version: false,
  show_source_code: false,
  gh_proxy: '',
  per_page: 30,
  max_page: 0,
  client_id: '',
  client_secret: '',
  use_online_api: true,
  device_id: '',
  share_code: '',
  receive_code: '',
  share_id: '',
  origin_urls: '',
  uid: 0,
  valid_duration: 30,
  app_id: '',
  sign_key: '',
  api_address: '',
  link_method: 'download',
  num_file: 5,
  num_folder: 0,
  repo_id: '',
  repo_pwd: '',
  site: 'ilanzou',
  download_api: 'official',
  server_proxy: false
})

const currentDriverLabel = computed(
  () => DRIVERS.find((d) => d.value === form.driver)?.label.replace('网盘', '') || ''
)

function resetForm() {
  editingId.value = null
  form.driver = 'quark'
  form.name = ''
  form.cookie = ''
  form.username = ''
  form.password = ''
  form.refresh_token = ''
  form.authorization = ''
  form.root_path = ''
  form.url = ''
  form.share_key = ''
  form.share_pwd = ''
  form.access_token = ''
  form.cookies = ''
  form.region = 'global'
  form.is_sharepoint = false
  form.site_id = ''
  form.root_folder_id = ''
  form.host = 'openapi.2dland.cn'
  form.timeout = 60
  form.server_proxy = false
  form.num_file = 5
  form.num_folder = 0
  form.repo_id = ''
  form.repo_pwd = ''
  form.site = 'ilanzou'
  form.download_api = 'official'
  form.address = ''
}

function openAdd() {
  resetForm()
  secretError.value = ''
  modalOpen.value = true
}

function closeModal() {
  // 提交中不允许关闭，避免丢状态
  if (props.adding) return
  modalOpen.value = false
  resetForm()
  secretError.value = ''
}

// 编辑回填中的 loading 状态（用于按钮禁用/提示）
const loadingSecret = ref(false)
const secretError = ref('')

// 点击编辑图标：弹窗打开并回填信息（包括凭据，如 cookie/密码/refresh_token）
async function startEdit(account) {
  editingId.value = account.id
  secretError.value = ''
  modalOpen.value = true
  // 先用列表里已有的字段回填，不用等接口
  form.driver = account.driver
  form.name = account.name
  form.cookie = ''
  form.username = ''
  form.password = ''
  form.refresh_token = ''
  form.authorization = ''
  form.root_path = ''
  form.url = ''
  form.share_key = ''
  form.share_pwd = ''
  form.access_token = ''
  form.cookies = ''
  form.region = 'global'
  form.is_sharepoint = false
  form.site_id = ''
  form.root_folder_id = ''
  form.host = 'openapi.2dland.cn'
  form.timeout = 60
  form.server_proxy = account.server_proxy ?? false

  // 再拉取凭据明细，回填 cookie / 账号密码 / refresh_token
  if (!props.fetchSecret) return
  loadingSecret.value = true
  try {
    const secret = await props.fetchSecret(account.id)
    // 若在请求过程中用户切换了编辑目标或关闭了弹窗，则丢弃这次结果
    if (editingId.value !== account.id || !modalOpen.value) return
    form.driver = secret.driver ?? form.driver
    form.name = secret.name ?? form.name
    form.cookie = secret.cookie ?? ''
    form.username = secret.username ?? ''
    form.password = secret.password ?? ''
    form.refresh_token = secret.refresh_token ?? ''
    form.authorization = secret.authorization ?? ''
    form.root_path = secret.root_path ?? ''
    form.url = secret.url ?? ''
    form.share_key = secret.share_key ?? ''
    form.share_pwd = secret.share_pwd ?? ''
    form.access_token = secret.access_token ?? ''
    form.cookies = secret.cookies ?? ''
    form.region = secret.region ?? 'global'
    form.is_sharepoint = secret.is_sharepoint ?? false
    form.site_id = secret.site_id ?? ''
    form.root_folder_id = secret.root_folder_id ?? ''
    form.bucket = secret.bucket ?? ''
    form.endpoint = secret.endpoint ?? ''
    form.access_key_id = secret.access_key_id ?? ''
    form.secret_access_key = secret.secret_access_key ?? ''
    form.session_token = secret.session_token ?? ''
    form.custom_host = secret.custom_host ?? ''
    form.host = secret.host ?? 'openapi.2dland.cn'
    form.timeout = secret.timeout ?? 60
    form.force_path_style = secret.force_path_style ?? false
    form.sign_url_expire = secret.sign_url_expire ?? 4
    form.private_key = secret.private_key ?? ''
    form.passphrase = secret.passphrase ?? ''
    form.ignore_symlink_error = secret.ignore_symlink_error ?? false
    form.encoding = secret.encoding ?? ''
    form.cwd_list = secret.cwd_list ?? false
    form.address = secret.address ?? ''
    form.share_name = secret.share_name ?? ''
    form.meta_password = secret.meta_password ?? ''
    form.token = secret.token ?? ''
    form.repo_structure = secret.repo_structure ?? ''
    form.show_all_version = secret.show_all_version ?? false
    form.show_source_code = secret.show_source_code ?? false
    form.gh_proxy = secret.gh_proxy ?? ''
    form.per_page = secret.per_page ?? 30
    form.max_page = secret.max_page ?? 0
    form.client_id = secret.client_id ?? ''
    form.client_secret = secret.client_secret ?? ''
    form.use_online_api = secret.use_online_api ?? true
    form.device_id = secret.device_id ?? ''
    form.num_file = secret.num_file ?? 5
    form.num_folder = secret.num_folder ?? 0
    form.repo_id = secret.repo_id ?? ''
    form.repo_pwd = secret.repo_pwd ?? ''
    form.site = secret.site ?? 'ilanzou'
    form.download_api = secret.download_api ?? 'official'
    form.address = secret.address ?? ''
    form.server_proxy = secret.server_proxy ?? form.server_proxy
  } catch (e) {
    secretError.value = e.message || '获取凭据失败，请手动重新填写'
  } finally {
    loadingSecret.value = false
  }
}

function submit() {
  if (editingId.value) {
    emit('edit', { id: editingId.value, ...form })
  } else {
    emit('add', form)
  }
}

// 操作成功后重置并关闭弹窗（账号列表变化 = 成功信号，如删除）
watch(
  () => props.accounts.length,
  () => {
    modalOpen.value = false
    resetForm()
  }
)

// 编辑成功：error 清空且 adding 从 true→false 时也重置并关闭弹窗；失败则保持弹窗打开显示错误
watch(
  () => props.adding,
  (val) => {
    if (!val && !props.error && editingId.value) {
      modalOpen.value = false
      resetForm()
    }
  }
)

const DRIVER_COLORS = {
  quark: '#00b578',
  quark_uc: '#0089ff',
  '123pan': '#ff7d00',
  aliyundrive_open: '#722ed1',
  baidu_netdisk: '#2468f2',
  pan115: '#f53f3f',
  thunder: '#00b4d8',
  lanzou: '#86909c',
  pan139: '#0e932e',
  cloud189: '#d62828',
  local: '#6366f1',
  webdav: '#0ea5e9',
  '123pan_share': '#ff7d00',
  weiyun: '#12b7f5',
  onedrive: '#0364b8',
  google_drive: '#1fa463',
  s3: '#e85d04',
  sftp: '#5c4b51',
  ftp: '#7b2cbf',
  smb: '#3a86ff',
  alist_v3: '#2a9d8f',
  github_releases: '#24292f',
  pikpak: '#1d9bf0',
  onedrive_share: '#0078d4',
  dropbox: '#0061ff',
  google_photo: '#ea4335',
  pikpak_share: '#1d9bf0',
  onedrive_app: '#0364b8',
  openlist: '#0ea5a5',
  openlist_share: '#0d9488',
  virtual: '#94a3b8',
  bunny: '#ff8c42',
  yandex_disk: '#fc3f1d',
  seafile: '#1c84c6',
  kodbox: '#3f7df6',
  cloudreve_v4: '#6f5bd5',
  terabox: '#06a7ff',
  ilanzou: '#5cb85c',
  halalcloud_open: '#2f6fed'
}
const badgeName = (d) => props.driverLabels[d] || d
const badgeStyle = (d) => {
  const c = DRIVER_COLORS[d] || '#86909c'
  return { background: c + '1f', color: c }
}
</script>

<style scoped>
.accounts-page {
  max-width: 980px;
  margin: 0 auto;
  padding: 4px 20px 60px;
}

/* 页头：标题 + 添加按钮 */
.accounts-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.accounts-title {
  font-size: 18px;
  font-weight: 700;
  color: var(--ol-text);
  margin: 0;
}
.add-btn {
  display: flex;
  align-items: center;
  gap: 5px;
}
.accounts-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.view-toggle {
  display: flex;
  border: 1px solid var(--ol-border-strong);
  border-radius: 6px;
  overflow: hidden;
}
.view-toggle button {
  width: 34px;
  height: 34px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--ol-panel);
  border: none;
  color: var(--ol-text-dim);
  cursor: pointer;
}
.view-toggle button + button {
  border-left: 1px solid var(--ol-border-strong);
}
.view-toggle button.active {
  background: var(--ol-primary-light);
  color: var(--ol-primary);
}
.storage-table-wrap {
  overflow-x: auto;
}
.storage-table {
  width: 100%;
  border-collapse: collapse;
}
.storage-table th,
.storage-table td {
  text-align: left;
  padding: 12px 14px;
  border-bottom: 1px solid var(--ol-border);
  font-size: 13.5px;
}
.storage-table th {
  color: var(--ol-text-dim);
  font-size: 13px;
  font-weight: 700;
}
.storage-table tbody tr:hover {
  background: color-mix(in srgb, var(--ol-primary) 8%, transparent);
}
.storage-table tr.disabled {
  opacity: 0.55;
}
.storage-table .col-op {
  text-align: right;
  white-space: nowrap;
}
.storage-table .col-op .btn {
  margin-left: 6px;
}
.btn-sm {
  height: 30px;
  padding: 0 10px;
  font-size: 13px;
}
.btn-warning {
  background: #ed8936;
}
.btn-warning:hover {
  background: #dd6b20;
}
.btn-success {
  background: #38a169;
}
.btn-success:hover {
  background: #2f855a;
}
.btn-danger-solid {
  background: var(--ol-danger);
}
.btn-danger-solid:hover {
  filter: brightness(0.92);
}
.status-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #cbd5e0;
  margin-right: 6px;
  vertical-align: middle;
}
.status-dot.on {
  background: #38a169;
}

.panel {
  overflow: hidden;
}
.panel-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--ol-border);
  color: var(--ol-primary);
}
.panel-head h2 {
  font-size: 15px;
  font-weight: 600;
  color: var(--ol-text);
  margin: 0;
  flex: 1;
}
.panel-body {
  padding: 20px;
}

/* 存储卡片网格：桌面多列铺满，移动端单列 */
.storage-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 14px;
}
.storage-card {
  padding: 14px 16px;
  border: 1px solid var(--ol-border);
  border-radius: 12px;
  background: var(--ol-panel);
  transition: box-shadow 0.15s, border-color 0.15s, transform 0.15s;
}
.storage-card:hover {
  border-color: color-mix(in srgb, var(--ol-primary) 45%, var(--ol-border));
  box-shadow: var(--ol-shadow);
  transform: translateY(-1px);
}
.storage-card.editing {
  border-color: var(--ol-primary);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--ol-primary) 18%, transparent);
}
.sc-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.sc-actions {
  display: flex;
  align-items: center;
  gap: 2px;
  opacity: 0.85;
}
.storage-card:hover .sc-actions {
  opacity: 1;
}
.sc-name {
  margin-top: 10px;
  font-size: 14.5px;
  font-weight: 600;
  color: var(--ol-text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.sc-meta {
  margin-top: 6px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.sc-id {
  font-size: 11.5px;
  color: var(--ol-text-faint);
}

@media (max-width: 640px) {
  .storage-grid {
    grid-template-columns: 1fr;
  }
}

.loader {
  width: 13px;
  height: 13px;
  border: 2px solid rgba(255, 255, 255, 0.4);
  border-top-color: #fff;
  border-radius: 50%;
}

/* 凭据加载状态提示 */
.secret-status {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  white-space: nowrap;
}
.secret-status.loading {
  color: var(--ol-text-dim);
}
.secret-status.error {
  color: var(--ol-danger);
}
.loader-sm {
  width: 11px;
  height: 11px;
  border: 2px solid color-mix(in srgb, var(--ol-text-dim) 30%, transparent);
  border-top-color: var(--ol-text-dim);
  border-radius: 50%;
  flex-shrink: 0;
}

/* 保存修改按钮用橙色区分 */
.btn.btn-edit {
  background: #f59e0b;
}
.btn.btn-edit:hover:not(:disabled) {
  background: #d97706;
}

.empty-mini {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  color: var(--ol-text-dim);
  padding: 30px 0;
  font-size: 13px;
}

/* 编辑按钮：样式与删除按钮保持一致，无背景/边框 */
.btn-edit-icon {
  background: transparent;
  border: 1px solid transparent;
  color: var(--ol-text-dim);
  cursor: pointer;
  transition: background-color 0.15s, color 0.15s;
}
.btn-edit-icon:hover,
.btn-edit-icon.active {
  background: color-mix(in srgb, var(--ol-primary) 10%, transparent);
  color: var(--ol-primary);
}

/* 服务器代理开关 */
.proxy-field {
  margin-top: 4px;
}
.proxy-label {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  cursor: default;
}
.proxy-label-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.proxy-title {
  font-size: 13.5px;
  font-weight: 500;
  color: var(--ol-text);
}
.proxy-desc {
  font-size: 12px;
  color: var(--ol-text-dim);
  line-height: 1.4;
}

/* Toggle 开关 */
.toggle {
  flex-shrink: 0;
  width: 42px;
  height: 24px;
  border-radius: 12px;
  background: var(--ol-border);
  position: relative;
  cursor: pointer;
  transition: background 0.2s;
  user-select: none;
}
.toggle.on {
  background: var(--ol-primary);
}
.toggle-thumb {
  position: absolute;
  top: 3px;
  left: 3px;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: #fff;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
  transition: transform 0.2s;
}
.toggle.on .toggle-thumb {
  transform: translateX(18px);
}

/* 代理状态角标 */
.proxy-badge {
  font-size: 11px;
  padding: 1px 6px;
  border-radius: 4px;
  background: #e6f4ff;
  color: #1677ff;
  font-weight: 500;
  flex-shrink: 0;
}

/* 添加 / 编辑弹窗 */
.modal-mask {
  position: fixed;
  inset: 0;
  z-index: 120;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: 40px 16px;
  background: rgba(15, 17, 21, 0.45);
  backdrop-filter: blur(2px);
  overflow-y: auto;
}
.modal-card {
  width: 100%;
  max-width: 560px;
  background: var(--ol-panel);
  border-radius: 14px;
  box-shadow: var(--ol-shadow-lg);
  overflow: hidden;
}
.modal-head {
  position: relative;
}
.modal-close {
  margin-left: auto;
  width: 30px;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  border-radius: 7px;
  color: var(--ol-text-dim);
  cursor: pointer;
  transition: background-color 0.15s, color 0.15s;
}
.modal-close:hover {
  background: color-mix(in srgb, var(--ol-text-dim) 12%, transparent);
  color: var(--ol-text);
}
.modal-body {
  padding-top: 16px;
}
.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  margin-top: 6px;
}
@media (max-width: 640px) {
  .modal-mask {
    padding: 16px 10px;
  }
}

/* 小号 toggle（卡片内）*/
.toggle-sm {
  width: 32px;
  height: 18px;
  border-radius: 9px;
  margin-left: auto;
  flex-shrink: 0;
}
.toggle-sm .toggle-thumb {
  width: 12px;
  height: 12px;
  top: 3px;
  left: 3px;
}
.toggle-sm.on .toggle-thumb {
  transform: translateX(14px);
}

/* 禁用状态卡片视觉降调 */
.storage-card.disabled {
  opacity: 0.5;
}
.storage-card.disabled .sc-name {
  color: var(--ol-text-dim);
}
</style>
