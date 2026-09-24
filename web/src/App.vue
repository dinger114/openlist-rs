<template>
  <LoginView
    v-if="needLogin"
    ref="loginViewRef"
    :form="loginForm"
    :error="loginError"
    :loading="loggingIn"
    @update:form="(v) => (loginForm = v)"
    @login="doLogin"
    @guest="guestBrowse"
  />

<div class="app-shell">
    <header class="app-header">
      <div class="header-inner">
        <div class="brand" @click="goHome">
          <Logo :size="34" class="brand-logo" />
          <span class="brand-name">OpenList</span>
        </div>

        <nav class="app-nav">
          <button class="nav-btn" :class="{ active: view === 'files' }" @click="view = 'files'">
            文件
          </button>
          <button class="nav-btn" :class="{ active: view === 'accounts' }" @click="view = 'accounts'">
            存储管理
          </button>
          <button class="nav-btn" :class="{ active: view === 'settings' }" @click="view = 'settings'">
            设置
          </button>
        </nav>

        <div class="header-actions">
          <button class="btn-icon btn-ghost" title="切换主题" @click="toggleTheme">
            <Icon :name="isDark ? 'sun' : 'moon'" :size="17" />
          </button>
          <button v-if="authEnabled" class="btn-icon btn-ghost" title="退出登录" @click="doLogout">
            <Icon name="logout" :size="17" />
          </button>
        </div>
      </div>
    </header>

    <AccountsView
      v-if="view === 'accounts'"
      :accounts="accounts"
      :error="accError"
      :adding="adding"
      :driver-labels="DRIVER_LABELS"
      :fetch-secret="fetchAccountSecret"
      @add="addAccount"
      @edit="editAccount"
      @delete="delAccount"
      @toggle-enabled="toggleEnabled"
      @refresh="loadAccounts"
    />

    <SettingsView
      v-else-if="view === 'settings'"
      @saved="onSettingsSaved"
    />

    <FilesView
      v-if="view !== 'accounts' && view !== 'settings'"
      :accounts="accounts"
      :current-id="currentId"
      :crumbs="crumbs"
      :entries="entries"
      :preview="preview"
      :loading="loading"
      :refreshing="refreshing"
      :err="err"
      :driver-labels="DRIVER_LABELS"
      :can-write="canWrite"
      v-model:view-mode="viewMode"
      @go-accounts="view = 'accounts'"
      @go-home="goHome"
      @open-account="onSwitchAccount"
      @switch-account="onSwitchAccount"
      @goto="goto"
      @refresh="refreshCurrent"
      @open-dir="openDir"
      @preview="handlePreview"
      @close-preview="closePreview"
      @download="download"
      @mkdir="fsMkdir"
      @rename="fsRename"
      @move="fsMove"
      @copy="fsCopy"
      @remove="fsRemove"
      @upload="fsUpload"
    />

    <!-- 目标目录选择弹窗（移动/复制用） -->
    <div v-if="picker.open" class="picker-mask" @click.self="picker.open = false">
      <div class="picker card">
        <div class="picker-head">
          <span>{{ picker.mode === 'move' ? '移动到' : '复制到' }}</span>
          <button class="btn-icon btn-ghost" @click="picker.open = false">
            <Icon name="close" :size="16" />
          </button>
        </div>
        <nav class="picker-crumbs">
          <a
            v-for="(c, i) in picker.crumbs"
            :key="i"
            href="#"
            class="crumb-link"
            @click.prevent="pickerGoto(i)"
            >{{ c.name }}</a
          >
        </nav>
        <div class="picker-body">
          <div v-if="picker.loading" class="picker-state">
            <span class="spin loader-sm"></span>
          </div>
          <div v-else-if="picker.dirs.length === 0" class="picker-state">没有子文件夹</div>
          <button
            v-for="d in picker.dirs"
            :key="d.fid"
            class="picker-item"
            @click="pickerEnter(d)"
          >
            <Icon name="folder-plus" :size="16" />
            <span>{{ d.name }}</span>
          </button>
        </div>
        <div class="picker-foot">
          <button class="btn btn-secondary" @click="picker.open = false">取消</button>
          <button class="btn" :disabled="picker.busy" @click="pickerConfirm">
            {{ picker.mode === 'move' ? '移动到此处' : '复制到此处' }}
          </button>
        </div>
      </div>
    </div>

    <!-- 上传任务面板 -->
    <div v-if="uploads.length" class="upload-panel card">
      <div class="upload-head">
        <span>上传任务</span>
        <button class="btn-icon btn-ghost" title="清除已完成" @click="clearFinishedUploads">
          <Icon name="close" :size="14" />
        </button>
      </div>
      <div v-for="(t, i) in uploads" :key="i" class="upload-item">
        <div class="upload-name" :title="t.relPath">
          <Icon :name="t.status === 'error' ? 'alert' : 'upload'" :size="14" />
          {{ t.relPath }}
        </div>
        <div class="upload-bar">
          <div
            class="upload-bar-fill"
            :class="{ done: t.status === 'done', fail: t.status === 'error' }"
            :style="{ width: uploadPct(t) + '%' }"
          ></div>
        </div>
        <div class="upload-meta">
          {{ t.status === 'error' ? t.error : `${fmtSize(t.loaded)} / ${fmtSize(t.size)}` }}
        </div>
      </div>
    </div>

    <!-- 页脚（对齐官方 Footer：Powered by | 管理） -->
    <footer class="app-footer">
      <a href="https://github.com/OpenListTeam/OpenList" target="_blank" rel="noopener">Powered by OpenList</a>
      <span>|</span>
      <a href="#" @click.prevent="view = 'accounts'">{{ view === 'accounts' ? '文件' : '管理' }}</a>
    </footer>
  </div>
</template>

<script setup>
import { ref, computed, reactive, onMounted } from 'vue'
import Icon from './components/Icon.vue'
import Logo from './components/Logo.vue'
import LoginView from './components/LoginView.vue'
import AccountsView from './components/AccountsView.vue'
import FilesView from './components/FilesView.vue'
import SettingsView from './components/SettingsView.vue'
import { kindOf } from './filekinds.js'

const loginViewRef = ref(null)

const view = ref('files')
const viewMode = ref('list')
const accounts = ref([])
const currentId = ref('')
const entries = ref([])
const crumbs = ref([{ fid: '0', name: '根目录' }])
const loading = ref(false)
const refreshing = ref(false)
const err = ref('')

const accError = ref('')
const adding = ref(false)

const DRIVER_LABELS = {
  quark: '夸克',
  quark_uc: 'UC',
  '123pan': '123',
  aliyundrive_open: '阿里',
  baidu_netdisk: '百度',
  pan115: '115',
  thunder: '迅雷',
  lanzou: '蓝奏云',
  pan139: '移动云盘',
  cloud189: '天翼',
  onedrive: 'OneDrive',
  google_drive: 'Google',
  s3: 'S3',
  sftp: 'SFTP',
  ftp: 'FTP',
  smb: 'SMB',
  pan115_open: '115 Open',
  pan115_share: '115 分享',
  pan123_open: '123 Open',
  pan123_link: '123Link',
  aliyundrive: '阿里(旧)',
  aliyundrive_share: '阿里分享',
  quark_open: '夸克 Open',
  quark_tv: '夸克 TV',
  uc_tv: 'UC TV',
  pikpak: 'PikPak',
  pikpak_share: 'PikPak 分享',
  onedrive_app: 'OneDrive APP',
  onedrive_share: 'OneDrive 分享',
  dropbox: 'Dropbox',
  google_photo: 'Photos',
  local: '本机',
  webdav: 'WebDAV',
  '123pan_share': '123 分享',
  weiyun: '微云',
  alist_v3: 'AList',
  github_releases: 'GitHub',
  openlist: 'OpenList',
  openlist_share: 'OL 分享',
  virtual: '虚拟',
  bunny: 'Bunny',
  yandex_disk: 'Yandex',
  seafile: 'Seafile',
  kodbox: '可道云',
  cloudreve_v4: 'Cloudreve',
  terabox: 'Terabox',
  ilanzou: '蓝奏优',
  halalcloud_open: 'halalcloud'
}

// 鉴权
const needLogin = ref(false)
const authEnabled = ref(false)
const loginForm = ref({ username: '', password: '' })
const loginError = ref('')
const loggingIn = ref(false)

// 预览（视频/音乐/图片/PDF/文本统一走这里，_kind 由扩展名判定）
const preview = ref(null)

// 主题
const isDark = ref(false)
function applyTheme() {
  document.documentElement.classList.toggle('dark', isDark.value)
}
function toggleTheme() {
  isDark.value = !isDark.value
  localStorage.setItem('ol-theme', isDark.value ? 'dark' : 'light')
  applyTheme()
}

async function api(path, opts) {
  const r = await fetch(path, opts)
  // 后端错误体可能是 JSON 也可能是 text/plain（axum (StatusCode, String)），
  // 必须先读 text 再尝试解析，否则真实错误信息会被 statusText（如 "Bad Request"）掩盖
  const text = await r.text()
  let body = {}
  try {
    body = text ? JSON.parse(text) : {}
  } catch {
    body = { message: text }
  }
  if ((r.status === 401 || body.code === 401) && authEnabled.value) {
    needLogin.value = true
    throw new Error('未登录或会话已过期')
  }
  if (!r.ok) throw new Error(body.message || body.error || r.statusText || `HTTP ${r.status}`)
  // 兼容层错误：HTTP 200 + {"code":500,"message":...}
  if (body.code && body.code !== 200) throw new Error(body.message || `错误码 ${body.code}`)
  return body
}

async function checkAuth() {
  const b = await fetch('/api/auth/status')
    .then((r) => r.json())
    .catch(() => ({ enabled: false }))
  authEnabled.value = !!b.enabled
}

async function doLogin() {
  loginError.value = ''
  loggingIn.value = true
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(loginForm.value)
    })
    if (!r.ok) {
      const b = await r.json().catch(() => ({}))
      throw new Error(b.error || '登录失败')
    }
    // 记住账号（对齐官方：勾选时把用户名/密码写入 localStorage）
    loginViewRef.value?.saveRemember(loginForm.value.username, loginForm.value.password)
    needLogin.value = false
    loginForm.value = { username: '', password: '' }
    await loadAccounts()
  } catch (e) {
    loginError.value = e.message
  } finally {
    loggingIn.value = false
  }
}

// 游客模式：直接尝试进入；后端要求登录时（401）会自动回到登录页
async function guestBrowse() {
  needLogin.value = false
  try {
    await loadAccounts()
  } catch {
    needLogin.value = true
  }
}

async function doLogout() {
  await fetch('/api/logout', { method: 'POST' }).catch(() => {})
  needLogin.value = true
}

// 设置页保存成功：服务端已清空全部会话，弹出登录页用新凭据重新登录
function onSettingsSaved() {
  needLogin.value = true
}

async function fetchAccountSecret(id) {
  return api(`/api/accounts/${id}/secret`)
}

async function loadAccounts() {
  const b = await api('/api/accounts')
  accounts.value = b.accounts || []
}

async function addAccount(form) {
  accError.value = ''
  adding.value = true
  try {
    const payload = { name: form.name, driver: form.driver, server_proxy: form.server_proxy ?? false }
    const d = form.driver
    if (['quark', 'quark_uc', 'pan115'].includes(d)) payload.cookie = form.cookie
    else if (d === 'lanzou') {
      payload.cookie = form.cookie
      payload.username = form.username
      payload.password = form.password
    }
    else if (['123pan', 'thunder', 'cloud189'].includes(d)) {
      payload.username = form.username
      payload.password = form.password
    } else if (['aliyundrive_open', 'baidu_netdisk'].includes(d)) payload.refresh_token = form.refresh_token
    else if (d === 'pan139') payload.authorization = form.authorization
    else if (d === 'local') payload.root_path = form.root_path
    else if (d === 'webdav') {
      payload.url = form.url
      payload.username = form.username
      payload.password = form.password
      payload.root_path = form.root_path
    } else if (d === '123pan_share') {
      payload.share_key = form.share_key
      payload.share_pwd = form.share_pwd
      payload.access_token = form.access_token
    } else if (d === 'weiyun') payload.cookies = form.cookies
    else if (d === 'onedrive') {
      payload.refresh_token = form.refresh_token
      payload.region = form.region
      payload.is_sharepoint = form.is_sharepoint
      payload.site_id = form.site_id
      payload.root_path = form.root_path
    } else if (d === 'google_drive') {
      payload.refresh_token = form.refresh_token
      payload.root_folder_id = form.root_folder_id
    }

    else if (d === 's3') {
      payload.bucket = form.bucket
      payload.endpoint = form.endpoint
      payload.region = form.region || 'us-east-1'
      payload.access_key_id = form.access_key_id
      payload.secret_access_key = form.secret_access_key
      payload.session_token = form.session_token
      payload.custom_host = form.custom_host
      payload.force_path_style = form.force_path_style
      payload.sign_url_expire = form.sign_url_expire || 4
      payload.root_path = form.root_path || '/'
    } else if (d === 'sftp') {
      payload.address = form.address
      payload.username = form.username
      payload.password = form.password
      payload.private_key = form.private_key
      payload.passphrase = form.passphrase
      payload.root_path = form.root_path || '/'
      payload.ignore_symlink_error = form.ignore_symlink_error
    } else if (d === 'ftp') {
      payload.address = form.address
      payload.username = form.username
      payload.password = form.password
      payload.encoding = form.encoding
      payload.root_path = form.root_path || '/'
      payload.cwd_list = form.cwd_list
    } else if (d === 'smb') {
      payload.address = form.address
      payload.username = form.username
      payload.password = form.password
      payload.share_name = form.share_name
      payload.root_path = form.root_path
    }
    else if (d === 'alist_v3') {
      payload.url = form.url
      payload.username = form.username || undefined
      payload.password = form.password || undefined
      payload.token = form.token || undefined
      payload.meta_password = form.meta_password || undefined
    } else if (d === 'github_releases') {
      payload.repo_structure = form.repo_structure
      payload.token = form.token || undefined
      payload.show_all_version = form.show_all_version
      payload.show_source_code = form.show_source_code
      payload.gh_proxy = form.gh_proxy || undefined
      payload.per_page = form.per_page
      payload.max_page = form.max_page
    }
    else if (d === 'pikpak') {
      payload.username = form.username
      payload.password = form.password
      payload.refresh_token = form.refresh_token || undefined
      payload.device_id = form.device_id || undefined
    } else if (d === 'onedrive_share') {
      payload.url = form.url
      payload.password = form.password || undefined
    } else if (d === 'pikpak_share') {
      payload.share_id = form.share_id
      payload.share_pwd = form.share_pwd || undefined
      payload.platform = form.platform || 'web'
      payload.device_id = form.device_id || undefined
      payload.use_transcoding_address = form.use_transcoding_address || false
    } else if (d === 'onedrive_app') {
      payload.region = form.region || 'global'
      payload.client_id = form.client_id
      payload.client_secret = form.client_secret
      payload.tenant_id = form.tenant_id || undefined
      payload.email = form.email
      payload.custom_host = form.custom_host || undefined
      payload.root_path = form.root_path || '/'
    } else if (d === 'dropbox') {
      payload.refresh_token = form.refresh_token
      payload.use_online_api = form.use_online_api
      payload.client_id = form.client_id || undefined
      payload.client_secret = form.client_secret || undefined
      payload.root_path = form.root_path || undefined
    } else if (d === 'google_photo') {
      payload.refresh_token = form.refresh_token
      payload.client_id = form.client_id || undefined
      payload.client_secret = form.client_secret || undefined
    } else if (d === 'pan115_open') {
      payload.access_token = form.access_token || undefined
      payload.refresh_token = form.refresh_token || undefined
    } else if (d === 'pan115_share') {
      payload.share_code = form.share_code
      payload.receive_code = form.receive_code || undefined
      payload.cookie = form.cookie || undefined
    } else if (d === 'pan123_open') {
      payload.client_id = form.client_id || undefined
      payload.client_secret = form.client_secret || undefined
      payload.refresh_token = form.refresh_token || undefined
      payload.access_token = form.access_token || undefined
      payload.use_online_api = form.use_online_api
      payload.api_address = form.api_address || undefined
    } else if (d === 'pan123_link') {
      payload.origin_urls = form.origin_urls
      payload.private_key = form.private_key || undefined
      payload.uid = form.uid || undefined
    } else if (d === 'aliyundrive') {
      payload.refresh_token = form.refresh_token
    } else if (d === 'aliyundrive_share') {
      payload.refresh_token = form.refresh_token
      payload.share_id = form.share_id
      payload.share_pwd = form.share_pwd || undefined
    } else if (d === 'quark_open') {
      payload.refresh_token = form.refresh_token
      payload.app_id = form.app_id
      payload.sign_key = form.sign_key
      payload.use_online_api = form.use_online_api
      payload.api_address = form.api_address || undefined
    } else if (d === 'quark_tv' || d === 'uc_tv') {
      payload.refresh_token = form.refresh_token || undefined
      payload.device_id = form.device_id || undefined
      payload.link_method = form.link_method || undefined
    }
    else if (d === 'openlist') {
      payload.url = form.url
      payload.username = form.username || undefined
      payload.password = form.password || undefined
      payload.token = form.token || undefined
      payload.meta_password = form.meta_password || undefined
    } else if (d === 'openlist_share') {
      payload.url = form.url
      payload.share_id = form.share_id
      payload.share_pwd = form.share_pwd || undefined
    } else if (d === 'virtual') {
      payload.num_file = form.num_file ?? 5
      payload.num_folder = form.num_folder ?? 0
    } else if (d === 'bunny') {
      payload.bucket = form.bucket
      payload.endpoint = form.endpoint || undefined
      payload.region = form.region || 'us-east-1'
      payload.access_key_id = form.access_key_id
      payload.secret_access_key = form.secret_access_key
      payload.root_path = form.root_path || '/'
    } else if (d === 'yandex_disk') {
      payload.refresh_token = form.refresh_token
      payload.access_token = form.access_token || undefined
      payload.use_online_api = form.use_online_api
      payload.api_address = form.api_address || undefined
      payload.client_id = form.client_id || undefined
      payload.client_secret = form.client_secret || undefined
      payload.root_path = form.root_path || '/'
    } else if (d === 'seafile') {
      payload.address = form.address
      payload.username = form.username || undefined
      payload.password = form.password || undefined
      payload.token = form.token || undefined
      payload.repo_id = form.repo_id || undefined
      payload.repo_pwd = form.repo_pwd || undefined
      payload.root_path = form.root_path || '/'
    } else if (d === 'kodbox') {
      payload.address = form.address
      payload.username = form.username || undefined
      payload.password = form.password || undefined
      payload.root_path = form.root_path || undefined
    } else if (d === 'cloudreve_v4') {
      payload.address = form.address
      payload.username = form.username || undefined
      payload.password = form.password || undefined
      payload.access_token = form.access_token || undefined
      payload.refresh_token = form.refresh_token || undefined
      payload.root_path = form.root_path || '/'
    } else if (d === 'terabox') {
      payload.cookie = form.cookie
      payload.download_api = form.download_api || 'official'
      payload.root_path = form.root_path || '/'
    } else if (d === 'ilanzou') {
      payload.site = form.site || 'ilanzou'
      payload.username = form.username
      payload.password = form.password
      payload.root_folder_id = form.root_folder_id || '0'
    } else if (d === 'halalcloud_open') {
      // 只有 client_id / client_secret 是必填；令牌留空即个人 API 方式
      payload.client_id = form.client_id
      payload.client_secret = form.client_secret
      payload.access_token = form.access_token || undefined
      payload.refresh_token = form.refresh_token || undefined
      payload.host = form.host || undefined
      payload.timeout = form.timeout || undefined
      payload.root_path = form.root_path || '/'
    }

    await api('/api/accounts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    await loadAccounts()
  } catch (e) {
    accError.value = e.message
  } finally {
    adding.value = false
  }
}

async function editAccount(form) {
  accError.value = ''
  adding.value = true
  try {
    const payload = { name: form.name, driver: form.driver, server_proxy: form.server_proxy ?? false }
    const d = form.driver
    if (['quark', 'quark_uc', 'pan115'].includes(d)) payload.cookie = form.cookie
    else if (d === 'lanzou') {
      payload.cookie = form.cookie
      payload.username = form.username
      payload.password = form.password
    }
    else if (['123pan', 'thunder', 'cloud189'].includes(d)) {
      payload.username = form.username
      payload.password = form.password
    } else if (['aliyundrive_open', 'baidu_netdisk'].includes(d)) payload.refresh_token = form.refresh_token
    else if (d === 'pan139') payload.authorization = form.authorization
    else if (d === 'local') payload.root_path = form.root_path
    else if (d === 'webdav') {
      payload.url = form.url
      payload.username = form.username
      payload.password = form.password
      payload.root_path = form.root_path
    } else if (d === '123pan_share') {
      payload.share_key = form.share_key
      payload.share_pwd = form.share_pwd
      payload.access_token = form.access_token
    } else if (d === 'weiyun') payload.cookies = form.cookies
    else if (d === 'onedrive') {
      payload.refresh_token = form.refresh_token
      payload.region = form.region
      payload.is_sharepoint = form.is_sharepoint
      payload.site_id = form.site_id
      payload.root_path = form.root_path
    } else if (d === 'google_drive') {
      payload.refresh_token = form.refresh_token
      payload.root_folder_id = form.root_folder_id
    }

    else if (d === 's3') {
      payload.bucket = form.bucket
      payload.endpoint = form.endpoint
      payload.region = form.region || 'us-east-1'
      payload.access_key_id = form.access_key_id
      payload.secret_access_key = form.secret_access_key
      payload.session_token = form.session_token
      payload.custom_host = form.custom_host
      payload.force_path_style = form.force_path_style
      payload.sign_url_expire = form.sign_url_expire || 4
      payload.root_path = form.root_path || '/'
    } else if (d === 'sftp') {
      payload.address = form.address
      payload.username = form.username
      payload.password = form.password
      payload.private_key = form.private_key
      payload.passphrase = form.passphrase
      payload.root_path = form.root_path || '/'
      payload.ignore_symlink_error = form.ignore_symlink_error
    } else if (d === 'ftp') {
      payload.address = form.address
      payload.username = form.username
      payload.password = form.password
      payload.encoding = form.encoding
      payload.root_path = form.root_path || '/'
      payload.cwd_list = form.cwd_list
    } else if (d === 'smb') {
      payload.address = form.address
      payload.username = form.username
      payload.password = form.password
      payload.share_name = form.share_name
      payload.root_path = form.root_path
    }
    else if (d === 'alist_v3') {
      payload.url = form.url
      payload.username = form.username || undefined
      payload.password = form.password || undefined
      payload.token = form.token || undefined
      payload.meta_password = form.meta_password || undefined
    } else if (d === 'github_releases') {
      payload.repo_structure = form.repo_structure
      payload.token = form.token || undefined
      payload.show_all_version = form.show_all_version
      payload.show_source_code = form.show_source_code
      payload.gh_proxy = form.gh_proxy || undefined
      payload.per_page = form.per_page
      payload.max_page = form.max_page
    }
    else if (d === 'pikpak') {
      payload.username = form.username
      payload.password = form.password
      payload.refresh_token = form.refresh_token || undefined
      payload.device_id = form.device_id || undefined
    } else if (d === 'onedrive_share') {
      payload.url = form.url
      payload.password = form.password || undefined
    } else if (d === 'pikpak_share') {
      payload.share_id = form.share_id
      payload.share_pwd = form.share_pwd || undefined
      payload.platform = form.platform || 'web'
      payload.device_id = form.device_id || undefined
      payload.use_transcoding_address = form.use_transcoding_address || false
    } else if (d === 'onedrive_app') {
      payload.region = form.region || 'global'
      payload.client_id = form.client_id
      payload.client_secret = form.client_secret
      payload.tenant_id = form.tenant_id || undefined
      payload.email = form.email
      payload.custom_host = form.custom_host || undefined
      payload.root_path = form.root_path || '/'
    } else if (d === 'dropbox') {
      payload.refresh_token = form.refresh_token
      payload.use_online_api = form.use_online_api
      payload.client_id = form.client_id || undefined
      payload.client_secret = form.client_secret || undefined
      payload.root_path = form.root_path || undefined
    } else if (d === 'google_photo') {
      payload.refresh_token = form.refresh_token
      payload.client_id = form.client_id || undefined
      payload.client_secret = form.client_secret || undefined
    } else if (d === 'pan115_open') {
      payload.access_token = form.access_token || undefined
      payload.refresh_token = form.refresh_token || undefined
    } else if (d === 'pan115_share') {
      payload.share_code = form.share_code
      payload.receive_code = form.receive_code || undefined
      payload.cookie = form.cookie || undefined
    } else if (d === 'pan123_open') {
      payload.client_id = form.client_id || undefined
      payload.client_secret = form.client_secret || undefined
      payload.refresh_token = form.refresh_token || undefined
      payload.access_token = form.access_token || undefined
      payload.use_online_api = form.use_online_api
      payload.api_address = form.api_address || undefined
    } else if (d === 'pan123_link') {
      payload.origin_urls = form.origin_urls
      payload.private_key = form.private_key || undefined
      payload.uid = form.uid || undefined
    } else if (d === 'aliyundrive') {
      payload.refresh_token = form.refresh_token
    } else if (d === 'aliyundrive_share') {
      payload.refresh_token = form.refresh_token
      payload.share_id = form.share_id
      payload.share_pwd = form.share_pwd || undefined
    } else if (d === 'quark_open') {
      payload.refresh_token = form.refresh_token
      payload.app_id = form.app_id
      payload.sign_key = form.sign_key
      payload.use_online_api = form.use_online_api
      payload.api_address = form.api_address || undefined
    } else if (d === 'quark_tv' || d === 'uc_tv') {
      payload.refresh_token = form.refresh_token || undefined
      payload.device_id = form.device_id || undefined
      payload.link_method = form.link_method || undefined
    }
    else if (d === 'openlist') {
      payload.url = form.url
      payload.username = form.username || undefined
      payload.password = form.password || undefined
      payload.token = form.token || undefined
      payload.meta_password = form.meta_password || undefined
    } else if (d === 'openlist_share') {
      payload.url = form.url
      payload.share_id = form.share_id
      payload.share_pwd = form.share_pwd || undefined
    } else if (d === 'virtual') {
      payload.num_file = form.num_file ?? 5
      payload.num_folder = form.num_folder ?? 0
    } else if (d === 'bunny') {
      payload.bucket = form.bucket
      payload.endpoint = form.endpoint || undefined
      payload.region = form.region || 'us-east-1'
      payload.access_key_id = form.access_key_id
      payload.secret_access_key = form.secret_access_key
      payload.root_path = form.root_path || '/'
    } else if (d === 'yandex_disk') {
      payload.refresh_token = form.refresh_token
      payload.access_token = form.access_token || undefined
      payload.use_online_api = form.use_online_api
      payload.api_address = form.api_address || undefined
      payload.client_id = form.client_id || undefined
      payload.client_secret = form.client_secret || undefined
      payload.root_path = form.root_path || '/'
    } else if (d === 'seafile') {
      payload.address = form.address
      payload.username = form.username || undefined
      payload.password = form.password || undefined
      payload.token = form.token || undefined
      payload.repo_id = form.repo_id || undefined
      payload.repo_pwd = form.repo_pwd || undefined
      payload.root_path = form.root_path || '/'
    } else if (d === 'kodbox') {
      payload.address = form.address
      payload.username = form.username || undefined
      payload.password = form.password || undefined
      payload.root_path = form.root_path || undefined
    } else if (d === 'cloudreve_v4') {
      payload.address = form.address
      payload.username = form.username || undefined
      payload.password = form.password || undefined
      payload.access_token = form.access_token || undefined
      payload.refresh_token = form.refresh_token || undefined
      payload.root_path = form.root_path || '/'
    } else if (d === 'terabox') {
      payload.cookie = form.cookie
      payload.download_api = form.download_api || 'official'
      payload.root_path = form.root_path || '/'
    } else if (d === 'ilanzou') {
      payload.site = form.site || 'ilanzou'
      payload.username = form.username
      payload.password = form.password
      payload.root_folder_id = form.root_folder_id || '0'
    } else if (d === 'halalcloud_open') {
      // 只有 client_id / client_secret 是必填；令牌留空即个人 API 方式
      payload.client_id = form.client_id
      payload.client_secret = form.client_secret
      payload.access_token = form.access_token || undefined
      payload.refresh_token = form.refresh_token || undefined
      payload.host = form.host || undefined
      payload.timeout = form.timeout || undefined
      payload.root_path = form.root_path || '/'
    }

    await api(`/api/accounts/${form.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    await loadAccounts()
  } catch (e) {
    accError.value = e.message
  } finally {
    adding.value = false
  }
}

async function toggleEnabled(a) {
  const newVal = !a.enabled
  try {
    await api(`/api/accounts/${a.id}/enabled`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: newVal })
    })
    // 乐观更新本地列表，避免重新拉取整个列表
    const acc = accounts.value.find((x) => x.id === a.id)
    if (acc) acc.enabled = newVal
    // 若禁用了当前正在浏览的账号，退回首页
    if (!newVal && currentId.value === a.id) {
      currentId.value = ''
      entries.value = []
      crumbs.value = [{ fid: '0', name: '网盘' }]
    }
  } catch (e) {
    accError.value = e.message
  }
}

async function delAccount(a) {
  if (!confirm(`删除存储「${a.name}」？`)) return
  await api(`/api/accounts/${a.id}`, { method: 'DELETE' })
  if (currentId.value === a.id) {
    currentId.value = ''
    entries.value = []
    crumbs.value = [{ fid: '0', name: '根目录' }]
  }
  await loadAccounts()
}

function onSwitchAccount(id) {
  view.value = 'files'
  currentId.value = id
  const acc = accounts.value.find((a) => a.id === id)
  crumbs.value = [{ fid: '0', name: acc?.name || '根目录' }]
  listFiles('0')
}

// 返回网盘列表首页：不自动加载任何网盘的内容
function goHome() {
  preview.value = null
  view.value = 'files'
  currentId.value = ''
  entries.value = []
  crumbs.value = [{ fid: '0', name: '网盘' }]
}

// 刷新：强制向网盘重新拉取当前目录（跳过服务端缓存），刷新按钮转圈反馈
async function refreshCurrent() {
  if (!currentId.value) {
    await loadAccounts()
    return
  }
  if (refreshing.value) return
  refreshing.value = true
  try {
    await listFiles(crumbs.value[crumbs.value.length - 1].fid, true)
  } finally {
    refreshing.value = false
  }
}

// refresh=true 时请求跳过服务端缓存；此时不清空旧列表、不显示整页 loading，
// 由刷新按钮转圈反馈，失败时保留旧数据只提示错误
async function listFiles(fid, refresh = false) {
  if (!currentId.value) return
  if (!refresh) loading.value = true
  err.value = ''
  try {
    const b = await api(
      `/api/files?account=${encodeURIComponent(currentId.value)}&fid=${encodeURIComponent(fid)}${refresh ? '&refresh=true' : ''}`
    )
    entries.value = b.entries || []
  } catch (e) {
    err.value = e.message
    if (!refresh) entries.value = []
  } finally {
    loading.value = false
  }
}

function openDir(e) {
  crumbs.value.push({ fid: e.fid, name: e.name })
  listFiles(e.fid)
}

function goto(i) {
  preview.value = null
  crumbs.value = crumbs.value.slice(0, i + 1)
  listFiles(crumbs.value[i].fid)
}

function fileQuery(e, disp) {
  const p = new URLSearchParams({ account: currentId.value, fid: e.fid })
  if (e.name) p.set('name', e.name)
  if (e.size) p.set('size', e.size)
  if (e.etag) p.set('etag', e.etag)
  if (e.s3_key_flag) p.set('s3key', e.s3_key_flag)
  if (e.file_type != null) p.set('ftype', e.file_type)
  if (e.extra) p.set('extra', JSON.stringify(e.extra))
  if (disp) p.set('disp', disp)
  return p.toString()
}

// 取真实预览/下载地址：由后端根据账号 server_proxy 开关决定
// 返回网盘直链（开关关闭）还是本服务 /api/stream 中转地址（开关开启）
// forceProxy：预览时强制中转（直链上游常是 octet-stream + nosniff，浏览器播不了）
async function resolveUrl(e, forceProxy = false) {
  const b = await api(`/api/download?${fileQuery(e)}${forceProxy ? '&proxy=true' : ''}`)
  return b.url
}

function download(e) {
  // 上游 CDN（ipfs-gateway.qzy.xyz）有防盗链：请求带外部 Referer/Origin 一律 403，
  // 而 window.open 必然带上面板的地址 → 浏览器里下载下来是空白文件（命令行不带 Referer 所以测不出来）。
  // 用 <a rel="noreferrer" referrerpolicy="no-referrer"> 打开即可，浏览器不再发送 Referer，直链照旧可下。
  resolveUrl(e)
    .then((url) => {
      const a = document.createElement('a')
      a.href = url
      a.target = '_blank'
      a.rel = 'noreferrer'
      a.referrerPolicy = 'no-referrer'
      document.body.appendChild(a)
      a.click()
      a.remove()
    })
    .catch((ex) => {
      err.value = ex.message || '获取下载地址失败'
    })
}

async function handlePreview(e) {
  try {
    const url = await resolveUrl(e, true)
    preview.value = { ...e, _url: url, _kind: kindOf(e.name, e.is_dir) }
  } catch (ex) {
    err.value = ex.message || '获取预览地址失败'
  }
}

function closePreview() {
  preview.value = null
}

// ============================================================
// 文件写操作（走 OpenList 兼容层 /api/fs/*，path = /账号名/目录/...）
// ============================================================

// 当前账号是否可写（只读驱动隐藏写操作入口）
const canWrite = computed(() => {
  if (!currentId.value) return false
  const acc = accounts.value.find((a) => a.id === currentId.value)
  const READ_ONLY_DRIVERS = ['123pan_share', 'pan115_share', 'aliyundrive_share', 'pan123_link', 'pikpak_share', 'onedrive_share']
  return !!acc && !READ_ONLY_DRIVERS.includes(acc.driver)
})

// 当前目录的虚拟路径：第一段为账号名（crumbs[0].name 即账号名）
function currentPath() {
  return '/' + crumbs.value.map((c) => c.name).join('/')
}

function entryPath(e) {
  return `${currentPath().replace(/\/$/, '')}/${e.name}`
}

function fsErr(e) {
  err.value = e.message || String(e)
}

async function fsMkdir() {
  const name = prompt('新建文件夹名称：')
  if (!name?.trim()) return
  try {
    await api('/api/fs/mkdir', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: `${currentPath()}/${name.trim()}` })
    })
    await listFiles(crumbs.value[crumbs.value.length - 1].fid, true)
  } catch (e) {
    fsErr(e)
  }
}

async function fsRename(e) {
  const name = prompt('重命名为：', e.name)
  if (!name?.trim() || name.trim() === e.name) return
  try {
    await api('/api/fs/rename', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: entryPath(e), name: name.trim() })
    })
    await listFiles(crumbs.value[crumbs.value.length - 1].fid, true)
  } catch (ex) {
    fsErr(ex)
  }
}

async function fsRemove(e) {
  if (!confirm(`确认删除「${e.name}」？${e.is_dir ? '文件夹内的全部内容将一并删除，' : ''}此操作不可恢复！`)) return
  try {
    await api('/api/fs/remove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dir: currentPath(), names: [e.name] })
    })
    await listFiles(crumbs.value[crumbs.value.length - 1].fid, true)
  } catch (ex) {
    fsErr(ex)
  }
}

// ----- 目标目录选择弹窗（移动/复制共用） -----
const picker = ref({ open: false, mode: 'move', crumbs: [], dirs: [], loading: false, busy: false, entry: null })

function fsMove(e) {
  picker.value = { open: true, mode: 'move', crumbs: [{ fid: '0', name: accounts.value.find((a) => a.id === currentId.value)?.name || '' }], dirs: [], loading: false, busy: false, entry: e }
  pickerLoad('0')
}

function fsCopy(e) {
  picker.value = { open: true, mode: 'copy', crumbs: [{ fid: '0', name: accounts.value.find((a) => a.id === currentId.value)?.name || '' }], dirs: [], loading: false, busy: false, entry: e }
  pickerLoad('0')
}

async function pickerLoad(fid) {
  picker.value.loading = true
  try {
    const b = await api(`/api/files?account=${encodeURIComponent(currentId.value)}&fid=${encodeURIComponent(fid)}`)
    picker.value.dirs = (b.entries || []).filter((x) => x.is_dir)
  } catch (e) {
    picker.value.dirs = []
    fsErr(e)
  } finally {
    picker.value.loading = false
  }
}

function pickerEnter(d) {
  picker.value.crumbs.push({ fid: d.fid, name: d.name })
  pickerLoad(d.fid)
}

function pickerGoto(i) {
  picker.value.crumbs = picker.value.crumbs.slice(0, i + 1)
  pickerLoad(picker.value.crumbs[i].fid)
}

async function pickerConfirm() {
  const p = picker.value
  if (p.busy) return
  const dst = '/' + p.crumbs.map((c) => c.name).join('/')
  const endpoint = p.mode === 'move' ? '/api/fs/move' : '/api/fs/copy'
  p.busy = true
  try {
    await api(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ src_dir: currentPath(), dst_dir: dst, names: [p.entry.name] })
    })
    p.open = false
    await listFiles(crumbs.value[crumbs.value.length - 1].fid, true)
  } catch (e) {
    fsErr(e)
  } finally {
    p.busy = false
  }
}

// ----- 上传（浏览器 -> /api/fs/form，XHR 自带进度） -----
const uploads = ref([])

function fmtSize(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

function uploadPct(t) {
  if (t.status === 'done') return 100
  if (!t.size) return t.status === 'uploading' ? 5 : 100
  return Math.min(99, Math.round((t.loaded / t.size) * 100))
}

function clearFinishedUploads() {
  uploads.value = uploads.value.filter((t) => t.status === 'uploading')
}

// 文件夹上传：相对路径里的中间目录需要先逐级创建（网盘 API 不支持自动建目录）
async function ensureDirs(relPath) {
  const segs = relPath.split('/').filter(Boolean)
  segs.pop() // 最后一段是文件名
  let cur = currentPath()
  for (const seg of segs) {
    cur = `${cur}/${seg}`
    await api('/api/fs/mkdir', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: cur })
    }).catch(() => {}) // 已存在会报错，忽略继续
  }
}

function xhrUpload(item, fullPath) {
  return new Promise((resolve) => {
    const form = new FormData()
    form.append('file', item.file)
    const xhr = new XMLHttpRequest()
    xhr.open('POST', '/api/fs/form')
    // 后端按 Go url.PathUnescape 语义解码 %XX（含 %2F 回 '/'）
    xhr.setRequestHeader('File-Path', encodeURIComponent(fullPath))
    xhr.setRequestHeader('X-File-Size', String(item.file.size))
    xhr.upload.onprogress = (ev) => {
      if (ev.lengthComputable) item.loaded = ev.loaded
    }
    xhr.onload = () => {
      try {
        const body = JSON.parse(xhr.responseText || '{}')
        if (xhr.status === 200 && (!body.code || body.code === 200)) resolve()
        else reject(new Error(body.message || `HTTP ${xhr.status}`))
      } catch {
        reject(new Error(`HTTP ${xhr.status}`))
      }
    }
    xhr.onerror = () => reject(new Error('网络错误'))
    xhr.send(form)
  })
}

async function fsUpload(items) {
  for (const it of items) {
    const task = reactive({ relPath: it.relPath, size: it.file.size, loaded: 0, status: 'uploading', error: '', file: it.file })
    uploads.value.push(task)
    try {
      await ensureDirs(it.relPath)
      const fullPath = `${currentPath().replace(/\/$/, '')}/${it.relPath}`
      await xhrUpload(task, fullPath)
      task.status = 'done'
      task.loaded = task.size
    } catch (e) {
      task.status = 'error'
      task.error = e.message || String(e)
    }
  }
  // 全部结束后刷新当前目录
  if (crumbs.value.length) await listFiles(crumbs.value[crumbs.value.length - 1].fid, true)
}

onMounted(async () => {
  const saved = localStorage.getItem('ol-theme')
  isDark.value = saved
    ? saved === 'dark'
    : window.matchMedia?.('(prefers-color-scheme: dark)').matches
  applyTheme()

  await checkAuth()
  try {
    await loadAccounts()
  } catch {
    /* 401 时已弹出登录 */
  }
})
</script>

<style scoped>
.app-shell {
  min-height: 100vh;
}

.app-header {
  position: sticky;
  top: 0;
  z-index: 50;
  background: var(--ol-panel);
  border-bottom: 1px solid var(--ol-border);
}
.header-inner {
  max-width: 1180px;
  margin: 0 auto;
  padding: 0 20px;
  height: var(--ol-header-h);
  display: flex;
  align-items: center;
  gap: 28px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 9px;
  cursor: pointer;
  user-select: none;
  flex-shrink: 0;
}
.brand-logo {
  --ol-logo-hole: var(--ol-panel);
}
.brand-name {
  font-size: 17px;
  font-weight: 700;
  letter-spacing: 0.2px;
  white-space: nowrap;
}

.app-nav {
  display: flex;
  gap: 4px;
  height: 100%;
  overflow-x: auto;
  scrollbar-width: none;
}
.app-nav::-webkit-scrollbar {
  display: none;
}
.nav-btn {
  height: 100%;
  padding: 0 4px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--ol-text-dim);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  margin: 0 12px;
  white-space: nowrap;
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.nav-btn:hover {
  color: var(--ol-text);
}
.nav-btn.active {
  color: var(--ol-primary);
  border-bottom-color: var(--ol-primary);
}

.header-actions {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}

@media (max-width: 560px) {
  .header-inner {
    gap: 14px;
    padding: 0 12px;
  }
  .brand-name {
    display: none;
  }
  .nav-btn {
    margin: 0 8px;
    font-size: 13px;
  }
}

/* 目标目录选择弹窗 */
.picker-mask {
  position: fixed;
  inset: 0;
  z-index: 100;
  background: rgba(0, 0, 0, 0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.picker {
  width: min(420px, 100%);
  max-height: 70vh;
  display: flex;
  flex-direction: column;
  padding: 0;
  overflow: hidden;
}
.picker-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  font-weight: 600;
  border-bottom: 1px solid var(--ol-border);
}
.picker-crumbs {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  padding: 10px 16px;
  border-bottom: 1px solid var(--ol-border);
  font-size: 13px;
}
.picker-crumbs .crumb-link {
  color: var(--ol-primary);
}
.picker-crumbs .crumb-link + .crumb-link::before {
  content: '/';
  color: var(--ol-text-faint);
  margin-right: 6px;
}
.picker-body {
  flex: 1;
  overflow: auto;
  padding: 6px;
}
.picker-state {
  padding: 30px 0;
  text-align: center;
  color: var(--ol-text-dim);
  font-size: 13px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
}
.picker-item {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 9px 10px;
  border: none;
  background: transparent;
  border-radius: 8px;
  color: var(--ol-text);
  font-size: 13.5px;
  cursor: pointer;
  text-align: left;
}
.picker-item:hover {
  background: var(--ol-primary-light);
  color: var(--ol-primary);
}
.picker-foot {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding: 12px 16px;
  border-top: 1px solid var(--ol-border);
}
.loader-sm {
  width: 18px;
  height: 18px;
  border: 2px solid var(--ol-border-strong);
  border-top-color: var(--ol-primary);
  border-radius: 50%;
}
.spin {
  display: inline-block;
  animation: spin-rot 0.8s linear infinite;
}
@keyframes spin-rot {
  to {
    transform: rotate(360deg);
  }
}

/* 页脚（对齐官方 Footer） */
.app-footer {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 8px;
  padding: 18px 0 26px;
  font-size: 13px;
  color: var(--ol-text-dim);
}
.app-footer a {
  color: var(--ol-text-dim);
}
.app-footer a:hover {
  color: var(--ol-primary);
  text-decoration: none;
}

/* 上传任务面板 */
.upload-panel {
  position: fixed;
  right: 28px;
  bottom: 96px;
  z-index: 90;
  width: min(340px, calc(100vw - 40px));
  max-height: 40vh;
  overflow: auto;
  padding: 10px 12px;
}
.upload-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-weight: 600;
  font-size: 13.5px;
  margin-bottom: 6px;
}
.upload-item {
  padding: 6px 0;
  border-bottom: 1px solid var(--ol-border);
}
.upload-item:last-child {
  border-bottom: none;
}
.upload-name {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12.5px;
  color: var(--ol-text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.upload-bar {
  height: 4px;
  margin: 5px 0 4px;
  background: var(--ol-bg);
  border-radius: 999px;
  overflow: hidden;
}
.upload-bar-fill {
  height: 100%;
  background: var(--ol-primary);
  border-radius: 999px;
  transition: width 0.2s ease;
}
.upload-bar-fill.done {
  background: #2fa96c;
}
.upload-bar-fill.fail {
  background: #e5484d;
}
.upload-meta {
  font-size: 11px;
  color: var(--ol-text-dim);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
