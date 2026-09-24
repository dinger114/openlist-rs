<template>
  <div class="page">
    <div v-if="accounts.length === 0" class="empty-state card">
      <Icon name="inbox" :size="40" />
      <p>还没有存储，先去 <a href="#" @click.prevent="$emit('go-accounts')">存储管理</a> 添加一个云盘账号</p>
    </div>

    <template v-else>
      <!-- 面包屑（对齐官方 Nav：🏠 首页 / xx / xx）+ 布局切换（对齐官方 header Layout） -->
      <div class="crumbs-row">
        <nav class="crumbs">
          <a href="#" class="crumb-link crumb-home" title="返回首页" @click.prevent="$emit('go-home')">
            🏠 首页
          </a>
          <template v-if="currentId">
            <template v-for="(c, i) in crumbs" :key="c.fid + i">
              <span class="crumb-sep">/</span>
              <a
                v-if="preview || i !== crumbs.length - 1"
                href="#"
                class="crumb-link"
                @click.prevent="$emit('goto', i)"
                >{{ c.name }}</a
              >
              <span v-else class="crumb-link crumb-current">{{ c.name }}</span>
            </template>
            <template v-if="preview">
              <span class="crumb-sep">/</span>
              <span class="crumb-link crumb-current">{{ preview.name }}</span>
            </template>
          </template>
        </nav>
        <div v-if="!preview" class="view-toggle" role="group" aria-label="视图切换">
          <button
            :class="{ active: viewMode === 'list' }"
            :title="viewMode === 'list' ? '切换为宫格' : '列表'"
            @click="$emit('update:view-mode', viewMode === 'list' ? 'grid' : 'list')"
          >
            <Icon :name="viewMode === 'list' ? 'grid' : 'list'" :size="16" />
          </button>
        </div>
      </div>

      <div v-if="err" class="alert alert-error">{{ err }}</div>

      <!-- 预览页（对齐官方 File 页：文件名行 + obj-box 卡片） -->
      <template v-if="preview">
        <div class="file-line">
          <span class="file-line-name" :title="preview.name">{{ preview.name }}</span>
          <span v-if="navList.length > 1" class="player-pos">{{ navIndex + 1 }} / {{ navList.length }}</span>
          <span class="file-line-ops">
            <button
              class="op-icon"
              :disabled="navIndex <= 0"
              title="上一个（←）"
              @click="nav(-1)"
            >
              <Icon name="chevron-left" :size="15" />
            </button>
            <button
              class="op-icon"
              :disabled="navIndex >= navList.length - 1"
              title="下一个（→）"
              @click="nav(1)"
            >
              <Icon name="chevron-right" :size="15" />
            </button>
            <button class="op-icon" title="下载" @click="$emit('download', preview)">
              <Icon name="download" :size="15" />
            </button>
            <button class="op-icon" title="关闭（Esc）" @click="$emit('close-preview')">
              <Icon name="close" :size="15" />
            </button>
          </span>
        </div>

        <div class="obj-box">
          <!-- 视频 -->
          <div v-if="preview._kind === 'video'" class="video-stage">
            <video
              ref="videoEl"
              :src="preview._url"
              controls
              autoplay
              playsinline
              class="player-video"
              @ended="onVideoEnded"
            ></video>
          </div>

          <!-- 音乐 -->
          <div v-else-if="preview._kind === 'audio'" class="audio-stage">
            <div class="disc" :class="{ spinning: audioPlaying }">
              <Icon name="music" :size="44" />
            </div>
            <audio
              :src="preview._url"
              controls
              autoplay
              class="audio-player"
              @play="audioPlaying = true"
              @pause="audioPlaying = false"
              @ended="audioPlaying = false"
            ></audio>
          </div>

          <!-- 图片 -->
          <div v-else-if="preview._kind === 'image'" class="image-stage">
            <img :src="preview._url" :alt="preview.name" class="image-view" />
          </div>

          <!-- PDF -->
          <iframe
            v-else-if="preview._kind === 'pdf'"
            :src="preview._url"
            class="pdf-frame"
            title="PDF 预览"
          ></iframe>

          <!-- 文本 / Markdown / 代码等 -->
          <div v-else-if="preview._kind === 'text'" class="text-stage">
            <div v-if="textLoading" class="state-box">
              <span class="spin loader-lg"></span>
              <span>加载中…</span>
            </div>
            <div v-else-if="textError" class="state-box">
              <Icon name="alert" :size="30" />
              <span>{{ textError }}</span>
              <a :href="preview._url" target="_blank" class="btn btn-secondary" rel="noopener">在新窗口打开</a>
            </div>
            <div v-else class="text-editor">
              <div class="text-gutter" aria-hidden="true">
                <span v-for="n in textLineCount" :key="n">{{ n }}</span>
              </div>
              <pre class="text-view">{{ textContent }}</pre>
            </div>
          </div>
        </div>

        <!-- 视频页脚（对齐官方 VideoBox：文件名 select + 自动下一页 + 播放器图标行） -->
        <template v-if="preview._kind === 'video' || preview._kind === 'audio'">
          <div class="video-foot">
            <select class="input video-select" :value="preview.name" @change="onVideoPick">
              <option v-for="v in navList" :key="v.fid" :value="v.name">{{ v.name }}</option>
            </select>
            <label class="auto-next">
              <span
                class="toggle"
                :class="{ on: autoNext }"
                role="switch"
                :aria-checked="autoNext"
                @click="autoNext = !autoNext"
              >
                <span class="toggle-thumb"></span>
              </span>
              <span>自动下一页</span>
            </label>
          </div>

          <div class="player-exts">
            <button
              v-for="p in shownPlayers"
              :key="p.name"
              class="ext-btn"
              :title="p.name"
              @click="openExternal(p)"
            >
              <img :src="`/images/${p.img}.png`" :alt="p.name" />
            </button>
            <button class="ext-more" :title="showAll ? '收起' : '显示全部'" @click="toggleShowAll">
              <Icon name="arrow-right" :size="17" :class="{ 'flip-x': showAll }" />
            </button>
          </div>
        </template>
      </template>

      <template v-else>
        <!-- 加载中（进入网盘后） -->
        <div v-if="currentId && loading" class="obj-box state-box">
          <span class="spin loader-lg"></span>
          <span>加载中…</span>
        </div>

        <!-- 空目录 -->
        <div v-else-if="currentId && entries.length === 0" class="obj-box state-box">
          <Icon name="inbox" :size="34" />
          <span>此文件夹为空</span>
        </div>

        <!-- 列表视图（对齐官方 List：标题行 + 圆角行，无表格线） -->
        <div v-else-if="viewMode === 'list'" class="obj-box">
          <div class="list-title">
            <span class="lt-name">名称</span>
            <span class="lt-size">大小</span>
            <span class="lt-date">修改时间</span>
            <span class="lt-op"></span>
          </div>

          <!-- 桌面端 -->
          <div class="list-body desktop-list">
            <div
              v-for="e in displayEntries"
              :key="e.key"
              class="list-item"
              @click="rowActivate(e)"
            >
              <span class="li-name">
                <span class="ficon">
                  <FileIcon :name="e.name" :is-dir="e.is_dir" />
                </span>
                <span class="fname-text">{{ e.name }}</span>
              </span>
              <span class="li-size">{{ e.is_dir || e.is_drive ? '-' : fmtSize(e.size) }}</span>
              <span class="li-date">{{ e.updated_at ? fmtDate(e.updated_at) : '-' }}</span>
              <span class="li-op">
                <template v-if="!e.is_drive">
                  <button
                    v-if="kindOf(e.name, e.is_dir)"
                    class="op-icon"
                    :title="KIND_TITLE[kindOf(e.name, e.is_dir)]"
                    @click.stop="$emit('preview', e)"
                  >
                    <Icon :name="KIND_ICON[kindOf(e.name, e.is_dir)]" :size="14" />
                  </button>
                  <button v-if="!e.is_dir" class="op-icon" title="下载" @click.stop="$emit('download', e)">
                    <Icon name="download" :size="14" />
                  </button>
                  <template v-if="canWrite">
                    <button class="op-icon" title="重命名" @click.stop="$emit('rename', e)">
                      <Icon name="edit" :size="14" />
                    </button>
                    <button class="op-icon" title="移动到…" @click.stop="$emit('move', e)">
                      <Icon name="move" :size="14" />
                    </button>
                    <button v-if="!e.is_dir" class="op-icon" title="复制到…" @click.stop="$emit('copy', e)">
                      <Icon name="copy" :size="14" />
                    </button>
                    <button class="op-icon op-del" title="删除" @click.stop="$emit('remove', e)">
                      <Icon name="trash" :size="14" />
                    </button>
                  </template>
                </template>
              </span>
            </div>
          </div>

          <!-- 移动端：卡片式列表 -->
          <ul class="list-body mobile-list">
            <li
              v-for="e in displayEntries"
              :key="e.key"
              class="list-item mobile-item"
              @click="e.is_drive ? $emit('open-account', e.id) : rowActivate(e)"
            >
              <div class="mobile-row-info">
                <span class="ficon">
                  <FileIcon :name="e.name" :is-dir="e.is_dir" />
                </span>
                <span class="fname-text">{{ e.name }}</span>
              </div>
              <div class="mobile-meta">
                <span>{{ e.is_dir || e.is_drive ? '-' : fmtSize(e.size) }}</span>
                <span v-if="e.updated_at" class="mobile-date">{{ fmtDate(e.updated_at) }}</span>
              </div>
              <div v-if="!e.is_drive" class="mobile-row-ops">
                <button
                  v-if="kindOf(e.name, e.is_dir)"
                  class="op-icon"
                  :title="KIND_TITLE[kindOf(e.name, e.is_dir)]"
                  @click.stop="$emit('preview', e)"
                >
                  <Icon :name="KIND_ICON[kindOf(e.name, e.is_dir)]" :size="14" />
                </button>
                <button v-if="!e.is_dir" class="op-icon" title="下载" @click.stop="$emit('download', e)">
                  <Icon name="download" :size="14" />
                </button>
                <template v-if="canWrite">
                  <button class="op-icon" title="重命名" @click.stop="$emit('rename', e)">
                    <Icon name="edit" :size="14" />
                  </button>
                  <button class="op-icon" title="移动到…" @click.stop="$emit('move', e)">
                    <Icon name="move" :size="14" />
                  </button>
                  <button v-if="!e.is_dir" class="op-icon" title="复制到…" @click.stop="$emit('copy', e)">
                    <Icon name="copy" :size="14" />
                  </button>
                  <button class="op-icon op-del" title="删除" @click.stop="$emit('remove', e)">
                    <Icon name="trash" :size="14" />
                  </button>
                </template>
              </div>
            </li>
          </ul>
        </div>

        <!-- 宫格视图（对齐官方 Grid：大图标居中 + 悬停放大） -->
        <div v-else class="obj-box">
          <div class="grid-view">
            <div
              v-for="e in displayEntries"
              :key="e.key"
              class="grid-item"
              @click="gridActivate(e)"
            >
              <div class="grid-icon">
                <FileIcon :name="e.name" :is-dir="e.is_dir" />
              </div>
              <div class="grid-name" :title="e.name">{{ e.name }}</div>
              <div class="grid-hover-actions" v-if="!e.is_drive">
                <button
                  v-if="!e.is_dir && kindOf(e.name, e.is_dir)"
                  class="op-icon"
                  :title="KIND_TITLE[kindOf(e.name, e.is_dir)]"
                  @click.stop="$emit('preview', e)"
                >
                  <Icon :name="KIND_ICON[kindOf(e.name, e.is_dir)]" :size="13" />
                </button>
                <button v-if="!e.is_dir" class="op-icon" title="下载" @click.stop="$emit('download', e)">
                  <Icon name="download" :size="13" />
                </button>
                <template v-if="canWrite">
                  <button class="op-icon" title="删除" @click.stop="$emit('remove', e)">
                    <Icon name="trash" :size="13" />
                  </button>
                </template>
              </div>
            </div>
          </div>
        </div>
      </template>

      <!-- 右下角悬浮操作按钮（对齐官方 Right 工具栏：⋯ 展开 + 图标列） -->
      <div v-if="currentId && !preview" class="fab-wrap">
        <transition name="fab-pop">
          <div v-if="fabOpen" class="fab-menu">
            <button class="fab-item" :disabled="refreshing" title="刷新" @click="fabAct('refresh')">
              <Icon name="refresh" :size="17" :class="{ spinning: refreshing }" />
            </button>
            <button class="fab-item" title="新建文件夹" @click="fabAct('mkdir')">
              <Icon name="folder-plus" :size="17" />
            </button>
            <button class="fab-item" title="上传文件" @click="fabAct('upload')">
              <Icon name="upload" :size="17" />
            </button>
            <button class="fab-item" title="上传文件夹" @click="fabAct('upload-folder')">
              <Icon name="upload" :size="17" />
            </button>
          </div>
        </transition>
        <button class="fab" :class="{ open: fabOpen }" title="操作" @click="fabOpen = !fabOpen">
          <Icon name="more" :size="22" />
        </button>
      </div>

      <!-- 隐藏的文件选择器 -->
      <input ref="fileInput" type="file" multiple hidden @change="onFilesPicked" />
      <input
        ref="folderInput"
        type="file"
        multiple
        hidden
        webkitdirectory
        directory
        @change="onFilesPicked"
      />
    </template>
  </div>
</template>

<script setup>
import { computed, ref, watch, onMounted, onBeforeUnmount } from 'vue'
import Icon from './Icon.vue'
import FileIcon from './FileIcon.vue'
import { kindOf, KIND_ICON, KIND_TITLE, TEXT_PREVIEW_MAX } from '../filekinds.js'

const props = defineProps({
  accounts: { type: Array, required: true },
  currentId: { type: String, required: true },
  crumbs: { type: Array, required: true },
  entries: { type: Array, required: true },
  preview: { type: Object, default: null },
  loading: { type: Boolean, default: false },
  refreshing: { type: Boolean, default: false },
  err: { type: String, default: '' },
  viewMode: { type: String, default: 'list' },
  driverLabels: { type: Object, default: () => ({}) },
  // 当前账号是否可写（123 分享等只读驱动隐藏写操作）
  canWrite: { type: Boolean, default: false }
})
const emit = defineEmits([
  'go-accounts', 'go-home', 'open-account', 'switch-account', 'goto', 'refresh', 'update:view-mode',
  'open-dir', 'preview', 'close-preview', 'download',
  'mkdir', 'rename', 'move', 'copy', 'remove', 'upload'
])

// 统一数据源：根目录（未选网盘）时把网盘映射为“文件夹”行，进入网盘后为文件条目
const displayEntries = computed(() => {
  if (props.currentId) {
    return props.entries.map((e) => ({ ...e, key: e.fid }))
  }
  return props.accounts
    .filter((a) => a.enabled !== false)
    .map((a) => ({
      key: 'drive-' + a.id,
      id: a.id,
      name: a.name,
      is_dir: true,
      is_drive: true,
      driver: a.driver,
      size: null,
      updated_at: null
    }))
})

// ===== 外部播放器（对齐官方 video_box.tsx players 列表，图标来自官方 images） =====
const PLAYERS = [
  { name: 'IINA', img: 'iina', scheme: 'iina://weblink?url=$edurl' },
  { name: 'PotPlayer', img: 'potplayer', scheme: 'potplayer://$durl' },
  { name: 'VLC', img: 'vlc', scheme: 'vlc://$durl' },
  { name: 'Android', img: 'android', scheme: 'intent:$durl#Intent;type=video/*;S.title=$name;end' },
  { name: 'nPlayer', img: 'nplayer', scheme: 'nplayer-$durl' },
  { name: 'OmniPlayer', img: 'omniplayer', scheme: 'omniplayer://weblink?url=$durl' },
  { name: 'Fig Player', img: 'figplayer', scheme: 'figplayer://weblink?url=$durl' },
  { name: 'Infuse', img: 'infuse', scheme: 'infuse://x-callback-url/play?url=$edurl' },
  { name: 'Fileball', img: 'fileball', scheme: 'filebox://play?url=$durl' },
  { name: 'MX Player', img: 'mxplayer', scheme: 'intent:$durl#Intent;package=com.mxtech.videoplayer.ad;S.title=$name;end' },
  { name: 'MX Player Pro', img: 'mxplayer-pro', scheme: 'intent:$durl#Intent;package=com.mxtech.videoplayer.pro;S.title=$name;end' },
  { name: 'iPlay', img: 'iPlay', scheme: 'iplay://play/any?type=url&url=$bdurl' },
  { name: 'mpv', img: 'mpv', scheme: 'mpv://$edurl' }
]

// 默认只显示常用几个，点箭头展开全部（对齐官方 showAllPlayers）
const BASE_PLAYERS = ['iina', 'potplayer', 'vlc', 'android', 'nplayer', 'infuse', 'mpv']
const showAll = ref(localStorage.getItem('video_show_all_players') === 'true')
const shownPlayers = computed(() =>
  showAll.value ? PLAYERS : PLAYERS.filter((p) => BASE_PLAYERS.includes(p.img))
)
function toggleShowAll() {
  showAll.value = !showAll.value
  localStorage.setItem('video_show_all_players', String(showAll.value))
}

// 占位符语义与官方 convertURL 一致：$name、$url/$eurl/$burl（原始直链）、$durl/$edurl/$bdurl（下载链接）
function applyMods(ops, u) {
  let s = u
  if (ops) {
    for (const o of [...ops].reverse()) {
      if (o === 'e') s = encodeURIComponent(s)
      else if (o === 'b') s = window.btoa(s)
    }
  }
  return s
}

function absoluteUrl() {
  try {
    return new URL(props.preview._url, window.location.href).href
  } catch {
    return props.preview._url
  }
}

function openExternal(p) {
  const durl = absoluteUrl()
  const name = props.preview.name
  const url = p.scheme
    .replace('$name', name)
    .replace(/\$[eb_]*durl/g, (m) => applyMods(m.slice(1).replace('durl', ''), durl))
    .replace(/\$[eb_]*url/g, (m) => applyMods(m.slice(1).replace('url', ''), durl))
  window.location.href = url
}

function rowActivate(e) {
  if (e.is_drive) emit('open-account', e.id)
  else if (e.is_dir) emit('open-dir', e)
  else if (kindOf(e.name, e.is_dir)) emit('preview', e)
  else emit('download', e)
}

function gridActivate(e) {
  rowActivate(e)
}

// ===== 同目录内预览导航（←/→ 切换上一个/下一个可预览文件） =====
const navList = computed(() => props.entries.filter((e) => !e.is_dir && kindOf(e.name, e.is_dir)))
const navIndex = computed(() =>
  props.preview ? navList.value.findIndex((e) => e.fid === props.preview.fid) : -1
)

function nav(dir) {
  const i = navIndex.value + dir
  const t = navList.value[i]
  if (t) emit('preview', t)
}

// 自动下一页（对齐官方 video_auto_next）
const autoNext = ref(localStorage.getItem('video_auto_next') !== 'false')
watch(autoNext, (v) => localStorage.setItem('video_auto_next', String(v)))

function onVideoEnded() {
  if (!autoNext.value) return
  if (navIndex.value < navList.value.length - 1) nav(1)
}

function onVideoPick(ev) {
  const t = navList.value.find((v) => v.name === ev.target.value)
  if (t) emit('preview', t)
}

function onKey(ev) {
  if (!props.preview) return
  if (ev.key === 'Escape') emit('close-preview')
  else if (ev.key === 'ArrowLeft') nav(-1)
  else if (ev.key === 'ArrowRight') nav(1)
}
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))

// ===== 文本类预览：fetch 全文展示（server_proxy 关闭时为跨域直链，失败则降级提示） =====
const textContent = ref(null)
const textLoading = ref(false)
const textError = ref('')
const textLineCount = computed(() => {
  const t = textContent.value
  if (!t) return 1
  return String(t).split('\n').length
})
const audioPlaying = ref(false)

watch(
  () => props.preview,
  (p) => {
    audioPlaying.value = false
    textContent.value = null
    textError.value = ''
    if (!p || p._kind !== 'text') return
    if (p.size != null && p.size > TEXT_PREVIEW_MAX) {
      textError.value = '文件过大，不支持在线预览'
      return
    }
    textLoading.value = true
    fetch(p._url)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.text()
      })
      .then((t) => {
        textContent.value = t
      })
      .catch(() => {
        textError.value = '无法加载文本内容（直链跨域或网络失败）'
      })
      .finally(() => {
        textLoading.value = false
      })
  }
)

function fmtSize(n) {
  if (n == null) return '-'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

function fmtDate(ms) {
  if (!ms) return '-'
  const d = new Date(ms)
  const p = (x) => String(x).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

// ===== 右下角 FAB 操作菜单 =====
const fabOpen = ref(false)
const fileInput = ref(null)
const folderInput = ref(null)
let pickMode = 'files'

function fabAct(act) {
  fabOpen.value = false
  if (act === 'mkdir') emit('mkdir')
  else if (act === 'refresh') emit('refresh')
  else if (act === 'upload') {
    pickMode = 'files'
    fileInput.value?.click()
  } else if (act === 'upload-folder') {
    pickMode = 'folder'
    folderInput.value?.click()
  }
}

function onFilesPicked(ev) {
  const files = Array.from(ev.target.files || [])
  ev.target.value = ''
  if (files.length === 0) return
  const isFolder = pickMode === 'folder'
  emit(
    'upload',
    files.map((f) => ({
      file: f,
      // 文件夹上传时保留相对路径（含中间目录），单文件只用文件名
      relPath: isFolder ? (f.webkitRelativePath || f.name) : f.name
    }))
  )
}

// 点击 FAB 菜单外部时收起
function onDocClick(ev) {
  if (!fabOpen.value) return
  if (ev.target.closest?.('.fab-wrap')) return
  fabOpen.value = false
}
onMounted(() => document.addEventListener('click', onDocClick))
onBeforeUnmount(() => document.removeEventListener('click', onDocClick))
</script>

<style scoped>
.page {
  max-width: 980px;
  margin: 0 auto;
  padding: 4px 20px 40px;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  color: var(--ol-text-dim);
  padding: 60px 20px;
  text-align: center;
}

/* ===== 面包屑（对齐官方 Nav） ===== */
.crumbs-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.crumbs {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 2px;
  padding: 14px 0;
  font-size: 14px;
  flex: 1;
  min-width: 0;
}
.crumb-link {
  color: var(--ol-text);
  padding: 4px 10px;
  border-radius: 8px;
  word-break: break-all;
  transition: background-color 0.15s ease, transform 0.1s ease;
}
.crumb-link:hover {
  background: rgba(0, 0, 0, 0.05);
  text-decoration: none;
}
.crumb-link:active {
  transform: scale(0.95);
}
html.dark .crumb-link:hover {
  background: rgba(255, 255, 255, 0.08);
}
.crumb-sep {
  color: var(--ol-text-faint);
  padding: 0 2px;
}

/* 布局切换（对齐官方 header Layout 按钮） */
.view-toggle button {
  width: 34px;
  height: 34px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: none;
  border-radius: 9px;
  background: var(--ol-accent-light);
  color: var(--ol-accent);
  cursor: pointer;
  flex-shrink: 0;
  transition: filter 0.15s ease;
}
.view-toggle button:hover {
  filter: brightness(0.96);
}

/* ===== 文件名行（预览页，对齐官方 File 页布局） ===== */
.file-line {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 2px 4px 12px;
  font-size: 14px;
}
.file-line-name {
  flex: 1;
  min-width: 0;
  word-break: break-all;
  color: var(--ol-text);
}
.player-pos {
  flex-shrink: 0;
  font-size: 12px;
  color: var(--ol-text-faint);
  font-variant-numeric: tabular-nums;
}
.file-line-ops {
  display: flex;
  gap: 2px;
  flex-shrink: 0;
}
.file-line-ops .op-icon:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

/* ===== obj-box 白卡（对齐官方 Obj：rounded-xl + shadow） ===== */
.obj-box {
  background: var(--ol-panel);
  border-radius: 12px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.06);
  padding: 8px;
}
html.dark .obj-box {
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
}

/* 列表标题行 */
.list-title {
  display: flex;
  align-items: center;
  padding: 8px;
  font-size: 13px;
  font-weight: 700;
  color: var(--ol-text-dim);
}
.lt-name {
  width: 50%;
}
.lt-size {
  width: 17%;
  flex-shrink: 0;
  text-align: right;
}
.lt-date {
  width: 26%;
  flex-shrink: 0;
  text-align: right;
}
.lt-op {
  /* 文件行最多 6 个图标（播放/下载/重命名/移动/复制/删除）：28*6 + 2*5 = 178 */
  width: 178px;
  flex-shrink: 0;
}

.list-body {
  display: flex;
  flex-direction: column;
  gap: 2px;
  list-style: none;
  margin: 0;
  padding: 0;
}
/* 列表行：圆角、悬停放大（对齐官方 ListItem） */
.list-item {
  display: flex;
  align-items: center;
  width: 100%;
  padding: 8px;
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.3s;
}
.list-item:hover {
  transform: scale(1.01);
  background: rgba(0, 0, 0, 0.045);
}
html.dark .list-item:hover {
  background: rgba(255, 255, 255, 0.07);
}
.li-name {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 50%;
  min-width: 0;
  padding-right: 8px;
}
.fname-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  word-break: break-all;
  color: var(--ol-text);
}
.li-size {
  width: 17%;
  flex-shrink: 0;
  text-align: right;
  color: var(--ol-text-dim);
  font-size: 13px;
  white-space: nowrap;
}
.li-date {
  width: 26%;
  flex-shrink: 0;
  text-align: right;
  color: var(--ol-text-dim);
  font-size: 13px;
  white-space: nowrap;
}
.li-op {
  /* 必须容得下最多 6 个 28px 图标：旧值 132px 会让图标往左溢出压住「修改时间」 */
  width: 178px;
  flex-shrink: 0;
  display: flex;
  justify-content: flex-end;
  gap: 2px;
  opacity: 0;
  transition: opacity 0.15s ease;
}
.list-item:hover .li-op {
  opacity: 1;
}

.ficon {
  width: 24px;
  height: 24px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
}

/* 行内小图标按钮 */
.op-icon {
  width: 28px;
  height: 28px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: none;
  border-radius: 7px;
  background: transparent;
  color: var(--ol-text-dim);
  cursor: pointer;
  flex-shrink: 0;
  transition: background-color 0.15s ease, color 0.15s ease;
}
.op-icon:hover {
  background: rgba(0, 0, 0, 0.06);
  color: var(--ol-text);
}
html.dark .op-icon:hover {
  background: rgba(255, 255, 255, 0.1);
}
.op-del:hover {
  color: var(--ol-danger);
}

/* ===== 预览容器 ===== */
.state-box {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 60px 0;
  color: var(--ol-text-dim);
  font-size: 13.5px;
}
.loader-lg {
  width: 26px;
  height: 26px;
  border: 3px solid var(--ol-border-strong);
  border-top-color: var(--ol-primary);
  border-radius: 50%;
}

.video-stage {
  background: #000;
  border-radius: 10px;
  overflow: hidden;
  display: flex;
  align-items: center;
  justify-content: center;
}
.player-video {
  display: block;
  width: 100%;
  max-height: 60vh;
  aspect-ratio: 16 / 9;
  background: #000;
  outline: none;
}

/* 音乐 */
.audio-stage {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 22px;
  padding: 40px 20px 34px;
  background: linear-gradient(165deg, rgba(0, 145, 255, 0.08), rgba(204, 127, 204, 0.08));
  border-radius: 10px;
}
.disc {
  width: 116px;
  height: 116px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  background:
    radial-gradient(circle at center, rgba(255, 255, 255, 0.9) 0 11%, transparent 11.5%),
    linear-gradient(135deg, #70c6be, #162dcc);
  box-shadow: 0 10px 30px rgba(22, 45, 204, 0.25), inset 0 0 0 6px rgba(255, 255, 255, 0.12);
}
.disc.spinning {
  animation: disc-spin 5s linear infinite;
}
@keyframes disc-spin {
  to {
    transform: rotate(360deg);
  }
}
.audio-player {
  width: min(520px, 100%);
  outline: none;
}

/* 图片 */
.image-stage {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 200px;
  background: #14161a;
  background-image:
    linear-gradient(45deg, #1c1f26 25%, transparent 25%, transparent 75%, #1c1f26 75%),
    linear-gradient(45deg, #1c1f26 25%, transparent 25%, transparent 75%, #1c1f26 75%);
  background-size: 24px 24px;
  background-position: 0 0, 12px 12px;
  border-radius: 10px;
  overflow: hidden;
}
.image-view {
  display: block;
  max-width: 100%;
  max-height: 68vh;
  object-fit: contain;
}

/* PDF */
.pdf-frame {
  display: block;
  width: 100%;
  height: 72vh;
  border: none;
  border-radius: 10px;
  background: #525659;
}

/* 文本 — 行号 + 等宽 */
.text-stage {
  background: var(--ol-panel);
}
.text-editor {
  display: flex;
  max-height: 68vh;
  overflow: auto;
  background: var(--ol-bg);
  border-radius: 10px;
}
.text-gutter {
  flex-shrink: 0;
  min-width: 44px;
  padding: 16px 8px 16px 12px;
  text-align: right;
  font-family: var(--ol-mono, ui-monospace, Consolas, monospace);
  font-size: 12px;
  line-height: 1.65;
  color: var(--ol-text-faint);
  user-select: none;
  border-right: 1px solid var(--ol-border);
  background: color-mix(in srgb, var(--ol-bg) 80%, var(--ol-panel));
}
.text-gutter span {
  display: block;
}
.text-view {
  margin: 0;
  flex: 1;
  padding: 16px 18px;
  font-family: var(--ol-mono, ui-monospace, Consolas, monospace);
  font-size: 13px;
  line-height: 1.65;
  color: var(--ol-text);
  white-space: pre;
  overflow-wrap: normal;
  tab-size: 4;
}

/* ===== 视频页脚（对齐官方 VideoBox） ===== */
.video-foot {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 12px;
}
.video-select {
  flex: 1;
  min-width: 0;
  height: 38px;
}
.auto-next {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  color: var(--ol-text);
  white-space: nowrap;
  cursor: pointer;
  user-select: none;
}
.toggle {
  flex-shrink: 0;
  width: 42px;
  height: 24px;
  border-radius: 12px;
  background: var(--ol-border-strong);
  position: relative;
  cursor: pointer;
  transition: background 0.2s;
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

/* 播放器图标行（对齐官方 player-exts） */
.player-exts {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: 12px;
}
.ext-btn {
  width: 36px;
  height: 36px;
  padding: 2px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: none;
  background: transparent;
  cursor: pointer;
  transition: transform 0.15s ease;
}
.ext-btn:hover {
  transform: scale(1.12);
}
.ext-btn img {
  width: 100%;
  height: 100%;
  object-fit: contain;
}
.ext-more {
  width: 34px;
  height: 34px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: none;
  background: transparent;
  color: var(--ol-primary);
  cursor: pointer;
}
.ext-more .flip-x {
  transform: rotate(180deg);
  transition: transform 0.2s;
}

/* ===== 宫格视图（对齐官方 GridItem） ===== */
.grid-view {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(110px, 1fr));
  gap: 4px;
  padding: 4px;
}
.grid-item {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  padding: 10px 6px;
  border-radius: 10px;
  cursor: pointer;
  text-align: center;
  transition: all 0.3s;
}
.grid-item:hover {
  background: rgba(0, 0, 0, 0.045);
  transform: scale(1.06);
}
html.dark .grid-item:hover {
  background: rgba(255, 255, 255, 0.07);
}
.grid-icon {
  width: 52px;
  height: 52px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.grid-icon .fi {
  width: 44px;
  height: 44px;
}
.grid-name {
  font-size: 13px;
  width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--ol-text);
}
.grid-hover-actions {
  position: absolute;
  top: 4px;
  right: 4px;
  display: none;
  gap: 2px;
}
.grid-item:hover .grid-hover-actions {
  display: flex;
}

/* ===== 右下角 FAB（对齐官方 Right 工具栏） ===== */
.fab-wrap {
  position: fixed;
  right: 22px;
  bottom: 22px;
  z-index: 80;
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 8px;
}
.fab {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  border: none;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--ol-text);
  background: var(--ol-panel);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.18);
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.fab:hover {
  transform: scale(1.06);
}
.fab.open {
  color: var(--ol-primary);
}
.fab-menu {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: 4px;
  background: var(--ol-panel);
  border-radius: 12px;
  box-shadow: 0 8px 28px rgba(0, 0, 0, 0.16);
}
.fab-item {
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: none;
  background: transparent;
  border-radius: 50%;
  color: var(--ol-text);
  cursor: pointer;
  transition: background-color 0.15s ease, color 0.15s ease;
}
.fab-item:hover {
  background: rgba(0, 0, 0, 0.06);
  color: var(--ol-primary);
}
html.dark .fab-item:hover {
  background: rgba(255, 255, 255, 0.1);
}
.fab-item:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.fab-pop-enter-active,
.fab-pop-leave-active {
  transition: opacity 0.15s ease, transform 0.15s ease;
}
.fab-pop-enter-from,
.fab-pop-leave-to {
  opacity: 0;
  transform: translateY(8px) scale(0.96);
}
.spinning {
  animation: refresh-spin 0.8s linear infinite;
}
@keyframes refresh-spin {
  to {
    transform: rotate(360deg);
  }
}

/* ===== 移动端 ===== */
.mobile-row-info {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  flex: 1;
}
.mobile-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: var(--ol-text-dim);
  white-space: nowrap;
}
.mobile-date {
  color: var(--ol-text-faint);
}
.mobile-row-ops {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 2px;
  padding-left: 32px;
}
.mobile-row-ops .op-icon {
  opacity: 1;
}

@media (max-width: 768px) {
  .page {
    padding: 4px 12px 40px;
  }
  .lt-date,
  .li-date {
    display: none;
  }
  .lt-name,
  .li-name {
    width: 76%;
  }
  .lt-size,
  .li-size {
    width: 24%;
  }
  .lt-op,
  .li-op {
    display: none;
  }
  .desktop-list {
    display: none;
  }
  .mobile-list {
    display: flex;
  }
  .mobile-item {
    flex-wrap: wrap;
  }
  .mobile-item .mobile-row-info {
    width: 100%;
  }
  .mobile-item .mobile-meta {
    width: 100%;
    padding-left: 32px;
    order: 2;
  }
  .mobile-item .mobile-row-ops {
    order: 3;
    width: 100%;
  }
  .video-foot {
    flex-wrap: wrap;
  }
}
@media (min-width: 769px) {
  .mobile-list {
    display: none;
  }
}
</style>
