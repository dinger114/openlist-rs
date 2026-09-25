<template>
  <section class="card panel">
    <div class="panel-head">
      <Icon name="cloud" :size="18" />
      <h2>WebDAV</h2>
    </div>
    <div class="panel-body">
      <div class="dav-field">
        <label>服务地址</label>
        <div class="dav-row">
          <code class="dav-code">{{ davUrl }}</code>
          <button class="btn btn-ghost btn-sm" @click="copy('url')">
            <Icon name="copy" :size="14" />{{ copied === 'url' ? '已复制' : '复制' }}
          </button>
        </div>
      </div>

      <p class="hint-text">
        用面板账号 <b>{{ username || 'admin' }}</b> 与登录密码认证（HTTP Basic）。只读存储（如网易云音乐）
        可浏览、下载与播放，写操作会失败。
      </p>

      <div class="dav-field dav-mounts">
        <label>挂载方式</label>
        <ul class="hint-text">
          <li>macOS：访达 → 前往 → 连接服务器，填上面的地址</li>
          <li>Windows：资源管理器 → 映射网络驱动器，填上面的地址</li>
          <li>
            命令行：
            <code class="dav-code">rclone lsd dav: --webdav-url {{ davUrl }}</code>
            <button class="btn btn-ghost btn-sm" @click="copy('rclone')">
              {{ copied === 'rclone' ? '已复制' : '复制命令' }}
            </button>
          </li>
        </ul>
      </div>

      <p v-if="!secure" class="hint-text dav-warn">
        当前通过 HTTP 明文访问，Basic 凭据可能被同网段抓包；建议仅在可信内网使用，或反向代理加 HTTPS。
      </p>
    </div>
  </section>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import Icon from './Icon.vue'

defineProps({
  username: { type: String, default: '' }
})

const davUrl = ref('/dav')
const secure = ref(true)
const copied = ref('')

onMounted(() => {
  // 面板接口都按站点根路径请求，这里同样以 origin 拼 DAV 地址
  davUrl.value = `${location.origin}/dav`
  secure.value =
    location.protocol === 'https:' ||
    ['localhost', '127.0.0.1'].includes(location.hostname)
})

async function copy(what) {
  const text =
    what === 'rclone'
      ? `rclone lsd dav: --webdav-url ${davUrl.value}`
      : davUrl.value
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
    } else {
      // 局域网 HTTP 下 navigator.clipboard 不存在，退化为 execCommand
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.top = '-1000px'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
    copied.value = what
    setTimeout(() => {
      copied.value = ''
    }, 2000)
  } catch (_) {
    copied.value = ''
  }
}
</script>

<style scoped>
/* 卡片结构与设置页其他卡片一致（panel-head / panel-body 为各组件自带作用域样式） */
.panel {
  margin-top: 16px;
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

.dav-field {
  margin-bottom: 14px;
}
.dav-field label {
  display: block;
  margin-bottom: 8px;
  font-size: 13px;
  color: var(--ol-text-dim);
  font-weight: 500;
}
.dav-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.dav-code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12.5px;
  background: var(--ol-bg);
  border: 1px solid var(--ol-border);
  border-radius: var(--ol-radius-sm);
  padding: 5px 9px;
  word-break: break-all;
}
.dav-mounts ul {
  margin: 0;
  padding-left: 18px;
}
.dav-mounts li {
  margin-bottom: 6px;
}
.dav-warn {
  color: var(--ol-danger);
}
</style>
