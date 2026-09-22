<template>
  <!-- 官方列表用的是 IoFolder 实心文件夹（跟随主题紫色） -->
  <svg v-if="type === 'folder'" class="fi" viewBox="0 0 48 48" fill="none">
    <path
      d="M4 11a4 4 0 0 1 4-4h9.6l4.2 4.6H40a4 4 0 0 1 4 4V36a4 4 0 0 1-4 4H8a4 4 0 0 1-4-4V11Z"
      fill="var(--ol-folder, #cc7fcc)"
    />
  </svg>

  <svg v-else-if="type === 'video'" class="fi" viewBox="0 0 48 48" fill="none">
    <rect x="5" y="8" width="38" height="32" rx="4" fill="#7C4DFF" />
    <path d="M20 18.5 30 24l-10 5.5v-11Z" fill="#fff" />
  </svg>

  <svg v-else-if="type === 'image'" class="fi" viewBox="0 0 48 48" fill="none">
    <rect x="5" y="8" width="38" height="32" rx="4" fill="#00B368" />
    <circle cx="16" cy="19" r="4" fill="#fff" />
    <path d="M9 34l10-10 7 7 6-6 10 10v1a2 2 0 0 1-2 2H11a2 2 0 0 1-2-2v-2Z" fill="#fff" />
  </svg>

  <svg v-else-if="type === 'audio'" class="fi" viewBox="0 0 48 48" fill="none">
    <rect x="5" y="8" width="38" height="32" rx="4" fill="#FF6B6B" />
    <circle cx="19" cy="30" r="4" fill="#fff" />
    <circle cx="31" cy="27" r="4" fill="#fff" />
    <path d="M23 30V16l12-3v11" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" />
  </svg>

  <svg v-else-if="type === 'pdf'" class="fi" viewBox="0 0 48 48" fill="none">
    <path d="M11 4h16l10 10v26a2 2 0 0 1-2 2H11a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z" fill="#F53F3F" />
    <path d="M27 4v8a2 2 0 0 0 2 2h8" fill="#FF8080" />
    <text x="24" y="33" text-anchor="middle" font-size="10" font-weight="700" fill="#fff" font-family="Arial">PDF</text>
  </svg>

  <svg v-else-if="type === 'doc'" class="fi" viewBox="0 0 48 48" fill="none">
    <path d="M11 4h16l10 10v26a2 2 0 0 1-2 2H11a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z" fill="#3B82F6" />
    <path d="M27 4v8a2 2 0 0 0 2 2h8" fill="#93C1FF" />
    <text x="24" y="33" text-anchor="middle" font-size="9.5" font-weight="700" fill="#fff" font-family="Arial">DOC</text>
  </svg>

  <svg v-else-if="type === 'sheet'" class="fi" viewBox="0 0 48 48" fill="none">
    <path d="M11 4h16l10 10v26a2 2 0 0 1-2 2H11a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z" fill="#00A870" />
    <path d="M27 4v8a2 2 0 0 0 2 2h8" fill="#7FDDBB" />
    <text x="24" y="33" text-anchor="middle" font-size="9" font-weight="700" fill="#fff" font-family="Arial">XLS</text>
  </svg>

  <svg v-else-if="type === 'ppt'" class="fi" viewBox="0 0 48 48" fill="none">
    <path d="M11 4h16l10 10v26a2 2 0 0 1-2 2H11a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z" fill="#FF7D00" />
    <path d="M27 4v8a2 2 0 0 0 2 2h8" fill="#FFC17F" />
    <text x="24" y="33" text-anchor="middle" font-size="9" font-weight="700" fill="#fff" font-family="Arial">PPT</text>
  </svg>

  <svg v-else-if="type === 'archive'" class="fi" viewBox="0 0 48 48" fill="none">
    <path d="M11 4h16l10 10v26a2 2 0 0 1-2 2H11a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z" fill="#B98A3A" />
    <path d="M27 4v8a2 2 0 0 0 2 2h8" fill="#DCB77B" />
    <rect x="21" y="12" width="6" height="4" fill="#fff" />
    <rect x="21" y="19" width="6" height="4" fill="#fff" />
    <rect x="21" y="26" width="6" height="6" fill="#fff" />
  </svg>

  <svg v-else-if="type === 'code'" class="fi" viewBox="0 0 48 48" fill="none">
    <path d="M11 4h16l10 10v26a2 2 0 0 1-2 2H11a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z" fill="#1D2129" />
    <path d="M27 4v8a2 2 0 0 0 2 2h8" fill="#4E5969" />
    <path d="M18 22l-4 4 4 4M30 22l4 4-4 4M25 20l-2 12" stroke="#5B8DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none" />
  </svg>

  <svg v-else-if="type === 'text'" class="fi" viewBox="0 0 48 48" fill="none">
    <path d="M11 4h16l10 10v26a2 2 0 0 1-2 2H11a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z" fill="#86909C" />
    <path d="M27 4v8a2 2 0 0 0 2 2h8" fill="#C2C6D0" />
    <path d="M16 22h16M16 27h16M16 32h10" stroke="#fff" stroke-width="2" stroke-linecap="round" />
  </svg>

  <svg v-else class="fi" viewBox="0 0 48 48" fill="none">
    <path d="M11 4h16l10 10v26a2 2 0 0 1-2 2H11a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z" fill="#A0A6B3" />
    <path d="M27 4v8a2 2 0 0 0 2 2h8" fill="#CDD1DA" />
  </svg>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  name: { type: String, default: '' },
  isDir: { type: Boolean, default: false }
})

const EXT_MAP = {
  // video
  mp4: 'video', mkv: 'video', webm: 'video', mov: 'video', m4v: 'video',
  avi: 'video', flv: 'video', ts: 'video', wmv: 'video', rmvb: 'video', '3gp': 'video',
  // image
  jpg: 'image', jpeg: 'image', png: 'image', gif: 'image', webp: 'image',
  bmp: 'image', svg: 'image', heic: 'image', avif: 'image',
  // audio
  mp3: 'audio', flac: 'audio', wav: 'audio', aac: 'audio', ogg: 'audio', m4a: 'audio',
  // docs
  pdf: 'pdf',
  doc: 'doc', docx: 'doc', rtf: 'doc',
  xls: 'sheet', xlsx: 'sheet', csv: 'sheet',
  ppt: 'ppt', pptx: 'ppt',
  // archive
  zip: 'archive', rar: 'archive', '7z': 'archive', tar: 'archive', gz: 'archive', bz2: 'archive',
  // code
  js: 'code', ts: 'code', py: 'code', rs: 'code', go: 'code', java: 'code', c: 'code',
  cpp: 'code', h: 'code', json: 'code', html: 'code', css: 'code', vue: 'code', sh: 'code',
  // text
  txt: 'text', md: 'text', markdown: 'text', log: 'text',
  // more
  m3u8: 'video', iso: 'archive', dmg: 'archive', apk: 'archive',
  exe: 'archive', msi: 'archive', epub: 'text',
}

const type = computed(() => {
  if (props.isDir) return 'folder'
  const ext = props.name.split('.').pop()?.toLowerCase() || ''
  return EXT_MAP[ext] || 'file'
})
</script>

<style scoped>
.fi {
  width: 100%;
  height: 100%;
  display: block;
}
</style>
