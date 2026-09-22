// 文件预览类型判定：视频 / 音乐 / 图片 / PDF / 文本，与 FilesView、App 共用
const VIDEO_EXT = ['mp4', 'mkv', 'webm', 'mov', 'm4v', 'avi', 'flv', 'ts', 'wmv', 'rmvb', '3gp']
const AUDIO_EXT = ['mp3', 'flac', 'ape', 'wav', 'aac', 'ogg', 'm4a', 'wma', 'opus', 'm4b']
const IMAGE_EXT = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'ico', 'avif']
const PDF_EXT = ['pdf']
// 浏览器可直接以文本展示的"常见文档"：纯文本、标记、配置、代码、字幕/歌词等
const TEXT_EXT = [
  'txt', 'md', 'markdown', 'log', 'csv', 'tsv',
  'json', 'xml', 'yaml', 'yml', 'toml', 'ini', 'conf', 'env',
  'srt', 'ass', 'ssa', 'vtt', 'lrc',
  'js', 'ts', 'css', 'html', 'htm', 'vue', 'jsx', 'tsx',
  'py', 'rs', 'go', 'java', 'c', 'h', 'cpp', 'sh', 'bat', 'ps1', 'sql'
]

export const KIND_ICON = {
  video: 'play',
  audio: 'music',
  image: 'eye',
  pdf: 'file-text',
  text: 'file-text'
}

export const KIND_TITLE = {
  video: '播放',
  audio: '播放',
  image: '预览',
  pdf: '预览',
  text: '预览'
}

export function extOf(name) {
  return String(name || '').split('.').pop()?.toLowerCase() || ''
}

// 返回 'video' | 'audio' | 'image' | 'pdf' | 'text' | null
export function kindOf(name, isDir = false) {
  if (isDir) return null
  const x = extOf(name)
  if (VIDEO_EXT.includes(x)) return 'video'
  if (AUDIO_EXT.includes(x)) return 'audio'
  if (IMAGE_EXT.includes(x)) return 'image'
  if (PDF_EXT.includes(x)) return 'pdf'
  if (TEXT_EXT.includes(x)) return 'text'
  return null
}

// 文本预览上限：超过后不再 fetch 全文（直链/大文件场景）
export const TEXT_PREVIEW_MAX = 5 * 1024 * 1024
