<template>
  <svg :width="size" :height="size" viewBox="0 0 48 48" fill="none" class="ol-logo">
    <defs>
      <linearGradient id="ol-logo-g" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stop-color="#70c6be" />
        <stop offset="1" stop-color="#162dcc" />
      </linearGradient>
    </defs>
    <path
      d="M23.2 5.6a3 3 0 0 1 3.9-1.2c.5.3 1 .7 1.3 1.3l15.4 27a3 3 0 0 1-2.6 4.5H6.8a3 3 0 0 1-2.6-4.5l15.4-27a3 3 0 0 1 3.6-1.3Z"
      fill="url(#ol-logo-g)"
    />
    <path d="M24 17.5 33.5 34h-19Z" fill="var(--ol-logo-hole, #fff)" />
  </svg>
</template>

<script setup>
defineProps({
  size: { type: [Number, String], default: 44 }
})
</script>

<style scoped>
.ol-logo {
  display: block;
  flex-shrink: 0;
}
</style>
