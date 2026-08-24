# Update Log 2026-08-25

## [2026-08-25 02:54] Update sw.js & timedisplay.html

### 优化
- 升级 PWA 缓存策略：Cache-First → Stale-While-Revalidate
  - 优先返回本地缓存，保证秒开体验
  - 后台静默更新资源，下次访问自动生效
- install 阶段强制清空当前缓存再重新添加，确保版本更新即时生效

### 修复
- 修复缓存版本更新不及时问题
  - Service Worker 缓存版本号升级至 v3
- QRCode.js 从 CDN 迁移到本地 (`js/qrcode.min.js`)
  - 解决离线模式下二维码功能失效问题
  - 更新 `urlsToCache` 包含本地 JS 资源

### 依赖变更
- 移除：CDN `cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js`
- 新增：本地 `js/qrcode.min.js`
