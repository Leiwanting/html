# Update Log 2026-08-25

## [2026-08-25 01:04] Update sw.js

### 优化
- 升级 PWA 缓存策略：Cache-First → Stale-While-Revalidate
  - 优先返回本地缓存，保证秒开体验
  - 后台静默更新资源，下次访问自动生效

### 修复
- 修复缓存版本更新不及时问题
  - install 阶段强制清空旧缓存并重填资源
  - Service Worker 缓存版本号升级至 v2

