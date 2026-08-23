# Update Log 2026-08-23

## [2026-08-23 22:30] Update timedisplay.html
- 添加 PWA 支持：引入 manifest.json 和 Service Worker 注册
- 添加 Apple 全屏支持：meta viewport-capable + status-bar-style + touch-icon
- 优化时区处理：改用 Intl.DateTimeFormat API，支持 12 个预设时区
- 补全信息展示：干支纪年、周数、儒略日、年内天数、月相、日出日落
- 添加经纬度映射表，日出日落计算更精确
- 重构 getTimeInTimezone 为"伪 Date"对象，兼容所有 getter
- 优化时区缩写获取逻辑（short/long fallback）
- 代码结构优化，添加分区注释

## [2026-08-23 22:35] Add PWA support
- 新增 manifest.json
- 新增 icons/ 文件夹

## [2026-08-23 22:36] Add service worker
- 新增 sw.js

## [2026-08-23 23:04] Update README.md
- 更新项目说明
- 添加社交账号（快手、B站）
- 添加在线访问地址

## [2026-08-23 23:11] Add Log folder
- 新增 log/ 文件夹
- 新增 Update log_20260823.md
