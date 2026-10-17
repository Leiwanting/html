# Orbitron

自托管字体，避免依赖 Google Fonts（国内网络经常加载失败，会静默回退到系统字体）。

- 字重：400 / 500 / 700（woff2，fonttools 从官方 ttf 转换）
- 授权：SIL Open Font License 1.1，见 `OFL.txt`
- 上游：https://fonts.google.com/specimen/Orbitron

只覆盖拉丁字母、数字与常用符号；中文仍由系统字体渲染。

## 中文字体：MiSans 子集

- 来源：小米 [MiSans](https://hyperos.mi.com/font/)，小米官方声明免费商用
- 做法：用 fonttools 按 `<cn-charset.txt>` 里实际用到的字符做子集，每字重仅 29KB
- 字符集来自 `timedisplay.html` + `js/app.js` 中的全部中日文与标点（224 个）
- **以后页面新增中文，需要重新生成子集**，否则新字会回退到系统字体（可读，但风格不一致）

重新生成（需 `pip install fonttools brotli`）：

```bash
python3 -m fontTools.subset MiSans-Regular.woff2 --text-file=cn-charset.txt \
  --flavor=woff2 --output-file=MiSans-400.woff2 --layout-features='kern,liga,vert'
```
