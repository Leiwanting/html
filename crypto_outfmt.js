/* ============================================================
 * 输出格式扩展（Base45 / Z85 / UUEncode / Hex dump / 语言字面量）
 * 7 种额外输出格式，使输出格式总数达 21 种。
 * Base45 与 Z85 支持反向解码，其余为单向编码。
 * ============================================================ */
/* ========== 输出格式扩展 ========== */
var B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
function outBase45(b) {
  var s = '', i;
  for (i = 0; i < b.length - 1; i += 2) {
    var v = b[i] | (b[i + 1] << 8);
    s += B45[v % 45] + B45[Math.floor(v / 45) % 45] + B45[Math.floor(v / 2025)];
  }
  if (i < b.length) { var r = b[i]; s += B45[r % 45] + B45[Math.floor(r / 45)]; }
  return s;
}
function inBase45(s) {
  var out = [], i;
  for (i = 0; i + 2 < s.length; i += 3) {
    var v = B45.indexOf(s[i]) + B45.indexOf(s[i + 1]) * 45 + B45.indexOf(s[i + 2]) * 2025;
    if (v < 0 || v > 0xFFFF) throw new Error('Base45 非法字符');
    out.push(v & 0xff, (v >> 8) & 0xff);
  }
  if (i < s.length) {
    if (s.length - i !== 2) throw new Error('Base45 长度非法');
    var v2 = B45.indexOf(s[i]) + B45.indexOf(s[i + 1]) * 45;
    if (v2 < 0 || v2 > 0xff) throw new Error('Base45 非法字符');
    out.push(v2);
  }
  return new Uint8Array(out);
}
var Z85 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#';
function outZ85(b) {
  if (b.length % 4 !== 0) throw new Error('Z85 要求输入长度为 4 的倍数');
  var s = '', i;
  for (i = 0; i < b.length; i += 4) {
    var v = (b[i] << 24 | b[i + 1] << 16 | b[i + 2] << 8 | b[i + 3]) >>> 0;
    for (var j = 4; j >= 0; j--) s += Z85[Math.floor(v / Math.pow(85, j)) % 85];
  }
  return s;
}
function inZ85(s) {
  if (s.length % 5 !== 0) throw new Error('Z85 要求字符数为 5 的倍数');
  var out = new Uint8Array(s.length / 5 * 4), o = 0, i;
  for (i = 0; i < s.length; i += 5) {
    var v = 0;
    for (var j = 0; j < 5; j++) { var d = Z85.indexOf(s[i + j]); if (d < 0) throw new Error('Z85 非法字符'); v = v * 85 + d; }
    out[o++] = (v >>> 24) & 0xff; out[o++] = (v >>> 16) & 0xff; out[o++] = (v >>> 8) & 0xff; out[o++] = v & 0xff;
  }
  return out;
}
function outUU(b) {
  var s = 'begin 644 -\n', i;
  for (i = 0; i < b.length; i += 45) {
    var n = Math.min(45, b.length - i);
    s += String.fromCharCode(32 + n);
    for (var j = 0; j < n; j += 3) {
      var c0 = b[i + j], c1 = (j + 1 < n) ? b[i + j + 1] : 0, c2 = (j + 2 < n) ? b[i + j + 2] : 0;
      s += String.fromCharCode(32 + (c0 >> 2));
      s += String.fromCharCode(32 + (((c0 & 3) << 4) | (c1 >> 4)));
      s += String.fromCharCode(32 + (((c1 & 15) << 2) | (c2 >> 6)));
      s += String.fromCharCode(32 + (c2 & 63));
    }
    s += '\n';
  }
  return s + '`\nend\n';
}
function outHexdump(b) {
  var s = '', i, j;
  for (i = 0; i < b.length; i += 16) {
    var hex = '', asc = '';
    for (j = 0; j < 16; j++) {
      if (i + j < b.length) { hex += (b[i + j] < 16 ? '0' : '') + b[i + j].toString(16) + ' '; asc += (b[i + j] >= 32 && b[i + j] < 127) ? String.fromCharCode(b[i + j]) : '.'; }
      else { hex += '   '; }
    }
    s += (i).toString(16).padStart(8, '0') + ': ' + hex + ' ' + asc + '\n';
  }
  return s;
}
function outPyLiteral(b) { return 'b"' + Array.from(b).map(function (x) { return '\\x' + (x < 16 ? '0' : '') + x.toString(16); }).join('') + '"'; }
function outGoLiteral(b) { return '[]byte{0x' + Array.from(b).map(function (x) { return (x < 16 ? '0' : '') + x.toString(16); }).join(', 0x') + '}'; }
function outRustLiteral(b) { return '[' + Array.from(b).map(function (x) { return '0x' + (x < 16 ? '0' : '') + x.toString(16); }).join(', ') + ']'; }

/* 【这段注释已过时，保留说明以免重蹈】早期版本的 POLYVAL 位循环（GF(2^128) 的
   第三种约定，与 GHASH 不同）未能与 cryptography 的 AESGCMSIV 对上，当时据此
   判定「未通过验证前不注册」。
   后来在 crypto_aead_adv.js 里修好了 POLYVAL，关键点是 SIV 的构造为【先解密、
   后验签】——POLYVAL 作用在【明文】上而非密文（早期对密文做 POLYVAL，非空明文
   全部认证失败，只有空明文因两边皆空而碰巧通过）。
   现状：aes-gcm-siv 已注册，与 cryptography 的 AESGCMSIV 交叉验证 24/24（本批
   追加 5/5 复算），并已接入「加密模式」下拉（nonce 12 字节，输出 nonce‖密文‖tag）。 */

/* 输出格式在运行时合并进 OUT_FORMATS：crypto_core.js 的 OUT_FORMATS 定义
   在加载时就被 initFmtSelect 遍历，若把新格式写进 core 会引用到尚未定义的函数。
   放在 core 之后合并则两边都安全。 */
if (typeof OUT_FORMATS === 'object') {
  OUT_FORMATS.base45 = { label: 'Base45（二维码）', out: outBase45, inFn: inBase45 };
  OUT_FORMATS.z85 = { label: 'Z85（ZeroMQ）', out: outZ85, inFn: inZ85 };
  OUT_FORMATS.uuencode = { label: 'UUEncode', out: outUU, inFn: null };
  OUT_FORMATS.hexdump = { label: 'Hex dump（带偏移）', out: outHexdump, inFn: null };
  OUT_FORMATS.pyliteral = { label: 'Python bytes 字面量', out: outPyLiteral, inFn: null };
  OUT_FORMATS.goliteral = { label: 'Go []byte 字面量', out: outGoLiteral, inFn: null };
  OUT_FORMATS.rustliteral = { label: 'Rust 数组字面量', out: outRustLiteral, inFn: null };
}

/* ---- 新增两种可逆输出格式 ---- */
function outJsonArr(b) { return '[' + Array.from(b).join(', ') + ']'; }
function inJsonArr(s) {
  var a = JSON.parse(String(s || '').trim());
  if (!Array.isArray(a)) throw new Error('JSON 数组格式应为 [1, 2, 3]');
  a.forEach(function (x) { if (!(x >= 0 && x <= 255)) throw new Error('数组元素需在 0~255'); });
  return new Uint8Array(a);
}
function outMime64(b) { return bytesToBase64(b).replace(/(.{76})/g, '$1\n'); }
function inMime64(s) { return base64ToBytes(String(s || '').replace(/\s+/g, '')); }
if (typeof OUT_FORMATS === 'object') {
  OUT_FORMATS.jsonarr = { label: 'JSON 数组 [1, 2, ..]', out: outJsonArr, inFn: inJsonArr };
  OUT_FORMATS.mime64 = { label: 'Base64（MIME 76 换行）', out: outMime64, inFn: inMime64 };
}
/* 重填「密文格式」下拉框：
   crypto_core.js 末尾的 initFmtSelect 在本文件之前执行，只装了 14 种基础格式；
   本文件合并进来的 9 种必须再填一次才会出现在界面上（此前一直选不到）。 */
(function refillFmtSelect() {
  if (typeof document === 'undefined' || !document.getElementById) return;
  var sel = document.getElementById('fmt');
  if (!sel || typeof OUT_FORMATS !== 'object') return;
  var cur = sel.value;
  sel.innerHTML = '';
  Object.keys(OUT_FORMATS).forEach(function (k) {
    var o = document.createElement('option');
    o.value = k; o.textContent = OUT_FORMATS[k].label;
    sel.appendChild(o);
  });
  sel.value = OUT_FORMATS[cur] ? cur : 'base64';
})();
