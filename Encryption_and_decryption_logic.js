'use strict';

/* ============================================================
 * 版本、正式名与代号
 * ------------------------------------------------------------
 * 正式名 Aegis（埃癸斯）：希腊神话中宙斯与雅典娜所持的神盾，守护之意。
 *   缩写 AGS，界面角落以小字展示。
 *   ARGUS（阿格斯·百眼）是本项目最初的 v0.x 内部代号，因"100 个算法"
 *   而起；如今算法早已过百，仅保留在 CHANGELOG 与此处注释中，不再对外展示。
 *
 * ⚠ 改名时记得同步三处：本文件常量、index.html 的版本徽章与版本卡、
 *   CHANGELOG 的版本表。曾因只改一处导致界面与常量不一致。
 * ============================================================ */
var APP_VERSION = '1.0.0';
var APP_NAME = 'Aegis';
var APP_CODENAME = 'AGS';
var APP_TAGLINE = '149 种算法 · 零外部依赖';
var BUILD_INFO = { algos: 268, stress: 2222, selfTest: 43 };


/* ============================================================
 * 全局错误
 * ============================================================ */
(function () {
  function show(msg, line) {
    var el = document.getElementById('globalError');
    if (!el) return;
    el.classList.remove('hidden');
    el.textContent = '脚本错误：' + msg + (line ? '（行 ' + line + '）' : '');
  }
  window.onerror = function (msg, src, line) { show(msg, line); return false; };
  window.addEventListener('unhandledrejection', function (e) {
    var r = e.reason;
    show('异步错误：' + (r && r.message ? r.message : String(r)), 0);
  });
})();

/* ============================================================
 * 基础
 * ============================================================ */
var textEnc = new TextEncoder();
var textDec = new TextDecoder('utf-8');
/* 传入 Uint8Array 时直接返回，不要走 TextEncoder——
   否则 encode() 会先把它转成 "233,154,143" 这种逗号分隔字符串，静默产出垃圾字节 */
function strToBytes(s) { return s instanceof Uint8Array ? s : textEnc.encode(s); }
function bytesToStr(b) { return textDec.decode(b); }

function bytesToHex(bytes) {
  var s = '';
  for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}
function hexToBytes(hex) {
  var clean = String(hex).replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2) clean = '0' + clean;
  var out = new Uint8Array(clean.length / 2);
  for (var i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}
function bytesToBase64(bytes) {
  var s = '', CH = 0x8000;
  for (var i = 0; i < bytes.length; i += CH) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  return btoa(s);
}
function base64ToBytes(b64) {
  var s = String(b64).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  var bin = atob(s);
  var out = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
/* ⚠ 本函数历史上是【只收 2 个参数】的版本，导致调用处写 concatBytes(a,b,c) 时
   第三个参数被静默丢弃 —— 且不报错。这在本项目里已经踩了三次：
     Argon2 的密钥拼接、ML-KEM 的密文（丢了 c2 和 ρ）、BIP-340 的 nonce（丢了 msg）。
   现在改成可变参数，从根上杜绝。两参数调用行为完全不变。 */
function concatBytes() {
  var i, total = 0;
  for (i = 0; i < arguments.length; i++) total += arguments[i].length;
  var out = new Uint8Array(total), o = 0;
  for (i = 0; i < arguments.length; i++) { out.set(arguments[i], o); o += arguments[i].length; }
  return out;
}

function readU32LE(b, o) { return (b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)) >>> 0; }
function readU32BE(b, o) { return ((b[o]<<24) | (b[o+1]<<16) | (b[o+2]<<8) | b[o+3]) >>> 0; }
function writeU32LE(v, b, o) { b[o]=v&255; b[o+1]=(v>>>8)&255; b[o+2]=(v>>>16)&255; b[o+3]=(v>>>24)&255; }
function writeU32BE(v, b, o) { b[o]=(v>>>24)&255; b[o+1]=(v>>>16)&255; b[o+2]=(v>>>8)&255; b[o+3]=v&255; }

function rotl32(x, n) { n &= 31; return ((x << n) | (x >>> (32 - n))) >>> 0; }
function rotr32(x, n) { n &= 31; return ((x >>> n) | (x << (32 - n))) >>> 0; }

/* saltHex / evpMode 由 crypto_modes.js 的容器格式驱动：
   evpMode='sha256'|'md5' 时走 EVP_BytesToKey（与 OpenSSL / CryptoJS 互通），
   否则把 salt 混进普通派生。 */
async function deriveKeyBytes(keyStr, len, saltBytes, evpMode) {
  if (evpMode && typeof evpBytesToKey === 'function' && saltBytes && saltBytes.length) {
    var r = evpBytesToKey(keyStr || '', saltBytes, len, 0, evpMode === 'md5');
    return new Uint8Array(r.key);
  }
  if (typeof deriveKeyFromPassword === 'function') {
    /* 用 Salt 框里的值当 KDF 盐：留空时由 KDF 生成并回写到 Salt 框（与 IV 一致），
       保证解密时能拿到同一个盐 */
    var d = await deriveKeyFromPassword(keyStr, len, saltBytes);
    window._lastKdfTag = d.kdfTag;
    window._lastKdfSalt = d.salt;
    return d.key;
  }
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto');
  var src = (saltBytes && saltBytes.length) ? concatBytes(saltBytes, strToBytes(keyStr || '')) : strToBytes(keyStr || '');
  var digest = await crypto.subtle.digest('SHA-256', src);
  var full = new Uint8Array(digest);
  var out = new Uint8Array(len);
  for (var i = 0; i < len; i++) out[i] = full[i % full.length];
  return out;
}

/* ============================================================
 * 填充
 * ============================================================ */
function padPKCS7(data, bs) {
  var p = bs - (data.length % bs);
  var out = new Uint8Array(data.length + p);
  out.set(data);
  for (var i = data.length; i < out.length; i++) out[i] = p;
  return out;
}
function unpadPKCS7(data, bs) {
  if (data.length === 0) return data;
  var p = data[data.length - 1];
  if (p === 0 || p > bs || p > data.length) throw new Error('填充无效，密钥或数据可能不正确');
  for (var i = data.length - p; i < data.length; i++) if (data[i] !== p) throw new Error('填充无效，密钥或数据可能不正确');
  return data.subarray(0, data.length - p);
}
function padZero(data, bs) {
  if (data.length % bs === 0) return data;
  var p = bs - (data.length % bs);
  var out = new Uint8Array(data.length + p);
  out.set(data);
  return out;
}
function unpadZero(data) {
  var end = data.length;
  while (end > 0 && data[end - 1] === 0) end--;
  return data.subarray(0, end);
}
function padNone(data, bs) {
  if (data.length % bs !== 0) throw new Error('无填充模式下，数据长度必须是块大小 ' + bs + ' 的整数倍');
  return data;
}
function applyPad(data, bs, mode) {
  if (typeof applyPadEx === 'function') return applyPadEx(data, bs, mode);
  if (mode === 'PKCS7') return padPKCS7(data, bs);
  if (mode === 'Zero') return padZero(data, bs);
  if (mode === 'None') return padNone(data, bs);
  throw new Error('未知填充: ' + mode);
}
function applyUnpad(data, bs, mode) {
  if (typeof applyUnpadEx === 'function') return applyUnpadEx(data, bs, mode);
  if (mode === 'PKCS7') return unpadPKCS7(data, bs);
  if (mode === 'Zero') return unpadZero(data);
  if (mode === 'None') return data;
  throw new Error('未知填充: ' + mode);
}

/* ============================================================
 * 分组模式（blockFn / invBlockFn 都是 单块 加/解密）
 * ============================================================ */
function ecbEnc(plain, bs, blockFn, padMode) {
  var d = applyPad(plain, bs, padMode);
  var out = new Uint8Array(d.length);
  for (var o = 0; o < d.length; o += bs) out.set(blockFn(d.subarray(o, o + bs)), o);
  return out;
}
function ecbDec(cipher, bs, invFn, padMode) {
  if (cipher.length % bs !== 0) throw new Error('密文长度不是块大小整数倍');
  var out = new Uint8Array(cipher.length);
  for (var o = 0; o < cipher.length; o += bs) out.set(invFn(cipher.subarray(o, o + bs)), o);
  return applyUnpad(out, bs, padMode);
}
function cbcEnc(plain, bs, blockFn, padMode, iv) {
  var d = applyPad(plain, bs, padMode);
  var out = new Uint8Array(d.length);
  var prev = iv;
  for (var o = 0; o < d.length; o += bs) {
    var b = new Uint8Array(bs);
    for (var i = 0; i < bs; i++) b[i] = d[o + i] ^ prev[i];
    var e = blockFn(b);
    out.set(e, o);
    prev = e;
  }
  return out;
}
/* ============================================================
 * 大文件分片处理：协作式让出 + 进度 + 取消
 *
 * 原实现一次性跑完整条数据，几 MB 就会把页面卡死到无法操作、也无法中止。
 * 这里【新增】一套异步分片路径（modeEncAsync / modeDecAsync），
 * 只在数据量超过 CHUNK_THRESHOLD 时使用；小数据仍走原同步函数，
 * 因此既有 2222 项测试的结果不受影响。
 *
 * 分片边界严格对齐块大小，且模式内部状态（CBC 的 prev、CFB/OFB 的
 * 移位寄存器、CTR 的计数器）在片间完整传递 —— 输出与同步版逐字节一致。
 * ============================================================ */
var CHUNK_THRESHOLD = 256 * 1024;   /* 超过 256KB 才启用分片 */
var CHUNK_BLOCKS = 2048;            /* 每次让出前处理的块数 */
var JOB = { running: false, cancel: false, pct: 0 };

function yieldToUI() {
  return new Promise(function (res) {
    if (typeof requestAnimationFrame === 'function') requestAnimationFrame(function () { res(); });
    else setTimeout(res, 0);
  });
}
function jobStart() { JOB.running = true; JOB.cancel = false; JOB.pct = 0; setProgress(0, '准备中…'); }
function jobEnd() { JOB.running = false; JOB.cancel = false; setProgress(100, ''); }
function jobCancel() { if (JOB.running) { JOB.cancel = true; setMsg('正在取消…', 'err'); } }
function setProgress(pct, label) {
  JOB.pct = pct;
  var bar = document.getElementById('progBar');
  var box = document.getElementById('progBox');
  var txt = document.getElementById('progText');
  var btn = document.getElementById('btnCancel');
  if (box) box.classList.toggle('hidden', !JOB.running && pct >= 100);
  if (bar) bar.style.width = Math.max(0, Math.min(100, pct)) + '%';
  if (txt) txt.textContent = label || (pct + '%');
  if (btn) btn.classList.toggle('hidden', !JOB.running);
}
async function chunkStep(done, total, bs) {
  if (JOB.cancel) throw new Error('__CANCELLED__');
  setProgress(total ? Math.floor(done * 100 / total) : 0, null);
  await yieldToUI();
}

/* ---- 加密：ECB / CBC / CFB / OFB / CTR ----
   签名与同步版 modeEnc(plain, bs, blockFn, mode, padMode, iv) 完全一致。
   （第一版我把 mode 与 padMode 写反了，且 CFB/CTR 的语义没对齐，
     同步/异步会算出不同结果 —— 必须与同步版逐行镜像。） */
async function modeEncAsync(plain, bs, blockFn, mode, padMode, iv) {
  var total, i, j, o, len, ks;
  if (mode === 'ECB') {
    var d = applyPad(plain, bs, padMode);
    var out = new Uint8Array(d.length);
    total = d.length;
    for (o = 0; o < d.length; o += bs) {
      out.set(blockFn(d.subarray(o, o + bs)), o);
      if ((o / bs + 1) % CHUNK_BLOCKS === 0) await chunkStep(o + bs, total, bs);
    }
    return out;
  }
  if (mode === 'CBC') {
    var d2 = applyPad(plain, bs, padMode);
    var out2 = new Uint8Array(d2.length);
    total = d2.length;
    var prev = iv, b = new Uint8Array(bs);
    for (o = 0; o < d2.length; o += bs) {
      for (i = 0; i < bs; i++) b[i] = d2[o + i] ^ prev[i];
      var e = blockFn(b);
      out2.set(e, o);
      prev = e;
      if ((o / bs + 1) % CHUNK_BLOCKS === 0) await chunkStep(o + bs, total, bs);
    }
    return out2;
  }
  if (mode === 'CFB') {
    var out3 = new Uint8Array(plain.length);
    total = plain.length;
    var prev3 = iv;
    for (o = 0; o < plain.length; o += bs) {
      ks = blockFn(prev3);
      len = Math.min(bs, plain.length - o);
      var c = new Uint8Array(len);
      for (i = 0; i < len; i++) c[i] = plain[o + i] ^ ks[i];
      out3.set(c, o);
      /* 注意：末块不足时，剩余字节取的是【上一个 prev】，不是密钥流 */
      var next = new Uint8Array(bs);
      next.set(c);
      for (j = len; j < bs; j++) next[j] = prev3[j];
      prev3 = next;
      if ((o / bs + 1) % CHUNK_BLOCKS === 0) await chunkStep(o + bs, total, bs);
    }
    return out3;
  }
  if (mode === 'OFB') {
    var out4 = new Uint8Array(plain.length);
    total = plain.length;
    var prev4 = iv;
    for (o = 0; o < plain.length; o += bs) {
      ks = blockFn(prev4);
      len = Math.min(bs, plain.length - o);
      for (i = 0; i < len; i++) out4[o + i] = plain[o + i] ^ ks[i];
      prev4 = ks;
      if ((o / bs + 1) % CHUNK_BLOCKS === 0) await chunkStep(o + bs, total, bs);
    }
    return out4;
  }
  if (mode === 'CTR') {
    var out5 = new Uint8Array(plain.length);
    total = plain.length;
    /* CTR 的块输入是 IV【异或一个独立计数器】，不是把 IV 自增 */
    var ctr = new Uint8Array(bs);
    for (o = 0; o < plain.length; o += bs) {
      var cb = new Uint8Array(bs);
      for (i = 0; i < bs; i++) cb[i] = iv[i] ^ ctr[i];
      ks = blockFn(cb);
      len = Math.min(bs, plain.length - o);
      for (j = 0; j < len; j++) out5[o + j] = plain[o + j] ^ ks[j];
      for (var k = bs - 1; k >= 0; k--) { if (++ctr[k] !== 0) break; }
      if ((o / bs + 1) % CHUNK_BLOCKS === 0) await chunkStep(o + bs, total, bs);
    }
    return out5;
  }
  throw new Error('未知模式: ' + mode);
}

async function modeDecAsync(cipher, bs, invFn, mode, padMode, iv, encFn) {
  var total, i, j, o, len, ks;
  if (mode === 'ECB') {
    if (cipher.length % bs !== 0) throw new Error('密文长度不是块大小整数倍');
    var out = new Uint8Array(cipher.length);
    total = cipher.length;
    for (o = 0; o < cipher.length; o += bs) {
      out.set(invFn(cipher.subarray(o, o + bs)), o);
      if ((o / bs + 1) % CHUNK_BLOCKS === 0) await chunkStep(o + bs, total, bs);
    }
    return applyUnpad(out, bs, padMode);
  }
  if (mode === 'CBC') {
    if (cipher.length % bs !== 0) throw new Error('密文长度不是块大小整数倍');
    var out2 = new Uint8Array(cipher.length);
    total = cipher.length;
    var prev = iv;
    for (o = 0; o < cipher.length; o += bs) {
      var blk = cipher.subarray(o, o + bs);
      var p = invFn(blk);
      for (i = 0; i < bs; i++) out2[o + i] = p[i] ^ prev[i];
      prev = blk.slice();
      if ((o / bs + 1) % CHUNK_BLOCKS === 0) await chunkStep(o + bs, total, bs);
    }
    return applyUnpad(out2, bs, padMode);
  }
  var streamFn = encFn || invFn;
  if (mode === 'CFB') {
    var out3 = new Uint8Array(cipher.length);
    total = cipher.length;
    var prev3 = iv;
    for (o = 0; o < cipher.length; o += bs) {
      ks = streamFn(prev3);
      len = Math.min(bs, cipher.length - o);
      for (i = 0; i < len; i++) out3[o + i] = cipher[o + i] ^ ks[i];
      var next = new Uint8Array(bs);
      next.set(cipher.subarray(o, o + len));
      for (j = len; j < bs; j++) next[j] = prev3[j];
      prev3 = next;
      if ((o / bs + 1) % CHUNK_BLOCKS === 0) await chunkStep(o + bs, total, bs);
    }
    /* 与同步版一致：流模式不填充，因此解密后也不去填充 */
    return out3;
  }
  if (mode === 'OFB') {
    var out4 = new Uint8Array(cipher.length);
    total = cipher.length;
    var prev4 = iv;
    for (o = 0; o < cipher.length; o += bs) {
      ks = streamFn(prev4);
      len = Math.min(bs, cipher.length - o);
      for (i = 0; i < len; i++) out4[o + i] = cipher[o + i] ^ ks[i];
      prev4 = ks;
      if ((o / bs + 1) % CHUNK_BLOCKS === 0) await chunkStep(o + bs, total, bs);
    }
    return out4;
  }
  if (mode === 'CTR') {
    var out5 = new Uint8Array(cipher.length);
    total = cipher.length;
    var ctr = new Uint8Array(bs);
    for (o = 0; o < cipher.length; o += bs) {
      var cb = new Uint8Array(bs);
      for (i = 0; i < bs; i++) cb[i] = iv[i] ^ ctr[i];
      ks = streamFn(cb);
      len = Math.min(bs, cipher.length - o);
      for (j = 0; j < len; j++) out5[o + j] = cipher[o + j] ^ ks[j];
      for (var k = bs - 1; k >= 0; k--) { if (++ctr[k] !== 0) break; }
      if ((o / bs + 1) % CHUNK_BLOCKS === 0) await chunkStep(o + bs, total, bs);
    }
    return out5;
  }
  throw new Error('未知模式: ' + mode);
}
function blockFnSafe(fn, x) { return fn(x); }

function cbcDec(cipher, bs, invFn, padMode, iv) {
  if (cipher.length % bs !== 0) throw new Error('密文长度不是块大小整数倍');
  var out = new Uint8Array(cipher.length);
  var prev = iv;
  for (var o = 0; o < cipher.length; o += bs) {
    var blk = cipher.subarray(o, o + bs);
    var d = invFn(blk);
    for (var i = 0; i < bs; i++) out[o + i] = d[i] ^ prev[i];
    prev = blk;
  }
  return applyUnpad(out, bs, padMode);
}
function cfbEnc(plain, bs, blockFn, iv) {
  var out = new Uint8Array(plain.length);
  var prev = iv;
  for (var o = 0; o < plain.length; o += bs) {
    var ks = blockFn(prev);
    var len = Math.min(bs, plain.length - o);
    var c = new Uint8Array(len);
    for (var i = 0; i < len; i++) c[i] = plain[o + i] ^ ks[i];
    out.set(c, o);
    var next = new Uint8Array(bs);
    next.set(c);
    for (var j = len; j < bs; j++) next[j] = prev[j];
    prev = next;
  }
  return out;
}
function cfbDec(cipher, bs, blockFn, iv) {
  var out = new Uint8Array(cipher.length);
  var prev = iv;
  for (var o = 0; o < cipher.length; o += bs) {
    var ks = blockFn(prev);
    var len = Math.min(bs, cipher.length - o);
    for (var i = 0; i < len; i++) out[o + i] = cipher[o + i] ^ ks[i];
    var next = new Uint8Array(bs);
    next.set(cipher.subarray(o, o + len));
    for (var j = len; j < bs; j++) next[j] = prev[j];
    prev = next;
  }
  return out;
}
function ofbEnc(plain, bs, blockFn, iv) {
  var out = new Uint8Array(plain.length);
  var prev = iv;
  for (var o = 0; o < plain.length; o += bs) {
    var ks = blockFn(prev);
    var len = Math.min(bs, plain.length - o);
    for (var i = 0; i < len; i++) out[o + i] = plain[o + i] ^ ks[i];
    prev = ks;
  }
  return out;
}
function ofbDec(cipher, bs, blockFn, iv) { return ofbEnc(cipher, bs, blockFn, iv); }
function ctrEnc(plain, bs, blockFn, iv) {
  var out = new Uint8Array(plain.length);
  var ctr = new Uint8Array(bs);
  for (var o = 0; o < plain.length; o += bs) {
    var cb = new Uint8Array(bs);
    for (var i = 0; i < bs; i++) cb[i] = iv[i] ^ ctr[i];
    var ks = blockFn(cb);
    var len = Math.min(bs, plain.length - o);
    for (var j = 0; j < len; j++) out[o + j] = plain[o + j] ^ ks[j];
    for (var k = bs - 1; k >= 0; k--) { if (++ctr[k] !== 0) break; }
  }
  return out;
}
function ctrDec(cipher, bs, blockFn, iv) { return ctrEnc(cipher, bs, blockFn, iv); }

function modeEnc(plain, bs, blockFn, mode, padMode, iv) {
  if (mode === 'ECB') return ecbEnc(plain, bs, blockFn, padMode);
  if (mode === 'CBC') return cbcEnc(plain, bs, blockFn, padMode, iv);
  if (mode === 'CFB') return cfbEnc(plain, bs, blockFn, iv);
  if (mode === 'OFB') return ofbEnc(plain, bs, blockFn, iv);
  if (mode === 'CTR') return ctrEnc(plain, bs, blockFn, iv);
  throw new Error('未知模式: ' + mode);
}
/* CFB / OFB / CTR 是流模式：解密同样要用「加密函数」生成密钥流，
   只有 ECB / CBC 才用解密函数。encFn 缺省时退回 invFn 以兼容旧调用。 */
function modeDec(cipher, bs, invFn, mode, padMode, iv, encFn) {
  if (mode === 'ECB') return ecbDec(cipher, bs, invFn, padMode);
  if (mode === 'CBC') return cbcDec(cipher, bs, invFn, padMode, iv);
  var streamFn = encFn || invFn;
  if (mode === 'CFB') return cfbDec(cipher, bs, streamFn, iv);
  if (mode === 'OFB') return ofbDec(cipher, bs, streamFn, iv);
  if (mode === 'CTR') return ctrDec(cipher, bs, streamFn, iv);
  throw new Error('未知模式: ' + mode);
}
var AEAD_MODES = ['GCM', 'CCM', 'SIV', 'EAX', 'OCB'];
var BLOCK_MODES = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'XTS'];
var NO_PAD_MODES = ['CFB', 'OFB', 'CTR', 'XTS', 'CFB8', 'CFB1', 'LRW', 'CTS-CS1', 'CTS-CS2', 'CTS-CS3'];
/* 需要 IV/tweak 的模式 */
function isAEAD(mode) { return AEAD_MODES.indexOf(mode) >= 0; }
function isCTS(mode) { return mode === 'CTS-CS1' || mode === 'CTS-CS2' || mode === 'CTS-CS3'; }
function modeUsesPadding(mode) { return NO_PAD_MODES.indexOf(mode) < 0 && !isAEAD(mode); }
/* AEAD 的 nonce 长度：GCM 12、CCM 13、SIV 0（确定性，无 nonce） */
function aeadNonceLen(mode) {
if (mode === 'GCM') return 12;
if (mode === 'CCM') return 13;
if (mode === 'EAX') return 16;
if (mode === 'OCB') return 12;
return 0;
}
function setSelectValue(sel, val) {
  if (!sel) return;
  for (var i = 0; i < sel.options.length; i++) {
    if (sel.options[i].value === val) { sel.selectedIndex = i; sel.value = val; return; }
  }
  sel.value = val;
}
/* 打开页面时默认选中的算法：AES-256（模式默认 GCM）。
   下拉框按注册顺序填充，第一位是 Base64，不显式设置就会停在编码类上。 */
var DEFAULT_ALGO_ID = 'aes256';

/* 模式是否被该算法支持。
   AEAD（GCM/CCM/EAX/OCB/SIV）目前的认证部分以 AES 原语实现，
   非 AES 算法不支持；XTS/LRW 只定义在 128 位块上。
   不做这个判定的话，默认模式 GCM 会让 Camellia / SM4 / ARIA / SEED 等
   一点「加密」就报错——是上一轮把默认改成 GCM 后引入的体验问题。 */
function modeSupportedBy(mode, algo) {
  if (!algo) return true;
  if (isAEAD(mode)) return /^aes/.test(algo.id);
  if (mode === 'XTS' || mode === 'LRW') return algo.blockSize === 16;
  return true;
}
/* 该算法下应回退到的安全默认模式 */
function fallbackModeFor(algo) {
  return 'CBC';
}
function modeNeedsIV(mode) { return mode !== 'ECB' && mode !== 'XTS' && !isAEAD(mode); }

/* IV 框在 XTS 下用作 tweak 输入，所以也要显示 */
function modeShowsIVField(mode) { return mode !== 'ECB'; }

/* ============================================================
 * AES 纯 JS 实现（支持 128/192/256）
 * ============================================================ */
var AES_SBOX = new Uint8Array(256);
var AES_INV_SBOX = new Uint8Array(256);
(function initAES() {
  var p = 1, q = 1;
  do {
    p = (p ^ (p << 1) ^ ((p & 0x80) ? 0x1B : 0)) & 0xFF;
    q ^= q << 1; q &= 0xFF;
    q ^= q << 2; q &= 0xFF;
    q ^= q << 4; q &= 0xFF;
    if (q & 0x80) q ^= 0x09;
    q &= 0xFF;
    var x = q ^ ((q << 1) | (q >>> 7)) ^ ((q << 2) | (q >>> 6)) ^ ((q << 3) | (q >>> 5)) ^ ((q << 4) | (q >>> 4));
    x &= 0xFF;
    AES_SBOX[p] = x ^ 0x63;
  } while (p !== 1);
  AES_SBOX[0] = 0x63;
  for (var i = 0; i < 256; i++) AES_INV_SBOX[AES_SBOX[i]] = i;
})();

function aesSubWord(w) {
  return ((AES_SBOX[(w >>> 24) & 0xFF] << 24) |
          (AES_SBOX[(w >>> 16) & 0xFF] << 16) |
          (AES_SBOX[(w >>> 8) & 0xFF] << 8) |
          AES_SBOX[w & 0xFF]) >>> 0;
}
function aesXtime(b) { return ((b << 1) ^ ((b & 0x80) ? 0x1B : 0)) & 0xFF; }

function aesExpandKey(key) {
  var Nk = key.length / 4;
  var Nr = Nk + 6;
  var w = new Uint32Array(4 * (Nr + 1));
  for (var i = 0; i < Nk; i++) w[i] = readU32BE(key, i * 4);
  var Rcon = 1;
  for (var j = Nk; j < 4 * (Nr + 1); j++) {
    var t = w[j - 1];
    if (j % Nk === 0) {
      t = ((t << 8) | (t >>> 24)) >>> 0;
      t = (aesSubWord(t) ^ (Rcon << 24)) >>> 0;
      Rcon = aesXtime(Rcon);
    } else if (Nk > 6 && j % Nk === 4) {
      t = aesSubWord(t);
    }
    w[j] = (w[j - Nk] ^ t) >>> 0;
  }
  return { w: w, Nr: Nr };
}

function aesAddRoundKey(state, w, round) {
  for (var i = 0; i < 4; i++) state[i] = (state[i] ^ w[round * 4 + i]) >>> 0;
}
function aesSubBytes(state) {
  for (var i = 0; i < 4; i++) {
    state[i] = ((AES_SBOX[(state[i] >>> 24) & 0xFF] << 24) |
                (AES_SBOX[(state[i] >>> 16) & 0xFF] << 16) |
                (AES_SBOX[(state[i] >>> 8) & 0xFF] << 8) |
                AES_SBOX[state[i] & 0xFF]) >>> 0;
  }
}
function aesInvSubBytes(state) {
  for (var i = 0; i < 4; i++) {
    state[i] = ((AES_INV_SBOX[(state[i] >>> 24) & 0xFF] << 24) |
                (AES_INV_SBOX[(state[i] >>> 16) & 0xFF] << 16) |
                (AES_INV_SBOX[(state[i] >>> 8) & 0xFF] << 8) |
                AES_INV_SBOX[state[i] & 0xFF]) >>> 0;
  }
}
function aesShiftRows(state) {
  var t0 = state[0], t1 = state[1], t2 = state[2], t3 = state[3];
  state[0] = ((t0 & 0xFF000000) | (t1 & 0x00FF0000) | (t2 & 0x0000FF00) | (t3 & 0x000000FF)) >>> 0;
  state[1] = ((t1 & 0xFF000000) | (t2 & 0x00FF0000) | (t3 & 0x0000FF00) | (t0 & 0x000000FF)) >>> 0;
  state[2] = ((t2 & 0xFF000000) | (t3 & 0x00FF0000) | (t0 & 0x0000FF00) | (t1 & 0x000000FF)) >>> 0;
  state[3] = ((t3 & 0xFF000000) | (t0 & 0x00FF0000) | (t1 & 0x0000FF00) | (t2 & 0x000000FF)) >>> 0;
}
function aesInvShiftRows(state) {
  var t0 = state[0], t1 = state[1], t2 = state[2], t3 = state[3];
  state[0] = ((t0 & 0xFF000000) | (t3 & 0x00FF0000) | (t2 & 0x0000FF00) | (t1 & 0x000000FF)) >>> 0;
  state[1] = ((t1 & 0xFF000000) | (t0 & 0x00FF0000) | (t3 & 0x0000FF00) | (t2 & 0x000000FF)) >>> 0;
  state[2] = ((t2 & 0xFF000000) | (t1 & 0x00FF0000) | (t0 & 0x0000FF00) | (t3 & 0x000000FF)) >>> 0;
  state[3] = ((t3 & 0xFF000000) | (t2 & 0x00FF0000) | (t1 & 0x0000FF00) | (t0 & 0x000000FF)) >>> 0;
}
function gmul(a, b) {
  var p = 0;
  for (var i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    var hi = a & 0x80;
    a = (a << 1) & 0xFF;
    if (hi) a ^= 0x1B;
    b >>= 1;
  }
  return p;
}
/* GF(2^8) 乘法表：原实现在 MixColumns / InvMixColumns 里逐位调用 gmul，
   加密每个块每轮 48 次、解密 64 次，每次 8 次循环 —— 这是 AES 慢的主因。
   改为 256 项查表后，整轮只剩异或。
   表由 gmul 自身在加载时生成，因此与旧行为严格等价，不会引入偏差。 */
var AES_MUL = {};
(function () {
  var need = [2, 3, 9, 11, 13, 14];
  for (var k = 0; k < need.length; k++) {
    var m = need[k], t = new Uint8Array(256);
    for (var i = 0; i < 256; i++) t[i] = gmul(i, m);
    AES_MUL[m] = t;
  }
})();

function aesMixColumns(state) {
  for (var c = 0; c < 4; c++) {
    var i = c * 4;
    var s0 = (state[i >> 2] >>> (24 - (i & 3) * 8)) & 0xFF;
  }
  var M2 = AES_MUL[2], M3 = AES_MUL[3];
  function mixCol(a0, a1, a2, a3) {
    return [
      M2[a0] ^ M3[a1] ^ a2 ^ a3,
      a0 ^ M2[a1] ^ M3[a2] ^ a3,
      a0 ^ a1 ^ M2[a2] ^ M3[a3],
      M3[a0] ^ a1 ^ a2 ^ M2[a3]
    ];
  }
  var tmp = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  for (var i = 0; i < 4; i++) {
    tmp[i * 4 + 0] = (state[i] >>> 24) & 0xFF;
    tmp[i * 4 + 1] = (state[i] >>> 16) & 0xFF;
    tmp[i * 4 + 2] = (state[i] >>> 8) & 0xFF;
    tmp[i * 4 + 3] = state[i] & 0xFF;
  }
  for (var c = 0; c < 4; c++) {
    var b0 = tmp[c * 4], b1 = tmp[c * 4 + 1], b2 = tmp[c * 4 + 2], b3 = tmp[c * 4 + 3];
    var r = mixCol(b0, b1, b2, b3);
    tmp[c * 4] = r[0]; tmp[c * 4 + 1] = r[1]; tmp[c * 4 + 2] = r[2]; tmp[c * 4 + 3] = r[3];
  }
  for (var j = 0; j < 4; j++) {
    state[j] = ((tmp[j * 4] << 24) | (tmp[j * 4 + 1] << 16) | (tmp[j * 4 + 2] << 8) | tmp[j * 4 + 3]) >>> 0;
  }
}
function aesInvMixColumns(state) {
  var M9 = AES_MUL[9], M11 = AES_MUL[11], M13 = AES_MUL[13], M14 = AES_MUL[14];
  function invMixCol(a0, a1, a2, a3) {
    return [
      M14[a0] ^ M11[a1] ^ M13[a2] ^ M9[a3],
      M9[a0] ^ M14[a1] ^ M11[a2] ^ M13[a3],
      M13[a0] ^ M9[a1] ^ M14[a2] ^ M11[a3],
      M11[a0] ^ M13[a1] ^ M9[a2] ^ M14[a3]
    ];
  }
  var tmp = new Array(16);
  for (var i = 0; i < 4; i++) {
    tmp[i * 4 + 0] = (state[i] >>> 24) & 0xFF;
    tmp[i * 4 + 1] = (state[i] >>> 16) & 0xFF;
    tmp[i * 4 + 2] = (state[i] >>> 8) & 0xFF;
    tmp[i * 4 + 3] = state[i] & 0xFF;
  }
  for (var c = 0; c < 4; c++) {
    var r = invMixCol(tmp[c*4], tmp[c*4+1], tmp[c*4+2], tmp[c*4+3]);
    tmp[c*4] = r[0]; tmp[c*4+1] = r[1]; tmp[c*4+2] = r[2]; tmp[c*4+3] = r[3];
  }
  for (var j = 0; j < 4; j++) {
    state[j] = ((tmp[j*4] << 24) | (tmp[j*4+1] << 16) | (tmp[j*4+2] << 8) | tmp[j*4+3]) >>> 0;
  }
}
/* 参考实现（逐步 SubBytes/ShiftRows/MixColumns），保留用于等价对照与回归。
   ⚠ 慢的原因：aesMixColumns 每轮要建 16 元素 JS 数组 + 4 个 4 元素数组（mixCol 返回），
     即每块每轮 5 次分配；10 轮就是 50 次。下面 T-table 版本完全无分配。 */
function aesEncryptBlockJSRef(block, ks) {
  var state = [readU32BE(block, 0), readU32BE(block, 4), readU32BE(block, 8), readU32BE(block, 12)];
  aesAddRoundKey(state, ks.w, 0);
  for (var r = 1; r < ks.Nr; r++) {
    aesSubBytes(state);
    aesShiftRows(state);
    aesMixColumns(state);
    aesAddRoundKey(state, ks.w, r);
  }
  aesSubBytes(state);
  aesShiftRows(state);
  aesAddRoundKey(state, ks.w, ks.Nr);
  var out = new Uint8Array(16);
  writeU32BE(state[0], out, 0);
  writeU32BE(state[1], out, 4);
  writeU32BE(state[2], out, 8);
  writeU32BE(state[3], out, 12);
  return out;
}
function aesDecryptBlockJSRef(block, ks) {
  var state = [readU32BE(block, 0), readU32BE(block, 4), readU32BE(block, 8), readU32BE(block, 12)];
  aesAddRoundKey(state, ks.w, ks.Nr);
  for (var r = ks.Nr - 1; r >= 1; r--) {
    aesInvShiftRows(state);
    aesInvSubBytes(state);
    aesAddRoundKey(state, ks.w, r);
    aesInvMixColumns(state);
  }
  aesInvShiftRows(state);
  aesInvSubBytes(state);
  aesAddRoundKey(state, ks.w, 0);
  var out = new Uint8Array(16);
  writeU32BE(state[0], out, 0);
  writeU32BE(state[1], out, 4);
  writeU32BE(state[2], out, 8);
  writeU32BE(state[3], out, 12);
  return out;
}
/* ---------------- 快速路径：经典 T-table ----------------
 * 把 SubBytes + ShiftRows + MixColumns 三步压进 4 张 256 项 32 位表：
 *   T0[x] = (2·S(x)<<24)|(S(x)<<16)|(S(x)<<8)|(3·S(x))
 *   T1..T3 是 T0 的字节循环移位（对应 ShiftRows 的行偏移）
 * 于是每轮只剩 16 次查表 + 16 次异或，且【零分配】（不再有 tmp/mixCol 数组）。
 * 末轮没有 MixColumns，改用 S 盒直接拼 32 位字。
 *
 * 解密要额外处理一处：标准解密轮的次序是 AddRoundKey 在 InvMixColumns 【之前】，
 * 而 T-table 把两者合在了一起。利用 InvMixColumns 的线性性
 *   InvMixColumns(A ^ B) = InvMixColumns(A) ^ InvMixColumns(B)
 * 预先把中间轮密钥过一遍 InvMixColumns（等价逆密码，FIPS 197 的做法），
 * 首轮与末轮仍用原轮密钥。结果缓存在 ks._wi 上。
 *
 * 表由 AES_SBOX / AES_INV_SBOX 与 gmul 在加载时生成，与参考实现严格等价。 */
var AES_T0 = null, AES_T1 = null, AES_T2 = null, AES_T3 = null;
var AES_IT0 = null, AES_IT1 = null, AES_IT2 = null, AES_IT3 = null;
function aesBuildTables() {
  if (AES_T0) return;
  var M2 = AES_MUL[2], M3 = AES_MUL[3], M9 = AES_MUL[9], M11 = AES_MUL[11], M13 = AES_MUL[13], M14 = AES_MUL[14];
  AES_T0 = new Uint32Array(256); AES_T1 = new Uint32Array(256); AES_T2 = new Uint32Array(256); AES_T3 = new Uint32Array(256);
  AES_IT0 = new Uint32Array(256); AES_IT1 = new Uint32Array(256); AES_IT2 = new Uint32Array(256); AES_IT3 = new Uint32Array(256);
  for (var x = 0; x < 256; x++) {
    var s = AES_SBOX[x], si = AES_INV_SBOX[x];
    var s2 = M2[s], s3 = M3[s];
    AES_T0[x] = ((s2 << 24) | (s << 16) | (s << 8) | s3) >>> 0;
    AES_T1[x] = ((s3 << 24) | (s2 << 16) | (s << 8) | s) >>> 0;
    AES_T2[x] = ((s << 24) | (s3 << 16) | (s2 << 8) | s) >>> 0;
    AES_T3[x] = ((s << 24) | (s << 16) | (s3 << 8) | s2) >>> 0;
    var i9 = M9[si], i11 = M11[si], i13 = M13[si], i14 = M14[si];
    AES_IT0[x] = ((i14 << 24) | (i9 << 16) | (i13 << 8) | i11) >>> 0;
    AES_IT1[x] = ((i11 << 24) | (i14 << 16) | (i9 << 8) | i13) >>> 0;
    AES_IT2[x] = ((i13 << 24) | (i11 << 16) | (i14 << 8) | i9) >>> 0;
    AES_IT3[x] = ((i9 << 24) | (i13 << 16) | (i11 << 8) | i14) >>> 0;
  }
}
/* 对 4 个 32 位字做 InvMixColumns（用于变换中间轮密钥） */
function aesInvMixColumnsWords(a) {
  var M9 = AES_MUL[9], M11 = AES_MUL[11], M13 = AES_MUL[13], M14 = AES_MUL[14], c;
  for (c = 0; c < 4; c++) {
    var w = a[c];
    var b0 = (w >>> 24) & 255, b1 = (w >>> 16) & 255, b2 = (w >>> 8) & 255, b3 = w & 255;
    a[c] = ((M14[b0] ^ M11[b1] ^ M13[b2] ^ M9[b3]) << 24 |
            (M9[b0] ^ M14[b1] ^ M11[b2] ^ M13[b3]) << 16 |
            (M13[b0] ^ M9[b1] ^ M14[b2] ^ M11[b3]) << 8 |
            (M11[b0] ^ M13[b1] ^ M9[b2] ^ M14[b3])) >>> 0;
  }
}
function aesDecRoundKeys(ks) {
  if (ks._wi) return ks._wi;
  var wi = new Uint32Array(ks.w.length);
  wi.set(ks.w);
  for (var r = 1; r < ks.Nr; r++) {
    var q = new Uint32Array(4), i;
    for (i = 0; i < 4; i++) q[i] = ks.w[r * 4 + i];
    aesInvMixColumnsWords(q);
    for (i = 0; i < 4; i++) wi[r * 4 + i] = q[i];
  }
  ks._wi = wi;
  return wi;
}
function aesEncryptBlockJS(block, ks) {
  aesBuildTables();
  var w = ks.w, Nr = ks.Nr;
  var T0 = AES_T0, T1 = AES_T1, T2 = AES_T2, T3 = AES_T3, SB = AES_SBOX;
  var s0 = (readU32BE(block, 0) ^ w[0]) >>> 0, s1 = (readU32BE(block, 4) ^ w[1]) >>> 0,
      s2 = (readU32BE(block, 8) ^ w[2]) >>> 0, s3 = (readU32BE(block, 12) ^ w[3]) >>> 0;
  var r, o, n0, n1, n2, n3;
  for (r = 1; r < Nr; r++) {
    o = r * 4;
    n0 = T0[(s0 >>> 24) & 255] ^ T1[(s1 >>> 16) & 255] ^ T2[(s2 >>> 8) & 255] ^ T3[s3 & 255] ^ w[o];
    n1 = T0[(s1 >>> 24) & 255] ^ T1[(s2 >>> 16) & 255] ^ T2[(s3 >>> 8) & 255] ^ T3[s0 & 255] ^ w[o + 1];
    n2 = T0[(s2 >>> 24) & 255] ^ T1[(s3 >>> 16) & 255] ^ T2[(s0 >>> 8) & 255] ^ T3[s1 & 255] ^ w[o + 2];
    n3 = T0[(s3 >>> 24) & 255] ^ T1[(s0 >>> 16) & 255] ^ T2[(s1 >>> 8) & 255] ^ T3[s2 & 255] ^ w[o + 3];
    s0 = n0 >>> 0; s1 = n1 >>> 0; s2 = n2 >>> 0; s3 = n3 >>> 0;
  }
  /* 末轮无 MixColumns */
  o = Nr * 4;
  n0 = ((SB[(s0 >>> 24) & 255] << 24) | (SB[(s1 >>> 16) & 255] << 16) | (SB[(s2 >>> 8) & 255] << 8) | SB[s3 & 255]) ^ w[o];
  n1 = ((SB[(s1 >>> 24) & 255] << 24) | (SB[(s2 >>> 16) & 255] << 16) | (SB[(s3 >>> 8) & 255] << 8) | SB[s0 & 255]) ^ w[o + 1];
  n2 = ((SB[(s2 >>> 24) & 255] << 24) | (SB[(s3 >>> 16) & 255] << 16) | (SB[(s0 >>> 8) & 255] << 8) | SB[s1 & 255]) ^ w[o + 2];
  n3 = ((SB[(s3 >>> 24) & 255] << 24) | (SB[(s0 >>> 16) & 255] << 16) | (SB[(s1 >>> 8) & 255] << 8) | SB[s2 & 255]) ^ w[o + 3];
  var out = new Uint8Array(16);
  writeU32BE(n0 >>> 0, out, 0); writeU32BE(n1 >>> 0, out, 4);
  writeU32BE(n2 >>> 0, out, 8); writeU32BE(n3 >>> 0, out, 12);
  return out;
}
function aesDecryptBlockJS(block, ks) {
  aesBuildTables();
  var w = ks.w, Nr = ks.Nr, W = aesDecRoundKeys(ks);
  var I0 = AES_IT0, I1 = AES_IT1, I2 = AES_IT2, I3 = AES_IT3, SI = AES_INV_SBOX;
  var s0 = (readU32BE(block, 0) ^ w[Nr * 4]) >>> 0, s1 = (readU32BE(block, 4) ^ w[Nr * 4 + 1]) >>> 0,
      s2 = (readU32BE(block, 8) ^ w[Nr * 4 + 2]) >>> 0, s3 = (readU32BE(block, 12) ^ w[Nr * 4 + 3]) >>> 0;
  var r, o, n0, n1, n2, n3;
  for (r = Nr - 1; r >= 1; r--) {
    o = r * 4;
    n0 = I0[(s0 >>> 24) & 255] ^ I1[(s3 >>> 16) & 255] ^ I2[(s2 >>> 8) & 255] ^ I3[s1 & 255] ^ W[o];
    n1 = I0[(s1 >>> 24) & 255] ^ I1[(s0 >>> 16) & 255] ^ I2[(s3 >>> 8) & 255] ^ I3[s2 & 255] ^ W[o + 1];
    n2 = I0[(s2 >>> 24) & 255] ^ I1[(s1 >>> 16) & 255] ^ I2[(s0 >>> 8) & 255] ^ I3[s3 & 255] ^ W[o + 2];
    n3 = I0[(s3 >>> 24) & 255] ^ I1[(s2 >>> 16) & 255] ^ I2[(s1 >>> 8) & 255] ^ I3[s0 & 255] ^ W[o + 3];
    s0 = n0 >>> 0; s1 = n1 >>> 0; s2 = n2 >>> 0; s3 = n3 >>> 0;
  }
  /* 末轮无 InvMixColumns，且用【原】轮密钥 w[0] */
  n0 = ((SI[(s0 >>> 24) & 255] << 24) | (SI[(s3 >>> 16) & 255] << 16) | (SI[(s2 >>> 8) & 255] << 8) | SI[s1 & 255]) ^ w[0];
  n1 = ((SI[(s1 >>> 24) & 255] << 24) | (SI[(s0 >>> 16) & 255] << 16) | (SI[(s3 >>> 8) & 255] << 8) | SI[s2 & 255]) ^ w[1];
  n2 = ((SI[(s2 >>> 24) & 255] << 24) | (SI[(s1 >>> 16) & 255] << 16) | (SI[(s0 >>> 8) & 255] << 8) | SI[s3 & 255]) ^ w[2];
  n3 = ((SI[(s3 >>> 24) & 255] << 24) | (SI[(s2 >>> 16) & 255] << 16) | (SI[(s1 >>> 8) & 255] << 8) | SI[s0 & 255]) ^ w[3];
  var out = new Uint8Array(16);
  writeU32BE(n0 >>> 0, out, 0); writeU32BE(n1 >>> 0, out, 4);
  writeU32BE(n2 >>> 0, out, 8); writeU32BE(n3 >>> 0, out, 12);
  return out;
}
function aesMakeBlockFn(keyBytes) {
  var ks = aesExpandKey(keyBytes);
  return {
    enc: function (b) { return aesEncryptBlockJS(b, ks); },
    dec: function (b) { return aesDecryptBlockJS(b, ks); }
  };
}

/* ============================================================
 * DES / 3DES
 * ============================================================ */
var DES_PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4];
var DES_PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32];
var DES_IP  = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7];
var DES_FP  = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25];
var DES_E   = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1];
var DES_P   = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25];
var DES_SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];
var DES_SBOX = [
  [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
  [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
  [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
  [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
  [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
  [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
  [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
  [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
];

function permuteBits(bits, table) {
  var out = new Array(table.length);
  for (var i = 0; i < table.length; i++) out[i] = bits[table[i] - 1];
  return out;
}
function bytesToBits(bytes) {
  var bits = new Array(bytes.length * 8);
  for (var i = 0; i < bytes.length; i++) for (var j = 0; j < 8; j++) bits[i*8+j] = (bytes[i] >> (7 - j)) & 1;
  return bits;
}
function bitsToBytes(bits) {
  var out = new Uint8Array(bits.length / 8);
  for (var i = 0; i < out.length; i++) {
    var v = 0;
    for (var j = 0; j < 8; j++) v = (v << 1) | bits[i*8+j];
    out[i] = v;
  }
  return out;
}
/* 预合成 SP 盒：S 盒输出直接按 P 置换摆到 32 位字里。
 * 这样一轮 F 只剩「取 8 个 6 位组 → 异或子密钥 → 8 次查表 → 按位或」，
 * 不再逐比特建数组。表由 DES_SBOX / DES_P 自身生成，与旧实现严格等价。
 * ⚠ 6 位组的取位有两处【跨边界环绕】（第 0 组含 bit32、第 7 组含 bit1），
 *   写成连续移位会静默算错，且仅在部分密钥/明文上暴露。 */
var DES_SP = (function () {
  var sp = [], i, g, j;
  for (i = 0; i < 8; i++) {
    var t = new Uint32Array(64);
    for (g = 0; g < 64; g++) {
      var row = ((g & 0x20) >> 4) | (g & 1);
      var col = (g >> 1) & 0x0f;
      var v = DES_SBOX[i][row * 16 + col];
      var acc = 0;
      for (j = 1; j <= 32; j++) {
        var src = DES_P[j - 1];
        if (((src - 1) >> 2) !== i) continue;      /* 该输出位不来自本 S 盒 */
        var bw = (src - 1) & 3;
        if ((v >> (3 - bw)) & 1) acc |= (1 << (32 - j));
      }
      t[g] = acc >>> 0;
    }
    sp.push(t);
  }
  return sp;
})();
/* 子密钥压成 16×8 个 6 位值（Uint8Array 128），与 48 位比特数组等价 */
function desSubkeysFast(keyBytes) {
  var kp = permuteBits(bytesToBits(keyBytes), DES_PC1);
  var C = kp.slice(0, 28), D = kp.slice(28, 56);
  var out = new Uint8Array(128), i, j;
  for (i = 0; i < 16; i++) {
    var s = DES_SHIFTS[i];
    C = C.slice(s).concat(C.slice(0, s));
    D = D.slice(s).concat(D.slice(0, s));
    var k48 = permuteBits(C.concat(D), DES_PC2);
    for (j = 0; j < 8; j++) {
      var g = 0, t;
      for (t = 0; t < 6; t++) g = (g << 1) | k48[j * 6 + t];
      out[i * 8 + j] = g;
    }
  }
  return out;
}
function desSubkeys(keyBytes) {
  var flat = desSubkeysFast(keyBytes), out = [], i, j, t;
  for (i = 0; i < 16; i++) {
    var a = new Array(48);
    for (j = 0; j < 8; j++) for (t = 0; t < 6; t++) a[j * 6 + t] = (flat[i * 8 + j] >> (5 - t)) & 1;
    out.push(a);
  }
  return out;
}
function desFeistel(R, sk) {
  var x = permuteBits(R, DES_E);
  for (var i = 0; i < 48; i++) x[i] ^= sk[i];
  var out = new Array(32);
  for (var ii = 0; ii < 8; ii++) {
    var b0 = x[ii*6], b1 = x[ii*6+1], b2 = x[ii*6+2], b3 = x[ii*6+3], b4 = x[ii*6+4], b5 = x[ii*6+5];
    var row = (b0 << 1) | b5;
    var col = (b1 << 3) | (b2 << 2) | (b3 << 1) | b4;
    var v = DES_SBOX[ii][row * 16 + col];
    for (var j = 0; j < 4; j++) out[ii*4+j] = (v >> (3 - j)) & 1;
  }
  return permuteBits(out, DES_P);
}
/* 32 位字 <-> 比特数组（bit1 = 最高位，与 DES 的编号一致） */
function desWord32(bits) {
  var v = 0, j;
  for (j = 0; j < 32; j++) v = (v << 1) | bits[j];
  return v >>> 0;
}
function desBits32(v) {
  var a = new Array(32), j;
  for (j = 0; j < 32; j++) a[j] = (v >>> (31 - j)) & 1;
  return a;
}
/* IP / FP 的字节查表版。
 * 原实现每块要走 bytesToBits → permuteBits → desWord32 ×2（IP）和
 * desBits32 ×2 → permuteBits → bitsToBytes（FP）：6 个临时数组、约 400 次
 * 逐比特搬运，比 16 轮 Feistel 本身还贵。
 * 这里把 64 位置换按【源字节】拆开预合成：
 *   IPL[p][v] / IPR[p][v] —— 输入第 p 字节取值为 v 时，对 L / R 的位贡献
 *   FPH[p][v] / FPL[p][v] —— 虚拟输入 (R‖L) 第 p 字节为 v 时，对输出高/低 32 位的贡献
 * 于是 IP 与 FP 各只需 16 次查表、零分配。
 * ⚠ 表由 DES_IP / DES_FP 自身在载入时生成（不硬编码），因此与逐比特版必然等价。 */
var DES_IPL = [], DES_IPR = [], DES_FPH = [], DES_FPL = [];
(function buildDesPermTables() {
  var p, v, j, s, bp, bt, m;
  for (p = 0; p < 8; p++) {
    DES_IPL[p] = new Uint32Array(256);
    DES_IPR[p] = new Uint32Array(256);
    DES_FPH[p] = new Uint32Array(256);
    DES_FPL[p] = new Uint32Array(256);
  }
  /* IP：out[j] = in[DES_IP[j]-1]；in 的第 s 位 = 第 (s>>3) 字节的 MSB-first 第 (s&7) 位 */
  for (j = 0; j < 64; j++) {
    s = DES_IP[j] - 1; bp = s >> 3; bt = s & 7;
    m = (1 << (j < 32 ? (31 - j) : (63 - j))) >>> 0;
    for (v = 0; v < 256; v++) {
      if (!((v >>> (7 - bt)) & 1)) continue;
      if (j < 32) DES_IPL[bp][v] |= m; else DES_IPR[bp][v] |= m;
    }
  }
  /* FP：out[j] = in[DES_FP[j]-1]；in = R‖L，各 32 位、MSB-first */
  for (j = 0; j < 64; j++) {
    s = DES_FP[j] - 1; bp = s >> 3; bt = s & 7;
    m = (1 << (j < 32 ? (31 - j) : (63 - j))) >>> 0;
    for (v = 0; v < 256; v++) {
      if (!((v >>> (7 - bt)) & 1)) continue;
      if (j < 32) DES_FPH[bp][v] |= m; else DES_FPL[bp][v] |= m;
    }
  }
})();
function desF32(R, k, off) {
  /* E 扩展：第 i 组取 R 的 bit(4i..4i+5)，组内 b0 是【最高】位。
   * 第 0 组 = bit32,bit1..bit5 —— 环绕位 bit32 落在组的【最高】位；
   * 第 7 组 = bit28..bit31,bit32,bit1 —— 两个环绕位在组的【低 2 位】。
   * ⚠ 这两处方向写反不会报错，只在部分密钥/明文上暴露，必须逐组核对 E 表。 */
  return (DES_SP[0][((((R >>> 27) & 0x1f)) | ((R & 1) << 5)) ^ k[off]] |
          DES_SP[1][(((R >>> 23) & 0x3f)) ^ k[off + 1]] |
          DES_SP[2][(((R >>> 19) & 0x3f)) ^ k[off + 2]] |
          DES_SP[3][(((R >>> 15) & 0x3f)) ^ k[off + 3]] |
          DES_SP[4][(((R >>> 11) & 0x3f)) ^ k[off + 4]] |
          DES_SP[5][(((R >>> 7) & 0x3f)) ^ k[off + 5]] |
          DES_SP[6][(((R >>> 3) & 0x3f)) ^ k[off + 6]] |
          DES_SP[7][(((((R >>> 1) & 0x0f) << 2) | ((R & 1) << 1) | ((R >>> 31) & 1)) ^ k[off + 7])]) >>> 0;
}
function desCryptBlock(block, subkeys) {
  var k = (subkeys instanceof Uint8Array) ? subkeys : (function () {
    var f = new Uint8Array(128), i, j, t;
    for (i = 0; i < 16; i++) for (j = 0; j < 8; j++) {
      var g = 0;
      for (t = 0; t < 6; t++) g = (g << 1) | subkeys[i][j * 6 + t];
      f[i * 8 + j] = g;
    }
    return f;
  })();
  var w = desIpWords(block), L = w[0], R = w[1], i;
  for (i = 0; i < 16; i++) {
    var nR = (L ^ desF32(R, k, i * 8)) >>> 0;
    L = R; R = nR;
  }
  return desFpBytes(R, L);
}
/* 解密 = 按轮序倒着用同一批子密钥。
 * ⚠ 不能对扁平 Uint8Array 直接 .reverse()：那会把每轮内部的 8 个组也倒过来。 */
function desRevRounds(flat) {
  var out = new Uint8Array(128), i;
  for (i = 0; i < 16; i++) out.set(flat.subarray((15 - i) * 8, (15 - i) * 8 + 8), i * 8);
  return out;
}
function desMakeBlockFn(keyBytes) {
  var sk = desSubkeysFast(keyBytes);
  var skRev = desRevRounds(sk);
  return {
    enc: function (b) { return desCryptBlock(b, sk); },
    dec: function (b) { return desCryptBlock(b, skRev); }
  };
}
/* 只跑 16 轮 Feistel，不做 IP/FP 置换。返回 [L,R]（【不】交换）。
 * 3DES 连续三次调用 desCryptBlock 时，中间两次的 FP 与下一次的 IP 互为逆运算，
 * 会完全抵消 —— 合并后能省掉 2 次 IP + 2 次 FP（各 64 次逐比特搬运）。 */
function desCore32(L, R, k) {
  for (var i = 0; i < 16; i++) {
    var nR = (L ^ desF32(R, k, i * 8)) >>> 0;
    L = R; R = nR;
  }
  return [L, R];
}
/* 一次 IP：字节 → 两个 32 位字（查表版，见 buildDesPermTables） */
function desIpWords(b) {
  var L = (DES_IPL[0][b[0]] | DES_IPL[1][b[1]] | DES_IPL[2][b[2]] | DES_IPL[3][b[3]] |
           DES_IPL[4][b[4]] | DES_IPL[5][b[5]] | DES_IPL[6][b[6]] | DES_IPL[7][b[7]]) >>> 0;
  var R = (DES_IPR[0][b[0]] | DES_IPR[1][b[1]] | DES_IPR[2][b[2]] | DES_IPR[3][b[3]] |
           DES_IPR[4][b[4]] | DES_IPR[5][b[5]] | DES_IPR[6][b[6]] | DES_IPR[7][b[7]]) >>> 0;
  return [L, R];
}
/* 一次 FP：两个 32 位字（注意是 R||L）→ 字节（查表版） */
function desFpBytes(R, L) {
  var v0 = (R >>> 24) & 0xff, v1 = (R >>> 16) & 0xff, v2 = (R >>> 8) & 0xff, v3 = R & 0xff;
  var v4 = (L >>> 24) & 0xff, v5 = (L >>> 16) & 0xff, v6 = (L >>> 8) & 0xff, v7 = L & 0xff;
  var hi = (DES_FPH[0][v0] | DES_FPH[1][v1] | DES_FPH[2][v2] | DES_FPH[3][v3] |
            DES_FPH[4][v4] | DES_FPH[5][v5] | DES_FPH[6][v6] | DES_FPH[7][v7]) >>> 0;
  var lo = (DES_FPL[0][v0] | DES_FPL[1][v1] | DES_FPL[2][v2] | DES_FPL[3][v3] |
            DES_FPL[4][v4] | DES_FPL[5][v5] | DES_FPL[6][v6] | DES_FPL[7][v7]) >>> 0;
  var out = new Uint8Array(8);
  out[0] = hi >>> 24; out[1] = (hi >>> 16) & 0xff; out[2] = (hi >>> 8) & 0xff; out[3] = hi & 0xff;
  out[4] = lo >>> 24; out[5] = (lo >>> 16) & 0xff; out[6] = (lo >>> 8) & 0xff; out[7] = lo & 0xff;
  return out;
}
/* 逐比特版（保留作等价性对照的基准，正常路径不再调用） */
function desIpWordsBits(b) {
  var bits = permuteBits(bytesToBits(b), DES_IP);
  return [desWord32(bits.slice(0, 32)), desWord32(bits.slice(32, 64))];
}
function desFpBytesBits(R, L) {
  return bitsToBytes(permuteBits(desBits32(R).concat(desBits32(L)), DES_FP));
}
function des3MakeBlockFn(keyBytes) {
  var k1 = keyBytes.subarray(0, 8);
  var k2 = keyBytes.subarray(8, 16);
  var k3 = keyBytes.subarray(16, 24);
  var s1 = desSubkeysFast(k1), s2 = desSubkeysFast(k2), s3 = desSubkeysFast(k3);
  /* 解密轮序反转，不是反转字节 */
  var s1r = desRevRounds(s1), s2r = desRevRounds(s2), s3r = desRevRounds(s3);
  return {
    enc: function (b) {
      var w = desIpWords(b), L = w[0], R = w[1], r, t;
      r = desCore32(L, R, s3); L = r[0]; R = r[1];
      t = L; L = R; R = t;                    /* 中间两次 IP∘FP 抵消，等价于交换 */
      r = desCore32(L, R, s2r); L = r[0]; R = r[1];
      t = L; L = R; R = t;
      r = desCore32(L, R, s1); L = r[0]; R = r[1];
      return desFpBytes(R, L);
    },
    dec: function (b) {
      var w = desIpWords(b), L = w[0], R = w[1], r, t;
      r = desCore32(L, R, s1r); L = r[0]; R = r[1];
      t = L; L = R; R = t;
      r = desCore32(L, R, s2); L = r[0]; R = r[1];
      t = L; L = R; R = t;
      r = desCore32(L, R, s3r); L = r[0]; R = r[1];
      return desFpBytes(R, L);
    }
  };
}

/* ============================================================
 * SM4
 * ============================================================ */
var SM4_SBOX = new Uint8Array([
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
]);
var SM4_FK = [0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc];
var SM4_CK = [0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279];
function sm4Tau(a) {
  return ((SM4_SBOX[(a>>>24)&0xff]<<24)|(SM4_SBOX[(a>>>16)&0xff]<<16)|(SM4_SBOX[(a>>>8)&0xff]<<8)|SM4_SBOX[a&0xff])>>>0;
}
function sm4T(a) { var b = sm4Tau(a); return (b ^ rotl32(b,2) ^ rotl32(b,10) ^ rotl32(b,18) ^ rotl32(b,24)) >>> 0; }
function sm4Tp(a) { var b = sm4Tau(a); return (b ^ rotl32(b,13) ^ rotl32(b,23)) >>> 0; }
function sm4ExpandKey(key) {
  var MK = new Uint32Array(4);
  for (var i = 0; i < 4; i++) MK[i] = readU32BE(key, i*4);
  var K = new Uint32Array(36);
  for (var j = 0; j < 4; j++) K[j] = (MK[j] ^ SM4_FK[j]) >>> 0;
  for (var r = 0; r < 32; r++) K[r+4] = (K[r] ^ sm4Tp((K[r+1]^K[r+2]^K[r+3]^SM4_CK[r])>>>0)) >>> 0;
  return K.subarray(4);
}
function sm4EncBlock(block, rk) {
  var X0 = readU32BE(block, 0), X1 = readU32BE(block, 4), X2 = readU32BE(block, 8), X3 = readU32BE(block, 12);
  for (var i = 0; i < 32; i++) {
    var X4 = (X0 ^ sm4T((X1^X2^X3^rk[i])>>>0)) >>> 0;
    X0 = X1; X1 = X2; X2 = X3; X3 = X4;
  }
  var out = new Uint8Array(16);
  writeU32BE(X3, out, 0); writeU32BE(X2, out, 4); writeU32BE(X1, out, 8); writeU32BE(X0, out, 12);
  return out;
}
function sm4DecBlock(block, rk) {
  var X0 = readU32BE(block, 0), X1 = readU32BE(block, 4), X2 = readU32BE(block, 8), X3 = readU32BE(block, 12);
  for (var i = 31; i >= 0; i--) {
    var X4 = (X0 ^ sm4T((X1^X2^X3^rk[i])>>>0)) >>> 0;
    X0 = X1; X1 = X2; X2 = X3; X3 = X4;
  }
  var out = new Uint8Array(16);
  writeU32BE(X3, out, 0); writeU32BE(X2, out, 4); writeU32BE(X1, out, 8); writeU32BE(X0, out, 12);
  return out;
}
function sm4MakeBlockFn(keyBytes) {
  var rk = sm4ExpandKey(keyBytes);
  return {
    enc: function (b) { return sm4EncBlock(b, rk); },
    dec: function (b) { return sm4DecBlock(b, rk); }
  };
}

/* ============================================================
 * RC5 / RC6
 * ============================================================ */
var RC5_P = 0xB7E15163, RC5_Q = 0x9E3779B9;
var RC5_ROUNDS = 12, RC6_ROUNDS = 20;

function rcKeySchedule(keyBytes, rounds, sSize) {
  var u = 4, b = keyBytes.length, c = Math.max(1, Math.ceil(b / u));
  var L = new Uint32Array(c);
  for (var i = b - 1; i >= 0; i--) L[(i/u)|0] = (((L[(i/u)|0] << 8) >>> 0) + keyBytes[i]) >>> 0;
  var t = sSize || (2 * (rounds + 1));
  var S = new Uint32Array(t);
  S[0] = RC5_P;
  for (var j = 1; j < t; j++) S[j] = (S[j-1] + RC5_Q) >>> 0;
  var A = 0, B = 0, ii = 0, jj = 0;
  var n = 3 * Math.max(t, c);
  for (var k = 0; k < n; k++) {
    A = S[ii] = rotl32((S[ii] + A + B) >>> 0, 3);
    B = L[jj] = rotl32((L[jj] + A + B) >>> 0, (A + B) & 31);
    ii = (ii + 1) % t; jj = (jj + 1) % c;
  }
  return S;
}
function rc5EncBlock(block, S) {
  var A = (readU32LE(block, 0) + S[0]) >>> 0;
  var B = (readU32LE(block, 4) + S[1]) >>> 0;
  for (var i = 1; i <= RC5_ROUNDS; i++) {
    A = (rotl32(A ^ B, B & 31) + S[2*i]) >>> 0;
    B = (rotl32(B ^ A, A & 31) + S[2*i+1]) >>> 0;
  }
  var out = new Uint8Array(8); writeU32LE(A, out, 0); writeU32LE(B, out, 4); return out;
}
function rc5DecBlock(block, S) {
  var A = readU32LE(block, 0), B = readU32LE(block, 4);
  for (var i = RC5_ROUNDS; i >= 1; i--) {
    B = (rotr32((B - S[2*i+1]) >>> 0, A & 31) ^ A) >>> 0;
    A = (rotr32((A - S[2*i]) >>> 0, B & 31) ^ B) >>> 0;
  }
  B = (B - S[1]) >>> 0; A = (A - S[0]) >>> 0;
  var out = new Uint8Array(8); writeU32LE(A, out, 0); writeU32LE(B, out, 4); return out;
}
function rc5MakeBlockFn(keyBytes) {
  var S = rcKeySchedule(keyBytes, RC5_ROUNDS);
  return {
    enc: function (b) { return rc5EncBlock(b, S); },
    dec: function (b) { return rc5DecBlock(b, S); }
  };
}
/* RC6 的 f(x) = x*(2x+1) mod 2^32。
   两个 32 位数相乘可达 2^64，远超 JS 双精度 2^53 的安全整数范围，
   直接写 B * (2B+1) 会丢低位（表现为密文出现大片 0）。
   必须用 Math.imul 做真正的 32 位模乘。 */
function rc6F(x) {
  var y = ((((x << 1) >>> 0) + 1) >>> 0);   /* (2x+1) mod 2^32 */
  return Math.imul(x, y) >>> 0;              /* x*(2x+1) mod 2^32 */
}
function rc6EncBlock(block, S) {
  var A = readU32LE(block, 0), B = readU32LE(block, 4), C = readU32LE(block, 8), D = readU32LE(block, 12);
  B = (B + S[0]) >>> 0; D = (D + S[1]) >>> 0;
  for (var i = 1; i <= RC6_ROUNDS; i++) {
    var t = rotl32(rc6F(B), 5);
    var u = rotl32(rc6F(D), 5);
    A = (rotl32(A ^ t, u) + S[2*i]) >>> 0;
    C = (rotl32(C ^ u, t) + S[2*i+1]) >>> 0;
    var tmp = A; A = B; B = C; C = D; D = tmp;
  }
  A = (A + S[2*RC6_ROUNDS+2]) >>> 0; C = (C + S[2*RC6_ROUNDS+3]) >>> 0;
  var out = new Uint8Array(16);
  writeU32LE(A, out, 0); writeU32LE(B, out, 4); writeU32LE(C, out, 8); writeU32LE(D, out, 12);
  return out;
}
function rc6DecBlock(block, S) {
  var A = readU32LE(block, 0), B = readU32LE(block, 4), C = readU32LE(block, 8), D = readU32LE(block, 12);
  C = (C - S[2*RC6_ROUNDS+3]) >>> 0; A = (A - S[2*RC6_ROUNDS+2]) >>> 0;
  for (var i = RC6_ROUNDS; i >= 1; i--) {
    var tmp = D; D = C; C = B; B = A; A = tmp;
    var u = rotl32(rc6F(D), 5);
    var t = rotl32(rc6F(B), 5);
    C = (rotr32((C - S[2*i+1]) >>> 0, t) ^ u) >>> 0;
    A = (rotr32((A - S[2*i]) >>> 0, u) ^ t) >>> 0;
  }
  D = (D - S[1]) >>> 0; B = (B - S[0]) >>> 0;
  var out = new Uint8Array(16);
  writeU32LE(A, out, 0); writeU32LE(B, out, 4); writeU32LE(C, out, 8); writeU32LE(D, out, 12);
  return out;
}
function rc6MakeBlockFn(keyBytes) {
  var S = rcKeySchedule(keyBytes, RC6_ROUNDS, 2 * RC6_ROUNDS + 4);
  return {
    enc: function (b) { return rc6EncBlock(b, S); },
    dec: function (b) { return rc6DecBlock(b, S); }
  };
}

/* ============================================================
 * RC4 / ChaCha20
 * ============================================================ */
function rc4Process(keyBytes, data) {
  var S = new Uint8Array(256);
  for (var i = 0; i < 256; i++) S[i] = i;
  var j = 0;
  for (var ii = 0; ii < 256; ii++) {
    j = (j + S[ii] + keyBytes[ii % keyBytes.length]) & 255;
    var t = S[ii]; S[ii] = S[j]; S[j] = t;
  }
  var out = new Uint8Array(data.length);
  var i2 = 0, j2 = 0;
  for (var k = 0; k < data.length; k++) {
    i2 = (i2 + 1) & 255;
    j2 = (j2 + S[i2]) & 255;
    var t2 = S[i2]; S[i2] = S[j2]; S[j2] = t2;
    out[k] = data[k] ^ S[(S[i2] + S[j2]) & 255];
  }
  return out;
}

function chachaQR(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotr32(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotr32(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotr32(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotr32(s[b] ^ s[c], 7);
}
function chacha20Process(keyBytes, nonce, counter, data) {
  var state = new Uint32Array(16);
  state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
  for (var i = 0; i < 8; i++) state[4+i] = readU32LE(keyBytes, i*4);
  state[12] = counter >>> 0;
  for (var j = 0; j < 3; j++) state[13+j] = readU32LE(nonce, j*4);
  var out = new Uint8Array(data.length);
  for (var off = 0; off < data.length; off += 64) {
    var w = new Uint32Array(state);
    for (var r = 0; r < 10; r++) {
      chachaQR(w, 0, 4, 8, 12); chachaQR(w, 1, 5, 9, 13); chachaQR(w, 2, 6, 10, 14); chachaQR(w, 3, 7, 11, 15);
      chachaQR(w, 0, 5, 10, 15); chachaQR(w, 1, 6, 11, 12); chachaQR(w, 2, 7, 8, 13); chachaQR(w, 3, 4, 9, 14);
    }
    var ks = new Uint8Array(64);
    for (var k = 0; k < 16; k++) writeU32LE((w[k] + state[k]) >>> 0, ks, k*4);
    var len = Math.min(64, data.length - off);
    for (var m = 0; m < len; m++) out[off+m] = data[off+m] ^ ks[m];
    state[12] = (state[12] + 1) >>> 0;
  }
  return out;
}

/* ============================================================
 * 哈希：MD5 / SM3 / BLAKE2s
 * ============================================================ */
var MD5_K = new Uint32Array([
0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
]);
var MD5_S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
function md5Digest(input) {
  var bytes = input instanceof Uint8Array ? input : strToBytes(String(input));
  var bitLen = bytes.length * 8;
  var withOne = bytes.length + 1;
  var padLen = ((56 - (withOne % 64)) + 64) % 64;
  var total = withOne + padLen + 8;
  var msg = new Uint8Array(total);
  msg.set(bytes); msg[bytes.length] = 0x80;
  var dv = new DataView(msg.buffer);
  dv.setUint32(total - 8, bitLen >>> 0, true);
  dv.setUint32(total - 4, Math.floor(bitLen / 4294967296), true);
  var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (var off = 0; off < total; off += 64) {
    var M = new Uint32Array(16);
    for (var i = 0; i < 16; i++) M[i] = dv.getUint32(off + i*4, true);
    var A = a0, B = b0, C = c0, D = d0;
    for (var j = 0; j < 64; j++) {
      var F, g;
      if (j < 16) { F = (B & C) | (~B & D); g = j; }
      else if (j < 32) { F = (D & B) | (~D & C); g = (5*j + 1) % 16; }
      else if (j < 48) { F = B ^ C ^ D; g = (3*j + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7*j) % 16; }
      F = (F + A + MD5_K[j] + M[g]) >>> 0;
      A = D; D = C; C = B; B = (B + rotl32(F, MD5_S[j])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  var out = new Uint8Array(16);
  var odv = new DataView(out.buffer);
  odv.setUint32(0, a0, true); odv.setUint32(4, b0, true);
  odv.setUint32(8, c0, true); odv.setUint32(12, d0, true);
  return out;
}

var SM3_IV = new Uint32Array([0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e]);
var SM3_T = new Uint32Array(64);
for (var smi = 0; smi < 16; smi++) SM3_T[smi] = 0x79cc4519;
for (var smj = 16; smj < 64; smj++) SM3_T[smj] = 0x7a879d8a;
function sm3Digest(input) {
  var bytes = input instanceof Uint8Array ? input : strToBytes(String(input));
  var bitLen = bytes.length * 8;
  var withOne = bytes.length + 1;
  var padLen = ((56 - (withOne % 64)) + 64) % 64;
  var total = withOne + padLen + 8;
  var msg = new Uint8Array(total);
  msg.set(bytes); msg[bytes.length] = 0x80;
  var dv = new DataView(msg.buffer);
  dv.setUint32(total - 8, Math.floor(bitLen / 4294967296), false);
  dv.setUint32(total - 4, bitLen >>> 0, false);
  var V = new Uint32Array(SM3_IV);
  for (var off = 0; off < total; off += 64) {
    var W = new Uint32Array(68), W1 = new Uint32Array(64);
    for (var i = 0; i < 16; i++) W[i] = dv.getUint32(off + i*4, false);
    for (var ii = 16; ii < 68; ii++) {
      var x = (W[ii-16] ^ W[ii-9] ^ rotl32(W[ii-3], 15)) >>> 0;
      x = (x ^ rotl32(x, 15) ^ rotl32(x, 23)) >>> 0;
      W[ii] = (x ^ rotl32(W[ii-13], 7) ^ W[ii-6]) >>> 0;
    }
    for (var j = 0; j < 64; j++) W1[j] = (W[j] ^ W[j+4]) >>> 0;
    var A = V[0], B = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
    for (var k = 0; k < 64; k++) {
      var SS1 = rotl32((rotl32(A,12) + E + rotl32(SM3_T[k], k % 32)) >>> 0, 7);
      var SS2 = (SS1 ^ rotl32(A, 12)) >>> 0;
      var FF = k < 16 ? (A ^ B ^ C) : ((A & B) | (A & C) | (B & C));
      var GG = k < 16 ? (E ^ F ^ G) : ((E & F) | (~E & G));
      var TT1 = (FF + D + SS2 + W1[k]) >>> 0;
      var TT2 = (GG + H + SS1 + W[k]) >>> 0;
      D = C; C = rotl32(B, 9); B = A; A = TT1;
      H = G; G = rotl32(F, 19); F = E;
      E = (TT2 ^ rotl32(TT2, 9) ^ rotl32(TT2, 17)) >>> 0;
    }
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D; V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
  }
  var out = new Uint8Array(32);
  var odv = new DataView(out.buffer);
  for (var m = 0; m < 8; m++) odv.setUint32(m*4, V[m], false);
  return out;
}

var BLAKE2S_IV = new Uint32Array([0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19]);
var BLAKE2S_SIGMA = [
[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
[11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
[9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
[12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
[6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]
];
function blake2sCompress(h, block, t, last) {
  var v = new Uint32Array(16);
  for (var i = 0; i < 8; i++) v[i] = h[i];
  for (var j = 0; j < 8; j++) v[j+8] = BLAKE2S_IV[j];
  v[12] ^= t >>> 0; v[13] ^= Math.floor(t / 4294967296);
  if (last) v[14] = (~v[14]) >>> 0;
  var m = new Uint32Array(16);
  for (var k = 0; k < 16; k++) m[k] = readU32LE(block, k*4);
  function G(a, b, c, d, x, y) {
    v[a] = (v[a] + v[b] + x) >>> 0; v[d] = rotr32(v[d] ^ v[a], 16);
    v[c] = (v[c] + v[d]) >>> 0; v[b] = rotr32(v[b] ^ v[c], 12);
    v[a] = (v[a] + v[b] + y) >>> 0; v[d] = rotr32(v[d] ^ v[a], 8);
    v[c] = (v[c] + v[d]) >>> 0; v[b] = rotr32(v[b] ^ v[c], 7);
  }
  for (var r = 0; r < 10; r++) {
    var s = BLAKE2S_SIGMA[r];
    G(0,4,8,12,m[s[0]],m[s[1]]); G(1,5,9,13,m[s[2]],m[s[3]]);
    G(2,6,10,14,m[s[4]],m[s[5]]); G(3,7,11,15,m[s[6]],m[s[7]]);
    G(0,5,10,15,m[s[8]],m[s[9]]); G(1,6,11,12,m[s[10]],m[s[11]]);
    G(2,7,8,13,m[s[12]],m[s[13]]); G(3,4,9,14,m[s[14]],m[s[15]]);
  }
  for (var n = 0; n < 8; n++) h[n] = (h[n] ^ v[n] ^ v[n+8]) >>> 0;
}
function blake2sDigest(input, outLen) {
  var bytes = input instanceof Uint8Array ? input : strToBytes(String(input));
  var os = outLen || 32;
  var h = new Uint32Array(BLAKE2S_IV);
  h[0] ^= 0x01010000 ^ os;
  var total = bytes.length;
  if (total === 0) blake2sCompress(h, new Uint8Array(64), 0, true);
  else {
    var off = 0;
    while (off < total) {
      var len = Math.min(64, total - off);
      var blk = new Uint8Array(64);
      blk.set(bytes.subarray(off, off + len));
      off += len;
      blake2sCompress(h, blk, off, off >= total);
    }
  }
  var out = new Uint8Array(os);
  for (var i = 0; i < os; i++) out[i] = (h[i >> 2] >>> ((i & 3) * 8)) & 0xff;
  return out;
}

async function webCryptoHash(name, bytes) {
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto');
  var buf = await crypto.subtle.digest(name, bytes);
  return new Uint8Array(buf);
}

/* ============================================================
 * 编码类
 * ============================================================ */
var B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(bytes) {
  var bits = 0, value = 0, out = '';
  for (var i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i]; bits += 8;
    while (bits >= 5) { out += B32_ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  while (out.length % 8) out += '=';
  return out;
}
function base32Decode(str) {
  var s = String(str).toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '');
  var bits = 0, value = 0, out = [];
  for (var i = 0; i < s.length; i++) {
    var idx = B32_ALPHABET.indexOf(s[i]);
    if (idx === -1) throw new Error('非法的 Base32 字符: ' + s[i]);
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

var B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(bytes) {
  if (bytes.length === 0) return '';
  var zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  if (zeros === bytes.length) return '1'.repeat(zeros);
  var digits = [0];
  for (var i = zeros; i < bytes.length; i++) {
    var carry = bytes[i];
    for (var j = 0; j < digits.length; j++) {
      carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  var out = '1'.repeat(zeros);
  for (var k = digits.length - 1; k >= 0; k--) out += B58_ALPHABET[digits[k]];
  return out;
}
function base58Decode(str) {
  var s = String(str).trim();
  var zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  if (zeros === s.length) return new Uint8Array(zeros);
  var bytes = [0];
  for (var i = zeros; i < s.length; i++) {
    var idx = B58_ALPHABET.indexOf(s[i]);
    if (idx === -1) throw new Error('非法的 Base58 字符: ' + s[i]);
    var carry = idx;
    for (var j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  var out = new Uint8Array(zeros + bytes.length);
  for (var k = 0; k < bytes.length; k++) out[out.length - 1 - k] = bytes[k];
  return out;
}

function base85Encode(bytes) {
  var out = '';
  for (var i = 0; i < bytes.length; i += 4) {
    var chunk = bytes.subarray(i, i+4);
    var pad = 4 - chunk.length;
    var n = 0;
    for (var j = 0; j < 4; j++) n = n * 256 + (j < chunk.length ? chunk[j] : 0);
    if (n === 0 && chunk.length === 4) { out += 'z'; continue; }
    var s = '';
    for (var k = 0; k < 5; k++) { s = String.fromCharCode(33 + (n % 85)) + s; n = Math.floor(n / 85); }
    out += pad === 0 ? s : s.slice(0, 5 - pad);
  }
  return out;
}
function base85Decode(str) {
  var s = String(str).replace(/\s+/g, '');
  var out = [];
  var i = 0;
  while (i < s.length) {
    if (s[i] === 'z') { out.push(0,0,0,0); i++; continue; }
    var n = 0, count = 0;
    while (count < 5 && i < s.length) {
      var c = s.charCodeAt(i);
      if (c < 33 || c > 117) throw new Error('非法的 Base85 字符: ' + s[i]);
      n = n * 85 + (c - 33); count++; i++;
    }
    var bc = count - 1;
    var tmp = [0,0,0,0];
    for (var j = 3; j >= 0; j--) { tmp[j] = n % 256; n = Math.floor(n / 256); }
    for (var k = 0; k < bc; k++) out.push(tmp[k]);
  }
  return new Uint8Array(out);
}

var HTML_NAMED = { amp:'&',lt:'<',gt:'>',quot:'"',apos:"'",nbsp:'\u00a0',copy:'\u00a9',reg:'\u00ae',trade:'\u2122',hellip:'\u2026',mdash:'\u2014',ndash:'\u2013',laquo:'\u00ab',raquo:'\u00bb',times:'\u00d7',divide:'\u00f7',deg:'\u00b0',plusmn:'\u00b1',euro:'\u20ac',pound:'\u00a3',yen:'\u00a5',sect:'\u00a7',para:'\u00b6',middot:'\u00b7',bull:'\u2022',dagger:'\u2020' };
function htmlEncode(str) { return String(str).replace(/[&<>"']/g, function (c) { return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]; }); }
function htmlDecode(str) {
  return String(str).replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/g, function (m, ent) {
    if (ent[0] === '#') {
      var code = (ent[1] === 'x' || ent[1] === 'X') ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
      if (!isNaN(code)) return String.fromCodePoint(code);
    }
    var n = HTML_NAMED[ent.toLowerCase()];
    return n !== undefined ? n : m;
  });
}
function unicodeEscape(str) {
  var out = '';
  for (var i = 0; i < str.length; i++) {
    var cp = str.codePointAt(i);
    if (cp > 0xffff) {
      var hi = Math.floor((cp - 0x10000) / 0x400) + 0xd800;
      var lo = ((cp - 0x10000) % 0x400) + 0xdc00;
      out += '\\u' + hi.toString(16).padStart(4,'0') + '\\u' + lo.toString(16).padStart(4,'0');
      i++;
    } else out += '\\u' + cp.toString(16).padStart(4,'0');
  }
  return out;
}
function unicodeUnescape(str) {
  return String(str)
    .replace(/\\u\{([0-9a-fA-F]+)\}/g, function (m, h) { return String.fromCodePoint(parseInt(h, 16)); })
    .replace(/\\u([0-9a-fA-F]{4})/g, function (m, h) { return String.fromCharCode(parseInt(h, 16)); })
    .replace(/\\x([0-9a-fA-F]{2})/g, function (m, h) { return String.fromCharCode(parseInt(h, 16)); })
    .replace(/\\U([0-9a-fA-F]{8})/g, function (m, h) { return String.fromCodePoint(parseInt(h, 16)); });
}
function rot13(str) { return String(str).replace(/[a-zA-Z]/g, function (c) { var b = c <= 'Z' ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b); }); }
function caesarShift(str, shift) {
  var n = parseInt(shift, 10);
  if (isNaN(n)) throw new Error('请输入有效的移位数');
  n = ((n % 26) + 26) % 26;
  return String(str).replace(/[a-zA-Z]/g, function (c) { var b = c <= 'Z' ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + n) % 26) + b); });
}
function caesarUnshift(str, shift) {
  var n = parseInt(shift, 10);
  if (isNaN(n)) throw new Error('请输入有效的移位数');
  return caesarShift(str, -n);
}
var MORSE_MAP = {'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---','K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..','0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.','.':'.-.-.-',',':'--..--','?':'..--..',"'":'.----.','!':'-.-.--','/':'-..-.','(':'-.--.',')':'-.--.-','&':'.-...',':':'---...',';':'-.-.-.','=':'-...-','+':'.-.-.','-':'-....-','_':'..--.-','"':'.-..-.','$':'...-..-','@':'.--.-.'};
var MORSE_REVERSE = {};
for (var mk in MORSE_MAP) MORSE_REVERSE[MORSE_MAP[mk]] = mk;
function morseEncode(str) {
  return String(str).toUpperCase().split(/\s+/).map(function (w) {
    return w.split('').map(function (ch) { return MORSE_MAP[ch] || ''; }).filter(Boolean).join(' ');
  }).join(' / ');
}
function morseDecode(str) {
  return String(str).trim().split(/\s*\/\s*/).map(function (w) {
    return w.trim().split(/\s+/).map(function (c) { return MORSE_REVERSE[c] || ''; }).join('');
  }).join(' ');
}

/* ============================================================
 * 非对称
 * ============================================================ */
function pemToBuffer(pem) {
  var s = String(pem).trim();
  var b64 = s.replace(/-----BEGIN [^-]+-----/g, '').replace(/-----END [^-]+-----/g, '').replace(/\s+/g, '');
  return base64ToBytes(b64);
}

/* RSA-PSS：签名与验签。PSS 是概率性的——同一消息两次签名结果不同，这是正常的，
   不要把「两次签名不一样」当成 bug。 */
async function rsaPssSign(dataBytes, privPem) {
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto');
  var key = await crypto.subtle.importKey('pkcs8', pemToBuffer(privPem),
    { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['sign']);
  var sig = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, key, dataBytes);
  return new Uint8Array(sig);
}
async function rsaPssVerify(dataBytes, sigBytes, pubPem) {
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto');
  var key = await crypto.subtle.importKey('spki', pemToBuffer(pubPem),
    { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
  return await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, key, sigBytes, dataBytes);
}

async function rsaEncryptData(data, pubPem) {
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto');
  var key = await crypto.subtle.importKey('spki', pemToBuffer(pubPem), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  var modLen = key.algorithm.modulusLength / 8;
  var maxLen = modLen - 66;
  if (maxLen <= 0) throw new Error('RSA 密钥长度不足');
  var parts = [];
  if (data.length === 0) {
    var ct0 = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, new Uint8Array(0));
    parts.push(new Uint8Array(ct0));
  } else {
    for (var i = 0; i < data.length; i += maxLen) {
      var ct = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data.subarray(i, i + maxLen));
      parts.push(new Uint8Array(ct));
    }
  }
  var out = new Uint8Array(parts.length * modLen);
  parts.forEach(function (p, i) { out.set(p, i * modLen); });
  return out;
}
async function rsaDecryptData(cipher, privPem) {
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto');
  var key = await crypto.subtle.importKey('pkcs8', pemToBuffer(privPem), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  var modLen = key.algorithm.modulusLength / 8;
  if (cipher.length % modLen !== 0) throw new Error('密文长度与密钥不匹配');
  var parts = [];
  for (var off = 0; off < cipher.length; off += modLen) {
    var pt = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, cipher.subarray(off, off + modLen));
    parts.push(new Uint8Array(pt));
  }
  var total = parts.reduce(function (s, p) { return s + p.length; }, 0);
  var out = new Uint8Array(total);
  var o2 = 0;
  parts.forEach(function (p) { out.set(p, o2); o2 += p.length; });
  return out;
}
async function ecdsaSignData(data, privPem, curve) {
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto');
  var key = await crypto.subtle.importKey('pkcs8', pemToBuffer(privPem), { name: 'ECDSA', namedCurve: curve }, false, ['sign']);
  var sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data);
  return new Uint8Array(sig);
}
async function ecdsaVerifyData(data, sigBytes, pubPem, curve) {
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto');
  var key = await crypto.subtle.importKey('spki', pemToBuffer(pubPem), { name: 'ECDSA', namedCurve: curve }, false, ['verify']);
  var ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sigBytes, data);
  return ok ? '签名有效' : '签名无效';
}
async function ed25519SignData(data, privPem) {
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto');
  var key = await crypto.subtle.importKey('pkcs8', pemToBuffer(privPem), { name: 'Ed25519' }, false, ['sign']);
  var sig = await crypto.subtle.sign({ name: 'Ed25519' }, key, data);
  return new Uint8Array(sig);
}
async function ed25519VerifyData(data, sigBytes, pubPem) {
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto');
  var key = await crypto.subtle.importKey('spki', pemToBuffer(pubPem), { name: 'Ed25519' }, false, ['verify']);
  var ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, sigBytes, data);
  return ok ? '签名有效' : '签名无效';
}
async function ecdhDerive(privPem, pubPem, curve) {
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto');
  var priv = await crypto.subtle.importKey('pkcs8', pemToBuffer(privPem), { name: 'ECDH', namedCurve: curve }, false, ['deriveBits']);
  var pub = await crypto.subtle.importKey('spki', pemToBuffer(pubPem), { name: 'ECDH', namedCurve: curve }, false, []);
  var bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256);
  return new Uint8Array(bits);
}

/* ============================================================
 * 算法注册表
 * ============================================================ */
var ALGOS = [];
/* ⚠ 历史 bug：index.html 曾把 crypto_extra6.js 引用了【两次】，
   导致其中 11 个算法各注册两遍，下拉框里出现 11 个重名条目
   （salsa20/x448/ff3/ed448/aes-gcm-siv/hctr2/cast5/rc2/gost28147/schnorr/bip32）。
   压力测试只看 id→算法，不会发现；只有按列表遍历才暴露。
   现在 reg 自带去重 + 控制台告警，杜绝这类问题再次静默发生。 */
function reg(cfg) {
  for (var i = 0; i < ALGOS.length; i++) {
    if (ALGOS[i].id === cfg.id) {
      if (typeof console !== 'undefined' && console.warn) console.warn('算法重复注册，已跳过：' + cfg.id);
      return;
    }
  }
  ALGOS.push(cfg);
}
function bytesOut(bytes, fmt) {
if (typeof fmtEncode === 'function') return fmtEncode(bytes, fmt);
return fmt === 'hex' ? bytesToHex(bytes) : bytesToBase64(bytes);
}
function bytesIn(str, fmt) {
if (typeof fmtDecode === 'function') return fmtDecode(str, fmt);
return fmt === 'hex' ? hexToBytes(str) : base64ToBytes(str);
}
var FMT_LIST = (typeof OUT_FORMATS === 'object') ? Object.keys(OUT_FORMATS) : ['base64', 'hex'];

/* 加密：返回 { ciphertext, iv }
   embedIV = true  → 把 IV 拼在密文头部（兼容旧格式）
   embedIV = false → 密文里不含 IV，调用方负责把 iv 单独保存/回写到界面
   ivProvided     → 区分 IV 是用户填的还是本次自动生成的 */
async function symEncrypt(algo, bytes, key, mode, padMode, ivHex, embedIV, aadStr, saltHex, tagLen) {
  var bs = algo.blockSize;
  var saltB = saltHex ? hexToBytes(saltHex) : null;
  var evpM = null;
  if (typeof CURRENT_CONTAINER !== 'undefined') {
    if (CURRENT_CONTAINER === 'openssl') evpM = 'sha256';
    else if (CURRENT_CONTAINER === 'cryptojs') evpM = 'md5';
  }
  if ((evpM === 'sha256' || evpM === 'md5') && !saltB) {
    saltB = crypto.getRandomValues(new Uint8Array(8));
  }
  /* salt 必须回传给调用方：容器要把同一个 salt 写进 Salted__ 头。
     若外层再生成一个，密钥派生用的 salt 和容器里的 salt 就对不上了。 */
  var saltUsed = saltB;
  var keyBytes = await deriveKeyBytes(key, mode === 'XTS' ? algo.keyLen * 2 : algo.keyLen, saltB, evpM);
  var bf = algo.makeBlockFn(keyBytes.subarray(0, algo.keyLen));
  var iv = null;
  var ivProvided = false;
  if (mode === 'XTS') {
    /* XTS（IEEE 1619）只定义在 128 位块上，64 位块的算法用它会直接算错 */
    if (bs !== 16) throw new Error('XTS 模式仅支持 128 位（16 字节）块，' + (algo.name || algo.id) + ' 的块大小是 ' + bs + ' 字节');
    var tweakFn = algo.makeBlockFn(keyBytes.subarray(algo.keyLen, algo.keyLen * 2));
    var tw = ivHex ? hexToBytes(ivHex) : crypto.getRandomValues(new Uint8Array(16));
    if (tw.length !== 16) throw new Error('XTS 的 tweak 必须为 16 字节（32 位 Hex）');
    if (ivHex) ivProvided = true;
    var xbody = xtsEnc(bytes, bf, tweakFn, tw);
    return { ciphertext: xbody, iv: tw, ivProvided: ivProvided , salt: saltUsed };
  }
  if (isAEAD(mode)) {
    /* AEAD 只允许 AES：GCM/CCM/SIV 的认证部分（GHASH、CBC-MAC、S2V）都是围绕
       AES 定义的，套到别的密码上没有标准依据，宁可报错也不静默算错。 */
    if (!/^aes/.test(algo.id)) {
      throw new Error(mode + ' 模式仅支持 AES 系算法，' + (algo.name || algo.id) + ' 不适用');
    }
    var aad = strToBytes(aadStr || '');
    if (mode === 'GCM') {
      var nLen = aeadNonceLen('GCM');
      var nonce = ivHex ? hexToBytes(ivHex) : crypto.getRandomValues(new Uint8Array(nLen));
      if (nonce.length !== nLen) throw new Error('GCM 的 nonce 必须为 ' + nLen + ' 字节（' + (nLen * 2) + ' 位 Hex）');
      if (ivHex) ivProvided = true;
      /* nonce 复用检测：同一 (密钥,nonce) 第二次加密前拦下来 */
      var nw = (typeof nonceGuard === 'function') ? nonceGuard('GCM', keyBytes, nonce) : null;
      /* 存到全局，由 runEncrypt 拼进最终状态栏——直接 setMsg 会被后面的“加密完成”覆盖 */
      if (nw) window._lastNonceWarning = nw;
      var g = aesGcmEncrypt(bytes, keyBytes, nonce, aad);
      if (typeof nonceRemember === 'function') nonceRemember('GCM', keyBytes, nonce);
      return { ciphertext: concatBytes(concatBytes(nonce, g.ciphertext), g.tag), iv: nonce, ivProvided: ivProvided , salt: saltUsed };
    }
    if (mode === 'CCM') {
      if (bytes.length === 0) throw new Error('CCM 明文不能为空');
      var nLen2 = aeadNonceLen('CCM');
      var nonce2 = ivHex ? hexToBytes(ivHex) : crypto.getRandomValues(new Uint8Array(nLen2));
      if (nonce2.length !== nLen2) throw new Error('CCM 的 nonce 必须为 ' + nLen2 + ' 字节（' + (nLen2 * 2) + ' 位 Hex）');
      if (ivHex) ivProvided = true;
      var nw2 = (typeof nonceGuard === 'function') ? nonceGuard('CCM', keyBytes, nonce2) : null;
      if (nw2) window._lastNonceWarning = nw2;
      var c = aesCcmEncrypt(bytes, keyBytes, nonce2, aad, 16);
      if (typeof nonceRemember === 'function') nonceRemember('CCM', keyBytes, nonce2);
      return { ciphertext: concatBytes(concatBytes(nonce2, c.ciphertext), c.tag), iv: nonce2, ivProvided: ivProvided , salt: saltUsed };
    }
    if (mode === 'EAX') {
      var nLe = aeadNonceLen('EAX');
      var ne = ivHex ? hexToBytes(ivHex) : crypto.getRandomValues(new Uint8Array(nLe));
      if (ne.length !== nLe) throw new Error('EAX 的 nonce 必须为 ' + nLe + ' 字节（' + (nLe * 2) + ' 位 Hex）');
      if (ivHex) ivProvided = true;
      var nwe = (typeof nonceGuard === 'function') ? nonceGuard('EAX', keyBytes, ne) : null;
      if (nwe) window._lastNonceWarning = nwe;
      var ee = aesEaxEncrypt(bytes, keyBytes, ne, aad);
      if (typeof nonceRemember === 'function') nonceRemember('EAX', keyBytes, ne);
      return { ciphertext: concatBytes(concatBytes(ne, ee.ciphertext), ee.tag), iv: ne, ivProvided: ivProvided, salt: saltUsed };
    }
    if (mode === 'OCB') {
      var nLo = aeadNonceLen('OCB');
      var no = ivHex ? hexToBytes(ivHex) : crypto.getRandomValues(new Uint8Array(nLo));
      if (no.length !== nLo) throw new Error('OCB 的 nonce 必须为 ' + nLo + ' 字节（' + (nLo * 2) + ' 位 Hex）');
      if (ivHex) ivProvided = true;
      var nwo = (typeof nonceGuard === 'function') ? nonceGuard('OCB', keyBytes, no) : null;
      if (nwo) window._lastNonceWarning = nwo;
      var oo = aesOcbEncrypt(bytes, keyBytes, no, aad);
      if (typeof nonceRemember === 'function') nonceRemember('OCB', keyBytes, no);
      return { ciphertext: concatBytes(concatBytes(no, oo.ciphertext), oo.tag), iv: no, ivProvided: ivProvided, salt: saltUsed };
    }
    /* SIV：确定性 AEAD，不需要 nonce，抗 nonce 误用 */
    var sivKey = await deriveKeyBytes(key, algo.keyLen * 2);
    var sv = aesSivEncrypt(bytes, sivKey, aad.length ? [aad] : []);
    return { ciphertext: concatBytes(sv.tag, sv.ciphertext), iv: null, ivProvided: false };
  }
  if (mode === 'PCBC') {
    var piv = ivHex ? hexToBytes(ivHex) : crypto.getRandomValues(new Uint8Array(bs));
    if (piv.length !== bs) throw new Error('PCBC 的 IV 必须为 ' + bs + ' 字节');
    if (ivHex) ivProvided = true;
    return { ciphertext: pcbcEnc(bytes, bs, bf, padMode, piv), iv: piv, ivProvided: ivProvided , salt: saltUsed };
  }
  if (mode === 'CFB8' || mode === 'CFB1') {
    var fiv = ivHex ? hexToBytes(ivHex) : crypto.getRandomValues(new Uint8Array(bs));
    if (fiv.length !== bs) throw new Error(mode + ' 的 IV 必须为 ' + bs + ' 字节');
    if (ivHex) ivProvided = true;
    var cbody = (mode === 'CFB8') ? cfb8Enc(bytes, bs, bf, fiv) : cfb1Enc(bytes, bs, bf, fiv);
    return { ciphertext: cbody, iv: fiv, ivProvided: ivProvided , salt: saltUsed };
  }
  if (isCTS(mode)) {
    if (bytes.length < bs) throw new Error('CTS 明文至少需要 ' + bs + ' 字节');
    var civ = ivHex ? hexToBytes(ivHex) : crypto.getRandomValues(new Uint8Array(bs));
    if (civ.length !== bs) throw new Error('CTS 的 IV 必须为 ' + bs + ' 字节');
    if (ivHex) ivProvided = true;
    var variant = mode === 'CTS-CS1' ? 'CS1' : (mode === 'CTS-CS2' ? 'CS2' : 'CS3');
    return { ciphertext: ctsEnc(bytes, bs, bf, civ, variant), iv: civ, ivProvided: ivProvided , salt: saltUsed };
  }
  if (mode === 'LRW') {
    if (bs !== 16) throw new Error('LRW 仅支持 128 位块，' + (algo.name || algo.id) + ' 的块大小是 ' + bs + ' 字节');
    if (bytes.length < 16) throw new Error('LRW 明文至少需要 16 字节');
    var lkb = await deriveKeyBytes(key, algo.keyLen * 2, saltB, evpM);
    var lbf = algo.makeBlockFn(lkb.subarray(0, algo.keyLen));
    var lk2 = lkb.subarray(algo.keyLen, algo.keyLen + 16);
    var liv = ivHex ? hexToBytes(ivHex) : crypto.getRandomValues(new Uint8Array(16));
    if (liv.length !== 16) throw new Error('LRW 的 tweak 必须为 16 字节（32 位 Hex）');
    if (ivHex) ivProvided = true;
    return { ciphertext: lrwEnc(bytes, lbf, lk2, liv), iv: liv, ivProvided: ivProvided , salt: saltUsed };
  }
  if (modeNeedsIV(mode)) {
    if (ivHex) {
      iv = hexToBytes(ivHex);
      if (iv.length !== bs) throw new Error('IV 长度必须为 ' + bs + ' 字节（' + (bs * 2) + ' 位 Hex）');
      ivProvided = true;
    } else {
      iv = crypto.getRandomValues(new Uint8Array(bs));
    }
  }
  var body = (bytes.length > CHUNK_THRESHOLD && BLOCK_MODES.indexOf(mode) >= 0)
    ? await modeEncAsync(bytes, bs, bf.enc, mode, padMode, iv)
    : modeEnc(bytes, bs, bf.enc, mode, padMode, iv);
  var wantEmbed = (embedIV === undefined) ? true : !!embedIV;
  var out = (modeNeedsIV(mode) && wantEmbed) ? concatBytes(iv, body) : body;
  return { ciphertext: out, iv: iv, ivProvided: ivProvided , salt: saltUsed };
}
async function symDecrypt(algo, cipher, key, mode, padMode, ivHex, aadStr, saltHex, tagLen) {
  var bs = algo.blockSize;
  var saltB = saltHex ? hexToBytes(saltHex) : null;
  var evpM = null;
  if (typeof CURRENT_CONTAINER !== 'undefined') {
    if (CURRENT_CONTAINER === 'openssl') evpM = 'sha256';
    else if (CURRENT_CONTAINER === 'cryptojs') evpM = 'md5';
  }
  var iv = null;
  var body = cipher;
  /* AEAD 分支也要用 keyBytes，所以派生要提到分支之前
     （SIV 是双倍密钥，单独再派生一次） */
  var keyBytes = await deriveKeyBytes(key, algo.keyLen, saltB, evpM);
  var bf0 = algo.makeBlockFn(keyBytes);
  if (isAEAD(mode)) {
    if (!/^aes/.test(algo.id)) {
      throw new Error(mode + ' 模式仅支持 AES 系算法，' + (algo.name || algo.id) + ' 不适用');
    }
    var aad2 = strToBytes(aadStr || '');
    if (mode === 'GCM') {
      var nl = aeadNonceLen('GCM');
      if (cipher.length < nl + 16) throw new Error('GCM 密文长度不足（需 nonce + 密文 + 16 字节标签）');
      var ng = cipher.subarray(0, nl);
      var tg = cipher.subarray(cipher.length - 16);
      return aesGcmDecrypt(cipher.subarray(nl, cipher.length - 16), tg, keyBytes, ng, aad2);
    }
    if (mode === 'CCM') {
      var nl2 = aeadNonceLen('CCM');
      if (cipher.length < nl2 + 16) throw new Error('CCM 密文长度不足（需 nonce + 密文 + 16 字节标签）');
      var nc = cipher.subarray(0, nl2);
      var tc = cipher.subarray(cipher.length - 16);
      return aesCcmDecrypt(cipher.subarray(nl2, cipher.length - 16), tc, keyBytes, nc, aad2, 16);
    }
    if (mode === 'EAX') {
      var nlE = aeadNonceLen('EAX');
      if (cipher.length < nlE + 16) throw new Error('EAX 密文长度不足（需 nonce + 密文 + 16 字节标签）');
      return aesEaxDecrypt(cipher.subarray(nlE, cipher.length - 16), cipher.subarray(cipher.length - 16), keyBytes, cipher.subarray(0, nlE), aad2);
    }
    if (mode === 'OCB') {
      var nlO = aeadNonceLen('OCB');
      if (cipher.length < nlO + 16) throw new Error('OCB 密文长度不足（需 nonce + 密文 + 16 字节标签）');
      return aesOcbDecrypt(cipher.subarray(nlO, cipher.length - 16), cipher.subarray(cipher.length - 16), keyBytes, cipher.subarray(0, nlO), aad2);
    }
    var sivKey2 = await deriveKeyBytes(key, algo.keyLen * 2);
    if (cipher.length < 16) throw new Error('SIV 密文长度不足（需 16 字节 V + 密文）');
    return aesSivDecrypt(cipher, sivKey2, aad2.length ? [aad2] : []);
  }
  if (mode === 'PCBC') {
    if (cipher.length % bs) throw new Error('PCBC 密文长度必须是块大小 ' + bs + ' 的整数倍');
    if (!ivHex) throw new Error('PCBC 解密必须提供 IV');
    return pcbcDec(cipher, bs, bf0, padMode, hexToBytes(ivHex));
  }
  if (mode === 'CFB8' || mode === 'CFB1') {
    if (!ivHex) throw new Error(mode + ' 解密必须提供 IV');
    return (mode === 'CFB8') ? cfb8Dec(cipher, bs, bf0, hexToBytes(ivHex)) : cfb1Dec(cipher, bs, bf0, hexToBytes(ivHex));
  }
  if (isCTS(mode)) {
    if (cipher.length < bs) throw new Error('CTS 密文至少需要 ' + bs + ' 字节');
    if (!ivHex) throw new Error('CTS 解密必须提供 IV');
    var variant2 = mode === 'CTS-CS1' ? 'CS1' : (mode === 'CTS-CS2' ? 'CS2' : 'CS3');
    return ctsDec(cipher, bs, bf0, bf0, hexToBytes(ivHex), variant2);
  }
  if (mode === 'LRW') {
    if (bs !== 16) throw new Error('LRW 仅支持 128 位块');
    if (cipher.length < 16) throw new Error('LRW 密文至少需要 16 字节');
    if (!ivHex) throw new Error('LRW 解密必须提供 tweak（填在 IV 框）');
    var lkb2 = await deriveKeyBytes(key, algo.keyLen * 2, saltB, evpM);
    var lbf2 = algo.makeBlockFn(lkb2.subarray(0, algo.keyLen));
    return lrwDec(cipher, lbf2, lkb2.subarray(algo.keyLen, algo.keyLen + 16), hexToBytes(ivHex));
  }
  if (mode === 'XTS') {
    if (bs !== 16) throw new Error('XTS 模式仅支持 128 位（16 字节）块，' + (algo.name || algo.id) + ' 的块大小是 ' + bs + ' 字节');
    var kb = await deriveKeyBytes(key, algo.keyLen * 2);
    var dbf = algo.makeBlockFn(kb.subarray(0, algo.keyLen));
    var tbf = algo.makeBlockFn(kb.subarray(algo.keyLen, algo.keyLen * 2));
    if (!ivHex) throw new Error('XTS 解密必须提供 tweak（填在 IV 框）');
    var tw = hexToBytes(ivHex);
    if (tw.length !== 16) throw new Error('XTS 的 tweak 必须为 16 字节（32 位 Hex）');
    return xtsDec(cipher, dbf, tbf, tw);
  }
  var bf = bf0;
  if (modeNeedsIV(mode)) {
    if (ivHex) {
      iv = hexToBytes(ivHex);
      if (iv.length !== bs) throw new Error('IV 长度必须为 ' + bs + ' 字节（' + (bs * 2) + ' 位 Hex）');
      /* 现在默认格式是「密文不含 IV」，所以先按不带头部解密；
         解不通再退回旧格式（IV 头 + 密文），这样之前产生的老密文仍能用。
         注意：跳过头部后必须至少剩一个块，否则会把 1 块的密文误判成「只有 IV」而静默返回空。 */
      try {
        return (cipher.length > CHUNK_THRESHOLD && BLOCK_MODES.indexOf(mode) >= 0)
          ? await modeDecAsync(cipher, bs, bf.dec, mode, padMode, iv, bf.enc)
          : modeDec(cipher, bs, bf.dec, mode, padMode, iv, bf.enc);
      } catch (e1) {
        if (cipher.length > bs && cipher.length % bs === 0) {
          try {
            var cpart = cipher.subarray(bs);
            return (cpart.length > CHUNK_THRESHOLD && BLOCK_MODES.indexOf(mode) >= 0)
              ? await modeDecAsync(cpart, bs, bf.dec, mode, padMode, iv, bf.enc)
              : modeDec(cpart, bs, bf.dec, mode, padMode, iv, bf.enc);
          } catch (e2) { throw e1; }
        }
        throw e1;
      }
    } else {
      /* IV 框为空：只有旧格式（IV 头 + 密文）才能这样解。
         若密文长度不足「IV + 1 个块」，说明它不可能是带头部的格式，
         否则会把整个密文当 IV 而解出空内容，静默失败。 */
      if (cipher.length < bs * 2) {
        throw new Error('未提供 IV：当前密文不含 IV 头（长度不足），请把加密时生成的 IV 填入 IV 框');
      }
      iv = cipher.subarray(0, bs);
      body = cipher.subarray(bs);
    }
  }
  return (body.length > CHUNK_THRESHOLD && BLOCK_MODES.indexOf(mode) >= 0)
    ? await modeDecAsync(body, bs, bf.dec, mode, padMode, iv, bf.enc)
    : modeDec(body, bs, bf.dec, mode, padMode, iv, bf.enc);
}

reg({ id:'base64', name:'Base64', group:'编码', key:false, param:false,
  info:'标准 Base64 编码，输入文本按 UTF-8 处理。',
  enc:function(b){return bytesToBase64(b);}, dec:function(s){return base64ToBytes(s);} });
reg({ id:'base32', name:'Base32', group:'编码', key:false, param:false,
  info:'RFC 4648 Base32 编码。',
  enc:function(b){return base32Encode(b);}, dec:function(s){return base32Decode(s);} });
reg({ id:'base58', name:'Base58', group:'编码', key:false, param:false,
  info:'比特币风格 Base58。',
  enc:function(b){return base58Encode(b);}, dec:function(s){return base58Decode(s);} });
reg({ id:'base85', name:'Base85 (ASCII85)', group:'编码', key:false, param:false,
  info:'ASCII85 编码。',
  enc:function(b){return base85Encode(b);}, dec:function(s){return base85Decode(s);} });
reg({ id:'url', name:'URL 编码', group:'编码', key:false, param:false,
  info:'encodeURIComponent / decodeURIComponent。',
  enc:function(b){return encodeURIComponent(bytesToStr(b));}, dec:function(s){return strToBytes(decodeURIComponent(s));} });
reg({ id:'html', name:'HTML 实体', group:'编码', key:false, param:false,
  info:'转义 & < > " 单引号。',
  enc:function(b){return htmlEncode(bytesToStr(b));}, dec:function(s){return strToBytes(htmlDecode(s));} });
reg({ id:'unicode', name:'Unicode 转义序列', group:'编码', key:false, param:false,
  info:'\\uXXXX 形式。',
  enc:function(b){return unicodeEscape(bytesToStr(b));}, dec:function(s){return strToBytes(unicodeUnescape(s));} });
reg({ id:'hex', name:'16 进制编码', group:'编码', key:false, param:false,
  info:'每字节两位 Hex。',
  enc:function(b){return bytesToHex(b);}, dec:function(s){return hexToBytes(s);} });
reg({ id:'rot13', name:'ROT13', group:'编码', key:false, param:false,
  info:'字母旋转 13。',
  enc:function(b){return rot13(bytesToStr(b));}, dec:function(s){return strToBytes(rot13(s));} });
reg({ id:'caesar', name:'ASCII 移位 / 凯撒', group:'编码', key:false, param:true, paramLabel:'移位数（整数）',
  info:'仅对字母移位。',
  enc:function(b,k,p){return caesarShift(bytesToStr(b), p);}, dec:function(s,k,p){return strToBytes(caesarUnshift(s, p));} });
reg({ id:'morse', name:'摩尔斯电码', group:'编码', key:false, param:false,
  info:'字母间用空格，词间用 / 分隔。',
  enc:function(b){return morseEncode(bytesToStr(b));}, dec:function(s){return strToBytes(morseDecode(s));} });
reg({ id:'binary', name:'二进制', group:'编码', key:false, param:false,
  info:'每字节 8 位二进制。',
  enc:function(b){return Array.prototype.map.call(b,function(x){return x.toString(2).padStart(8,'0');}).join(' ');},
  dec:function(s){return new Uint8Array(String(s).trim().split(/\s+/).filter(Boolean).map(function(x){var v=parseInt(x,2);if(isNaN(v)||v>255)throw new Error('非法二进制:'+x);return v;}));} });
reg({ id:'octal', name:'八进制', group:'编码', key:false, param:false,
  info:'每字节 3 位八进制。',
  enc:function(b){return Array.prototype.map.call(b,function(x){return x.toString(8).padStart(3,'0');}).join(' ');},
  dec:function(s){return new Uint8Array(String(s).trim().split(/\s+/).filter(Boolean).map(function(x){var v=parseInt(x,8);if(isNaN(v)||v>255)throw new Error('非法八进制:'+x);return v;}));} });

var SHA256_K = new Uint32Array([
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);
var SHA256_IV = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
var SHA224_IV = new Uint32Array([0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4]);
function sha256Core(input, iv, outWords) {
  var h = iv.slice();
  var ml = input.length * 8;
  var total = Math.ceil((input.length + 9) / 64) * 64;
  var buf = new Uint8Array(total);
  buf.set(input);
  buf[input.length] = 0x80;
  var hiLen = Math.floor(ml / 4294967296), loLen = ml >>> 0;
  buf[total-8]=(hiLen>>>24)&255; buf[total-7]=(hiLen>>>16)&255; buf[total-6]=(hiLen>>>8)&255; buf[total-5]=hiLen&255;
  buf[total-4]=(loLen>>>24)&255; buf[total-3]=(loLen>>>16)&255; buf[total-2]=(loLen>>>8)&255; buf[total-1]=loLen&255;
  var w = new Uint32Array(64);
  for (var o = 0; o < total; o += 64) {
    for (var i = 0; i < 16; i++) w[i] = readU32BE(buf, o + i * 4);
    for (var i = 16; i < 64; i++) {
      var s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15]>>>3);
      var s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19) ^ (w[i-2]>>>10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    var a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (var i = 0; i < 64; i++) {
      var S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
      var ch = ((e & f) ^ (~e & g)) >>> 0;
      var t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      var S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
      var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      var t2 = (S0 + maj) >>> 0;
      hh=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    h[0]=(h[0]+a)>>>0; h[1]=(h[1]+b)>>>0; h[2]=(h[2]+c)>>>0; h[3]=(h[3]+d)>>>0;
    h[4]=(h[4]+e)>>>0; h[5]=(h[5]+f)>>>0; h[6]=(h[6]+g)>>>0; h[7]=(h[7]+hh)>>>0;
  }
  var out = new Uint8Array(outWords * 4);
  for (var i = 0; i < outWords; i++) writeU32BE(h[i], out, i * 4);
  return out;
}
function sha224Digest(input) { return sha256Core(input, SHA224_IV, 7); }

/* ============================================================
 * Keccak-f[1600] —— hi/lo 双 32 位字实现
 *
 * 原实现用 BigInt 保存 25 个 64 位通道，24 轮置换全部是任意精度运算：
 * SHA3-256 哈希 1MB 要 1.1 秒、SHA3-512 要 2.1 秒，
 * SPHINCS+ 签名（海量调用 SHAKE256）更是长达 24 秒。
 *
 * 改为把每个通道拆成 (hi, lo) 两个 32 位字、全部用 JS 原生位运算后，
 * 置换内部不再出现任何 BigInt。
 *
 * 状态表示：扁平数组 S（长度 50）
 *   S[2*i]     = 第 i 个通道的低 32 位
 *   S[2*i + 1] = 第 i 个通道的高 32 位
 * 字节序为【小端】，与 Keccak 规范一致。
 * ============================================================ */
var KEC_MASK = (1n << 64n) - 1n;   /* 保留：其它模块可能引用 */
function kecStateNew() { var s = new Array(50); for (var i = 0; i < 50; i++) s[i] = 0; return s; }

var KEC_RC = [
0x0000000000000001n,0x0000000000008082n,0x800000000000808An,0x8000000080008000n,
0x000000000000808Bn,0x0000000080000001n,0x8000000080008081n,0x8000000000008009n,
0x000000000000008An,0x0000000000000088n,0x0000000080008009n,0x000000008000000An,
0x000000008000808Bn,0x800000000000008Bn,0x8000000000008089n,0x8000000000008003n,
0x8000000000008002n,0x8000000000000080n,0x000000000000800An,0x800000008000000An,
0x8000000080008081n,0x8000000000008080n,0x0000000080000001n,0x8000000080008008n
];
var KEC_RC_LO = [], KEC_RC_HI = [];
for (var _k = 0; _k < KEC_RC.length; _k++) {
  KEC_RC_LO.push(Number(KEC_RC[_k] & 0xffffffffn));
  KEC_RC_HI.push(Number((KEC_RC[_k] >> 32n) & 0xffffffffn));
}
var KEC_ROT = [
[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]
];

/* ------------------------------------------------------------
 * 预计算表：把每轮内层循环里的 %5 取模与二维表访问全部消除。
 *   KEC_ROTF[i] = lane i 的 ρ 旋转位数（i = x + 5*y）
 *   KEC_PI[i]   = ρ+π 之后的落点 lane 索引 = y + 5*((2x+3y)%5)
 *   KEC_X1/X2[i]= χ 用到的 ((x+1)%5)+5y 与 ((x+2)%5)+5y
 *   KEC_TP1/TM4 = θ 里的 (x+1)%5 与 (x+4)%5
 * 全部由 KEC_ROT 在加载时一次算好，运行期只做查表。
 * ------------------------------------------------------------ */
var KEC_ROTF = new Int32Array(25), KEC_PI = new Int32Array(25);
var KEC_X1 = new Int32Array(25), KEC_X2 = new Int32Array(25);
(function () {
  for (var x = 0; x < 5; x++) for (var y = 0; y < 5; y++) {
    var i = x + 5 * y;
    KEC_ROTF[i] = KEC_ROT[x][y];
    KEC_PI[i]   = y + 5 * ((2 * x + 3 * y) % 5);
    KEC_X1[i]   = ((x + 1) % 5) + 5 * y;
    KEC_X2[i]   = ((x + 2) % 5) + 5 * y;
  }
})();
var KEC_TP1 = new Int32Array([1, 2, 3, 4, 0]);
var KEC_TM4 = new Int32Array([4, 0, 1, 2, 3]);

/* 复用临时数组：keccakF 是纯串行的（无重入、无并发），
   提到模块级可避免每块 6 次数组分配 —— 64KB 输入下约 3000 次。 */
var _kecCh = new Int32Array(5), _kecCl = new Int32Array(5);
var _kecDh = new Int32Array(5), _kecDl = new Int32Array(5);
var _kecBh = new Int32Array(25), _kecBl = new Int32Array(25);

function keccakF(S, rounds) {
  /* rounds 省略时为标准 24 轮；TurboSHAKE/KangarooTwelve 需要 12 轮，
     此时从第 24-12=12 轮开始（Keccak-p[1600,n_r=12] 的定义），不是从 0 开始。 */
  var start = (rounds === undefined || rounds === 24) ? 0 : (24 - rounds);
  var Ch = _kecCh, Cl = _kecCl, Dh = _kecDh, Dl = _kecDl, Bh = _kecBh, Bl = _kecBl;
  var x, y, r, hi, lo, t, m, n, i4, dst;
  for (r = start; r < 24; r++) {
    /* θ 第一步：C[x] = 第 x 列五个 lane 的异或（索引按 10 步进，展开避免乘法） */
    for (x = 0; x < 5; x++) {
      var a = 2 * x, b = a + 10, c = a + 20, d = a + 30, e = a + 40;
      Ch[x] = (S[a+1] ^ S[b+1] ^ S[c+1] ^ S[d+1] ^ S[e+1]) >>> 0;
      Cl[x] = (S[a]   ^ S[b]   ^ S[c]   ^ S[d]   ^ S[e]  ) >>> 0;
    }
    /* D[x] = C[(x+4)%5] XOR rotl(C[(x+1)%5], 1) */
    for (x = 0; x < 5; x++) {
      var p1 = KEC_TP1[x], m4 = KEC_TM4[x];
      var h1 = Ch[p1], l1 = Cl[p1];
      var rh = ((h1 << 1) | (l1 >>> 31)) >>> 0;
      var rl = ((l1 << 1) | (h1 >>> 31)) >>> 0;
      Dh[x] = (Ch[m4] ^ rh) >>> 0;
      Dl[x] = (Cl[m4] ^ rl) >>> 0;
    }
    /* θ 第二步与 ρ+π 合并：直接读 S、异或 D、旋转、写入 B。
       原实现先写回 S 再从 S 读，多出 25 次写 + 25 次读。 */
    for (y = 0; y < 5; y++) for (x = 0; x < 5; x++) {
      i4 = x + 5 * y;
      hi = (S[2*i4+1] ^ Dh[x]) >>> 0;
      lo = (S[2*i4]   ^ Dl[x]) >>> 0;
      n = KEC_ROTF[i4];
      if (n === 0) { /* lane 0 不旋转 */ }
      else if (n >= 32) {
        m = n - 32;
        if (m === 0) { t = hi; hi = lo; lo = t; }
        else {
          t  = ((lo << m) | (hi >>> (32 - m))) >>> 0;
          lo = ((hi << m) | (lo >>> (32 - m))) >>> 0;
          hi = t;
        }
      } else {
        t  = ((hi << n) | (lo >>> (32 - n))) >>> 0;
        lo = ((lo << n) | (hi >>> (32 - n))) >>> 0;
        hi = t;
      }
      dst = KEC_PI[i4];
      Bh[dst] = hi; Bl[dst] = lo;
    }
    /* χ：A[i] = B[i] XOR (~B[i+1] AND B[i+2]) */
    for (i4 = 0; i4 < 25; i4++) {
      var i5 = KEC_X1[i4], i6 = KEC_X2[i4];
      S[2*i4+1] = (Bh[i4] ^ (~Bh[i5] & Bh[i6])) >>> 0;
      S[2*i4]   = (Bl[i4] ^ (~Bl[i5] & Bl[i6])) >>> 0;
    }
    /* ι：只在 lane 0 上加轮常量 */
    S[1] = (S[1] ^ KEC_RC_HI[r]) >>> 0;
    S[0] = (S[0] ^ KEC_RC_LO[r]) >>> 0;
  }
}

function kecXorLane(S, laneIdx, bytes, off) {
  var lo = (bytes[off] | (bytes[off+1] << 8) | (bytes[off+2] << 16) | (bytes[off+3] << 24)) >>> 0;
  var hi = (bytes[off+4] | (bytes[off+5] << 8) | (bytes[off+6] << 16) | (bytes[off+7] << 24)) >>> 0;
  S[2*laneIdx]   = (S[2*laneIdx]   ^ lo) >>> 0;
  S[2*laneIdx+1] = (S[2*laneIdx+1] ^ hi) >>> 0;
}
function keccakStateToBytes(S, lanes) {
  var out = new Uint8Array(lanes * 8);
  for (var i = 0; i < lanes; i++) {
    var lo = S[2*i], hi = S[2*i+1];
    out[i*8]   = lo & 0xff;        out[i*8+1] = (lo >>> 8) & 0xff;
    out[i*8+2] = (lo >>> 16) & 0xff; out[i*8+3] = (lo >>> 24) & 0xff;
    out[i*8+4] = hi & 0xff;        out[i*8+5] = (hi >>> 8) & 0xff;
    out[i*8+6] = (hi >>> 16) & 0xff; out[i*8+7] = (hi >>> 24) & 0xff;
  }
  return out;
}
function keccakAbsorb(S, input, rateBytes, padByte) {
  padByte = (padByte === undefined) ? 0x1F : padByte;
  var lanes = rateBytes / 8;
  var off = 0;
  var blocks = Math.floor(input.length / rateBytes);
  for (var b = 0; b < blocks; b++) {
    for (var i = 0; i < lanes; i++) kecXorLane(S, i, input, off + i * 8);
    keccakF(S);
    off += rateBytes;
  }
  var rem = input.length - off;
  var pad = new Uint8Array(rateBytes);
  pad.set(input.subarray(off));
  pad[rem] = padByte;               /* SHAKE 用 0x1F，cSHAKE 用 0x04，SHA3 用 0x06 */
  pad[rateBytes - 1] |= 0x80;
  for (var i = 0; i < lanes; i++) kecXorLane(S, i, pad, i * 8);
  keccakF(S);
}
function keccakDigest(input, rateBytes, outLen, padByte) {
  var S = kecStateNew();
  keccakAbsorb(S, input, rateBytes, padByte);
  var lanes = rateBytes / 8;
  var out = new Uint8Array(outLen), produced = 0;
  while (produced < outLen) {
    for (var i = 0; i < lanes && produced < outLen; i++) {
      var lo = S[2*i], hi = S[2*i+1];
      var b0 = lo & 0xff, b1 = (lo >>> 8) & 0xff, b2 = (lo >>> 16) & 0xff, b3 = (lo >>> 24) & 0xff;
      var b4 = hi & 0xff, b5 = (hi >>> 8) & 0xff, b6 = (hi >>> 16) & 0xff, b7 = (hi >>> 24) & 0xff;
      var seq = [b0,b1,b2,b3,b4,b5,b6,b7];
      for (var j = 0; j < 8 && produced < outLen; j++) out[produced++] = seq[j];
    }
    if (produced < outLen) keccakF(S);
  }
  return out;
}
function sha3Digest(input, outLen) { return keccakDigest(input, outLen === 32 ? 136 : 72, outLen, 0x06); }

function oneway(cfg) { cfg.oneway = true; cfg.dec = function () { throw new Error('单向哈希不支持解密'); }; reg(cfg); }
oneway({ id:'md5', name:'MD5', group:'单向哈希', key:false, param:false, info:'128 位摘要。', enc:function(b,k,p,f){return bytesOut(md5Digest(b),f);} });
oneway({ id:'sha1', name:'SHA-1', group:'单向哈希', key:false, param:false, info:'160 位摘要。', enc:async function(b,k,p,f){return bytesOut(await webCryptoHash('SHA-1',b),f);} });
oneway({ id:'sha224', name:'SHA-224', group:'单向哈希', key:false, param:false, info:'SHA-2 家族，224 位摘要（纯 JS 实现）。', enc:function(b,k,p,f){return bytesOut(sha224Digest(b),f);} });
oneway({ id:'sha256', name:'SHA-256', group:'单向哈希', key:false, param:false, info:'SHA-2 家族，最常用。', enc:async function(b,k,p,f){return bytesOut(await webCryptoHash('SHA-256',b),f);} });
oneway({ id:'sha384', name:'SHA-384', group:'单向哈希', key:false, param:false, info:'SHA-2 家族。', enc:async function(b,k,p,f){return bytesOut(await webCryptoHash('SHA-384',b),f);} });
oneway({ id:'sha512', name:'SHA-512', group:'单向哈希', key:false, param:false, info:'SHA-2 家族。', enc:async function(b,k,p,f){return bytesOut(await webCryptoHash('SHA-512',b),f);} });
oneway({ id:'sha3-256', name:'SHA-3-256', group:'单向哈希', key:false, param:false, info:'Keccak 标准，纯 JS 实现。', enc:function(b,k,p,f){return bytesOut(sha3Digest(b,32),f);} });
oneway({ id:'sha3-512', name:'SHA-3-512', group:'单向哈希', key:false, param:false, info:'Keccak 标准，纯 JS 实现。', enc:function(b,k,p,f){return bytesOut(sha3Digest(b,64),f);} });
oneway({ id:'blake2s', name:'BLAKE2s-256', group:'单向哈希', key:false, param:false, info:'纯 JS 实现。', enc:function(b,k,p,f){return bytesOut(blake2sDigest(b,32),f);} });
oneway({ id:'sm3', name:'SM3', group:'单向哈希', key:false, param:false, info:'中国商用哈希标准。', enc:function(b,k,p,f){return bytesOut(sm3Digest(b),f);} });

function regSym(cfg) {
  cfg.isSym = true;
  cfg.key = true;
  cfg.param = false;
  reg(cfg);
}

regSym({ id:'aes128', name:'AES-128', group:'对称加密',
  keyLabel:'密钥（任意字符串，SHA-256 派生 16 字节）',
  blockSize:16, keyLen:16, makeBlockFn:aesMakeBlockFn,
  info:'AES-128 分组密码，支持 ECB/CBC/CFB/OFB/CTR，IV 自动生成并前置。' });
regSym({ id:'aes192', name:'AES-192', group:'对称加密',
  keyLabel:'密钥（任意字符串，SHA-256 派生 24 字节）',
  blockSize:16, keyLen:24, makeBlockFn:aesMakeBlockFn,
  info:'AES-192 分组密码，支持 ECB/CBC/CFB/OFB/CTR。' });
regSym({ id:'aes256', name:'AES-256', group:'对称加密',
  keyLabel:'密钥（任意字符串，SHA-256 派生 32 字节）',
  blockSize:16, keyLen:32, makeBlockFn:aesMakeBlockFn,
  info:'AES-256 分组密码，支持 ECB/CBC/CFB/OFB/CTR。' });
regSym({ id:'des', name:'DES', group:'对称加密',
  keyLabel:'密钥（任意字符串，SHA-256 派生 8 字节）',
  blockSize:8, keyLen:8, makeBlockFn:desMakeBlockFn,
  info:'DES 分组密码，支持 ECB/CBC/CFB/OFB/CTR。' });
regSym({ id:'3des', name:'3DES (Triple DES)', group:'对称加密',
  keyLabel:'密钥（任意字符串，SHA-256 派生 24 字节）',
  blockSize:8, keyLen:24, makeBlockFn:des3MakeBlockFn,
  info:'3DES-EDE 分组密码，支持 ECB/CBC/CFB/OFB/CTR。' });
regSym({ id:'sm4', name:'SM4', group:'对称加密',
  keyLabel:'密钥（任意字符串，SHA-256 派生 16 字节）',
  blockSize:16, keyLen:16, makeBlockFn:sm4MakeBlockFn,
  info:'中国商用分组密码，支持 ECB/CBC/CFB/OFB/CTR。' });
regSym({ id:'rc5', name:'RC5', group:'对称加密',
  keyLabel:'密钥（任意字符串，SHA-256 派生 16 字节）',
  blockSize:8, keyLen:16, makeBlockFn:rc5MakeBlockFn,
  info:'RC5-32/12/16，支持 ECB/CBC/CFB/OFB/CTR。' });
regSym({ id:'rc6', name:'RC6', group:'对称加密',
  keyLabel:'密钥（任意字符串，SHA-256 派生 16 字节）',
  blockSize:16, keyLen:16, makeBlockFn:rc6MakeBlockFn,
  info:'RC6-32/20/16，支持 ECB/CBC/CFB/OFB/CTR。' });

reg({ id:'rc4', name:'RC4', group:'对称加密', key:true, keyLabel:'密钥（任意字符串）', param:false,
  info:'流密码，密钥取自 SHA-256 全部 32 字节。',
  enc:async function(b,k){var kb=await deriveKeyBytes(k,32);return bytesToBase64(rc4Process(kb,b));},
  dec:async function(s,k,f){var kb=await deriveKeyBytes(k,32);return rc4Process(kb, base64ToBytes(s));} });
reg({ id:'chacha20', name:'ChaCha20', group:'对称加密', key:true, keyLabel:'密钥（任意字符串，SHA-256 派生 32 字节）', param:false,
  info:'流密码，12 字节随机 nonce 前置。',
  enc:async function(b,k,f){
    var kb=await deriveKeyBytes(k,32);
    var nonce=crypto.getRandomValues(new Uint8Array(12));
    var ct=chacha20Process(kb,nonce,0,b);
    return bytesToBase64(concatBytes(nonce,ct));
  },
  dec:async function(s,k,f){
    var raw=base64ToBytes(s);
    var kb=await deriveKeyBytes(k,32);
    return chacha20Process(kb, raw.subarray(0,12), 0, raw.subarray(12));
  } });

reg({ id:'rsa', name:'RSA (RSA-OAEP)', group:'非对称加密', key:true,
  keyLabel:'加密填公钥 PEM，解密填私钥 PEM', param:false,
  info:'RSA-OAEP + SHA-256。加密填公钥（SPKI PEM），解密填私钥（PKCS#8 PEM）。',
  enc:async function(b,k,f){if(!k)throw new Error('请输入公钥 PEM');return bytesOut(await rsaEncryptData(b,k),f);},
  dec:async function(s,k,f){if(!k)throw new Error('请输入私钥 PEM');return rsaDecryptData(bytesIn(s,f),k);} });
reg({ id:'rsa-pss', name:'RSA-PSS 签名', group:'非对称加密', key:true,
  keyLabel:'加密（签名）填私钥 PEM，解密（验签）填公钥 PEM', param:true, paramLabel:'验签时的签名（Base64）',
  info:'RSA-PSS + SHA-256 + MGF1，盐长 32 字节。PSS 是概率性签名（每次签名结果不同），比 RSA PKCS#1 v1.5 更安全，是新系统的推荐选择。加密＝私钥签名；解密＝公钥验签（参数栏填签名）。',
  enc:async function(b,k,p,f){ if(!k)throw new Error('请输入私钥 PEM'); return bytesOut(await rsaPssSign(b,k),f); },
  dec:async function(s,k,p){ if(!k)throw new Error('请输入公钥 PEM'); if(!p)throw new Error('请在参数栏填入签名');
    var ok=await rsaPssVerify(strToBytes(s),base64ToBytes(p),k);
    return strToBytes(ok?'验签通过：签名有效':'验签失败：签名无效或数据被篡改'); } });
reg({ id:'ecdsa-p256', name:'ECDSA (P-256)', group:'非对称加密', key:true,
  keyLabel:'加密（签名）填私钥，解密（验签）填公钥', param:true, paramLabel:'验签时的签名（Base64）',
  info:'加密 = 私钥签名；解密 = 公钥验签，需在参数栏填签名。',
  enc:async function(b,k,p,f){if(!k)throw new Error('请输入私钥 PEM');return bytesOut(await ecdsaSignData(b,k,'P-256'),f);},
  dec:async function(s,k,p){if(!k)throw new Error('请输入公钥 PEM');if(!p)throw new Error('请填签名');var r=await ecdsaVerifyData(strToBytes(s),base64ToBytes(p),k,'P-256');return strToBytes(r);} });
reg({ id:'ecdsa-p384', name:'ECDSA (P-384)', group:'非对称加密', key:true,
  keyLabel:'加密（签名）填私钥，解密（验签）填公钥', param:true, paramLabel:'验签时的签名（Base64）',
  info:'同上，使用 P-384 曲线。',
  enc:async function(b,k,p,f){if(!k)throw new Error('请输入私钥 PEM');return bytesOut(await ecdsaSignData(b,k,'P-384'),f);},
  dec:async function(s,k,p){if(!k)throw new Error('请输入公钥 PEM');if(!p)throw new Error('请填签名');var r=await ecdsaVerifyData(strToBytes(s),base64ToBytes(p),k,'P-384');return strToBytes(r);} });
reg({ id:'ed25519', name:'EdDSA (Ed25519)', group:'非对称加密', key:true,
  keyLabel:'加密（签名）填私钥，解密（验签）填公钥', param:true, paramLabel:'验签时的签名（Base64）',
  info:'加密 = 私钥签名；解密 = 公钥验签。需要浏览器支持 Ed25519。',
  enc:async function(b,k,p,f){if(!k)throw new Error('请输入私钥 PEM');return bytesOut(await ed25519SignData(b,k),f);},
  dec:async function(s,k,p){if(!k)throw new Error('请输入公钥 PEM');if(!p)throw new Error('请填签名');var r=await ed25519VerifyData(strToBytes(s),base64ToBytes(p),k);return strToBytes(r);} });
reg({ id:'ecdh-p256', name:'ECDH (P-256 密钥协商)', group:'非对称加密', key:true,
  keyLabel:'己方私钥 PEM', param:true, paramLabel:'对方公钥 PEM',
  info:'加密与解密同一操作：协商出 32 字节共享密钥。',
  enc:async function(b,k,p,f){if(!k||!p)throw new Error('需要己方私钥与对方公钥');return bytesOut(await ecdhDerive(k,p,'P-256'),f);},
  dec:async function(s,k,p){if(!k||!p)throw new Error('需要己方私钥与对方公钥');return ecdhDerive(k,p,'P-256');} });

/* ============================================================
 * UI
 * ============================================================ */
/* 无 DOM 环境（Web Worker / Node 测试）下返回 null，而不是抛 ReferenceError。
   这样本文件可被 Worker 直接 importScripts 以复用全部算法实现。 */
var $ = function (id) {
  return (typeof document !== 'undefined' && document.getElementById) ? document.getElementById(id) : null;
};
var els = {
  algo: $('algo'), fileIn: $('fileIn'), btnDownload: $('btnDownload'), btnImportKey: $('btnImportKey'), keyField: $('keyField'), keyLabel: $('keyLabel'), key: $('key'), keyMode: $('keyMode'),
  paramField: $('paramField'), paramLabel: $('paramLabel'), param: $('param'),
  cipherRow: $('cipherRow'), modeField: $('modeField'), mode: $('mode'),
  padField: $('padField'), padding: $('padding'), ivField: $('ivField'), iv: $('iv'),
  algoInfo: $('algoInfo'), input: $('input'), drop: $('drop'), dropText: $('dropText'),
  file: $('file'), fileInfo: $('fileInfo'), fmt: $('fmt'),
  btnEnc: $('btnEnc'), btnDec: $('btnDec'), btnClear: $('btnClear'),
  container: $('container'), salt: $('salt'), tagLen: $('tagLen'), aad: $('aad'),
  padStrict: $('padStrict'), saltField: $('saltField'),
  algoSearch: $('algoSearch'), secWarn: $('secWarn'), nonceGuard: $('nonceGuard'),
  btnSelftest: $('btnSelftest'), selftestBox: $('selftestBox'), selftestOut: $('selftestOut'), nonceGuardField: $('nonceGuardField'), btnClearNonce: $('btnClearNonce'),
  kdf: $('kdf'), kdfIter: $('kdfIter'), kdfField: $('kdfField'), kdfIterField: $('kdfIterField'),
  kdfHash: $('kdfHash'), kdfHashField: $('kdfHashField'), kdfIterLabel: $('kdfIterLabel'),
  aadField: $('aadField'), tagLenField: $('tagLenField'),
  output: $('output'), ivInfoBox: $('ivInfoBox'), ivInfoLabel: $('ivInfoLabel'), ivInfoValue: $('ivInfoValue'),
  btnCopyIV: $('btnCopyIV'), btnCopy: $('btnCopy'), btnDownload: $('btnDownload'), msg: $('msg')
};
var pendingFile = null;
var busy = false;
var MAX_FILE_SIZE = 100 * 1024 * 1024;

function buildAlgoList() {
  if (!els.algo) return;
  while (els.algo.firstChild) els.algo.removeChild(els.algo.firstChild);
  var groups = {};
  for (var i = 0; i < ALGOS.length; i++) {
    var a = ALGOS[i];
    if (!groups[a.group]) groups[a.group] = [];
    groups[a.group].push(a);
  }
  var keys = Object.keys(groups);
  for (var k = 0; k < keys.length; k++) {
    var og = document.createElement('optgroup');
    og.label = keys[k];
    var list = groups[keys[k]];
    for (var j = 0; j < list.length; j++) {
      var opt = document.createElement('option');
      opt.value = list[j].id;
      opt.textContent = list[j].name;
      og.appendChild(opt);
    }
    els.algo.appendChild(og);
  }
}

function rebuildAlgoList() {
  if (!els.algo) return;
  var keep = els.algo.value;
  while (els.algo.firstChild) els.algo.removeChild(els.algo.firstChild);
  buildAlgoList();
  if (keep) els.algo.value = keep;
  if (!els.algo.value && els.algo.options.length) els.algo.selectedIndex = 0;
  /* 原生 select 是分类选择器的唯一状态源，重建后必须让自定义面板同步重绘，
     否则面板里显示的仍是旧列表（条目增删后会错位）。 */
  if (typeof algoRenderPanel === 'function') algoRenderPanel();
  if (typeof algoSyncButton === 'function') algoSyncButton();
}
window.rebuildAlgoList = rebuildAlgoList;

function currentAlgo() {
  if (!els.algo) return null;
  var id = els.algo.value;
  for (var i = 0; i < ALGOS.length; i++) if (ALGOS[i].id === id) return ALGOS[i];
  return ALGOS[0];
}

function updateAlgoUI() {
  var a = currentAlgo();
  if (!a) return;
  if (els.keyField) els.keyField.classList.toggle('hidden', !a.key);
  if (a.key && els.keyLabel) els.keyLabel.textContent = a.keyLabel || '密钥';
  if (els.paramField) els.paramField.classList.toggle('hidden', !a.param);
  if (a.param && els.paramLabel) els.paramLabel.textContent = a.paramLabel || '参数';
  if (els.algoInfo) els.algoInfo.textContent = a.info || '';
  if (els.cipherRow) els.cipherRow.classList.toggle('hidden', !a.isSym);
  if (a.isSym) {
    updateModePadUI();
  } else if (els.ivInfoBox) {
    els.ivInfoBox.classList.add('hidden');
  }
  /* 切换算法后，若当前模式不被该算法支持，自动回退到 CBC 并提示。
     否则默认模式 GCM 会让非 AES 算法一加密就报错。 */
  if (a.isSym && els.mode && !modeSupportedBy(els.mode.value, a)) {
    var oldMode = els.mode.value;
    setSelectValue(els.mode, fallbackModeFor(a));
    if (typeof setMsg === 'function') {
      setMsg('已把模式从 ' + oldMode + ' 切到 ' + fallbackModeFor(a) + '：' +
        (a.name || a.id) + ' 不支持 ' + oldMode + '（该模式的认证部分以 AES 原语实现）。' +
        '如需认证加密，请改用 AES-256-GCM。', 'warn');
    }
  }
  /* 非对称/哈希算法不走 updateModePadUI，这里单独刷新安全提示 */
  if (!a.isSym) refreshSecurity();
}

/* 统一安全提示：扫描当前所有选择，按 danger / warn / info 分级渲染。
   任何相关控件变化都会调用它。 */
var SEC_LEVEL_STYLE = {
  danger: { label: '严重', color: '#c62828', bg: '#fdecea' },
  warn:   { label: '警告', color: '#8d6e00', bg: '#fff8e1' },
  info:   { label: '说明', color: '#1565c0', bg: '#e8f1fb' }
};
function refreshSecurity() {
  if (!els.secWarn || typeof securityAudit !== 'function') return;
  var cur = currentAlgo();
  var cfg = {
    algoId: cur ? cur.id : '',
    isSym: !!(cur && cur.isSym),
    blockSize: cur ? cur.blockSize : 0,
    mode: (cur && cur.isSym && els.mode) ? els.mode.value : '',
    pad: els.pad ? els.pad.value : '',
    padStrict: els.padStrict ? els.padStrict.value : '',
    kdfMode: els.kdf ? els.kdf.value : '',
    kdfIter: els.kdfIter ? els.kdfIter.value : '',
    kdfHash: els.kdfHash ? els.kdfHash.value : '',
    nonceGuard: els.nonceGuard ? els.nonceGuard.value : '',
    container: (typeof CURRENT_CONTAINER !== 'undefined') ? CURRENT_CONTAINER : '',
    tagLen: els.tagLen ? els.tagLen.value : '',
    fmt: els.fmt ? els.fmt.value : ''
  };
  var ws = securityAudit(cfg);
  if (!ws.length) { els.secWarn.classList.add('hidden'); els.secWarn.innerHTML = ''; return; }
  var order = { danger: 0, warn: 1, info: 2 };
  ws.sort(function (a, b) { return (order[a.level] || 3) - (order[b.level] || 3); });
  var top = ws[0].level;
  els.secWarn.classList.remove('notice--danger', 'notice--warn', 'notice--info');
  els.secWarn.classList.add(top === 'danger' ? 'notice--danger' : (top === 'warn' ? 'notice--warn' : 'notice--info'));
  var html = '<b>安全提示（' + ws.length + '）</b>';
  for (var i = 0; i < ws.length; i++) {
    var w = ws[i], st = SEC_LEVEL_STYLE[w.level] || SEC_LEVEL_STYLE.info;
    html += '<div style="margin-top:8px;padding:7px 9px;border-left:3px solid ' + st.color +
      ';background:' + st.bg + ';border-radius:3px">' +
      '<b style="color:' + st.color + '">[' + st.label + '] ' + w.title + '</b><br>' +
      '<span style="opacity:.85">' + w.why + '</span><br>' +
      '<b>建议</b>：' + w.use + '</div>';
  }
  els.secWarn.innerHTML = html;
  els.secWarn.classList.remove('hidden');
}

function updateModePadUI() {
  var mode = els.mode ? els.mode.value : 'GCM';
  var cur = currentAlgo();
  /* IV 框：XTS 装 tweak，GCM/CCM 装 nonce，SIV 不用（确定性），ECB 不用 */
  var needIV = (mode === 'SIV' || mode === 'ECB') ? false : true;
  /* AEAD 需要 AAD 输入框（复用 param 框），非 AEAD 时按算法本身的配置还原 */
  if (els.paramField) {
    var needAad = isAEAD(mode);
    els.paramField.classList.toggle('hidden', needAad ? false : !(cur && cur.param));
    if (needAad && els.paramLabel) els.paramLabel.textContent = 'AAD 附加认证数据（可选）';
    else if (cur && cur.paramLabel && els.paramLabel) els.paramLabel.textContent = cur.paramLabel;
  }
  /* 安全提示统一由 refreshSecurity 渲染（覆盖算法/模式/填充/KDF/nonce/容器/格式） */
  refreshSecurity();
  if (els.aadField) els.aadField.classList.toggle('hidden', !isAEAD(mode));
  /* nonce 复用检测只对 GCM/CCM 有意义（SIV 抗误用、其它模式无 nonce 语义） */
  if (els.nonceGuardField) els.nonceGuardField.classList.toggle('hidden', !(mode === 'GCM' || mode === 'CCM' || mode === 'EAX' || mode === 'OCB'));
  if (els.tagLenField) els.tagLenField.classList.toggle('hidden', !isAEAD(mode));
  var needPad = modeUsesPadding(mode) && !isAEAD(mode);
  if (els.ivField) els.ivField.classList.toggle('hidden', !needIV);
  if (els.padField) {
    var hidePad = !needPad;
    if (!hidePad && cur && cur.isSym === false) hidePad = true;
    els.padField.classList.toggle('hidden', hidePad);
  }
  /* IV 框的提示语随模式变化，避免用户填错 */
  var ivLabel = document.querySelector('label[for="iv"]');
  if (ivLabel) {
    if (mode === 'XTS') ivLabel.textContent = 'Tweak（留空则自动生成并回写）';
    else if (mode === 'GCM' || mode === 'CCM') ivLabel.textContent = 'Nonce（留空则自动生成并回写）';
    else ivLabel.textContent = 'IV（留空则自动生成并回写）';
  }
}

/* 把底层（Web Crypto 等）抛出的原始英文错误翻译成用户能看懂的提示 */
function friendlyError(e) {
  var m = (e && e.message) ? String(e.message) : String(e || '未知错误');
  if (/Invalid keyData|keyData/i.test(m)) return '密钥或密钥文件格式不正确：请检查是否粘贴完整（PEM 需包含 -----BEGIN / END----- 两行）。';
  if (/DataError|too large|too long/i.test(m)) return '数据过大或格式不对：非对称算法单次能处理的数据长度有限，长内容请改用对称加密。';
  if (/OperationError/i.test(m)) return '操作失败：密钥与算法不匹配，或数据已被篡改（校验未通过）。';
  if (/NotSupportedError/i.test(m)) return '当前浏览器不支持该算法或该参数组合。';
  return m;
}
function setMsg(text, cls) {
  if (!els.msg) return;
  els.msg.textContent = text || '';
  els.msg.className = 'status' + (cls ? ' ' + cls : '');
}

function clearFile() {
  pendingFile = null;
  try { if (els.file) els.file.value = ''; } catch (e) {}
  if (els.fileInfo) els.fileInfo.textContent = '';
  if (els.input) els.input.placeholder = '在此输入文本，或拖拽文件到下方';
  if (els.dropText) els.dropText.textContent = '拖拽文件到此处，或点击选择文件';
}

async function loadFile(f) {
  if (!f) return;
  if (f.size > MAX_FILE_SIZE) { setMsg('文件过大（上限 ' + (MAX_FILE_SIZE/1024/1024) + 'MB）', 'err'); return; }
  try {
    var buf = await f.arrayBuffer();
    pendingFile = { name: f.name || ('未命名_' + Date.now()), bytes: new Uint8Array(buf) };
    if (els.input) { els.input.value = ''; els.input.placeholder = '已选择文件，输入框内容将被忽略'; }
    if (els.fileInfo) els.fileInfo.textContent = '已加载：' + pendingFile.name + '（' + pendingFile.bytes.length + ' 字节）';
    if (els.dropText) els.dropText.textContent = '已选择：' + pendingFile.name + '（点击可重新选择）';
    setMsg('');
  } catch (e) { setMsg('读取文件失败：' + e.message, 'err'); }
}

function getInputBytes() {
  if (pendingFile) return pendingFile.bytes;
  return strToBytes(els.input ? els.input.value : '');
}
function renderOutput(result) {
  if (!els.output) return;
  if (typeof result === 'string') { els.output.value = result; return; }
  /* 算法可以返回 { text, textInfo }：正文进输出框，说明部分追加在下方。
     注意先判这个分支——普通字节（Uint8Array）也有 length，会被下面的分支吃掉。 */
  if (result && typeof result === 'object' && result.length === undefined && typeof result.text === 'string') {
    els.output.value = result.text + (result.textInfo ? '\n\n' + result.textInfo : '');
    return;
  }
  if (!result || result.length === 0) { els.output.value = ''; return; }
  try { els.output.value = bytesToStr(result); }
  catch (e) { els.output.value = '[二进制数据，' + result.length + ' 字节]\n' + bytesToHex(result); }
}
function setBusy(on) {
  busy = on;
  if (els.btnEnc) els.btnEnc.disabled = on;
  if (els.btnDec) els.btnDec.disabled = on;
  if (!on) { JOB.running = false; var b = document.getElementById('btnCancel'); if (b) b.classList.add('hidden'); }
}

/* IV 框里可能是「用户手填」也可能是「上次自动回写」的。
   只有用户手填的才应参与下次加密——否则连点两次加密就会复用同一个 nonce，
   这在 GCM/CCM 下是灾难性的。用户一改动输入框就置位。 */
var _ivUserEdited = false;
function markIvUserEdited() { _ivUserEdited = true; }
function resetIvEdited() { _ivUserEdited = false; }

/* ============================================================
 * Web Worker 封装（零依赖手写）
 *
 * 只有【无状态】运算适合丢给 Worker：单向哈希与 KDF。
 * 对称 / 非对称加解密会写 nonce 记录、回写 IV 等 UI 状态，
 * 放后台线程会导致两边状态不一致，故一律留在主线程。
 *
 * Worker 创建失败时（file:// 协议下多数浏览器会拦截、
 * 或环境不支持）自动回退到主线程同步执行 —— 结果完全一致，
 * 只是期间页面会短暂卡顿。
 * ============================================================ */
var WW = { worker: null, ready: false, failed: false, seq: 0, pending: {} };
var WW_STATELESS = /^(md5|sha1|sha224|sha256|sha384|sha512|sha3-256|sha3-512|sha512-224|sha512-256|blake2b|blake2s|blake3|sm3|ripemd160|streebog256|streebog512|shake128|shake256|cshake128|cshake256|md4|crc32|crc32c|adler32|pbkdf2|hkdf|scrypt|argon2id|argon2i|argon2d|hmac|cmac|kmac128|kmac256|poly1305)$/;

function wwInit() {
  if (WW.worker || WW.failed) return WW.worker;
  try {
    if (typeof Worker === 'undefined') { WW.failed = true; return null; }
    WW.worker = new Worker('crypto_worker.js');
    WW.worker.onmessage = function (e) {
      var m = e.data || {};
      var p = WW.pending[m.id];
      if (!p) return;
      delete WW.pending[m.id];
      if (m.ok) p.resolve(new Uint8Array(m.out || []));
      else p.reject(new Error(m.err || 'Worker 执行失败'));
    };
    WW.worker.onerror = function (ev) {
      WW.failed = true;
      for (var k in WW.pending) { WW.pending[k].reject(new Error('Worker 异常')); delete WW.pending[k]; }
      try { WW.worker.terminate(); } catch (e2) {}
      WW.worker = null;
    };
    WW.ready = true;
  } catch (e) {
    WW.failed = true; WW.worker = null;
  }
  return WW.worker;
}
function wwAvailable() {
  if (WW.failed) return false;
  if (WW.worker) return true;
  return !!wwInit();
}
async function wwRun(algo, bytes, key, param, fmt) {
  if (!algo || !algo.oneway || !WW_STATELESS.test(algo.id)) {
    return await algo.enc(bytes, key, param, fmt);
  }
  if (!wwAvailable()) return await algo.enc(bytes, key, param, fmt);
  var id = ++WW.seq;
  return await new Promise(function (resolve, reject) {
    var timer = setTimeout(function () {
      delete WW.pending[id];
      WW.failed = true;                       /* 超时则本次与后续都回退主线程 */
      algo.enc(bytes, key, param, fmt).then(resolve, reject);
    }, 5000);
    WW.pending[id] = {
      resolve: function (v) { clearTimeout(timer); resolve(v); },
      reject: function (e) { clearTimeout(timer); reject(e); }
    };
    try {
      WW.worker.postMessage({
        id: id, algoId: algo.id, op: 'enc',
        bytes: Array.prototype.slice.call(bytes),
        key: key || '', param: param || '', fmt: fmt || 'base64'
      });
    } catch (e) {
      clearTimeout(timer); delete WW.pending[id];
      algo.enc(bytes, key, param, fmt).then(resolve, reject);
    }
  });
}

async function runEncrypt() {
  if (busy) return;
  var a = currentAlgo();
  if (!a) return;
  setMsg('');
  setBusy(true);
  jobStart();
  try {
    var key = els.key ? els.key.value : '';
    var param = els.param ? els.param.value : '';
    var fmt = els.fmt ? els.fmt.value : 'base64';
    if (a.key && !key && !a.keyOptional) throw new Error('请填写密钥');
    if (a.param && !param && !a.paramOptional) throw new Error('请填写参数：' + (a.paramLabel || ''));
    var bytes = getInputBytes();
    window._lastNonceWarning = null;

    if (a.oneway && WW_STATELESS.test(a.id)) {
      var res = await wwRun(a, bytes, key, param, fmt);
      renderOutput(bytesToStr(res));
      setMsg('计算完成' + (wwAvailable() ? '（后台线程）' : ''), 'ok');
      return;
    }

    if (a.isSym) {
      var mode = els.mode ? els.mode.value : 'GCM';
      var padMode = els.padding ? els.padding.value : 'PKCS7';
      var ivRaw = (els.iv && !els.ivField.classList.contains('hidden')) ? els.iv.value.trim() : '';
      var ivHex = _ivUserEdited ? ivRaw : '';
      var cont = els.container ? els.container.value : 'none';
      var saltHex = els.salt ? els.salt.value : '';
      var tagLen = els.tagLen ? parseInt(els.tagLen.value, 10) : 16;
      var aad = els.aad ? els.aad.value : '';
      window.CURRENT_CONTAINER = cont;
      /* IV 不再拼进密文头部：留空时自动生成并回写到 IV 输入框，由用户单独保存 */
      var r = await symEncrypt(a, bytes, key, mode, padMode, ivHex, false, isAEAD(mode) ? (aad || param) : '', saltHex, tagLen);
      var outBytes = r.ciphertext;
      if (cont === 'openssl') {
        /* 必须用 symEncrypt 内部实际派生所用的 salt，不能另生成一个 */
        var slt = (r.salt && r.salt.length === 8) ? r.salt : ((saltHex && hexToBytes(saltHex).length === 8) ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(8)));
        outBytes = opensslWrap(outBytes, slt);
        if (els.salt) els.salt.value = bytesToHex(slt);
      } else if (cont === 'cryptojs') {
        var slt2 = (r.salt && r.salt.length === 8) ? r.salt : ((saltHex && hexToBytes(saltHex).length === 8) ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(8)));
        if (els.salt) els.salt.value = bytesToHex(slt2);
        renderOutput(JSON.stringify({
          ct: bytesToBase64(outBytes),
          iv: r.iv ? bytesToHex(r.iv) : '',
          s: bytesToHex(slt2)
        }));
        if (els.ivInfoBox) els.ivInfoBox.classList.add('hidden');
        setMsg('加密完成（CryptoJS JSON；密钥用 EVP_BytesToKey(MD5) 派生，与 CryptoJS 默认一致）', 'ok');
        return;
      } else if (cont === 'pgp') {
        if (els.salt) els.salt.value = '';
        renderOutput(pgpArmor(outBytes));
        /* PGP Armor 只做 ASCII 装甲，不携带 IV——必须照常把 IV 回写到输入框，
           否则解密时会误把密文头 16 字节当成 IV（旧格式回退），解出乱码。 */
        if (r.iv && els.ivInfoBox) {
          if (!r.ivProvided && els.iv) els.iv.value = bytesToHex(r.iv);
          els.ivInfoBox.classList.remove('hidden');
          els.ivInfoLabel.textContent = 'IV（Hex，已自动填入上方 IV 框）：';
          els.ivInfoValue.textContent = bytesToHex(r.iv);
        }
        setMsg('加密完成（PGP ASCII Armor，含 CRC24 校验）', 'ok');
        return;
      } else if (cont === 'jwe') {
        var cek = await deriveKeyBytes(key, 32, null, null);
        var tok = await jweEncrypt(outBytes, cek, isAEAD(mode) ? (aad || param) : '', 'A256GCM');
        renderOutput(tok);
        /* JWE 也要回写 IV：它的载荷是内层密文，解封后还要按原模式解密 */
        if (r.iv && els.ivInfoBox) {
          if (!r.ivProvided && els.iv) els.iv.value = bytesToHex(r.iv);
          els.ivInfoBox.classList.remove('hidden');
          els.ivInfoValue.textContent = bytesToHex(r.iv);
        }
        setMsg('加密完成（JWE 紧凑序列化；内层仍按 ' + mode + ' 解密）', 'ok');
        return;
      } else if (els.salt) {
        els.salt.value = '';
      }
      if (window._lastKdfSalt && els.salt) {
        els.salt.value = bytesToHex(window._lastKdfSalt);
      }
      renderOutput(bytesOut(outBytes, fmt));
      if (r.iv && els.ivInfoBox) {
        if (!r.ivProvided && els.iv) {
          els.iv.value = bytesToHex(r.iv);
          /* 这是自动填入的，下次加密不要复用它（见 _ivUserEdited 说明） */
          resetIvEdited();
          els.ivInfoLabel.textContent = 'IV（Hex，已自动填入上方 IV 框，供保存；再次加密会自动换新的）：';
        } else {
          els.ivInfoLabel.textContent = 'IV（Hex，使用你填写的值）：';
        }
        els.ivInfoBox.classList.remove('hidden');
        els.ivInfoValue.textContent = bytesToHex(r.iv);
      } else if (els.ivInfoBox) {
        els.ivInfoBox.classList.add('hidden');
      }
      setMsg('加密完成' + (r.iv && !r.ivProvided ? '（IV 已填入 IV 框，请连同密文一起保存）' : '') +
        (window._lastKdfTag ? '　· 密钥派生：' + window._lastKdfTag + '，盐已填入 Salt 框，请一并保存' : '') +
        (window._lastNonceWarning ? '　⚠ ' + window._lastNonceWarning : ''),
        window._lastNonceWarning ? 'err' : 'ok');
    } else {
      var result = await a.enc(bytes, key, param, fmt);
      renderOutput(result);
      if (els.ivInfoBox) els.ivInfoBox.classList.add('hidden');
      setMsg('加密完成', 'ok');
    }
  } catch (e) {
    /* 取消是用户主动行为，不应当成错误红字 */
    if (e && e.message === '__CANCELLED__') {
      setMsg('已取消（未产生输出）', 'ok');
    } else {
      setMsg('错误：' + (typeof friendlyError === 'function' ? friendlyError(e) : (e && e.message ? e.message : e)), 'err');
    }
  } finally {
    setBusy(false);
    jobEnd();
  }
}

async function runDecrypt() {
  if (busy) return;
  var a = currentAlgo();
  if (!a) return;
  setMsg('');
  setBusy(true);
  try {
    if (a.oneway) throw new Error('单向哈希算法不支持解密');
    var key = els.key ? els.key.value : '';
    var cont2 = els.container ? els.container.value : 'none';
    window.CURRENT_CONTAINER = cont2;
    var param = els.param ? els.param.value : '';
    var fmt = els.fmt ? els.fmt.value : 'base64';
    if (a.key && !key && !a.keyOptional) throw new Error('请填写密钥');
    if (a.param && !param && !a.paramOptional) throw new Error('请填写参数：' + (a.paramLabel || ''));
    var text = els.input ? els.input.value : '';
    if (!text) throw new Error('请输入要解密的内容');

    if (a.isSym) {
      var mode = els.mode ? els.mode.value : 'GCM';
      var padMode = els.padding ? els.padding.value : 'PKCS7';
      var ivHex = (els.iv && !els.ivField.classList.contains('hidden')) ? els.iv.value : '';
      /* Salt 框现在是 KDF 盐：无论哪种容器都要读，否则解密拿不到加密时的盐。
         EVP 型容器会用密文头里的盐覆盖它。
         框被清空时退回「本次会话最后一次加密用过的盐」——这样在同一页面里
         加密完直接解密（忘了保存盐）也能正常解开。 */
      var saltHex2 = (els.salt && els.salt.value.trim()) ? els.salt.value.trim()
        : (window._lastKdfSalt ? bytesToHex(window._lastKdfSalt) : '');
      var aad2 = els.aad ? els.aad.value : '';
      var cont3 = els.container ? els.container.value : 'none';
      /* 文本型容器（PGP Armor / CryptoJS JSON / JWE）自带编码，
         不能再按 fmt 做 base64/hex 解码，否则会把 ASCII 文本当成密文拆坏。
         注意 cont3 必须先于 cipher 定义——var 提升会让它变成 undefined。 */
      var cipher = (cont3 === 'pgp' || cont3 === 'cryptojs' || cont3 === 'jwe')
        ? strToBytes(String(text))
        : bytesIn(text, fmt);
      /* 解容器：openssl/cryptojs 要顺带取出 salt（密钥派生要用），
         cryptojs 还会给出 iv，IV 框为空时自动填回 */
      if (cont3 === 'openssl') {
        var u1 = opensslUnwrap(cipher);
        cipher = u1.ciphertext;
        saltHex2 = bytesToHex(u1.salt);
        if (els.salt) els.salt.value = saltHex2;
      } else if (cont3 === 'cryptojs') {
        var u2 = cryptoJsUnwrap(bytesToStr(cipher));
        cipher = u2.ciphertext;
        if (u2.salt && u2.salt.length) { saltHex2 = bytesToHex(u2.salt); if (els.salt) els.salt.value = saltHex2; }
        if (u2.iv && u2.iv.length && !ivHex) { ivHex = bytesToHex(u2.iv); if (els.iv) els.iv.value = ivHex; }
      } else if (cont3 === 'pgp') {
        cipher = pgpDearchor(bytesToStr(cipher));
      } else if (cont3 === 'jwe') {
        var cek2 = await deriveKeyBytes(key, 32, null, null);
        cipher = await jweDecrypt(String(text).trim(), cek2);
      }
      var result;
      try {
        result = await symDecrypt(a, cipher, key, mode, padMode, ivHex, isAEAD(mode) ? (aad2 || param) : '', saltHex2);
      } catch (e) {
        if (!ivHex && modeNeedsIV(mode)) {
          throw new Error((e && e.message ? e.message : e) + '。当前 IV 框为空：新加密的密文不含 IV，请把加密时自动生成的 IV 填回 IV 框');
        }
        throw e;
      }
      renderOutput(result);
      if (els.ivInfoBox) els.ivInfoBox.classList.add('hidden');
      setMsg('解密完成', 'ok');
    } else {
      var r2 = await a.dec(text, key, param, fmt);
      renderOutput(r2);
      if (els.ivInfoBox) els.ivInfoBox.classList.add('hidden');
      setMsg('解密完成', 'ok');
    }
  } catch (e) {
    setMsg('错误：' + (typeof friendlyError === 'function' ? friendlyError(e) : (e && e.message ? e.message : e)), 'err');
  } finally {
    setBusy(false);
  }
}

function doCopy(text, okMsg) {
  var ok = false;
  try {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;top:0;left:0;width:1px;height:1px;padding:0;border:none;outline:none;background:transparent;opacity:0;';
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    ta.setSelectionRange(0, ta.value.length);
    ok = document.execCommand('copy');
    document.body.removeChild(ta);
  } catch (e) { ok = false; }
  if (ok) { setMsg(okMsg || '已复制', 'ok'); return true; }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function () { setMsg(okMsg || '已复制', 'ok'); }).catch(function () { fallbackSelect(); });
    return true;
  }
  fallbackSelect();
  return false;
}
function fallbackSelect() {
  if (!els.output) return;
  try {
    els.output.focus(); els.output.select();
    if (els.output.setSelectionRange) els.output.setSelectionRange(0, els.output.value.length);
    setMsg('已选中输出，请手动复制', 'err');
  } catch (e) { setMsg('复制失败', 'err'); }
}

function doCopyResult() {
  var text = els.output ? els.output.value : '';
  if (!text) { setMsg('没有可复制的内容', 'err'); return; }
  doCopy(text, '已复制到剪贴板');
}
function doCopyIV() {
  var v = els.ivInfoValue ? els.ivInfoValue.textContent : '';
  if (!v) { setMsg('没有 IV', 'err'); return; }
  doCopy(v, 'IV 已复制');
}
function doDownload() {
  var text = els.output ? els.output.value : '';
  if (!text) { setMsg('没有可下载的内容', 'err'); return; }
  try {
    var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = 'result.txt';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    setMsg('已开始下载', 'ok');
  } catch (e) { setMsg('下载失败：' + e.message, 'err'); }
}
function doClear() {
  if (els.input) els.input.value = '';
  if (els.output) els.output.value = '';
  /* 安全收尾：清掉派生产物与口令残留。
     _lastKdfSalt 要保留（同一会话内解密可能还需要），其余中间密钥一律丢弃。 */
  try {
    if (typeof window !== 'undefined') {
      ['_lastDerivedKey', '_lastKeyBytes', '_lastKeyMaterial'].forEach(function (n) {
        if (window[n] && window[n].fill) window[n].fill(0);
        delete window[n];
      });
    }
  } catch (e) { /* 清理失败不影响主流程 */ }
  if (els.key) els.key.value = '';
  if (els.param) els.param.value = '';
  if (els.iv) els.iv.value = '';
  clearFile();
  if (els.ivInfoBox) els.ivInfoBox.classList.add('hidden');
  setMsg('');
}

function handleDocDragOver(e) { e.preventDefault(); }
function handleDocDrop(e) {
  if (!e.dataTransfer) return;
  var t = e.target;
  if (t && t.id === 'file') return;
  e.preventDefault();
  var dt = e.dataTransfer;
  if (dt.files && dt.files.length > 0) { loadFile(dt.files[0]); return; }
  try { var txt = dt.getData('text/plain'); if (txt && els.input) els.input.value = txt; } catch (err) {}
}

function init() {
  try {
    buildAlgoList();
    updateAlgoUI();
    if (els.algo) els.algo.addEventListener('change', updateAlgoUI);
    /* 默认算法：AES-256（模式默认 GCM）。
       下拉框选项按注册顺序填充，第一位是 Base64，若不显式设置就会默认停在
       编码类算法上——用户打开页面第一个看到的不是加密，很反直觉。 */
    if (els.algo) {
      setSelectValue(els.algo, DEFAULT_ALGO_ID);
      updateAlgoUI();
    }
    /* 自定义选择器必须放在【默认算法设定之后】初始化：
       它会读取 select 当前值来决定「默认展开哪个分类」和按钮显示的名称。
       早于 setSelectValue 的话，读到的还是列表第一项（Base64），
       于是默认展开的是「编码与古典密码」而非「对称加密」。 */
    if (typeof initAlgoPicker === 'function') initAlgoPicker();
    if (els.mode) els.mode.addEventListener('change', updateModePadUI);
    if (els.file) els.file.addEventListener('change', function () {
      if (els.file.files && els.file.files[0]) loadFile(els.file.files[0]).then(function () { try { els.file.value = ''; } catch (e) {} });
    });
    if (els.drop) {
      els.drop.addEventListener('dragover', function (e) { e.preventDefault(); els.drop.classList.add('over'); });
      els.drop.addEventListener('dragleave', function () { els.drop.classList.remove('over'); });
      els.drop.addEventListener('drop', function () {});
    }
    document.addEventListener('dragover', handleDocDragOver);
    document.addEventListener('drop', handleDocDrop);
    document.addEventListener('paste', function (e) {
      var cd = e.clipboardData;
      if (!cd) return;
      if (cd.files && cd.files.length > 0) { e.preventDefault(); loadFile(cd.files[0]); return; }
      if (cd.items) {
        for (var i = 0; i < cd.items.length; i++) {
          if (cd.items[i].kind === 'file') {
            var f = cd.items[i].getAsFile();
            if (f) { e.preventDefault(); loadFile(f); return; }
          }
        }
      }
    });
    /* 填充校验严格度：严格模式是防御 padding oracle 的正确姿势 */
    if (els.padStrict) {
      var applyStrict = function () {
        var loose = els.padStrict.value === 'loose';
        if (typeof setPadStrict === 'function') setPadStrict(!loose);
        /* 宽松模式本身就是 padding oracle 的攻击面，切换时明说 */
        if (loose && typeof setMsg === 'function') {
          setMsg('已切到宽松模式：填充校验不过也照样返回，这会构成 Padding Oracle 攻击面。仅用于排查旧数据，生产环境请保持严格。', 'err');
        }
      };
      els.padStrict.addEventListener('change', applyStrict);
      applyStrict();
    }
    /* nonce 复用检测开关 */
    if (els.nonceGuard) {
      var applyGuard = function () {
        if (typeof setNonceGuardMode === 'function') setNonceGuardMode(els.nonceGuard.value);
      };
      els.nonceGuard.addEventListener('change', applyGuard);
      applyGuard();
    }

    var pendingFileBytes = null, pendingFileExt = 'bin';
    if (els.fileIn) {
      els.fileIn.addEventListener('change', function () {
        var f = els.fileIn.files && els.fileIn.files[0];
        if (!f) return;
        var fr = new FileReader();
        fr.onload = function () {
          pendingFileBytes = new Uint8Array(fr.result);
          pendingFileExt = (f.name.indexOf('.') >= 0) ? f.name.split('.').pop() : 'bin';
          var txt = null;
          try { txt = new TextDecoder('utf-8', { fatal: true }).decode(pendingFileBytes); } catch (e) { txt = null; }
          if (txt !== null && els.input) { els.input.value = txt; }
          else if (els.input) { els.input.value = ''; }
          if (typeof setMsg === 'function') {
            setMsg('已载入文件 ' + f.name + '（' + pendingFileBytes.length + ' 字节）' +
              (txt !== null ? '，已填入输入区。' : '，为二进制内容，加密时将直接处理文件字节。'));
          }
        };
        fr.readAsArrayBuffer(f);
      });
    }
    if (els.btnDownload) {
      els.btnDownload.addEventListener('click', function () {
        var out = els.output ? els.output.value : '';
        if (!out) { if (typeof setMsg === 'function') setMsg('结果为空，没有可下载的内容。', 'err'); return; }
        var blob = new Blob([out], { type: 'text/plain;charset=utf-8' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'crypto-result.txt';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
      });
    }
    if (els.btnImportKey) {
      els.btnImportKey.addEventListener('click', function () {
        var txt = els.output ? prompt('粘贴 PEM 公钥/私钥：', '') : '';
        if (!txt) return;
        try {
          var b64 = txt.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
          var der = atob(b64);
          var bytes = new Uint8Array(der.length);
          for (var i = 0; i < der.length; i++) bytes[i] = der.charCodeAt(i);
          if (typeof setMsg === 'function') {
            setMsg('已解析 PEM（' + bytes.length + ' 字节 DER）。' +
              '当前界面按算法要求使用密钥区/公钥区内容，请把需要的部分复制进去。');
          }
          if (els.key) els.key.value = bytesToHex(bytes);
        } catch (e) {
          if (typeof setMsg === 'function') setMsg('PEM 解析失败：' + e.message, 'err');
        }
      });
    }
    var verBadge = (typeof document !== 'undefined') ? document.getElementById('verBadge') : null;
    var verCard = (typeof document !== 'undefined') ? document.getElementById('verCard') : null;
    if (verBadge && verCard) {
      var fillVer = function () {
        var a = (typeof ALGOS !== 'undefined') ? ALGOS.length : 0;
        var set = function (id, v) { var e = document.getElementById(id); if (e) e.textContent = v; };
        set('verAlgo', a);
        set('verStress', (typeof BUILD_INFO !== 'undefined' ? BUILD_INFO.stress : 0));
        set('verSelf', (typeof BUILD_INFO !== 'undefined' ? BUILD_INFO.selfTest : 0));
      };
      /* 注意：主逻辑加载时（readyState 已是 complete）会立刻执行 init，
         而 crypto_core.js 尚未加载，此刻 ALGOS 还不完整（只有主逻辑自注册的那些）。
         所以统计必须在「点开卡片时」才取——那时所有脚本都已就绪。 */
      verCard.classList.add('hidden');      /* 确保初始收起 */
      verBadge.addEventListener('click', function () {
        var nowHidden = verCard.classList.toggle('hidden');
        if (!nowHidden) fillVer();
      });
    }

    /* 容器 / 输出格式 / 标签长度 / nonce 档位 / 填充校验 变化后刷新安全提示 */
    ['container', 'fmt', 'tagLen', 'nonceGuard', 'padStrict', 'pad', 'mode', 'algo'].forEach(function (n) {
      var el = els[n] || (typeof document !== 'undefined' ? document.getElementById(n) : null);
      if (el) el.addEventListener('change', function () { refreshSecurity(); });
    });
    if (els.keyMode) {
      var applyKeyMode = function () {
        var m = els.keyMode.value;
        if (typeof setKeyMode === 'function') setKeyMode(m);
        var raw = (m === 'raw');
        if (els.keyLabel) els.keyLabel.textContent = raw ? '密钥（Hex 原始密钥）' : '密钥 / 口令';
        if (els.key) els.key.placeholder = raw ? '例如 32 字节密钥 = 64 位 Hex' : '输入口令';
        ['kdfField', 'kdfHashField', 'kdfIterField', 'saltField'].forEach(function (n) {
          var el = els[n] || (typeof document !== 'undefined' ? document.getElementById(n) : null);
          if (el) el.classList.toggle('hidden', raw);
        });
        refreshSecurity();
      };
      els.keyMode.addEventListener('change', applyKeyMode);
      applyKeyMode();
    }
    var KDF_COST_DEFAULT = { kdf2: '210000', argon2id: '2', argon2i: '2', argon2d: '2', scrypt: '14', bcrypt: '10', legacy: '' };
    var kdfCustom = {};      /* 记住用户在各档位手填过的参数，切换档位回来时保留 */
    var KDF_COST_LABEL = {
      kdf2: 'PBKDF2 迭代次数（建议 ≥ 210000）',
      argon2id: 'Argon2id 轮数 t（1~10，默认 2）',
      argon2i: 'Argon2i 轮数 t（1~10，默认 2）',
      argon2d: 'Argon2d 轮数 t（1~10，默认 2）',
      scrypt: 'scrypt 的 N 指数（10~20，默认 14）',
      bcrypt: 'bcrypt cost（4~18，默认 10）',
      legacy: ''
    };
    if (els.kdf) {
      var applyKdf = function () {
        var m = els.kdf.value;
        if (typeof setKdfMode === 'function') setKdfMode(m);
        var legacy = (m === 'legacy');
        if (els.kdfHashField) els.kdfHashField.classList.toggle('hidden', m !== 'kdf2');
        if (els.kdfIterField) els.kdfIterField.classList.toggle('hidden', legacy);
        if (els.kdfIterLabel && KDF_COST_LABEL[m]) els.kdfIterLabel.textContent = KDF_COST_LABEL[m];
        var key = 'cost_' + m;
        if (els.kdfIter && KDF_COST_DEFAULT[m] !== undefined) {
          if (kdfCustom[key] !== undefined) els.kdfIter.value = kdfCustom[key];
          else els.kdfIter.value = KDF_COST_DEFAULT[m];
        }
        applyCost();
        if (legacy && typeof setMsg === 'function') {
          setMsg('注意：旧版派生（单次 SHA-256）抗不住暴力破解，仅用于解开历史密文。新数据请切回 Argon2id 或 PBKDF2。', 'err');
        }
      };
      var applyHash = function () {
        if (typeof setKdfHash === 'function') setKdfHash(els.kdfHash.value);
      };
      var applyCost = function (fromUser) {
        var m = els.kdf ? els.kdf.value : 'kdf2';
        if (fromUser && els.kdfIter.value !== '') kdfCustom['cost_' + m] = els.kdfIter.value;
        if (typeof setKdfIterations === 'function') setKdfIterations(els.kdfIter.value);
        if (typeof setKdfCost === 'function') setKdfCost(els.kdfIter.value);
        /* 低迭代次数要明确警告：否则用户以为自己填的值生效了 */
        if (typeof kdfIterWarning === 'function' && m === 'kdf2') {
          var w = kdfIterWarning();
          if (w && typeof setMsg === 'function') setMsg('警告：' + w, 'err');
        }
      };
      els.kdf.addEventListener('change', function () { applyKdf(); refreshSecurity(); });
      if (els.kdfHash) els.kdfHash.addEventListener('change', function () { applyHash(); refreshSecurity(); });
      if (els.kdfIter) {
        els.kdfIter.addEventListener('change', function () { applyCost(true); refreshSecurity(); });
        applyCost();
      }
      applyKdf();
      if (els.kdfHash) applyHash();
    }
    if (els.btnClearNonce) {
      els.btnClearNonce.addEventListener('click', function () {
        if (typeof nonceLogClear === 'function') nonceLogClear();
        if (typeof setMsg === 'function') setMsg('已清空 nonce 使用记录', 'ok');
      });
    }
    if (els.iv) els.iv.addEventListener('input', markIvUserEdited);
    if (els.btnSelftest) {
      var cancelBtn = document.getElementById('btnCancel');
      if (cancelBtn) cancelBtn.addEventListener('click', function () { jobCancel(); });
      els.btnSelftest.addEventListener('click', async function () {
        if (typeof runSelfTest !== 'function') { setMsg('自检模块未加载', 'err'); return; }
        setMsg('正在运行自检…', '');
        setBusy(true);
        try {
          var r = await runSelfTest();
          var html = '<b>汇总：通过 ' + r.passed + ' · 失败 ' + r.failed + ' · 跳过 ' + r.skipped + '</b><br><br>';
          html += '<b>一、已知答案测试（对标官方/权威库）</b><br>';
          for (var i = 0; i < r.kat.length; i++) {
            var mark = r.kat[i].ok === true ? '✓' : (r.kat[i].ok === 'skip' ? '－' : '✗');
            html += mark + ' ' + r.kat[i].name + '<br>';
          }
          html += '<br><b>二、往返测试（加密后解密，比对原文）</b><br>';
          var badRt = r.rt.filter(function (x) { return !x.ok; });
          if (badRt.length === 0) {
            html += '✓ 全部 ' + r.rt.length + ' 个对称算法通过<br>';
          } else {
            r.rt.forEach(function (x) { html += (x.ok ? '✓ ' : '✗ ') + x.name + '<br>'; });
          }
          els.selftestOut.innerHTML = html;
          els.selftestBox.classList.remove('hidden');
          setMsg(r.failed === 0 ? '自检完成：全部通过' : '自检完成：有 ' + r.failed + ' 项未通过',
            r.failed === 0 ? 'ok' : 'err');
        } catch (e) {
          setMsg('自检出错：' + (e && e.message ? e.message : e), 'err');
        } finally {
          setBusy(false);
        }
      });
    }
    if (els.btnEnc) els.btnEnc.addEventListener('click', runEncrypt);
    if (els.btnDec) els.btnDec.addEventListener('click', runDecrypt);
    if (els.btnClear) els.btnClear.addEventListener('click', doClear);
    if (els.btnCopy) els.btnCopy.addEventListener('click', doCopyResult);
    if (els.btnCopyIV) els.btnCopyIV.addEventListener('click', doCopyIV);
    if (els.btnDownload) els.btnDownload.addEventListener('click', doDownload);
    if (!window.crypto || !crypto.subtle) setMsg('提示：当前环境不支持 Web Crypto，部分算法不可用。', 'err');
  } catch (e) { if (window.onerror) window.onerror(e.message, 'init', 0, 0, e); }
}
/* 仅在浏览器主线程里自动初始化；Worker / Node 环境没有 document，
   只加载算法定义供 importScripts 后调用，不能执行 UI 初始化。
   加这个守卫是为了让本文件能被 Web Worker 直接 importScripts。 */
if (typeof document !== 'undefined' && document.readyState !== undefined) {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}