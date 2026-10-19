/* ============================================================
 * NIST SP 800-56A（单步 KDF，5.8.1）/ SP 800-56C（两步 KDF）/
 * TLS PRF（TLS 1.0-1.1，RFC 5246 §5 的 MD5⊕SHA-1 双 PRF）/
 * TLS 1.2 PRF（RFC 5246 §5，单哈希 P_hash）/ ANSI X9.42 PRF
 * ------------------------------------------------------------
 * 语义逐行对照 Botan 2.19.5 官方 C++ 源码：
 *   src/lib/kdf/sp800_56a/sp800_56a.cpp
 *   src/lib/kdf/sp800_56c/sp800_56c.cpp
 *   src/lib/kdf/prf_tls/prf_tls.cpp
 *   src/lib/kdf/prf_x942/prf_x942.cpp
 * 向量：src/tests/data/kdf/{sp800_56a,sp800_56c,tls_prf,x942_prf}.vec
 *
 * 【三个极易写反的地方，均已按官方源码确认】
 * 1) SP800-56A 的计数 counter 从 1 起，以【4 字节大端】参与，
 *    顺序是 counter ‖ secret ‖ label（不是 label 在前）。
 * 2) SP800-56A 的 Hash 变体【忽略 salt】（官方源码 BOTAN_UNUSED(salt)）；
 *    HMAC 变体才把 salt 当 HMAC 密钥，且 salt 为空时等价于零长度密钥。
 * 3) SP800-56C 的展开步 salt 传【空】（nullptr,0），不是沿用提取步的 salt。
 * ============================================================ */
(function () {
  'use strict';
  if (typeof ALGOS === 'undefined') return;
  function G(n) { return (typeof window !== 'undefined' ? window : globalThis)[n]; }
  var push = (typeof reg === 'function') ? reg : function (o) { ALGOS.push(o); };

  var HLEN = { 'SHA-160': 20, 'SHA-224': 28, 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64, 'MD5': 16 };
  function hblock(n) { return (n === 'SHA-384' || n === 'SHA-512') ? 128 : 64; }

  function hfn(n) {
    var f = null;
    if (n === 'SHA-160') { var o = G('OTP'); f = o && o.sha1Bytes; }
    else if (n === 'SHA-224') f = G('sha224Digest');
    else if (n === 'SHA-256') f = G('sha256BytesSync') || G('sha256Bytes');
    else if (n === 'SHA-384') f = G('sha384Digest');
    else if (n === 'SHA-512') f = G('sha512Digest');
    else if (n === 'MD5') f = G('md5Bytes');
    if (typeof f !== 'function') throw new Error('哈希内核未加载：' + n);
    return f;
  }
  function H(n, b) { return hfn(n)(b); }

  function HM(n, key, msg) {
    var bs = hblock(n), f = hfn(n);
    if (key.length > bs) key = f(key);
    var k = new Uint8Array(bs); k.set(key);
    var ip = new Uint8Array(bs), op = new Uint8Array(bs), i;
    for (i = 0; i < bs; i++) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
    return f(cat(op, f(cat(ip, msg))));
  }

  function cat() {
    var a = arguments, t = 0, i;
    for (i = 0; i < a.length; i++) t += a[i].length;
    var o = new Uint8Array(t), p = 0;
    for (i = 0; i < a.length; i++) { o.set(a[i], p); p += a[i].length; }
    return o;
  }
  function be32(n) {
    return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  }
  function hexB(s) {
    s = String(s === undefined || s === null ? '' : s).replace(/[^0-9a-fA-F]/g, '');
    if (s.length % 2) s = '0' + s;
    var o = new Uint8Array(s.length / 2);
    for (var i = 0; i < o.length; i++) o[i] = parseInt(s.substr(i * 2, 2), 16);
    return o;
  }
  function toB(b) {
    if (b instanceof Uint8Array || ArrayBuffer.isView(b)) return new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
    return G('strToBytes')(String(b === undefined || b === null ? '' : b));
  }
  /* 解析 "SHA-256,32,hmac" 这类逗号参数 */
  function p3(p, d1, d2, d3) {
    var a = String(p === undefined || p === null ? '' : p).split(',').map(function (x) { return x.trim(); });
    return [a[0] || d1, a[1] || d2, a[2] || d3];
  }
  function toHexFromBytes(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  }
  /* 输入内容一律按【Hex 文本】解析；若传来的是字节数组先转 hex，
   * 不能直接 String(Uint8Array)——那会得到 "233,154,143" 这种逗号串。 */
  function inHex(b) {
    if (b instanceof Uint8Array || ArrayBuffer.isView(b)) {
      var u = new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
      return hexB(toHexFromBytes(u));
    }
    return hexB(b);
  }

  /* ---- SP 800-56A：counter(4B BE) ‖ secret ‖ label，逐轮取摘要拼接 ---- */
  function sp56a(secret, label, salt, outLen, hn, useHmac) {
    var dl = HLEN[hn];
    if (!dl) throw new Error('不支持的哈希：' + hn);
    var f = useHmac ? function (m) { return HM(hn, salt, m); } : function (m) { return H(hn, m); };
    var reps = Math.floor(outLen / dl) + (outLen % dl ? 1 : 0);
    var out = new Uint8Array(outLen), off = 0, c = 1, i, r, n;
    for (i = 0; i < reps; i++) {
      r = f(cat(be32(c++), secret, label));
      n = Math.min(r.length, outLen - off);
      out.set(r.subarray(0, n), off); off += n;
    }
    return out;
  }

  /* ---- SP 800-108 Feedback 模式（SP800-56C 的展开步用的就是它） ----
   * 每轮输入 = prev ‖ BE32(counter) ‖ label ‖ 0x00 ‖ ctx ‖ BE32(输出位数)
   * salt 的前 prf_len 字节当 IV（不足 prf_len 则没有 IV），其余当 ctx。
   * 本轮输出【整体】作为下一轮的 prev（不是截断后的部分）。 */
  function sp108fb(secret, label, salt, outLen, hn) {
    var prfLen = HLEN[hn];
    var ivLen = salt.length >= prfLen ? prfLen : 0;
    var prev = salt.subarray(0, ivLen), ctx = salt.subarray(ivLen);
    var out = new Uint8Array(outLen), off = 0, c = 1, i, h, n;
    var lenB = be32(outLen * 8);
    while (off < outLen) {
      h = HM(hn, secret, cat(prev, be32(c++), label, new Uint8Array([0]), ctx, lenB));
      n = Math.min(h.length, outLen - off);
      out.set(h.subarray(0, n), off); off += n;
      prev = h;
    }
    return out;
  }

  /* ---- SP 800-56C：提取 = HMAC(salt, Z)；展开 = SP800-108 Feedback ----
   * 【极易写错】展开步不是 SP800-56A！Botan 在 kdf.cpp 里构造的是
   *   SP800_56C(mac, kdf_create_mac_or_hash<SP800_108_Feedback>(...))，
   * 且展开步的 salt 传【空】（nullptr,0）。 */
  function sp56c(secret, salt, label, outLen, hn) {
    var kdk = HM(hn, salt, secret);
    return sp108fb(kdk, label, new Uint8Array(0), outLen, hn);
  }

  /* ---- P_hash：A(0)=seed，A(i)=HMAC(A(i-1))，输出块 = HMAC(A(i)‖seed) ---- */
  function pHash(macName, secret, seed, outLen) {
    var out = new Uint8Array(outLen), A = seed, off = 0, h, n, i;
    while (off < outLen) {
      A = HM(macName, secret, A);
      h = HM(macName, secret, cat(A, seed));
      n = Math.min(h.length, outLen - off);
      for (i = 0; i < n; i++) out[off + i] ^= h[i];
      off += n;
    }
    return out;
  }

  /* ---- TLS 1.0/1.1 PRF：secret 均分两半，MD5 与 SHA-1 的 P_hash 逐字节异或 ---- */
  function tlsPrfOld(secret, label, seed, outLen) {
    var half = Math.floor((secret.length + 1) / 2);
    var S1 = secret.subarray(0, half);
    var S2 = secret.subarray(secret.length - half);
    var msg = cat(label, seed);
    var a = pHash('MD5', S1, msg, outLen);
    var b = pHash('SHA-160', S2, msg, outLen);
    var o = new Uint8Array(outLen);
    for (var i = 0; i < outLen; i++) o[i] = a[i] ^ b[i];
    return o;
  }

  /* ---- X9.42 PRF：SHA-1(secret ‖ DER(SEQUENCE{...}))，counter 从 1 起 ---- */
  function derLen(n) {
    if (n < 128) return [n];
    if (n < 256) return [0x81, n];
    return [0x82, (n >> 8) & 255, n & 255];
  }
  /* 注意：content 可能是 Uint8Array，Array.concat 遇到非数组参数会把它当成
   *【单个元素】塞进去（而不是展开），拼出的 DER 就全是错的。统一转成普通数组。 */
  function tlv(tag, content) { var c = Array.from(content); return [tag].concat(derLen(c.length), c); }
  function x942Int(n) { return tlv(0x04, [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]); }
  var OID_DER = {
    'des3': [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x06], /* 1.2.840.113549.1.9.16.3.6 */
    '3.7': [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x07]  /* 1.2.840.113549.1.9.16.3.7 */
  };
  function x942(oid, secret, label, salt, outLen) {
    var inb = cat(label, salt);
    var out = new Uint8Array(outLen), off = 0, counter = 1, parts, h, n;
    while (off < outLen && counter !== 0) {
      parts = tlv(0x30, tlv(0x06, oid).concat(x942Int(counter)));
      if (salt.length) parts = parts.concat(tlv(0xA0, tlv(0x04, inb)));
      parts = parts.concat(tlv(0xA2, x942Int(8 * outLen)));
      h = H('SHA-160', cat(secret, new Uint8Array(tlv(0x30, parts))));
      n = Math.min(h.length, outLen - off);
      out.set(h.subarray(0, n), off); off += n; counter++;
    }
    return out;
  }

  /* ============ 条目 ============ */

  push({
    id: 'sp800-56a', name: 'SP 800-56A 单步 KDF', group: '单向哈希',
    key: true, param: true,
    keyLabel: 'salt（Hex；Hash 变体忽略，HMAC 变体作密钥）',
    paramLabel: '参数：哈希,输出字节数,mode（hash|hmac）[,OtherInfo 的 Hex]，如 SHA-256,32,hmac',
    info: 'NIST SP 800-56A §5.8.1 单步 KDF：每轮 Aux(计数器4字节大端‖Z‖OtherInfo)，逐轮拼接取前 N 字节。hash 模式 Aux 即哈希（忽略 salt），hmac 模式 Aux=HMAC(key=salt)。输入是共享秘密 Z 的 Hex，口令派生请用 PBKDF2。Botan 全量向量通过。',
    enc: function (b, k, p, fmt) {
      var a = String(p === undefined || p === null ? '' : p).split(',').map(function (x) { return x.trim(); });
      var hn = a[0] || 'SHA-256', len = parseInt(a[1] || '32', 10);
      if (!(len >= 1 && len <= 1024)) throw new Error('输出字节数需在 1..1024');
      var mode = String(a[2] || 'hmac').toLowerCase();
      if (mode !== 'hash' && mode !== 'hmac') throw new Error('mode 只能是 hash 或 hmac');
      var secret = inHex(b), label = hexB(a[3] || '');
      return G('bytesOut')(sp56a(secret, label, hexB(k), len, hn, mode === 'hmac'), fmt);
    }
  });

  push({
    id: 'sp800-56c', name: 'SP 800-56C 两步 KDF', group: '单向哈希',
    key: true, param: true,
    keyLabel: 'salt（Hex，提取步的盐）',
    paramLabel: '参数：哈希,输出字节数[,label 的 Hex]，如 SHA-256,32',
    info: 'SP 800-56C 两步 KDF：先用 KDK=HMAC(salt,Z) 提取随机性，再展开。【关键】展开步不是 SP 800-56A，而是 SP 800-108 Feedback（Botan kdf.cpp 写死），且展开步 salt 传空、不沿用提取步。Botan 四组向量全通过。',
    enc: function (b, k, p, fmt) {
      var a = String(p === undefined || p === null ? '' : p).split(',').map(function (x) { return x.trim(); });
      var hn = a[0] || 'SHA-256', len = parseInt(a[1] || '32', 10);
      if (!(len >= 1 && len <= 1024)) throw new Error('输出字节数需在 1..1024');
      var secret = inHex(b), label = hexB(a[2] || '');
      return G('bytesOut')(sp56c(secret, hexB(k), label, len, hn), fmt);
    }
  });

  push({
    id: 'tls12-prf', name: 'TLS 1.2 PRF（RFC 5246 §5）', group: '单向哈希',
    key: true, param: true,
    keyLabel: 'seed（Hex，通常是 client_random‖server_random）',
    paramLabel: '参数：哈希,输出字节数[,label 的 Hex]，如 SHA-256,48',
    info: 'TLS 1.2 PRF：P_hash(secret, label‖seed) 单哈希迭代，A(0)=seed′，A(i)=HMAC(A(i-1))，第 i 块=HMAC(A(i)‖seed′)。默认 SHA-256，仅 SHA-384 套件用 SHA-384。Botan 四组向量全通过。TLS 1.0/1.1 另见 tls-prf。',
    enc: function (b, k, p, fmt) {
      var a = p3(p, 'SHA-256', '48', '');
      var hn = a[0], len = parseInt(a[1], 10);
      if (!(len >= 1 && len <= 1024)) throw new Error('输出字节数需在 1..1024');
      if (hn === 'MD5' || hn === 'SHA-160') throw new Error('TLS 1.2 PRF 用的是 SHA-256/384 等，TLS1.0/1.1 请用 tls-prf');
      var secret = inHex(b);
      var label = a[2] ? hexB(a[2]) : new Uint8Array(0);
      return G('bytesOut')(pHash(hn, secret, cat(label, hexB(k)), len), fmt);
    }
  });

  push({
    id: 'tls-prf', name: 'TLS PRF（TLS 1.0/1.1，MD5⊕SHA-1）', group: '单向哈希',
    key: true, param: true,
    keyLabel: 'seed（Hex）',
    paramLabel: '参数：输出字节数[,label 的 Hex]，如 48',
    info: 'TLS 1.0/1.1 的 PRF（RFC 5246 §5 之前版本）：把预主密钥切成两半，S1 用 HMAC-MD5、S2 用 HMAC-SHA-1，两个 P_hash 输出【逐字节异或】。\n【已废弃】MD5 已不安全，仅用于兼容旧协议与验证历史数据，新系统请用 TLS 1.2 PRF。\n【验证】Botan kdf/tls_prf.vec 的 [TLS-PRF] 分节全部通过。',
    enc: function (b, k, p, fmt) {
      var a = p3(p, '48', '', '');
      var len = parseInt(a[0], 10);
      if (!(len >= 1 && len <= 1024)) throw new Error('输出字节数需在 1..1024');
      var secret = inHex(b);
      var label = a[1] ? hexB(a[1]) : new Uint8Array(0);
      return G('bytesOut')(tlsPrfOld(secret, label, hexB(k), len), fmt);
    }
  });

  push({
    id: 'x942-prf', name: 'ANSI X9.42 PRF', group: '单向哈希',
    key: true, param: true,
    keyLabel: 'salt（Hex，可空）',
    paramLabel: '参数：密钥包装算法（des3|3.7）,输出字节数，如 des3,24',
    info: 'ANSI X9.42 密钥派生 PRF：SHA-1(secret‖DER)，DER 内含密钥包装算法 OID、4 字节计数器、可选 salt、请求位数（8×输出字节数）。Botan 两组向量全通过。老式 KDF，常见于 CMS，新设计请用 HKDF。',
    enc: function (b, k, p, fmt) {
      var a = p3(p, 'des3', '24', '');
      var oid = OID_DER[a[0]];
      if (!oid) throw new Error('密钥包装算法只能是 des3 或 3.7');
      var len = parseInt(a[1], 10);
      if (!(len >= 1 && len <= 255)) throw new Error('输出字节数需在 1..255（X9.42 用单字节表示位数）');
      var secret = inHex(b);
      return G('bytesOut')(x942(oid, secret, new Uint8Array(0), hexB(k), len), fmt);
    }
  });

  /* 暴露内核给「口令派生（KDF）」下拉框复用：
     口令当 secret、Salt 框当 salt，label 固定为空（与界面默认一致）。 */
  if (typeof window !== 'undefined') {
    window.KDFX = window.KDFX || {};
    window.KDFX.sp56a = function (secret, salt, outLen, hn) { return sp56a(secret, new Uint8Array(0), salt, outLen, hn || 'SHA-256', true); };
    window.KDFX.sp56c = function (secret, salt, outLen, hn) { return sp56c(secret, salt, new Uint8Array(0), outLen, hn || 'SHA-256'); };
    window.KDFX.tls12 = function (secret, salt, outLen, hn) { return pHash(hn || 'SHA-256', secret, salt, outLen); };
    window.KDFX.x942 = function (secret, salt, outLen) { return x942(OID_DER.des3, secret, new Uint8Array(0), salt, outLen); };
  }
})();
