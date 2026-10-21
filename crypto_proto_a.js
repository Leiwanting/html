/* crypto_proto_a.js
 * 协议 / 容器级封装：XSalsa20 · NaCl secretbox/box/sealedbox · Fernet · PASETO v2/v4
 *
 * 参照物（全部为第三方权威实现，非自洽）：
 *   XSalsa20 / secretbox / box / sealedbox  → PyNaCl 1.6.2（libsodium 官方绑定）
 *   Fernet                                   → Python cryptography 50.0.1（cryptography.fernet）
 *   PASETO v2.local / v2.public               → pyseto 1.10.0 读源码确认语义后对拍
 *   PASETO v4.local / v4.public               → 同上
 *
 * 语义要点（照实现源码核对，不凭记忆写）：
 *  · XSalsa20 = HSalsa20(key, nonce[0:16]) 得子密钥，再 Salsa20(subkey, nonce[16:24])。
 *    HSalsa20 与 Salsa20 core 的区别：输出【不加】初始状态，且只取 state[0..3]‖state[12..15]。
 *  · NaCl secretbox：block0 = XSalsa20 首个 64 字节块，其中 [0:32] 作 Poly1305 一次性密钥，
 *    明文从 keystream 的第 32 字节开始异或。输出 = tag(16)‖ct。
 *  · NaCl box：先 beforenm，k = HSalsa20(X25519(sk,pk), 全零 16 字节)，再走 secretbox。
 *  · sealed box：临时密钥对 + beforenm，nonce = BLAKE2b-256(epk‖rpk)[0:24]，
 *    输出 = epk(32)‖box。
 *  · Fernet：0x80‖ts(8,大端)‖iv(16)‖AES-128-CBC(enckey)‖HMAC-SHA256(signkey, 前四段)，
 *    整段 base64url。key 前 16 字节签名、后 16 字节加密。
 *  · PASETO v4.local：n(32) → ek/n2 = BLAKE2b(key, "paseto-encryption-key"+n, 56)，
 *    ak = BLAKE2b(key, "paseto-auth-key-for-aead"+n, 32)；c = XChaCha20(ek,n2)【纯加密，无内联 tag】，
 *    t = BLAKE2b(ak, PAE(header,n,c,footer,implicit), 32)。
 *  · PASETO v2.local：n(24)，XChaCha20-Poly1305(key, n)，AAD = PAE(header,n,footer)。
 *    —— v4 是「加密 + 外部 BLAKE2b 认证」，v2 是「AEAD 内联 tag」，两者结构不同，不可混用。
 */
(function () {
  if (typeof reg !== 'function') { console.error('crypto_proto_a.js 需要在算法注册框架之后加载'); return; }

  /* ---------------- 基础工具 ---------------- */
  function _xor(a, b) {
    var n = Math.min(a.length, b.length), o = new Uint8Array(n), i;
    for (i = 0; i < n; i++) o[i] = a[i] ^ b[i];
    return o;
  }
  function _zeros(n) { return new Uint8Array(n); }
  function _rand(n) {
    var b = new Uint8Array(n);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(b);
    else for (var i = 0; i < n; i++) b[i] = Math.floor(Math.random() * 256);
    return b;
  }
  function _hex(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  }
  function _u8(s) { return typeof strToBytes === 'function' ? strToBytes(s) : new TextEncoder().encode(s); }
  function _str(b) { return typeof bytesToStr === 'function' ? bytesToStr(b) : new TextDecoder().decode(b); }

  /* ---------------- HSalsa20 / XSalsa20 ---------------- */
  /* HSalsa20：Salsa20 core 跑 20 轮，输出不加初始状态，只取 word 0..3 与 12..15 */
  function hsalsa20(key, nonce16) {
    if (key.length !== 32) throw new Error('XSalsa20 密钥必须 32 字节');
    if (nonce16.length !== 16) throw new Error('HSalsa20 nonce 必须 16 字节');
    var st = new Uint32Array(16), i;
    st[0] = 0x61707865;
    for (i = 0; i < 4; i++) st[1 + i] = readU32LE(key, i * 4);
    st[5] = 0x3320646e;
    st[6] = readU32LE(nonce16, 0); st[7] = readU32LE(nonce16, 4);
    st[8] = readU32LE(nonce16, 8); st[9] = readU32LE(nonce16, 12);
    st[10] = 0x79622d32;
    for (i = 0; i < 4; i++) st[11 + i] = readU32LE(key, 16 + i * 4);
    st[15] = 0x6b206574;
    var x = new Uint32Array(st), r;
    for (r = 0; r < 10; r++) {
      /* 与 crypto_salsa20.js 的 salsaCore 完全相同的轮次序，直接复用其 salsaQR，
         不另写一份 —— 避免两份实现的轮函数不一致导致静默错位。 */
      salsaQR(x, 0, 4, 8, 12); salsaQR(x, 5, 9, 13, 1);
      salsaQR(x, 10, 14, 2, 6); salsaQR(x, 15, 3, 7, 11);
      salsaQR(x, 0, 1, 2, 3); salsaQR(x, 5, 6, 7, 4);
      salsaQR(x, 10, 11, 8, 9); salsaQR(x, 15, 12, 13, 14);
    }
    /* 输出 word 次序是 0,5,10,15（常量槽）+ 6,7,8,9（nonce 槽）—— 与直觉的
       「0..3 + 12..15」不同。这一点是拿 libsodium 的 crypto_core_hsalsa20
       直接对拍确认的，不是凭记忆：写成 0..3+12..15 时全部向量静默不匹配。 */
    var out = new Uint8Array(32);
    var idx = [0, 5, 10, 15, 6, 7, 8, 9];
    for (i = 0; i < 8; i++) writeU32LE(x[idx[i]], out, i * 4);
    return out;
  }
  function xsalsa20Stream(key, nonce24, len) {
    if (nonce24.length !== 24) throw new Error('XSalsa20 nonce 必须 24 字节');
    var sub = hsalsa20(key, nonce24.subarray(0, 16));
    var n8 = nonce24.subarray(16, 24);
    var out = new Uint8Array(len), ks, ctr = 0n, i, j;
    for (i = 0; i < len; i += 64) {
      ks = salsa20Keystream(sub, n8, ctr++);
      var n = Math.min(64, len - i);
      for (j = 0; j < n; j++) out[i + j] = ks[j];
    }
    return out;
  }
  function xsalsa20Crypt(data, key, nonce24) {
    return _xor(data, xsalsa20Stream(key, nonce24, data.length));
  }

  /* ---------------- NaCl secretbox ---------------- */
  function secretboxSeal(msg, key32, nonce24) {
    var ks = xsalsa20Stream(key32, nonce24, 32 + msg.length);
    var polyKey = ks.subarray(0, 32);
    var ct = _xor(msg, ks.subarray(32));
    var tag = poly1305Mac(ct, polyKey);
    return { box: concatBytes(tag, ct), tag: tag, ct: ct };
  }
  function secretboxOpen(box, key32, nonce24) {
    if (box.length < 16) throw new Error('secretbox 数据太短');
    var tag = box.subarray(0, 16), ct = box.subarray(16);
    var ks = xsalsa20Stream(key32, nonce24, 32 + ct.length);
    var t2 = poly1305Mac(ct, ks.subarray(0, 32));
    if (_hex(t2) !== _hex(tag)) throw new Error('secretbox 认证失败：密钥或 nonce 不匹配，或密文被篡改');
    return _xor(ct, ks.subarray(32));
  }

  /* ---------------- NaCl box / sealed box ---------------- */
  /* 注意：框架里的 x25519Derive 是 async 且对 32 字节私钥走 WebCrypto 分支，
     这里需要同步、纯 JS 的 X25519，故直接用 x25519ScalarMult。 */
  function boxBeforenm(sk, pk) {
    return hsalsa20(x25519ScalarMult(sk, pk), _zeros(16));
  }
  function pubFromSk(sk) { return x25519ScalarMult(sk, _x25519Base()); }
  function _x25519Base() {
    var b = new Uint8Array(32); b[0] = 9; return b;
  }

  /* ---------------- HChaCha20 / XChaCha20 ---------------- */
  function hchacha20(key, nonce16) {
    if (key.length !== 32) throw new Error('XChaCha20 密钥必须 32 字节');
    if (nonce16.length !== 16) throw new Error('HChaCha20 nonce 必须 16 字节');
    var x = new Uint32Array(16), i;
    x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;
    for (i = 0; i < 8; i++) x[4 + i] = readU32LE(key, i * 4);
    for (i = 0; i < 4; i++) x[12 + i] = readU32LE(nonce16, i * 4);
    var w = new Uint32Array(x), r;
    for (r = 0; r < 10; r++) {
      chachaQuarter(w, 0, 4, 8, 12); chachaQuarter(w, 1, 5, 9, 13);
      chachaQuarter(w, 2, 6, 10, 14); chachaQuarter(w, 3, 7, 11, 15);
      chachaQuarter(w, 0, 5, 10, 15); chachaQuarter(w, 1, 6, 11, 12);
      chachaQuarter(w, 2, 7, 8, 13); chachaQuarter(w, 3, 4, 9, 14);
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 4; i++) writeU32LE(w[i], out, i * 4);
    for (i = 0; i < 4; i++) writeU32LE(w[12 + i], out, 16 + i * 4);
    return out;
  }
  function xchacha20Stream(key, nonce24, len) {
    if (nonce24.length !== 24) throw new Error('XChaCha20 nonce 必须 24 字节');
    var sub = hchacha20(key, nonce24.subarray(0, 16));
    var c12 = new Uint8Array(12);
    c12.set(nonce24.subarray(16, 24), 4);
    return chacha20Stream(sub, c12, 0, len);
  }
  function xchacha20Crypt(data, key, nonce24) {
    return _xor(data, xchacha20Stream(key, nonce24, data.length));
  }
  /* XChaCha20-Poly1305（draft-irtf-cfrg-xchacha）：子密钥 + 12 字节 nonce(前 4 字节零) */
  function xchacha20Poly1305Encrypt(plain, key, nonce24, aad) {
    var sub = hchacha20(key, nonce24.subarray(0, 16));
    var c12 = new Uint8Array(12);
    c12.set(nonce24.subarray(16, 24), 4);
    return chacha20Poly1305Encrypt(plain, sub, c12, aad || new Uint8Array(0));
  }
  function xchacha20Poly1305Decrypt(ct, tag, key, nonce24, aad) {
    var sub = hchacha20(key, nonce24.subarray(0, 16));
    var c12 = new Uint8Array(12);
    c12.set(nonce24.subarray(16, 24), 4);
    return chacha20Poly1305Decrypt(ct, tag, sub, c12, aad || new Uint8Array(0));
  }

  /* ---------------- PASETO PAE ---------------- */
  function _le64(n) {
    var b = new Uint8Array(8), v = n;
    for (var i = 0; i < 8; i++) { b[i] = Number(v & 0xffn); v >>= 8n; }
    return b;
  }
  function pae(pieces) {
    var out = _le64(BigInt(pieces.length)), i;
    for (i = 0; i < pieces.length; i++) {
      out = concatBytes(out, _le64(BigInt(pieces[i].length)));
      out = concatBytes(out, pieces[i]);
    }
    return out;
  }
  /* 无填充 base64url（PASETO 规范要求不带 =） */
  function b64u(b) {
    if (typeof b64urlEncode === 'function') {
      var r = b64urlEncode(b);
      return typeof r === 'string' ? r : _str(r);
    }
    return null;
  }
  /* 带填充 base64url（Fernet 规范要求保留 =，去掉会导致 token 无法被
     Python cryptography 解析——实测差异只在尾部等号，极易被忽略） */
  function b64uPad(b) {
    var s = typeof bytesToBase64 === 'function' ? bytesToBase64(b) : null;
    if (!s) return b64u(b);
    return s.replace(/\+/g, '-').replace(/\//g, '_');
  }
  function b64uDec(s) {
    if (typeof b64urlDecode === 'function') return b64urlDecode(s);
    return null;
  }

  /* ---------------- Fernet ---------------- */
  function aes128CbcEncrypt(plain, key16, iv16) {
    var ks = aesExpandKey(key16);
    var encFn = function (blk) { return aesEncryptBlockJS(blk, ks); };
    return cbcEnc(plain, 16, encFn, 'PKCS7', iv16);
  }
  function aes128CbcDecrypt(ct, key16, iv16) {
    var ks = aesExpandKey(key16);
    var decFn = (typeof aesDecryptBlockJS === 'function')
      ? function (blk) { return aesDecryptBlockJS(blk, ks); }
      : null;
    if (!decFn) throw new Error('缺少 AES 解密块函数');
    return cbcDec(ct, 16, decFn, 'PKCS7', iv16);
  }
  function fernetEncrypt(payload, key32, tsSec, iv16) {
    if (key32.length !== 32) throw new Error('Fernet 密钥必须 32 字节（base64url 解码后）');
    var signKey = key32.subarray(0, 16), encKey = key32.subarray(16, 32);
    var head = new Uint8Array(9);
    head[0] = 0x80;
    var t = BigInt(Math.floor(tsSec));
    for (var i = 0; i < 8; i++) head[1 + i] = Number((t >> BigInt(8 * (7 - i))) & 0xffn);
    var ct = aes128CbcEncrypt(payload, encKey, iv16);
    var body = concatBytes(head, iv16, ct);
    var mac = hmacSha256(signKey, body);
    return b64uPad(concatBytes(body, mac));
  }
  function fernetDecrypt(tokenStr, key32) {
    if (key32.length !== 32) throw new Error('Fernet 密钥必须 32 字节（base64url 解码后）');
    var signKey = key32.subarray(0, 16), encKey = key32.subarray(16, 32);
    var raw = b64uDec(String(tokenStr).trim());
    if (!raw || raw.length < 9 + 16 + 16 + 32) throw new Error('Fernet token 长度不足或 base64url 解析失败');
    if (raw[0] !== 0x80) throw new Error('Fernet 版本字节不是 0x80（不是 v1 token）');
    var ts = 0n;
    for (var i = 0; i < 8; i++) ts = (ts << 8n) | BigInt(raw[1 + i]);
    var iv = raw.subarray(9, 25);
    var ct = raw.subarray(25, raw.length - 32);
    var mac = raw.subarray(raw.length - 32);
    var body = raw.subarray(0, raw.length - 32);
    var mac2 = hmacSha256(signKey, body);
    /* 常量时间比较：不要用逐字节 break，避免通过计时泄漏「哪一位先不同」 */
    var diff = 0;
    for (i = 0; i < 32; i++) diff |= mac[i] ^ mac2[i];
    if (diff !== 0) throw new Error('Fernet HMAC 校验失败：密钥错误或 token 被篡改');
    var pt = aes128CbcDecrypt(ct, encKey, iv);
    return { payload: pt, timestamp: ts };
  }

  /* ---------------- PASETO v4.local ---------------- */
  function pasetoV4LocalEncrypt(payload, key32, nonce32, footer, implicit) {
    footer = footer || new Uint8Array(0);
    implicit = implicit || new Uint8Array(0);
    var header = _u8('v4.local.');
    if (!nonce32 || nonce32.length === 0) nonce32 = _rand(32);
    if (nonce32.length !== 32) throw new Error('v4.local nonce 必须 32 字节');
    var tmp = blake2bDigest(concatBytes(_u8('paseto-encryption-key'), nonce32), 56, key32);
    var ek = tmp.subarray(0, 32), n2 = tmp.subarray(32, 56);
    var ak = blake2bDigest(concatBytes(_u8('paseto-auth-key-for-aead'), nonce32), 32, key32);
    var c = xchacha20Crypt(payload, ek, n2);
    var preAuth = pae([header, nonce32, c, footer, implicit]);
    var t = blake2bDigest(preAuth, 32, ak);
    var tok = _str(header) + b64u(concatBytes(nonce32, concatBytes(c, t)));
    if (footer.length) tok += '.' + b64u(footer);
    return tok;
  }
  function pasetoV4LocalDecrypt(tokenStr, key32, footer, implicit) {
    footer = footer || new Uint8Array(0);
    implicit = implicit || new Uint8Array(0);
    var header = _u8('v4.local.');
    var s = String(tokenStr).trim(), parts = s.split('.');
    var b = b64uDec(parts[2]);
    if (!b || b.length < 32 + 32) throw new Error('v4.local token 长度不足');
    var n = b.subarray(0, 32);
    var c = b.subarray(32, b.length - 32);
    var t = b.subarray(b.length - 32);
    var tmp = blake2bDigest(concatBytes(_u8('paseto-encryption-key'), n), 56, key32);
    var ek = tmp.subarray(0, 32), n2 = tmp.subarray(32, 56);
    var ak = blake2bDigest(concatBytes(_u8('paseto-auth-key-for-aead'), n), 32, key32);
    var preAuth = pae([header, n, c, footer, implicit]);
    var t2 = blake2bDigest(preAuth, 32, ak);
    var diff = 0;
    for (var i = 0; i < 32; i++) diff |= t[i] ^ t2[i];
    if (diff !== 0) throw new Error('v4.local 认证失败：密钥错误或 token 被篡改');
    return xchacha20Crypt(c, ek, n2);
  }

  /* ---------------- PASETO v2.local ---------------- */
  function pasetoV2LocalEncrypt(payload, key32, nonce24, footer) {
    footer = footer || new Uint8Array(0);
    var header = _u8('v2.local.');
    if (!nonce24 || nonce24.length === 0) nonce24 = _rand(24);
    if (nonce24.length !== 24) throw new Error('v2.local nonce 必须 24 字节');
    var preAuth = pae([header, nonce24, footer]);
    var r = xchacha20Poly1305Encrypt(payload, key32, nonce24, preAuth);
    var tok = _str(header) + b64u(concatBytes(nonce24, concatBytes(r.ciphertext, r.tag)));
    if (footer.length) tok += '.' + b64u(footer);
    return tok;
  }
  function pasetoV2LocalDecrypt(tokenStr, key32, footer) {
    footer = footer || new Uint8Array(0);
    var header = _u8('v2.local.');
    var s = String(tokenStr).trim(), parts = s.split('.');
    var b = b64uDec(parts[2]);
    if (!b || b.length < 24 + 16) throw new Error('v2.local token 长度不足');
    var n = b.subarray(0, 24);
    var ct = b.subarray(24, b.length - 16);
    var tag = b.subarray(b.length - 16);
    var preAuth = pae([header, n, footer]);
    return xchacha20Poly1305Decrypt(ct, tag, key32, n, preAuth);
  }

  /* ---------------- PASETO v4.public / v2.public ---------------- */
  function pasetoV4PublicSign(payload, sk32, footer, implicit) {
    footer = footer || new Uint8Array(0);
    implicit = implicit || new Uint8Array(0);
    var header = _u8('v4.public.');
    var m2 = pae([header, payload, footer, implicit]);
    var sig = ed25519SignCore(m2, sk32, null, 'pure');
    var tok = _str(header) + b64u(concatBytes(payload, sig));
    if (footer.length) tok += '.' + b64u(footer);
    return tok;
  }
  function pasetoV4PublicVerify(tokenStr, pk32, footer, implicit) {
    footer = footer || new Uint8Array(0);
    implicit = implicit || new Uint8Array(0);
    var header = _u8('v4.public.');
    var b = b64uDec(String(tokenStr).trim().split('.')[2]);
    if (!b || b.length <= 64) throw new Error('v4.public token 长度不足');
    var m = b.subarray(0, b.length - 64), sig = b.subarray(b.length - 64);
    var m2 = pae([header, m, footer, implicit]);
    var ok = ed25519VerifyCore(m2, sig, pk32, null, 'pure');
    if (!ok) throw new Error('v4.public 验签失败：签名无效或公钥不匹配');
    return m;
  }
  function pasetoV2PublicSign(payload, sk32, footer) {
    footer = footer || new Uint8Array(0);
    var header = _u8('v2.public.');
    var m2 = pae([header, payload, footer]);
    var sig = ed25519SignCore(m2, sk32, null, 'pure');
    var tok = _str(header) + b64u(concatBytes(payload, sig));
    if (footer.length) tok += '.' + b64u(footer);
    return tok;
  }
  function pasetoV2PublicVerify(tokenStr, pk32, footer) {
    footer = footer || new Uint8Array(0);
    var header = _u8('v2.public.');
    var b = b64uDec(String(tokenStr).trim().split('.')[2]);
    if (!b || b.length <= 64) throw new Error('v2.public token 长度不足');
    var m = b.subarray(0, b.length - 64), sig = b.subarray(b.length - 64);
    var m2 = pae([header, m, footer]);
    var ok = ed25519VerifyCore(m2, sig, pk32, null, 'pure');
    if (!ok) throw new Error('v2.public 验签失败：签名无效或公钥不匹配');
    return m;
  }

  /* ================= 调试 / 测试出口 ================= */
  globalThis.__protoA = {
    hsalsa20: hsalsa20, xsalsa20Stream: xsalsa20Stream, xsalsa20Crypt: xsalsa20Crypt,
    secretboxSeal: secretboxSeal, secretboxOpen: secretboxOpen,
    boxBeforenm: boxBeforenm,
    hchacha20: hchacha20, xchacha20Crypt: xchacha20Crypt,
    xchacha20Poly1305Encrypt: xchacha20Poly1305Encrypt,
    xchacha20Poly1305Decrypt: xchacha20Poly1305Decrypt,
    pae: pae,
    fernetEncrypt: fernetEncrypt, fernetDecrypt: fernetDecrypt,
    pasetoV4LocalEncrypt: pasetoV4LocalEncrypt, pasetoV4LocalDecrypt: pasetoV4LocalDecrypt,
    pasetoV2LocalEncrypt: pasetoV2LocalEncrypt, pasetoV2LocalDecrypt: pasetoV2LocalDecrypt,
    pasetoV4PublicSign: pasetoV4PublicSign, pasetoV4PublicVerify: pasetoV4PublicVerify,
    pasetoV2PublicSign: pasetoV2PublicSign, pasetoV2PublicVerify: pasetoV2PublicVerify
  };

  var _n = 0;
  /* ================= 条目注册 ================= */

  /* --- XSalsa20 --- */
  reg({
    id: 'xsalsa20',
    name: 'XSalsa20 流密码（NaCl 用）',
    group: '对称加密',
    key: true, param: true,
    keyLabel: '密钥（Hex，32 字节）',
    paramLabel: 'nonce（Hex，24 字节；留空随机）',
    info: 'XSalsa20 = HSalsa20(key, nonce[0:16]) 派生子密钥 + Salsa20(subkey, nonce[16:24])，24 字节 nonce 可安全随机生成。NaCl / libsodium 的 crypto_stream 与 secretbox 均基于此。输出 nonce‖密文，解密时自动剥离。参照 PyNaCl 1.6.2。',
    enc: async function (b, k, p, fmt) {
      var key = hexToBytes(String(k || '').trim());
      if (key.length !== 32) throw new Error('XSalsa20 需要 32 字节密钥');
      var n = hexToBytes(String(p || '').trim());
      if (!n.length) n = _rand(24);
      if (n.length !== 24) throw new Error('nonce 必须 24 字节');
      return bytesOut(concatBytes(n, xsalsa20Crypt(b, key, n)), fmt);
    },
    dec: async function (b, k, p, fmt) {
      var key = hexToBytes(String(k || '').trim());
      if (key.length !== 32) throw new Error('XSalsa20 需要 32 字节密钥');
      if (b.length < 24) throw new Error('输入需含 24 字节 nonce 前缀');
      var n = b.subarray(0, 24);
      return bytesOut(xsalsa20Crypt(b.subarray(24), key, n), fmt);
    }
  }); _n++;

  /* --- NaCl secretbox --- */
  reg({
    id: 'nacl-secretbox-enc',
    name: 'NaCl secretbox 封装（XSalsa20-Poly1305）',
    group: '对称加密',
    key: true, param: true,
    keyLabel: '对称密钥（Hex，32 字节）',
    paramLabel: 'nonce（Hex，24 字节；留空随机）',
    info: 'libsodium crypto_secretbox：首个 keystream 块的前 32 字节作 Poly1305 一次性密钥，明文从第 32 字节起异或，输出 tag(16)‖密文。24 字节 nonce 可随机。参照 PyNaCl 1.6.2。',
    enc: async function (b, k, p, fmt) {
      var key = hexToBytes(String(k || '').trim());
      if (key.length !== 32) throw new Error('secretbox 需要 32 字节密钥');
      var n = hexToBytes(String(p || '').trim());
      if (!n.length) n = _rand(24);
      if (n.length !== 24) throw new Error('nonce 必须 24 字节');
      return bytesOut(concatBytes(n, secretboxSeal(b, key, n).box), fmt);
    }
  }); _n++;
  reg({
    id: 'nacl-secretbox-dec',
    name: 'NaCl secretbox 解封（XSalsa20-Poly1305）',
    group: '对称加密',
    key: true, param: true,
    keyLabel: '对称密钥（Hex，32 字节）',
    paramLabel: 'nonce 可留空（输入为 nonce‖box 时自动取前 24 字节）',
    info: '解封并校验 Poly1305 tag：密钥/nonce 不匹配或密文被篡改会直接报错，不会返回错误明文。输入格式 nonce(24)‖tag(16)‖密文。参照 PyNaCl 1.6.2。',
    dec: async function (b, k, p, fmt) {
      var key = hexToBytes(String(k || '').trim());
      if (key.length !== 32) throw new Error('secretbox 需要 32 字节密钥');
      var ps = String(p || '').trim();
      var n, box;
      if (ps.length) { n = hexToBytes(ps); box = b; }
      else { if (b.length < 40) throw new Error('输入需为 nonce(24)‖box'); n = b.subarray(0, 24); box = b.subarray(24); }
      if (n.length !== 24) throw new Error('nonce 必须 24 字节');
      return bytesOut(secretboxOpen(box, key, n), fmt);
    }
  }); _n++;

  /* --- NaCl box --- */
  reg({
    id: 'nacl-box-enc',
    name: 'NaCl box 封装（X25519 双方）',
    group: '非对称加密',
    key: true, key2: true, param: true, rawKey: true,
    keyLabel: '自己的私钥（Hex，32 字节）',
    key2Label: '对方公钥（Hex，32 字节）',
    paramLabel: 'nonce（Hex，24 字节，留空随机）',
    info: 'libsodium crypto_box：k = HSalsa20(X25519(自己的私钥, 对方公钥), 全零 16 字节)，再走 secretbox。24 字节 nonce 可随机。输出 nonce‖box。参照 PyNaCl 1.6.2。',
    enc: async function (b, k, p, fmt, k2) {
      var sk = hexToBytes(String(k || '').trim());
      var pk = hexToBytes(String(k2 || '').trim());
      if (sk.length !== 32) throw new Error('自己的私钥需 32 字节');
      if (pk.length !== 32) throw new Error('对方公钥需 32 字节');
      if (pk.length !== 32) throw new Error('对方公钥需 32 字节');
      var n = hexToBytes(String(p || '').split(',')[0].trim());
      if (!n.length) n = _rand(24);
      if (n.length !== 24) throw new Error('nonce 必须 24 字节');
      var ks = boxBeforenm(sk, pk);
      return bytesOut(concatBytes(n, secretboxSeal(b, ks, n).box), fmt);
    }
  }); _n++;
  reg({
    id: 'nacl-box-dec',
    name: 'NaCl box 解封（X25519 双方）',
    group: '非对称加密',
    key: true, key2: true, param: false, rawKey: true,
    keyLabel: '自己的私钥（Hex，32 字节）',
    key2Label: '对方公钥（Hex，32 字节）',
    info: '输入 nonce(24)‖tag(16)‖密文，用 X25519 共享密钥解封并校验 Poly1305 tag。参照 PyNaCl 1.6.2。',
    dec: async function (b, k, p, fmt, k2) {
      var sk = hexToBytes(String(k || '').trim());
      var pk = hexToBytes(String(k2 || '').trim());
      if (sk.length !== 32) throw new Error('自己的私钥需 32 字节');
      if (pk.length !== 32) throw new Error('对方公钥需 32 字节');
      if (b.length < 40) throw new Error('输入需为 nonce(24)‖box');
      var n = b.subarray(0, 24);
      var ks = boxBeforenm(sk, pk);
      return bytesOut(secretboxOpen(b.subarray(24), ks, n), fmt);
    }
  }); _n++;

  /* --- NaCl sealed box --- */
  reg({
    id: 'nacl-sealedbox-enc',
    name: 'NaCl sealed box 封装（匿名发送）',
    group: '非对称加密',
    key: true, key2: true, param: false, rawKey: true,
    keyLabel: '接收方公钥（Hex，32 字节）',
    key2Label: '自己的私钥（可留空，留空则自动随机生成临时密钥对）',
    key2Optional: true,
    info: 'libsodium crypto_box_seal：生成临时 X25519 密钥对，共享密钥经 HSalsa20 派生，nonce = BLAKE2b-256(临时公钥‖接收方公钥)[0:24]。输出 = 临时公钥(32)‖box，发送方不留痕迹。默认随机生成临时密钥对（匿名）；若要可复现，在第二栏填入指定的临时私钥。参照 PyNaCl 1.6.2。',
    enc: async function (b, k, p, fmt, k2) {
      var rpk = hexToBytes(String(k || '').trim());
      if (rpk.length !== 32) throw new Error('接收方公钥需 32 字节');
      var k2s = String(k2 || '').trim();
      var esk = k2s ? hexToBytes(k2s) : _rand(32);
      if (esk.length !== 32) throw new Error('临时私钥需 32 字节');
      var epk = pubFromSk(esk);
      var ks = boxBeforenm(esk, rpk);
      var n = blake2bDigest(concatBytes(epk, rpk), 24);
      return bytesOut(concatBytes(epk, secretboxSeal(b, ks, n).box), fmt);
    }
  }); _n++;
  reg({
    id: 'nacl-sealedbox-dec',
    name: 'NaCl sealed box 解封（匿名接收）',
    group: '非对称加密',
    key: true, key2: true, param: false, rawKey: true,
    keyLabel: '接收方私钥（Hex，32 字节）',
    key2Label: '对方公钥（通常留空：临时公钥已含在密文前 32 字节）',
    key2Optional: true,
    info: '输入 = 临时公钥(32)‖tag(16)‖密文。用接收方私钥与密文里的临时公钥重建共享密钥，nonce 同样由 BLAKE2b 派生。第二栏一般不用填；若密文不含临时公钥（已被剥离），才在此填入对方公钥。参照 PyNaCl 1.6.2。',
    dec: async function (b, k, p, fmt, k2) {
      var sk = hexToBytes(String(k || '').trim());
      if (sk.length !== 32) throw new Error('接收方私钥需 32 字节');
      var k2s = String(k2 || '').trim();
      var epk, body;
      if (k2s) {
        /* 密文不含临时公钥：整段都是 box，临时公钥从第二栏取 */
        epk = hexToBytes(k2s);
        if (epk.length !== 32) throw new Error('对方公钥需 32 字节');
        body = b;
      } else {
        if (b.length < 48) throw new Error('输入需为 临时公钥(32)‖box');
        epk = b.subarray(0, 32);
        body = b.subarray(32);
      }
      var rpk = pubFromSk(sk);
      var ks = boxBeforenm(sk, epk);
      var n = blake2bDigest(concatBytes(epk, rpk), 24);
      return bytesOut(secretboxOpen(body, ks, n), fmt);
    }
  }); _n++;

  /* --- Fernet --- */
  reg({
    id: 'fernet-enc',
    name: 'Fernet 加密（Python cryptography 格式）',
    group: '对称加密',
    key: true, param: true,
    keyLabel: '密钥（base64url 32 字节，或 Hex 64 字符）',
    paramLabel: '时间戳（Unix 秒）[, IV（Hex，16 字节）]（均留空则取当前时间/随机 IV）',
    info: 'Fernet 是 Python cryptography 的事实标准容器：0x80‖时间戳(8,大端)‖IV(16)‖AES-128-CBC‖HMAC-SHA256，整段 base64url。32 字节密钥前 16 字节用于 HMAC、后 16 字节用于 AES。参照 cryptography 50.0.1。',
    enc: async function (b, k, p, fmt) {
      var key = _parseKey32(k);
      var f = String(p || '').split(',').map(function (x) { return x.trim(); });
      var ts = f[0] ? parseInt(f[0], 10) : Math.floor(Date.now() / 1000);
      var iv = hexToBytes(f[1] || '');
      if (!iv.length) iv = _rand(16);
      if (iv.length !== 16) throw new Error('IV 必须 16 字节');
      return fernetEncrypt(b, key, ts, iv);
    }
  }); _n++;
  reg({
    id: 'fernet-dec',
    name: 'Fernet 解密（Python cryptography 格式）',
    group: '对称加密',
    key: true, param: false,
    keyLabel: '密钥（base64url 32 字节，或 Hex 64 字符）',
    info: '校验 HMAC-SHA256 后用 AES-128-CBC 解密。HMAC 用常量时间比较，不匹配直接报错——Fernet 是「先认证后解密」，不会返回错误明文。输入框填完整 token（gAAAAA…）。参照 cryptography 50.0.1。',
    dec: async function (b, k, p, fmt) {
      var key = _parseKey32(k);
      var tok = _str(b).trim();
      var r = fernetDecrypt(tok, key);
      return bytesOut(r.payload, fmt);
    }
  }); _n++;
  function _parseKey32(k) {
    var s = String(k || '').trim();
    if (!s.length) throw new Error('请填 Fernet 密钥');
    if (/^[0-9a-fA-F]{64}$/.test(s)) return hexToBytes(s);
    var b = b64uDec(s);
    if (!b || b.length !== 32) throw new Error('Fernet 密钥需 32 字节（base64url 或 64 位 Hex）');
    return b;
  }

  /* --- PASETO v4.local --- */
  reg({
    id: 'paseto-v4-local-enc',
    name: 'PASETO v4.local 加密',
    group: '对称加密',
    key: true, param: true,
    keyLabel: '对称密钥（Hex，32 字节）',
    paramLabel: 'nonce（Hex，32 字节；留空随机）[, footer]',
    info: 'PASETO v4.local：n(32) 经 BLAKE2b 派生 ek/n2 与 ak；密文 = XChaCha20(ek,n2) 纯加密，标签 t = BLAKE2b(ak, PAE(header,n,c,footer,implicit),32)。v4 属「加密 + 外部认证」，与 v2 的内联 AEAD tag 结构不同。参照 pyseto 1.10.0。',
    enc: async function (b, k, p, fmt) {
      var key = hexToBytes(String(k || '').trim());
      if (key.length !== 32) throw new Error('v4.local 需要 32 字节密钥');
      var f = _splitP(String(p || ''));
      var n = hexToBytes(f[0] || '');
      if (!n.length) n = _rand(32);
      var footer = f[1] ? _u8(f[1]) : new Uint8Array(0);
      return pasetoV4LocalEncrypt(b, key, n, footer, new Uint8Array(0));
    }
  }); _n++;
  reg({
    id: 'paseto-v4-local-dec',
    name: 'PASETO v4.local 解密',
    group: '对称加密',
    key: true, param: true,
    keyLabel: '对称密钥（Hex，32 字节）',
    paramLabel: 'footer（若加密时带 footer 需一致）',
    info: '重算 BLAKE2b 认证标签并常量时间比对，不匹配直接报错（不解密）。输入框填完整 token（v4.local.xxx）。参照 pyseto 1.10.0。',
    dec: async function (b, k, p, fmt) {
      var key = hexToBytes(String(k || '').trim());
      if (key.length !== 32) throw new Error('v4.local 需要 32 字节密钥');
      var footer = String(p || '').trim() ? _u8(String(p).trim()) : new Uint8Array(0);
      return bytesOut(pasetoV4LocalDecrypt(_str(b).trim(), key, footer, new Uint8Array(0)), fmt);
    }
  }); _n++;

  /* --- PASETO v2.local --- */
  reg({
    id: 'paseto-v2-local-enc',
    name: 'PASETO v2.local 加密',
    group: '对称加密',
    key: true, param: true,
    keyLabel: '对称密钥（Hex，32 字节）',
    paramLabel: 'nonce（Hex，24 字节；留空随机）[, footer]',
    info: 'PASETO v2.local：n(24)，XChaCha20-Poly1305(key, n)，AAD = PAE(header, n, footer)，tag 内联在 token 末尾（16 字节）。与 v4 的区别：v2 用 AEAD 内联 tag，v4 用分离的 BLAKE2b 标签。参照 pyseto 1.10.0。',
    enc: async function (b, k, p, fmt) {
      var key = hexToBytes(String(k || '').trim());
      if (key.length !== 32) throw new Error('v2.local 需要 32 字节密钥');
      var f = _splitP(String(p || ''));
      var n = hexToBytes(f[0] || '');
      if (!n.length) n = _rand(24);
      var footer = f[1] ? _u8(f[1]) : new Uint8Array(0);
      return pasetoV2LocalEncrypt(b, key, n, footer);
    }
  }); _n++;
  reg({
    id: 'paseto-v2-local-dec',
    name: 'PASETO v2.local 解密',
    group: '对称加密',
    key: true, param: true,
    keyLabel: '对称密钥（Hex，32 字节）',
    paramLabel: 'footer（若加密时带 footer 需一致）',
    info: '校验 XChaCha20-Poly1305 内联 tag（含 PAE 前缀作为 AAD），失败直接报错。输入框填完整 token（v2.local.xxx）。参照 pyseto 1.10.0。',
    dec: async function (b, k, p, fmt) {
      var key = hexToBytes(String(k || '').trim());
      if (key.length !== 32) throw new Error('v2.local 需要 32 字节密钥');
      var footer = String(p || '').trim() ? _u8(String(p).trim()) : new Uint8Array(0);
      return bytesOut(pasetoV2LocalDecrypt(_str(b).trim(), key, footer), fmt);
    }
  }); _n++;

  /* --- PASETO v4.public --- */
  reg({
    id: 'paseto-v4-public-sign',
    name: 'PASETO v4.public 签发（Ed25519）',
    group: '数字签名',
    key: true, param: true,
    keyLabel: 'Ed25519 私钥（Hex，32 字节种子）',
    paramLabel: '可留空；格式：footer[, implicit_assertion]',
    info: 'PASETO v4.public：对 PAE("v4.public.", payload, footer, implicit_assertion) 做 Ed25519 签名，token = 明文‖签名(64) 的 base64url。v4 引入 implicit assertion（不随 token 传输的隐式断言），v2 没有这一层。参照 pyseto 1.10.0。',
    enc: async function (b, k, p, fmt) {
      var sk = hexToBytes(String(k || '').trim());
      if (sk.length !== 32) throw new Error('Ed25519 私钥需 32 字节种子');
      var f = _splitP(String(p || ''));
      return pasetoV4PublicSign(b, sk, f[0] ? _u8(f[0]) : new Uint8Array(0), f[1] ? _u8(f[1]) : new Uint8Array(0));
    }
  }); _n++;
  reg({
    id: 'paseto-v4-public-verify',
    name: 'PASETO v4.public 验签（Ed25519）',
    group: '数字签名',
    key: true, param: true,
    keyLabel: 'Ed25519 公钥（Hex，32 字节）',
    paramLabel: '格式：footer[, implicit_assertion]（须与签发时一致）',
    info: '验证 v4.public token 的 Ed25519 签名并返回原文。验签失败直接报错。输入框填完整 token（v4.public.xxx）。参照 pyseto 1.10.0。',
    dec: async function (b, k, p, fmt) {
      var pk = hexToBytes(String(k || '').trim());
      if (pk.length !== 32) throw new Error('Ed25519 公钥需 32 字节');
      var f = _splitP(String(p || ''));
      return bytesOut(pasetoV4PublicVerify(_str(b).trim(), pk, f[0] ? _u8(f[0]) : new Uint8Array(0), f[1] ? _u8(f[1]) : new Uint8Array(0)), fmt);
    }
  }); _n++;

  /* --- PASETO v2.public --- */
  reg({
    id: 'paseto-v2-public-sign',
    name: 'PASETO v2.public 签发（Ed25519）',
    group: '数字签名',
    key: true, param: true,
    keyLabel: 'Ed25519 私钥（Hex，32 字节种子）',
    paramLabel: 'footer（可留空）',
    info: 'PASETO v2.public：对 PAE("v2.public.", payload, footer) 做 Ed25519 签名。与 v4 的差别是没有 implicit assertion 字段。参照 pyseto 1.10.0。',
    enc: async function (b, k, p, fmt) {
      var sk = hexToBytes(String(k || '').trim());
      if (sk.length !== 32) throw new Error('Ed25519 私钥需 32 字节种子');
      return pasetoV2PublicSign(b, sk, String(p || '').trim() ? _u8(String(p).trim()) : new Uint8Array(0));
    }
  }); _n++;
  reg({
    id: 'paseto-v2-public-verify',
    name: 'PASETO v2.public 验签（Ed25519）',
    group: '数字签名',
    key: true, param: true,
    keyLabel: 'Ed25519 公钥（Hex，32 字节）',
    paramLabel: 'footer（须与签发时一致，可留空）',
    info: '验证 v2.public token 的 Ed25519 签名并返回原文。参照 pyseto 1.10.0。',
    dec: async function (b, k, p, fmt) {
      var pk = hexToBytes(String(k || '').trim());
      if (pk.length !== 32) throw new Error('Ed25519 公钥需 32 字节');
      return bytesOut(pasetoV2PublicVerify(_str(b).trim(), pk, String(p || '').trim() ? _u8(String(p).trim()) : new Uint8Array(0)), fmt);
    }
  }); _n++;

  /* 逗号分隔，双引号内的逗号不分隔。
     注意：引号字符本身要保留 —— footer 常是 JSON（如 {"kid":"x"}），
     若把引号全部吃掉会变成 {kid:x}，静默产出错误的 token。
     只在字段首尾是【配对】引号时才剥掉这一对。 */
  function _splitP(s) {
    var out = [], cur = '', inQ = false, i, ch;
    for (i = 0; i < s.length; i++) {
      ch = s[i];
      if (ch === '"') { inQ = !inQ; cur += ch; continue; }
      if (ch === ',' && !inQ) { out.push(cur.trim()); cur = ''; continue; }
      cur += ch;
    }
    out.push(cur.trim());
    return out.map(function (x) {
      if (x.length >= 2 && x.charAt(0) === '"' && x.charAt(x.length - 1) === '"') return x.slice(1, -1);
      return x;
    });
  }

  console.log('crypto_proto_a.js：XSalsa20 / NaCl(secretbox·box·sealedbox) / Fernet / PASETO v2·v4 已注册，共 ' + _n + ' 个算法');
})();
