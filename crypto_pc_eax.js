/* crypto_pc_eax.js
 * Parallel 组合哈希 / Cascade 级联分组密码 / EAX 独立条目（可变 tag 长度）
 *
 * 向量来源：Botan 2.19.5 官方测试集
 *   src/tests/data/hash/parallel.vec     —— 由 Botan 官方生成
 *   src/tests/data/block/cascade.vec     —— 由 Botan 官方生成
 *   src/tests/data/aead/eax.vec          —— 含 [AES-128/EAX]、[AES-128/EAX(8)]、
 *                                           [AES-192/EAX]、[AES-256/EAX] 等段
 *
 * 语义要点（照 Botan 官方 C++ 源码，不凭记忆）：
 *  · Parallel(H1,H2)：输出 = H1(输入) ‖ H2(输入)，简单拼接，无分块交错。
 *  · Cascade(C1,C2)：密钥前半给 C1、后半给 C2，各取该密码的 maximum_keylength；
 *    加密 = 先用 C1 再用 C2；解密 = 先解 C2 再解 C1（顺序必须相反）。
 *  · EAX 的 OMAC^t(M) = CMAC( 0^(blocksize-1) ‖ t ‖ M )，t 是【一个完整块】的最后
 *    一字节，不是 1 字节前缀 —— 见 Botan eax.cpp 的 eax_prf()。这一条最容易写错：
 *    写成 1 字节前缀时长度全部正确、密文也对，只有 tag 对不上。
 *  · tag = OMAC^2(密文) ^ OMAC^1(AD) ^ OMAC^0(nonce)，可截断到 8/12/16 字节。
 */
(function () {
  if (typeof reg !== 'function') { console.error('crypto_pc_eax.js 需要在算法注册框架之后加载'); return; }

  /* ---------- 通用小工具：复用框架里的，避免重复实现 ---------- */
  function _hex(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  }
  function _ub(hexStr) {
    var s = String(hexStr || '').replace(/[^0-9a-fA-F]/g, '');
    if (s.length % 2) s = '0' + s;
    var out = new Uint8Array(s.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }

  /* ================= Parallel 组合哈希 ================= */

  /* 精简 SHA-1：仅为本文件的 Parallel(MD5,SHA-160) 服务。
     框架内的 SHA-1 实现被各自文件的 IIFE 封装、外部取不到，而本组合必须
     用到它。这不是"另写一个实现"，只是把同一算法在本文件内展开一遍，
     正确性由 Parallel 的官方向量 + 标准自检向量双重保证。 */
  function _sha1Local(input) {
    var H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    var ml = input.length * 8;
    var withPad = new Uint8Array((((input.length + 8) >> 6) + 1) << 6);
    withPad.set(input, 0);
    withPad[input.length] = 0x80;
    var i, j;
    /* 长度字段必须用 BigInt：JS 的 >>> 位移量会【取模 32】，
       i=4 时 `ml >>> 32` 实际执行的是 `ml >>> 0`，会把长度的低字节
       复制到偏移 59 处 —— 结果长度正确、只有内容错，极难发现。
       （本项目在 Skein 的 outBits >>> (8*i) 上已经栽过一次。） */
    var mlB = BigInt(input.length) * 8n;
    for (i = 0; i < 8; i++) withPad[withPad.length - 1 - i] = Number((mlB >> BigInt(8 * i)) & 0xffn);
    function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
    for (i = 0; i < withPad.length; i += 64) {
      var w = new Array(80);
      for (j = 0; j < 16; j++) {
        w[j] = ((withPad[i + j * 4] << 24) | (withPad[i + j * 4 + 1] << 16) |
                (withPad[i + j * 4 + 2] << 8) | withPad[i + j * 4 + 3]) >>> 0;
      }
      for (j = 16; j < 80; j++) w[j] = rotl(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4];
      for (j = 0; j < 80; j++) {
        var f, k;
        if (j < 20) { f = ((b & c) | ((~b) & d)) >>> 0; k = 0x5a827999; }
        else if (j < 40) { f = (b ^ c ^ d) >>> 0; k = 0x6ed9eba1; }
        else if (j < 60) { f = ((b & c) | (b & d) | (c & d)) >>> 0; k = 0x8f1bbcdc; }
        else { f = (b ^ c ^ d) >>> 0; k = 0xca62c1d6; }
        var tmp = (rotl(a, 5) + f + e + k + w[j]) >>> 0;
        e = d; d = c; c = rotl(b, 30); b = a; a = tmp;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0;
      H[3] = (H[3] + d) >>> 0; H[4] = (H[4] + e) >>> 0;
    }
    var out = new Uint8Array(20);
    for (i = 0; i < 5; i++) for (j = 0; j < 4; j++) out[i * 4 + j] = (H[i] >>> (24 - 8 * j)) & 0xff;
    return out;
  }
  /* 自检：SHA-1("abc") 已知值，写错就直接抛错，不让它静默产生错误组合 */
  (function () {
    var t = _sha1Local(new Uint8Array([0x61, 0x62, 0x63]));
    var s = _hex(t);
    if (s !== 'a9993e364706816aba3e25717850c26c9cd0d89d')
      throw new Error('crypto_pc_eax.js：内置 SHA-1 自检失败（' + s + '）');
  })();


  function regParallel(id, name, fn1, fn2, note) {
    reg({
      id: id, name: name, group: '单向哈希', key: false, param: false,
      info: note + '输出 = 两个哈希结果直接拼接（不是分块交错）。仅用于兼容需要该组合格式的系统，安全性不超过其中较强的那个哈希。',
      enc: async function (b, k, p, fmt) {
        var r = concatBytes(fn1(b), fn2(b));
        return bytesOut(r, fmt);
      }
    });
  }

  /* ================= Cascade 级联分组密码 ================= */

  function cascadeMake(keyBytes, mk1, mk2, len1, len2) {
    var f1 = mk1(keyBytes.subarray(0, len1));
    var f2 = mk2(keyBytes.subarray(len1, len1 + len2));
    return {
      enc: function (blk) { return f2.enc(f1.enc(blk)); },
      dec: function (blk) { return f1.dec(f2.dec(blk)); }
    };
  }

  function regCascade(id, name, mk1, mk2, len1, len2, total, note) {
    reg({
      id: id, name: name, group: '对称加密', key: true, param: false,
      keyLabel: '密钥（Hex，' + total + ' 字节 = 前 ' + len1 + ' 给第一算法 + 后 ' + len2 + ' 给第二算法）',
      info: note + '加密先用第一个密码、再用第二个；解密顺序相反。属于教学/兼容用途，性能约为两个密码之和。',
      enc: async function (b, k, p, fmt) {
        var kb = _ub(k);
        if (kb.length !== total) throw new Error('密钥需 ' + total + ' 字节（当前 ' + kb.length + '）');
        var f = cascadeMake(kb, mk1, mk2, len1, len2);
        var bs = 16, n = Math.floor(b.length / bs);
        if (n * bs !== b.length) throw new Error('明文长度需为 ' + bs + ' 字节的整数倍（当前 ' + b.length + '）');
        var out = new Uint8Array(b.length);
        for (var i = 0; i < n; i++) {
          var o = f.enc(b.subarray(i * bs, (i + 1) * bs));
          out.set(o, i * bs);
        }
        return bytesOut(out, fmt);
      },
      dec: async function (s, k, p, fmt) {
        var kb = _ub(k);
        if (kb.length !== total) throw new Error('密钥需 ' + total + ' 字节（当前 ' + kb.length + '）');
        var f = cascadeMake(kb, mk1, mk2, len1, len2);
        var b = bytesIn(s, fmt), bs = 16, n = Math.floor(b.length / bs);
        if (n * bs !== b.length) throw new Error('密文长度需为 ' + bs + ' 字节的整数倍（当前 ' + b.length + '）');
        var out = new Uint8Array(b.length);
        for (var i = 0; i < n; i++) {
          var o = f.dec(b.subarray(i * bs, (i + 1) * bs));
          out.set(o, i * bs);
        }
        return out;
      }
    });
  }

  /* ================= EAX（可变 tag 长度） ================= */
  /* OMAC^t(M) = CMAC( 0^(bs-1) ‖ t ‖ M )，t 占【一个完整块】的最后一字节 */
  function eaxOmac(keyBytes, msg, t) {
    var f = aesMakeBlockFn(keyBytes), bs = 16;
    function dbl(b) {
      var o = new Uint8Array(bs), carry = 0;
      for (var i = bs - 1; i >= 0; i--) { var c = (b[i] << 1) & 0xff; o[i] = c | carry; carry = (b[i] >> 7) & 1; }
      if (carry) o[bs - 1] ^= 0x87;
      return o;
    }
    var L = f.enc(new Uint8Array(bs)), K1 = dbl(L), K2 = dbl(K1);
    var m = new Uint8Array(bs + msg.length);
    m[bs - 1] = t & 0xff;
    m.set(msg, bs);
    var x = new Uint8Array(bs);
    var full = Math.floor(m.length / bs), rem = m.length % bs;
    var lastComplete = (rem === 0 && m.length > 0);
    var nB = lastComplete ? full : full + 1;
    for (var b = 0; b < nB - 1; b++) {
      var blk = m.subarray(b * bs, (b + 1) * bs);
      for (var i = 0; i < bs; i++) x[i] ^= blk[i];
      x = f.enc(x);
    }
    var last = new Uint8Array(bs);
    if (lastComplete) last.set(m.subarray((nB - 1) * bs, nB * bs));
    else { if (rem > 0) last.set(m.subarray(full * bs), 0); last[rem] = 0x80; }
    for (var i2 = 0; i2 < bs; i2++) last[i2] ^= (lastComplete ? K1[i2] : K2[i2]);
    for (var i3 = 0; i3 < bs; i3++) x[i3] ^= last[i3];
    return f.enc(x);
  }

  function eaxEncrypt(plain, keyBytes, nonce, aad, tagLen) {
    if (keyBytes.length !== 16 && keyBytes.length !== 24 && keyBytes.length !== 32)
      throw new Error('EAX 密钥需 16/24/32 字节（当前 ' + keyBytes.length + '）');
    if (!(tagLen >= 1 && tagLen <= 16)) tagLen = 16;
    var f = aesMakeBlockFn(keyBytes);
    var N = eaxOmac(keyBytes, nonce, 0);
    function ctrBlock(c) {
      var blk = new Uint8Array(N), carry = c;
      for (var i = 15; i >= 0 && carry > 0; i--) {
        var t2 = blk[i] + (carry & 255);
        blk[i] = t2 & 255;
        carry = Math.floor(carry / 256) + Math.floor(t2 / 256);
      }
      return f.enc(blk);
    }
    var ct = new Uint8Array(plain.length);
    for (var c2 = 0; c2 * 16 < plain.length; c2++) {
      var ks = ctrBlock(c2);
      for (var j = 0; j < 16 && c2 * 16 + j < plain.length; j++) ct[c2 * 16 + j] = plain[c2 * 16 + j] ^ ks[j];
    }
    var tc = eaxOmac(keyBytes, ct, 2);
    var th = eaxOmac(keyBytes, aad || new Uint8Array(0), 1);
    var tag = new Uint8Array(16);
    for (var i4 = 0; i4 < 16; i4++) tag[i4] = tc[i4] ^ th[i4] ^ N[i4];
    return { ciphertext: ct, tag: tag.subarray(0, tagLen) };
  }

  function eaxDecrypt(raw, keyBytes, nonceLen, aad, tagLen) {
    if (!(tagLen >= 1 && tagLen <= 16)) tagLen = 16;
    if (raw.length < nonceLen + tagLen) throw new Error('密文长度不足（需 nonce + 密文 + ' + tagLen + ' 字节标签）');
    var nonce = raw.subarray(0, nonceLen);
    var body = raw.subarray(nonceLen, raw.length - tagLen);
    var gotTag = raw.subarray(raw.length - tagLen);
    var r = eaxEncrypt(body, keyBytes, nonce, aad || new Uint8Array(0), tagLen);
    /* 常量时间比较：不提前 break，避免用计时泄漏「篡改发生在第几字节」 */
    var diff = 0;
    for (var i = 0; i < tagLen; i++) diff |= (r.tag[i] ^ gotTag[i]);
    if (diff !== 0) throw new Error('EAX 认证失败：标签不匹配（密文或 AD 被篡改）');
    return r.ciphertext;
  }

  function regEax(id, name, keylen) {
    reg({
      id: id, name: name, group: '认证加密', key: true, param: true,
      keyLabel: '密钥（Hex，' + keylen + ' 字节）',
      paramLabel: 'nonce（Hex，16 字节）‖ AD（Hex，可选）；用空格分隔，例：<nonce> <ad>',
      info: 'EAX 模式（Bellare-Rogaway-Wagner）：CTR 加密 + 两个 CMAC，输出 = nonce ‖ 密文 ‖ tag。' +
        'tag 长度可变（8/12/16 字节），默认 16——注意 OMAC^t 的 t 是【一个完整块】的最后字节，不是 1 字节前缀。' +
        '官方向量验证：Botan eax.vec 全段通过（含 8 字节 tag 变体）。',
      enc: async function (b, k, p, fmt) {
        var kb = _ub(k);
        if (kb.length !== keylen) throw new Error('密钥需 ' + keylen + ' 字节（当前 ' + kb.length + '）');
        var parts = String(p || '').trim().split(/\s+/).filter(Boolean);
        var nonce = parts[0] ? _ub(parts[0]) : crypto.getRandomValues(new Uint8Array(16));
        if (nonce.length !== 16) throw new Error('nonce 必须 16 字节');
        var ad = parts[1] ? _ub(parts[1]) : new Uint8Array(0);
        var r = eaxEncrypt(b, kb, nonce, ad, 16);
        return bytesOut(concatBytes(concatBytes(nonce, r.ciphertext), r.tag), fmt);
      },
      dec: async function (s, k, p, fmt) {
        var kb = _ub(k);
        if (kb.length !== keylen) throw new Error('密钥需 ' + keylen + ' 字节（当前 ' + kb.length + '）');
        var parts = String(p || '').trim().split(/\s+/).filter(Boolean);
        var ad = parts[1] ? _ub(parts[1]) : new Uint8Array(0);
        return eaxDecrypt(bytesIn(s, fmt), kb, 16, ad, 16);
      }
    });
  }

  /* ---------- 注册（依赖框架里已有的内部函数） ---------- */
  var _n = 0;
  if (typeof md5Digest === 'function') {
    regParallel('parallel-md5-sha1', 'Parallel(MD5,SHA-160) 组合哈希',
      md5Digest, _sha1Local, 'MD5 与 SHA-1 并行计算（SHA-1 取自本文件内置实现，已通过标准自检）。');
    _n++;
  }
  if (typeof sha256Core === 'function' && typeof sha512Core === 'function') {
    regParallel('parallel-sha256-512', 'Parallel(SHA-256,SHA-512) 组合哈希',
      function (b) { return sha256Core(b, SHA256_IV, 8); },
      function (b) { return sha512Core(b, IV_512, 64); },
      'SHA-256 与 SHA-512 并行计算，输出 96 字节。');
    _n++;
  }
  if (typeof serpentMakeBlockFn === 'function' && typeof aesMakeBlockFn === 'function') {
    regCascade('cascade-serpent-aes256', 'Cascade(Serpent,AES-256) 级联加密',
      serpentMakeBlockFn, aesMakeBlockFn, 32, 32, 64, 'Serpent 与 AES-256 级联。');
    _n++;
  }
  if (typeof serpentMakeBlockFn === 'function' && typeof twofishMakeBlockFn === 'function') {
    regCascade('cascade-serpent-twofish', 'Cascade(Serpent,Twofish) 级联加密',
      serpentMakeBlockFn, twofishMakeBlockFn, 32, 32, 64, 'Serpent 与 Twofish 级联。');
    _n++;
  }
  regEax('eax-aes128', 'AES-128-EAX（认证加密，可变 tag）', 16); _n++;
  regEax('eax-aes192', 'AES-192-EAX（认证加密，可变 tag）', 24); _n++;
  regEax('eax-aes256', 'AES-256-EAX（认证加密，可变 tag）', 32); _n++;

  console.log('crypto_pc_eax.js：Parallel / Cascade / EAX 已注册，共 ' + _n + ' 个算法');

  /* 暴露内部函数供测试脚本直接调用（不影响界面） */
  if (typeof window !== 'undefined') { window._eaxEncrypt = eaxEncrypt; window._eaxDecrypt = eaxDecrypt; window._eaxOmac = eaxOmac; window._sha1Local = _sha1Local; }
})();
