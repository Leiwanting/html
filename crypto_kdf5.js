/* ============================================================
 * bcrypt-pbkdf / Base58Check / Comb4P / RSA-KEM
 * ------------------------------------------------------------
 * 实现与向量均取自 Botan 2.19.5：
 *   pbkdf/bcrypt_pbkdf.vec      OpenSSH 用的 bcrypt-pbkdf
 *   base58c.vec                 Base58Check（比特币地址编码）
 *   hash/comp4p.vec             Comb4P 哈希组合器
 *   pubkey/rsa_kem.vec          ISO 18033-2 RSA-KEM
 * 语义逐行照官方 C++ 源码：
 *   src/lib/pbkdf/bcrypt_pbkdf/bcrypt_pbkdf.cpp（workfactor=6、
 *     salt_first=true、MAGIC="OxychromaticBlowfishSwatDynamite"、
 *     64 轮 blowfish、结果逐 4 字节 load_le→store_be 后异或累加）
 *   src/lib/hash/comb4p/comb4p.cpp（clear 时两哈希各 update(0)；
 *     h1^=h2；再两轮 comb4p_round；输出 h1||h2）
 *   src/lib/kdf/kdf1_iso18033（counter 从 0）；kdf2（counter 从 1）
 * RSA-KEM 的 KDF 输入是【明文 R】(ISO 18033-2)，不是密文 C0——
 *   这一点第一版写错过，靠官方向量才纠正。
 * ============================================================ */
(function () {
  'use strict';
  if (typeof ALGOS === 'undefined') return;
  function G(n) { return (typeof window !== 'undefined' ? window : globalThis)[n]; }

  var OTP = G('OTP');
  var sha1 = OTP && OTP.sha1Bytes;

  function hexToB(s) { return G('hexToBytes')(String(s || '').replace(/\s/g, '')); }
  function out(b, fmt) { return G('bytesOut')(b, fmt); }
  /* 框架给 enc 的第一个参数是已解码的字节（Uint8Array）；直接 String(b)
     会得到 "72,101,108,..." 这类逗号数字串而不是原文，必须先判类型。 */
  function inB(b) {
    if (b instanceof Uint8Array || ArrayBuffer.isView(b)) {
      return new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
    }
    return G('strToBytes')(String(b === undefined || b === null ? '' : b));
  }
  function be32(n) {
    var o = new Uint8Array(4);
    o[0] = (n >>> 24) & 255; o[1] = (n >>> 16) & 255; o[2] = (n >>> 8) & 255; o[3] = n & 255; return o;
  }
  function cat() {
    var i, n = 0; for (i = 0; i < arguments.length; i++) n += arguments[i].length;
    var o = new Uint8Array(n), p = 0;
    for (i = 0; i < arguments.length; i++) { o.set(arguments[i], p); p += arguments[i].length; }
    return o;
  }
  function xor(a, b) { var o = new Uint8Array(a.length), i; for (i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; }

  /* ============ 1. bcrypt-pbkdf ============ */
  var BF_MAGIC = hexToB('4F78796368726F6D61746963426C6F77666973685377617444796E616D697465');
  function bfFresh() {
    var fc = G('blowfishFreshConstants')();
    return [fc.P ? fc.P.slice() : fc[0].slice(), fc.S ? fc.S.slice() : fc[1].slice()];
  }
  function ldBE(salt, idx) {
    var o = idx * 4;
    return ((salt[o] << 24) | (salt[o + 1] << 16) | (salt[o + 2] << 8) | salt[o + 3]) >>> 0;
  }
  function genSbox(box, L, R, P, S, salt, saltLen, saltOff) {
    var n4 = saltLen / 4, i, r;
    for (i = 0; i < box.length; i += 2) {
      if (saltLen > 0) {
        L = (L ^ ldBE(salt, (i + saltOff) % n4)) >>> 0;
        R = (R ^ ldBE(salt, (i + saltOff + 1) % n4)) >>> 0;
      }
      r = G('blowfishEncipherWords')(L >>> 0, R >>> 0, P, S);
      L = r[0] >>> 0; R = r[1] >>> 0;
      box[i] = L; box[i + 1] = R;
    }
    return [L, R];
  }
  function bfKeyExpand(key, keyLen, salt, saltLen, P, S) {
    var i, j, r1;
    for (i = 0, j = 0; i < 18; i++ , j += 4) P[i] = (P[i] ^ ldBE(key, (j % keyLen) / 4 | 0)) >>> 0;
    var L = 0, R = 0;
    r1 = genSbox(P, L, R, P, S, salt, saltLen, 0); L = r1[0]; R = r1[1];
    genSbox(S, L, R, P, S, salt, saltLen, saltLen > 0 ? 18 % (saltLen / 4) : 0);
  }
  function bcryptRound(passHash, saltHash, out, tmp) {
    var f = bfFresh(), P = f[0], S = f[1], i, k, r, o, a, b;
    bfKeyExpand(passHash, passHash.length, saltHash, saltHash.length, P, S);
    for (i = 0; i < 64; i++) {           /* workfactor = 6 → 2^6 = 64 轮 */
      bfKeyExpand(saltHash, saltHash.length, null, 0, P, S);
      bfKeyExpand(passHash, passHash.length, null, 0, P, S);
    }
    tmp.set(BF_MAGIC);
    for (i = 0; i < 64; i++) {
      o = new Uint8Array(tmp.length);
      for (k = 0; k < tmp.length; k += 8) {
        a = ((tmp[k] << 24) | (tmp[k + 1] << 16) | (tmp[k + 2] << 8) | tmp[k + 3]) >>> 0;
        b = ((tmp[k + 4] << 24) | (tmp[k + 5] << 16) | (tmp[k + 6] << 8) | tmp[k + 7]) >>> 0;
        r = G('blowfishEncipherWords')(a, b, P, S);
        o[k] = (r[0] >>> 24) & 255; o[k + 1] = (r[0] >>> 16) & 255; o[k + 2] = (r[0] >>> 8) & 255; o[k + 3] = r[0] & 255;
        o[k + 4] = (r[1] >>> 24) & 255; o[k + 5] = (r[1] >>> 16) & 255; o[k + 6] = (r[1] >>> 8) & 255; o[k + 7] = r[1] & 255;
      }
      tmp.set(o);
    }
    for (i = 0; i < 8; i++) {            /* load_le → store_be */
      var w = ((tmp[i * 4]) | (tmp[i * 4 + 1] << 8) | (tmp[i * 4 + 2] << 16) | (tmp[i * 4 + 3] << 24)) >>> 0;
      tmp[i * 4] = (w >>> 24) & 255; tmp[i * 4 + 1] = (w >>> 16) & 255;
      tmp[i * 4 + 2] = (w >>> 8) & 255; tmp[i * 4 + 3] = w & 255;
    }
    for (i = 0; i < 32; i++) out[i] ^= tmp[i];
  }
  function bcryptPbkdf(passBytes, salt, rounds, outLen) {
    if (rounds < 1) throw new Error('迭代次数必须 ≥ 1');
    if (outLen < 1 || outLen > 1024) throw new Error('输出长度需在 1..1024 之间');
    var bs = 32, nb = Math.ceil(outLen / bs);
    var passHash = G('sha512Digest')(passBytes), saltHash = new Uint8Array(64);
    var res = new Uint8Array(outLen), block, r, i, o, tmp, sh, dest;
    for (block = 0; block < nb; block++) {
      o = new Uint8Array(bs); tmp = new Uint8Array(bs);
      sh = G('sha512Digest')(cat(salt, be32(block + 1)));
      saltHash.set(sh);
      bcryptRound(passHash, saltHash, o, tmp);
      for (r = 1; r < rounds; r++) {
        saltHash.set(G('sha512Digest')(tmp));
        bcryptRound(passHash, saltHash, o, tmp);
      }
      for (i = 0; i < bs; i++) { dest = i * nb + block; if (dest < outLen) res[dest] = o[i]; }
    }
    return res;
  }

  /* ============ 2. Base58Check ============ */
  function b58cEncode(payload) {
    var d1 = G('sha256Bytes')(payload), d2 = G('sha256Bytes')(d1);
    return G('bytesToBase58')(cat(payload, d2.subarray(0, 4)));
  }
  function b58cDecode(s) {
    var raw = G('base58ToBytes')(s), i;
    if (!raw || raw.length < 4) throw new Error('Base58Check 长度不足（至少 4 字节校验和）');
    var payload = raw.subarray(0, raw.length - 4), chk = raw.subarray(raw.length - 4);
    var d1 = G('sha256Bytes')(payload), d2 = G('sha256Bytes')(d1);
    for (i = 0; i < 4; i++) if (d2[i] !== chk[i]) throw new Error('Base58Check 校验和不匹配');
    return payload;
  }

  /* ============ 3. Comb4P ============ */
  function comb4p(h1, h2, data) {
    var pre = new Uint8Array(1), i;
    var A = h1(cat(pre, data)), B = h2(cat(pre, data));
    var n = A.length, a1 = new Uint8Array(n);
    for (i = 0; i < n; i++) a1[i] = A[i] ^ B[i]; A = a1;
    function round(outv, inv, rn, ha, hb) {
      var tag = new Uint8Array(1); tag[0] = rn;
      var t = new Uint8Array(outv.length), x, j;
      for (j = 0; j < t.length; j++) t[j] = outv[j];
      x = ha(cat(tag, inv)); for (j = 0; j < t.length && j < x.length; j++) t[j] ^= x[j];
      x = hb(cat(tag, inv)); for (j = 0; j < t.length && j < x.length; j++) t[j] ^= x[j];
      return t;
    }
    B = round(B, A, 1, h1, h2);
    A = round(A, B, 2, h1, h2);
    return cat(A, B);
  }

  /* ============ 4. RSA-KEM ============ */
  function hsh(name, b) {
    if (name === 'SHA-1') return G('OTP').sha1Bytes(b);
    if (name === 'SHA-256') return G('sha256Bytes')(b);
    if (name === 'SHA-512') return G('sha512Digest')(b);
    throw new Error('不支持的哈希：' + name);
  }
  function kdf(kind, hash, secret, outLen) {
    var o = new Uint8Array(outLen), off = 0, ctr = (kind === 'kdf2' ? 1 : 0), h, add;
    while (off < outLen && ctr !== 0xFFFFFFFF) {
      h = hsh(hash, cat(secret, be32(ctr++)));
      add = Math.min(h.length, outLen - off);
      o.set(h.subarray(0, add), off); off += add;
    }
    return o;
  }
  function modPow(b, e, m) { var r = 1n; b = b % m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e = e >> 1n; } return r; }
  function hexToBig(s) { s = String(s || '').replace(/\s/g, ''); if (!/^[0-9a-fA-F]+$/.test(s)) throw new Error('需要十六进制：' + s); return BigInt('0x' + s); }

  /* ============ 注册 ============ */
  ALGOS.push({
    id: 'bcrypt-pbkdf', name: 'bcrypt-pbkdf（OpenSSH 口令派生）', group: '单向哈希',
    key: true, param: true,
    keyLabel: '盐值 salt（Hex）', paramLabel: '轮数,输出字节数（如 12,32）',
    info: "OpenSSH 新格式私钥用的口令派生：以 SHA-512(pass) 为口令、SHA-512(salt‖BE32(块号)) 为盐，反复调用 bcrypt 风格 Blowfish 编排（workfactor=6、先盐后口令、64 轮加密）后异或累加。\n【验证】Botan bcrypt_pbkdf.vec 官方向量 36/36。\n【注意】比 PBKDF2 慢，轮数建议 ≥ 16。",
    enc: function (b, k, p, fmt) {
      var pass = inB(b);
      var salt = hexToB(k);
      var a = String(p || '12,32').split(',');
      var rounds = parseInt(a[0], 10), n = parseInt(a[1], 10);
      if (isNaN(rounds) || rounds < 1) rounds = 12;
      if (isNaN(n) || n < 1) n = 32;
      return out(bcryptPbkdf(pass, salt, rounds, n), fmt);
    }
  });

  ALGOS.push({
    id: 'base58check', name: 'Base58Check 编码（比特币地址）', group: '编码',
    param: false,
    info: '在 Base58 基础上追加 4 字节校验和（SHA-256d 的前 4 字节），用于比特币地址与 WIF 私钥。\n【验证】Botan base58c.vec 官方向量 4/4（含空输入 → 3QJmnh）。\n【说明】输入栏填文本时按 UTF-8 取字节；需要按原始字节编码请勾选 Hex 输入。',
    enc: function (b, k, p, fmt) {
      var payload;
      if (b instanceof Uint8Array || ArrayBuffer.isView(b)) {
        /* 框架已按输入框（含 Hex 勾选）解码成字节，直接用 */
        payload = new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
      } else {
        var s = String(b === undefined || b === null ? '' : b);
        var t = s.replace(/\s/g, '');
        /* 纯 hex 且长度为偶数 → 按字节；否则按 UTF-8 文本 */
        payload = (/^[0-9a-fA-F]+$/.test(t) && t.length >= 2 && t.length % 2 === 0) ? hexToB(t) : G('strToBytes')(s);
      }
      return b58cEncode(payload);
    },
    dec: function (b, k, p, fmt) {
      var s = String(b === undefined || b === null ? '' : b).trim();
      var payload = b58cDecode(s);
      return out(payload, fmt);
    }
  });

  ALGOS.push({
    id: 'comb4p-md4md5', name: 'Comb4P(MD4,MD5) 哈希组合器', group: '单向哈希',
    info: 'Mihir Bellare 的哈希组合器：两个哈希各自先 update(0) 再吸收消息，输出 h1^h2 后经两轮带轮号的再哈希，最终输出 h1‖h2（32 字节）。只要其中一个哈希是抗碰撞的，组合结果就抗碰撞。\n【验证】Botan hash/comp4p.vec 官方向量 2/2。\n【注意】MD4/MD5 均已不安全，此条目仅用于复现向量与研究组合器。',
    enc: function (b, k, p, fmt) {
      return out(comb4p(G('md4Digest'), G('md5Digest'), inB(b)), fmt);
    }
  });

  ALGOS.push({
    id: 'comb4p-sha1rmd160', name: 'Comb4P(SHA-1,RIPEMD-160) 哈希组合器', group: '单向哈希',
    info: '同上组合器，两个哈希换成 SHA-1 与 RIPEMD-160，输出 40 字节。\n【验证】Botan hash/comp4p.vec 官方向量 2/2。',
    enc: function (b, k, p, fmt) {
      if (!sha1) throw new Error('SHA-1 内核未加载');
      return out(comb4p(sha1, G('ripemd160Digest'), inB(b)), fmt);
    }
  });

  ALGOS.push({
    id: 'rsa-kem-encaps', name: 'RSA-KEM 封装（ISO 18033-2）', group: '非对称加密',
    key: true, param: true,
    keyLabel: '公钥 E,N（Hex，逗号分隔）', paramLabel: 'KDF,哈希,输出字节数（如 kdf1,SHA-1,128）',
    info: "RSA-KEM 封装：C0 = R^E mod N，共享密钥 K = KDF(R)。\n【关键】KDF 输入是明文 R 而非密文 C0。\n【验证】Botan pubkey/rsa_kem.vec 官方向量 10/10（KDF1-18033/KDF2 × SHA-1/256/512）。\n【输出】前 N 字节为 C0，其后为 K。",
    enc: function (b, k, p, fmt) {
      var a = String(k || '').split(','); if (a.length < 2) throw new Error('密钥栏需填 E,N（Hex，逗号分隔）');
      var E = hexToBig(a[0]), N = hexToBig(a[1]);
      var pa = String(p || 'kdf1,SHA-1,128').split(',');
      var kind = (pa[0] || 'kdf1').trim(), hash = (pa[1] || 'SHA-1').trim(), L = parseInt(pa[2], 10);
      if (isNaN(L) || L < 1) L = 128;
      var s = String(b === undefined || b === null ? '' : b).replace(/\s/g, '');
      var R = hexToBig(s);
      if (R >= N) throw new Error('R 必须小于 N');
      var c0 = modPow(R, E, N);
      var nb = Math.ceil(N.toString(16).length / 2); nb = nb % 2 ? nb + 1 : nb;
      var c0hex = c0.toString(16); while (c0hex.length < nb * 2) c0hex = '0' + c0hex;
      var rhexx = R.toString(16); while (rhexx.length < nb * 2) rhexx = '0' + rhexx;
      var K = kdf(kind, hash, hexToB(rhexx), L);
      return out(cat(hexToB(c0hex), K), fmt);
    }
  });

  ALGOS.push({
    id: 'rsa-kem-decaps', name: 'RSA-KEM 解封装（ISO 18033-2）', group: '非对称加密',
    key: true, param: true,
    keyLabel: '私钥 P,Q,E（Hex，逗号分隔）', paramLabel: 'KDF,哈希,输出字节数（如 kdf2,SHA-256,32）',
    info: "RSA-KEM 解封装：由 C0 还原 R = C0^D mod N，再算 K = KDF(R)。\n【验证】Botan pubkey/rsa_kem.vec 官方向量 10/10。\n【输出】前 N 字节为 R，其后为 K。",
    enc: function (b, k, p, fmt) {
      var a = String(k || '').split(','); if (a.length < 3) throw new Error('密钥栏需填 P,Q,E（Hex，逗号分隔）');
      var P = hexToBig(a[0]), Q = hexToBig(a[1]), E = hexToBig(a[2]);
      var N = P * Q, phi = (P - 1n) * (Q - 1n);
      var D = 1n, t = E, r0 = phi, t0 = 0n, r1 = t, t1 = 1n, q, tmp;
      while (r1 !== 0n) { q = r0 / r1; tmp = r0 - q * r1; r0 = r1; r1 = tmp; tmp = t0 - q * t1; t0 = t1; t1 = tmp; }
      D = ((t0 % phi) + phi) % phi;
      var pa = String(p || 'kdf1,SHA-1,128').split(',');
      var kind = (pa[0] || 'kdf1').trim(), hash = (pa[1] || 'SHA-1').trim(), L = parseInt(pa[2], 10);
      if (isNaN(L) || L < 1) L = 128;
      var c0b = hexToB(b);
      var R = modPow(BigInt('0x' + (function (x) { var h = ''; for (var i = 0; i < x.length; i++) { var c = x[i].toString(16); h += c.length < 2 ? '0' + c : c; } return h; })(c0b)), D, N);
      var nb = Math.ceil(N.toString(16).length / 2); nb = nb % 2 ? nb + 1 : nb;
      var rhexx = R.toString(16); while (rhexx.length < nb * 2) rhexx = '0' + rhexx;
      var K = kdf(kind, hash, hexToB(rhexx), L);
      return out(cat(hexToB(rhexx), K), fmt);
    }
  });

  if (typeof window !== 'undefined') window.BCRYPT_PBKDF = bcryptPbkdf;
})();
