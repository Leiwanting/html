/* ============================================================
 * 宽块加密模式：EME2-AES / XCB-AES（IEEE 1619.2）+ CBC-ESSIV
 * 参考实现 xurz97/TES（C, AES-NI）；EME2 另有 IEEE 1619 工作组向量思路可循。
 * 注意：EME2 的 crank 是 XTS 方向（左移 + 0x87 回绕），
 *       XCB 的 multx 是反射方向（左移 + 0xc2..01），两者不可混用。
 * ============================================================ */
(function () {
  var M64 = (1n << 64n) - 1n, M128 = (1n << 128n) - 1n;
  var POLY = 0xc2n << 56n, MULTX_MASK = (0xc2n << 120n) | 1n;

  function clmul64(a, b) {
    var r = 0n; a &= M64; b &= M64;
    while (b) { var t = b & -b, i = 0, s = t; while (s > 1n) { s >>= 1n; i++; } r ^= a << BigInt(i); b ^= t; }
    return r & M128;
  }
  function gfmul(A, B) {
    A &= M128; B &= M128;
    var alo = A & M64, ahi = A >> 64n, blo = B & M64, bhi = B >> 64n;
    var t1 = clmul64(alo, blo), t2 = clmul64(ahi, bhi), t3 = clmul64(alo, bhi) ^ clmul64(ahi, blo);
    var t4 = (t3 << 64n) & M128; t3 >>= 64n;
    t1 = (t1 ^ t4) & M128; t4 = (t3 ^ t2) & M128;
    var r2 = clmul64(t1 & M64, POLY), r3 = ((t1 << 64n) | (t1 >> 64n)) & M128;
    t1 = (r2 ^ r3) & M128;
    r2 = clmul64(t1 & M64, POLY); r3 = ((t1 << 64n) | (t1 >> 64n)) & M128;
    t1 = (r2 ^ r3) & M128;
    return (t1 ^ t4) & M128;
  }
  function multx(a) { a &= M128; return ((a << 1n) & M128) ^ (((a >> 127n) & 1n) ? MULTX_MASK : 0n); }
  function crank(v) { v &= M128; return ((v << 1n) & M128) ^ (((v >> 127n) & 1n) ? 0x87n : 0n); }
  function b2i(b, o) { var v = 0n; for (var i = 15; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]); return v; }
  function i2b(v, o, off) { for (var i = 0; i < 16; i++) { o[off + i] = Number(v & 0xffn); v >>= 8n; } }
  function bswap(v) { var r = 0n; for (var i = 0; i < 16; i++) { r = (r << 8n) | (v & 0xffn); v >>= 8n; } return r; }
  /* 每个 64 位半字内部反转字节，半字不互换 */
  function bswapEpi64(v) {
    var b = new Uint8Array(16), o = new Uint8Array(16); i2b(v, b, 0);
    for (var i = 0; i < 8; i++) { o[i] = b[7 - i]; o[8 + i] = b[15 - i]; }
    return b2i(o, 0);
  }
  /* SHA-256（复用主逻辑的 sha256Core，避免自己再造轮子） */
  function sha256Bytes(msg) {
    var w = sha256Core(msg, SHA256_IV, 8), out = new Uint8Array(32);
    for (var i = 0; i < 8; i++) {
      out[i * 4] = (w[i] >>> 24) & 0xff; out[i * 4 + 1] = (w[i] >>> 16) & 0xff;
      out[i * 4 + 2] = (w[i] >>> 8) & 0xff; out[i * 4 + 3] = w[i] & 0xff;
    }
    return out;
  }
  function blk(i) { var t = new Uint8Array(16); i2b(i, t, 0); return t; }
  function blkOf(b, i) { return b2i(b, i * 16); }

  /* ---------- XCB-AES ---------- */
  function xcbSetup(mk, key) {
    var a = mk(key), z = new Uint8Array(16);
    var H0 = bswap(b2i(a.enc(z), 0));
    z[15] = 1; var Ke = mk(a.enc(z));
    z[15] = 3; var Kd = mk(a.enc(z));
    z[15] = 5; var Kc = mk(a.enc(z));
    return { H0: H0, Ke: Ke, Kd: Kd, Kc: Kc };
  }
  function xcbCrypt(mk, pt, ad, key, encrypt) {
    if (key.length !== 16) throw new Error('XCB-AES-128 密钥需 16 字节');
    if (pt.length % 16 || pt.length < 32) throw new Error('明文需为 16 的倍数且至少 32 字节');
    var S = xcbSetup(mk, key), H = multx(S.H0), n = pt.length / 16, m = ad.length / 16, i;
    var out = new Uint8Array(pt.length), tmp = new Uint8Array(16);
    if (encrypt) {
      var C = b2i(S.Ke.enc(pt.subarray((n - 1) * 16, n * 16)), 0);
      var D = 0n;
      for (i = 0; i < m; i++) { D ^= bswap(blkOf(ad, i)); D = gfmul(D, H); }
      for (i = 0; i < n - 1; i++) { D ^= bswap(blkOf(pt, i)); D = gfmul(D, H); }
      D = gfmul(D, H);
      D ^= (BigInt(ad.length * 8 + 128) << 64n) | BigInt(pt.length * 8);
      D = gfmul(D, H);
      D = bswap(D) ^ C;
      var ctr = bswapEpi64(D), F = 0n;
      for (i = 0; i < m; i++) { F ^= bswap(blkOf(ad, i)); F = gfmul(F, H); }
      F = gfmul(F, H);
      for (i = 0; i < n - 1; i++) {
        i2b(bswapEpi64(ctr), tmp, 0);
        var lo = ctr & M64, hi = ctr >> 64n;
        ctr = (((hi + 1n) & M64) << 64n) | lo;   /* ONE = 1<<64，加在高半字 */
        var cb = blkOf(pt, i) ^ b2i(S.Kc.enc(tmp), 0);
        i2b(cb, out, i * 16);
        F ^= bswap(cb); F = gfmul(F, H);
      }
      F ^= (BigInt(ad.length * 8 + 128) << 64n) | BigInt(pt.length * 8 - 128);
      F = gfmul(F, H);
      F ^= (BigInt(ad.length * 8 + 128) << 64n) | BigInt(pt.length * 8);
      F = gfmul(F, H);
      i2b(bswap(F) ^ D, tmp, 0);
      var last = S.Kd.dec(tmp);
      for (i = 0; i < 16; i++) out[(n - 1) * 16 + i] = last[i];
    } else {
      var Flast = b2i(S.Kd.enc(pt.subarray((n - 1) * 16, n * 16)), 0);
      var F = 0n;
      for (i = 0; i < m; i++) { F ^= bswap(blkOf(ad, i)); F = gfmul(F, H); }
      F = gfmul(F, H);
      for (i = 0; i < n - 1; i++) { F ^= bswap(blkOf(pt, i)); F = gfmul(F, H); }
      F ^= (BigInt(ad.length * 8 + 128) << 64n) | BigInt(pt.length * 8 - 128);
      F = gfmul(F, H);
      F ^= (BigInt(ad.length * 8 + 128) << 64n) | BigInt(pt.length * 8);
      F = gfmul(F, H);
      var D = bswap(F) ^ Flast, ctr = bswapEpi64(D);
      for (i = 0; i < n - 1; i++) {
        i2b(bswapEpi64(ctr), tmp, 0);
        var lo2 = ctr & M64, hi2 = ctr >> 64n;
        ctr = (((hi2 + 1n) & M64) << 64n) | lo2;
        i2b(blkOf(pt, i) ^ b2i(S.Kc.enc(tmp), 0), out, i * 16);
      }
      var Dh = 0n;
      for (i = 0; i < m; i++) { Dh ^= bswap(blkOf(ad, i)); Dh = gfmul(Dh, H); }
      for (i = 0; i < n - 1; i++) { Dh ^= bswap(blkOf(out, i)); Dh = gfmul(Dh, H); }
      Dh = gfmul(Dh, H);
      Dh ^= (BigInt(ad.length * 8 + 128) << 64n) | BigInt(pt.length * 8);
      Dh = gfmul(Dh, H);
      i2b(bswap(Dh) ^ D, tmp, 0);
      var lp = S.Ke.dec(tmp);
      for (i = 0; i < 16; i++) out[(n - 1) * 16 + i] = lp[i];
    }
    return out;
  }

  /* ---------- EME2-AES ---------- */
  function eme2Setup(mk, key) {
    if (key.length !== 48) throw new Error('EME2-AES-128 密钥需 48 字节（Kad‖Kecb‖Kaes）');
    return { Kad: b2i(key, 0), Kecb: b2i(key, 16), aes: mk(key.subarray(32, 48)) };
  }
  function eme2Tstar(S, ad) {
    var T = 0n, Kad = S.Kad, tmp = new Uint8Array(16);
    if (ad.length === 0) { i2b(Kad, tmp, 0); return b2i(S.aes.enc(tmp), 0); }
    for (var i = 0; i < ad.length / 16; i++) {
      Kad = crank(Kad);
      i2b(Kad ^ blkOf(ad, i), tmp, 0);
      T ^= b2i(S.aes.enc(tmp), 0) ^ Kad;
    }
    return T;
  }
  function eme2Crypt(mk, d, ad, key, encrypt) {
    var S = eme2Setup(mk, key), aes = S.aes, n = d.length / 16, i, tmp = new Uint8Array(16);
    if (n < 1 || d.length % 16) throw new Error('长度必须是 16 的倍数');
    var T = eme2Tstar(S, ad), out = new Uint8Array(d.length), PPP = new Array(n), CCC = new Array(n), L;
    if (encrypt) {
      L = S.Kecb;
      for (i = 0; i < n; i++) { i2b(L ^ blkOf(d, i), tmp, 0); PPP[i] = b2i(aes.enc(tmp), 0); L = crank(L); }
      var MP = T; for (i = 0; i < n; i++) MP ^= PPP[i];
      i2b(MP, tmp, 0);
      var MC = b2i(aes.enc(tmp), 0), MC1 = MC, M = MP ^ MC, M1 = M;
      for (i = 1; i < n; i++) {
        if (i % 128) { M = crank(M); CCC[i] = PPP[i] ^ M; }
        else {
          var MPe = PPP[i] ^ M1; i2b(MPe, tmp, 0);
          MC = b2i(aes.enc(tmp), 0); M = MPe ^ MC; CCC[i] = MC ^ M1;
        }
      }
      CCC[0] = MC1 ^ T; for (i = 1; i < n; i++) CCC[0] ^= CCC[i];
      L = S.Kecb;
      for (i = 0; i < n; i++) { i2b(CCC[i], tmp, 0); i2b(b2i(aes.enc(tmp), 0) ^ L, out, i * 16); L = crank(L); }
    } else {
      L = S.Kecb;
      for (i = 0; i < n; i++) { i2b(blkOf(d, i) ^ L, tmp, 0); CCC[i] = b2i(aes.dec(tmp), 0); L = crank(L); }
      var x = CCC[0] ^ T; for (i = 1; i < n; i++) x ^= CCC[i];
      i2b(x, tmp, 0);
      var MPd = b2i(aes.dec(tmp), 0), Md = MPd ^ x, M1d = Md;
      for (i = 1; i < n; i++) {
        if (i % 128) { Md = crank(Md); PPP[i] = CCC[i] ^ Md; }
        else {
          /* 必须用独立变量 MCi/MPi，不能复用 MPd —— 后面 PPP[0] 还要用原始 MPd */
          var MCi = CCC[i] ^ M1d; i2b(MCi, tmp, 0);
          var MPi = b2i(aes.dec(tmp), 0);
          Md = MPi ^ MCi; PPP[i] = MPi ^ M1d;
        }
      }
      PPP[0] = MPd ^ T; for (i = 1; i < n; i++) PPP[0] ^= PPP[i];
      L = S.Kecb;
      for (i = 0; i < n; i++) { i2b(PPP[i], tmp, 0); i2b(b2i(aes.dec(tmp), 0) ^ L, out, i * 16); L = crank(L); }
    }
    return out;
  }

  /* ---------- CBC-ESSIV（dm-crypt / LUKS 语义，无官方向量） ---------- */
  function essivCrypt(mk, d, key, lba, encrypt) {
    if (key.length !== 16 && key.length !== 24 && key.length !== 32) throw new Error('密钥需 16/24/32 字节');
    if (d.length === 0 || d.length % 16) throw new Error('数据需为 16 字节的倍数且非空');
    var salt = sha256Bytes(key);
    var skey = salt.subarray(0, key.length);
    var iv = new Uint8Array(16);
    for (var i = 0; i < 8; i++) iv[i] = Number((BigInt(lba) >> BigInt(8 * i)) & 0xffn);
    var a = mk(skey), out = new Uint8Array(d.length), tmp = new Uint8Array(16), prev;
    var civ = encrypt ? a.enc(iv) : a.enc(iv);          /* ESSIV: IV = AES(salt, lba_le64) */
    if (!encrypt) { /* 解密首块 IV 与加密相同 */ }
    prev = civ;
    for (var b = 0; b < d.length / 16; b++) {
      if (encrypt) {
        for (i = 0; i < 16; i++) tmp[i] = d[b * 16 + i] ^ prev[i];
        var e = a.enc(tmp);
        for (i = 0; i < 16; i++) out[b * 16 + i] = e[i];
        prev = e;
      } else {
        var cur = d.subarray(b * 16, b * 16 + 16);
        var dd = a.dec(cur);
        for (i = 0; i < 16; i++) out[b * 16 + i] = dd[i] ^ prev[i];
        prev = cur;
      }
    }
    return out;
  }

  /* ---------- 注册 ---------- */
  function parseAd(p) {
    if (p === undefined || p === null || String(p).trim() === '') return new Uint8Array(0);
    return hexToBytes(String(p).trim());
  }
  function entry(alg) {
    return function (b, k, p, fmt) {
      var key = hexToBytes(String(k || '').trim());
      var ad = parseAd(p);
      var r = alg(b, key, ad);
      return bytesOut(r, fmt);
    };
  }
  reg({ id: 'eme2', name: 'EME2-AES-128 宽块加密', group: '对称加密', key: true, keyLen: 48,
    keyLabel: '密钥（Hex，48 字节 = Kad‖Kecb‖Kaes）',
    paramLabel: '关联数据 AD（Hex，16 的倍数；留空=无 AD）', param: true, paramOptional: true,
    info: 'EME2：IEEE 1619.2 宽块加密，改 1 比特整个消息全变。磁盘扇区加密用，AD 通常填 LBA。密钥 48 字节，长度保持（密文=明文长度）。',
    enc: entry(function (b, k, ad) { return eme2Crypt(aesMakeBlockFn, b, ad, k, true); }),
    dec: entry(function (b, k, ad) { return eme2Crypt(aesMakeBlockFn, b, ad, k, false); }) });

  reg({ id: 'xcb', name: 'XCB-AES-128 宽块加密', group: '对称加密', key: true, keyLen: 16,
    keyLabel: '密钥（Hex，16 字节）',
    paramLabel: '关联数据 AD（Hex，16 的倍数；留空=无 AD）', param: true, paramOptional: true,
    info: 'XCB：IEEE 1619.2 宽块加密（Feistel＋泛哈希＋CTR），密钥 16 字节，长度保持，明文需 16 的倍数且≥32 字节，参数填关联数据 AD。⚠ 有公开密码学批评（FSE 2013《XCB is not sound》：解密非加密逆、安全证明有误），仅作研究，勿用于生产。',
    enc: entry(function (b, k, ad) { return xcbCrypt(aesMakeBlockFn, b, ad, k, true); }),
    dec: entry(function (b, k, ad) { return xcbCrypt(aesMakeBlockFn, b, ad, k, false); }) });

  reg({ id: 'cbc-essiv', name: 'CBC-ESSIV（磁盘扇区）', group: '对称加密', key: true, keyLen: 16,
    keyLabel: '密钥（Hex，16/24/32 字节）',
    paramLabel: '扇区号 LBA（十进制；留空=0）', param: true, paramOptional: true,
    info: 'CBC-ESSIV：dm-crypt/LUKS 磁盘加密的 IV 方案，IV = AES(SHA256(密钥), LBA小端)，防同一明文在不同扇区产生相同密文的水印攻击。⚠ 无官方向量，仅按语义实现。',
    enc: function (b, k, p, fmt) {
      var key = hexToBytes(String(k || '').trim());
      var lba = (p === undefined || String(p).trim() === '') ? 0 : parseInt(String(p).trim(), 10);
      if (!isFinite(lba) || lba < 0) throw new Error('LBA 需为非负整数');
      return bytesOut(essivCrypt(aesMakeBlockFn, b, key, lba, true), fmt);
    },
    dec: function (b, k, p, fmt) {
      var key = hexToBytes(String(k || '').trim());
      var lba = (p === undefined || String(p).trim() === '') ? 0 : parseInt(String(p).trim(), 10);
      if (!isFinite(lba) || lba < 0) throw new Error('LBA 需为非负整数');
      return bytesOut(essivCrypt(aesMakeBlockFn, b, key, lba, false), fmt);
    } });
})();
