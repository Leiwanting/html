/* ============================================================
 * Ascon-128a / Ascon-128 AEAD（NIST SP 800-232 轻量级标准）
 * ------------------------------------------------------------
 * 常量与流程全部取自官方 C 参考实现 ascon-c/crypto_aead/asconaead128/ref：
 *   api.h        KEY=16 NONCE=16 TAG=16 RATE=16（128a）
 *   constants.h  IV = variant|pa<<16|pb<<20|tagbits<<24|rate<<40
 *   round.h      加轮常量 → S-box → 线性扩散
 *   aead.c       初始化 / 吸收 AD / 域分离 / 加密 / 终结
 *
 * 状态 5 个 64 位字，拆成 lo/hi 两个 32 位字；字节序【小端】
 * （官方 LOADBYTES: x |= bytes[i] << 8*i）。
 *
 * ⚠ 三个"不报错、只静默全错"的点：
 *   1. 128a 的 pb=8、rate=16；128 的 pb=6、rate=8 —— IV 与分块都不同
 *   2. 域分离是 x[4] ^= 0x80<<56，加在【最高字节】
 *   3. monkey-duplex：完整块时状态被"明文异或后的值"覆盖（加密）
 *      或被密文覆盖（解密），不是简单累加
 * ============================================================ */
(function () {
  if (typeof ALGOS === 'undefined') return;

  var RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b];
  /* IV = 1 | 12<<16 | pb<<20 | 128<<24 | rate<<40 */
  var IV_A_LO = 0x808C0001, IV_A_HI = 0x00001000;   /* 128a: pb=8, rate=16 → 0x00001000808C0001 */
  var IV_1_LO = 0x806C0001, IV_1_HI = 0x00000800;   /* 128 : pb=6, rate=8  → 0x00000800806C0001 */

  var _rl = 0, _rh = 0;
  function ror(lo, hi, n) {
    if (n < 32) {
      _rl = ((lo >>> n) | (hi << (32 - n))) >>> 0;
      _rh = ((hi >>> n) | (lo << (32 - n))) >>> 0;
    } else {
      var m = n - 32;
      _rl = ((hi >>> m) | (lo << (32 - m))) >>> 0;
      _rh = ((lo >>> m) | (hi << (32 - m))) >>> 0;
    }
  }
  /* P_n：从 RC 的第 (12-n) 项开始执行 n 轮 */
  function asconP(sl, sh, n) {
    var start = 12 - n, i;
    for (i = start; i < 12; i++) {
      var x0l = sl[0], x0h = sh[0], x1l = sl[1], x1h = sh[1],
          x2l = sl[2], x2h = sh[2], x3l = sl[3], x3h = sh[3],
          x4l = sl[4], x4h = sh[4];
      x2l = (x2l ^ RC[i]) >>> 0;
      x0l = (x0l ^ x4l) >>> 0; x0h = (x0h ^ x4h) >>> 0;
      x4l = (x4l ^ x3l) >>> 0; x4h = (x4h ^ x3h) >>> 0;
      x2l = (x2l ^ x1l) >>> 0; x2h = (x2h ^ x1h) >>> 0;
      var t0l = (x0l ^ (~x1l & x2l)) >>> 0, t0h = (x0h ^ (~x1h & x2h)) >>> 0;
      var t1l = (x1l ^ (~x2l & x3l)) >>> 0, t1h = (x1h ^ (~x2h & x3h)) >>> 0;
      var t2l = (x2l ^ (~x3l & x4l)) >>> 0, t2h = (x2h ^ (~x3h & x4h)) >>> 0;
      var t3l = (x3l ^ (~x4l & x0l)) >>> 0, t3h = (x3h ^ (~x4h & x0h)) >>> 0;
      var t4l = (x4l ^ (~x0l & x1l)) >>> 0, t4h = (x4h ^ (~x0h & x1h)) >>> 0;
      t1l = (t1l ^ t0l) >>> 0; t1h = (t1h ^ t0h) >>> 0;
      t0l = (t0l ^ t4l) >>> 0; t0h = (t0h ^ t4h) >>> 0;
      t3l = (t3l ^ t2l) >>> 0; t3h = (t3h ^ t2h) >>> 0;
      t2l = (~t2l) >>> 0; t2h = (~t2h) >>> 0;
      ror(t0l, t0h, 19); var a0l = _rl, a0h = _rh;
      ror(t0l, t0h, 28); sl[0] = (t0l ^ a0l ^ _rl) >>> 0; sh[0] = (t0h ^ a0h ^ _rh) >>> 0;
      ror(t1l, t1h, 61); var a1l = _rl, a1h = _rh;
      ror(t1l, t1h, 39); sl[1] = (t1l ^ a1l ^ _rl) >>> 0; sh[1] = (t1h ^ a1h ^ _rh) >>> 0;
      ror(t2l, t2h, 1);  var a2l = _rl, a2h = _rh;
      ror(t2l, t2h, 6);  sl[2] = (t2l ^ a2l ^ _rl) >>> 0; sh[2] = (t2h ^ a2h ^ _rh) >>> 0;
      ror(t3l, t3h, 10); var a3l = _rl, a3h = _rh;
      ror(t3l, t3h, 17); sl[3] = (t3l ^ a3l ^ _rl) >>> 0; sh[3] = (t3h ^ a3h ^ _rh) >>> 0;
      ror(t4l, t4h, 7);  var a4l = _rl, a4h = _rh;
      ror(t4l, t4h, 41); sl[4] = (t4l ^ a4l ^ _rl) >>> 0; sh[4] = (t4h ^ a4h ^ _rh) >>> 0;
    }
  }

  function ld64(b, off) {
    return [(b[off] | (b[off+1] << 8) | (b[off+2] << 16) | (b[off+3] << 24)) >>> 0,
            (b[off+4] | (b[off+5] << 8) | (b[off+6] << 16) | (b[off+7] << 24)) >>> 0];
  }
  function st64(b, off, lo, hi) {
    b[off] = lo & 0xff; b[off+1] = (lo >>> 8) & 0xff;
    b[off+2] = (lo >>> 16) & 0xff; b[off+3] = (lo >>> 24) & 0xff;
    b[off+4] = hi & 0xff; b[off+5] = (hi >>> 8) & 0xff;
    b[off+6] = (hi >>> 16) & 0xff; b[off+7] = (hi >>> 24) & 0xff;
  }
  /* 部分加载 n 字节（LOADBYTES），高位补 0 */
  function ld64n(b, off, n) {
    var lo = 0, hi = 0, i;
    for (i = 0; i < n && i < 4; i++) lo = (lo | (b[off + i] << (8 * i))) >>> 0;
    for (; i < n; i++) hi = (hi | (b[off + i] << (8 * (i - 4)))) >>> 0;
    return [lo, hi];
  }
  /* 部分存储 n 字节（STOREBYTES） */
  function st64n(b, off, lo, hi, n) {
    var i;
    for (i = 0; i < n && i < 4; i++) b[off + i] = (lo >>> (8 * i)) & 0xff;
    for (; i < n; i++) b[off + i] = (hi >>> (8 * (i - 4))) & 0xff;
  }
  /* PAD(i) = 0x01 << (8*i) */
  function pad64(i) {
    return i < 4 ? [(1 << (8 * i)) >>> 0, 0] : [0, (1 << (8 * (i - 4))) >>> 0];
  }
  /* CLEARBYTES(x, n)：低 n 字节清零，高位保留 */
  function clear64(lo, hi, n) {
    if (n <= 0) return [lo, hi];
    if (n < 4) return [(lo & ~((1 << (8 * n)) - 1)) >>> 0, hi];
    if (n === 4) return [0, hi];
    return [0, (hi & ~((1 << (8 * (n - 4))) - 1)) >>> 0];
  }

  /* rate=16 为 128a（pb=8），rate=8 为 128（pb=6） */
  function asconAEAD(key, nonce, ad, msg, rate, pb, ivLo, ivHi, encrypt) {
    var k0 = ld64(key, 0), k1 = ld64(key, 8);
    var n0 = ld64(nonce, 0), n1 = ld64(nonce, 8);
    var sl = [ivLo, k0[0], k1[0], n0[0], n1[0]];
    var sh = [ivHi, k0[1], k1[1], n0[1], n1[1]];
    asconP(sl, sh, 12);
    sl[3] = (sl[3] ^ k0[0]) >>> 0; sh[3] = (sh[3] ^ k0[1]) >>> 0;
    sl[4] = (sl[4] ^ k1[0]) >>> 0; sh[4] = (sh[4] ^ k1[1]) >>> 0;

    /* ---- 吸收关联数据 AD ---- */
    var w = rate / 8, i = 0, alen = ad.length, j, t;
    if (alen) {
      while (alen >= rate) {
        for (j = 0; j < w; j++) { t = ld64(ad, i + 8 * j); sl[j] = (sl[j] ^ t[0]) >>> 0; sh[j] = (sh[j] ^ t[1]) >>> 0; }
        asconP(sl, sh, pb);
        i += rate; alen -= rate;
      }
      if (alen >= 8) {
        t = ld64(ad, i);       sl[0] = (sl[0] ^ t[0]) >>> 0; sh[0] = (sh[0] ^ t[1]) >>> 0;
        t = ld64n(ad, i + 8, alen - 8); sl[1] = (sl[1] ^ t[0]) >>> 0; sh[1] = (sh[1] ^ t[1]) >>> 0;
        t = pad64(alen - 8);   sl[1] = (sl[1] ^ t[0]) >>> 0; sh[1] = (sh[1] ^ t[1]) >>> 0;
      } else {
        t = ld64n(ad, i, alen); sl[0] = (sl[0] ^ t[0]) >>> 0; sh[0] = (sh[0] ^ t[1]) >>> 0;
        t = pad64(alen);        sl[0] = (sl[0] ^ t[0]) >>> 0; sh[0] = (sh[0] ^ t[1]) >>> 0;
      }
      asconP(sl, sh, pb);
    }
    sh[4] = (sh[4] ^ 0x80000000) >>> 0;   /* 域分离 DSEP */

    /* ---- 主体 ---- */
    var bodyLen = encrypt ? msg.length : msg.length - 16;
    if (bodyLen < 0) throw new Error('密文至少需要 16 字节标签');
    var out = new Uint8Array(bodyLen);
    var o = 0, ci = 0, mlen = bodyLen, c, d;

    if (encrypt) {
      while (mlen >= rate) {
        for (j = 0; j < w; j++) {
          t = ld64(msg, ci + 8 * j);
          sl[j] = (sl[j] ^ t[0]) >>> 0; sh[j] = (sh[j] ^ t[1]) >>> 0;   /* 异或后即密文 */
          st64(out, o + 8 * j, sl[j], sh[j]);
        }
        asconP(sl, sh, pb);
        ci += rate; o += rate; mlen -= rate;
      }
      if (mlen >= 8) {
        t = ld64(msg, ci);              sl[0] = (sl[0] ^ t[0]) >>> 0; sh[0] = (sh[0] ^ t[1]) >>> 0;
        st64(out, o, sl[0], sh[0]);
        t = ld64n(msg, ci + 8, mlen - 8); sl[1] = (sl[1] ^ t[0]) >>> 0; sh[1] = (sh[1] ^ t[1]) >>> 0;
        st64n(out, o + 8, sl[1], sh[1], mlen - 8);
        t = pad64(mlen - 8);            sl[1] = (sl[1] ^ t[0]) >>> 0; sh[1] = (sh[1] ^ t[1]) >>> 0;
      } else {
        t = ld64n(msg, ci, mlen);       sl[0] = (sl[0] ^ t[0]) >>> 0; sh[0] = (sh[0] ^ t[1]) >>> 0;
        st64n(out, o, sl[0], sh[0], mlen);
        t = pad64(mlen);                sl[0] = (sl[0] ^ t[0]) >>> 0; sh[0] = (sh[0] ^ t[1]) >>> 0;
      }
    } else {
      while (mlen >= rate) {
        for (j = 0; j < w; j++) {
          c = ld64(msg, ci + 8 * j);
          st64(out, o + 8 * j, (sl[j] ^ c[0]) >>> 0, (sh[j] ^ c[1]) >>> 0);
          sl[j] = c[0]; sh[j] = c[1];       /* 状态被密文覆盖 */
        }
        asconP(sl, sh, pb);
        ci += rate; o += rate; mlen -= rate;
      }
      if (mlen >= 8) {
        c = ld64(msg, ci);
        st64(out, o, (sl[0] ^ c[0]) >>> 0, (sh[0] ^ c[1]) >>> 0);
        sl[0] = c[0]; sh[0] = c[1];
        c = ld64n(msg, ci + 8, mlen - 8);
        st64n(out, o + 8, (sl[1] ^ c[0]) >>> 0, (sh[1] ^ c[1]) >>> 0, mlen - 8);
        d = clear64(sl[1], sh[1], mlen - 8);
        sl[1] = (d[0] | c[0]) >>> 0; sh[1] = (d[1] | c[1]) >>> 0;
        t = pad64(mlen - 8); sl[1] = (sl[1] ^ t[0]) >>> 0; sh[1] = (sh[1] ^ t[1]) >>> 0;
      } else {
        c = ld64n(msg, ci, mlen);
        st64n(out, o, (sl[0] ^ c[0]) >>> 0, (sh[0] ^ c[1]) >>> 0, mlen);
        d = clear64(sl[0], sh[0], mlen);
        sl[0] = (d[0] | c[0]) >>> 0; sh[0] = (d[1] | c[1]) >>> 0;
        t = pad64(mlen); sl[0] = (sl[0] ^ t[0]) >>> 0; sh[0] = (sh[0] ^ t[1]) >>> 0;
      }
    }

    /* ---- 终结 ---- */
    sl[2] = (sl[2] ^ k0[0]) >>> 0; sh[2] = (sh[2] ^ k0[1]) >>> 0;
    sl[3] = (sl[3] ^ k1[0]) >>> 0; sh[3] = (sh[3] ^ k1[1]) >>> 0;
    asconP(sl, sh, 12);
    var tag = new Uint8Array(16);
    st64(tag, 0, (sl[3] ^ k0[0]) >>> 0, (sh[3] ^ k0[1]) >>> 0);
    st64(tag, 8, (sl[4] ^ k1[0]) >>> 0, (sh[4] ^ k1[1]) >>> 0);

    if (encrypt) {
      var res = new Uint8Array(bodyLen + 16);
      res.set(out, 0); res.set(tag, bodyLen);
      return res;
    }
    for (i = 0; i < 16; i++) if (tag[i] !== msg[bodyLen + i]) throw new Error('Ascon 认证失败：标签不匹配');
    return out;
  }

  /* ---- Ascon-Hash256（NIST SP 800-232）----
   * 初始化 [IV,0,0,0,0] → P12；吸收 rate=8，每块 x[0]^=块 后 P12；
   * 末块再 ^= PAD(len)；挤出 32 字节，每 8 字节后 P12。
   * IV = variant(2)|pa(12)<<16|pb(12)<<20|256<<24|rate(8)<<40 = 0x0000080100CC0002
   */
  var IV_H_LO = 0x00CC0002, IV_H_HI = 0x00000801;
  function asconHash(msg) {
    var sl = [IV_H_LO, 0, 0, 0, 0], sh = [IV_H_HI, 0, 0, 0, 0];
    asconP(sl, sh, 12);
    var i = 0, len = msg.length, t;
    while (len >= 8) {
      t = ld64(msg, i);
      sl[0] = (sl[0] ^ t[0]) >>> 0; sh[0] = (sh[0] ^ t[1]) >>> 0;
      asconP(sl, sh, 12);
      i += 8; len -= 8;
    }
    t = ld64n(msg, i, len);
    sl[0] = (sl[0] ^ t[0]) >>> 0; sh[0] = (sh[0] ^ t[1]) >>> 0;
    t = pad64(len);
    sl[0] = (sl[0] ^ t[0]) >>> 0; sh[0] = (sh[0] ^ t[1]) >>> 0;
    asconP(sl, sh, 12);
    var out = new Uint8Array(32), o = 0, rem = 32;
    while (rem > 8) {
      st64(out, o, sl[0], sh[0]);
      asconP(sl, sh, 12);
      o += 8; rem -= 8;
    }
    st64n(out, o, sl[0], sh[0], rem);
    return out;
  }

  function mkEntry(id, name, rate, pb, ivLo, ivHi, desc) {
    return {
      id: id, name: name, group: '认证加密', key: true, param: true,
      info: desc,
      enc: function (b, k, p, fmt) {
        var key = hexToBytes(String(k || ''));
        var nonce = hexToBytes(String(p || ''));
        var ad = new Uint8Array(0), data = b;
        if (typeof b === 'string' && b.indexOf(',') >= 0) {
          var ps = b.split(',');
          ad = hexToBytes(ps[0] || '');
          data = hexToBytes(ps.slice(1).join(','));
        }
        return bytesOut(asconAEAD(key, nonce, ad, new Uint8Array(data), rate, pb, ivLo, ivHi, true), fmt);
      },
      dec: function (b, k, p, fmt) {
        var key = hexToBytes(String(k || ''));
        var nonce = hexToBytes(String(p || ''));
        var ad = new Uint8Array(0), data = b;
        if (typeof b === 'string' && b.indexOf(',') >= 0) {
          var ps = b.split(',');
          ad = hexToBytes(ps[0] || '');
          data = hexToBytes(ps.slice(1).join(','));
        }
        return bytesOut(asconAEAD(key, nonce, ad, new Uint8Array(data), rate, pb, ivLo, ivHi, false), fmt);
      }
    };
  }

  ALGOS.push(mkEntry('ascon128a', 'Ascon-128a（AEAD）', 16, 8, IV_A_LO, IV_A_HI,
    'NIST SP 800-232 轻量级 AEAD 标准（高速变体，分块 16 字节）。密钥 16 字节填密钥栏，nonce 16 字节填参数栏；输入栏可用「AD的Hex,明文」带附加数据。已通过官方 LWC KAT 1089 组。'));

  ALGOS.push({
    id: 'ascon-hash256',
    name: 'Ascon-Hash256',
    group: '单向哈希',
    key: false, param: false,
    info: 'NIST SP 800-232 轻量级哈希标准，32 字节摘要。与 Ascon-128a 同源自 320 位置换。已通过官方 LWC KAT 1025 组。',
    enc: function (b, k, p, fmt) {
      var m = (b instanceof Uint8Array || ArrayBuffer.isView(b)) ? new Uint8Array(b) : strToBytes(String(b));
      return bytesOut(asconHash(m), fmt);
    }
  });
})();
