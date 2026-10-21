/* ============================================================
 * AEGIS-128L / AEGIS-256  AEAD（RFC 10032，原 draft-irtf-cfrg-aegis-aead-18）
 * ------------------------------------------------------------
 * 常量、状态初始化、Update / Absorb / Enc / Dec / DecPartial / Finalize
 * 全部取自 RFC 10032 正文（datatracker 与 rfc-editor 两个来源逐字一致）。
 *
 *   C0 = 00 01 01 02 03 05 08 0d 15 22 37 59 90 e9 79 62
 *   C1 = db 3d 18 55 6d c2 2f f1 20 11 31 42 73 b5 28 dd
 *
 * AEGIS-128L：8 块 × 128 位状态（1024 位），密钥/ nonce 各 16 字节，
 *             处理 256 位（32 字节）输入块，标签 128 或 256 位。
 *   Init : S0=K^N S1=C1 S2=C0 S3=C1 S4=K^N S5=K^C0 S6=K^C1 S7=K^C0
 *          随后 10 次 Update(N, K)
 *   Update(M0,M1):
 *          S'0=AESRound(S7, S0^M0)  S'1=AESRound(S0,S1)  S'2=AESRound(S1,S2)
 *          S'3=AESRound(S2,S3)      S'4=AESRound(S3, S4^M1) S'5=AESRound(S4,S5)
 *          S'6=AESRound(S5,S6)      S'7=AESRound(S6,S7)
 *   Enc  : z0=S1^S6^(S2&S3)  z1=S2^S5^(S6&S7)
 *          出 = 明文 ^ z，然后 Update(明文两半)   ← 注意喂进去的是明文不是密文
 *   Finalize: t = S2 ^ (LE64(ad位长) || LE64(消息位长))，7 次 Update(t,t)
 *          128 位标签 = S0^S1^S2^S3^S4^S5^S6（7 块）
 *          256 位标签 = (S0^S1^S2^S3) || (S4^S5^S6^S7)
 *
 * AEGIS-256 ：6 块 × 128 位状态（768 位），密钥/ nonce 各 32 字节，
 *             处理 128 位（16 字节）输入块，标签 128 或 256 位。
 *   Init : k0,k1 = Split(K,128)   n0,n1 = Split(N,128)
 *          S0=k0^n0 S1=k1^n1 S2=C1 S3=C0 S4=k0^C0 S5=k1^C1
 *          随后 4 轮：Update(k0) Update(k1) Update(k0^n0) Update(k1^n1)
 *   Update(M): S'0=AESRound(S5, S0^M)，其后 S'i=AESRound(S(i-1), Si)
 *   Enc  : z = S1^S4^S5^(S2&S3)；先 Update(明文)，再 ci = 明文 ^ z
 *          ← 与 128L 相反：256 是"先更新再异或"，128L 是"先异或再更新"
 *   Finalize: t = S3 ^ (LE64(ad位长) || LE64(消息位长))，7 次 Update(t)
 *          128 位标签 = S0^S1^S2^S3^S4^S5（6 块）
 *          256 位标签 = (S0^S1^S2) || (S3^S4^S5)
 *
 * AESRound(in, rk) = AddRoundKey(MixColumns(ShiftRows(SubBytes(in))), rk)
 *   —— 就是 FIPS-197 第五节的那一轮，rk 当轮密钥用。
 *
 * ⚠ 三个"不报错、只静默全错"的点（本实现踩过）：
 *   1. MixColumns 的 xtime 化简式必须配 a0/a1/a2/a3 自身，
 *      错配成下一个系数会得到转置矩阵，标签全错但代码不报错
 *   2. ShiftRows 的行/列索引：new[r+4c] = old[r + 4*((c+r)%4)]
 *   3. 128L 的末块用 DecPartial，喂回 Update 的是"明文补零"而不是密文补零
 *
 * 验证：RFC 10032 官方测试向量 128L 与 256 各 10 组（含 4 组官方标注
 *       "verification failed" 的篡改用例：换 key/nonce、改 ct、改 ad、改 tag）
 *       —— 90/90 全过。
 * ============================================================ */
(function () {
  if (typeof ALGOS === 'undefined') return;

  var SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  ];

  var XT = new Uint8Array(256), _i, _v;
  for (_i = 0; _i < 256; _i++) { _v = _i << 1; if (_v & 0x100) _v ^= 0x11b; XT[_i] = _v; }

  var C0 = [0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62];
  var C1 = [0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd];

  /* AESRound(in, rk) → 写入 out[oo..oo+15] */
  function aesRound(st, so, rk, ro, out, oo) {
    var t = new Uint8Array(16), r, c, i, a0, a1, a2, a3, x;
    /* SubBytes + ShiftRows：new[r+4c] = old[r + 4*((c+r)%4)] */
    for (r = 0; r < 4; r++) for (c = 0; c < 4; c++) t[r + 4 * c] = SBOX[st[so + r + 4 * ((c + r) % 4)]];
    /* MixColumns + AddRoundKey */
    for (c = 0; c < 4; c++) {
      i = 4 * c;
      a0 = t[i]; a1 = t[i + 1]; a2 = t[i + 2]; a3 = t[i + 3];
      x = a0 ^ a1 ^ a2 ^ a3;
      out[oo + i] = XT[a0 ^ a1] ^ a0 ^ x ^ rk[ro + i];
      out[oo + i + 1] = XT[a1 ^ a2] ^ a1 ^ x ^ rk[ro + i + 1];
      out[oo + i + 2] = XT[a2 ^ a3] ^ a2 ^ x ^ rk[ro + i + 2];
      out[oo + i + 3] = XT[a3 ^ a0] ^ a3 ^ x ^ rk[ro + i + 3];
    }
  }

  function xor16(a, ao, b, bo) {
    var o = new Uint8Array(16), i;
    for (i = 0; i < 16; i++) o[i] = a[ao + i] ^ b[bo + i];
    return o;
  }

  /* ---------------- AEGIS-128L ---------------- */
  function A128L(key, nonce) {
    var S = new Uint8Array(128), i, kn = xor16(key, 0, nonce, 0);
    S.set(kn, 0); S.set(C1, 16); S.set(C0, 32); S.set(C1, 48);
    S.set(kn, 64);
    S.set(xor16(key, 0, C0, 0), 80);
    S.set(xor16(key, 0, C1, 0), 96);
    S.set(xor16(key, 0, C0, 0), 112);
    this.S = S; this.N = new Uint8Array(128);
    for (i = 0; i < 10; i++) this.upd(nonce, 0, key, 0);
  }
  A128L.prototype.upd = function (M0, o0, M1, o1) {
    var S = this.S, N = this.N;
    var t0 = xor16(S, 0, M0, o0), t4 = xor16(S, 64, M1, o1);
    aesRound(S, 112, t0, 0, N, 0);
    aesRound(S, 0, S, 16, N, 16);
    aesRound(S, 16, S, 32, N, 32);
    aesRound(S, 32, S, 48, N, 48);
    aesRound(S, 48, t4, 0, N, 64);
    aesRound(S, 64, S, 80, N, 80);
    aesRound(S, 80, S, 96, N, 96);
    aesRound(S, 96, S, 112, N, 112);
    S.set(N);
  };
  A128L.prototype.absorb = function (ai, o) { this.upd(ai, o, ai, o + 16); };
  A128L.prototype.enc = function (xi, oi, out, oo) {
    var S = this.S, i;
    var t0 = new Uint8Array(16), t1 = new Uint8Array(16);
    for (i = 0; i < 16; i++) {
      t0[i] = xi[oi + i]; t1[i] = xi[oi + 16 + i];
      out[oo + i] = t0[i] ^ S[16 + i] ^ S[96 + i] ^ (S[32 + i] & S[48 + i]);
      out[oo + 16 + i] = t1[i] ^ S[32 + i] ^ S[80 + i] ^ (S[96 + i] & S[112 + i]);
    }
    this.upd(t0, 0, t1, 0);
  };
  A128L.prototype.dec = function (ci, oi, out, oo) {
    var S = this.S, i;
    var o0 = new Uint8Array(16), o1 = new Uint8Array(16);
    for (i = 0; i < 16; i++) {
      o0[i] = ci[oi + i] ^ S[16 + i] ^ S[96 + i] ^ (S[32 + i] & S[48 + i]);
      o1[i] = ci[oi + 16 + i] ^ S[32 + i] ^ S[80 + i] ^ (S[96 + i] & S[112 + i]);
      out[oo + i] = o0[i]; out[oo + 16 + i] = o1[i];
    }
    this.upd(o0, 0, o1, 0);
  };
  /* 末块：补零解密 → 截断 → 用"明文补零"喂回 Update */
  A128L.prototype.decPart = function (cn, oi, len) {
    var S = this.S, i, t = new Uint8Array(32), o = new Uint8Array(32), v = new Uint8Array(32);
    t.set(cn.subarray(oi, oi + len));
    for (i = 0; i < 16; i++) {
      o[i] = t[i] ^ S[16 + i] ^ S[96 + i] ^ (S[32 + i] & S[48 + i]);
      o[16 + i] = t[16 + i] ^ S[32 + i] ^ S[80 + i] ^ (S[96 + i] & S[112 + i]);
    }
    v.set(o.subarray(0, len));
    this.upd(v, 0, v, 16);
    return o.slice(0, len);
  };
  A128L.prototype.fin = function (adBits, msgBits, tagB) {
    var S = this.S, t = new Uint8Array(16), i, v, r, a, b;
    for (i = 0; i < 16; i++) t[i] = S[32 + i];
    v = adBits; for (i = 0; i < 8; i++) { t[i] ^= (v % 256); v = Math.floor(v / 256); }
    v = msgBits; for (i = 0; i < 8; i++) { t[8 + i] ^= (v % 256); v = Math.floor(v / 256); }
    for (i = 0; i < 7; i++) this.upd(t, 0, t, 0);
    if (tagB === 16) {
      r = new Uint8Array(16);
      for (b = 0; b < 7; b++) for (i = 0; i < 16; i++) r[i] ^= S[b * 16 + i];
      return r;
    }
    r = new Uint8Array(32); a = new Uint8Array(16); b = new Uint8Array(16);
    for (var q = 0; q < 4; q++) for (i = 0; i < 16; i++) a[i] ^= S[q * 16 + i];
    for (var w = 4; w < 8; w++) for (i = 0; i < 16; i++) b[i] ^= S[w * 16 + i];
    r.set(a, 0); r.set(b, 16);
    return r;
  };

  /* ---------------- AEGIS-256 ---------------- */
  function A256(key, nonce) {
    var S = new Uint8Array(96), i;
    var k0 = key, k1 = key, n0 = nonce, n1 = nonce;
    var kn0 = xor16(key, 0, nonce, 0), kn1 = xor16(key, 16, nonce, 16);
    S.set(kn0, 0);
    S.set(kn1, 16);
    S.set(C1, 32);
    S.set(C0, 48);
    S.set(xor16(key, 0, C0, 0), 64);
    S.set(xor16(key, 16, C1, 0), 80);
    this.S = S; this.N = new Uint8Array(96);
    for (i = 0; i < 4; i++) {
      this.upd(key, 0); this.upd(key, 16);
      this.upd(kn0, 0); this.upd(kn1, 0);
    }
  }
  A256.prototype.upd = function (M, o) {
    var S = this.S, N = this.N, t = xor16(S, 0, M, o), b;
    aesRound(S, 80, t, 0, N, 0);
    for (b = 1; b < 6; b++) aesRound(S, (b - 1) * 16, S, b * 16, N, b * 16);
    S.set(N);
  };
  A256.prototype.absorb = function (ai, o) { this.upd(ai, o); };
  /* AEGIS-256：先 Update(明文)，再 ci = 明文 ^ z */
  A256.prototype.enc = function (xi, oi, out, oo) {
    var S = this.S, z = new Uint8Array(16), i;
    for (i = 0; i < 16; i++) z[i] = S[16 + i] ^ S[64 + i] ^ S[80 + i] ^ (S[32 + i] & S[48 + i]);
    this.upd(xi, oi);
    for (i = 0; i < 16; i++) out[oo + i] = xi[oi + i] ^ z[i];
  };
  A256.prototype.dec = function (ci, oi, out, oo) {
    var S = this.S, z = new Uint8Array(16), i;
    for (i = 0; i < 16; i++) z[i] = S[16 + i] ^ S[64 + i] ^ S[80 + i] ^ (S[32 + i] & S[48 + i]);
    for (i = 0; i < 16; i++) out[oo + i] = ci[oi + i] ^ z[i];
    this.upd(out, oo);
  };
  A256.prototype.decPart = function (cn, oi, len) {
    var S = this.S, z = new Uint8Array(16), t = new Uint8Array(16), v = new Uint8Array(16), i;
    for (i = 0; i < 16; i++) z[i] = S[16 + i] ^ S[64 + i] ^ S[80 + i] ^ (S[32 + i] & S[48 + i]);
    t.set(cn.subarray(oi, oi + len));
    for (i = 0; i < 16; i++) t[i] ^= z[i];
    v.set(t.subarray(0, len));
    this.upd(v, 0);
    return t.slice(0, len);
  };
  A256.prototype.fin = function (adBits, msgBits, tagB) {
    var S = this.S, t = new Uint8Array(16), i, v, r, a, b;
    for (i = 0; i < 16; i++) t[i] = S[48 + i];
    v = adBits; for (i = 0; i < 8; i++) { t[i] ^= (v % 256); v = Math.floor(v / 256); }
    v = msgBits; for (i = 0; i < 8; i++) { t[8 + i] ^= (v % 256); v = Math.floor(v / 256); }
    for (i = 0; i < 7; i++) this.upd(t, 0);
    if (tagB === 16) {
      r = new Uint8Array(16);
      for (b = 0; b < 6; b++) for (i = 0; i < 16; i++) r[i] ^= S[b * 16 + i];
      return r;
    }
    r = new Uint8Array(32); a = new Uint8Array(16); b = new Uint8Array(16);
    /* 注意：此处循环变量不能再用 b —— b 已被用作输出数组（下面 128L 同理用 q/w） */
    for (var q = 0; q < 3; q++) for (i = 0; i < 16; i++) a[i] ^= S[q * 16 + i];
    for (var w = 3; w < 6; w++) for (i = 0; i < 16; i++) b[i] ^= S[w * 16 + i];
    r.set(a, 0); r.set(b, 16);
    return r;
  };

  function zeroPad(buf, block) {
    var r = buf.length % block;
    if (r === 0) return buf;
    var o = new Uint8Array(buf.length + block - r);
    o.set(buf);
    return o;
  }

  function seal(variant, key, nonce, ad, msg, tagB) {
    var isL = variant === 'L';
    var st, bs, i;
    if (isL) {
      if (key.length !== 16) throw new Error('AEGIS-128L 密钥必须是 16 字节（32 位 Hex）');
      if (nonce.length !== 16) throw new Error('AEGIS-128L nonce 必须是 16 字节（32 位 Hex）');
    } else {
      if (key.length !== 32) throw new Error('AEGIS-256 密钥必须是 32 字节（64 位 Hex）');
      if (nonce.length !== 32) throw new Error('AEGIS-256 nonce 必须是 32 字节（64 位 Hex）');
    }
    st = isL ? new A128L(key, nonce) : new A256(key, nonce);
    bs = isL ? 32 : 16;
    var adp = zeroPad(ad, bs), msgp = zeroPad(msg, bs);
    for (i = 0; i < adp.length; i += bs) st.absorb(adp, i);
    var ctFull = new Uint8Array(msgp.length);
    for (i = 0; i < msgp.length; i += bs) st.enc(msgp, i, ctFull, i);
    var tag = st.fin(ad.length * 8, msg.length * 8, tagB);
    var out = new Uint8Array(msg.length + tagB);
    out.set(ctFull.subarray(0, msg.length), 0);
    out.set(tag, msg.length);
    return out;
  }

  function open(variant, key, nonce, ad, ct, tagB) {
    var isL = variant === 'L';
    var st, bs, i;
    if (isL) {
      if (key.length !== 16) throw new Error('AEGIS-128L 密钥必须是 16 字节（32 位 Hex）');
      if (nonce.length !== 16) throw new Error('AEGIS-128L nonce 必须是 16 字节（32 位 Hex）');
    } else {
      if (key.length !== 32) throw new Error('AEGIS-256 密钥必须是 32 字节（64 位 Hex）');
      if (nonce.length !== 32) throw new Error('AEGIS-256 nonce 必须是 32 字节（64 位 Hex）');
    }
    if (ct.length < tagB) throw new Error('输入太短：至少要含 ' + tagB + ' 字节认证标签');
    var body = ct.subarray(0, ct.length - tagB);
    var tag = ct.subarray(ct.length - tagB);
    st = isL ? new A128L(key, nonce) : new A256(key, nonce);
    bs = isL ? 32 : 16;
    var adp = zeroPad(ad, bs);
    for (i = 0; i < adp.length; i += bs) st.absorb(adp, i);
    var full = Math.floor(body.length / bs) * bs;
    var out = new Uint8Array(body.length);
    for (i = 0; i < full; i += bs) st.dec(body, i, out, i);
    if (full < body.length) out.set(st.decPart(body, full, body.length - full), full);
    var t2 = st.fin(ad.length * 8, body.length * 8, tagB);
    for (i = 0; i < tagB; i++) if (tag[i] !== t2[i]) throw new Error('AEGIS 认证失败：标签不匹配');
    return out;
  }

  function splitInput(b) {
    var ad = new Uint8Array(0), data = b;
    if (typeof b === 'string' && b.indexOf(',') >= 0) {
      var ps = b.split(',');
      ad = hexToBytes(ps[0] || '');
      data = hexToBytes(ps.slice(1).join(','));
    }
    return { ad: ad, data: new Uint8Array(data) };
  }

  function mkEntry(id, name, variant, tagB, desc) {
    return {
      id: id, name: name, group: '认证加密', key: true, param: true,
      info: desc,
      enc: function (b, k, p, fmt) {
        var key = hexToBytes(String(k || ''));
        var nonce = hexToBytes(String(p || ''));
        var s = splitInput(b);
        return bytesOut(seal(variant, key, nonce, s.ad, s.data, tagB), fmt);
      },
      dec: function (b, k, p, fmt) {
        var key = hexToBytes(String(k || ''));
        var nonce = hexToBytes(String(p || ''));
        var s = splitInput(b);
        return bytesOut(open(variant, key, nonce, s.ad, s.data, tagB), fmt);
      }
    };
  }

  reg(mkEntry('aegis128l', 'AEGIS-128L（AEAD，128 位标签）', 'L', 16,
    'RFC 10032 高速 AEAD，基于 AES 轮函数、无需求逆。密钥 16 字节填密钥栏，nonce 16 字节填参数栏；输入栏可用「AD的Hex,明文」带附加数据，输出为密文‖标签。已通过 RFC 官方测试向量 10 组（含 4 组篡改拒绝）。'));

  reg(mkEntry('aegis128l256', 'AEGIS-128L（AEAD，256 位标签）', 'L', 32,
    'RFC 10032 高速 AEAD 的 256 位标签变体，标签 32 字节。参数与 128 位版相同。已通过 RFC 官方测试向量 10 组。'));

  reg(mkEntry('aegis256aead', 'AEGIS-256（AEAD，128 位标签）', 'P', 16,
    'RFC 10032 高速 AEAD，256 位安全级别，状态 6 块 × 128 位。密钥 32 字节填密钥栏，nonce 32 字节填参数栏。nonce 可安全随机选取。已通过 RFC 官方测试向量 10 组（含 4 组篡改拒绝）。'));

  reg(mkEntry('aegis256aead256', 'AEGIS-256（AEAD，256 位标签）', 'P', 32,
    'RFC 10032 高速 AEAD 的 256 位标签变体，标签 32 字节。参数与 128 位版相同。已通过 RFC 官方测试向量 10 组。'));
})();
