/* Classic McEliece 348864（Niederreiter 版）
   逐行移植自 PQClean clean 实现（liboqs 内置），参数 GFBITS=12 SYS_N=3488 SYS_T=64
   sk 布局: [0:40] 保留(pivots) | [40:168] irr | [168:6056] cond | [6056:6492] s
   参考: PQClean/crypto_kem/mceliece348864/clean
   规范: https://classic.mceliece.org                                        */
(function () {
  'use strict';
  var GFBITS = 12, SYS_N = 3488, SYS_T = 64, GFMASK = (1 << GFBITS) - 1;
  var PK_NROWS = SYS_T * GFBITS;                       // 768
  var PK_NCOLS = SYS_N - PK_NROWS;                     // 2720
  var PK_ROW_BYTES = ((PK_NCOLS + 7) / 8) | 0;         // 340
  var SYND_BYTES = ((PK_NROWS + 7) / 8) | 0;           // 96
  var IRR_BYTES = SYS_T * 2;                           // 128
  var COND_BYTES = ((1 << (GFBITS - 4)) * (2 * GFBITS - 1)); // 5888
  var PK_BYTES = 261120, SK_BYTES = 6492, CT_BYTES = 96, SS_BYTES = 32;
  var SYSNB = SYS_N / 8;                              // 436
  var RBYTES = SYSNB + (1 << GFBITS) * 4 + SYS_T * 2 + 32;  // 16980

  /* ---------- SHAKE256（BigInt 实现，正确性优先） ---------- */
  var M64 = 0xFFFFFFFFFFFFFFFFn;
  var RCk = [
    0x0000000000000001n,0x0000000000008082n,0x800000000000808An,0x8000000080008000n,
    0x000000000000808Bn,0x0000000080000001n,0x8000000080008081n,0x8000000000008009n,
    0x000000000000008An,0x0000000000000088n,0x0000000080008009n,0x000000008000000An,
    0x000000008000808Bn,0x800000000000008Bn,0x8000000000008089n,0x8000000000008003n,
    0x8000000000008002n,0x8000000000000080n,0x000000000000800An,0x800000008000000An,
    0x8000000080008081n,0x8000000000008080n,0x0000000080000001n,0x8000000080008008n];
  var ROTk = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];
  function rotl64(x, n) { n = BigInt(n); if (n === 0n) return x; return ((x << n) | (x >> (64n - n))) & M64; }
  function keccakF(A) {
    var C = new Array(5), B = new Array(25), x, y, i, d, rnd;
    for (rnd = 0; rnd < 24; rnd++) {
      for (x = 0; x < 5; x++) C[x] = A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20];
      for (x = 0; x < 5; x++) {
        d = C[(x+4)%5] ^ rotl64(C[(x+1)%5], 1);
        for (y = 0; y < 5; y++) A[x + 5*y] ^= d;
      }
      for (i = 0; i < 25; i++) {
        x = i % 5; y = (i / 5) | 0;
        B[y + 5 * ((2*x + 3*y) % 5)] = rotl64(A[i], ROTk[i]);
      }
      for (y = 0; y < 5; y++) for (x = 0; x < 5; x++) {
        A[x + 5*y] = B[x + 5*y] ^ ((~B[((x+1)%5) + 5*y] & M64) & B[((x+2)%5) + 5*y]);
      }
      A[0] ^= RCk[rnd];
    }
  }
  function shake256Bytes(input, outLen) {
    var rate = 136, A = new Array(25), i, j, lane, off;
    for (i = 0; i < 25; i++) A[i] = 0n;
    var n = input.length;
    var padLen = rate - (n % rate);
    var padded = new Uint8Array(n + padLen);
    padded.set(input);
    padded[n] = 0x1F;
    padded[n + padLen - 1] ^= 0x80;
    for (off = 0; off < padded.length; off += rate) {
      for (i = 0; i < rate / 8; i++) {
        lane = 0n;
        for (j = 0; j < 8; j++) lane |= BigInt(padded[off + i*8 + j]) << BigInt(8*j);
        A[i] ^= lane;
      }
      keccakF(A);
    }
    var out = new Uint8Array(outLen), p = 0;
    var blk = new Uint8Array(rate);
    while (p < outLen) {
      for (i = 0; i < rate / 8; i++)
        for (j = 0; j < 8; j++) blk[i*8 + j] = Number((A[i] >> BigInt(8*j)) & 0xFFn);
      var take = outLen - p; if (take > rate) take = rate;
      for (i = 0; i < take; i++) out[p + i] = blk[i];
      p += take;
      if (p < outLen) keccakF(A);
    }
    return out;
  }

  /* ---------- GF(2^12) ---------- */
  function gfIsZero(a) { var t = a; t -= 1; t >>= 19; return t; }
  function gfAdd(a, b) { return a ^ b; }
  function gfMul(a, b) {
    var i, tmp = 0, t;
    tmp = a * (b & 1);
    for (i = 1; i < GFBITS; i++) tmp ^= (a * (b & (1 << i)));
    t = tmp & 0x7FC000; tmp ^= t >> 9; tmp ^= t >> 12;
    t = tmp & 0x3000;   tmp ^= t >> 9; tmp ^= t >> 12;
    return tmp & GFMASK;
  }
  function gfSq(a) {
    var x = a, t;
    x = (x | (x << 8)) & 0x00FF00FF;
    x = (x | (x << 4)) & 0x0F0F0F0F;
    x = (x | (x << 2)) & 0x33333333;
    x = (x | (x << 1)) & 0x55555555;
    t = x & 0x7FC000; x ^= t >> 9; x ^= t >> 12;
    t = x & 0x3000;   x ^= t >> 9; x ^= t >> 12;
    return x & GFMASK;
  }
  function gfInv(a) {
    var out = a, t11, t1111;
    out = gfSq(out); t11 = gfMul(out, a);
    out = gfSq(t11); out = gfSq(out); t1111 = gfMul(out, t11);
    out = gfSq(t1111); out = gfSq(out); out = gfSq(out); out = gfSq(out); out = gfMul(out, t1111);
    out = gfSq(out); out = gfSq(out); out = gfMul(out, t11);
    out = gfSq(out); out = gfMul(out, a);
    return gfSq(out);
  }
  function gfFrac(den, num) { return gfMul(gfInv(den), num); }

  /* ---------- util ---------- */
  function loadGf(src, o) { return (src[o] | (src[o+1] << 8)) & GFMASK; }
  function load4(inp, o) { return ((inp[o] | (inp[o+1] << 8) | (inp[o+2] << 16)) + inp[o+3] * 16777216) >>> 0; }
  function bitrev(a) {
    a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
    a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
    a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
    a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);
    return a >> 4;
  }

  /* ---------- transpose_64x64（BigInt，64 元素，正确性优先） ---------- */
  function load8B(b, o) {
    var v = 0n;
    for (var j = 7; j >= 0; j--) v = (v << 8n) | BigInt(b[o + j]);
    return v;
  }
  function store8B(b, o, v) {
    for (var j = 0; j < 8; j++) b[o + j] = Number((v >> BigInt(8 * j)) & 0xFFn);
  }
  var MASKS = [0x5555555555555555n, 0x3333333333333333n, 0x0F0F0F0F0F0F0F0Fn,
               0x00FF00FF00FF00FFn, 0x0000FFFF0000FFFFn, 0x00000000FFFFFFFFn];
  function transpose64(A) {
    var i, j, s, d, x, y;
    for (d = 5; d >= 0; d--) {
      s = 1 << d;
      for (i = 0; i < 64; i += s * 2) {
        for (j = i; j < i + s; j++) {
          var m = MASKS[d];
          x = (A[j] & m) | ((A[j + s] & m) << BigInt(s));
          y = ((A[j] & ~m) >> BigInt(s)) | (A[j + s] & ~m);
          A[j] = x; A[j + s] = y;
        }
      }
    }
  }

  /* ---------- benes ---------- */
  function benesLayer(A, C, lgs) {
    var i, j, s = 1 << lgs, d, p = 0;
    for (i = 0; i < 64; i += s * 2) {
      for (j = i; j < i + s; j++) {
        d = (A[j] ^ A[j + s]) & C[p++];
        A[j] ^= d; A[j + s] ^= d;
      }
    }
  }
  function applyBenes(r, bits, rev) {
    var i, low, inc, cptr;
    var A = new Array(64), C = new Array(64);
    for (i = 0; i < 64; i++) A[i] = load8B(r, i * 8);
    if (rev === 0) { inc = 256; cptr = 0; } else { inc = -256; cptr = (2 * GFBITS - 2) * 256; }
    transpose64(A);
    for (low = 0; low <= 5; low++) {
      for (i = 0; i < 64; i++) C[i] = BigInt(load4(bits, cptr + i * 4) >>> 0);
      transpose64(C);
      benesLayer(A, C, low);
      cptr += inc;
    }
    transpose64(A);
    for (low = 0; low <= 5; low++) {
      for (i = 0; i < 32; i++) C[i] = load8B(bits, cptr + i * 8);
      benesLayer(A, C, low);
      cptr += inc;
    }
    for (low = 4; low >= 0; low--) {
      for (i = 0; i < 32; i++) C[i] = load8B(bits, cptr + i * 8);
      benesLayer(A, C, low);
      cptr += inc;
    }
    transpose64(A);
    for (low = 5; low >= 0; low--) {
      for (i = 0; i < 64; i++) C[i] = BigInt(load4(bits, cptr + i * 4) >>> 0);
      transpose64(C);
      benesLayer(A, C, low);
      cptr += inc;
    }
    transpose64(A);
    for (i = 0; i < 64; i++) store8B(r, i * 8, A[i]);
  }
  /* support_gen: s[i] 由 L 的 GFBITS 行逐位拼出 */
  function supportGen(c) {
    var L = [], i, j, a;
    for (j = 0; j < GFBITS; j++) L.push(new Uint8Array((1 << GFBITS) / 8));
    for (i = 0; i < (1 << GFBITS); i++) {
      a = bitrev(i);
      for (j = 0; j < GFBITS; j++) L[j][(i / 8) | 0] |= ((a >> j) & 1) << (i & 7);
    }
    for (j = 0; j < GFBITS; j++) applyBenes(L[j], c, 0);
    var s = new Int32Array(SYS_N);
    for (i = 0; i < SYS_N; i++) {
      s[i] = 0;
      for (j = GFBITS - 1; j >= 0; j--) { s[i] <<= 1; s[i] |= (L[j][(i / 8) | 0] >> (i & 7)) & 1; }
    }
    return s;
  }

  /* ---------- root / synd / bm ---------- */
  function evalPoly(f, a) {
    var r = f[SYS_T], i;
    for (i = SYS_T - 1; i >= 0; i--) { r = gfMul(r, a); r = gfAdd(r, f[i]); }
    return r;
  }
  function root(out, f, L) { for (var i = 0; i < SYS_N; i++) out[i] = evalPoly(f, L[i]); }
  function synd(out, f, L, r) {
    var i, j, e, eInv, c;
    for (j = 0; j < 2 * SYS_T; j++) out[j] = 0;
    for (i = 0; i < SYS_N; i++) {
      c = (r[(i / 8) | 0] >> (i & 7)) & 1;
      e = evalPoly(f, L[i]);
      eInv = gfInv(gfMul(e, e));
      for (j = 0; j < 2 * SYS_T; j++) { out[j] = gfAdd(out[j], gfMul(eInv, c)); eInv = gfMul(eInv, L[i]); }
    }
  }
  function bm(out, s) {
    var i, N, L = 0, mle, mne;
    var T = new Int32Array(SYS_T + 1), C = new Int32Array(SYS_T + 1), B = new Int32Array(SYS_T + 1);
    var b = 1, d, f, mn;
    for (i = 0; i < SYS_T + 1; i++) { C[i] = 0; B[i] = 0; }
    B[1] = 1; C[0] = 1;
    for (N = 0; N < 2 * SYS_T; N++) {
      d = 0;
      mn = Math.min(N, SYS_T);
      for (i = 0; i <= mn; i++) d ^= gfMul(C[i], s[N - i]);
      /* C: uint16_t mne/mle —— 必须显式模拟 16 位下溢与右移 */
      mne = (d - 1) & 0xFFFF;
      mne = (mne >> 15);
      mne = (mne - 1) & 0xFFFF;
      mle = (N - 2 * L) & 0xFFFF;
      mle = (mle >> 15);
      mle = (mle - 1) & 0xFFFF;
      mle &= mne;
      for (i = 0; i <= SYS_T; i++) T[i] = C[i];
      f = gfFrac(b, d);
      for (i = 0; i <= SYS_T; i++) C[i] ^= gfMul(f, B[i]) & mne;
      L = (L & ~mle) | ((N + 1 - L) & mle);
      for (i = 0; i <= SYS_T; i++) B[i] = (B[i] & ~mle) | (T[i] & mle);
      b = (b & ~mle) | (d & mle);
      for (i = SYS_T; i >= 1; i--) B[i] = B[i - 1];
      B[0] = 0;
    }
    for (i = 0; i <= SYS_T; i++) out[i] = C[SYS_T - i];
  }

  /* ---------- encrypt（Niederreiter） ---------- */
  function sameMask(x, y) {
    var mask = (x ^ y);
    mask -= 1;
    mask = mask >>> 31;
    mask = -mask;
    return mask & 0xFF;
  }
  /* 生成重量 SYS_T 的错误向量；rnd(n) 返回 n 个随机字节 */
  function genE(rnd) {
    var i, j, eq, count;
    var ind = new Int32Array(SYS_T), val = new Uint8Array(SYS_T);
    var buf = new Uint8Array(SYS_T * 2 * 2);
    var nums = new Int32Array(SYS_T * 2);
    for (;;) {
      var rb = rnd(buf.length);
      for (i = 0; i < buf.length; i++) buf[i] = rb[i];
      for (i = 0; i < SYS_T * 2; i++) nums[i] = (buf[i*2] | (buf[i*2+1] << 8)) & GFMASK;
      count = 0;
      for (i = 0; i < SYS_T * 2 && count < SYS_T; i++) {
        if (nums[i] < SYS_N) ind[count++] = nums[i];
      }
      if (count < SYS_T) continue;
      eq = 0;
      for (i = 1; i < SYS_T; i++) for (j = 0; j < i; j++) if (ind[i] === ind[j]) eq = 1;
      if (eq === 0) break;
    }
    for (j = 0; j < SYS_T; j++) val[j] = 1 << (ind[j] & 7);
    var e = new Uint8Array(SYS_N / 8);
    for (i = 0; i < SYS_N / 8; i++) {
      e[i] = 0;
      for (j = 0; j < SYS_T; j++) e[i] |= val[j] & sameMask(i, ind[j] >> 3);
    }
    return e;
  }
  /* syndrome: s[i] = <row_i, e> */
  function syndrome(pk, e) {
    var s = new Uint8Array(SYND_BYTES), row = new Uint8Array(SYS_N / 8);
    var i, j, b, p = 0;
    for (i = 0; i < SYND_BYTES; i++) s[i] = 0;
    var off = SYS_N / 8 - PK_ROW_BYTES;
    for (i = 0; i < PK_NROWS; i++) {
      for (j = 0; j < SYS_N / 8; j++) row[j] = 0;
      for (j = 0; j < PK_ROW_BYTES; j++) row[off + j] = pk[p + j];
      row[(i / 8) | 0] |= 1 << (i & 7);
      b = 0;
      for (j = 0; j < SYS_N / 8; j++) b ^= row[j] & e[j];
      b ^= b >> 4; b ^= b >> 2; b ^= b >> 1; b &= 1;
      s[(i / 8) | 0] |= (b << (i & 7));
      p += PK_ROW_BYTES;
    }
    return s;
  }
  function kemEnc(pkBytes, rnd) {
    var pk = new Uint8Array(pkBytes);
    var e = genE(rnd);
    var c = syndrome(pk, e);
    var oneEc = new Uint8Array(1 + SYS_N / 8 + SYND_BYTES);
    oneEc[0] = 1;
    oneEc.set(e, 1);
    oneEc.set(c, 1 + SYS_N / 8);
    return { ct: c, ss: shake256Bytes(oneEc, 32), e: e };
  }

  /* ---------- decrypt ---------- */
  function decrypt(sk, c) {
    var i, w = 0, t;
    var r = new Uint8Array(SYS_N / 8);
    var g = new Int32Array(SYS_T + 1), L, s = new Int32Array(SYS_T * 2);
    var sCmp = new Int32Array(SYS_T * 2), locator = new Int32Array(SYS_T + 1);
    var images = new Int32Array(SYS_N);
    var e = new Uint8Array(SYS_N / 8);
    var skp = 40;
    for (i = 0; i < SYND_BYTES; i++) r[i] = c[i];
    for (i = SYND_BYTES; i < SYS_N / 8; i++) r[i] = 0;
    for (i = 0; i < SYS_T; i++) { g[i] = loadGf(sk, skp); skp += 2; }
    g[SYS_T] = 1;
    var cond = sk.subarray(skp, skp + COND_BYTES);
    L = supportGen(cond);
    synd(s, g, L, r);
    bm(locator, s);
    root(images, locator, L);
    for (i = 0; i < SYS_N / 8; i++) e[i] = 0;
    for (i = 0; i < SYS_N; i++) {
      t = gfIsZero(images[i]) & 1;
      e[(i / 8) | 0] |= t << (i & 7);
      w += t;
    }
    synd(sCmp, g, L, e);
    /* C: uint16_t check */
    var check = w & 0xFFFF;
    check ^= SYS_T;
    for (i = 0; i < SYS_T * 2; i++) check |= s[i] ^ sCmp[i];
    check = (check - 1) & 0xFFFF;
    check = check >> 15;
    /* C: return check ^ 1 —— 返回 0 表示成功 */
    var ret = (check ^ 1) & 0xFFFF;
    return { ok: ret === 0, e: e };
  }
  function kemDec(skBytes, cBytes) {
    var sk = new Uint8Array(skBytes), c = new Uint8Array(cBytes);
    var r = decrypt(sk, c);
    var ok = r.ok ? 1 : 0;
    var sOff = 40 + IRR_BYTES + COND_BYTES;
    var pre = new Uint8Array(1 + SYS_N / 8 + SYND_BYTES);
    var p = 0, i;
    pre[p++] = ok;
    for (i = 0; i < SYS_N / 8; i++) pre[p++] = ok ? r.e[i] : sk[sOff + i];
    for (i = 0; i < SYND_BYTES; i++) pre[p++] = c[i];
    return shake256Bytes(pre, 32);
  }

  /* ================= 密钥生成 ================= */
  /* 以下逐行移植自 PQClean clean: sk_gen.c / pk_gen.c / controlbits.c
     已与官方 NIST KAT（seed→pk/sk）逐字节交叉验证 3 组 + 完整 261120/6492 字节 */
  function storeGf(d, o, a) { d[o] = a & 0xFF; d[o + 1] = (a >> 8) & 0xFF; }

  /* GF((2^12)^64) 乘法（sk_gen.c GF_mul） */
  function gfPolyMul(out, in0, in1) {
    var prod = new Int32Array(2 * SYS_T - 1), i, j;
    for (i = 0; i < SYS_T; i++) for (j = 0; j < SYS_T; j++) prod[i + j] ^= gfMul(in0[i], in1[j]);
    for (i = (SYS_T - 1) * 2; i >= SYS_T; i--) {
      prod[i - SYS_T + 3] ^= prod[i];
      prod[i - SYS_T + 1] ^= prod[i];
      prod[i - SYS_T + 0] ^= gfMul(prod[i], 2);
    }
    for (i = 0; i < SYS_T; i++) out[i] = prod[i];
  }
  /* genpoly_gen：求 f 的极小多项式（= Goppa 多项式系数） */
  function genpolyGen(f) {
    var mat = new Int32Array((SYS_T + 1) * SYS_T);
    var i, j, k, c, m, inv, t;
    mat[0] = 1;
    for (i = 1; i < SYS_T; i++) mat[i] = 0;
    for (i = 0; i < SYS_T; i++) mat[SYS_T + i] = f[i];
    for (j = 2; j <= SYS_T; j++) gfPolyMul(mat.subarray(j * SYS_T, (j + 1) * SYS_T), mat.subarray((j - 1) * SYS_T, j * SYS_T), f);
    for (j = 0; j < SYS_T; j++) {
      for (k = j + 1; k < SYS_T; k++) {
        m = gfIsZero(mat[j * SYS_T + j]) & 0xFFFF;
        for (c = j; c < SYS_T + 1; c++) mat[c * SYS_T + j] ^= mat[c * SYS_T + k] & m;
      }
      if (gfIsZero(mat[j * SYS_T + j])) return null;
      inv = gfInv(mat[j * SYS_T + j]);
      for (c = j; c < SYS_T + 1; c++) mat[c * SYS_T + j] = gfMul(mat[c * SYS_T + j], inv);
      for (k = 0; k < SYS_T; k++) {
        if (k !== j) {
          t = mat[j * SYS_T + k];
          for (c = j; c < SYS_T + 1; c++) mat[c * SYS_T + k] ^= gfMul(mat[c * SYS_T + j], t);
        }
      }
    }
    var out = new Int32Array(SYS_T);
    for (i = 0; i < SYS_T; i++) out[i] = mat[SYS_T * SYS_T + i];
    return out;
  }
  /* int32 双调排序（与 PQClean int32_sort 同一网络） */
  function int32Sort(x, off, n) {
    if (n < 2) return;
    var top = 1, p, q, r, i, a, t;
    while (top < n - top) top += top;
    for (p = top; p > 0; p >>= 1) {
      for (i = 0; i < n - p; i++) {
        if (!(i & p)) { if (x[off + i] > x[off + i + p]) { t = x[off + i]; x[off + i] = x[off + i + p]; x[off + i + p] = t; } }
      }
      i = 0;
      for (q = top; q > p; q >>= 1) {
        for (; i < n - q; i++) {
          if (!(i & p)) {
            a = x[off + i + p];
            for (r = q; r > p; r >>= 1) {
              if (a > x[off + i + r]) { t = a; a = x[off + i + r]; x[off + i + r] = t; }
            }
            x[off + i + p] = a;
          }
        }
      }
    }
  }
  /* uint64_sort 等价实现：按 (perm 值, 原下标) 字典序排索引（避开 2^53 精度问题） */
  function sortIdxByPerm(perm) {
    var n = perm.length, idx = new Int32Array(n), i, top = 1, p, q, r, t;
    for (i = 0; i < n; i++) idx[i] = i;
    function sw(u, v) { var tt = idx[u]; idx[u] = idx[v]; idx[v] = tt; }
    function gt(u, v) {
      var iu = idx[u], iv = idx[v], pu = perm[iu], pv = perm[iv];
      if (pu !== pv) return pu > pv;
      return iu > iv;
    }
    while (top < n - top) top += top;
    for (p = top; p > 0; p >>= 1) {
      for (i = 0; i < n - p; i++) if (!(i & p)) { if (gt(i, i + p)) sw(i, i + p); }
      i = 0;
      for (q = top; q > p; q >>= 1) {
        for (; i < n - q; i++) {
          if (!(i & p)) { for (r = q; r > p; r >>= 1) { if (gt(i + p, i + r)) sw(i + p, i + r); } }
        }
      }
    }
    return idx;
  }
  /* pk_gen：由 Goppa 多项式 + 排列生成系统形式公钥 */
  function pkGen(irrBytes, perm) {
    var i, j, k, row, c, b;
    var g = new Int32Array(SYS_T + 1), L = new Int32Array(SYS_N), inv = new Int32Array(SYS_N);
    g[SYS_T] = 1;
    for (i = 0; i < SYS_T; i++) g[i] = loadGf(irrBytes, i * 2);
    var idx = sortIdxByPerm(perm);
    for (i = 1; i < (1 << GFBITS); i++) if (perm[idx[i - 1]] === perm[idx[i]]) return null;
    var pi = new Int32Array(1 << GFBITS);
    for (i = 0; i < (1 << GFBITS); i++) pi[i] = idx[i];
    for (i = 0; i < SYS_N; i++) L[i] = bitrev(pi[i]);
    for (i = 0; i < SYS_N; i++) inv[i] = evalPoly(g, L[i]);
    for (i = 0; i < SYS_N; i++) inv[i] = gfInv(inv[i]);
    var buf = new ArrayBuffer(PK_NROWS * SYSNB);
    var matU8 = new Uint8Array(buf), matU32 = new Uint32Array(buf);
    var U32W = SYSNB / 4, mask;   // 109
    matU8.fill(0);
    for (i = 0; i < SYS_T; i++) {
      for (j = 0; j < SYS_N; j += 8) {
        for (k = 0; k < GFBITS; k++) {
          b = (inv[j + 7] >> k) & 1; b <<= 1;
          b |= (inv[j + 6] >> k) & 1; b <<= 1;
          b |= (inv[j + 5] >> k) & 1; b <<= 1;
          b |= (inv[j + 4] >> k) & 1; b <<= 1;
          b |= (inv[j + 3] >> k) & 1; b <<= 1;
          b |= (inv[j + 2] >> k) & 1; b <<= 1;
          b |= (inv[j + 1] >> k) & 1; b <<= 1;
          b |= (inv[j + 0] >> k) & 1;
          matU8[(i * GFBITS + k) * SYSNB + (j / 8)] = b;
        }
      }
      for (j = 0; j < SYS_N; j++) inv[j] = gfMul(inv[j], L[j]);
    }
    for (i = 0; i < (PK_NROWS + 7) / 8; i++) {
      for (j = 0; j < 8; j++) {
        row = i * 8 + j;
        if (row >= PK_NROWS) break;
        for (k = row + 1; k < PK_NROWS; k++) {
          mask = (matU8[row * SYSNB + i] ^ matU8[k * SYSNB + i]) >> j;
          mask &= 1; mask = -mask;
          if (mask) for (c = 0; c < U32W; c++) matU32[row * U32W + c] ^= matU32[k * U32W + c];
        }
        if (((matU8[row * SYSNB + i] >> j) & 1) === 0) return null;
        for (k = 0; k < PK_NROWS; k++) {
          if (k !== row) {
            mask = (matU8[k * SYSNB + i] >> j) & 1; mask = -mask;
            if (mask) for (c = 0; c < U32W; c++) matU32[k * U32W + c] ^= matU32[row * U32W + c];
          }
        }
      }
    }
    var pk = new Uint8Array(PK_BYTES);
    for (i = 0; i < PK_NROWS; i++)
      for (j = 0; j < PK_ROW_BYTES; j++) pk[i * PK_ROW_BYTES + j] = matU8[i * SYSNB + PK_NROWS / 8 + j];
    return { pk: pk, pi: pi };
  }
  /* controlbits：Nassimi-Sahni 算法，把排列压成 Benes 网络控制位 */
  function cbrec(out, pos, step, pi, w, n, temp) {
    var x, y, i, j, k, fj, Fx, Fx1, lk, Ly, Ly1, px, cx, Ax, ppcx, ppcpx, cpx, q;
    if (w === 1) { out[pos >> 3] ^= pi[0] << (pos & 7); return; }
    for (x = 0; x < n; x++) temp[x] = ((pi[x] ^ 1) << 16) | pi[x ^ 1];
    int32Sort(temp, 0, n);
    for (x = 0; x < n; x++) { Ax = temp[x]; px = Ax & 0xffff; cx = Math.min(px, x); temp[n + x] = (px << 16) | cx; }
    for (x = 0; x < n; x++) temp[x] = ((temp[x] << 16) | x) | 0;
    int32Sort(temp, 0, n);
    for (x = 0; x < n; x++) temp[x] = ((temp[x] << 16) + (temp[n + x] >> 16)) | 0;
    int32Sort(temp, 0, n);
    if (w <= 10) {
      for (x = 0; x < n; x++) temp[n + x] = ((temp[x] & 0xffff) << 10) | (temp[n + x] & 0x3ff);
      for (i = 1; i < w - 1; i++) {
        for (x = 0; x < n; x++) temp[x] = ((temp[n + x] & ~0x3ff) << 6) | x;
        int32Sort(temp, 0, n);
        for (x = 0; x < n; x++) temp[x] = ((temp[x] << 20) | temp[n + x]) | 0;
        int32Sort(temp, 0, n);
        for (x = 0; x < n; x++) {
          ppcpx = temp[x] & 0xfffff;
          ppcx = (temp[x] & 0xffc00) | (temp[n + x] & 0x3ff);
          temp[n + x] = Math.min(ppcx, ppcpx);
        }
      }
      for (x = 0; x < n; x++) temp[n + x] &= 0x3ff;
    } else {
      for (x = 0; x < n; x++) temp[n + x] = ((temp[x] << 16) | (temp[n + x] & 0xffff)) | 0;
      for (i = 1; i < w - 1; i++) {
        for (x = 0; x < n; x++) temp[x] = ((temp[n + x] & ~0xffff) | x) | 0;
        int32Sort(temp, 0, n);
        for (x = 0; x < n; x++) temp[x] = ((temp[x] << 16) | (temp[n + x] & 0xffff)) | 0;
        if (i < w - 2) {
          for (x = 0; x < n; x++) temp[n + x] = ((temp[x] & ~0xffff) | (temp[n + x] >> 16)) | 0;
          int32Sort(temp, n, n);
          for (x = 0; x < n; x++) temp[n + x] = ((temp[n + x] << 16) | (temp[x] & 0xffff)) | 0;
        }
        int32Sort(temp, 0, n);
        for (x = 0; x < n; x++) {
          cpx = ((temp[n + x] & ~0xffff) | (temp[x] & 0xffff)) | 0;
          temp[n + x] = Math.min(temp[n + x], cpx);
        }
      }
      for (x = 0; x < n; x++) temp[n + x] &= 0xffff;
    }
    for (x = 0; x < n; x++) temp[x] = ((pi[x] << 16) + x) | 0;
    int32Sort(temp, 0, n);
    for (j = 0; j < n / 2; j++) {
      x = 2 * j;
      fj = temp[n + x] & 1;
      Fx = x + fj; Fx1 = Fx ^ 1;
      out[pos >> 3] ^= fj << (pos & 7);
      pos += step;
      temp[n + x] = ((temp[x] << 16) | Fx) | 0;
      temp[n + x + 1] = ((temp[x + 1] << 16) | Fx1) | 0;
    }
    int32Sort(temp, n, n);
    pos += (2 * w - 3) * step * (n / 2);
    for (k = 0; k < n / 2; k++) {
      y = 2 * k;
      lk = temp[n + y] & 1;
      Ly = y + lk; Ly1 = Ly ^ 1;
      out[pos >> 3] ^= lk << (pos & 7);
      pos += step;
      temp[y] = ((Ly << 16) | (temp[n + y] & 0xffff)) | 0;
      temp[y + 1] = ((Ly1 << 16) | (temp[n + y + 1] & 0xffff)) | 0;
    }
    int32Sort(temp, 0, n);
    pos -= (2 * w - 2) * step * (n / 2);
    /* C 的 q 在 temp 之后，实占 n 个 int16：前 n/2 给第一个递归，后 n/2 给第二个 */
    q = new Int16Array(n);
    for (j = 0; j < n / 2; j++) {
      q[j] = (temp[2 * j] & 0xffff) >> 1;
      q[j + n / 2] = (temp[2 * j + 1] & 0xffff) >> 1;
    }
    cbrec(out, pos, step * 2, q.subarray(0, n / 2), w - 1, n / 2, temp);
    cbrec(out, pos + step, step * 2, q.subarray(n / 2, n), w - 1, n / 2, temp);
  }
  function cbLayer(p, cb, s, n) {
    var stride = 1 << s, index = 0, i, j, d, m;
    for (i = 0; i < n; i += stride * 2) {
      for (j = 0; j < stride; j++) {
        d = p[i + j] ^ p[i + j + stride];
        m = (cb[index >> 3] >> (index & 7)) & 1; m = -m;
        d &= m;
        p[i + j] ^= d; p[i + j + stride] ^= d;
        index++;
      }
    }
  }
  function controlbitsFromPermutation(pi, w, n) {
    var nb = (((2 * w - 1) * n / 2) + 7) / 8 | 0;
    var out = new Uint8Array(nb), test = new Int16Array(n), temp = new Int32Array(2 * n);
    var i, ptr, diff;
    for (;;) {
      out.fill(0);
      cbrec(out, 0, 1, pi, w, n, temp);
      for (i = 0; i < n; i++) test[i] = i;
      ptr = 0;
      for (i = 0; i < w; i++) { cbLayer(test, out.subarray(ptr), i, n); ptr += n >> 4; }
      for (i = w - 2; i >= 0; i--) { cbLayer(test, out.subarray(ptr), i, n); ptr += n >> 4; }
      diff = 0;
      for (i = 0; i < n; i++) diff |= pi[i] ^ test[i];
      if (diff === 0) break;
    }
    return out;
  }
  /* 由 shake256 展开结果 r 构造密钥对 */
  function mceKeygenFromR(seed32, r) {
    var i, rp = r.length - 32 - SYS_T * 2;
    var sk = new Uint8Array(SK_BYTES);
    sk.set(seed32, 0);
    var f = new Int32Array(SYS_T);
    for (i = 0; i < SYS_T; i++) f[i] = loadGf(r, rp + i * 2);
    var irr = genpolyGen(f);
    if (!irr) return null;
    var irrb = new Uint8Array(IRR_BYTES);
    for (i = 0; i < SYS_T; i++) storeGf(irrb, i * 2, irr[i]);
    sk.set(irrb, 40);
    rp -= (1 << GFBITS) * 4;
    var perm = new Uint32Array(1 << GFBITS);
    for (i = 0; i < (1 << GFBITS); i++) perm[i] = load4(r, rp + i * 4);
    var res = pkGen(irrb, perm);
    if (!res) return null;
    sk.set(controlbitsFromPermutation(res.pi, GFBITS, 1 << GFBITS), 40 + IRR_BYTES);
    sk.set(r.subarray(0, SYSNB), 40 + IRR_BYTES + COND_BYTES);
    /* store8(sk+32, 0xFFFFFFFF)：8 字节 0x00000000FFFFFFFF，小端 */
    for (i = 32; i < 36; i++) sk[i] = 0xFF;
    return { pk: res.pk, sk: sk };
  }
  /* 完整密钥生成：seed 结构 0x40 ‖ 32 字节（与 PQClean 一致） */
  function mceKeygen(seed32) {
    var s33 = new Uint8Array(33), cur = new Uint8Array(seed32), res, r, next;
    s33[0] = 64;
    for (var att = 0; att < 64; att++) {
      s33.set(cur, 1);
      r = shake256Bytes(s33, RBYTES);
      next = r.subarray(RBYTES - 32, RBYTES);
      res = mceKeygenFromR(cur, r);
      if (res) return res;
      cur = new Uint8Array(next);
    }
    return null;
  }

  var API = { kemDec: kemDec, decrypt: decrypt, shake256Bytes: shake256Bytes,
                   supportGen: supportGen, synd: synd, bm: bm, gfMul: gfMul, gfInv: gfInv,
                   transpose64: transpose64, kemEnc: kemEnc, genE: genE, syndrome: syndrome,
                   mceKeygen: mceKeygen, mceKeygenFromR: mceKeygenFromR, pkGen: pkGen,
                   genpolyGen: genpolyGen, controlbitsFromPermutation: controlbitsFromPermutation,
                   RBYTES: RBYTES, SYSNB: SYSNB,
                   GFBITS: GFBITS, SYS_N: SYS_N, SYS_T: SYS_T, SYND_BYTES: SYND_BYTES,
                   PK_NROWS: PK_NROWS, PK_ROW_BYTES: PK_ROW_BYTES, PK_BYTES: PK_BYTES, SK_BYTES: SK_BYTES,
                   IRR_BYTES: IRR_BYTES, COND_BYTES: COND_BYTES };
  window.__MCE = API;

  /* ---------------- 注册到算法表 ---------------- */
  if (typeof reg === 'function') {
    function rndBytes(n) {
      if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        var a = new Uint8Array(n); crypto.getRandomValues(a); return a;
      }
      var a2 = new Uint8Array(n);
      for (var i = 0; i < n; i++) a2[i] = (Math.random() * 256) | 0;
      return a2;
    }
    var INFO = 'Classic McEliece 348864：码基后量子 KEM（二元 Goppa 码），抗量子攻击。' +
      '公钥 261120 字节（约 255KB，建议【载入文件】导入）、私钥 6492 字节、密文 96 字节、密钥 32 字节。' +
      '已过官方 NIST KAT：解封装与往返均逐字节一致。密钥生成见同组下一条。';
    reg({ id: 'mceliece348864', name: 'Classic McEliece 348864（码基 KEM）',
      group: '后量子密码', key: true, param: false,
      keyLabel: '封装填公钥（261120 字节 Hex，建议用载入文件）；解封装填私钥（6492 字节 Hex）',
      info: INFO,
      enc: function (b, kk, pp, fmt) {
        if (!kk) throw new Error('请在密钥栏填入封装公钥（Hex）');
        var pk = hexToBytes(String(kk).replace(/\s/g, ''));
        if (pk.length !== PK_BYTES) throw new Error('公钥长度应为 ' + PK_BYTES + ' 字节，实际 ' + pk.length);
        var out = API.kemEnc(pk, rndBytes);
        return bytesOut(out.ct, fmt) + '\n::K::' + bytesOut(out.ss, fmt);
      },
      dec: function (str, kk, pp, fmt) {
        if (!kk) throw new Error('请在密钥栏填入解封装私钥（Hex）');
        var sk = hexToBytes(String(kk).replace(/\s/g, ''));
        if (sk.length !== SK_BYTES) throw new Error('私钥长度应为 ' + SK_BYTES + ' 字节，实际 ' + sk.length);
        var cHex = String(str).split('::K::')[0].trim();
        var c = bytesIn(cHex, fmt);
        if (c.length !== 96) throw new Error('密文长度应为 96 字节，实际 ' + c.length);
        return bytesOut(API.kemDec(sk, c), fmt);
      } });

    var KG_INFO = '生成 Classic McEliece 348864 密钥对：公钥 261120 字节（约 255KB）、私钥 6492 字节。' +
      '流程：随机 Goppa 多项式 → 随机排列 → 系统形式公钥 → Benes 控制位压缩。' +
      '已过官方 NIST KAT（3 组种子，pk/sk 逐字节一致）。' +
      '输出约 53 万字符；参数栏填 sk 只输出私钥（12984 字符）。约 0.2 秒。';
    reg({ id: 'mceliece348864-keygen', name: 'Classic McEliece 348864 密钥生成（官方 KAT 验证）',
      group: '后量子密码', key: false, param: true,
      paramLabel: '留空=随机生成；填 64 位 Hex=用该种子确定性生成；填 sk=只输出私钥',
      info: KG_INFO,
      enc: function (b, kk, pp, fmt) {
        var seed = null, onlySk = false;
        if (pp) {
          var s = String(pp).trim();
          if (/^[0-9a-fA-F]{64}$/.test(s)) seed = hexToBytes(s);
          else if (/sk/i.test(s)) onlySk = true;
        }
        if (!seed) seed = rndBytes(32);
        var res = API.mceKeygen(seed);
        if (!res) throw new Error('密钥生成失败（概率极低），请重试');
        if (onlySk) return bytesOut(res.sk, fmt);
        return bytesOut(res.pk, fmt) + '\n::K::' + bytesOut(res.sk, fmt);
      },
      dec: false });
  }
})();
