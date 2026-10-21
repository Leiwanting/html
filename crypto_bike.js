/* ============================================================
 * BIKE（NIST Round 4 码基 KEM，additional_r4 2023-01-27 版）
 *   条目：bike-keygen / bike-encaps / bike-decaps
 *   参数集 LEVEL 1/3/5：R_BITS=12323/24659/40973，D=71/103/137，T=134/199/264
 *   密钥生成：seed[0] → Fisher-Yates 采样 h0,h1（各 D 个 1）
 *             → pk = h = h1 · h0⁻¹ mod (x^R − 1)
 *   封装：m = seed[0]；e = H(m)；c0 = e0 + e1·h；c1 = m ⊕ L(e)；ss = K(m, C)
 *   解封装：BGF 译码还原 e → 校验 H(m') == (e0',e1') → ss = K(m', C)
 *
 * 参照物：编译 liboqs additional_r4 官方源码 + 确定性 splitmix64 产出的 KAT
 *         dist/testvectors/bike_l{1,3,5}.txt（SK/PK/CT/SS 四段齐全）
 * ============================================================ */
(function () {
  'use strict';

  var PARAMS = {
    1: { R_BITS: 12323, D: 71, T: 134 },
    3: { R_BITS: 24659, D: 103, T: 199 },
    5: { R_BITS: 40973, D: 137, T: 264 }
  };

  /* ---------- GF(2)[x] 多项式：Uint32Array，bit i = w[i>>5] 的第 (i&31) 位 ---------- */
  function pNew(nbits) { return new Uint32Array((nbits + 31) >> 5); }
  function pDeg(a) {
    for (var i = a.length - 1; i >= 0; i--) if (a[i]) return i * 32 + (31 - Math.clz32(a[i]));
    return -1;
  }
  function pZero(a) { for (var i = 0; i < a.length; i++) if (a[i]) return false; return true; }
  function pXorShift(b, a, k) {          // b ^= (a << k)
    var wq = k >> 5, br = k & 31, i;
    if (br === 0) { for (i = 0; i < a.length; i++) b[i + wq] ^= a[i]; }
    else {
      for (i = 0; i < a.length; i++) {
        b[i + wq] ^= a[i] << br;
        b[i + wq + 1] ^= a[i] >>> (32 - br);
      }
    }
  }
  /* 约简 mod (x^R − 1)：deg ≥ R 的项折叠回 p−R（因 x^R ≡ 1） */
  function pReduce(a, R) {
    var out = pNew(R);
    var lim = Math.min(a.length * 32, 2 * R + 64), p;
    for (p = lim - 1; p >= R; p--) {
      if ((a[p >> 5] >>> (p & 31)) & 1) { var q = p - R; out[q >> 5] ^= 1 << (q & 31); }
    }
    var top = Math.min(R, lim);
    for (p = 0; p < top; p++) {
      if ((a[p >> 5] >>> (p & 31)) & 1) out[p >> 5] ^= 1 << (p & 31);
    }
    return out;
  }
  /* c = a·b mod (x^R−1)；b 稀疏时最快（只按 b 的置位做 shift-add） */
  function pMul(a, b, R) {
    var acc = new Uint32Array(((2 * R + 63) >> 5) + 2);
    var lim = Math.min(b.length * 32, R);
    for (var p = 0; p < lim; p++) {
      if ((b[p >> 5] >>> (p & 31)) & 1) pXorShift(acc, a, p);
    }
    return pReduce(acc, R);
  }
  /* 扩展欧几里得求 a⁻¹ mod (x^R−1)；要求 gcd(a, x^R−1)=1 */
  function pInv(a, R) {
    var nw = pNew(2 * R + 96).length;
    var r = new Uint32Array(nw), nr = new Uint32Array(nw);
    var s = new Uint32Array(nw), ns = new Uint32Array(nw);
    r[0] = 1; r[R >> 5] |= 1 << (R & 31);      // r = x^R + 1
    nr.set(a);                                  // nr = a
    ns[0] = 1;                                  // s=0, ns=1
    var guard = 0;
    while (!pZero(nr)) {
      var dr = pDeg(r), dn = pDeg(nr), t;
      if (dr < dn) { t = r; r = nr; nr = t; t = s; s = ns; ns = t; dr = pDeg(r); dn = pDeg(nr); }
      var k = dr - dn;
      pXorShift(r, nr, k);
      pXorShift(s, ns, k);
      if (++guard > 4 * R + 128) throw new Error('BIKE pInv: 未收敛');
    }
    if (pDeg(r) !== 0) throw new Error('BIKE pInv: gcd≠1（h0 不可逆，需换种子）');
    return pReduce(s, R);
  }

  /* ---------- SHAKE256 PRF（复刻 shake_prf.c：136 字节块，不跨块） ---------- */
  function Prf(seed) { this.s = { seed: seed, buf: new Uint8Array(0), pos: 0 }; this.curr = 136; this.buf = null; }
  Prf.prototype._read = function (n) {
    var s = this.s;
    if (s.pos + n > s.buf.length) {
      var want = s.pos + n, len = Math.max(136 * 8, s.buf.length * 2);
      while (len < want) len *= 2;
      s.buf = shake256Digest(s.seed, len, 136);
    }
    var o = s.buf.slice(s.pos, s.pos + n); s.pos += n; return o;
  };
  Prf.prototype.out = function (len) {
    if (len + this.curr <= 136) { var o = this.buf.slice(this.curr, this.curr + len); this.curr += len; return o; }
    this.buf = this._read(136);
    var r = this.buf.slice(0, len); this.curr = len; return r;
  };
  /* 32×32 乘法取高 32 位（mid<<16 在 JS 会 32 位截断，必须用乘法） */
  function mulHi(a, b) {
    var a0 = a & 0xffff, a1 = a >>> 16, b0 = b & 0xffff, b1 = b >>> 16;
    var p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    var mid = p01 + p10;
    var t = p00 + ((mid & 0xffff) * 65536);
    return (p11 + (mid >>> 16) + Math.floor(t / 4294967296)) >>> 0;
  }
  /* sample_indices_fisher_yates：倒序，每次 4 字节，rand *= (max−i)，取高 32 位 */
  function fisherYates(num, max, prf) {
    var out = new Uint32Array(num);
    for (var i = num; i-- > 0;) {
      var b = prf.out(4);
      var rand = (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
      var l = (i + mulHi(rand, max - i)) >>> 0;
      var dup = 0;
      for (var j = i + 1; j < num; j++) if (l === out[j]) { dup = 1; break; }
      out[i] = dup ? i : l;
    }
    return out;
  }

  /* ---------- 字节 ↔ 位向量 ---------- */
  function bitsFromBytes(bytes, nbits) {
    var w = pNew(nbits), n = Math.min(bytes.length * 8, nbits);
    for (var i = 0; i < n; i++) if ((bytes[i >> 3] >>> (i & 7)) & 1) w[i >> 5] |= 1 << (i & 31);
    return w;
  }
  function bytesFromBits(w, nbytes) {
    var out = new Uint8Array(nbytes);
    for (var i = 0; i < nbytes * 8; i++) if ((w[i >> 5] >>> (i & 31)) & 1) out[i >> 3] |= 1 << (i & 7);
    return out;
  }
  function setBitsVec(w, wlist, firstPos, R) {   // secure_set_bits：w = idx − firstPos，越界丢弃
    for (var i = 0; i < wlist.length; i++) {
      var j = wlist[i] - firstPos;
      if (j >= 0 && j < R) w[j >> 5] |= 1 << (j & 31);
    }
  }
  function wlistToBytes(wl) {
    var b = new Uint8Array(wl.length * 4);
    for (var i = 0; i < wl.length; i++) {
      b[i * 4] = wl[i] & 0xff; b[i * 4 + 1] = (wl[i] >>> 8) & 0xff;
      b[i * 4 + 2] = (wl[i] >>> 16) & 0xff; b[i * 4 + 3] = (wl[i] >>> 24) & 0xff;
    }
    return b;
  }
  function concat2() {
    var n = 0, i;
    for (i = 0; i < arguments.length; i++) n += arguments[i].length;
    var o = new Uint8Array(n), p = 0;
    for (i = 0; i < arguments.length; i++) { o.set(arguments[i], p); p += arguments[i].length; }
    return o;
  }

  /* ---------- 密钥生成 ---------- */
  function bikeKeygen(level, seeds) {
    var P = PARAMS[level]; if (!P) throw new Error('BIKE LEVEL 只支持 1 / 3 / 5');
    var R = P.R_BITS, D = P.D, RB = Math.ceil(R / 8);
    var prf = new Prf(seeds.subarray(0, 32));
    var w0 = fisherYates(D, R, prf), w1 = fisherYates(D, R, prf);
    var h0 = pNew(R), h1 = pNew(R);
    setBitsVec(h0, w0, 0, R);
    setBitsVec(h1, w1, 0, R);
    var h0inv = pInv(h0, R);
    var h = pMul(h0inv, h1, R);            // pk = h1 · h0⁻¹
    var b0 = bytesFromBits(h0, RB), b1 = bytesFromBits(h1, RB), bpk = bytesFromBits(h, RB);
    var sk = concat2(wlistToBytes(w0), wlistToBytes(w1), b0, b1, bpk, seeds.subarray(32, 64));
    return { pk: bpk, sk: sk, h0: b0, h1: b1 };
  }

  /* ---------- 封装 ---------- */
  function bikeEncaps(pkBytes, level, seeds) {
    var P = PARAMS[level]; if (!P) throw new Error('BIKE LEVEL 只支持 1 / 3 / 5');
    var R = P.R_BITS, T = P.T, RB = Math.ceil(R / 8), N = 2 * R;
    var m = seeds.subarray(0, 32);
    var prf = new Prf(m);
    var wl = fisherYates(T, N, prf);
    var e0 = pNew(R), e1 = pNew(R);
    setBitsVec(e0, wl, 0, R);
    setBitsVec(e1, wl, R, R);              // first_pos = R_BITS
    var h = bitsFromBytes(pkBytes, R);
    var c0 = pMul(h, e1, R);               // e1·h
    for (var i = 0; i < c0.length; i++) c0[i] ^= e0[i];   // + e0
    var b0 = bytesFromBits(e0, RB), b1 = bytesFromBits(e1, RB);
    var L = sha3Hash(384, concat2(b0, b1), 32);           // L(e) = SHA3-384(e0‖e1)[:32]
    var c1 = new Uint8Array(32);
    for (i = 0; i < 32; i++) c1[i] = L[i] ^ m[i];
    var bc0 = bytesFromBits(c0, RB);
    var ss = sha3Hash(384, concat2(m, bc0, c1), 32);      // K(m, C)
    return { ct: concat2(bc0, c1), ss: ss, e0: b0, e1: b1, m: m };
  }

  /* ---------- BGF 译码（Black-Gray-Flip，MAX_IT = 5） ---------- */
  var THR = {
    1: { c0: 1353000000, c1: 697220, min: 36 },
    3: { c0: 1525880000, c1: 526500, min: 52 },
    5: { c0: 1787850000, c1: 402312, min: 69 }
  };
  var MUL_CONST = 12379400392853802749n, SHR_CONST = 26, DELTA = 3, MAX_IT = 5;
  // defs.h: LOG2_MSB(v) 是最高位的 1-based 位置；LOG2_MSB(1)=1、LOG2_MSB(2)=2
  function LOG2_MSB(v) { return v === 0 ? 0 : (32 - Math.clz32(v)); }

  /* 循环右移 k 位（在 R 位内）：out[j] = s[(j+k) mod R]
     ⚠ R 不是 32 的整数倍（如 12323 = 385×32+3），第二份不能按 word 直接复制，
       否则 word 385 的 bit 3 之后是 0 而不是 s[0]，循环在填充位处断开。
       必须按 off = R mod 32 移位拼接（这正是 dup_port() 里那一步的作用）。 */
  function rotRight(out, s, k, R) {
    var NW = s.length, off = R & 31, base = R >> 5, i;
    var ss = new Uint32Array(NW * 2 + 3);
    ss.set(s, 0);
    for (i = 0; i <= NW; i++) {
      var lo = off === 0 ? 0 : ((i > 0 ? s[i - 1] : 0) >>> (32 - off));
      var hi = (off === 0 ? (s[i] || 0) : ((s[i] || 0) << off));
      ss[base + i] |= lo | hi;
    }
    for (var j = 0; j < NW; j++) {
      var srcBit = j * 32 + k, w = srcBit >> 5, b = srcBit & 31;
      out[j] = b === 0 ? ss[w] : ((ss[w] >>> b) | (ss[w + 1] << (32 - b)));
    }
    maskTop(out, R);
  }
  function maskTop(w, R) {                 // 清掉 ≥ R 的位
    var last = R & 31;
    if (last) w[(R >> 5)] &= (1 << last) - 1;
    for (var i = (R >> 5) + 1; i < w.length; i++) w[i] = 0;
  }
  /* 半加器累加：把 rs 加到 upc 的第 j 层，进位传到上层（rs 被改写为进位） */
  function slicedAdder(upc, rs, numSlices, NW) {
    for (var j = 0; j < numSlices && j < upc.length; j++) {
      var u = upc[j];
      for (var i = 0; i < NW; i++) {
        var carry = u[i] & rs[i];
        u[i] ^= rs[i];
        rs[i] = carry;
      }
    }
  }
  /* upc 各层减去 val（位切片全减器，带借位传播） */
  function slicedSubtract(upc, val, NW) {
    var br = new Uint32Array(NW);
    for (var j = 0; j < upc.length; j++) {
      var b = (val & 1) ? 0xffffffff : 0, u = upc[j];
      val >>= 1;
      for (var i = 0; i < NW; i++) {
        var a = u[i];
        var tmp = ((~a) & b & (~br[i])) | (((~a) | b) & br[i]);
        u[i] = a ^ b ^ br[i];
        br[i] = tmp;
      }
    }
  }
  function getThreshold(s, level, R) {
    var t = THR[level];
    var w = 0;
    for (var i = 0; i < R; i++) if ((s[i >> 5] >>> (i & 31)) & 1) w++;
    var thr = BigInt(t.c0) + BigInt(t.c1) * BigInt(w);
    var a = thr, b = MUL_CONST;
    var a_lo = a & 0xffffffffn, a_hi = a >> 32n, b_lo = b & 0xffffffffn, b_hi = b >> 32n;
    var hi = a_hi * b_hi + ((a_hi * b_lo + a_lo * b_hi) >> 32n);   // MUL64HIGH
    var v = Number(hi >> BigInt(SHR_CONST));
    return Math.max(v, t.min);
  }
  function lastMask(R) { var m = R % 8; return m ? ((1 << m) - 1) : 0xff; }

  function findErr1(e, blackE, grayE, s, wlist, threshold, R, RB, SLICES) {
    var NW = pNew(R).length;
    var upc = [], j;
    for (j = 0; j < SLICES; j++) upc.push(new Uint32Array(NW));
    var rs = new Uint32Array(NW);
    for (var i = 0; i < 2; i++) {
      for (j = 0; j < SLICES; j++) upc[j].fill(0);
      // ⚠ wlist 是 [w0, w1] 两层，长度 2；每层内部才是 D 个索引
      for (j = 0; j < wlist[i].length; j++) {
        rotRight(rs, s, wlist[i][j], R);
        slicedAdder(upc, rs, LOG2_MSB(j + 1), NW);
      }
      slicedSubtract(upc, threshold, NW);
      var last = upc[SLICES - 1];
      for (j = 0; j < RB; j++) {
        var sm = (~bytesFromWord(last, j)) & 0xff;
        blackE[i][j] = sm;
        e[i][j] ^= sm;
      }
      e[i][RB - 1] &= lastMask(R);
      for (var l = 0; l < DELTA; l++) {
        rs.fill(0xffffffff); maskTop(rs, R);
        slicedAdder(upc, rs, SLICES, NW);
      }
      for (j = 0; j < RB; j++) {
        var sm2 = (~bytesFromWord(last, j)) & 0xff;
        grayE[i][j] = (~blackE[i][j]) & sm2;
      }
    }
    return upc;
  }
  function findErr2(e, posE, s, wlist, threshold, R, RB, SLICES) {
    var NW = pNew(R).length, upc = [], j;
    for (j = 0; j < SLICES; j++) upc.push(new Uint32Array(NW));
    var rs = new Uint32Array(NW);
    for (var i = 0; i < 2; i++) {
      for (j = 0; j < SLICES; j++) upc[j].fill(0);
      // ⚠ wlist 是 [w0, w1] 两层，长度 2；每层内部才是 D 个索引
      for (j = 0; j < wlist[i].length; j++) {
        rotRight(rs, s, wlist[i][j], R);
        slicedAdder(upc, rs, LOG2_MSB(j + 1), NW);
      }
      slicedSubtract(upc, threshold, NW);
      var last = upc[SLICES - 1];
      for (j = 0; j < RB; j++) {
        e[i][j] ^= (posE[i][j] & ((~bytesFromWord(last, j)) & 0xff));
      }
      e[i][RB - 1] &= lastMask(R);
    }
  }
  /* 从第 j 字节取 upc 末层的值 */
  function bytesFromWord(w, j) { return (w[j >> 2] >>> (8 * (j & 3))) & 0xff; }

  function parseSk(skBytes, level) {
    var P = PARAMS[level], R = P.R_BITS, D = P.D, RB = Math.ceil(R / 8);
    var wl = [[], []], p = 0, i;
    for (i = 0; i < 2 * D; i++) {
      var v = skBytes[p] | (skBytes[p + 1] << 8) | (skBytes[p + 2] << 16) | (skBytes[p + 3] << 24);
      p += 4; wl[i < D ? 0 : 1].push(v >>> 0);
    }
    var h0 = bitsFromBytes(skBytes.subarray(p, p + RB), R); p += RB;
    var h1 = bitsFromBytes(skBytes.subarray(p, p + RB), R); p += RB;
    var pk = bitsFromBytes(skBytes.subarray(p, p + RB), R); p += RB;
    var sigma = skBytes.subarray(p, p + 32); p += 32;
    return { wlist: wl, h0: h0, h1: h1, pk: pk, sigma: sigma, R: R, RB: RB };
  }

  function bikeDecaps(skBytes, ctBytes, level) {
    var P = PARAMS[level]; if (!P) throw new Error('BIKE LEVEL 只支持 1 / 3 / 5');
    var R = P.R_BITS, D = P.D, T = P.T, RB = Math.ceil(R / 8);
    var SL = LOG2_MSB(D) + 1;
    var K = parseSk(skBytes, level);
    var c0 = bitsFromBytes(ctBytes.subarray(0, RB), R);
    var c1 = ctBytes.subarray(RB, RB + 32);
    // s = c0·h0
    var s = pMul(c0, K.h0, R);
    var e = [new Uint8Array(RB), new Uint8Array(RB)];
    var black = [new Uint8Array(RB), new Uint8Array(RB)];
    var gray = [new Uint8Array(RB), new Uint8Array(RB)];
    function recompute() {
      var eb = [bitsFromBytes(e[0], R), bitsFromBytes(e[1], R)];
      var tmp = pMul(K.pk, eb[1], R);
      for (var i = 0; i < tmp.length; i++) tmp[i] ^= c0[i] ^ eb[0][i];
      s = pMul(tmp, K.h0, R);
    }
    for (var it = 0; it < MAX_IT; it++) {
      var thr = getThreshold(s, level, R);
      findErr1(e, black, gray, s, K.wlist, thr, R, RB, SL);
      recompute();
      if (it >= 1) continue;
      var th2 = ((D + 1) >> 1) + 1;
      findErr2(e, black, s, K.wlist, th2, R, RB, SL);
      recompute();
      findErr2(e, gray, s, K.wlist, th2, R, RB, SL);
      recompute();
    }
    // m' = c1 ⊕ L(e)
    var L = sha3Hash(384, concat2(e[0], e[1]), 32);
    var mp = new Uint8Array(32);
    for (var i = 0; i < 32; i++) mp[i] = L[i] ^ c1[i];
    // 校验 H(m') == (e0',e1')，失败则用 sigma（隐式拒绝）
    var prf = new Prf(mp), wl2 = fisherYates(T, 2 * R, prf);
    var t0 = pNew(R), t1 = pNew(R);
    setBitsVec(t0, wl2, 0, R); setBitsVec(t1, wl2, R, R);
    var b0 = bytesFromBits(t0, RB), b1 = bytesFromBits(t1, RB);
    b0[RB - 1] &= lastMask(R); b1[RB - 1] &= lastMask(R);
    var ok = true;
    for (i = 0; i < RB; i++) if (b0[i] !== e[0][i] || b1[i] !== e[1][i]) { ok = false; break; }
    if (!ok) mp = K.sigma.slice(0, 32);
    var ss = sha3Hash(384, concat2(mp, ctBytes.subarray(0, RB), c1), 32);
    return { ss: ss, m: mp, ok: ok, e0: e[0], e1: e[1] };
  }

  /* ---------- 界面条目注册（isKem：gen / enc / dec 一体） ---------- */
  if (typeof reg === 'function') {
    var NAME = { 1: 'BIKE-L1', 3: 'BIKE-L3', 5: 'BIKE-L5' };
    [1, 3, 5].forEach(function (L) {
      var P = PARAMS[L], RB = Math.ceil(P.R_BITS / 8);
      var SKLEN = 2 * P.D * 4 + 3 * RB + 32, CTLEN = RB + 32;
      reg({
        id: 'bike' + L, name: NAME[L] + '（后量子 KEM · 码基）', group: '后量子密码',
        key: true, param: false,
        keyLabel: '封装填对方公钥（Hex）；解封装填自己的私钥（Hex）',
        isKem: true, kemK: L,
        info: NAME[L] + '：NIST Round 4 附加候选，基于 QC-MDPC 准循环中密度校验码，' +
          '格路线之外的备份。R=' + P.R_BITS + '，D=' + P.D + '，T=' + P.T + '。' +
          '公钥 ' + RB + ' B、私钥 ' + SKLEN + ' B、密文 ' + CTLEN + ' B、共享密钥 32 B。' +
          '已用编译官方源码产出的确定性 KAT 逐字节验证（含 BGF 译码 5 轮迭代）。',
        gen: function () {
          var kp = bikeKeygen(L, crypto.getRandomValues(new Uint8Array(64)));
          return { pub: bytesToHex(kp.pk), priv: bytesToHex(kp.sk) };
        },
        enc: function (b, kk, pp, fmt) {
          if (!kk) throw new Error('请先在密钥栏填入对方的封装公钥（Hex），或先点【生成密钥】');
          var pk = hexToBytes(String(kk).replace(/\s/g, ''));
          if (pk.length !== RB) throw new Error('公钥长度不对，应为 ' + RB + ' 字节');
          var e = bikeEncaps(pk, L, crypto.getRandomValues(new Uint8Array(64)));
          return bytesOut(e.ct, fmt) + '\n::K::' + bytesOut(e.ss, fmt);
        },
        dec: function (str, kk, pp, fmt) {
          if (!kk) throw new Error('请在密钥栏填入自己的解封装私钥（Hex）');
          var c = bytesIn(String(str).split('::K::')[0].trim(), fmt);
          var sk = hexToBytes(String(kk).replace(/\s/g, ''));
          if (sk.length !== SKLEN) throw new Error('私钥长度不对，应为 ' + SKLEN + ' 字节');
          if (c.length !== CTLEN) throw new Error('密文长度不对，应为 ' + CTLEN + ' 字节');
          var r = bikeDecaps(sk, c, L);
          if (!r.ok) throw new Error('译码未通过校验（返回的是隐式拒绝值 sigma）');
          return bytesOut(r.ss, fmt);
        }
      });
    });
  }

  if (typeof globalThis !== 'undefined') {
    globalThis.bikeKeygen = bikeKeygen;
    globalThis.bikeEncaps = bikeEncaps;
    globalThis.bikeDecaps = bikeDecaps;
    globalThis.BIKE_PARAMS = PARAMS;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { bikeKeygen: bikeKeygen, bikeEncaps: bikeEncaps, PARAMS: PARAMS };
  }
})();
