/* FrodoKEM-640-SHAKE（格基 KEM，ISO/IEC 18033-2 Amd.2 已标准化）
   逐行移植自 liboqs 内置官方实现：
     ext/frodo/kem.c                        主流程 keypair / encaps / decaps
     ext/noise.c                            frodo_sample_n（CDF 采样）
     ext/util.c                             pack / unpack / ct_verify / ct_select
     ext/frodo_macrify_reference.c          frodo_mul_add_as_plus_e（A 按行生成）
     ext/frodo_macrify_shake_portable.c     frodo_mul_add_sa_plus_e（A 按列生成）
     ext/frodo_macrify_optimized.c          mul_bs / mul_add_sb_plus_e / add / sub / key_encode / key_decode
   参考源码已随包保存在 work/ref/frodo/（含可复现的确定性随机数）。
   规格: https://frodokem.org                                                   */
(function () {
  'use strict';
  var N = 640, NBAR = 8, LOGQ = 15, EXTRACTED_BITS = 2;
  var MASKQ = (1 << LOGQ) - 1;                       // 32767
  var BYTES_SEED_A = 16, BYTES_MU = 16, BYTES_SALT = 32;
  var BYTES_SEED_SE = 32, BYTES_PKHASH = 16, SS_BYTES = 16;
  var PK_BYTES = 9616, SK_BYTES = 19888, CT_BYTES = 9752;
  var B_BYTES = (LOGQ * N * NBAR) / 8;               // 9600
  var C2_BYTES = (LOGQ * NBAR * NBAR) / 8;           // 120

  /* CDF 表（取自 frodo640shake_params.h 原文） */
  var CDF = [4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767];

  /* ---------- Keccak-f[1600] + SHAKE128（rate 168） ---------- */
  var M64 = 0xFFFFFFFFFFFFFFFFn;
  var RCk = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808An, 0x8000000080008000n,
    0x000000000000808Bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008An, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000An,
    0x000000008000808Bn, 0x800000000000008Bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800An, 0x800000008000000An,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n];
  var ROTk = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

  function rotl64(x, n) { n = BigInt(n); if (n === 0n) return x; return ((x << n) | (x >> (64n - n))) & M64; }
  function keccakF(A) {
    var C = new Array(5), B = new Array(25), x, y, i, rnd, d;
    for (rnd = 0; rnd < 24; rnd++) {
      for (x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
      for (x = 0; x < 5; x++) {
        d = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        for (y = 0; y < 5; y++) A[x + 5 * y] ^= d;
      }
      for (i = 0; i < 25; i++) {
        x = i % 5; y = (i / 5) | 0;
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(A[i], ROTk[i]);
      }
      for (y = 0; y < 5; y++) for (x = 0; x < 5; x++) {
        A[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y] & M64) & B[((x + 2) % 5) + 5 * y]);
      }
      A[0] ^= RCk[rnd];
    }
  }
  /* FIPS 202 的 SHAKE：域分隔 0x1F，rate 168 */
  function shake128(input, outLen) {
    var rate = 168, A = new Array(25), i, j, lane, off;
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
        for (j = 0; j < 8; j++) lane |= BigInt(padded[off + i * 8 + j]) << BigInt(8 * j);
        A[i] ^= lane;
      }
      keccakF(A);
    }
    var out = new Uint8Array(outLen), p = 0, blk = new Uint8Array(rate);
    while (p < outLen) {
      for (i = 0; i < rate / 8; i++)
        for (j = 0; j < 8; j++) blk[i * 8 + j] = Number((A[i] >> BigInt(8 * j)) & 0xFFn);
      var take = outLen - p; if (take > rate) take = rate;
      for (i = 0; i < take; i++) out[p + i] = blk[i];
      p += take;
      if (p < outLen) keccakF(A);
    }
    return out;
  }

  /* ---------- 噪声采样（noise.c） ---------- */
  function sampleN(s, n) {
    for (var i = 0; i < n; i++) {
      var prnd = s[i] >> 1, sign = s[i] & 1, sample = 0, j;
      for (j = 0; j < CDF.length - 1; j++) {
        /* C: (uint16_t)(cdf[j] - prnd) >> 15 —— 差为负时靠 uint16 回绕得到 1 */
        sample += (((CDF[j] - prnd) & 0xFFFF) >>> 15);
      }
      s[i] = sign ? ((65536 - sample) & 0xFFFF) : sample;
    }
  }

  /* ---------- pack / unpack（util.c） ---------- */
  function frodoPack(out, inn, inlen, lsb) {
    out.fill(0);
    var outlen = out.length, i = 0, j = 0, w = 0, bits = 0;
    while (i < outlen && (j < inlen || ((j === inlen) && bits > 0))) {
      var b = 0;
      while (b < 8) {
        var nbits = Math.min(8 - b, bits);
        var mask = (1 << nbits) - 1;
        var t = (w >> (bits - nbits)) & mask;
        out[i] = out[i] + (t << (8 - b - nbits));
        b += nbits; bits -= nbits;
        w &= (~(mask << bits)) & 0xFFFF;
        if (bits === 0) {
          if (j < inlen) { w = inn[j]; bits = lsb; j++; }
          else break;
        }
      }
      if (b === 8) i++;
    }
  }
  function frodoUnpack(out, outlen, inn, inlen, lsb) {
    for (var q = 0; q < outlen; q++) out[q] = 0;
    var i = 0, j = 0, w = 0, bits = 0;
    while (i < outlen && (j < inlen || ((j === inlen) && bits > 0))) {
      var b = 0;
      while (b < lsb) {
        var nbits = Math.min(lsb - b, bits);
        var mask = (1 << nbits) - 1;
        var t = (w >> (bits - nbits)) & mask;
        out[i] = out[i] + (t << (lsb - b - nbits));
        b += nbits; bits -= nbits;
        w &= (~(mask << bits)) & 0xFF;
        if (bits === 0) {
          if (j < inlen) { w = inn[j]; bits = 8; j++; }
          else break;
        }
      }
      if (b === lsb) i++;
    }
  }
  function ctVerify(a, b, len) {
    var r = 0;
    for (var i = 0; i < len; i++) r |= a[i] ^ b[i];
    return r === 0 ? 0 : -1;
  }
  function ctSelect(a, b, len, selector) {
    var r = new Uint8Array(len);
    for (var i = 0; i < len; i++) r[i] = (selector === 0 ? a[i] : b[i]) & 0xFF;
    return r;
  }

  /* ---------- A 矩阵生成 + 乘加（reference / shake_portable） ---------- */
  /* A 按行：第 i 行 = SHAKE128(LE16(i) || seedA, 2N)。用于 B = A*S + E */
  function mulAddAsPlusE(out, s, e, seedA) {
    var seedSep = new Uint8Array(2 + BYTES_SEED_A);
    seedSep.set(seedA, 2);
    var A = new Uint16Array(N * N), row = new Uint8Array(2 * N);
    for (var i = 0; i < N; i++) {
      seedSep[0] = i & 0xFF; seedSep[1] = (i >> 8) & 0xFF;
      row = shake128(seedSep, 2 * N);
      for (var j = 0; j < N; j++) A[i * N + j] = row[2 * j] | (row[2 * j + 1] << 8);
    }
    out.set(e.subarray(0, N * NBAR));
    for (i = 0; i < N; i++) {
      var base = i * N;
      for (var k = 0; k < NBAR; k++) {
        var sum = 0, sk = k * N;
        for (j = 0; j < N; j++) sum = (sum + A[base + j] * s[sk + j]) & 0xFFFF;
        out[i * NBAR + k] = (out[i * NBAR + k] + sum) & 0xFFFF;
      }
    }
  }
  /* A 按列：第 c 列 = SHAKE128(LE16(c) || seedA, 2N)。用于 Bp = Sp*A + Ep */
  function mulAddSaPlusE(out, s, e, seedA) {
    var seedSep = new Uint8Array(2 + BYTES_SEED_A);
    seedSep.set(seedA, 2);
    var col = new Uint8Array(2 * N), ac = new Uint16Array(N);
    out.set(e.subarray(0, N * NBAR));
    for (var c = 0; c < N; c++) {
      seedSep[0] = c & 0xFF; seedSep[1] = (c >> 8) & 0xFF;
      col = shake128(seedSep, 2 * N);
      for (var k = 0; k < N; k++) ac[k] = col[2 * k] | (col[2 * k + 1] << 8);
      for (var i = 0; i < NBAR; i++) {
        var sp = s[i * N + c], ob = i * N;
        for (k = 0; k < N; k++) out[ob + k] = (out[ob + k] + sp * ac[k]) & 0xFFFF;
      }
    }
  }
  /* out = b*s，b(NBAR x N) 行优先，s(N x NBAR) 由 s[j*N+k] 索引 */
  function mulBs(out, b, s) {
    for (var i = 0; i < NBAR; i++) {
      for (var j = 0; j < NBAR; j++) {
        var acc = 0;
        for (var k = 0; k < N; k++) acc = (acc + b[i * N + k] * s[j * N + k]) & 0xFFFF;
        out[i * NBAR + j] = acc & MASKQ;
      }
    }
  }
  /* out = s*b + e，s(NBAR x N)，b(N x NBAR) 行优先 */
  function mulAddSbPlusE(out, b, s, e) {
    for (var k = 0; k < NBAR; k++) {
      for (var i = 0; i < NBAR; i++) {
        var acc = e[k * NBAR + i];
        for (var j = 0; j < N; j++) acc = (acc + s[k * N + j] * b[j * NBAR + i]) & 0xFFFF;
        out[k * NBAR + i] = acc & MASKQ;
      }
    }
  }
  function frodoAdd(out, a, b) {
    for (var i = 0; i < NBAR * NBAR; i++) out[i] = (a[i] + b[i]) & MASKQ;
  }
  function frodoSub(out, a, b) {
    for (var i = 0; i < NBAR * NBAR; i++) out[i] = (a[i] - b[i]) & MASKQ;
  }
  function keyEncode(out, innBytes) {
    var nwords = (NBAR * NBAR) / 8, pos = 0, i, j;
    for (i = 0; i < nwords; i++) {
      var temp = innBytes[i * EXTRACTED_BITS] | (innBytes[i * EXTRACTED_BITS + 1] << 8);
      for (j = 0; j < 8; j++) {
        out[pos++] = ((temp & 3) << (LOGQ - EXTRACTED_BITS)) & 0xFFFF;
        temp >>= EXTRACTED_BITS;
      }
    }
  }
  function keyDecode(outBytes, inn) {
    var nwords = (NBAR * NBAR) / 8, index = 0, i, j;
    for (i = 0; i < nwords; i++) {
      var templong = 0;
      for (j = 0; j < 8; j++) {
        var temp = ((inn[index] & MASKQ) + (1 << (LOGQ - EXTRACTED_BITS - 1))) >> (LOGQ - EXTRACTED_BITS);
        templong |= (temp & 3) * Math.pow(2, EXTRACTED_BITS * j);
        index++;
      }
      for (j = 0; j < EXTRACTED_BITS; j++) outBytes[i * EXTRACTED_BITS + j] = (templong >>> (8 * j)) & 0xFF;
    }
  }

  /* ---------- 主流程（kem.c） ---------- */
  function keypair(rnd) {
    var pk = new Uint8Array(PK_BYTES), sk = new Uint8Array(SK_BYTES);
    var B = new Uint16Array(N * NBAR);
    var Sbuf = new Uint16Array(2 * N * NBAR);
    var r = rnd(SS_BYTES + BYTES_SEED_SE + BYTES_SEED_A);
    var s = r.subarray(0, SS_BYTES), seedSE = r.subarray(SS_BYTES, SS_BYTES + BYTES_SEED_SE);
    var z = r.subarray(SS_BYTES + BYTES_SEED_SE);
    var seedA = shake128(z, BYTES_SEED_A);
    pk.set(seedA, 0);

    var shakeIn = new Uint8Array(1 + BYTES_SEED_SE);
    shakeIn[0] = 0x5F; shakeIn.set(seedSE, 1);
    var raw = shake128(shakeIn, 2 * N * NBAR * 2);
    for (var i = 0; i < 2 * N * NBAR; i++) Sbuf[i] = raw[2 * i] | (raw[2 * i + 1] << 8);
    var E = Sbuf.subarray(N * NBAR);
    sampleN(Sbuf, N * NBAR);
    sampleN(E, N * NBAR);
    mulAddAsPlusE(B, Sbuf, E, seedA);
    frodoPack(pk.subarray(BYTES_SEED_A), B, N * NBAR, LOGQ);

    sk.set(s, 0);
    sk.set(pk, SS_BYTES);
    /* sk_S 只存 S 的前 N*NBAR 个 uint16（= 2*N*NBAR 字节），不含 E；
       C 里 memcpy(sk_S, S, 2*PARAMS_N*PARAMS_NBAR) 的单位是字节，极易写成 2 倍长度 */
    var rawS = new Uint8Array(2 * N * NBAR);
    for (i = 0; i < N * NBAR; i++) { rawS[2 * i] = Sbuf[i] & 0xFF; rawS[2 * i + 1] = (Sbuf[i] >> 8) & 0xFF; }
    sk.set(rawS, SS_BYTES + PK_BYTES);
    var pkh = shake128(pk, BYTES_PKHASH);
    sk.set(pkh, SS_BYTES + PK_BYTES + 2 * N * NBAR);
    return { pk: pk, sk: sk };
  }

  function encaps(pk, rnd) {
    if (pk.length !== PK_BYTES) throw new Error('公钥长度应为 ' + PK_BYTES + ' 字节');
    var seedA = pk.subarray(0, BYTES_SEED_A), pkB = pk.subarray(BYTES_SEED_A);
    var ct = new Uint8Array(CT_BYTES);
    var B = new Uint16Array(N * NBAR), V = new Uint16Array(NBAR * NBAR), C = new Uint16Array(NBAR * NBAR);
    var Bp = new Uint16Array(N * NBAR), Sp = new Uint16Array((2 * N + NBAR) * NBAR);
    var Ep = Sp.subarray(N * NBAR), Epp = Sp.subarray(2 * N * NBAR);

    var pkh = shake128(pk, BYTES_PKHASH);
    var G2in = new Uint8Array(BYTES_PKHASH + BYTES_MU + BYTES_SALT);
    G2in.set(pkh, 0);
    var ms = rnd(BYTES_MU + BYTES_SALT);
    G2in.set(ms, BYTES_PKHASH);
    var salt = G2in.subarray(BYTES_PKHASH + BYTES_MU);
    var G2out = shake128(G2in, BYTES_SEED_SE + SS_BYTES);
    var seedSE = G2out.subarray(0, BYTES_SEED_SE), k = G2out.subarray(BYTES_SEED_SE);

    var shakeIn = new Uint8Array(1 + BYTES_SEED_SE);
    shakeIn[0] = 0x96; shakeIn.set(seedSE, 1);
    var raw = shake128(shakeIn, (2 * N + NBAR) * NBAR * 2);
    for (var i = 0; i < (2 * N + NBAR) * NBAR; i++) Sp[i] = raw[2 * i] | (raw[2 * i + 1] << 8);
    sampleN(Sp, N * NBAR);
    sampleN(Ep, N * NBAR);
    mulAddSaPlusE(Bp, Sp, Ep, seedA);
    frodoPack(ct.subarray(0, B_BYTES), Bp, N * NBAR, LOGQ);

    sampleN(Epp, NBAR * NBAR);
    frodoUnpack(B, N * NBAR, pkB, PK_BYTES - BYTES_SEED_A, LOGQ);
    mulAddSbPlusE(V, B, Sp, Epp);

    var mu = G2in.subarray(BYTES_PKHASH, BYTES_PKHASH + BYTES_MU);
    keyEncode(C, mu);
    frodoAdd(C, V, C);
    frodoPack(ct.subarray(B_BYTES, B_BYTES + C2_BYTES), C, NBAR * NBAR, LOGQ);

    ct.set(salt, CT_BYTES - BYTES_SALT);
    var Fin = new Uint8Array(CT_BYTES + SS_BYTES);
    Fin.set(ct, 0); Fin.set(k, CT_BYTES);
    return { ct: ct, ss: shake128(Fin, SS_BYTES) };
  }

  function decaps(ct, sk) {
    if (ct.length !== CT_BYTES) throw new Error('密文长度应为 ' + CT_BYTES + ' 字节');
    if (sk.length !== SK_BYTES) throw new Error('私钥长度应为 ' + SK_BYTES + ' 字节');
    var B = new Uint16Array(N * NBAR), Bp = new Uint16Array(N * NBAR);
    var W = new Uint16Array(NBAR * NBAR), C = new Uint16Array(NBAR * NBAR), CC = new Uint16Array(NBAR * NBAR);
    var BBp = new Uint16Array(N * NBAR), Sp = new Uint16Array((2 * N + NBAR) * NBAR);
    var Ep = Sp.subarray(N * NBAR), Epp = Sp.subarray(2 * N * NBAR);
    var skS = sk.subarray(SS_BYTES + PK_BYTES, SS_BYTES + PK_BYTES + 2 * N * NBAR);
    var skPkh = sk.subarray(SS_BYTES + PK_BYTES + 2 * N * NBAR);
    var skPk = sk.subarray(SS_BYTES, SS_BYTES + PK_BYTES);
    var seedA = skPk.subarray(0, BYTES_SEED_A), pkB = skPk.subarray(BYTES_SEED_A);
    var salt = ct.subarray(CT_BYTES - BYTES_SALT);
    var S = new Uint16Array(N * NBAR), i;
    for (i = 0; i < N * NBAR; i++) S[i] = skS[2 * i] | (skS[2 * i + 1] << 8);

    frodoUnpack(Bp, N * NBAR, ct.subarray(0, B_BYTES), B_BYTES, LOGQ);
    frodoUnpack(C, NBAR * NBAR, ct.subarray(B_BYTES, B_BYTES + C2_BYTES), C2_BYTES, LOGQ);
    mulBs(W, Bp, S);
    frodoSub(W, C, W);
    var muprime = new Uint8Array(BYTES_MU);
    keyDecode(muprime, W);

    var G2in = new Uint8Array(BYTES_PKHASH + BYTES_MU + BYTES_SALT);
    G2in.set(skPkh, 0); G2in.set(muprime, BYTES_PKHASH); G2in.set(salt, BYTES_PKHASH + BYTES_MU);
    var G2out = shake128(G2in, BYTES_SEED_SE + SS_BYTES);
    var seedSEp = G2out.subarray(0, BYTES_SEED_SE), kprime = G2out.subarray(BYTES_SEED_SE);

    var shakeIn = new Uint8Array(1 + BYTES_SEED_SE);
    shakeIn[0] = 0x96; shakeIn.set(seedSEp, 1);
    var raw = shake128(shakeIn, (2 * N + NBAR) * NBAR * 2);
    for (i = 0; i < (2 * N + NBAR) * NBAR; i++) Sp[i] = raw[2 * i] | (raw[2 * i + 1] << 8);
    sampleN(Sp, N * NBAR);
    sampleN(Ep, N * NBAR);
    mulAddSaPlusE(BBp, Sp, Ep, seedA);

    sampleN(Epp, NBAR * NBAR);
    frodoUnpack(B, N * NBAR, pkB, PK_BYTES - BYTES_SEED_A, LOGQ);
    mulAddSbPlusE(W, B, Sp, Epp);
    keyEncode(CC, muprime);
    frodoAdd(CC, W, CC);

    for (i = 0; i < N * NBAR; i++) BBp[i] = BBp[i] & MASKQ;
    var selector = ctVerify(Bp, BBp, N * NBAR) | ctVerify(C, CC, NBAR * NBAR);
    var Fin = new Uint8Array(CT_BYTES + SS_BYTES);
    Fin.set(ct, 0);
    Fin.set(ctSelect(kprime, sk.subarray(0, SS_BYTES), SS_BYTES, selector), CT_BYTES);
    return shake128(Fin, SS_BYTES);
  }

  var API = { shake128: shake128, keypair: keypair, encaps: encaps, decaps: decaps,
    PK_BYTES: PK_BYTES, SK_BYTES: SK_BYTES, CT_BYTES: CT_BYTES, SS_BYTES: SS_BYTES };
  if (typeof window !== 'undefined') window.FrodoKEM = API;
  if (typeof globalThis !== 'undefined') globalThis.FrodoKEM = API;

  /* rndBytes 是 crypto_core.js IIFE 内的局部函数，跨文件取不到（本项目第 4 次遇到：
     sm2ZA / bigToBytes / bigToHex 之后又一个）。这里写本地版本。 */
  function rndBytes(n) {
    var b = new Uint8Array(n);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(b);
    else if (typeof require === 'function') { b.set(require('crypto').randomBytes(n)); }
    else { for (var i = 0; i < n; i++) b[i] = (Math.random() * 256) | 0; }
    return b;
  }

  /* ---------- 注册 ---------- */
  if (typeof reg === 'function') {
    var INFO = 'FrodoKEM-640-SHAKE：基于（普通）LWE 的格基 KEM，非结构化格，安全性归约到 LWE 困难性。' +
      '已列入 ISO/IEC 18033-2:2006/Amd 2，也是德国 BSI 与欧盟 ENISA 推荐的 Level 1 后量子算法之一。' +
      '公钥 9616 字节、私钥 19888 字节、密文 9752 字节、共享密钥 16 字节。' +
      '逐行移植自 liboqs 内置官方实现，官方向量 pk/sk/ct/ss 逐字节一致。' +
      '注意：密钥与密文远大于 ML-KEM，约 1 秒。';
    var KG_INFO = '生成 FrodoKEM-640-SHAKE 密钥对，输出 pk（19232 字符）与 sk（39776 字符）。' +
      '参数栏填 sk 则只输出私钥。约 1 秒。';
    var EN_INFO = '用公钥封装：输出密文 ct（19504 字符）与共享密钥 ss（32 字符）。密钥栏填公钥。';
    var DE_INFO = '用私钥解封装：密钥栏填私钥，输入填密文，输出 16 字节共享密钥。' +
      '密文被篡改时会静默返回伪随机密钥（FO 变换的隐含拒绝），属正常行为。';

    reg({ id: 'frodo640shake-keygen', name: 'FrodoKEM-640-SHAKE 密钥生成（ISO 标准化）',
      group: '后量子密码', key: false, param: true,
      paramLabel: '留空=随机生成；填 sk=只输出私钥',
      info: KG_INFO,
      enc: function (b, kk, pp, fmt) {
        var kp = keypair(function (n) { return rndBytes(n); });
        if (pp && /sk/i.test(String(pp))) return bytesOut(kp.sk, fmt);
        return bytesOut(kp.pk, fmt) + '\n::K::' + bytesOut(kp.sk, fmt);
      }, dec: false });

    reg({ id: 'frodo640shake-encaps', name: 'FrodoKEM-640-SHAKE 封装（公钥加密）',
      group: '后量子密码', key: true, param: false,
      keyLabel: '封装公钥（9616 字节 Hex，19232 字符）',
      info: EN_INFO,
      enc: function (b, kk, pp, fmt) {
        if (!kk) throw new Error('请在密钥栏填入封装公钥（Hex）');
        var pk = hexToBytes(String(kk).replace(/\s/g, ''));
        var out = encaps(pk, function (n) { return rndBytes(n); });
        return bytesOut(out.ct, fmt) + '\n::K::' + bytesOut(out.ss, fmt);
      }, dec: false });

    reg({ id: 'frodo640shake-decaps', name: 'FrodoKEM-640-SHAKE 解封装（私钥解密）',
      group: '后量子密码', key: true, param: false,
      keyLabel: '解封装私钥（19888 字节 Hex，39776 字符）',
      info: DE_INFO,
      enc: function (b, kk, pp, fmt) {
        if (!kk) throw new Error('请在密钥栏填入解封装私钥（Hex）');
        var sk = hexToBytes(String(kk).replace(/\s/g, ''));
        var ct = bytesIn(String(b), fmt);
        return bytesOut(decaps(ct, sk), fmt);
      }, dec: false });
  }
})();
