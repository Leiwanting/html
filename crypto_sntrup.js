/* sntrup761（Streamlined NTRU Prime，NTRU Prime 的精简参数集）
   逐行移植自 PQClean clean 实现（liboqs 0.10.0 内置）：
     src/kem/ntruprime/pqclean_sntrup761_clean/kem.c                     主流程 keypair / encaps / decaps
     ..._clean/crypto_core_multsntrup761.c                               Rq 乘 small（Fq_freeze）
     ..._clean/crypto_core_mult3sntrup761.c                              R3 乘（F3_freeze）
     ..._clean/crypto_core_invsntrup761.c                                Rq 中 1/(3*in)
     ..._clean/crypto_core_inv3sntrup761.c                               R3 中求逆
     ..._clean/crypto_core_scale3sntrup761.c                             Rq 中乘 3
     ..._clean/crypto_core_wforcesntrup761.c                             强制权重为 w
     ..._clean/crypto_encode_761x4591.c / decode_761x4591.c              Rq 打包（1158 字节）
     ..._clean/crypto_encode_761x1531.c / decode_761x1531.c              Rounded 打包（1007 字节）
     ..._clean/crypto_encode_761x3.c   / decode_761x3.c                  small 打包（191 字节）
     ..._clean/crypto_encode_761xfreeze3.c / 761x1531round.c / int16 / int32 / sort_uint32 / verify_1039
   参考源码与官方向量生成器已随包保存在 work/ref/sntrup/。
   规格: https://ntruprime.cr.yp.to                                                       */
(function () {
  'use strict';

  var p = 761, q = 4591, w = 286;
  var q18 = 57, q27 = 29235, q14 = 4;

  var Rq_bytes = 1158;          /* 公钥 */
  var Rounded_bytes = 1007;     /* 密文中的 Rounded 部分 */
  var Small_bytes = 191;        /* small 多项式打包长度 */
  var SecretKeys_bytes = 2 * Small_bytes;  /* 382 */
  var PublicKeys_bytes = Rq_bytes;         /* 1158 */
  var Confirm_bytes = 32;
  /* 注意：C 中 #define Ciphertexts_bytes Rounded_bytes（即 1007），
     密文全长是 Ciphertexts_bytes + Confirm_bytes = 1039。两者不可混用 */
  var Ciphertexts_bytes = Rounded_bytes;  /* 1007 */
  var Hash_bytes = 32;
  var SK_BYTES = 1763, PK_BYTES = 1158, CT_BYTES = 1039;

  /* ==================== SHA-512（kem.c 的 Hash 用其前 32 字节） ==================== */
  var M64 = 0xFFFFFFFFFFFFFFFFn;
  var K512 = [
    0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
    0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
    0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
    0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
    0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
    0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
    0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
    0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
    0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
    0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
    0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
    0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
    0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
    0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
    0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
    0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
    0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
    0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
    0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
    0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n];

  function ror64b(x, n) { n = BigInt(n); return ((x >> n) | (x << (64n - n))) & M64; }

  function sha512Compress(h, blk) {
    var wd = new Array(80), t, s0, s1, S0, S1, ch, mj, t1, t2;
    for (t = 0; t < 16; t++) {
      wd[t] = (BigInt(blk[t * 8]) << 56n) | (BigInt(blk[t * 8 + 1]) << 48n) |
        (BigInt(blk[t * 8 + 2]) << 40n) | (BigInt(blk[t * 8 + 3]) << 32n) |
        (BigInt(blk[t * 8 + 4]) << 24n) | (BigInt(blk[t * 8 + 5]) << 16n) |
        (BigInt(blk[t * 8 + 6]) << 8n) | BigInt(blk[t * 8 + 7]);
    }
    for (t = 16; t < 80; t++) {
      s0 = ror64b(wd[t - 15], 1) ^ ror64b(wd[t - 15], 8) ^ (wd[t - 15] >> 7n);
      s1 = ror64b(wd[t - 2], 19) ^ ror64b(wd[t - 2], 61) ^ (wd[t - 2] >> 6n);
      wd[t] = (wd[t - 16] + s0 + wd[t - 7] + s1) & M64;
    }
    var a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (t = 0; t < 80; t++) {
      S1 = ror64b(e, 14) ^ ror64b(e, 18) ^ ror64b(e, 41);
      ch = (e & f) ^ ((~e & M64) & g);
      t1 = (hh + S1 + ch + K512[t] + wd[t]) & M64;
      S0 = ror64b(a, 28) ^ ror64b(a, 34) ^ ror64b(a, 39);
      mj = (a & bb) ^ (a & c) ^ (bb & c);
      t2 = (S0 + mj) & M64;
      hh = g; g = f; f = e; e = (d + t1) & M64; d = c; c = bb; bb = a; a = (t1 + t2) & M64;
    }
    h[0] = (h[0] + a) & M64; h[1] = (h[1] + bb) & M64; h[2] = (h[2] + c) & M64; h[3] = (h[3] + d) & M64;
    h[4] = (h[4] + e) & M64; h[5] = (h[5] + f) & M64; h[6] = (h[6] + g) & M64; h[7] = (h[7] + hh) & M64;
  }

  function sha512Bytes(input) {
    var h = [0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
      0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n];
    var n = input.length, i = 0, rem, j;
    var blk = new Uint8Array(128);
    var bitlen = BigInt(n) * 8n;
    while (n - i >= 128) { for (j = 0; j < 128; j++) blk[j] = input[i + j]; sha512Compress(h, blk); i += 128; }
    rem = n - i;
    blk.fill(0);
    for (j = 0; j < rem; j++) blk[j] = input[i + j];
    blk[rem] = 0x80; rem++;
    if (rem > 112) { sha512Compress(h, blk); blk.fill(0); rem = 0; }
    blk.fill(0, rem, 120);            /* 112..119 是长度高 64 位，必须清零 */
    var tv = bitlen;
    for (j = 127; j >= 120; j--) { blk[j] = Number(tv & 0xFFn); tv >>= 8n; }
    sha512Compress(h, blk);
    var out = new Uint8Array(64), v;
    for (i = 0; i < 8; i++) { v = h[i]; for (j = 7; j >= 0; j--) { out[i * 8 + j] = Number(v & 0xFFn); v >>= 8n; } }
    return out;
  }

  /* kem.c: Hash(out, in, inlen) = SHA-512(in) 的前 32 字节 */
  function Hash32(input, off, len) {
    var sub = (off === 0 && len === input.length) ? input : input.subarray(off, off + len);
    return sha512Bytes(sub).subarray(0, 32);
  }

  /* ==================== 常量时间除法（decode_761x4591 / 761x1531 用） ==================== */
  function divmod_uint14(x, m) {
    var v = Math.floor(0x80000000 / m);
    var qq = 0, qpart, mask;
    x = x >>> 0;
    qpart = Number((BigInt(x) * BigInt(v)) >> 31n);
    x = (x - qpart * m) | 0;
    qq = (qq + qpart) >>> 0;
    qpart = Number((BigInt(x >>> 0) * BigInt(v)) >> 31n);
    x = (x - qpart * m) | 0;
    qq = (qq + qpart) >>> 0;
    x = (x - m) | 0;
    qq = (qq + 1) >>> 0;
    mask = (~(x >>> 31) + 1) | 0;
    x = (x + (mask & m)) | 0;
    qq = (qq + mask) >>> 0;
    return [qq, x >>> 0];
  }
  function mod_uint14(x, m) { return divmod_uint14(x, m)[1]; }

  /* ==================== small 打包（761x3，191 字节） ==================== */
  function encode_761x3(f) {           /* Int8Array(761) -> Uint8Array(191) */
    var s = new Uint8Array(191), i, x;
    for (i = 0; i < 190; i++) {
      x = (f[i * 4] + 1) & 0xFF;
      x = (x + ((f[i * 4 + 1] + 1) << 2)) & 0xFF;
      x = (x + ((f[i * 4 + 2] + 1) << 4)) & 0xFF;
      x = (x + ((f[i * 4 + 3] + 1) << 6)) & 0xFF;
      s[i] = x;
    }
    s[190] = (f[760] + 1) & 0xFF;
    return s;
  }
  function decode_761x3(s) {           /* Uint8Array(191) -> Int8Array(761) */
    var f = new Int8Array(761), i, x;
    for (i = 0; i < 190; i++) {
      x = s[i];
      f[i * 4] = (x & 3) - 1; x >>= 2;
      f[i * 4 + 1] = (x & 3) - 1; x >>= 2;
      f[i * 4 + 2] = (x & 3) - 1; x >>= 2;
      f[i * 4 + 3] = (x & 3) - 1;
    }
    f[760] = (s[190] & 3) - 1;
    return f;
  }

  /* ==================== int16 / int32 字节流 ==================== */
  function encode_pxint16(x) {         /* Int16Array(761) -> Uint8Array(1522) */
    var s = new Uint8Array(1522), i;
    for (i = 0; i < 761; i++) { var u = x[i] & 0xFFFF; s[2 * i] = u & 0xFF; s[2 * i + 1] = (u >> 8) & 0xFF; }
    return s;
  }
  function decode_pxint16(s) {         /* Uint8Array(1522) -> Int16Array(761) */
    var x = new Int16Array(761), i;
    for (i = 0; i < 761; i++) { var u = s[2 * i] | (s[2 * i + 1] << 8); x[i] = (u & 0x8000) ? (u - 0x10000) : u; }
    return x;
  }
  function decode_pxint32(s) {         /* Uint8Array(3044) -> Uint32Array(761) */
    var x = new Uint32Array(761), i;
    for (i = 0; i < 761; i++) {
      x[i] = (s[4 * i] | (s[4 * i + 1] << 8) | (s[4 * i + 2] << 16) | (s[4 * i + 3] << 24)) >>> 0;
    }
    return x;
  }

  /* ==================== F3_freeze / Fq_freeze / Fq_bigfreeze ==================== */
  function F3_freeze(x) { return (x - 3 * ((10923 * x + 16384) >> 15)) & 0xFF; }
  function F3_freezeS(x) { var v = x - 3 * ((10923 * x + 16384) >> 15); return v > 127 ? v - 256 : (v < -128 ? v + 256 : v); }

  function Fq_freeze(x) {
    x = x | 0;
    x = (x - q * ((q18 * x) >> 18)) | 0;
    x = (x - q * ((q27 * x + 67108864) >> 27)) | 0;
    return x;
  }
  function Fq_bigfreeze(x) {
    x = x | 0;
    x = (x - q * ((q14 * x) >> 14)) | 0;
    x = (x - q * ((q18 * x) >> 18)) | 0;
    x = (x - q * ((q27 * x + 67108864) >> 27)) | 0;
    x = (x - q * ((q27 * x + 67108864) >> 27)) | 0;
    return x;
  }
  function Fq_recip(a1) { var i = 1, ai = a1; while (i < q - 2) { ai = Fq_bigfreeze(a1 * ai); i += 1; } return ai; }

  /* ==================== Rq 打包 761x4591（1158 字节） ==================== */
  function encode_761x4591(R0) {
    var out = new Uint8Array(1158), o = 0, R = new Uint16Array(381), i, r0, r1, r2;
    for (i = 0; i < 380; i++) {
      r0 = ((R0[2 * i] + 2295) & 16383); r1 = ((R0[2 * i + 1] + 2295) & 16383);
      r2 = r0 + r1 * 4591;
      out[o++] = r2 & 0xFF; r2 >>>= 8; out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    R[380] = ((R0[760] + 2295) & 16383);
    for (i = 0; i < 190; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 322;
      out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    R[190] = R[380];
    for (i = 0; i < 95; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 406;
      out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    R[95] = R[190];
    for (i = 0; i < 48; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 644;
      out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    for (i = 0; i < 23; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 1621;
      out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    r0 = R[46]; r1 = R[47]; r2 = r0 + r1 * 1621;
    out[o++] = r2 & 0xFF; r2 >>>= 8; out[o++] = r2 & 0xFF; r2 >>>= 8; R[23] = r2 & 0xFFFF;
    for (i = 0; i < 11; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 10265;
      out[o++] = r2 & 0xFF; r2 >>>= 8; out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    r0 = R[22]; r1 = R[23]; r2 = r0 + r1 * 10265;
    out[o++] = r2 & 0xFF; r2 >>>= 8; R[11] = r2 & 0xFFFF;
    for (i = 0; i < 5; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 1608;
      out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    r0 = R[10]; r1 = R[11]; r2 = r0 + r1 * 1608;
    out[o++] = r2 & 0xFF; r2 >>>= 8; out[o++] = r2 & 0xFF; r2 >>>= 8; R[5] = r2 & 0xFFFF;
    for (i = 0; i < 2; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 10101;
      out[o++] = r2 & 0xFF; r2 >>>= 8; out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    r0 = R[4]; r1 = R[5]; r2 = r0 + r1 * 10101;
    out[o++] = r2 & 0xFF; r2 >>>= 8; R[2] = r2 & 0xFFFF;
    r0 = R[0]; r1 = R[1]; r2 = r0 + r1 * 1557;
    out[o++] = r2 & 0xFF; r2 >>>= 8; R[0] = r2 & 0xFFFF; R[1] = R[2];
    r0 = R[0]; r1 = R[1]; r2 = r0 + r1 * 9470;
    out[o++] = r2 & 0xFF; r2 >>>= 8; out[o++] = r2 & 0xFF; r2 >>>= 8; R[0] = r2 & 0xFFFF;
    r0 = R[0]; out[o++] = r0 & 0xFF; r0 >>>= 8; out[o++] = r0 & 0xFF;
    return out;
  }

  function decode_761x4591(s) {
    var R0 = new Int16Array(761);
    var R1 = new Uint16Array(381), R2 = new Uint16Array(191), R3 = new Uint16Array(96),
      R4 = new Uint16Array(48), R5 = new Uint16Array(24), R6 = new Uint16Array(12),
      R7 = new Uint16Array(6), R8 = new Uint16Array(3), R9 = new Uint16Array(2), R10 = new Uint16Array(1);
    var i, r0, r1, r2, idx = 1158 - 1, dm;
    r1 = 0; r1 = ((r1 << 8) | s[idx--]) >>> 0; r1 = ((r1 << 8) | s[idx--]) >>> 0;
    r1 = mod_uint14(r1, 1608); R10[0] = r1;

    r2 = R10[0]; r2 = ((r2 << 8) | s[idx--]) >>> 0; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 9470); r1 = dm[0]; r0 = dm[1];
    R9[0] = r0; r1 = mod_uint14(r1, 11127); R9[1] = r1;

    R8[2] = R9[1]; r2 = R9[0]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 1557); r1 = dm[0]; r0 = dm[1];
    R8[0] = r0; r1 = mod_uint14(r1, 1557); R8[1] = r1;

    r2 = R8[2]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 10101); r1 = dm[0]; r0 = dm[1];
    R7[4] = r0; r1 = mod_uint14(r1, 282); R7[5] = r1;
    for (i = 1; i >= 0; --i) {
      r2 = R8[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 10101); r1 = dm[0]; r0 = dm[1];
      R7[2 * i] = r0; r1 = mod_uint14(r1, 10101); R7[2 * i + 1] = r1;
    }

    r2 = R7[5]; r2 = ((r2 << 8) | s[idx--]) >>> 0; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 1608); r1 = dm[0]; r0 = dm[1];
    R6[10] = r0; r1 = mod_uint14(r1, 11468); R6[11] = r1;
    for (i = 4; i >= 0; --i) {
      r2 = R7[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 1608); r1 = dm[0]; r0 = dm[1];
      R6[2 * i] = r0; r1 = mod_uint14(r1, 1608); R6[2 * i + 1] = r1;
    }

    r2 = R6[11]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 10265); r1 = dm[0]; r0 = dm[1];
    R5[22] = r0; r1 = mod_uint14(r1, 286); R5[23] = r1;
    for (i = 10; i >= 0; --i) {
      r2 = R6[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 10265); r1 = dm[0]; r0 = dm[1];
      R5[2 * i] = r0; r1 = mod_uint14(r1, 10265); R5[2 * i + 1] = r1;
    }

    r2 = R5[23]; r2 = ((r2 << 8) | s[idx--]) >>> 0; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 1621); r1 = dm[0]; r0 = dm[1];
    R4[46] = r0; r1 = mod_uint14(r1, 11550); R4[47] = r1;
    for (i = 22; i >= 0; --i) {
      r2 = R5[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 1621); r1 = dm[0]; r0 = dm[1];
      R4[2 * i] = r0; r1 = mod_uint14(r1, 1621); R4[2 * i + 1] = r1;
    }

    r2 = R4[47]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 644); r1 = dm[0]; r0 = dm[1];
    R3[94] = r0; r1 = mod_uint14(r1, 4591); R3[95] = r1;
    for (i = 46; i >= 0; --i) {
      r2 = R4[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 644); r1 = dm[0]; r0 = dm[1];
      R3[2 * i] = r0; r1 = mod_uint14(r1, 644); R3[2 * i + 1] = r1;
    }

    R2[190] = R3[95];
    for (i = 94; i >= 0; --i) {
      r2 = R3[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 406); r1 = dm[0]; r0 = dm[1];
      R2[2 * i] = r0; r1 = mod_uint14(r1, 406); R2[2 * i + 1] = r1;
    }

    R1[380] = R2[190];
    /* 注意：R1 层每次只读 1 个输入字节（不是 2 个）；多读会使总字节数超出 1158 */
    for (i = 189; i >= 0; --i) {
      r2 = R2[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 322); r1 = dm[0]; r0 = dm[1];
      R1[2 * i] = r0; r1 = mod_uint14(r1, 322); R1[2 * i + 1] = r1;
    }

    R0[760] = R1[380] - 2295;
    for (i = 379; i >= 0; --i) {
      r2 = R1[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 4591); r1 = dm[0]; r0 = dm[1];
      R0[2 * i] = r0 - 2295; r1 = mod_uint14(r1, 4591); R0[2 * i + 1] = r1 - 2295;
    }
    return R0;
  }

  /* ==================== Rounded 打包 761x1531（1007 字节） ==================== */
  function encode_761x1531(R0) {
    var out = new Uint8Array(1007), o = 0, R = new Uint16Array(381), i, r0, r1, r2;
    for (i = 0; i < 380; i++) {
      r0 = ((((R0[2 * i] + 2295) & 16383) * 10923) >> 15);
      r1 = ((((R0[2 * i + 1] + 2295) & 16383) * 10923) >> 15);
      r2 = r0 + r1 * 1531;
      out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    R[380] = ((((R0[760] + 2295) & 16383) * 10923) >> 15);
    for (i = 0; i < 190; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 9157;
      out[o++] = r2 & 0xFF; r2 >>>= 8; out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    R[190] = R[380];
    for (i = 0; i < 95; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 1280;
      out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    R[95] = R[190];
    for (i = 0; i < 48; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 6400;
      out[o++] = r2 & 0xFF; r2 >>>= 8; out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    for (i = 0; i < 24; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 625;
      out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    for (i = 0; i < 12; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 1526;
      out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    for (i = 0; i < 6; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 9097;
      out[o++] = r2 & 0xFF; r2 >>>= 8; out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    for (i = 0; i < 3; i++) {
      r0 = R[2 * i]; r1 = R[2 * i + 1]; r2 = r0 + r1 * 1263;
      out[o++] = r2 & 0xFF; r2 >>>= 8; R[i] = r2 & 0xFFFF;
    }
    r0 = R[0]; r1 = R[1]; r2 = r0 + r1 * 6232;
    out[o++] = r2 & 0xFF; r2 >>>= 8; out[o++] = r2 & 0xFF; r2 >>>= 8; R[0] = r2 & 0xFFFF; R[1] = R[2];
    r0 = R[0]; r1 = R[1]; r2 = r0 + r1 * 593;
    out[o++] = r2 & 0xFF; r2 >>>= 8; R[0] = r2 & 0xFFFF;
    r0 = R[0]; out[o++] = r0 & 0xFF; r0 >>>= 8; out[o++] = r0 & 0xFF;
    return out;
  }

  function encode_761x1531round(a) {   /* Round_and_encode: 先 3*round(a/1531) 再打包 */
    var x = new Int16Array(761), i;
    for (i = 0; i < 761; i++) x[i] = 3 * ((10923 * a[i] + 16384) >> 15);
    return encode_761x1531(x);
  }

  function decode_761x1531(s) {
    var R0 = new Int16Array(761);
    var R1 = new Uint16Array(381), R2 = new Uint16Array(191), R3 = new Uint16Array(96),
      R4 = new Uint16Array(48), R5 = new Uint16Array(24), R6 = new Uint16Array(12),
      R7 = new Uint16Array(6), R8 = new Uint16Array(3), R9 = new Uint16Array(2), R10 = new Uint16Array(1);
    var i, r0, r1, r2, idx = 1007 - 1, dm;
    r1 = 0; r1 = ((r1 << 8) | s[idx--]) >>> 0; r1 = ((r1 << 8) | s[idx--]) >>> 0;
    r1 = mod_uint14(r1, 3475); R10[0] = r1;

    r2 = R10[0]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 593); r1 = dm[0]; r0 = dm[1];
    R9[0] = r0; r1 = mod_uint14(r1, 1500); R9[1] = r1;

    R8[2] = R9[1]; r2 = R9[0]; r2 = ((r2 << 8) | s[idx--]) >>> 0; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 6232); r1 = dm[0]; r0 = dm[1];
    R8[0] = r0; r1 = mod_uint14(r1, 6232); R8[1] = r1;

    r2 = R8[2]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 1263); r1 = dm[0]; r0 = dm[1];
    R7[4] = r0; r1 = mod_uint14(r1, 304); R7[5] = r1;
    for (i = 1; i >= 0; --i) {
      r2 = R8[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 1263); r1 = dm[0]; r0 = dm[1];
      R7[2 * i] = r0; r1 = mod_uint14(r1, 1263); R7[2 * i + 1] = r1;
    }

    r2 = R7[5]; r2 = ((r2 << 8) | s[idx--]) >>> 0; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 9097); r1 = dm[0]; r0 = dm[1];
    R6[10] = r0; r1 = mod_uint14(r1, 2188); R6[11] = r1;
    for (i = 4; i >= 0; --i) {
      r2 = R7[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 9097); r1 = dm[0]; r0 = dm[1];
      R6[2 * i] = r0; r1 = mod_uint14(r1, 9097); R6[2 * i + 1] = r1;
    }

    r2 = R6[11]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 1526); r1 = dm[0]; r0 = dm[1];
    R5[22] = r0; r1 = mod_uint14(r1, 367); R5[23] = r1;
    for (i = 10; i >= 0; --i) {
      r2 = R6[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 1526); r1 = dm[0]; r0 = dm[1];
      R5[2 * i] = r0; r1 = mod_uint14(r1, 1526); R5[2 * i + 1] = r1;
    }

    r2 = R5[23]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 625); r1 = dm[0]; r0 = dm[1];
    R4[46] = r0; r1 = mod_uint14(r1, 150); R4[47] = r1;
    for (i = 22; i >= 0; --i) {
      r2 = R5[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 625); r1 = dm[0]; r0 = dm[1];
      R4[2 * i] = r0; r1 = mod_uint14(r1, 625); R4[2 * i + 1] = r1;
    }

    r2 = R4[47]; r2 = ((r2 << 8) | s[idx--]) >>> 0; r2 = ((r2 << 8) | s[idx--]) >>> 0;
    dm = divmod_uint14(r2, 6400); r1 = dm[0]; r0 = dm[1];
    R3[94] = r0; r1 = mod_uint14(r1, 1531); R3[95] = r1;
    for (i = 46; i >= 0; --i) {
      r2 = R4[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 6400); r1 = dm[0]; r0 = dm[1];
      R3[2 * i] = r0; r1 = mod_uint14(r1, 6400); R3[2 * i + 1] = r1;
    }

    R2[190] = R3[95];
    for (i = 94; i >= 0; --i) {
      r2 = R3[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 1280); r1 = dm[0]; r0 = dm[1];
      R2[2 * i] = r0; r1 = mod_uint14(r1, 1280); R2[2 * i + 1] = r1;
    }

    R1[380] = R2[190];
    for (i = 189; i >= 0; --i) {
      r2 = R2[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 9157); r1 = dm[0]; r0 = dm[1];
      R1[2 * i] = r0; r1 = mod_uint14(r1, 9157); R1[2 * i + 1] = r1;
    }

    R0[760] = 3 * R1[380] - 2295;
    for (i = 379; i >= 0; --i) {
      r2 = R1[i]; r2 = ((r2 << 8) | s[idx--]) >>> 0;
      dm = divmod_uint14(r2, 1531); r1 = dm[0]; r0 = dm[1];
      R0[2 * i] = 3 * r0 - 2295; r1 = mod_uint14(r1, 1531); R0[2 * i + 1] = 3 * r1 - 2295;
    }
    return R0;
  }

  /* ==================== Rq 乘 small（crypto_core_multsntrup761） ==================== */
  function Rq_mult_small(h, g) {       /* h: Int16Array(761) Fq（原地）, g: Int8Array(761) small */
    var f = decode_pxint16(encode_pxint16(h));
    var i, j, result;
    for (i = 0; i < p; i++) f[i] = Fq_freeze(f[i]);
    var gg = new Int8Array(p);
    for (i = 0; i < p; i++) {
      var gi = g[i], gi0 = gi & 1;
      gg[i] = gi0 - (gi & (gi0 << 1));
    }
    var fg = new Array(p + p - 1);
    for (i = 0; i < p; i++) { result = 0; for (j = 0; j <= i; j++) result += f[j] * gg[i - j]; fg[i] = Fq_freeze(result); }
    for (i = p; i < p + p - 1; i++) { result = 0; for (j = i - p + 1; j < p; j++) result += f[j] * gg[i - j]; fg[i] = Fq_freeze(result); }
    for (i = p + p - 2; i >= p; i--) { fg[i - p] = Fq_freeze(fg[i - p] + fg[i]); fg[i - p + 1] = Fq_freeze(fg[i - p + 1] + fg[i]); }
    var o = new Int16Array(p);
    for (i = 0; i < p; i++) o[i] = fg[i];
    return o;
  }

  /* ==================== Rq 乘 3（crypto_core_scale3sntrup761） ==================== */
  function Rq_mult3(h) {               /* h: Int16Array(761) 原地 */
    var f = new Int16Array(p), i, x;
    for (i = 0; i < p; i++) {
      x = h[i] * 3;
      x = (x - ((q + 1) / 2)) | 0;
      x = (x + (q & (x >> 15))) | 0;
      x = (x + (q & (x >> 15))) | 0;
      x = (x - ((q - 1) / 2)) | 0;
      f[i] = x;
    }
    return f;
  }

  /* ==================== R3 乘（crypto_core_mult3sntrup761） ==================== */
  function R3_mult(f, g) {             /* f,g: Int8Array(761) -> Int8Array(761) */
    var ff = new Int8Array(p), gg = new Int8Array(p), fg = new Array(p + p - 1);
    var i, j, result;
    for (i = 0; i < p; i++) { var a = f[i], a0 = a & 1; ff[i] = a0 - (a & (a0 << 1)); }
    for (i = 0; i < p; i++) { var b = g[i], b0 = b & 1; gg[i] = b0 - (b & (b0 << 1)); }
    for (i = 0; i < p; i++) { result = 0; for (j = 0; j <= i; j++) result += ff[j] * gg[i - j]; fg[i] = F3_freezeS(result); }
    for (i = p; i < p + p - 1; i++) { result = 0; for (j = i - p + 1; j < p; j++) result += ff[j] * gg[i - j]; fg[i] = F3_freezeS(result); }
    for (i = p + p - 2; i >= p; i--) { fg[i - p] = F3_freezeS(fg[i - p] + fg[i]); fg[i - p + 1] = F3_freezeS(fg[i - p + 1] + fg[i]); }
    var out = new Int8Array(p);
    for (i = 0; i < p; i++) out[i] = fg[i];
    return out;
  }

  /* ==================== R3 求逆（crypto_core_inv3sntrup761） ==================== */
  function int16_nonzero_mask(x) {
    var u = x & 0xFFFF, v = (~u + 1) >>> 0;
    v = v >>> 31;
    return -v;
  }
  function int16_negative_mask(x) { var u = x & 0xFFFF; return -(u >>> 15); }

  function core_inv3(inp) {            /* Int8Array(761) -> {out:Int8Array(761), fail:bool} */
    var f = new Int8Array(p + 1), g = new Int8Array(p + 1), v = new Int8Array(p + 1), r = new Int8Array(p + 1);
    var i, loop, delta, sign, swap, t;
    for (i = 0; i < p + 1; i++) { v[i] = 0; r[i] = 0; }
    r[0] = 1;
    for (i = 0; i < p; i++) f[i] = 0;
    f[0] = 1; f[p - 1] = -1; f[p] = -1;
    for (i = 0; i < p; i++) { var i1 = inp[i] & 1; g[p - 1 - i] = i1 - (inp[i] & (i1 << 1)); }
    g[p] = 0;
    delta = 1;
    for (loop = 0; loop < 2 * p - 1; loop++) {
      for (i = p; i > 0; i--) v[i] = v[i - 1];
      v[0] = 0;
      sign = -g[0] * f[0];
      swap = int16_negative_mask(-delta) & int16_nonzero_mask(g[0]);
      delta ^= swap & (delta ^ -delta);
      delta += 1;
      for (i = 0; i < p + 1; i++) {
        t = swap & (f[i] ^ g[i]); f[i] ^= t; g[i] ^= t;
        t = swap & (v[i] ^ r[i]); v[i] ^= t; r[i] ^= t;
      }
      for (i = 0; i < p + 1; i++) g[i] = F3_freezeS(g[i] + sign * f[i]);
      for (i = 0; i < p + 1; i++) r[i] = F3_freezeS(r[i] + sign * v[i]);
      for (i = 0; i < p; i++) g[i] = g[i + 1];
      g[p] = 0;
    }
    sign = f[0];
    var out = new Int8Array(p);
    for (i = 0; i < p; i++) out[i] = sign * v[p - 1 - i];
    return { out: out, fail: int16_nonzero_mask(delta) !== 0 };
  }

  /* ==================== Rq 中 1/(3*in)（crypto_core_invsntrup761） ==================== */
  function core_inv(inp) {             /* Int8Array(761) -> Int16Array(761) */
    var out = new Int16Array(p), f = new Int16Array(p + 1), g = new Int16Array(p + 1),
      v = new Int16Array(p + 1), r = new Int16Array(p + 1);
    var i, loop, delta, swap, t, f0, g0, scale;
    for (i = 0; i < p + 1; i++) { v[i] = 0; r[i] = 0; }
    r[0] = Fq_recip(3);
    for (i = 0; i < p; i++) f[i] = 0;
    f[0] = 1; f[p - 1] = -1; f[p] = -1;
    for (i = 0; i < p; i++) g[p - 1 - i] = inp[i];
    g[p] = 0;
    delta = 1;
    for (loop = 0; loop < 2 * p - 1; loop++) {
      for (i = p; i > 0; i--) v[i] = v[i - 1];
      v[0] = 0;
      swap = int16_negative_mask(-delta) & int16_nonzero_mask(g[0]);
      delta ^= swap & (delta ^ -delta);
      delta += 1;
      for (i = 0; i < p + 1; i++) {
        t = swap & (f[i] ^ g[i]); f[i] ^= t; g[i] ^= t;
        t = swap & (v[i] ^ r[i]); v[i] ^= t; r[i] ^= t;
      }
      f0 = f[0]; g0 = g[0];
      for (i = 0; i < p + 1; i++) g[i] = Fq_bigfreeze(f0 * g[i] - g0 * f[i]);
      for (i = 0; i < p + 1; i++) r[i] = Fq_bigfreeze(f0 * r[i] - g0 * v[i]);
      for (i = 0; i < p; i++) g[i] = g[i + 1];
      g[p] = 0;
    }
    scale = Fq_recip(f[0]);
    for (i = 0; i < p; i++) out[i] = Fq_bigfreeze(scale * v[p - 1 - i]);
    return out;
  }

  /* ==================== 强制权重 w（crypto_core_wforcesntrup761） ==================== */
  function core_wforce(inp) {          /* Int8Array(761) -> Int8Array(761) */
    var weight = 0, i, mask;
    for (i = 0; i < p; i++) weight += inp[i] & 1;
    mask = int16_nonzero_mask(weight - w);
    var out = new Int8Array(p);
    for (i = 0; i < w; i++) out[i] = (((inp[i] ^ 1) & ~mask) ^ 1);
    for (i = w; i < p; i++) out[i] = inp[i] & ~mask;
    return out;
  }

  /* ==================== 排序（crypto_sort_int32 / uint32） ==================== */
  function minmax(x, ia, ib) {
    var a = x[ia], b = x[ib];
    var ab = (b ^ a) | 0;
    var c = (b - a) | 0;
    c = (c ^ (ab & (c ^ b))) | 0;
    c = (c >> 31) | 0;
    c = (c & ab) | 0;
    x[ia] = (a ^ c) | 0;
    x[ib] = (b ^ c) | 0;
  }
  function sort_int32(x) {
    var n = x.length, top, pp, qq, r, i, j;
    top = 1;
    while (top < n - top) top += top;
    for (pp = top; pp >= 1; pp >>= 1) {
      i = 0;
      while (i + 2 * pp <= n) { for (j = i; j < i + pp; j++) minmax(x, j, j + pp); i += 2 * pp; }
      for (j = i; j < n - pp; j++) minmax(x, j, j + pp);
      i = 0; j = 0;
      /* C 用 goto done 跳出到本轮 qq 末尾；此处用带标签 continue 等价实现 */
      qqloop: for (qq = top; qq > pp; qq >>= 1) {
        if (j !== i) {
          for (;;) {
            if (j === n - qq) { continue qqloop; }
            /* 注意：C 里 a 是 x[j+pp] 的副本，MINMAX 改 a 后写回；
               等价于直接对 x[j+pp] 做 minmax 且不写回旧副本 */
            for (r = qq; r > pp; r >>= 1) minmax(x, j + pp, j + r);
            ++j;
            if (j === i + pp) { i += 2 * pp; break; }
          }
        }
        while (i + pp <= n - qq) {
          for (j = i; j < i + pp; j++) {
            for (r = qq; r > pp; r >>= 1) minmax(x, j + pp, j + r);
          }
          i += 2 * pp;
        }
        j = i;
        while (j < n - qq) {
          for (r = qq; r > pp; r >>= 1) minmax(x, j + pp, j + r);
          ++j;
        }
      }
    }
  }
  function sort_uint32(arr) {          /* Uint32Array(761) 原地升序 */
    var n = arr.length, x = new Int32Array(n), j;
    for (j = 0; j < n; j++) x[j] = (arr[j] ^ 0x80000000) | 0;
    sort_int32(x);
    for (j = 0; j < n; j++) arr[j] = (x[j] ^ 0x80000000) >>> 0;
  }

  /* ==================== 常量时间比较（crypto_verify_1039） ==================== */
  function verify_1039(x, y) {
    var d = 0, i;
    for (i = 0; i < 1039; i++) d |= x[i] ^ y[i];
    return (1 & ((((d - 1) >>> 0)) >>> 8)) - 1;
  }

  /* ==================== 随机 small 多项式 ==================== */
  function Short_random(rnd) {         /* 权重恰为 w 的 small */
    var L = decode_pxint32(rnd(4 * p));
    var i;
    for (i = 0; i < w; i++) L[i] = (L[i] & -2) >>> 0;
    for (i = w; i < p; i++) L[i] = ((L[i] & -3) | 1) >>> 0;
    for (i = p; i < p; i++) L[i] = 0xffffffff;
    sort_uint32(L);
    var out = new Int8Array(p);
    for (i = 0; i < p; i++) out[i] = ((L[i] & 3) - 1);
    return out;
  }
  function Small_random(rnd) {         /* 均匀 small */
    var L = decode_pxint32(rnd(4 * p));
    var out = new Int8Array(p), i, v;
    for (i = 0; i < p; i++) {
      v = ((L[i] & 0x3fffffff) * 3) >>> 0;
      out[i] = (v >>> 30) - 1;
    }
    return out;
  }

  /* ==================== Hide ==================== */
  function Hide(r, pk, cache) {
    /* r: Int8Array(761) small；pk: Uint8Array(1158)；cache: Uint8Array(32) */
    var h = decode_761x4591(pk);
    h = Rq_mult_small(h, r);
    var c = new Uint8Array(Ciphertexts_bytes + Confirm_bytes);
    var rounded = encode_761x1531round(h);
    c.set(rounded, 0);
    var r_enc = new Uint8Array(1 + Small_bytes);
    r_enc.set(encode_761x3(r), 1);
    r_enc[0] = 3;
    var x = new Uint8Array(1 + Hash_bytes + Ciphertexts_bytes + Confirm_bytes);
    x.set(Hash32(r_enc, 0, r_enc.length), 1);
    for (var i = 0; i < Hash_bytes; i++) x[1 + Hash_bytes + i] = cache[i];
    x[0] = 2;
    c.set(Hash32(x, 0, 1 + Hash_bytes * 2), Rounded_bytes);
    return { c: c, r_enc: r_enc, x: x };
  }

  /* ==================== KEM ==================== */
  function keypair(rnd) {
    var sk = new Uint8Array(SK_BYTES), pk, g, vv, fb, h, i, sksave, rho;
    for (;;) {
      g = Small_random(rnd);
      vv = core_inv3(g);
      if (!vv.fail) { sk.set(encode_761x3(vv.out), Small_bytes); break; }
    }
    fb = Short_random(rnd);
    sk.set(encode_761x3(fb), 0);
    h = core_inv(fb);
    h = Rq_mult_small(h, g);
    pk = encode_761x4591(h);

    sksave = sk[SecretKeys_bytes - 1];
    sk.set(pk, SecretKeys_bytes);
    sk[SecretKeys_bytes - 1] = 4;
    var hc = Hash32(sk, SecretKeys_bytes - 1, 1 + PublicKeys_bytes);
    sk[SecretKeys_bytes - 1] = sksave;
    rho = rnd(Small_bytes);
    sk.set(rho, SecretKeys_bytes + PublicKeys_bytes);
    sk.set(hc, SecretKeys_bytes + PublicKeys_bytes + Small_bytes);
    return { pk: pk, sk: sk };
  }

  function encaps(pk, rnd) {
    if (pk.length !== PK_BYTES) throw new Error('公钥长度错误，应为 ' + PK_BYTES + ' 字节');
    var y = new Uint8Array(1 + PublicKeys_bytes), i;
    y[0] = 4;
    y.set(pk, 1);
    var cache = Hash32(y, 0, y.length);
    var r = Short_random(rnd);
    var h = Hide(r, pk, cache);
    var x = h.x;
    for (i = 0; i < Ciphertexts_bytes + Confirm_bytes; i++) x[1 + Hash_bytes + i] = h.c[i];
    x[0] = 1;
    return { ct: h.c, ss: Hash32(x, 0, x.length) };
  }

  function decaps(c, sk) {
    if (sk.length !== SK_BYTES) throw new Error('私钥长度错误，应为 ' + SK_BYTES + ' 字节');
    if (c.length !== CT_BYTES) throw new Error('密文长度错误，应为 ' + CT_BYTES + ' 字节');
    var pk = sk.subarray(SecretKeys_bytes, SecretKeys_bytes + PublicKeys_bytes);
    var rho = sk.subarray(SecretKeys_bytes + PublicKeys_bytes, SecretKeys_bytes + PublicKeys_bytes + Small_bytes);
    var cache = sk.subarray(SecretKeys_bytes + PublicKeys_bytes + Small_bytes,
      SecretKeys_bytes + PublicKeys_bytes + Small_bytes + Hash_bytes);
    var i, mask;
    var d = decode_761x1531(c);
    var f = decode_761x3(sk.subarray(0, Small_bytes));
    d = Rq_mult_small(d, f);
    d = Rq_mult3(d);
    var e = new Int8Array(p);
    for (i = 0; i < p; i++) e[i] = F3_freezeS(d[i]);
    var v = decode_761x3(sk.subarray(Small_bytes, SecretKeys_bytes));
    var r = R3_mult(e, v);
    r = core_wforce(r);
    var h = Hide(r, pk, cache);
    var r_enc = h.r_enc, x = h.x, cnew = h.c;
    mask = verify_1039(c, cnew);
    for (i = 0; i < Small_bytes; i++) r_enc[i + 1] ^= (mask & (r_enc[i + 1] ^ rho[i]));
    x.set(Hash32(r_enc, 0, 1 + Small_bytes), 1);
    for (i = 0; i < Ciphertexts_bytes + Confirm_bytes; i++) x[1 + Hash_bytes + i] = c[i];
    x[0] = 1 + mask;
    return Hash32(x, 0, x.length);
  }

  /* ==================== 测试/调试出口 ==================== */
  if (typeof globalThis !== 'undefined') {
    globalThis.__sntrup = {
      p: p, q: q, w: w, PK_BYTES: PK_BYTES, SK_BYTES: SK_BYTES, CT_BYTES: CT_BYTES,
      sha512Bytes: sha512Bytes, keypair: keypair, encaps: encaps, decaps: decaps,
      encode_761x4591: encode_761x4591, decode_761x4591: decode_761x4591,
      encode_761x1531round: encode_761x1531round, decode_761x1531: decode_761x1531,
      encode_761x3: encode_761x3, decode_761x3: decode_761x3
    };
  }

  /* ==================== 界面注册 ==================== */
  if (typeof reg === 'function') {
    var INFO = 'sntrup761（Streamlined NTRU Prime）：NTRU Prime 的精简参数集，基于 R/q 上多项式环，' +
      '不依赖结构化格，已被 OpenSSH 9.0+ 作为默认混合后量子密钥交换（sntrup761x25519-sha512@openssh.com）。' +
      '公钥 1158 字节、私钥 1763 字节、密文 1039 字节、共享密钥 32 字节。' +
      '逐行移植自 PQClean clean 官方实现，官方向量逐字节一致。';
    var KG_INFO = '生成 sntrup761 密钥对，输出 pk（2316 字符）与 sk（3526 字符）。参数栏填 sk 则只输出私钥。';
    var EN_INFO = '用公钥封装：密钥栏填公钥，输出密文 ct（2078 字符）与共享密钥 ss（64 字符）。';
    var DE_INFO = '用私钥解封装：密钥栏填 sk，输入填密文，输出 32 字节共享密钥。' +
      '密文被篡改时返回伪随机密钥（隐含拒绝），属正常行为。';

  /* rndBytes 是 crypto_core.js IIFE 内的局部函数，跨文件取不到
     （crypto_frodo.js 里已因同一原因本地定义过一次）。
     sntrup761 的 keygen / encaps 都要用它，缺了在浏览器会直接 ReferenceError。 */
  function rndBytes(n) {
    var b = new Uint8Array(n);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(b);
    else { for (var i = 0; i < n; i++) b[i] = (Math.random() * 256) | 0; }
    return b;
  }

    reg({
      id: 'sntrup761-keygen', name: 'sntrup761 密钥生成',
      group: '后量子密码', key: false, param: true,
      paramLabel: '留空=随机生成；填 sk=只输出私钥',
      info: KG_INFO,
      enc: function (b, kk, pp, fmt) {
        var kp = keypair(function (n) { return rndBytes(n); });
        if (pp && /sk/i.test(String(pp))) return bytesOut(kp.sk, fmt);
        return bytesOut(kp.pk, fmt) + '\n::K::' + bytesOut(kp.sk, fmt);
      }, dec: false
    });

    reg({
      id: 'sntrup761-encaps', name: 'sntrup761 封装（公钥加密）',
      group: '后量子密码', key: true, param: false,
      keyLabel: '封装公钥（1158 字节 Hex，2316 字符）',
      info: EN_INFO,
      enc: function (b, kk, pp, fmt) {
        if (!kk) throw new Error('请在密钥栏填入封装公钥（Hex，2316 字符）');
        var pk = hexToBytes(String(kk).replace(/\s/g, ''));
        var out = encaps(pk, function (n) { return rndBytes(n); });
        return bytesOut(out.ct, fmt) + '\n::K::' + bytesOut(out.ss, fmt);
      }, dec: false
    });

    reg({
      id: 'sntrup761-decaps', name: 'sntrup761 解封装（私钥解密）',
      group: '后量子密码', key: true, param: false,
      keyLabel: '解封装私钥（1763 字节 Hex，3526 字符）',
      info: DE_INFO,
      enc: function (b, kk, pp, fmt) {
        if (!kk) throw new Error('请在密钥栏填入解封装私钥（Hex，3526 字符）');
        var sk = hexToBytes(String(kk).replace(/\s/g, ''));
        var ct = bytesIn(String(b), fmt);
        return bytesOut(decaps(ct, sk), fmt);
      }, dec: false
    });
  }
})();
