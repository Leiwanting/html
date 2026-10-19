/* ============================================================
 * GIFT-64 / GIFT-128 —— 轻量级分组密码（CHES 2017, Banik et al.）
 *
 * 常量与流程全部取自官方参考实现：
 *   github.com/giftcipher/gift  implementations/reference/
 *   GIFT64-128_cipher.cpp  /  GIFT128-128_cipher.cpp（作者 Siang Meng Sim）
 *
 * 状态表示（与官方一致，务必注意方向）：
 *   内部是 nibble 数组 s[]，s[0] 为最低位 nibble，s[N-1] 为最高位。
 *   字节 j 与 nibble 的对应： byte[j] = s[N-1-2j]<<4 | s[N-2-2j]
 *   即 s 的最高两个 nibble 组成第一个字节，且 s[N-1] 是高 4 位。
 *
 * 三个易错点（都记在下方实现处）：
 *   1. bit 置换 perm_bits[GIFT_P[i]] = bits[i]，是「源→目的」，不是反过来
 *   2. 轮常数只作用于 bits[3],[7],[11],[15],[19],[23]，外加最高位 bits[N-1]
 *   3. 密钥更新里 k1 部分是 nibble 内 2 位旋转，不是整体移位
 * ============================================================ */
(function (global) {
  'use strict';

  var GIFT_S = [1, 10, 4, 12, 6, 15, 3, 9, 2, 13, 11, 7, 5, 0, 8, 14];
  var GIFT_S_INV = [13, 0, 8, 6, 2, 12, 4, 11, 14, 7, 1, 10, 3, 9, 15, 5];

  /* 官方源码里 64/128 两份置换都列着，128 那份是实际启用的。 */
  var GIFT_P128 = [
    0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3,
    4, 37, 70, 103, 100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7,
    8, 41, 74, 107, 104, 9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11,
    12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15,
    16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19,
    20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23,
    24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27,
    28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31
  ];
  var GIFT_P64 = [
    0, 17, 34, 51, 48, 1, 18, 35, 32, 49, 2, 19, 16, 33, 50, 3,
    4, 21, 38, 55, 52, 5, 22, 39, 36, 53, 6, 23, 20, 37, 54, 7,
    8, 25, 42, 59, 56, 9, 26, 43, 40, 57, 10, 27, 24, 41, 58, 11,
    12, 29, 46, 63, 60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15
  ];

  var GIFT_RC = [
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
    0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
    0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
    0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
    0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a, 0x15, 0x2a, 0x14, 0x28,
    0x10, 0x20
  ];

  /* ---------- 字节 <-> nibble ---------- */
  function bytesToNibbles(bytes, nn) {
    var s = new Uint8Array(nn), j, b;
    for (j = 0; j < bytes.length; j++) {
      b = bytes[j];
      s[nn - 1 - 2 * j] = (b >> 4) & 15;
      s[nn - 2 - 2 * j] = b & 15;
    }
    return s;
  }
  function nibblesToBytes(s) {
    var nn = s.length, n = nn / 2, out = new Uint8Array(n), j;
    for (j = 0; j < n; j++) out[j] = (s[nn - 1 - 2 * j] << 4) | s[nn - 2 - 2 * j];
    return out;
  }

  /* 轮函数的一次 SubCells+PermBits+AddRoundKey；enc=true 用 S，false 用 S^-1 */
  function giftRound(s, key, bits, permBits, keyBits, P, rc, enc) {
    var i, j, nn = s.length, nb = nn * 4;
    var S = enc ? GIFT_S : GIFT_S_INV;

    for (i = 0; i < nn; i++) s[i] = S[s[i]];

    for (i = 0; i < nn; i++) for (j = 0; j < 4; j++) bits[4 * i + j] = (s[i] >> j) & 1;
    /* 注意方向：perm_bits[P[i]] = bits[i] */
    for (i = 0; i < nb; i++) permBits[P[i]] = bits[i];
    for (i = 0; i < nn; i++) { s[i] = 0; for (j = 0; j < 4; j++) s[i] ^= permBits[4 * i + j] << j; }

    for (i = 0; i < nn; i++) for (j = 0; j < 4; j++) bits[4 * i + j] = (s[i] >> j) & 1;
    for (i = 0; i < 32; i++) for (j = 0; j < 4; j++) keyBits[4 * i + j] = (key[i] >> j) & 1;

    if (nn === 32) {           /* GIFT-128: u=v=32 */
      for (i = 0; i < 32; i++) { bits[4 * i + 1] ^= keyBits[i]; bits[4 * i + 2] ^= keyBits[i + 64]; }
    } else {                   /* GIFT-64: u=v=16 */
      for (i = 0; i < 16; i++) { bits[4 * i] ^= keyBits[i]; bits[4 * i + 1] ^= keyBits[i + 16]; }
    }

    var c = rc;
    bits[3] ^= c & 1;
    bits[7] ^= (c >> 1) & 1;
    bits[11] ^= (c >> 2) & 1;
    bits[15] ^= (c >> 3) & 1;
    bits[19] ^= (c >> 4) & 1;
    bits[23] ^= (c >> 5) & 1;
    bits[nb - 1] ^= 1;

    for (i = 0; i < nn; i++) { s[i] = 0; for (j = 0; j < 4; j++) s[i] ^= bits[4 * i + j] << j; }
  }

  /* 密钥更新：两种分组尺寸共用同一套 32-nibble 更新（官方源码如此） */
  function giftKeyUpdate(key, temp) {
    var i;
    for (i = 0; i < 32; i++) temp[i] = key[(i + 8) % 32];
    for (i = 0; i < 24; i++) key[i] = temp[i];
    key[24] = temp[27]; key[25] = temp[24]; key[26] = temp[25]; key[27] = temp[26];
    key[28] = ((temp[28] & 0xc) >> 2) ^ ((temp[29] & 0x3) << 2);
    key[29] = ((temp[29] & 0xc) >> 2) ^ ((temp[30] & 0x3) << 2);
    key[30] = ((temp[30] & 0xc) >> 2) ^ ((temp[31] & 0x3) << 2);
    key[31] = ((temp[31] & 0xc) >> 2) ^ ((temp[28] & 0x3) << 2);
  }

  /* 解密一轮：顺序与加密相反——逆轮密钥加 → 逆置换 → 逆 S 盒。
     官方 dec128 打印顺序亦为 inverse AddRoundKeys → inverse PermBits → inverse SubCells。
     加密 dest[P[i]] = src[i]，故逆操作为 src[i] = dest[P[i]]（读写互换即可，无需 P_inv）。 */
  function giftRoundDec(s, key, bits, permBits, keyBits, P, rc) {
    var i, j, nn = s.length, nb = nn * 4;

    for (i = 0; i < nn; i++) for (j = 0; j < 4; j++) bits[4 * i + j] = (s[i] >> j) & 1;
    for (i = 0; i < 32; i++) for (j = 0; j < 4; j++) keyBits[4 * i + j] = (key[i] >> j) & 1;

    if (nn === 32) {
      for (i = 0; i < 32; i++) { bits[4 * i + 1] ^= keyBits[i]; bits[4 * i + 2] ^= keyBits[i + 64]; }
    } else {
      for (i = 0; i < 16; i++) { bits[4 * i] ^= keyBits[i]; bits[4 * i + 1] ^= keyBits[i + 16]; }
    }

    var c = rc;
    bits[3] ^= c & 1;
    bits[7] ^= (c >> 1) & 1;
    bits[11] ^= (c >> 2) & 1;
    bits[15] ^= (c >> 3) & 1;
    bits[19] ^= (c >> 4) & 1;
    bits[23] ^= (c >> 5) & 1;
    bits[nb - 1] ^= 1;

    for (i = 0; i < nn; i++) { s[i] = 0; for (j = 0; j < 4; j++) s[i] ^= bits[4 * i + j] << j; }

    /* 逆置换 */
    for (i = 0; i < nn; i++) for (j = 0; j < 4; j++) permBits[4 * i + j] = (s[i] >> j) & 1;
    for (i = 0; i < nb; i++) bits[i] = permBits[P[i]];
    for (i = 0; i < nn; i++) { s[i] = 0; for (j = 0; j < 4; j++) s[i] ^= bits[4 * i + j] << j; }

    for (i = 0; i < nn; i++) s[i] = GIFT_S_INV[s[i]];
  }

  /* 轮密钥序列只依赖【密钥】，与明文无关 —— 可以在 makeBlockFn 里算一次复用。
     ⚠ 历史 bug：原本放在 giftCore 内部，每个块都要重算 28（或 40）轮密钥状态，
       且每轮 key.slice(0) 都新分配一个 32 字节数组 —— 64KB 数据就是
       8192 块 × 28 = 约 23 万次数组分配，纯 GC 负担。 */
  function giftKeySeq(kb, rounds) {
    var key = bytesToNibbles(kb, 32), temp = new Uint8Array(32), rkSeq = [];
    for (var r = 0; r < rounds; r++) { rkSeq.push(key.slice(0)); giftKeyUpdate(key, temp); }
    return rkSeq;
  }

  /* 加密时预先把每轮的轮常数取出（解密要倒序用），这里直接顺序跑即可 */
  function giftCore(pt, kb, rounds, enc, rkSeqIn) {
    var nn = pt.length * 2;                 /* nibble 数 */
    var s = bytesToNibbles(pt, nn);
    var bits = new Uint8Array(nn * 4), permBits = new Uint8Array(nn * 4), keyBits = new Uint8Array(128);
    var P = (nn === 32) ? GIFT_P128 : GIFT_P64;

    var r, i;
    /* 解密需要先推进到第 rounds-1 轮的密钥状态，故先记录所有轮密钥状态。
       若调用方已预计算（rkSeqIn），直接复用，不再重算。 */
    var rkSeq = rkSeqIn;
    if (!rkSeq) {
      var key = bytesToNibbles(kb, 32), temp = new Uint8Array(32);
      rkSeq = [];
      for (r = 0; r < rounds; r++) { rkSeq.push(key.slice(0)); giftKeyUpdate(key, temp); }
    }

    if (enc) {
      for (r = 0; r < rounds; r++) giftRound(s, rkSeq[r], bits, permBits, keyBits, P, GIFT_RC[r], true);
    } else {
      for (r = rounds - 1; r >= 0; r--) giftRoundDec(s, rkSeq[r], bits, permBits, keyBits, P, GIFT_RC[r]);
    }
    return nibblesToBytes(s);
  }

  function gift64Enc(pt, kb, rk) { return giftCore(pt, kb, 28, true, rk); }
  function gift64Dec(ct, kb, rk) { return giftCore(ct, kb, 28, false, rk); }
  function gift128Enc(pt, kb, rk) { return giftCore(pt, kb, 40, true, rk); }
  function gift128Dec(ct, kb, rk) { return giftCore(ct, kb, 40, false, rk); }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { gift64Enc: gift64Enc, gift64Dec: gift64Dec, gift128Enc: gift128Enc, gift128Dec: gift128Dec, giftKeySeq: giftKeySeq };
  }
  global.GIFT = { gift64Enc: gift64Enc, gift64Dec: gift64Dec, gift128Enc: gift128Enc, gift128Dec: gift128Dec, giftKeySeq: giftKeySeq };
})(typeof window !== 'undefined' ? window : globalThis);
