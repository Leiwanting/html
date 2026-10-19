/* ============================================================
 * NOEKEON —— 128 位分组 / 128 位密钥（NESSIE 入围，Joan Daemen 等）
 *
 * 结构与常量全部取自 Botan 官方实现 src/lib/block/noekeon/noekeon.cpp。
 *
 * 三个要点：
 *   1. gamma 是对合（自逆），所以加密解密共用同一函数
 *   2. theta 也是对合，但**解密用 DK、加密用 EK**，两者不同
 *   3. 轮常数共 17 个：加密用 RC[0..15] 进轮、RC[16] 收尾；
 *      解密反向用 RC[16..1] 进轮、RC[0] 收尾
 *   4. Pi1/Pi2 只对 A1/A2/A3 旋转，A0 不动（A0 只吃轮常数）
 *
 * 向量来源：Botan src/tests/data/block/noekeon.vec
 * ============================================================ */
(function (global) {
  'use strict';

  var RC = [0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4];

  function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
  function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

  /* Theta 的对合性质：带 EK 或带 DK 都是同一个流程，只是异或的常量不同 */
  function theta(A, EK) {
    var T = (A[0] ^ A[2]) >>> 0;
    T = (T ^ rotl(T, 8) ^ rotr(T, 8)) >>> 0;
    A[1] = (A[1] ^ T) >>> 0;
    A[3] = (A[3] ^ T) >>> 0;

    if (EK) { A[0] = (A[0] ^ EK[0]) >>> 0; A[1] = (A[1] ^ EK[1]) >>> 0; A[2] = (A[2] ^ EK[2]) >>> 0; A[3] = (A[3] ^ EK[3]) >>> 0; }

    T = (A[1] ^ A[3]) >>> 0;
    T = (T ^ rotl(T, 8) ^ rotr(T, 8)) >>> 0;
    A[0] = (A[0] ^ T) >>> 0;
    A[2] = (A[2] ^ T) >>> 0;
  }

  /* gamma 是对合，无需单独写逆 */
  function gamma(A) {
    var T;
    A[1] = (A[1] ^ (~A[3] & ~A[2])) >>> 0;
    A[0] = (A[0] ^ (A[2] & A[1])) >>> 0;
    T = A[3]; A[3] = A[0]; A[0] = T;
    A[2] = (A[2] ^ A[0] ^ A[1] ^ A[3]) >>> 0;
    A[1] = (A[1] ^ (~A[3] & ~A[2])) >>> 0;
    A[0] = (A[0] ^ (A[2] & A[1])) >>> 0;
  }

  function pi1(A) { A[1] = rotl(A[1], 1); A[2] = rotl(A[2], 5); A[3] = rotl(A[3], 2); }
  function pi2(A) { A[1] = rotr(A[1], 1); A[2] = rotr(A[2], 5); A[3] = rotr(A[3], 2); }

  /* 与加密同构，但用 null key（不异或子密钥） */
  function keySchedule(key) {
    var A = new Uint32Array([
      ((key[0] << 24) | (key[1] << 16) | (key[2] << 8) | key[3]) >>> 0,
      ((key[4] << 24) | (key[5] << 16) | (key[6] << 8) | key[7]) >>> 0,
      ((key[8] << 24) | (key[9] << 16) | (key[10] << 8) | key[11]) >>> 0,
      ((key[12] << 24) | (key[13] << 16) | (key[14] << 8) | key[15]) >>> 0
    ]);
    var i;
    for (i = 0; i < 16; i++) {
      A[0] = (A[0] ^ RC[i]) >>> 0;
      theta(A, null);
      pi1(A); gamma(A); pi2(A);
    }
    A[0] = (A[0] ^ RC[16]) >>> 0;
    var DK = new Uint32Array([A[0], A[1], A[2], A[3]]);
    theta(A, null);
    var EK = new Uint32Array([A[0], A[1], A[2], A[3]]);
    return { EK: EK, DK: DK };
  }

  function toWords(b) {
    return new Uint32Array([
      ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0,
      ((b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]) >>> 0,
      ((b[8] << 24) | (b[9] << 16) | (b[10] << 8) | b[11]) >>> 0,
      ((b[12] << 24) | (b[13] << 16) | (b[14] << 8) | b[15]) >>> 0
    ]);
  }
  function toBytes(A) {
    var b = new Uint8Array(16), i;
    for (i = 0; i < 4; i++) { b[4 * i] = (A[i] >>> 24) & 255; b[4 * i + 1] = (A[i] >>> 16) & 255; b[4 * i + 2] = (A[i] >>> 8) & 255; b[4 * i + 3] = A[i] & 255; }
    return b;
  }

  /* 预计算密钥编排版：ks 由 keySchedule 算出后在整段数据上复用。
     ⚠ 原来每块都跑一次 keySchedule（16 轮 theta+pi+gamma），64KB 数据 = 4096 次白算。 */
  function noekeonEncKS(pt, ks) {
    var A = toWords(pt), j;
    for (j = 0; j != 16; ++j) {
      A[0] = (A[0] ^ RC[j]) >>> 0;
      theta(A, ks.EK);
      pi1(A); gamma(A); pi2(A);
    }
    A[0] = (A[0] ^ RC[16]) >>> 0;
    theta(A, ks.EK);
    return toBytes(A);
  }

  function noekeonDecKS(ct, ks) {
    var A = toWords(ct), j;
    for (j = 16; j != 0; --j) {
      theta(A, ks.DK);
      A[0] = (A[0] ^ RC[j]) >>> 0;
      pi1(A); gamma(A); pi2(A);
    }
    theta(A, ks.DK);
    A[0] = (A[0] ^ RC[0]) >>> 0;
    return toBytes(A);
  }

  function noekeonEnc(pt, key) { return noekeonEncKS(pt, keySchedule(key)); }
  function noekeonDec(ct, key) { return noekeonDecKS(ct, keySchedule(key)); }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { noekeonEnc: noekeonEnc, noekeonDec: noekeonDec,
                       keySchedule: keySchedule, noekeonEncKS: noekeonEncKS, noekeonDecKS: noekeonDecKS };
  }
  global.NOEKEON = { noekeonEnc: noekeonEnc, noekeonDec: noekeonDec,
                     keySchedule: keySchedule, noekeonEncKS: noekeonEncKS, noekeonDecKS: noekeonDecKS };
})(typeof window !== 'undefined' ? window : globalThis);
