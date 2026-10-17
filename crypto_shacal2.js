/* ============================================================
 * SHACAL-2 —— 基于 SHA-256 压缩函数的分组密码（NESSIE / ISO/IEC 18033-3）
 *
 * 分组 256 位（32 字节），密钥最长 512 位（64 字节）。
 *
 * 加密定义（已用 Botan 测试向量 confirm）：
 *   把明文 32 字节视作 SHA-256 的 8 个链接变量 a..h，
 *   把密钥按 SHA-256 消息扩展成 W[0..63]，跑 64 轮压缩函数，
 *   输出「最终 working variables」，**不加**输入 h0（这是可逆的关键）。
 *
 * 解密即压缩函数逆推：由输出 a'..h' 还原输入 a..h。
 *   逆一轮的关键：t2 只依赖 a,b,c（= 输出的 b',c',d'），
 *   故 t1 = a' - t2，d = e' - t1，
 *   h = t1 - S1(e) - ch(e,f,g) - K - W，其中 e=f', f=g', g=h' 已知。
 *
 * 向量来源：Botan src/tests/data/block/shacal2.vec（注明 From Bouncy Castle）
 * ============================================================ */
(function (global) {
  'use strict';

  var K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

  /* 密钥 -> W[0..63]，与 SHA-256 消息扩展完全一致 */
  function expandKey(key) {
    var W = new Int32Array(64), i;
    for (i = 0; i < 16; i++) {
      W[i] = ((key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]) | 0;
    }
    for (i = 16; i < 64; i++) {
      var s0 = (rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3)) | 0;
      var s1 = (rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10)) | 0;
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }
    return W;
  }

  function loadWords(b) {
    var w = new Int32Array(8), i;
    for (i = 0; i < 8; i++) w[i] = ((b[4 * i] << 24) | (b[4 * i + 1] << 16) | (b[4 * i + 2] << 8) | b[4 * i + 3]) | 0;
    return w;
  }
  function storeWords(w) {
    var b = new Uint8Array(32), i;
    for (i = 0; i < 8; i++) {
      b[4 * i] = (w[i] >>> 24) & 255; b[4 * i + 1] = (w[i] >>> 16) & 255;
      b[4 * i + 2] = (w[i] >>> 8) & 255; b[4 * i + 3] = w[i] & 255;
    }
    return b;
  }

  /* 正向压缩：输出最终 working vars（不加 h0） */
  function compressFwd(h, W) {
    var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7], i;
    for (i = 0; i < 64; i++) {
      var S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) | 0;
      var ch = ((e & f) ^ ((~e) & g)) | 0;
      var t1 = (hh + S1 + ch + K256[i] + W[i]) | 0;
      var S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) | 0;
      var maj = ((a & b) ^ (a & c) ^ (b & c)) | 0;
      var t2 = (S0 + maj) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    return [a, b, c, d, e, f, g, hh];
  }

  /* 逆向压缩：由输出还原输入 */
  function compressBwd(out, W) {
    var a = out[0], b = out[1], c = out[2], d = out[3], e = out[4], f = out[5], g = out[6], hh = out[7], i;
    for (i = 63; i >= 0; i--) {
      /* 输出态的 a,b,c,d,e,f,g,h 记为此轮结果 */
      var oa = a, ob = b, oc = c, od = d, oe = e, of_ = f, og = g, oh = hh;
      /* 输入：a0=ob, b0=oc, c0=od, e0=of_, f0=og, g0=oh, h0=? , d0=? */
      var ia = ob, ib = oc, ic = od, ie = of_, if_ = og, ig = oh;
      var S0 = (rotr(ia, 2) ^ rotr(ia, 13) ^ rotr(ia, 22)) | 0;
      var maj = ((ia & ib) ^ (ia & ic) ^ (ib & ic)) | 0;
      var t2 = (S0 + maj) | 0;
      var t1 = (oa - t2) | 0;
      var id = (oe - t1) | 0;
      var S1 = (rotr(ie, 6) ^ rotr(ie, 11) ^ rotr(ie, 25)) | 0;
      var ch = ((ie & if_) ^ ((~ie) & ig)) | 0;
      var ih = (t1 - S1 - ch - K256[i] - W[i]) | 0;
      a = ia; b = ib; c = ic; d = id; e = ie; f = if_; g = ig; hh = ih;
    }
    return [a, b, c, d, e, f, g, hh];
  }

  function shacal2Enc(pt, key) { return storeWords(compressFwd(loadWords(pt), expandKey(key))); }
  function shacal2Dec(ct, key) { return storeWords(compressBwd(loadWords(ct), expandKey(key))); }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { shacal2Enc: shacal2Enc, shacal2Dec: shacal2Dec };
  }
  global.SHACAL2 = { shacal2Enc: shacal2Enc, shacal2Dec: shacal2Dec };
})(typeof window !== 'undefined' ? window : globalThis);
