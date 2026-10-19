/* ============================================================
 * Threefish-512 + Skein-512
 *
 * 常量与流程全部取自 Botan 2.19.5 官方源码（不是凭记忆写的）：
 *   src/lib/block/threefish_512/threefish_512.cpp   轮常量 / 置换 / 密钥注入
 *   src/lib/hash/skein/skein_512.cpp + .h           UBI 流程 / 类型码 / 配置串
 * 测试向量：
 *   src/tests/data/block/threefish.vec    （Threefish-512）
 *   src/tests/data/hash/skein.vec         （Skein-512(224/256/384/512/512,Test)）
 *
 * 64 位运算用 hi/lo 两个 32 位字表示（BLAKE2b 同款做法），避免 BigInt 的
 * 分配开销——Skein 每块 72 轮，用 BigInt 跑 3000 组向量会慢到不可用。
 *
 * 四个必须照抄、不能凭直觉推的点：
 *   1. 轮密钥注入是「4 轮 → 注入 → 4 轮 → 注入」，不是 8 轮后连注两次
 *   2. 注入里 X7 加的是「轮号 r」本身（不是 T 的某个分量）
 *   3. 置换是靠宏参数顺序体现的，A 组与 B 组下标集合不相交
 *   4. 奇偶字常量 C240 = 0x1BD11BDAA9FC1A22，K[8] = K0^..^K7^C240
 * ============================================================ */
(function (global) {
  'use strict';

  var C240H = 0x1BD11BDA, C240L = 0xA9FC1A22;

  /* ---------- 64 位基本运算（hi/lo 双 32 位字，数组 vh[] / vl[]） ---------- */
  function tfAdd(vh, vl, i, j) {
    var lo = (vl[i] + vl[j]) | 0;
    var c = (((vl[i] >>> 0) + (vl[j] >>> 0)) > 0xFFFFFFFF) ? 1 : 0;
    vh[i] = (vh[i] + vh[j] + c) | 0;
    vl[i] = lo;
  }
  function tfSub(vh, vl, i, j) {
    var lo = (vl[i] - vl[j]) | 0;
    var b = ((vl[i] >>> 0) < (vl[j] >>> 0)) ? 1 : 0;
    vh[i] = (vh[i] - vh[j] - b) | 0;
    vl[i] = lo;
  }
  function tfXor(vh, vl, i, j) { vh[i] ^= vh[j]; vl[i] ^= vl[j]; }
  function tfRotl(vh, vl, i, r) {
    var h = vh[i], l = vl[i], t;
    if (r === 0) return;
    if (r === 32) { vh[i] = l; vl[i] = h; return; }
    if (r < 32) {
      t = 32 - r;
      vh[i] = ((h << r) | (l >>> t)) | 0;
      vl[i] = ((l << r) | (h >>> t)) | 0;
    } else {
      var rr = r - 32, tt = 32 - rr;
      vh[i] = ((l << rr) | (h >>> tt)) | 0;
      vl[i] = ((h << rr) | (l >>> tt)) | 0;
    }
  }
  function tfRotr(vh, vl, i, r) { tfRotl(vh, vl, i, (64 - r) & 63); }

  function tfAddK(vh, vl, i, kh, kl) {
    var lo = (vl[i] + kl) | 0;
    var c = (((vl[i] >>> 0) + (kl >>> 0)) > 0xFFFFFFFF) ? 1 : 0;
    vh[i] = (vh[i] + kh + c) | 0;
    vl[i] = lo;
  }
  function tfSubK(vh, vl, i, kh, kl) {
    var lo = (vl[i] - kl) | 0;
    var b = ((vl[i] >>> 0) < (kl >>> 0)) ? 1 : 0;
    vh[i] = (vh[i] - kh - b) | 0;
    vl[i] = lo;
  }

  /* ---------- 轮结构（严格照抄 Botan 宏展开的参数顺序） ----------
   * 宏的 8 个参数是「变量名被重新排列」的写法：
   *   前 4 个是 A 组（做加法的一侧），后 4 个是 B 组（做旋转+异或的一侧）
   *   A[j] += B[j]；B[j] = rotl(B[j], R[j]) ^ A[j]
   */
  var TF_A = [
    [0, 2, 4, 6], [2, 4, 6, 0], [4, 6, 0, 2], [6, 0, 2, 4],
    [0, 2, 4, 6], [2, 4, 6, 0], [4, 6, 0, 2], [6, 0, 2, 4]
  ];
  var TF_B = [
    [1, 3, 5, 7], [1, 7, 5, 3], [1, 3, 5, 7], [1, 7, 5, 3],
    [1, 3, 5, 7], [1, 7, 5, 3], [1, 3, 5, 7], [1, 7, 5, 3]
  ];
  var TF_R = [
    [46, 36, 19, 37], [33, 27, 14, 42], [17, 49, 36, 39], [44, 9, 54, 56],
    [39, 30, 34, 24], [13, 50, 10, 17], [25, 29, 39, 43], [8, 35, 56, 22]
  ];

  function tfMix(vh, vl, d) {
    var A = TF_A[d], B = TF_B[d], R = TF_R[d], j;
    for (j = 0; j < 4; j++) tfAdd(vh, vl, A[j], B[j]);
    for (j = 0; j < 4; j++) { tfRotl(vh, vl, B[j], R[j]); tfXor(vh, vl, B[j], A[j]); }
  }
  function tfMixInv(vh, vl, d) {
    var A = TF_A[d], B = TF_B[d], R = TF_R[d], j;
    for (j = 0; j < 4; j++) tfXor(vh, vl, B[j], A[j]);
    for (j = 0; j < 4; j++) tfRotr(vh, vl, B[j], R[j]);
    for (j = 0; j < 4; j++) tfSub(vh, vl, A[j], B[j]);
  }

  /* 密钥注入：X7 额外加的是轮号 r 本身 */
  function tfInject(vh, vl, r, Kh, Kl, Th, Tl, dec) {
    var i, k;
    for (i = 0; i < 8; i++) {
      k = (r + i) % 9;
      if (dec) tfSubK(vh, vl, i, Kh[k], Kl[k]); else tfAddK(vh, vl, i, Kh[k], Kl[k]);
    }
    if (dec) {
      tfSubK(vh, vl, 5, Th[r % 3], Tl[r % 3]);
      tfSubK(vh, vl, 6, Th[(r + 1) % 3], Tl[(r + 1) % 3]);
      tfSubK(vh, vl, 7, 0, r);
    } else {
      tfAddK(vh, vl, 5, Th[r % 3], Tl[r % 3]);
      tfAddK(vh, vl, 6, Th[(r + 1) % 3], Tl[(r + 1) % 3]);
      tfAddK(vh, vl, 7, 0, r);
    }
  }

  function u64le(b, off) {
    return [((b[off + 4] | (b[off + 5] << 8) | (b[off + 6] << 16) | (b[off + 7] << 24)) | 0),
            ((b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) | 0)];
  }
  function putU64le(b, off, h, l) {
    b[off] = l & 0xff; b[off + 1] = (l >>> 8) & 0xff; b[off + 2] = (l >>> 16) & 0xff; b[off + 3] = (l >>> 24) & 0xff;
    b[off + 4] = h & 0xff; b[off + 5] = (h >>> 8) & 0xff; b[off + 6] = (h >>> 16) & 0xff; b[off + 7] = (h >>> 24) & 0xff;
  }
  function loadWords(bytes, n, off) {
    var vh = new Int32Array(n), vl = new Int32Array(n), i, t;
    off = off || 0;
    for (i = 0; i < n; i++) { t = u64le(bytes, off + 8 * i); vh[i] = t[0]; vl[i] = t[1]; }
    return [vh, vl];
  }
  function storeWords(vh, vl, n, out) {
    var i;
    for (i = 0; i < n; i++) putU64le(out, 8 * i, vh[i], vl[i]);
  }
  function parity(Kh, Kl) {
    var h = C240H, l = C240L, i;
    for (i = 0; i < 8; i++) { h ^= Kh[i]; l ^= Kl[i]; }
    Kh[8] = h | 0; Kl[8] = l | 0;
  }

  /* ---------- Threefish-512 核心（72 轮） ----------
   * 结构（照抄 Botan，注入是穿插的，不是 8 轮后连注两次）：
   *   inject(0)
   *   for r=0..8:  4 轮(d=0..3) → inject(2r+1) → 4 轮(d=4..7) → inject(2r+2)
   * feedfwd=True 时（Skein 用）结束后把 K 更新为 M ^ X 并重算奇偶字
   */
  function tfCore(vh, vl, Kh, Kl, Th, Tl, feedfwd) {
    var Mh = null, Ml = null, i, r, d;
    if (feedfwd) {
      Mh = new Int32Array(8); Ml = new Int32Array(8);
      for (i = 0; i < 8; i++) { Mh[i] = vh[i]; Ml[i] = vl[i]; }
    }
    tfInject(vh, vl, 0, Kh, Kl, Th, Tl, false);
    for (r = 0; r < 9; r++) {
      for (d = 0; d < 4; d++) tfMix(vh, vl, d);
      tfInject(vh, vl, 2 * r + 1, Kh, Kl, Th, Tl, false);
      for (d = 4; d < 8; d++) tfMix(vh, vl, d);
      tfInject(vh, vl, 2 * r + 2, Kh, Kl, Th, Tl, false);
    }
    if (feedfwd) {
      for (i = 0; i < 8; i++) { Kh[i] = Mh[i] ^ vh[i]; Kl[i] = Ml[i] ^ vl[i]; }
      parity(Kh, Kl);
    }
  }

  function tfCoreDec(vh, vl, Kh, Kl, Th, Tl) {
    var g, d;
    tfInject(vh, vl, 18, Kh, Kl, Th, Tl, true);
    for (g = 0; g < 9; g++) {
      for (d = 7; d >= 4; d--) tfMixInv(vh, vl, d);
      tfInject(vh, vl, 2 * (8 - g) + 1, Kh, Kl, Th, Tl, true);
      for (d = 3; d >= 0; d--) tfMixInv(vh, vl, d);
      tfInject(vh, vl, 2 * (8 - g), Kh, Kl, Th, Tl, true);
    }
  }

  function tfSetKey(keyBytes) {
    var t = loadWords(keyBytes, 8);
    var Kh = new Int32Array(9), Kl = new Int32Array(9), i;
    for (i = 0; i < 8; i++) { Kh[i] = t[0][i]; Kl[i] = t[1][i]; }
    parity(Kh, Kl);
    return { Kh: Kh, Kl: Kl, Th: new Int32Array(3), Tl: new Int32Array(3) };
  }
  /* 分组密码形态：密钥 64 字节，tweak 全 0（Botan key_schedule 把 tweak 清零） */
  /* 预计算版：st 复用。tfCore 在 feedfwd=false 时不修改 Kh/Kl，故可安全复用 */
  function tf512EncKS(pt, st) {
    var t = loadWords(pt, 8);
    tfCore(t[0], t[1], st.Kh, st.Kl, st.Th, st.Tl, false);
    var out = new Uint8Array(64);
    storeWords(t[0], t[1], 8, out);
    return out;
  }
  function tf512DecKS(ct, st) {
    var t = loadWords(ct, 8);
    tfCoreDec(t[0], t[1], st.Kh, st.Kl, st.Th, st.Tl);
    var out = new Uint8Array(64);
    storeWords(t[0], t[1], 8, out);
    return out;
  }

  /* ============================================================
   * Skein-512（UBI 模式）
   * ============================================================ */
  var SKEIN_CONFIG = 4, SKEIN_PERSONAL = 8, SKEIN_MSG = 48, SKEIN_OUTPUT = 63;
  var FIRST_FLAG_H = 1 << 30;   /* 1<<62 落在 hi 的 bit30 */
  var FINAL_FLAG_H = 1 << 31;   /* 1<<63 落在 hi 的 bit31 */

  function setTweak(Th, Tl, type, isFinal) {
    Th[0] = 0; Tl[0] = 0;
    Th[1] = ((type << 24) | FIRST_FLAG_H | (isFinal ? FINAL_FLAG_H : 0)) | 0;
    Tl[1] = 0;
  }

  function skeinInit() {
    var Kh = new Int32Array(9), Kl = new Int32Array(9);
    var Th = new Int32Array(3), Tl = new Int32Array(3);
    var i;
    for (i = 0; i < 8; i++) { Kh[i] = 0; Kl[i] = 0; }
    parity(Kh, Kl);
    return { Kh: Kh, Kl: Kl, Th: Th, Tl: Tl };
  }

  var UBI_BLK = new Uint8Array(64);
  function ubi(st, block, len) {
    var done = 0, toProc, i, lo, c;
    var vh = new Int32Array(8), vl = new Int32Array(8);
    var Th = st.Th, Tl = st.Tl;
    do {
      toProc = (len - done > 64) ? 64 : (len - done);
      lo = (Tl[0] + toProc) | 0;
      c = (((Tl[0] >>> 0) + toProc) > 0xFFFFFFFF) ? 1 : 0;
      Th[0] = (Th[0] + c) | 0; Tl[0] = lo;
      /* 不足 64 字节的部分补零（Botan 里 M 初值为 0） */
      for (i = 0; i < 64; i++) UBI_BLK[i] = 0;
      for (i = 0; i < toProc; i++) UBI_BLK[i] = block[done + i];
      for (i = 0; i < 8; i++) {
        var t = u64le(UBI_BLK, 8 * i);
        vh[i] = t[0]; vl[i] = t[1];
      }
      Th[2] = Th[0] ^ Th[1]; Tl[2] = Tl[0] ^ Tl[1];
      tfCore(vh, vl, st.Kh, st.Kl, Th, Tl, true);
      Th[1] &= ~FIRST_FLAG_H;
      done += toProc;
    } while (done < len);
  }

  function skeinHash(msg, outBits, pers) {
    var st = skeinInit();
    var i;
    /* 配置块：ASCII "SHA3" + 版本 01 00 00 00 + 输出位数(8 字节 LE) + 树参数(24 字节 0) */
    var cfg = new Uint8Array(32);
    cfg[0] = 0x53; cfg[1] = 0x48; cfg[2] = 0x41; cfg[3] = 0x33; cfg[4] = 0x01;
    /* Botan 是 store_le(uint32_t(output_bits), config_str+8)，只写 4 字节。
       这里绝不能写成 8 字节循环：JS 的 >>> 位移量取模 32，
       写 i=4..7 时 (x >>> 32) 等于 (x >>> 0)，会把低字节复制到偏移 12，
       结果长度完全正确、只有内容错——正是最难查的那类 bug。 */
    for (i = 0; i < 4; i++) cfg[8 + i] = (outBits >>> (8 * i)) & 0xff;
    setTweak(st.Th, st.Tl, SKEIN_CONFIG, true);
    ubi(st, cfg, 32);

    if (pers && pers.length) {
      var pb = new Uint8Array(pers.length);
      for (i = 0; i < pers.length; i++) pb[i] = pers.charCodeAt(i) & 0xff;
      setTweak(st.Th, st.Tl, SKEIN_PERSONAL, true);
      ubi(st, pb, pb.length);
    }

    setTweak(st.Th, st.Tl, SKEIN_MSG, false);

    var n = msg.length;
    /* 与 Botan 一致：完整块数取 (n-1)/64，最后一块留到 final 里处理 */
    var full = (n === 0) ? 0 : Math.floor((n - 1) / 64);
    if (full > 0) ubi(st, msg, full * 64);
    var rem = n - full * 64;
    var buf = new Uint8Array(64);
    for (i = 0; i < rem; i++) buf[i] = msg[full * 64 + i];

    st.Th[1] |= FINAL_FLAG_H;
    ubi(st, buf, rem);

    var counter = new Uint8Array(8);
    setTweak(st.Th, st.Tl, SKEIN_OUTPUT, true);
    ubi(st, counter, 8);

    var outBytes = Math.floor(outBits / 8);
    var out = new Uint8Array(outBytes);
    var tmp = new Uint8Array(64);
    storeWords(st.Kh, st.Kl, 8, tmp);
    for (i = 0; i < outBytes; i++) out[i] = tmp[i];
    return out;
  }

  function tf512Enc(pt, keyBytes) { return tf512EncKS(pt, tfSetKey(keyBytes)); }
  function tf512Dec(ct, keyBytes) { return tf512DecKS(ct, tfSetKey(keyBytes)); }

  global.THREEFISH = { tf512Enc: tf512Enc, tf512Dec: tf512Dec,
                       tfSetKey: tfSetKey, tf512EncKS: tf512EncKS, tf512DecKS: tf512DecKS };
  /* _test 只给回归测试用：threefish.vec 里有一条带 tweak 的向量，
   普通分组密码入口固定 tweak=0，无法覆盖，只能从内部函数验证。 */
  global.SKEIN = { skeinHash: skeinHash, _test: { skeinInit: skeinInit, ubi: ubi, setTweak: setTweak, parity: parity, tfCore: tfCore } };
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { tf512Enc: tf512Enc, tf512Dec: tf512Dec, skeinHash: skeinHash,
                       tfSetKey: tfSetKey, tf512EncKS: tf512EncKS, tf512DecKS: tf512DecKS };
  }
})(typeof window !== 'undefined' ? window : globalThis);

/* ---------- 界面注册 ---------- */
(function () {
  var g = (typeof window !== 'undefined') ? window : globalThis;
  var tf = g.THREEFISH, sk = g.SKEIN;
  if (!tf || !sk) return;

  /* Threefish-512 作为分组密码（块 64 字节、密钥 64 字节、tweak 置 0） */
  if (typeof regSym === 'function' || typeof reg === 'function') {
    var item = {
      id: 'threefish512', name: 'Threefish-512（Skein 核心可调分组密码）', group: '对称加密',
      blockSize: 64, keyLen: 64,
      makeBlockFn: function (keyBytes) {
        var st = tf.tfSetKey(keyBytes);
        return { enc: function (b) { return tf.tf512EncKS(b, st); },
                 dec: function (b) { return tf.tf512DecKS(b, st); } };
      },
      info: 'Skein 哈希的核心部件，块 512 位、密钥 512 位、另带 128 位 tweak（此处置 0）。72 轮，每 4 轮注入一次轮密钥，Skein 风格 MIX 只含加法/旋转/异或。\n【验证】Botan threefish.vec 官方向量。\n【注意】块为 64 字节，与限 16 字节块的模式（XTS/LRW）不兼容。'
    };
    if (typeof regSym === 'function') regSym(item);
    else { item.key = true; item.isSym = true; reg(item); }
  }

  if (typeof oneway !== 'function') return;
  var G = '单向哈希';
  var VARIANTS = [
    ['skein512-224', 224, null, 'Skein-512 的 224 位输出版本'],
    ['skein512-256', 256, null, 'Skein-512 的 256 位输出版本'],
    ['skein512-384', 384, null, 'Skein-512 的 384 位输出版本'],
    ['skein512-512', 512, null, 'Skein-512 的完整 512 位输出版本'],
    ['skein512-512-test', 512, 'Test', 'Skein-512-512 带个性化串 "Test" 的版本']
  ];
  VARIANTS.forEach(function (v) {
    var id = v[0], bits = v[1], pers = v[2], desc = v[3];
    var toB = function (b) {
      if (b instanceof Uint8Array || ArrayBuffer.isView(b)) return new Uint8Array(b);
      return strToBytes(String(b));
    };
    oneway({
      id: id, name: 'Skein-512' + (pers ? '(' + bits + ',' + pers + ')' : '-' + bits),
      group: G, key: false, param: false,
      info: desc + '。Skein 是 Schneier 等设计的 SHA-3 竞赛算法，基于 Threefish-512 可调分组密码、用 UBI 模式串联，配置串为 ASCII "SHA3" + 版本号 1。\n【验证】Botan skein.vec 官方向量。',
      enc: function (b, k, p, fmt) {
        return bytesOut(sk.skeinHash(toB(b), bits, pers), fmt || 'hex');
      }
    });
  });
})();
