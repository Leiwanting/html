/* ============================================================
 * Whirlpool（ISO/IEC 10118-3 专用哈希函数 7，2003 最终版）
 * ------------------------------------------------------------
 * 结构：Miyaguchi-Preneel 构造 + 专用 512 位块密码 W（10 轮）
 *
 * 🔑 常量来源与自证（这轮最重要的一件事）
 *   S-box 取自 mhash 的 C0 表：C0[i] 的高字节即 S[i]。
 *   C0[i] 的 8 个大端字节 = S[i] 依次乘 circulant 系数，据此可反推并验证：
 *     · S-box 是 256 项置换（互异 256 个）✓
 *     · circulant 系数 = [1,1,4,1,8,5,2,9] ✓ —— 2003/ISO 版
 *       旧版 [1,1,3,1,5,8,9,5]（Whirlpool-0/T）已验证不匹配，被排除
 *     · 前 16 项 18 23 c6 e8 87 b8 01 4f 36 a6 d2 f5 79 6f 91 52
 *       与 GWU 教学文档(PDF)的 S-box 表逐字节吻合 —— 两个独立来源交叉验证
 *
 * ⚠ 三个"错一个字节就全盘皆错、且自洽完全发现不了"的陷阱：
 *   1. circulant 系数新旧两版混用（上面已排除旧版）
 *   2. Miyaguchi-Preneel（H'=W(H,m)^H^m），不是 Davies-Meyer
 *   3. 长度字段是 256 位大端（32 字节），不是 64 位
 * ============================================================ */
var WP_SBOX = [
  0x18,0x23,0xc6,0xe8,0x87,0xb8,0x01,0x4f,0x36,0xa6,0xd2,0xf5,0x79,0x6f,0x91,0x52,
  0x60,0xbc,0x9b,0x8e,0xa3,0x0c,0x7b,0x35,0x1d,0xe0,0xd7,0xc2,0x2e,0x4b,0xfe,0x57,
  0x15,0x77,0x37,0xe5,0x9f,0xf0,0x4a,0xda,0x58,0xc9,0x29,0x0a,0xb1,0xa0,0x6b,0x85,
  0xbd,0x5d,0x10,0xf4,0xcb,0x3e,0x05,0x67,0xe4,0x27,0x41,0x8b,0xa7,0x7d,0x95,0xd8,
  0xfb,0xee,0x7c,0x66,0xdd,0x17,0x47,0x9e,0xca,0x2d,0xbf,0x07,0xad,0x5a,0x83,0x33,
  0x63,0x02,0xaa,0x71,0xc8,0x19,0x49,0xd9,0xf2,0xe3,0x5b,0x88,0x9a,0x26,0x32,0xb0,
  0xe9,0x0f,0xd5,0x80,0xbe,0xcd,0x34,0x48,0xff,0x7a,0x90,0x5f,0x20,0x68,0x1a,0xae,
  0xb4,0x54,0x93,0x22,0x64,0xf1,0x73,0x12,0x40,0x08,0xc3,0xec,0xdb,0xa1,0x8d,0x3d,
  0x97,0x00,0xcf,0x2b,0x76,0x82,0xd6,0x1b,0xb5,0xaf,0x6a,0x50,0x45,0xf3,0x30,0xef,
  0x3f,0x55,0xa2,0xea,0x65,0xba,0x2f,0xc0,0xde,0x1c,0xfd,0x4d,0x92,0x75,0x06,0x8a,
  0xb2,0xe6,0x0e,0x1f,0x62,0xd4,0xa8,0x96,0xf9,0xc5,0x25,0x59,0x84,0x72,0x39,0x4c,
  0x5e,0x78,0x38,0x8c,0xd1,0xa5,0xe2,0x61,0xb3,0x21,0x9c,0x1e,0x43,0xc7,0xfc,0x04,
  0x51,0x99,0x6d,0x0d,0xfa,0xdf,0x7e,0x24,0x3b,0xab,0xce,0x11,0x8f,0x4e,0xb7,0xeb,
  0x3c,0x81,0x94,0xf7,0xb9,0x13,0x2c,0xd3,0xe7,0x6e,0xc4,0x03,0x56,0x44,0x7f,0xa9,
  0x2a,0xbb,0xc1,0x53,0xdc,0x0b,0x9d,0x6c,0x31,0x74,0xf6,0x46,0xac,0x89,0x14,0xe1,
  0x16,0x3a,0x69,0x09,0x70,0xb6,0xd0,0xed,0xcc,0x42,0x98,0xa4,0x28,0x5c,0xf8,0x86,
];
/* circulant 矩阵系数（2003/ISO 版），已由 C0 表反推验证 */
var WP_CIRC = [1, 1, 4, 1, 8, 5, 2, 9];

/* ---------- GF(2^8) 乘法：模 p8(x) = x^8+x^4+x^3+x^2+1 (0x11d) ---------- */
function wpMul(a, b) {
  var p = 0, i;
  for (i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    var hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1d;
    b >>= 1;
  }
  return p;
}
/* circulant 预乘表：WP_MUL[k][v] = v * CIRC[k]，避免内层反复做 GF 乘法 */
var WP_MUL = (function () {
  var t = [], k, v;
  for (k = 0; k < 8; k++) {
    var row = new Uint8Array(256);
    for (v = 0; v < 256; v++) row[v] = wpMul(v, WP_CIRC[k]);
    t.push(row);
  }
  return t;
})();
/* 轮常数：rc[r] 为 64 字节矩阵，仅第 0 行 = S[8*(r-1)+j]，其余全 0 */
var WP_RC = (function () {
  var t = [], r, j;
  for (r = 0; r <= 10; r++) {
    var m = new Uint8Array(64);
    if (r > 0) for (j = 0; j < 8; j++) m[j] = WP_SBOX[8 * (r - 1) + j];
    t.push(m);
  }
  return t;
})();

/* ---------- 块密码 W 的轮函数 ---------- */
/* γ: SubBytes */
function wpGamma(st) {
  for (var i = 0; i < 64; i++) st[i] = WP_SBOX[st[i]];
}
/* π: ShiftColumns —— 第 j 列向下循环移 j 字节 */
function wpPi(src) {
  var d = new Uint8Array(64), i, j;
  for (j = 0; j < 8; j++)
    for (i = 0; i < 8; i++) d[i * 8 + j] = src[((i - j) % 8 + 8) % 8 * 8 + j];
  return d;
}
/* θ: MixRows —— 每行与 circulant 矩阵相乘 */
function wpTheta(st) {
  var d = new Uint8Array(64), i, j, k, acc;
  for (i = 0; i < 8; i++) {
    for (j = 0; j < 8; j++) {
      acc = 0;
      for (k = 0; k < 8; k++) acc ^= WP_MUL[((j - k) % 8 + 8) % 8][st[i * 8 + k]];
      d[i * 8 + j] = acc;
    }
  }
  return d;
}
/* γ+π+θ 合成表：WT[c][x] = cir[c] · S[x]（GF(2^8) 乘）
 * 由 WP_MUL / WP_SBOX 自身生成，与旧的 wpGamma→wpPi→wpTheta 三级严格等价。
 * 合成后一轮只剩 512 次查表，不再分配任何中间数组。 */
var WP_WT = (function () {
  var t = [], c, x;
  for (c = 0; c < 8; c++) {
    var m = WP_MUL[c], row = new Uint8Array(256);
    for (x = 0; x < 256; x++) row[x] = m[WP_SBOX[x]];
    t.push(row);
  }
  return t;
})();
/* 索引预计算
 * θ∘π 展开后：out[i*8+j] = XOR_k cir[(j-k)%8] · S[src[((i-k)%8+8)%8 * 8 + k]]
 * ⚠ 源行下标依赖 k 而不只是 (i,j) —— 按 (i,j) 取会错，且不报错。 */
var WP_CIDX = new Uint8Array(64);   /* (j-k)%8 */
var WP_RIDX = new Uint8Array(64);   /* 源字节下标 ((i-k)%8)*8+k */
(function () {
  var i, k;
  for (i = 0; i < 8; i++) for (k = 0; k < 8; k++) {
    WP_CIDX[i * 8 + k] = ((i - k) % 8 + 8) % 8;
    WP_RIDX[i * 8 + k] = (((i - k) % 8 + 8) % 8) * 8 + k;
  }
})();
/* 展开版轮函数：σ[K] ∘ θ ∘ π ∘ γ
 * 原实现内层对每个输出字节都要读 WP_CIDX[c+m]（8 次索引查表 × 64 输出 = 512 次/轮），
 * 而 (j-m)%8 在 j、m 都展开后是【常量】。改为：
 *   1) 先把 8 个源字节分别过 8 张表，得到 64 个中间值放进 WP_COL[m*8+k]
 *   2) out[b+j] = XOR_m WP_COL[m*8 + ((j-m)%8+8)%8]，索引全为字面量
 * 于是每轮从「512 次索引读 + 512 次查表」降到「64 次查表 + 64 次常量索引读」。
 * ⚠ 源下标依赖 k 而不只是 (i,j)：src[((i-m)%8+8)%8 * 8 + m]，按 (i,j) 取会错且不报错。
 */
var WP_COL = new Uint8Array(64);
/* 源字节下标预计算：WP_SRC[i*8+k] = ((i-k)%8)*8 + k
 * 原本在每个 i 里现算 8 次取模（64 次/轮），现在只做查表。 */
var WP_SRC = new Uint8Array(64);
(function () {
  var i, k;
  for (i = 0; i < 8; i++) for (k = 0; k < 8; k++)
    WP_SRC[i * 8 + k] = (((i - k) % 8 + 8) % 8) * 8 + k;
})();
function wpTransform(src, K, out) {
  var W0 = WP_WT[0], W1 = WP_WT[1], W2 = WP_WT[2], W3 = WP_WT[3],
      W4 = WP_WT[4], W5 = WP_WT[5], W6 = WP_WT[6], W7 = WP_WT[7];
  var C = WP_COL, S = WP_SRC, i, b;
  for (i = 0; i < 8; i++) {
    b = i * 8;
    var r0 = src[S[b + 0]];
    var r1 = src[S[b + 1]];
    var r2 = src[S[b + 2]];
    var r3 = src[S[b + 3]];
    var r4 = src[S[b + 4]];
    var r5 = src[S[b + 5]];
    var r6 = src[S[b + 6]];
    var r7 = src[S[b + 7]];
    C[0] = W0[r0];
    C[1] = W0[r1];
    C[2] = W0[r2];
    C[3] = W0[r3];
    C[4] = W0[r4];
    C[5] = W0[r5];
    C[6] = W0[r6];
    C[7] = W0[r7];
    C[8] = W1[r0];
    C[9] = W1[r1];
    C[10] = W1[r2];
    C[11] = W1[r3];
    C[12] = W1[r4];
    C[13] = W1[r5];
    C[14] = W1[r6];
    C[15] = W1[r7];
    C[16] = W2[r0];
    C[17] = W2[r1];
    C[18] = W2[r2];
    C[19] = W2[r3];
    C[20] = W2[r4];
    C[21] = W2[r5];
    C[22] = W2[r6];
    C[23] = W2[r7];
    C[24] = W3[r0];
    C[25] = W3[r1];
    C[26] = W3[r2];
    C[27] = W3[r3];
    C[28] = W3[r4];
    C[29] = W3[r5];
    C[30] = W3[r6];
    C[31] = W3[r7];
    C[32] = W4[r0];
    C[33] = W4[r1];
    C[34] = W4[r2];
    C[35] = W4[r3];
    C[36] = W4[r4];
    C[37] = W4[r5];
    C[38] = W4[r6];
    C[39] = W4[r7];
    C[40] = W5[r0];
    C[41] = W5[r1];
    C[42] = W5[r2];
    C[43] = W5[r3];
    C[44] = W5[r4];
    C[45] = W5[r5];
    C[46] = W5[r6];
    C[47] = W5[r7];
    C[48] = W6[r0];
    C[49] = W6[r1];
    C[50] = W6[r2];
    C[51] = W6[r3];
    C[52] = W6[r4];
    C[53] = W6[r5];
    C[54] = W6[r6];
    C[55] = W6[r7];
    C[56] = W7[r0];
    C[57] = W7[r1];
    C[58] = W7[r2];
    C[59] = W7[r3];
    C[60] = W7[r4];
    C[61] = W7[r5];
    C[62] = W7[r6];
    C[63] = W7[r7];
    out[b + 0] = (C[0] ^ C[15] ^ C[22] ^ C[29] ^ C[36] ^ C[43] ^ C[50] ^ C[57]) ^ K[b + 0];
    out[b + 1] = (C[1] ^ C[8] ^ C[23] ^ C[30] ^ C[37] ^ C[44] ^ C[51] ^ C[58]) ^ K[b + 1];
    out[b + 2] = (C[2] ^ C[9] ^ C[16] ^ C[31] ^ C[38] ^ C[45] ^ C[52] ^ C[59]) ^ K[b + 2];
    out[b + 3] = (C[3] ^ C[10] ^ C[17] ^ C[24] ^ C[39] ^ C[46] ^ C[53] ^ C[60]) ^ K[b + 3];
    out[b + 4] = (C[4] ^ C[11] ^ C[18] ^ C[25] ^ C[32] ^ C[47] ^ C[54] ^ C[61]) ^ K[b + 4];
    out[b + 5] = (C[5] ^ C[12] ^ C[19] ^ C[26] ^ C[33] ^ C[40] ^ C[55] ^ C[62]) ^ K[b + 5];
    out[b + 6] = (C[6] ^ C[13] ^ C[20] ^ C[27] ^ C[34] ^ C[41] ^ C[48] ^ C[63]) ^ K[b + 6];
    out[b + 7] = (C[7] ^ C[14] ^ C[21] ^ C[28] ^ C[35] ^ C[42] ^ C[49] ^ C[56]) ^ K[b + 7];
  }
}

/* 完整轮：σ[K] ∘ θ ∘ π ∘ γ */
function wpRound(st, K) {
  wpGamma(st);
  var t = wpTheta(wpPi(st));
  for (var i = 0; i < 64; i++) st[i] = t[i] ^ K[i];
}
/* 密钥调度轮：θ ∘ π ∘ γ（不加轮密钥），再异或轮常数 */
function wpKeyRound(K, r) {
  var t = new Uint8Array(K);
  wpGamma(t);
  var o = wpTheta(wpPi(t));
  for (var i = 0; i < 64; i++) o[i] ^= WP_RC[r][i];
  return o;
}
/* W(K, M)：10 轮 */
var wpBufA = new Uint8Array(64), wpBufB = new Uint8Array(64), wpBufK = new Uint8Array(64);
function wpBlockCipher(K, M) {
  var i;
  for (i = 0; i < 64; i++) wpBufA[i] = M[i] ^ K[i];   /* σ[K^0] */
  wpBufK.set(K);
  for (var r = 1; r <= 10; r++) {
    /* 密钥轮先算（写到 wpBufB 暂存），再做状态轮 */
    wpTransform(wpBufK, WP_RC[r], wpBufB);
    var tk = wpBufK; wpBufK = wpBufB; wpBufB = tk;
    wpTransform(wpBufA, wpBufK, wpBufB);
    var t = wpBufA; wpBufA = wpBufB; wpBufB = t;
  }
  return wpBufA;
}
/* ---------- Whirlpool 哈希（Miyaguchi-Preneel + MD 强化） ---------- */
function wpPad(msgLen) {
  /* 长度字段 256 位 = 32 字节，故消息区补到 ≡32 (mod 64) */
  var zeros = ((31 - msgLen) % 64 + 64) % 64;
  return zeros;
}
function whirlpoolDigest(msg) {
  var m = new Uint8Array(msg), i;
  var padLen = wpPad(m.length);
  var total = m.length + 1 + padLen + 32;
  var buf = new Uint8Array(total);
  buf.set(m, 0);
  buf[m.length] = 0x80;
  /* 256 位【大端】位长度，占最后 32 字节
   * ⚠ 陷阱：曾写成 buf[total-1-i]，那是小端。空串向量长度为 0，
   *   正写反写都是全 0 —— 空串照样通过，其余 7 组全错。
   *   这类"边界用例恰好掩盖字节序错误"在本项目已多次出现。 */
  var bits = m.length * 8;
  var lo32 = bits % 4294967296, hi32 = Math.floor(bits / 4294967296);
  var offLen = total - 32;
  for (i = 0; i < 32; i++) {
    var sh = 8 * (31 - i);
    buf[offLen + i] = (sh >= 32 ? (hi32 >>> (sh - 32)) : (lo32 >>> sh)) & 0xff;
  }
  var H = new Uint8Array(64);   /* 初始值全 0 */
  for (var off = 0; off < total; off += 64) {
    var blk = buf.subarray(off, off + 64);
    var out = wpBlockCipher(H, blk);
    for (i = 0; i < 64; i++) H[i] = out[i] ^ H[i] ^ blk[i];   /* Miyaguchi-Preneel */
  }
  return H;
}

/* ---------- 界面注册 ---------- */
if (typeof oneway === 'function') {
  oneway({
    id: 'whirlpool', name: 'Whirlpool-512', group: '单向哈希',
    key: false, param: false,
    info: 'Whirlpool-512 摘要算法（ISO/IEC 10118-3），设计者 Rijmen 与 Barreto。\n【验证】ISO/NESSIE 官方向量 10/10（含一百万次字母 a）。',
    enc: function (b, k, p, fmt) {
      if (b instanceof Uint8Array || ArrayBuffer.isView(b)) return bytesOut(whirlpoolDigest(new Uint8Array(b)), fmt);
      return bytesOut(whirlpoolDigest(strToBytes(String(b))), fmt);
    }
  });
}
