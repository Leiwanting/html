'use strict';
/* ============================================================
 * crypto_blake2p.js —— BLAKE2bp / BLAKE2sp（BLAKE2 并行变体）
 *
 * 规范来源：BLAKE2 官方参考实现（github.com/BLAKE2/BLAKE2，ref/blake2bp-ref.c、
 *           ref/blake2sp-ref.c），常量（IV / sigma / 旋转量 / 参数块布局）
 *           均逐字节取自该源码，不凭记忆书写。
 * 验证：官方 KAT（testvectors/blake2bp-kat.txt、blake2sp-kat.txt）
 *       各 256 组，密钥 00..3f，输入长度 0..255，全部逐字节一致。
 *
 * 关键实现要点（照官方 C 逐行移植）：
 *  1. 叶子并行度：bp=4（块 128B），sp=8（块 64B）
 *  2. 消息按「128/64 字节块」轮转分配：第 i 个叶子取块 i, i+P, i+2P …
 *  3. 叶子的 outlen 被强制设为 inner_length（64/32），与 root 不同
 *  4. last_node 标记：root 恒置，仅最后一个叶子置；它决定末块 f[1] 是否全 1
 *  5. 参数块为 packed struct：b 版 node_offset@8(u32)、xof_length@12、
 *     node_depth@16、inner_length@17；s 版 xof_length@12(u16)、node_depth@14、
 *     inner_length@15
 *  6. BLAKE2s 的 G 旋转量为 16/12/8/7，与 BLAKE2b 的 32/24/16/63 不同
 *
 * 内核用 hi/lo 双 32 位字表示 64 位（BLAKE2b），避免 BigInt 开销；
 * 已用 BigInt 版本做等价对照（见 t_blake2p.js）。
 * ============================================================ */
(function () {

  if (typeof ALGOS === 'undefined' || typeof reg !== 'function') {
    console.error('crypto_blake2p.js 需要在 Encryption_and_decryption_logic.js 之后加载');
    return;
  }

  /* ---------- 常量：由官方 hex 字面量在运行时拆分，避免手写 hi/lo ---------- */
  var BIV_HEX = ['6a09e667f3bcc908', 'bb67ae8584caa73b', '3c6ef372fe94f82b', 'a54ff53a5f1d36f1',
    '510e527fade682d1', '9b05688c2b3e6c1f', '1f83d9abfb41bd6b', '5be0cd19137e2179'];
  var BIV_LO = [], BIV_HI = [];
  (function () {
    for (var i = 0; i < 8; i++) {
      var h = BIV_HEX[i];
      BIV_HI.push(parseInt(h.substr(0, 8), 16) >>> 0);
      BIV_LO.push(parseInt(h.substr(8, 8), 16) >>> 0);
    }
  })();

  var BSG = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
  ];
  var SSG = BSG.slice(0, 10);
  var SIV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];

  /* 每轮 8 个 G 作用的 (a,b,c,d) 下标 */
  var GIDX = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15],
  [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];

  function load32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] * 0x1000000)) >>> 0; }
  function store32(v, b, o) { b[o] = v & 0xff; b[o + 1] = (v >>> 8) & 0xff; b[o + 2] = (v >>> 16) & 0xff; b[o + 3] = (v >>> 24) & 0xff; }

  /* ---------------- BLAKE2b 压缩（hi/lo 双 32 位） ---------------- */
  function b2bCompress(S, block) {
    var mLo = new Array(16), mHi = new Array(16), i;
    for (i = 0; i < 16; i++) { mLo[i] = load32(block, i * 8); mHi[i] = load32(block, i * 8 + 4); }
    var vLo = new Array(16), vHi = new Array(16);
    for (i = 0; i < 8; i++) { vLo[i] = S.hLo[i]; vHi[i] = S.hHi[i]; }
    vLo[8] = BIV_LO[0]; vHi[8] = BIV_HI[0];
    vLo[9] = BIV_LO[1]; vHi[9] = BIV_HI[1];
    vLo[10] = BIV_LO[2]; vHi[10] = BIV_HI[2];
    vLo[11] = BIV_LO[3]; vHi[11] = BIV_HI[3];
    vLo[12] = (BIV_LO[4] ^ S.tLo) >>> 0; vHi[12] = (BIV_HI[4] ^ S.tHi) >>> 0;
    vLo[13] = (BIV_LO[5] ^ S.uLo) >>> 0; vHi[13] = (BIV_HI[5] ^ S.uHi) >>> 0;
    vLo[14] = (BIV_LO[6] ^ S.fLo) >>> 0; vHi[14] = (BIV_HI[6] ^ S.fHi) >>> 0;
    vLo[15] = (BIV_LO[7] ^ S.gLo) >>> 0; vHi[15] = (BIV_HI[7] ^ S.gHi) >>> 0;

    for (var r = 0; r < 12; r++) {
      var sg = BSG[r];
      for (var j = 0; j < 8; j++) {
        var ix = GIDX[j], p0 = ix[0], p1 = ix[1], p2 = ix[2], p3 = ix[3];
        var aL = vLo[p0], aH = vHi[p0], bL = vLo[p1], bH = vHi[p1];
        var cL = vLo[p2], cH = vHi[p2], dL = vLo[p3], dH = vHi[p3];
        var s0 = sg[2 * j], s1 = sg[2 * j + 1], t, cy, xL, xH;

        /* a = a + b + m[s0] */
        t = aL + bL; cy = t > 0xFFFFFFFF ? 1 : 0; aL = t >>> 0; aH = (aH + bH + cy) >>> 0;
        t = aL + mLo[s0]; cy = t > 0xFFFFFFFF ? 1 : 0; aL = t >>> 0; aH = (aH + mHi[s0] + cy) >>> 0;
        /* d = rotr64(d ^ a, 32) → 高低半字互换 */
        xL = (dL ^ aL) >>> 0; xH = (dH ^ aH) >>> 0; dL = xH; dH = xL;
        /* c = c + d */
        t = cL + dL; cy = t > 0xFFFFFFFF ? 1 : 0; cL = t >>> 0; cH = (cH + dH + cy) >>> 0;
        /* b = rotr64(b ^ c, 24) */
        xL = (bL ^ cL) >>> 0; xH = (bH ^ cH) >>> 0;
        bL = ((xL >>> 24) | (xH << 8)) >>> 0; bH = ((xH >>> 24) | (xL << 8)) >>> 0;
        /* a = a + b + m[s1] */
        t = aL + bL; cy = t > 0xFFFFFFFF ? 1 : 0; aL = t >>> 0; aH = (aH + bH + cy) >>> 0;
        t = aL + mLo[s1]; cy = t > 0xFFFFFFFF ? 1 : 0; aL = t >>> 0; aH = (aH + mHi[s1] + cy) >>> 0;
        /* d = rotr64(d ^ a, 16) */
        xL = (dL ^ aL) >>> 0; xH = (dH ^ aH) >>> 0;
        dL = ((xL >>> 16) | (xH << 16)) >>> 0; dH = ((xH >>> 16) | (xL << 16)) >>> 0;
        /* c = c + d */
        t = cL + dL; cy = t > 0xFFFFFFFF ? 1 : 0; cL = t >>> 0; cH = (cH + dH + cy) >>> 0;
        /* b = rotr64(b ^ c, 63) → 等价于循环左移 1 位 */
        xL = (bL ^ cL) >>> 0; xH = (bH ^ cH) >>> 0;
        bL = ((xL << 1) | (xH >>> 31)) >>> 0; bH = ((xH << 1) | (xL >>> 31)) >>> 0;

        vLo[p0] = aL; vHi[p0] = aH; vLo[p1] = bL; vHi[p1] = bH;
        vLo[p2] = cL; vHi[p2] = cH; vLo[p3] = dL; vHi[p3] = dH;
      }
    }
    for (i = 0; i < 8; i++) {
      S.hLo[i] = (S.hLo[i] ^ vLo[i] ^ vLo[i + 8]) >>> 0;
      S.hHi[i] = (S.hHi[i] ^ vHi[i] ^ vHi[i + 8]) >>> 0;
    }
  }

  function b2bInitParam(p) {
    var S = {
      hLo: new Array(8), hHi: new Array(8),
      tLo: 0, tHi: 0, uLo: 0, uHi: 0,   /* t[0] = (tLo,tHi)；t[1] = (uLo,uHi) */
      fLo: 0, fHi: 0, gLo: 0, gHi: 0,   /* f[0] = (fLo,fHi)；f[1] = (gLo,gHi) */
      buf: new Uint8Array(128), buflen: 0, outlen: p[0], last_node: 0
    };
    for (var i = 0; i < 8; i++) {
      S.hLo[i] = (BIV_LO[i] ^ load32(p, i * 8)) >>> 0;
      S.hHi[i] = (BIV_HI[i] ^ load32(p, i * 8 + 4)) >>> 0;
    }
    return S;
  }

  function b2bIncT(S, inc) {
    var s = S.tLo + inc, c1 = s > 0xFFFFFFFF ? 1 : 0;
    S.tLo = s >>> 0;
    var s2 = S.tHi + c1, c2 = s2 > 0xFFFFFFFF ? 1 : 0;
    S.tHi = s2 >>> 0;
    var s3 = S.uLo + c2, c3 = s3 > 0xFFFFFFFF ? 1 : 0;
    S.uLo = s3 >>> 0;
    S.uHi = (S.uHi + c3) >>> 0;
  }

  function b2bUpdate(S, inp) {
    var inlen = inp.length;
    if (inlen > 0) {
      var left = S.buflen, fill = 128 - left, off = 0, rem = inlen;
      if (inlen > fill) {
        S.buflen = 0;
        S.buf.set(inp.subarray(0, fill), left);
        b2bIncT(S, 128);
        b2bCompress(S, S.buf);
        off = fill; rem = inlen - fill;
        while (rem > 128) {
          b2bIncT(S, 128);
          b2bCompress(S, inp.subarray(off, off + 128));
          off += 128; rem -= 128;
        }
      }
      S.buf.set(inp.subarray(off, off + rem), S.buflen);
      S.buflen += rem;
    }
  }

  function b2bFinal(S) {
    b2bIncT(S, S.buflen);
    if (S.last_node) { S.gLo = 0xFFFFFFFF; S.gHi = 0xFFFFFFFF; }
    S.fLo = 0xFFFFFFFF; S.fHi = 0xFFFFFFFF;
    S.buf.fill(0, S.buflen);
    b2bCompress(S, S.buf);
    var out = new Uint8Array(64);
    for (var i = 0; i < 8; i++) { store32(S.hLo[i], out, i * 8); store32(S.hHi[i], out, i * 8 + 4); }
    return out;
  }

  /* ---------------- BLAKE2s 压缩（32 位原生） ---------------- */
  function b2sCompress(S, block) {
    var m = new Array(16), i;
    for (i = 0; i < 16; i++) m[i] = load32(block, i * 4);
    var v = new Array(16);
    for (i = 0; i < 8; i++) v[i] = S.h[i];
    v[8] = SIV[0]; v[9] = SIV[1]; v[10] = SIV[2]; v[11] = SIV[3];
    v[12] = (SIV[4] ^ S.t0) >>> 0; v[13] = (SIV[5] ^ S.t1) >>> 0;
    v[14] = (SIV[6] ^ S.f0) >>> 0; v[15] = (SIV[7] ^ S.f1) >>> 0;
    for (var r = 0; r < 10; r++) {
      var sg = SSG[r];
      for (var j = 0; j < 8; j++) {
        var ix = GIDX[j], p0 = ix[0], p1 = ix[1], p2 = ix[2], p3 = ix[3];
        var a = v[p0], b = v[p1], c = v[p2], d = v[p3];
        var s0 = sg[2 * j], s1 = sg[2 * j + 1];
        a = (a + b + m[s0]) >>> 0; d = rotr32(d ^ a, 16); c = (c + d) >>> 0; b = rotr32(b ^ c, 12);
        a = (a + b + m[s1]) >>> 0; d = rotr32(d ^ a, 8); c = (c + d) >>> 0; b = rotr32(b ^ c, 7);
        v[p0] = a; v[p1] = b; v[p2] = c; v[p3] = d;
      }
    }
    for (i = 0; i < 8; i++) S.h[i] = (S.h[i] ^ v[i] ^ v[i + 8]) >>> 0;
  }
  function rotr32(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

  function b2sInitParam(p) {
    var S = {
      h: new Array(8), t0: 0, t1: 0, f0: 0, f1: 0,
      buf: new Uint8Array(64), buflen: 0, outlen: p[0], last_node: 0
    };
    for (var i = 0; i < 8; i++) S.h[i] = (SIV[i] ^ load32(p, i * 4)) >>> 0;
    return S;
  }
  function b2sIncT(S, inc) {
    var s = S.t0 + inc;
    if (s > 0xFFFFFFFF) { S.t0 = s >>> 0; S.t1 = (S.t1 + 1) >>> 0; }
    else S.t0 = s >>> 0;
  }
  function b2sUpdate(S, inp) {
    var inlen = inp.length;
    if (inlen > 0) {
      var left = S.buflen, fill = 64 - left, off = 0, rem = inlen;
      if (inlen > fill) {
        S.buflen = 0;
        S.buf.set(inp.subarray(0, fill), left);
        b2sIncT(S, 64);
        b2sCompress(S, S.buf);
        off = fill; rem = inlen - fill;
        while (rem > 64) {
          b2sIncT(S, 64);
          b2sCompress(S, inp.subarray(off, off + 64));
          off += 64; rem -= 64;
        }
      }
      S.buf.set(inp.subarray(off, off + rem), S.buflen);
      S.buflen += rem;
    }
  }
  function b2sFinal(S) {
    b2sIncT(S, S.buflen);
    if (S.last_node) S.f1 = 0xFFFFFFFF;
    S.f0 = 0xFFFFFFFF;
    S.buf.fill(0, S.buflen);
    b2sCompress(S, S.buf);
    var out = new Uint8Array(32);
    for (var i = 0; i < 8; i++) store32(S.h[i], out, i * 4);
    return out;
  }

  /* ---------------- 参数块（packed struct 布局，见文件头注释） ---------------- */
  function paramB(outlen, keylen, fanout, depth, nodeOffset, nodeDepth, innerLength) {
    var p = new Uint8Array(64);
    p[0] = outlen; p[1] = keylen; p[2] = fanout; p[3] = depth;
    /* leaf_length@4 = 0 */
    store32(nodeOffset >>> 0, p, 8);
    /* xof_length@12 = 0 */
    p[16] = nodeDepth; p[17] = innerLength;
    return p;
  }
  function paramS(outlen, keylen, fanout, depth, nodeOffset, nodeDepth, innerLength) {
    var p = new Uint8Array(32);
    p[0] = outlen; p[1] = keylen; p[2] = fanout; p[3] = depth;
    store32(nodeOffset >>> 0, p, 8);
    /* xof_length@12 (u16) = 0 */
    p[14] = nodeDepth; p[15] = innerLength;
    return p;
  }

  /* ---------------- BLAKE2bp：并行度 4，块 128B，叶输出 64B ---------------- */
  function blake2bp(msg, outlen, key) {
    var P = 4, BB = 128, OB = 64, i;
    var kl = key ? key.length : 0;
    var leaves = [];
    for (i = 0; i < P; i++) {
      var S = b2bInitParam(paramB(outlen, kl, P, 2, i, 0, OB));
      S.outlen = OB;               /* 叶子的 outlen 被强制改为 inner_length */
      leaves.push(S);
    }
    leaves[P - 1].last_node = 1;   /* 仅最后一个叶子置 last_node */

    if (kl > 0) {
      var blk = new Uint8Array(BB);
      blk.set(key.subarray(0, Math.min(kl, BB)));
      for (i = 0; i < P; i++) b2bUpdate(leaves[i], blk);
    }
    for (i = 0; i < P; i++) {
      var rem = msg.length, off = i * BB;
      while (rem >= P * BB) {
        b2bUpdate(leaves[i], msg.subarray(off, off + BB));
        off += P * BB; rem -= P * BB;
      }
      if (rem > i * BB) {
        var left = rem - i * BB, len = left <= BB ? left : BB;
        b2bUpdate(leaves[i], msg.subarray(off, off + len));
      }
    }
    var R = b2bInitParam(paramB(outlen, kl, P, 2, 0, 1, OB));
    R.last_node = 1;
    for (i = 0; i < P; i++) b2bUpdate(R, b2bFinal(leaves[i]));
    return b2bFinal(R).subarray(0, outlen);
  }

  /* ---------------- BLAKE2sp：并行度 8，块 64B，叶输出 32B ---------------- */
  function blake2sp(msg, outlen, key) {
    var P = 8, BB = 64, OB = 32, i;
    var kl = key ? key.length : 0;
    var leaves = [];
    for (i = 0; i < P; i++) {
      var S = b2sInitParam(paramS(outlen, kl, P, 2, i, 0, OB));
      S.outlen = OB;
      leaves.push(S);
    }
    leaves[P - 1].last_node = 1;
    if (kl > 0) {
      var blk = new Uint8Array(BB);
      blk.set(key.subarray(0, Math.min(kl, BB)));
      for (i = 0; i < P; i++) b2sUpdate(leaves[i], blk);
    }
    for (i = 0; i < P; i++) {
      var rem = msg.length, off = i * BB;
      while (rem >= P * BB) {
        b2sUpdate(leaves[i], msg.subarray(off, off + BB));
        off += P * BB; rem -= P * BB;
      }
      if (rem > i * BB) {
        var left = rem - i * BB, len = left <= BB ? left : BB;
        b2sUpdate(leaves[i], msg.subarray(off, off + len));
      }
    }
    var R = b2sInitParam(paramS(outlen, kl, P, 2, 0, 1, OB));
    R.last_node = 1;
    for (i = 0; i < P; i++) b2sUpdate(R, b2sFinal(leaves[i]));
    return b2sFinal(R).subarray(0, outlen);
  }

  /* 供 node 端测试对照（浏览器里无 module） */
  if (typeof globalThis !== 'undefined') {
    globalThis.bpHashRef = blake2bp;
    globalThis.spHashRef = blake2sp;
  }

  function parseKeyHex(str) {
    if (!str) return new Uint8Array(0);
    var s = String(str).trim().replace(/^0x/i, '').replace(/\s+/g, '');
    if (!s) return new Uint8Array(0);
    if (!/^[0-9a-fA-F]*$/.test(s)) throw new Error('密钥需为十六进制（留空表示无密钥模式）');
    if (s.length % 2) s = '0' + s;
    var out = new Uint8Array(s.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }

  function regBlake2bp() {
    oneway({
      id: 'blake2bp',
      name: 'BLAKE2bp-512（并行）',
      group: '单向哈希',
      key: false,
      param: true,
      paramLabel: '密钥（Hex，可选；留空为无密钥模式）',
      info: 'BLAKE2 的 4 路并行变体，512 位摘要。消息按 128 字节块轮转分给 4 个叶子，各出 64 字节后由根节点汇总。官方 KAT 256 组（密钥 00..3f）全部通过。',
      enc: function (b, k, p, fmt) {
        return bytesOut(blake2bp(b, 64, parseKeyHex(p)), fmt);
      }
    });
  }

  function regBlake2sp() {
    oneway({
      id: 'blake2sp',
      name: 'BLAKE2sp-256（并行）',
      group: '单向哈希',
      key: false,
      param: true,
      paramLabel: '密钥（Hex，可选；留空为无密钥模式）',
      info: 'BLAKE2 的 8 路并行变体，256 位摘要。消息按 64 字节块轮转分给 8 个叶子，各出 32 字节后由根节点汇总。官方 KAT 256 组全部通过。',
      enc: function (b, k, p, fmt) {
        return bytesOut(blake2sp(b, 32, parseKeyHex(p)), fmt);
      }
    });
  }

  try {
    regBlake2bp();
    regBlake2sp();
    if (typeof window !== 'undefined' && typeof window.rebuildAlgoList === 'function') {
      window.rebuildAlgoList();
    }
  } catch (e) {
    console.error('crypto_blake2p.js 注册失败:', e);
  }

})();
