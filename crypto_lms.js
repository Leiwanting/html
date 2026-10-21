/* LMS / HSS —— RFC 8554（Leighton-Micali Hash-Based Signatures），NIST SP 800-208 批准
 *
 * 官方向量：RFC 8554 Appendix F Test Case 2 顶层密钥
 *   I    = d08fabd4a2091ff0a8cb4ed834e74534
 *   SEED = 558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439
 *   参数 = LMS_SHA256_M32_H10 (0x00000006) / LMOTS_SHA256_N32_W4 (0x00000003)
 *   官方公钥 K = 32a58885cd9ba0431235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e
 *   本实现由 SEED 生成整棵树得到的根与之【逐字节一致】。
 *
 * ⚠ 四个必须照官方、凭直觉会写错的点（本项目逐一核对过）：
 *   1. 域分离常量不是 0x0000/0xffff，而是
 *      D_PBLC=0x8080、D_MESG=0x8181、D_LEAF=0x8282、D_INTR=0x8383；
 *   2. LM-OTS 私钥 x_q[i] = H(I‖u32str(q)‖u16str(i)‖u8str(0xff)‖SEED)，
 *      SEED 在【最后】，与 XMSS 的 PRF(sk_seed,…) 结构完全不同；
 *   3. 校验和 Cksm 要【左移 ls 位】再拼进 S（w=4 时 ls=4，w=8 时 ls=0）；
 *   4. 叶子编号 r = i + 2^h（不是 i），内部节点编号从 2^(h-1) 起递增。
 */
(function () {
  var D_PBLC = 0x8080, D_MESG = 0x8181, D_LEAF = 0x8282, D_INTR = 0x8383;

  /* ---------- 参数表（RFC 8554 §8） ---------- */
  var OTS = {
    1: { n: 32, w: 1 }, 2: { n: 32, w: 2 }, 3: { n: 32, w: 4 }, 4: { n: 32, w: 8 },
    5: { n: 24, w: 1 }, 6: { n: 24, w: 2 }, 7: { n: 24, w: 4 }, 8: { n: 24, w: 8 }
  };
  var LMS = {
    5: { n: 32, h: 5 }, 6: { n: 32, h: 10 }, 7: { n: 32, h: 15 }, 8: { n: 32, h: 20 },
    9: { n: 24, h: 5 }, 10: { n: 24, h: 10 }, 11: { n: 24, h: 15 }, 12: { n: 24, h: 20 }
  };
  var OTS_NAME = {
    1: 'LMOTS_SHA256_N32_W1', 2: 'LMOTS_SHA256_N32_W2', 3: 'LMOTS_SHA256_N32_W4', 4: 'LMOTS_SHA256_N32_W8',
    5: 'LMOTS_SHA256_N24_W1', 6: 'LMOTS_SHA256_N24_W2', 7: 'LMOTS_SHA256_N24_W4', 8: 'LMOTS_SHA256_N24_W8'
  };
  var LMS_NAME = {
    5: 'LMS_SHA256_M32_H5', 6: 'LMS_SHA256_M32_H10', 7: 'LMS_SHA256_M32_H15', 8: 'LMS_SHA256_M32_H20',
    9: 'LMS_SHA256_M24_H5', 10: 'LMS_SHA256_M24_H10', 11: 'LMS_SHA256_M24_H15', 12: 'LMS_SHA256_M24_H20'
  };

  /* ---------- 基础工具 ---------- */
  function u8(x) { var b = new Uint8Array(1); b[0] = x & 0xff; return b; }
  function u16(x) { var b = new Uint8Array(2); b[0] = (x >> 8) & 0xff; b[1] = x & 0xff; return b; }
  function u32(x) { var b = new Uint8Array(4); b[0] = (x >>> 24) & 0xff; b[1] = (x >>> 16) & 0xff; b[2] = (x >>> 8) & 0xff; b[3] = x & 0xff; return b; }
  function cat() {
    var n = 0, i;
    for (i = 0; i < arguments.length; i++) n += arguments[i].length;
    var o = new Uint8Array(n), p = 0;
    for (i = 0; i < arguments.length; i++) { o.set(arguments[i], p); p += arguments[i].length; }
    return o;
  }
  function sha256(b) { return sha256Core(b, SHA256_IV, 8); }
  function hexToBytes(s) {
    s = String(s || '').replace(/[\s:,_]/g, '');
    if (s.length % 2) throw new Error('Hex 长度必须为偶数');
    var o = new Uint8Array(s.length / 2), i;
    for (i = 0; i < o.length; i++) {
      var v = parseInt(s.substr(i * 2, 2), 16);
      if (isNaN(v)) throw new Error('Hex 含非法字符：' + s.substr(i * 2, 2));
      o[i] = v;
    }
    return o;
  }
  function toHex(b) {
    var s = '', i;
    for (i = 0; i < b.length; i++) { var h = b[i].toString(16); s += (h.length < 2 ? '0' : '') + h; }
    return s;
  }

  /* ---------- Winternitz 参数 ---------- */
  function params(n, w) {
    var u = Math.ceil(8 * n / w), v, p, ls, lg = 0, t = (1 << w) - 1;
    /* floor(lg(t*u)) —— 不用浮点，避免边界取整误差 */
    var m = t * u; while (m > 1) { m = m >> 1; lg++; }
    if (t * u !== (1 << lg)) lg = lg - 0; /* floor 已由循环保证 */
    v = Math.ceil((lg + 1) / w);
    ls = 16 - v * w; if (ls < 0) ls = 0;
    p = u + v;
    return { n: n, w: w, u: u, v: v, ls: ls, p: p };
  }
  /* coef(S,i,w)：RFC 8554 §3.1.3 —— 索引是 floor(i*w/8)，不是 i */
  function coef(S, i, w) {
    var idx = Math.floor(i * w / 8);
    var sh = 8 - (w * (i % Math.floor(8 / w)) + w);
    return (S[idx] >> sh) & ((1 << w) - 1);
  }

  /* ---------- LM-OTS ---------- */
  function lmotsPriv(I, q, i, SEED) {
    return sha256(cat(I, u32(q), u16(i), u8(0xff), SEED)).subarray(0, I.length === 16 ? 32 : 24);
  }
  function chainStep(I, q, i, j, t) { return sha256(cat(I, u32(q), u16(i), u8(j), t)); }
  function lmotsPub(I, q, SEED, ots) {
    var P = params(ots.n, ots.w), i, j, t, zs = [], z = new Uint8Array(P.p * ots.n);
    for (i = 0; i < P.p; i++) {
      t = lmotsPriv(I, q, i, SEED);
      for (j = 0; j < (1 << ots.w) - 1; j++) t = chainStep(I, q, i, j, t);
      z.set(t.subarray(0, ots.n), i * ots.n);
    }
    return sha256(cat(I, u32(q), u16(D_PBLC), z)).subarray(0, ots.n);
  }
  /* 签名：返回 {C, y} */
  function lmotsSign(I, q, SEED, C, msg, ots) {
    var P = params(ots.n, ots.w), n = ots.n, i, j, a, t;
    var Q = sha256(cat(I, u32(q), u16(D_MESG), C, msg)).subarray(0, n);
    var sum = 0;
    for (i = 0; i < P.u; i++) sum += ((1 << ots.w) - 1) - coef(Q, i, ots.w);
    var S = cat(Q, u16((sum << P.ls) & 0xffff));
    var y = new Uint8Array(P.p * n);
    for (i = 0; i < P.p; i++) {
      a = coef(S, i, ots.w);
      t = lmotsPriv(I, q, i, SEED);
      for (j = 0; j < a; j++) t = chainStep(I, q, i, j, t);
      y.set(t.subarray(0, n), i * n);
    }
    return { C: C, y: y, S: S };
  }
  /* 验签：从 y 继续走完链，返回 K_ots */
  function lmotsPubFromSig(I, q, C, msg, y, ots) {
    var P = params(ots.n, ots.w), n = ots.n, i, j, a, t;
    var Q = sha256(cat(I, u32(q), u16(D_MESG), C, msg)).subarray(0, n);
    var sum = 0;
    for (i = 0; i < P.u; i++) sum += ((1 << ots.w) - 1) - coef(Q, i, ots.w);
    var S = cat(Q, u16((sum << P.ls) & 0xffff));
    var z = new Uint8Array(P.p * n);
    for (i = 0; i < P.p; i++) {
      a = coef(S, i, ots.w);
      t = y.subarray(i * n, i * n + n);
      for (j = a; j < (1 << ots.w) - 1; j++) t = chainStep(I, q, i, j, t);
      z.set(t.subarray(0, n), i * n);
    }
    return sha256(cat(I, u32(q), u16(D_PBLC), z)).subarray(0, n);
  }

  /* ---------- LMS 树 ---------- */
  function buildTree(I, SEED, lms, ots) {
    var h = lms.h, N = 1 << h, n = ots.n, i;
    var level = new Array(N);
    for (i = 0; i < N; i++) {
      level[i] = sha256(cat(I, u32(i + N), u16(D_LEAF), lmotsPub(I, i, SEED, ots))).subarray(0, n);
    }
    var size = N, start = N;
    while (size > 1) {
      var nxt = new Array(size >> 1);
      for (i = 0; i < nxt.length; i++) {
        nxt[i] = sha256(cat(I, u32((start >> 1) + i), u16(D_INTR), level[2 * i], level[2 * i + 1])).subarray(0, n);
      }
      level = nxt; start >>= 1; size >>= 1;
    }
    return { root: level[0], levels: h };
  }
  /* 取认证路径 */
  function authPath(I, SEED, lms, ots, q) {
    var h = lms.h, N = 1 << h, n = ots.n, i, j;
    var level = new Array(N);
    for (i = 0; i < N; i++) {
      level[i] = sha256(cat(I, u32(i + N), u16(D_LEAF), lmotsPub(I, i, SEED, ots))).subarray(0, n);
    }
    var path = [], size = N, start = N, idx = q;
    for (j = 0; j < h; j++) {
      path.push(level[(idx ^ 1)]);
      var nxt = new Array(size >> 1);
      for (i = 0; i < nxt.length; i++) {
        nxt[i] = sha256(cat(I, u32((start >> 1) + i), u16(D_INTR), level[2 * i], level[2 * i + 1])).subarray(0, n);
      }
      level = nxt; start >>= 1; size >>= 1; idx >>= 1;
    }
    return path;
  }
  /* 验签：由 K_ots + path 上溯到根 */
  function computeRoot(I, q, Kots, path, h, n) {
    /* 起点是【叶子哈希】H(I‖u32str(q+2^h)‖D_LEAF‖K_ots)，不能直接用 K_ots */
    var r = q + (1 << h), t = sha256(cat(I, u32(r), u16(D_LEAF), Kots)).subarray(0, n), i;
    for (i = 0; i < h; i++) {
      t = sha256(cat(I, u32(r >> 1), u16(D_INTR), (r & 1) ? path[i] : t, (r & 1) ? t : path[i])).subarray(0, n);
      r >>= 1;
    }
    return t;
  }

  /* ---------- 序列化 ---------- */
  function pubBytes(lmsT, otsT, I, K) { return cat(u32(lmsT), u32(otsT), I, K); }
  function sigBytes(otsT, q, C, y, lmsT, path) {
    var parts = [u32(q), u32(otsT), C];
    parts.push(y); parts.push(u32(lmsT));
    for (var i = 0; i < path.length; i++) parts.push(path[i]);
    return cat.apply(null, parts);
  }
  function parsePub(b) {
    if (b.length < 8 + 16 + 8) throw new Error('LMS 公钥长度不足');
    var lmsT = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    var otsT = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7];
    var lms = LMS[lmsT], ots = OTS[otsT];
    if (!lms || !ots) throw new Error('未知 LMS/LMOTS 类型：' + lmsT + '/' + otsT);
    if (lms.n !== ots.n) throw new Error('LMS 与 LMOTS 的哈希长度不一致');
    var I = b.subarray(8, 8 + 16), K = b.subarray(24);
    if (K.length !== lms.n) throw new Error('公钥 K 长度应为 ' + lms.n + ' 字节，实为 ' + K.length);
    return { lmsT: lmsT, otsT: otsT, lms: lms, ots: ots, I: I, K: K };
  }
  function parseSig(b) {
    var q = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    var otsT = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7];
    var ots = OTS[otsT];
    if (!ots) throw new Error('未知 LMOTS 类型：' + otsT);
    var n = ots.n, o = 8;
    var C = b.subarray(o, o + n); o += n;
    var P = params(n, ots.w);
    var y = b.subarray(o, o + P.p * n); o += P.p * n;
    var lmsT = (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]; o += 4;
    var lms = LMS[lmsT];
    if (!lms) throw new Error('未知 LMS 类型：' + lmsT);
    var path = [], i;
    for (i = 0; i < lms.h; i++) { path.push(b.subarray(o, o + n)); o += n; }
    return { q: q, otsT: otsT, ots: ots, C: C, y: y, lmsT: lmsT, lms: lms, path: path };
  }

  var LMSAPI = {
    params: params, coef: coef,
    keygen: function (I, SEED, lmsT, otsT) {
      var lms = LMS[lmsT], ots = OTS[otsT];
      if (!lms || !ots) throw new Error('未知参数集');
      if (lms.n !== ots.n) throw new Error('LMS 与 LMOTS 的 n 必须一致');
      var t = buildTree(I, SEED, lms, ots);
      return { pk: pubBytes(lmsT, otsT, I, t.root), K: t.root };
    },
    sign: function (I, SEED, q, C, msg, lmsT, otsT) {
      var lms = LMS[lmsT], ots = OTS[otsT];
      if (!lms || !ots) throw new Error('未知参数集');
      if (q >= (1 << lms.h)) throw new Error('叶子索引 q 必须 < 2^' + lms.h);
      if (!C || C.length !== ots.n) C = new Uint8Array(ots.n);
      var s = lmotsSign(I, q, SEED, C, msg, ots);
      var path = authPath(I, SEED, lms, ots, q);
      return { sig: sigBytes(otsT, q, s.C, s.y, lmsT, path), q: q };
    },
    verify: function (pk, msg, sig) {
      var P = parsePub(pk), S = parseSig(sig);
      if (S.lmsT !== P.lmsT || S.otsT !== P.otsT) throw new Error('签名与公钥的参数集不一致');
      var Kots = lmotsPubFromSig(P.I, S.q, S.C, msg, S.y, S.ots);
      var root = computeRoot(P.I, S.q, Kots, S.path, S.lms.h, S.lms.n);
      var ok = true, i;
      if (root.length !== P.K.length) ok = false;
      else for (i = 0; i < root.length; i++) if (root[i] !== P.K[i]) { ok = false; break; }
      return { ok: ok, root: root, q: S.q };
    },
    _buildTree: buildTree, _authPath: authPath, _lmotsPub: lmotsPub,
    _lmotsSign: lmotsSign, _pubFromSig: lmotsPubFromSig, _computeRoot: computeRoot,
    OTS: OTS, LMS: LMS, OTS_NAME: OTS_NAME, LMS_NAME: LMS_NAME
  };
  if (typeof window !== 'undefined') window.LMS = LMSAPI;
  if (typeof module !== 'undefined' && module.exports) module.exports = LMSAPI;

  /* ---------- 界面条目 ---------- */
  if (typeof reg !== 'function') return;
  var GH = '后量子密码';

  function splitP(p, def) {
    var a = String(p == null || p === '' ? def : p).split(/[,，]/).map(function (x) { return String(x).trim(); });
    return a;
  }

  reg({
    id: 'lms-keygen',
    name: 'LMS 密钥生成（RFC 8554，公钥）',
    group: GH,
    key: true, param: true,
    keyLabel: 'SEED（Hex，32 字节）',
    paramLabel: 'I(Hex,16字节), LMS类型, LMOTS类型（默认 6,3）',
    info: '由 SEED 与 I 生成 LMS 公钥（RFC 8554 Appendix A 伪随机私钥派生）。公钥 = u32(LMS类型)‖u32(LMOTS类型)‖I‖树根。官方 TC2 顶层密钥（H10/W4）逐字节一致。⚠ 需建 2^h 叶 Merkle 树，H10 约百万次 SHA-256；H15/H20 极慢。',
    enc: async function (b, k, p) {
      var a = splitP(p, '');
      var I = hexToBytes(a[0] || 'd08fabd4a2091ff0a8cb4ed834e74534');
      if (I.length !== 16) throw new Error('I 必须为 16 字节');
      var lmsT = parseInt(a[1] || '6', 10), otsT = parseInt(a[2] || '3', 10);
      var seed = hexToBytes(k);
      var r = LMSAPI.keygen(I, seed, lmsT, otsT);
      return {
        text: '参数集 = ' + LMS_NAME[lmsT] + ' / ' + OTS_NAME[otsT] +
          '\n树根 K（' + r.K.length + ' 字节）:\n' + toHex(r.K) +
          '\n\n完整公钥（' + r.pk.length + ' 字节）:\n' + toHex(r.pk)
      };
    }
  });

  reg({
    id: 'lms-sign',
    name: 'LMS 签名（RFC 8554）',
    group: GH,
    key: true, param: true,
    keyLabel: 'SEED（Hex，32 字节）',
    paramLabel: 'I, q, C(Hex,可选), LMS类型, LMOTS类型（默认 6,3）',
    info: '用指定叶子 q 对消息签名：LM-OTS 签名 + 认证路径。⚠ 状态化签名：同一 q 复用会直接泄露私钥，签完必须把 q 前进。C 为可选随机量，留空则用全零（仅调试用，实际必须随机）。',
    enc: async function (b, k, p) {
      var a = splitP(p, '');
      var I = hexToBytes(a[0] || 'd08fabd4a2091ff0a8cb4ed834e74534');
      var q = parseInt(a[1] || '0', 10);
      var lmsT = parseInt(a[3] || '6', 10), otsT = parseInt(a[2] && a[2].length > 2 ? '3' : '3', 10);
      var otsT2 = parseInt(a[4] || '3', 10);
      var seed = hexToBytes(k);
      var C = null;
      if (a[2] && a[2].length >= 2 * OTS[otsT2].n) { try { C = hexToBytes(a[2]); } catch (e) { C = null; } }
      var r = LMSAPI.sign(I, seed, q, C, b, lmsT, otsT2);
      return {
        text: '签名（' + r.sig.length + ' 字节）:\n' + toHex(r.sig) +
          '\n\n使用叶子 q = ' + r.q + '，下次请用 q = ' + (r.q + 1)
      };
    }
  });

  reg({
    id: 'lms-verify',
    name: 'LMS 验签（RFC 8554）',
    group: GH,
    key: true,
    keyLabel: 'LMS 公钥（Hex）',
    info: '验证 LMS 签名：由 y 走完剩余 Winternitz 链得到 LM-OTS 公钥，再沿认证路径上溯到根，与公钥中的树根比对。消息或签名任一字节被改动都会判为无效。',
    enc: async function (b, k, p) {
      var pf = splitP(p, '');
      var sig = hexToBytes(pf[0] || '');
      var r = LMSAPI.verify(hexToBytes(k), b, sig);
      return {
        text: '验签结果：' + (r.ok ? '有效 ✓' : '无效 ✗') +
          '\n叶子 q = ' + r.q + '\n计算出的树根 = ' + toHex(r.root)
      };
    }
  });
})();
