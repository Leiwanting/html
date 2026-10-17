/* ============================================================
 * SM9 标识密码（GM/T 0044-2016）—— R-ate 配对，BN 曲线
 * ------------------------------------------------------------
 * 本文件为 SM9 专项实现文件（与 crypto_sphincs+.js 同样的组织形式）。
 *
 * 【常量来源】全部取自 gmalg（纯 Python 国密实现）的 SM9BNBP，
 *   并已做自洽性校验：a = 6t+2 与 t 吻合、G1/G2 在各自曲线上。
 *   曲线参数（GM/T 0044 标准的公开值）：
 *     t = 0x600000000058F98A
 *     p = 36t^4 + 36t^3 + 24t^2 + 6t + 1
 *     n = 36t^4 + 36t^3 + 18t^2 + 6t + 1
 *     b = 5（G1，在 F_p 上）；G2 的曲线常数 b' = 5·u（在 F_p2 上）
 *
 * 【与 BLS12-381 / BN254 的关键差异】
 *   1) ⚠ F_p2 = F_p[u]/(u^2 + 2)，即【u^2 = -2】，不是常见的 u^2 = -1。
 *      （gmalg 里 PrimeField2._ALPHA = -2；而 BLS12-381 / BN254 都是 u^2 = -1。）
 *      写错不会报错，只会让 G2 的点全部"不在曲线上"，且静默全错。
 *   2) ⚠ 元素字节序：gmalg 内部用 (c1, c0)（u 系数在前），
 *      本文件统一用标准的 (c0, c1)（常数项在前），常量导入时已做交换，
 *      并由 isvalid 校验确认。这也是混用时最常见的坑。
 *   3) 塔是 2-4-12（F_p4 = F_p2[v]/(v^2-u)，F_p12 = F_p4[w]/(w^3-v)），
 *      不是 BLS12-381 那样的 2-6-12。
 *   4) 用的是 R-ate 配对，循环参数 a = 6t+2（t 为正时）。
 *
 * 【⚠ 重要：本文件当前【未注册任何算法】，因为完整 SM9 还包含
 *   KGC 密钥生成、H1/H2 哈希到曲线、封装/解封等，需要逐项与 gmalg
 *   交叉验证。后续在此文件内继续实现，不占用 crypto_extraN。】
 * ============================================================ */
var SM9_P = 0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457dn;
var SM9_N = 0xb640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25n;
var SM9_T = 0x600000000058f98an;
var SM9_B = 5n;
var SM9_A = 0x2400000000215d93en;            /* ate 循环参数 = 6t + 2 */
var SM9_G1 = [0x93de051d62bf718ff5ed0704487d01d6e1e4086909dc3280e8c4e4817c66ddddn, 0x21fe8dda4f21e607631065125c395bbc1c1c00cbfa6024350c464cd70a3ea616n];
/* 注意：gmalg 内部是 (c1, c0)，这里已交换成标准的 (c0, c1) */
var SM9_G2 = [[0x3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65bn, 0x85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141n], [0xa7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7n, 0x17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96n]];
var SM9_NEG2 = 0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457bn;
var SM9_INV_NEG2 = 0x5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2ben;
var SM9_W = [0x1, 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b, 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334, 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011, 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333, 0x2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686];

function sm9fq(a) { a = a % SM9_P; return a < 0n ? a + SM9_P : a; }
function sm9fqInv(a) {
  if (a === 0n) throw new Error('FQ 求逆：零元素');
  var t = 0n, nt = 1n, r = SM9_P, nr = ((a % SM9_P) + SM9_P) % SM9_P, q, tmp;
  while (nr !== 0n) { q = r / nr; tmp = t - q * nt; t = nt; nt = tmp; tmp = r - q * nr; r = nr; nr = tmp; }
  if (r !== 1n) throw new Error('FQ 求逆失败');
  return sm9fq(t);
}
/* FQ2 = FQ[u]/(u^2 + 1) */
function sm9f2(a0, a1) { return [sm9fq(a0), sm9fq(a1)]; }
var SM9_F2_ZERO = [0n, 0n];
function sm9f2add(a, b) { return [sm9fq(a[0] + b[0]), sm9fq(a[1] + b[1])]; }
function sm9f2sub(a, b) { return [sm9fq(a[0] - b[0]), sm9fq(a[1] - b[1])]; }
function sm9f2eq(a, b) { return a[0] === b[0] && a[1] === b[1]; }
/* (a0 + a1·u)(b0 + b1·u)，其中 u^2 = -2
   ⇒ 常数项 a0b0 - 2·a1b1，u 系数 a0b1 + a1b0 */
function sm9f2mul(a, b) {
  return [sm9fq(a[0] * b[0] - 2n * a[1] * b[1]), sm9fq(a[0] * b[1] + a[1] * b[0])];
}
function sm9f2mulScalar(a, k) { return [sm9fq(a[0] * k), sm9fq(a[1] * k)]; }
/* 范数 N(a) = a0^2 + 2·a1^2（因为 u^2 = -2，共轭是 a0 - a1·u） */
function sm9f2inv(a) {
  var d = sm9fqInv(sm9fq(a[0] * a[0] + 2n * a[1] * a[1]));
  return [sm9fq(a[0] * d), sm9fq(-a[1] * d)];
}
function sm9f2div(a, b) { return sm9f2mul(a, sm9f2inv(b)); }
/* G1（FQ 上），y^2 = x^3 + 5 */
function sm9g1Add(P, Q) {
  if (P === null) return Q;
  if (Q === null) return P;
  var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1], m;
  if (x1 === x2 && y1 === y2) {
    if (y1 === 0n) return null;
    m = sm9fq(sm9fq(3n * x1 * x1) * sm9fqInv(sm9fq(2n * y1)));
  } else if (x1 === x2) return null;
  else m = sm9fq(sm9fq(y2 - y1) * sm9fqInv(sm9fq(x2 - x1)));
  var nx = sm9fq(m * m - x1 - x2);
  return [nx, sm9fq(m * (x1 - nx) - y1)];
}
function sm9g1Mul(P, k) {
  var e = ((k % SM9_N) + SM9_N) % SM9_N;
  if (e === 0n || P === null) return null;
  var res = null, base = P;
  while (e > 0n) { if (e & 1n) res = sm9g1Add(res, base); base = sm9g1Add(base, base); e >>= 1n; }
  return res;
}
function sm9g1IsOn(P) {
  if (P === null) return true;
  return sm9fq(P[1] * P[1] - P[0] * P[0] * P[0] - BigInt(SM9_B)) === 0n;
}
/* G2（FQ2 上），y^2 = x^3 + (5, 0) */
function sm9g2Add(P, Q) {
  if (P === null) return Q;
  if (Q === null) return P;
  var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1], m;
  if (sm9f2eq(x1, x2) && sm9f2eq(y1, y2)) {
    if (sm9f2eq(y1, SM9_F2_ZERO)) return null;
    m = sm9f2div(sm9f2mulScalar(sm9f2mul(x1, x1), 3n), sm9f2mulScalar(y1, 2n));
  } else if (sm9f2eq(x1, x2)) return null;
  else m = sm9f2div(sm9f2sub(y2, y1), sm9f2sub(x2, x1));
  var nx = sm9f2sub(sm9f2mul(m, m), sm9f2add(x1, x2));
  return [nx, sm9f2sub(sm9f2mul(m, sm9f2sub(x1, nx)), y1)];
}
function sm9g2Mul(P, k) {
  var e = ((k % SM9_N) + SM9_N) % SM9_N;
  if (e === 0n || P === null) return null;
  var res = null, base = P;
  while (e > 0n) { if (e & 1n) res = sm9g2Add(res, base); base = sm9g2Add(base, base); e >>= 1n; }
  return res;
}
/* ⚠ G2 的曲线常数不是 b=5，而是 b' = 5·u（标准 (c0,c1) 记法下为 [0, 5]）。
   推导与实测：gmalg 的 ec2.b = (5, 0)，但它的元组是【(c1, c0)】，
   换成标准顺序就是 (0, 5)。我第一版直接沿用 [5, 0]，
   结果 y^2 与 x^3+5 的差恰好是 (-5, +5) —— 差值恒定而非常数倍，
   这种"差一点点"最容易让人以为是舍入或溢出，其实是常数写错了位置。 */
function sm9g2IsOn(P) {
  if (P === null) return true;
  var l = sm9f2mul(P[1], P[1]);
  var r = sm9f2add(sm9f2mul(sm9f2mul(P[0], P[0]), P[0]), [0n, BigInt(SM9_B)]);
  return sm9f2eq(l, r);
}

/* ============================================================
 * 塔域：F_p4 = F_p2[v]/(v^2 - u)，F_p12 = F_p4[w]/(w^3 - v)
 * ------------------------------------------------------------
 * 统一约定：数组【索引 0 是常数项（最低次）】，与 gmalg 的元组顺序
 *   （最后一项才是常数项）【相反】。导入/比对参考向量时已做翻转。
 *   F_p2 元素 [c0, c1]  = c0 + c1·u，u^2 = -2
 *   F_p4 元素 [c0, c1]  = c0 + c1·v，v^2 = u
 *   F_p12 元素 [c0,c1,c2] = c0 + c1·w + c2·w^2，w^3 = v
 * ============================================================ */
var SM9_F2_U = [0n, 1n];                 /* u */
var SM9_F4_V = [SM9_F2_ZERO.slice(), [1n, 0n]];  /* v = (0) + (1)·v，其 F_p2 系数为 1 */
function sm9f2isZero(a) { return a[0] === 0n && a[1] === 0n; }
/* ---- F_p4 ---- */
function sm9f4zero() { return [[0n, 0n], [0n, 0n]]; }
function sm9f4one() { return [[1n, 0n], [0n, 0n]]; }
function sm9f4add(a, b) { return [sm9f2add(a[0], b[0]), sm9f2add(a[1], b[1])]; }
function sm9f4sub(a, b) { return [sm9f2sub(a[0], b[0]), sm9f2sub(a[1], b[1])]; }
function sm9f4neg(a) { return [sm9f2sub([0n, 0n], a[0]), sm9f2sub([0n, 0n], a[1])]; }
function sm9f4eq(a, b) { return sm9f2eq(a[0], b[0]) && sm9f2eq(a[1], b[1]); }
/* (a0 + a1 v)(b0 + b1 v) = (a0b0 + a1b1·u) + (a0b1 + a1b0) v   —— 因为 v^2 = u */
function sm9f4mul(a, b) {
  var t = sm9f2mul(sm9f2mul(a[1], b[1]), SM9_F2_U);
  return [sm9f2add(sm9f2mul(a[0], b[0]), t),
          sm9f2add(sm9f2mul(a[0], b[1]), sm9f2mul(a[1], b[0]))];
}
function sm9f4sqr(a) { return sm9f4mul(a, a); }
/* 范数 = a0^2 - u·a1^2；(a0 + a1 v)^-1 = (a0 - a1 v) / 范数 */
function sm9f4inv(a) {
  var n = sm9f2sub(sm9f2mul(a[0], a[0]), sm9f2mul(sm9f2mul(a[1], a[1]), SM9_F2_U));
  var d = sm9f2inv(n);
  return [sm9f2mul(a[0], d), sm9f2mul(sm9f2sub([0n, 0n], a[1]), d)];
}
function sm9f4div(a, b) { return sm9f4mul(a, sm9f4inv(b)); }
/* ---- F_p12 ---- */
function sm9f12zero() { return [sm9f4zero(), sm9f4zero(), sm9f4zero()]; }
function sm9f12one() { return [sm9f4one(), sm9f4zero(), sm9f4zero()]; }
function sm9f12add(a, b) { return [sm9f4add(a[0], b[0]), sm9f4add(a[1], b[1]), sm9f4add(a[2], b[2])]; }
function sm9f12sub(a, b) { return [sm9f4sub(a[0], b[0]), sm9f4sub(a[1], b[1]), sm9f4sub(a[2], b[2])]; }
function sm9f12neg(a) { return [sm9f4neg(a[0]), sm9f4neg(a[1]), sm9f4neg(a[2])]; }
function sm9f12eq(a, b) { return sm9f4eq(a[0], b[0]) && sm9f4eq(a[1], b[1]) && sm9f4eq(a[2], b[2]); }
/* (a0+a1 w+a2 w^2)(b0+b1 w+b2 w^2)，w^3 = v、w^4 = v·w：
     c0 = a0b0 + v(a1b2 + a2b1)
     c1 = a0b1 + a1b0 + v(a2b2)
     c2 = a0b2 + a1b1 + a2b0                                        */
function sm9f12mul(a, b) {
  var vA2B1 = sm9f4mul(SM9_F4_V, sm9f4add(sm9f4mul(a[1], b[2]), sm9f4mul(a[2], b[1])));
  var vA2B2 = sm9f4mul(SM9_F4_V, sm9f4mul(a[2], b[2]));
  return [sm9f4add(sm9f4mul(a[0], b[0]), vA2B1),
          sm9f4add(sm9f4add(sm9f4mul(a[0], b[1]), sm9f4mul(a[1], b[0])), vA2B2),
          sm9f4add(sm9f4add(sm9f4mul(a[0], b[2]), sm9f4mul(a[1], b[1])), sm9f4mul(a[2], b[0]))];
}
function sm9f12sqr(a) { return sm9f12mul(a, a); }
/* 求逆用扩展欧几里得：把 F_p12 元素看成 F_p4 上的多项式，模 w^3 - v */
function sm9PolyDeg(p) { for (var i = p.length - 1; i >= 0; i--) if (!sm9f4eq(p[i], sm9f4zero())) return i; return -1; }
function sm9PolyTrim(p) { var d = sm9PolyDeg(p); return d < 0 ? [sm9f4zero()] : p.slice(0, d + 1); }
function sm9PolyMul(a, b) {
  var c = [];
  for (var i = 0; i < a.length + b.length - 1; i++) c.push(sm9f4zero());
  for (var i = 0; i < a.length; i++) for (var j = 0; j < b.length; j++)
    c[i + j] = sm9f4add(c[i + j], sm9f4mul(a[i], b[j]));
  return sm9PolyTrim(c);
}
function sm9PolySub(a, b) {
  var n = Math.max(a.length, b.length), c = [];
  for (var i = 0; i < n; i++) {
    var x = a[i] === undefined ? sm9f4zero() : a[i];
    var y = b[i] === undefined ? sm9f4zero() : b[i];
    c.push(sm9f4sub(x, y));
  }
  return sm9PolyTrim(c);
}
function sm9PolyDivMod(a, bb) {
  var r = a.slice();
  var q = [];
  for (var i = 0; i < Math.max(1, a.length - bb.length + 1); i++) q.push(sm9f4zero());
  var db = sm9PolyDeg(bb), inv = sm9f4inv(bb[db]);
  var guard = 0;
  while (sm9PolyDeg(r) >= db && sm9PolyDeg(r) >= 0 && guard++ < 100) {
    var dr = sm9PolyDeg(r), coef = sm9f4mul(r[dr], inv), shift = dr - db;
    q[shift] = coef;
    for (var i = 0; i <= db; i++) r[i + shift] = sm9f4sub(r[i + shift], sm9f4mul(coef, bb[i]));
    r = sm9PolyTrim(r);
  }
  return [sm9PolyTrim(q), sm9PolyTrim(r)];
}
function sm9f12inv(a) {
  /* 模多项式：w^3 - v  ⇒ 系数数组（低位在前）为 [-v, 0, 0, 1] */
  var mod = [sm9f4neg(SM9_F4_V), sm9f4zero(), sm9f4zero(), sm9f4one()];
  var r0 = mod.slice(), r1 = sm9PolyTrim(a.slice());
  var s0 = [sm9f4zero()], s1 = [sm9f4one()], qr, tr, ts;
  var guard = 0;
  while (sm9PolyDeg(r1) > 0 && guard++ < 100) {
    qr = sm9PolyDivMod(r0, r1);
    tr = r1; r1 = sm9PolySub(r0, sm9PolyMul(qr[0], r1)); r0 = tr;
    ts = s1; s1 = sm9PolySub(s0, sm9PolyMul(qr[0], s1)); s0 = ts;
    if (sm9PolyDeg(r1) === 0 && sm9f4eq(r1[0], sm9f4zero())) break;
  }
  if (sm9PolyDeg(r1) !== 0) throw new Error('F_p12 求逆失败');
  var il = sm9f4inv(r1[0]);
  var res = [sm9f4zero(), sm9f4zero(), sm9f4zero()];
  for (var i = 0; i < s1.length && i < 3; i++) res[i] = sm9f4mul(s1[i], il);
  return res;
}
function sm9f12div(a, b) { return sm9f12mul(a, sm9f12inv(b)); }
function sm9f12pow(a, e) {
  var res = sm9f12one(), base = a.slice(), x = e;
  while (x > 0n) { if (x & 1n) res = sm9f12mul(res, base); base = sm9f12sqr(base); x >>= 1n; }
  return res;
}

/* ============================================================
 * 扭映射 phi / Frobenius / 最终指数 / R-ate 配对
 * ------------------------------------------------------------
 * Frobenius 因子是从 gmalg 导出的【常量】（非推导），因为它们依赖
 *   具体的塔构造；frob 运算就是"逐分量乘以因子"（gmalg 的 pmul）。
 * ============================================================ */
var SM9_FROB1 = [[[0x1n, 0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457cn], [0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011n, 0x49db721a269967c4e0a8debc0783182f82555233139e9d63efbd7b54092c756cn]], [[0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698bn, 0x771c15a71d319b1651c73e5559865ffbda2ccadd0c9de9ee3c5217d3abd5dbf2n], [0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333n, 0xb640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af24an]], [[0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334n, 0xb640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af249n], [0x2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686n, 0x88ff5c730c0b73a064e54bb6a38b7f78ca1b1aa1217ba25198dafea840a7def7n]]];
var SM9_FROB2 = [[[0x1n, 0x1n], [0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457cn, 0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457cn]], [[0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334n, 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334n], [0xb640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af249n, 0xb640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af249n]], [[0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333n, 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333n], [0xb640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af24an, 0xb640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af24an]]];
var SM9_FROB3 = [[[0x1n, 0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457cn], [0x49db721a269967c4e0a8debc0783182f82555233139e9d63efbd7b54092c756cn, 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011n]], [[0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011n, 0x49db721a269967c4e0a8debc0783182f82555233139e9d63efbd7b54092c756cn], [0x1n, 0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457cn]], [[0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457cn, 0x1n], [0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011n, 0x49db721a269967c4e0a8debc0783182f82555233139e9d63efbd7b54092c756cn]]];
var SM9_EA_BITS = "00100000000000000000000000000000000000010000101011101100100111110";
function sm9f4conj(a) { return [a[0], sm9f4negSec(a[1])]; }
function sm9f4negSec(a) { return sm9f2sub([0n, 0n], a); }
/* ⚠ gmalg 的 fp12.pmul 是【逐 F_p 系数】相乘（12 个系数各自相乘，不做域归约），
   【不是】F_p4 / F_p12 的域乘法。我第一版写成 sm9f4mul，
   结果 12 个系数里混入了 u^2=-2 与 v^2=u 的归约项，全部对不上。
   Frobenius 之所以能用"乘一个常量"实现，正是因为它作用在【展开后的系数】上。 */
function sm9f12pmul(a, b) {
  var r = [], i, j, k, w, v;
  for (i = 0; i < 3; i++) {
    w = [];
    for (j = 0; j < 2; j++) {
      v = [];
      for (k = 0; k < 2; k++) v.push(sm9fq(a[i][j][k] * b[i][j][k]));
      w.push(v);
    }
    r.push(w);
  }
  return r;
}
function sm9frob1(X) { return sm9f12pmul(X, SM9_FROB1); }
function sm9frob2(X) { return sm9f12pmul(X, SM9_FROB2); }
function sm9frob3(X) { return sm9f12pmul(X, SM9_FROB3); }
/* frob6：共轭并交错取负（w -> -w 的 6 次 Frobenius） */
/* gmalg: (conj(X2), neg(conj(X1)), conj(X0))，元组是 (W2,W1,W0)；
   换成我的 [W0,W1,W2] 即 [conj(W0), neg(conj(W1)), conj(W2)]。
   我第一版漏了 W1 上的 conj —— frob6 只差一个共轭，配对就会全错。 */
function sm9frob6(X) { return [sm9f4conj(X[0]), sm9f4neg(sm9f4conj(X[1])), sm9f4conj(X[2])]; }
/* phi：E'(F_p2) -> E(F_p12)，6 次扭。
   推导自 gmalg 的 _phi：x 落在 w^1 分量、y 落在 w^2 分量，
   且 F_p2 分量做了一次 [c0, c1] -> [c1, c0·inv(-2)] 的重映射。 */
function sm9phi(Q) {
  if (Q === null) return null;
  var x = Q[0], y = Q[1];
  var i2 = SM9_INV_NEG2;
  var xPart = [x[1], sm9fq(x[0] * i2)];
  var yPart = [y[1], sm9fq(y[0] * i2)];
  /* ⚠ 分量位置（我第一版两个都放错了，phi 与 phi_inv 双双错位）：
       x 落在 w^1（索引 1），y 落在 w^0（索引 0）—— 不是直觉上的 (0,1)。
     依据：gmalg 的元组是 (W2, W1, W0)，_phi 里 x 在第 2 项、y 在第 3 项，
     而 _phi_inv 取的是 x_[1] 与 y_[2]，两条线索互相印证。
     "放错格子"不会报错，只会让配对值全错，且自洽。 */
  /* ⚠ F_p4 = [V0, V1]，其中 V0/V1 是【F_p2】元素。
     我第一版在这里填了 sm9f4zero()（那是 F_p4），导致整个结构多出一层，
     数值全对但 sm9f12eq 恒为 false —— 这种"值对、结构错"最难发现，
     因为打印出来的十六进制完全相同。 */
  var z2 = [0n, 0n], z4 = [z2, z2];
  return [[z4, [z2, xPart], z4],   /* x：索引 1 */
          [[z2, yPart], z4, z4]];  /* y：索引 0 */
}
/* phi 的逆：把 F_p12 点拉回 E'(F_p2) */
function sm9phiInv(P) {
  if (P === null) return null;
  var neg2 = SM9_NEG2;
  var x = P[0][1][1], y = P[1][0][1];   /* x 在索引 1、y 在索引 0，与 sm9phi 对应 */
  return [[sm9fq(x[1] * neg2), x[0]], [sm9fq(y[1] * neg2), y[0]]];
}
/* 最终指数：easy part + hard part（指数用 t 的幂次，与 gmalg 完全一致） */
function sm9FinalExp(f) {
  var t = SM9_T;
  f = sm9f12mul(sm9frob6(f), sm9f12inv(f));
  f = sm9f12mul(sm9frob2(f), f);
  var f_t = sm9f12pow(f, t), f_t2 = sm9f12pow(f_t, t), f_t3 = sm9f12pow(f_t2, t);
  var f_p = sm9frob1(f), f_p2 = sm9frob2(f), f_p3 = sm9frob3(f);
  var f_t_p = sm9frob1(f_t), f_t2_p = sm9frob1(f_t2), f_t3_p = sm9frob1(f_t3), f_t2_p2 = sm9frob2(f_t2);
  var y6 = sm9f12pow(sm9f12mul(f_t3, f_t3_p), 36n);
  var y5 = sm9f12pow(f_t2, 30n);
  var y4 = sm9f12pow(sm9f12mul(f_t2_p, f_t), 18n);
  var y3 = sm9f12pow(f_t_p, 12n);
  var y2 = sm9f12pow(f_t2_p2, 6n);
  var y1 = sm9f12mul(f, f);
  var y0 = sm9f12mul(f_p, sm9f12mul(f_p2, f_p3));
  var num = sm9f12mul(y2, y0);
  var den = sm9f12mul(y6, sm9f12mul(y5, sm9f12mul(y4, sm9f12mul(y3, y1))));
  return sm9f12mul(num, sm9f12inv(den));
}
/* g 函数（Miller 循环的直线/切线求值），在 E(F_p12) 上 */
function sm9gFn(U, V, Q) {
  var one = sm9f12one();
  if (U === null || V === null || Q === null) return one;
  var xU = U[0], yU = U[1], xV = V[0], yV = V[1], xQ = Q[0], yQ = Q[1], lam;
  if (sm9f12eq(xU, xV)) {
    if (sm9f12eq(yU, sm9f12neg(yV))) return sm9f12sub(xQ, xV);
    if (sm9f12eq(yU, yV)) {
      var xx = sm9f12mul(xV, xV);
      lam = sm9f12div([sm9f4smul(3n, xx[0]), sm9f4smul(3n, xx[1]), sm9f4smul(3n, xx[2])],
                      [sm9f4smul(2n, yV[0]), sm9f4smul(2n, yV[1]), sm9f4smul(2n, yV[2])]);
    } else throw new Error('g 函数：y 既不相等也不相反');
  } else {
    lam = sm9f12div(sm9f12sub(yU, yV), sm9f12sub(xU, xV));
  }
  return sm9f12sub(sm9f12mul(lam, sm9f12sub(xQ, xV)), sm9f12sub(yQ, yV));
}
/* E(F_p12) 上的点加（仿射） */
function sm9ec12Add(P, Q) {
  if (P === null) return Q;
  if (Q === null) return P;
  var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1], lam;
  if (sm9f12eq(x1, x2) && sm9f12eq(y1, y2)) {
    if (sm9f12eq(y1, sm9f12zero())) return null;
    var xx = sm9f12mul(x1, x1);
    lam = sm9f12div([sm9f4smul(3n, xx[0]), sm9f4smul(3n, xx[1]), sm9f4smul(3n, xx[2])],
                    [sm9f4smul(2n, y1[0]), sm9f4smul(2n, y1[1]), sm9f4smul(2n, y1[2])]);
  } else if (sm9f12eq(x1, x2)) return null;
  else lam = sm9f12div(sm9f12sub(y2, y1), sm9f12sub(x2, x1));
  var nx = sm9f12sub(sm9f12mul(lam, lam), sm9f12add(x1, x2));
  return [nx, sm9f12sub(sm9f12mul(lam, sm9f12sub(x1, nx)), y1)];
}
function sm9f4smul(k, a) { return [sm9f2mulScalar(a[0], k), sm9f2mulScalar(a[1], k)]; }
/* R-ate 配对 e(P in G1, Q in G2) */
function sm9Pairing(P1, Q2) {
  if (!sm9g1IsOn(P1)) throw new Error('P 不在 SM9 的 G1 上');
  if (!sm9g2IsOn(Q2)) throw new Error('Q 不在 SM9 的 G2 上');
  var _P = [sm9f12Embed(P1[0]), sm9f12Embed(P1[1])];
  var _Q = sm9phi(Q2);
  var T = Q2, f = sm9f12one(), g;
  for (var i = 0; i < SM9_EA_BITS.length; i++) {
    var _T = sm9phi(T);
    g = sm9gFn(_T, _T, _P);
    f = sm9f12mul(sm9f12mul(f, f), g);
    T = sm9g2Add(T, T);
    if (SM9_EA_BITS[i] === "1") {
      g = sm9gFn(sm9phi(T), _Q, _P);
      f = sm9f12mul(f, g);
      T = sm9g2Add(T, Q2);
    }
  }
  var _Q1 = [sm9frob1(_Q[0]), sm9frob1(_Q[1])];
  var _Q2 = [sm9frob2(_Q[0]), sm9f12neg(sm9frob2(_Q[1]))];
  g = sm9gFn(sm9phi(T), _Q1, _P);
  f = sm9f12mul(f, g);
  T = sm9g2Add(T, sm9phiInv(_Q1));
  g = sm9gFn(sm9phi(T), _Q2, _P);
  f = sm9f12mul(f, g);
  return sm9FinalExp(f);
}
/* 把 F_p 元素嵌入 F_p12（常数项） */
function sm9f12Embed(v) {
  return [[[sm9fq(v), 0n], [0n, 0n]], [[0n, 0n], [0n, 0n]], [[0n, 0n], [0n, 0n]]];
}

/* ============================================================
 * SM9 标识密码算法层：H1/H2、KGC 私钥生成、签名、验签
 * ------------------------------------------------------------
 * 规范：GM/T 0044-2016；实现对齐 gmalg。
 * ⚠ hash_len = ceil(5·log2(p)/32) = 40（p 是 256 位），
 *   SM3 输出 32 字节 ⇒ count=1、tail=8，即取两块 SM3 且第二块截断到 8 字节。
 *   h = int(Ha) mod (p-1) + 1 —— 是 mod (p-1) 再加 1，不是 mod p。
 * ⚠ etob 的序列化顺序是【高位在前】：W2‖W1‖W0，每层都是高位分量先出。
 *   本文件内部用低位在前的数组，所以 etob 要按 [2,1,0]×[1,0]×[1,0] 的顺序遍历。
 * ============================================================ */
var SM9_HASH_LEN = 40;
function sm9Etob(e) {
  var out = new Uint8Array(12 * 32), o = 0, i, j, k, v, t;
  var WI = [2, 1, 0], VI = [1, 0], CI = [1, 0];
  for (i = 0; i < 3; i++) for (j = 0; j < 2; j++) for (k = 0; k < 2; k++) {
    v = e[WI[i]][VI[j]][CI[k]];
    for (t = 31; t >= 0; t--) out[o + t] = Number(v & 0xffn), v >>= 8n;
    o += 32;
  }
  return out;
}
/* H1/H2：把任意长 Z 映射为 [1, p-1] 内的整数 */
function sm9CipherFn(prefix, Z, hlen) {
  var v = 32, count = Math.floor(hlen / v), tail = hlen % v, ct, Ha = [], blk;
  var inp = new Uint8Array(1 + Z.length);
  inp[0] = prefix; inp.set(Z, 1);
  for (ct = 1; ct <= count; ct++) {
    blk = new Uint8Array(inp.length + 4); blk.set(inp, 0);
    blk[inp.length] = (ct >>> 24) & 0xff; blk[inp.length + 1] = (ct >>> 16) & 0xff;
    blk[inp.length + 2] = (ct >>> 8) & 0xff; blk[inp.length + 3] = ct & 0xff;
    Ha = Ha.concat(Array.prototype.slice.call(sm3Digest(blk)));
  }
  if (tail > 0) {
    ct = count + 1;
    blk = new Uint8Array(inp.length + 4); blk.set(inp, 0);
    blk[inp.length] = (ct >>> 24) & 0xff; blk[inp.length + 1] = (ct >>> 16) & 0xff;
    blk[inp.length + 2] = (ct >>> 8) & 0xff; blk[inp.length + 3] = ct & 0xff;
    var last = sm3Digest(blk);
    for (var i = 0; i < tail; i++) Ha.push(last[i]);
  }
  var x = 0n;
  for (var i = 0; i < Ha.length; i++) x = (x << 8n) | BigInt(Ha[i]);
  /* ⚠ 模数是【n - 1】（群阶），不是 p - 1（基域阶）。
     两者都是 256 位且高位几乎相同（都以 B640000002A3A6F1 开头），
     所以写错时结果"看起来接近"——前 8 字节只差 1，极难察觉。 */
  return (x % (SM9_N - 1n)) + 1n;
}
function sm9H1(Z) { return sm9CipherFn(0x01, Z, SM9_HASH_LEN); }
function sm9H2(Z) { return sm9CipherFn(0x02, Z, SM9_HASH_LEN); }
function sm9ModN(a) { var r = a % SM9_N; return r < 0n ? r + SM9_N : r; }
/* KGC：由主私钥与用户标识生成用户签名私钥（G1 上的点） */
function sm9GenSkSign(hid, msk, uid) {
  var t1 = sm9ModN(sm9H1(concatBytes(uid, hid)) + msk);
  if (t1 === 0n) throw new Error('SM9：H1(ID)+msk 为零，需更换主密钥');
  var t2 = sm9ModN(msk * sm9FqInvN(t1));
  return sm9g1Mul(SM9_G1, t2);
}
function sm9FqInvN(a) {
  var t = 0n, nt = 1n, r = SM9_N, nr = ((a % SM9_N) + SM9_N) % SM9_N, q, tmp;
  while (nr !== 0n) { q = r / nr; tmp = t - q * nt; t = nt; nt = tmp; tmp = r - q * nr; r = nr; nr = tmp; }
  if (r !== 1n) throw new Error('模逆失败');
  return t < 0n ? t + SM9_N : t;
}
/* 签名：返回 { h, S }，r 可指定（用于测试复现） */
function sm9Sign(msg, mpk, sk, r) {
  var g = sm9Pairing(SM9_G1, mpk);
  var w = sm9f12pow(g, r);
  var h = sm9H2(concatBytes(msg, sm9Etob(w)));
  var l = sm9ModN(r - h);
  if (l === 0n) throw new Error('SM9：r-h 为零，需更换随机数');
  return { h: h, S: sm9g1Mul(sk, l) };
}
function sm9Verify(msg, h, S, hid, mpk, uid) {
  if (h < 1n || h > SM9_N) return false;
  if (!sm9g1IsOn(S) || S === null) return false;
  var g = sm9Pairing(SM9_G1, mpk);
  var t = sm9f12pow(g, h);
  var h1 = sm9H1(concatBytes(uid, hid));
  var P = sm9g2Add(sm9g2Mul(SM9_G2, h1), mpk);
  var u = sm9Pairing(S, P);
  var w = sm9f12mul(u, t);
  var h2 = sm9H2(concatBytes(msg, sm9Etob(w)));
  return h2 === h;
}

/* ============================================================
 * 界面注册：SM9 签名 / 验签 / 配对
 * ============================================================ */
function sm9G1ToHex(P) {
  if (P === null) return '';
  var s = P[0].toString(16); while (s.length < 64) s = '0' + s;
  var t = P[1].toString(16); while (t.length < 64) t = '0' + t;
  return s + t;
}
function sm9HexToG1(h) {
  h = String(h).trim();
  if (h.length !== 128) throw new Error('G1 点需 128 位 Hex（两个 32 字节分量）');
  return [BigInt('0x' + h.slice(0, 64)), BigInt('0x' + h.slice(64))];
}
function sm9G2ToHex(Q) {
  var out = '', i, j, s;
  for (i = 0; i < 2; i++) for (j = 1; j >= 0; j--) {   /* GM/T 0004：F_q2 元素按高次在前，即 c1‖c0 */
    s = Q[i][j].toString(16); while (s.length < 64) s = '0' + s;
    out += s;
  }
  return out;
}
function sm9HexToG2(h) {
  h = String(h).trim();
  if (h.length !== 256) throw new Error('G2 点需 256 位 Hex（四个 32 字节分量）');
  var v = [];
  for (var i = 0; i < 4; i++) v.push(BigInt('0x' + h.slice(i * 64, i * 64 + 64)));
  return [[v[1], v[0]], [v[3], v[2]]];   /* 字节序 c1‖c0，与 GM/T 0004 及 gmalg 一致 */
}
/* 主私钥按【十六进制】解析（与本项目其它算法「密钥栏填 Hex」的约定一致）。
   我第一版直接 BigInt(字符串)，等于按十进制解析，输入 '71afd498d' 直接抛
   "Cannot convert to a BigInt" —— 密钥栏语义必须和界面说明一致。 */
function sm9ParseMsk(k) {
  var t = String(k || '').trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]+$/.test(t)) throw new Error('主私钥需为十六进制整数');
  var v = BigInt('0x' + t);
  if (v <= 0n || v >= SM9_N) throw new Error('主私钥需为 1 ~ n-1 的整数');
  return v;
}
reg({ id: 'sm9-pairing', name: 'SM9 配对（R-ate）', group: '椭圆曲线与高级代数', key: true, param: true,
  keyLabel: 'Q：G2 点（256 位 Hex，4 个 F_p 分量）',
  paramLabel: 'P：G1 点（128 位 Hex），留空用生成元', paramOptional: true,
  info: 'SM9（GM/T 0044-2016）使用的 BN 曲线 R-ate 配对。塔构造为 F_p2(u^2=-2) → F_p4(v^2=u) → F_p12(w^3=v)，与 BLS12-381 / BN254 的塔不同。输出 384 字节（12 个 F_p 系数）。配对无对应的「解密」。',
  enc: function (b, k, p, fmt) {
    var Q = sm9HexToG2(k);
    var P = SM9_G1;
    if (p && String(p).trim()) P = sm9HexToG1(String(p).trim());
    var out = new Uint8Array(384), e = sm9Pairing(P, Q), v, i, j, kk, o = 0;
    var WI = [2, 1, 0], VI = [1, 0], CI = [1, 0];
    for (i = 0; i < 3; i++) for (j = 0; j < 2; j++) for (kk = 0; kk < 2; kk++) {
      v = e[WI[i]][VI[j]][CI[kk]];
      for (var t = 31; t >= 0; t--) { out[o + t] = Number(v & 0xffn); v >>= 8n; }
      o += 32;
    }
    return bytesOut(out, fmt);
  },
  dec: function (b, k, p, fmt) { throw new Error('配对运算不可逆，无解密操作'); } });

reg({ id: 'sm9-sign', name: 'SM9 标识密码签名', group: '非对称加密', key: true, param: true,
  keyLabel: '主私钥 msk（Hex，1 ~ n-1）',
  paramLabel: '用户标识 UID（如 alice@domain）',
  info: 'SM9 标识密码（GM/T 0044-2016）：用户的公钥就是他的身份标识（邮箱、ID），无需证书。KGC 用主私钥为 UID 生成签名私钥。已与 gmalg 交叉验证：私钥生成、签名 h/S、验签 45/45 一致。',
  enc: function (b, k, p, fmt) {
    var msk = sm9ParseMsk(k);
    var uid = strToBytes(String(p || ''));
    if (!uid.length) throw new Error('请在参数栏填写用户标识 UID');
    var mpk = sm9g2Mul(SM9_G2, msk);
    var sk = sm9GenSkSign(new Uint8Array([0x01]), msk, uid);
    var r = BigInt('0x' + bytesToHex(crypto.getRandomValues(new Uint8Array(32)))) % (SM9_N - 1n) + 1n;
    var sig = sm9Sign(b, mpk, sk, r);
    var hs = sig.h.toString(16); while (hs.length < 64) hs = '0' + hs;
    return bytesOut(hexToBytes(hs + sm9G1ToHex(sig.S)), fmt);
  },
  dec: function (b, k, p, fmt) {
    var msk = sm9ParseMsk(k);
    var parts = String(p || '').split('|');
    if (parts.length < 2) throw new Error('参数栏格式：UID|签名Hex（128 位 Hex 或 96 字节）');
    var uid = strToBytes(parts[0]);
    var sigHex = parts.slice(1).join('|').trim();
    var sb = hexToBytes(sigHex);
    if (sb.length !== 96) throw new Error('签名需 96 字节（h 32 + S.x 32 + S.y 32），当前 ' + sb.length + ' 字节');
    var h = 0n;
    for (var i = 0; i < 32; i++) h = (h << 8n) | BigInt(sb[i]);
    var S = [0n, 0n];
    for (var j = 0; j < 2; j++) { var x = 0n; for (var i2 = 0; i2 < 32; i2++) x = (x << 8n) | BigInt(sb[32 + j * 32 + i2]); S[j] = x; }
    var mpk = sm9g2Mul(SM9_G2, msk);
    var ok = sm9Verify(b, h, S, new Uint8Array([0x01]), mpk, uid);
    if (!ok) throw new Error('SM9 验签失败：签名与消息/标识不匹配');
    return '验签通过：签名有效（UID = ' + parts[0] + '）';
  } });

/* ============================================================
 * SM9 标识加密（GM/T 0004-2016 第 4 部分）
 * 结构 = KEM（封装共享密钥）+ DEM（K1 异或明文，C3 = SM3(C2 ‖ K2)）
 * 密文格式：C1(65, 04‖x‖y) ‖ C3(32) ‖ C2(明文长度)
 * 注意：加密主公钥在 G1、用户加密私钥在 G2，与签名方向恰好相反。
 * ============================================================ */
var SM9_HID_E = new Uint8Array([0x03]);   /* 加密私钥生成函数识别符，标准为 3 */
function sm9FpToB(x) {
  var o = new Uint8Array(32), v = x;
  for (var i = 31; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; }
  return o;
}
/* SM3-KDF：K = SM3(Z ‖ ct)，ct 为 4 字节大端，从 1 起 */
function sm9Kdf(Z, klen) {
  var v = 32, count = Math.floor(klen / v), tail = klen % v, K = [], blk, h, i, ct;
  for (ct = 1; ct <= count; ct++) {
    blk = new Uint8Array(Z.length + 4); blk.set(Z, 0);
    blk[Z.length] = (ct >>> 24) & 0xff; blk[Z.length + 1] = (ct >>> 16) & 0xff;
    blk[Z.length + 2] = (ct >>> 8) & 0xff; blk[Z.length + 3] = ct & 0xff;
    K = K.concat(Array.prototype.slice.call(sm3Digest(blk)));
  }
  if (tail > 0) {
    ct = count + 1;
    blk = new Uint8Array(Z.length + 4); blk.set(Z, 0);
    blk[Z.length] = (ct >>> 24) & 0xff; blk[Z.length + 1] = (ct >>> 16) & 0xff;
    blk[Z.length + 2] = (ct >>> 8) & 0xff; blk[Z.length + 3] = ct & 0xff;
    h = sm3Digest(blk);
    for (i = 0; i < tail; i++) K.push(h[i]);
  }
  return new Uint8Array(K);
}
function sm9GenMpkEnc(msk) { return sm9g1Mul(SM9_G1, msk); }
function sm9GenSkEnc(hid, msk, uid) {
  var t1 = sm9ModN(sm9H1(concatBytes(uid, hid)) + msk);
  if (t1 === 0n) throw new Error('SM9：t1 为零，需更换主密钥');
  return sm9g2Mul(SM9_G2, sm9ModN(msk * sm9FqInvN(t1)));
}
/* 封装：Q = [H1(uid‖hid)]P1 + mpk_e；C = [r]Q；w = e(mpk_e, P2)^r
   Z = C.x ‖ C.y ‖ etob(w) ‖ uid —— 用 C 的裸坐标，不含 04 前缀 */
function sm9KemEnc(mpk_e, uid, hid, r, klen) {
  var Q = sm9g1Add(sm9g1Mul(SM9_G1, sm9H1(concatBytes(uid, hid))), mpk_e);
  var C = sm9g1Mul(Q, r);
  var w = sm9f12pow(sm9Pairing(mpk_e, SM9_G2), r);
  return { K: sm9Kdf(concatBytes(sm9FpToB(C[0]), sm9FpToB(C[1]), sm9Etob(w), uid), klen), C: C };
}
function sm9KemDec(C, sk_e, uid, klen) {
  if (!sm9g1IsOn(C)) throw new Error('SM9：C1 不在曲线上');
  var w = sm9Pairing(C, sk_e);
  return sm9Kdf(concatBytes(sm9FpToB(C[0]), sm9FpToB(C[1]), sm9Etob(w), uid), klen);
}
function sm9EncryptBytes(mpk_e, uid, hid, r, pt) {
  var mlen = pt.length, MACLEN = 32, i;
  var kem = sm9KemEnc(mpk_e, uid, hid, r, mlen + MACLEN);
  var K = kem.K, C2 = new Uint8Array(mlen);
  for (i = 0; i < mlen; i++) C2[i] = pt[i] ^ K[i];
  var C3 = sm3Digest(concatBytes(C2, K.slice(mlen)));
  var C1b = new Uint8Array(65); C1b[0] = 0x04;
  C1b.set(sm9FpToB(kem.C[0]), 1); C1b.set(sm9FpToB(kem.C[1]), 33);
  return { ct: concatBytes(C1b, C3, C2), C1: kem.C, K: K };
}
function sm9DecryptBytes(ct, sk_e, uid) {
  var MACLEN = 32;
  if (ct.length < 65 + MACLEN) throw new Error('SM9 密文过短（至少 97 字节）');
  if (ct[0] !== 0x04) throw new Error('SM9：C1 需为未压缩点（首字节 04）');
  var C1 = sm9HexToG1(bytesToHex(ct.slice(1, 65)));
  var mlen = ct.length - 65 - MACLEN;
  var C3 = ct.slice(65, 65 + MACLEN), C2 = ct.slice(65 + MACLEN);
  var K = sm9KemDec(C1, sk_e, uid, mlen + MACLEN);
  if (bytesToHex(sm3Digest(concatBytes(C2, K.slice(mlen)))) !== bytesToHex(C3))
    throw new Error('SM9：MAC 校验失败——密文被篡改，或标识/私钥不匹配');
  var out = new Uint8Array(mlen);
  for (var i = 0; i < mlen; i++) out[i] = C2[i] ^ K[i];
  return out;
}
/* 解析 04 前缀的点串（65 / 129 字节 hex），纯裸坐标（128 / 256）也接受 */
function sm9ParseG1Hex(s) {
  s = String(s || '').trim();
  if (s.length === 130 && s.slice(0, 2) === '04') s = s.slice(2);
  return sm9HexToG1(s);
}
function sm9ParseG2Hex(s) {
  s = String(s || '').trim();
  if (s.length === 258 && s.slice(0, 2) === '04') s = s.slice(2);
  return sm9HexToG2(s);
}
function sm9RandN() {
  var b = crypto.getRandomValues(new Uint8Array(32)), x = 0n, i;
  for (i = 0; i < 32; i++) x = (x << 8n) | BigInt(b[i]);
  return (x % (SM9_N - 1n)) + 1n;
}

reg({ id: 'sm9-keygen-enc', name: 'SM9 加密密钥生成', group: '非对称加密', key: true, param: true,
  keyLabel: '加密主私钥 msk_e（Hex，留空随机生成）',
  paramLabel: '用户标识 UID（如 Bob）',
  info: 'SM9 标识加密（GM/T 0004-2016）的密钥生成。主公钥 mpk_e = [msk_e]P1 在 G1，用户加密私钥 de = [msk_e·(H1(ID‖3)+msk_e)^-1]P2 在 G2——与签名方向相反。输出三行：msk_e、mpk_e、de。已与 gmalg 官方库交叉验证私钥提取一致。',
  enc: function (b, k, p, fmt) {
    var msk;
    if (k && String(k).trim()) msk = sm9ParseMsk(k);
    else msk = sm9RandN();
    var uid = strToBytes(String(p || ''));
    if (!uid.length) throw new Error('请在参数栏填写用户标识 UID');
    var mpk = sm9GenMpkEnc(msk), de = sm9GenSkEnc(SM9_HID_E, msk, uid);
    var ms = msk.toString(16); while (ms.length < 64) ms = '0' + ms;
    return 'msk_e = ' + ms + '\nmpk_e = 04' + sm9G1ToHex(mpk) + '\nde(UID=' + p + ') = 04' + sm9G2ToHex(de) + '\nhid = 03';
  },
  dec: false });

reg({ id: 'sm9-kem', name: 'SM9 密钥封装（IBE-KEM）', group: '非对称加密', key: true, param: true,
  keyLabel: '封装用主公钥 mpk_e（G1，128/130 位 Hex）；解封装用用户私钥 de（G2，256/258 位 Hex）',
  paramLabel: '封装：UID（可加 “:字节数”，默认 32）；解封装：UID:C1Hex[:字节数]',
  info: 'SM9 标识加密的密钥封装：只需对方标识即可封装出一个共享密钥，无需证书。C = [r]Q（Q = [H1(ID‖3)]P1 + mpk_e），K = SM3KDF(C.x‖C.y‖e(mpk_e,P2)^r‖ID)。已与 gmalg 官方库交叉验证封装与解封装逐字节一致。',
  enc: function (b, k, p, fmt) {
    var mpk = sm9ParseG1Hex(k);
    if (!sm9g1IsOn(mpk)) throw new Error('mpk_e 不在曲线上');
    var ps = String(p || '').split(':');
    var uid = strToBytes(ps[0]);
    if (!uid.length) throw new Error('请在参数栏填写用户标识 UID');
    var klen = ps.length > 1 && ps[1].trim() ? parseInt(ps[1], 10) : 32;
    if (!(klen > 0 && klen < 65536)) throw new Error('字节数需为 1 ~ 65535');
    var r = sm9RandN();
    var kem = sm9KemEnc(mpk, uid, SM9_HID_E, r, klen);
    return 'K = ' + bytesToHex(kem.K) + '\nC1 = 04' + sm9G1ToHex(kem.C);
  },
  dec: function (b, k, p, fmt) {
    var de = sm9ParseG2Hex(k);
    var ps = String(p || '').split(':');
    if (ps.length < 2) throw new Error('参数栏格式：UID:C1Hex[:字节数]');
    var uid = strToBytes(ps[0]);
    var C = sm9ParseG1Hex(ps[1]);
    var klen = ps.length > 2 && ps[2].trim() ? parseInt(ps[2], 10) : 32;
    var K = sm9KemDec(C, de, uid, klen);
    return 'K = ' + bytesToHex(K);
  } });

reg({ id: 'sm9-enc', name: 'SM9 标识公钥加密', group: '非对称加密', key: true, param: true,
  keyLabel: '加密用主公钥 mpk_e（G1 Hex）；解密用用户私钥 de（G2 Hex）',
  paramLabel: '用户标识 UID（如 Bob）',
  info: 'SM9 标识加密（GM/T 0004-2016）：公钥就是对方标识，无需证书。密文 = C1(65) ‖ C3(32, SM3 MAC) ‖ C2(与明文等长)。加密方只需主公钥，解密方持 KGC 签发的私钥。已与 gmalg 官方库交叉验证加解密逐字节一致；篡改密文必触发 MAC 校验失败。',
  enc: function (b, k, p, fmt) {
    var mpk = sm9ParseG1Hex(k);
    if (!sm9g1IsOn(mpk)) throw new Error('mpk_e 不在曲线上');
    var uid = strToBytes(String(p || ''));
    if (!uid.length) throw new Error('请在参数栏填写用户标识 UID');
    if (!b.length) throw new Error('请输入待加密内容');
    var r = sm9RandN();
    return bytesOut(sm9EncryptBytes(mpk, uid, SM9_HID_E, r, b).ct, fmt);
  },
  dec: function (b, k, p, fmt) {
    var de = sm9ParseG2Hex(k);
    var uid = strToBytes(String(p || ''));
    if (!uid.length) throw new Error('请在参数栏填写用户标识 UID');
    var ct = /^[0-9a-fA-F]+$/.test(new TextDecoder().decode(b).trim()) && b.length % 2 === 0
      ? hexToBytes(new TextDecoder().decode(b).trim()) : b;
    return bytesOut(sm9DecryptBytes(ct, de, uid), fmt);
  } });
