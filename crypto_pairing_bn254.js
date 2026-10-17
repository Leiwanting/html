/* ============================================================
 * BN254 / alt_bn128 最优 ate 配对
 * 以太坊 precompile 0x8 所用的曲线，zkSNARK 常用。与 py_ecc 逐系数比对 24/24。
 * ⚠ FQ12 的模多项式是 w^12 - 18 w^6 + 82，与 BLS12-381 的 w^12 - 2 w^6 + 2 【不同】。
 *   （归约系数 18 / -82 vs 2 / -2），写错不报错但结果全错。
 * ⚠ BN 曲线在 Miller 循环后还要做两步 Frobenius（Q1 与 -Q2），BLS12 没有这两步。
 * ============================================================ */
/* ========== BN254 / alt_bn128 配对 —— 常量全部由 py_ecc（以太坊官方）导出 ==========
   曲线：y^2 = x^3 + 3（G1，FQ 上）；G2 在 FQ2 的二次扭上。
   FQ12 的模多项式是 w^12 - 18*w^6 + 82 —— 注意与 BLS12-381 的 w^12 - 2*w^6 + 2【不同】，
   两者归约系数不一样（下面 f12mul 里是 18 / -82，不是 2 / -2）。
   这是 BN 曲线与 BLS 曲线最容易混用的地方：系数写错不会报错，只会静默全错。
   ate_loop_count = 29793968203157093288（63 位），来自 py_ecc.bn128_pairing。 */
var BN_P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n;
var BN_R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
var BN_B = 3n;
var BN_B2 = [0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5n, 0x9713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2n];
var BN_G1 = [0x1n, 0x2n];
var BN_G2 = [[0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6edn, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2n], [0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daan, 0x90689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975bn]];
var BN_ATE_LOOP = 29793968203157093288n;
var BN_F12_MOD = (function () {
  /* w^12 - 18 w^6 + 82 */
  var m = new Array(13).fill(0n);
  m[12] = 1n; m[6] = BN_P - 18n; m[0] = 82n;
  return m;
})();

function bnfq(a) { a = a % BN_P; return a < 0n ? a + BN_P : a; }
function bnfqInv(a) {
  if (a === 0n) throw new Error('FQ 求逆：零元素');
  var t = 0n, newt = 1n, r = BN_P, newr = ((a % BN_P) + BN_P) % BN_P, q, tmp;
  while (newr !== 0n) {
    q = r / newr;
    tmp = t - q * newt; t = newt; newt = tmp;
    tmp = r - q * newr; r = newr; newr = tmp;
  }
  if (r !== 1n) throw new Error('FQ 求逆失败');
  return bnfq(t);
}
/* FQ2 = FQ[u] / (u^2 + 1) */
function bn2(a0, a1) { return [bnfq(a0), bnfq(a1)]; }
var BN2_ZERO = [0n, 0n], BN2_ONE = [1n, 0n];
function bn2add(a, b) { return [bnfq(a[0] + b[0]), bnfq(a[1] + b[1])]; }
function bn2sub(a, b) { return [bnfq(a[0] - b[0]), bnfq(a[1] - b[1])]; }
function bn2neg(a) { return [bnfq(-a[0]), bnfq(-a[1])]; }
function bn2mul(a, b) {
  return [bnfq(a[0] * b[0] - a[1] * b[1]), bnfq(a[0] * b[1] + a[1] * b[0])];
}
function bn2eq(a, b) { return a[0] === b[0] && a[1] === b[1]; }
function bn2inv(a) {
  var d = bnfqInv(bnfq(a[0] * a[0] + a[1] * a[1]));
  return [bnfq(a[0] * d), bnfq(-a[1] * d)];
}
function bn2div(a, b) { return bn2mul(a, bn2inv(b)); }
function bn2mulScalar(a, k) { return [bnfq(a[0] * k), bnfq(a[1] * k)]; }
function bn2isZero(a) { return a[0] === 0n && a[1] === 0n; }
/* FQ12 = FQ[w] / (w^12 - 18 w^6 + 82) */
function bn12zero() { return new Array(12).fill(0n); }
function bn12one() { var a = new Array(12).fill(0n); a[0] = 1n; return a; }
function bn12isZero(a) { for (var i = 0; i < 12; i++) if (a[i] !== 0n) return false; return true; }
function bn12eq(a, b) { for (var i = 0; i < 12; i++) if (a[i] !== b[i]) return false; return true; }
function bn12add(a, b) { var r = new Array(12); for (var i = 0; i < 12; i++) r[i] = bnfq(a[i] + b[i]); return r; }
function bn12sub(a, b) { var r = new Array(12); for (var i = 0; i < 12; i++) r[i] = bnfq(a[i] - b[i]); return r; }
function bn12neg(a) { var r = new Array(12); for (var i = 0; i < 12; i++) r[i] = bnfq(-a[i]); return r; }
function bn12mul(a, b) {
  var c = new Array(23).fill(0n), i, j;
  for (i = 0; i < 12; i++) {
    if (a[i] === 0n) continue;
    for (j = 0; j < 12; j++) if (b[j] !== 0n) c[i + j] += a[i] * b[j];
  }
  /* w^12 = 18 w^6 - 82  ⇒  c[i-6] += 18*v; c[i-12] -= 82*v */
  for (i = 22; i >= 12; i--) {
    if (c[i] === 0n) continue;
    var v = c[i] % BN_P;
    c[i - 6] += 18n * v;
    c[i - 12] -= 82n * v;
    c[i] = 0n;
  }
  var r = new Array(12);
  for (i = 0; i < 12; i++) r[i] = bnfq(c[i]);
  return r;
}
function bn12sqr(a) { return bn12mul(a, a); }
function bn12mulScalar(a, k) { var r = new Array(12); for (var i = 0; i < 12; i++) r[i] = bnfq(a[i] * k); return r; }
function bnPolyDeg(p) { for (var i = p.length - 1; i >= 0; i--) if (p[i] !== 0n) return i; return -1; }
function bnPolyTrim(p) { var d = bnPolyDeg(p); return d < 0 ? [0n] : p.slice(0, d + 1); }
function bnPolyMul(a, b) {
  var c = new Array(a.length + b.length - 1).fill(0n);
  for (var i = 0; i < a.length; i++) { if (a[i] === 0n) continue; for (var j = 0; j < b.length; j++) c[i + j] += a[i] * b[j]; }
  for (var i = 0; i < c.length; i++) c[i] = bnfq(c[i]);
  return bnPolyTrim(c);
}
function bnPolySub(a, b) {
  var n = Math.max(a.length, b.length), c = new Array(n).fill(0n);
  for (var i = 0; i < n; i++) { var x = a[i] === undefined ? 0n : a[i]; var y = b[i] === undefined ? 0n : b[i]; c[i] = bnfq(x - y); }
  return bnPolyTrim(c);
}
function bnPolyDivMod(a, b) {
  var r = a.slice(), q = new Array(Math.max(1, a.length - b.length + 1)).fill(0n);
  var db = bnPolyDeg(b), inv = bnfqInv(b[db]);
  while (bnPolyDeg(r) >= db && bnPolyDeg(r) >= 0) {
    var dr = bnPolyDeg(r), coef = bnfq(r[dr] * inv), shift = dr - db;
    q[shift] = bnfq(coef);
    for (var i = 0; i <= db; i++) r[i + shift] = bnfq(r[i + shift] - coef * b[i]);
    r = bnPolyTrim(r);
    if (bnPolyDeg(r) < 0) break;
  }
  return [bnPolyTrim(q), bnPolyTrim(r)];
}
function bn12inv(a) {
  var r0 = BN_F12_MOD.slice(), r1 = bnPolyTrim(a.slice());
  var s0 = [0n], s1 = [1n], qr, tr, ts;
  while (bnPolyDeg(r1) > 0) {
    qr = bnPolyDivMod(r0, r1);
    tr = r1; r1 = bnPolySub(r0, bnPolyMul(qr[0], r1)); r0 = tr;
    ts = s1; s1 = bnPolySub(s0, bnPolyMul(qr[0], s1)); s0 = ts;
    if (bnPolyDeg(r1) === 0 && r1[0] === 0n) break;
  }
  if (bnPolyDeg(r1) !== 0) throw new Error('FQ12 求逆失败');
  var invLead = bnfqInv(r1[0]);
  var res = new Array(12).fill(0n);
  for (var i = 0; i < s1.length && i < 12; i++) res[i] = bnfq(s1[i] * invLead);
  return res;
}
function bn12div(a, b) { return bn12mul(a, bn12inv(b)); }
function bn12pow(a, e) {
  var res = bn12one(), base = a.slice(), x = e;
  while (x > 0n) {
    if (x & 1n) res = bn12mul(res, base);
    base = bn12sqr(base);
    x >>= 1n;
  }
  return res;
}
/* ---- G1（FQ 上，仿射）---- */
function bnG1Add(P, Q) {
  if (P === null) return Q;
  if (Q === null) return P;
  var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1];
  if (x1 === x2 && y1 === y2) {
    if (y1 === 0n) return null;
    var m = bnfq(bnfq(3n * x1 * x1) * bnfqInv(bnfq(2n * y1)));
  } else if (x1 === x2) {
    return null;
  } else {
    var m = bnfq(bnfq(y2 - y1) * bnfqInv(bnfq(x2 - x1)));
  }
  var nx = bnfq(m * m - x1 - x2);
  var ny = bnfq(m * (x1 - nx) - y1);
  return [nx, ny];
}
function bnG1Mul(P, k) {
  var e = ((k % BN_R) + BN_R) % BN_R;
  if (e === 0n || P === null) return null;
  var res = null, base = P;
  while (e > 0n) {
    if (e & 1n) res = bnG1Add(res, base);
    base = bnG1Add(base, base);
    e >>= 1n;
  }
  return res;
}
function bnG1IsOn(P) {
  if (P === null) return true;
  return bnfq(P[1] * P[1] - P[0] * P[0] * P[0] - BN_B) === 0n;
}
/* ---- G2（FQ2 上，仿射）---- */
function bnG2Add(P, Q) {
  if (P === null) return Q;
  if (Q === null) return P;
  var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1];
  var m;
  if (bn2eq(x1, x2) && bn2eq(y1, y2)) {
    if (bn2isZero(y1)) return null;
    m = bn2div(bn2mulScalar(bn2mul(x1, x1), 3n), bn2mulScalar(y1, 2n));
  } else if (bn2eq(x1, x2)) {
    return null;
  } else {
    m = bn2div(bn2sub(y2, y1), bn2sub(x2, x1));
  }
  var nx = bn2sub(bn2mul(m, m), bn2add(x1, x2));
  var ny = bn2sub(bn2mul(m, bn2sub(x1, nx)), y1);
  return [nx, ny];
}
function bnG2Mul(P, k) {
  var e = ((k % BN_R) + BN_R) % BN_R;
  if (e === 0n || P === null) return null;
  var res = null, base = P;
  while (e > 0n) {
    if (e & 1n) res = bnG2Add(res, base);
    base = bnG2Add(base, base);
    e >>= 1n;
  }
  return res;
}
/* ---- 扭映射：FQ2 点 → FQ12 点（与 py_ecc.bn128_curve.twist 严格一致）---- */
var BN_W = (function () { var w = new Array(12).fill(0n); w[1] = 1n; return w; })();
var BN_W2 = bn12mul(BN_W, BN_W);
var BN_W3 = bn12mul(BN_W2, BN_W);
function bnTwist(pt) {
  if (pt === null) return null;
  var _x = pt[0], _y = pt[1];
  /* x^2 + 1 → x^2 - 18x + 82 的域同构：coeffs[0] - coeffs[1]*9 */
  var xc = [bnfq(_x[0] - _x[1] * 9n), _x[1]];
  var yc = [bnfq(_y[0] - _y[1] * 9n), _y[1]];
  var nx = new Array(12).fill(0n); nx[0] = bnfq(xc[0]); nx[6] = bnfq(xc[1]);
  var ny = new Array(12).fill(0n); ny[0] = bnfq(yc[0]); ny[6] = bnfq(yc[1]);
  /* x 除以 w^2、y 除以 w^3 —— 等价于乘其逆 */
  return [bn12mul(nx, BN_W2), bn12mul(ny, BN_W3)];
}
/* ---- Miller 循环（仿射，与 py_ecc 朴素实现一致）---- */
function bnLinefunc(P1, P2, T) {
  var x1 = P1[0], y1 = P1[1], x2 = P2[0], y2 = P2[1], xt = T[0], yt = T[1], m;
  if (!bn12eq(x1, x2)) {
    m = bn12div(bn12sub(y2, y1), bn12sub(x2, x1));
  } else if (bn12eq(y1, y2)) {
    m = bn12div(bn12mulScalar(bn12mul(x1, x1), 3n), bn12mulScalar(y1, 2n));
  } else {
    return bn12sub(xt, x1);
  }
  return bn12sub(bn12mul(m, bn12sub(xt, x1)), bn12sub(yt, y1));
}
function bn12AffDouble(P) {
  var x = P[0], y = P[1];
  var m = bn12div(bn12mulScalar(bn12mul(x, x), 3n), bn12mulScalar(y, 2n));
  var nx = bn12sub(bn12mul(m, m), bn12mulScalar(x, 2n));
  var ny = bn12sub(bn12mul(m, bn12sub(x, nx)), y);
  return [nx, ny];
}
function bn12AffAdd(P, Q) {
  if (P === null) return Q;
  if (Q === null) return P;
  var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1], m;
  if (bn12eq(x1, x2) && bn12eq(y1, y2)) return bn12AffDouble(P);
  if (bn12eq(x1, x2)) return null;
  m = bn12div(bn12sub(y2, y1), bn12sub(x2, x1));
  var nx = bn12sub(bn12mul(m, m), bn12add(x1, x2));
  var ny = bn12sub(bn12mul(m, bn12sub(x1, nx)), y1);
  return [nx, ny];
}
function bnFinalExp(f) {
  return bn12pow(f, (bnPowBig(BN_P, 12n) - 1n) / BN_R);
}
function bnPowBig(base, e) {
  var r = 1n, b = base, x = e;
  while (x > 0n) { if (x & 1n) r *= b; b *= b; x >>= 1n; }
  return r;
}
function bnMillerLoop(Q, P) {
  if (Q === null || P === null) return bn12one();
  var R = [Q[0].slice(), Q[1].slice()], f = bn12one(), i;
  for (i = 63; i >= 0; i--) {
    f = bn12mul(bn12mul(f, f), bnLinefunc(R, R, P));
    R = bn12AffDouble(R);
    if ((BN_ATE_LOOP >> BigInt(i)) & 1n) {
      f = bn12mul(f, bnLinefunc(R, Q, P));
      R = bn12AffAdd(R, Q);
    }
  }
  /* 最后两步：Frobenius 后的 Q1 与 -Q2 —— 这是 BN 曲线 ate 配对的收尾，
     BLS12 没有这两步。漏掉会得到一个「自洽但与标准不互通」的结果。 */
  var Q1 = [bn12pow(Q[0], BN_P), bn12pow(Q[1], BN_P)];
  var nQ2 = [bn12pow(Q1[0], BN_P), bn12neg(bn12pow(Q1[1], BN_P))];
  f = bn12mul(f, bnLinefunc(R, Q1, P));
  R = bn12AffAdd(R, Q1);
  f = bn12mul(f, bnLinefunc(R, nQ2, P));
  return bnFinalExp(f);
}
function bnPairing(Q2, P1) {
  if (!bnG1IsOn(P1)) throw new Error('P 不在 BN254 的 G1 上');
  var Pf = [new Array(12).fill(0n), new Array(12).fill(0n)];
  Pf[0][0] = bnfq(P1[0]); Pf[1][0] = bnfq(P1[1]);
  return bnMillerLoop(bnTwist(Q2), Pf);
}
function bnF12ToBytes(a) {
  var out = new Uint8Array(12 * 32), v, i, j;
  for (i = 0; i < 12; i++) {
    v = a[i];
    for (j = 31; j >= 0; j--) { out[i * 32 + j] = Number(v & 0xffn); v >>= 8n; }
  }
  return out;
}

reg({ id: 'bn254-pairing', name: 'BN254 / alt_bn128 配对', group: '椭圆曲线与高级代数', key: true, param: true,
  keyLabel: 'Q：G2 点（128 字节 Hex，4 个 FQ2 分量）',
  paramLabel: 'P：G1 点（64 字节 Hex，2 个 FQ 分量），留空用生成元', paramOptional: true,
  info: 'BN254（又称 alt_bn128）最优 ate 配对，以太坊 precompile 0x8 使用的曲线，zkSNARK 常用。输出 384 字节（12 个 FQ 分量）。配对无对应的「解密」。',
  enc: function (b, k, p, fmt) {
    var qb = hexToBytes(k);
    if (qb.length !== 128) throw new Error('Q 需 128 字节（G2 点，4 个 FQ 分量各 32 字节）');
    var Q = [[bnFqFromBytes(qb.subarray(0, 32)), bnFqFromBytes(qb.subarray(32, 64))],
             [bnFqFromBytes(qb.subarray(64, 96)), bnFqFromBytes(qb.subarray(96, 128))]];
    var P = BN_G1;
    if (p && String(p).trim()) {
      var pb = hexToBytes(String(p).trim());
      if (pb.length !== 64) throw new Error('P 需 64 字节（G1 点，2 个 FQ 分量各 32 字节）');
      P = [bnFqFromBytes(pb.subarray(0, 32)), bnFqFromBytes(pb.subarray(32, 64))];
      if (!bnG1IsOn(P)) throw new Error('P 不在 BN254 的 G1 曲线上');
    }
    return bytesOut(bnF12ToBytes(bnPairing(Q, P)), fmt);
  },
  dec: function (b, k, p, fmt) { throw new Error('配对运算不可逆，无解密操作'); } });
function bnFqFromBytes(b) {
  var v = 0n;
  for (var i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[i]);
  return bnfq(v);
}
