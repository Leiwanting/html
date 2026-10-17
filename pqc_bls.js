/* ============================================================
 * BLS12-381 配对友好曲线（以太坊 / IETF 标准曲线）
 * 与 py_ecc（以太坊官方实现）逐项对齐
 * 常量来自 bls_const.js（由 py_ecc 导出，非手写）
 * ============================================================ */
function fq(a) { a = a % BLS_P; return a < 0n ? a + BLS_P : a; }
function fqInv(a) {
  if (a === 0n) throw new Error('FQ 除零');
  var oldR = a, r = BLS_P, oldS = 1n, s = 0n;
  while (r !== 0n) { var q = oldR / r; var tr = oldR - q * r; oldR = r; r = tr; var ts = oldS - q * s; oldS = s; s = ts; }
  oldS = oldS % BLS_P; return oldS < 0n ? oldS + BLS_P : oldS;
}
function f2(a0, a1) { return [fq(a0), fq(a1)]; }
var F2_ZERO = [0n, 0n], F2_ONE = [1n, 0n];
function f2add(a, b) { return [fq(a[0] + b[0]), fq(a[1] + b[1])]; }
function f2sub(a, b) { return [fq(a[0] - b[0]), fq(a[1] - b[1])]; }
function f2neg(a) { return [fq(-a[0]), fq(-a[1])]; }
function f2mul(a, b) {
  return [fq(a[0] * b[0] - a[1] * b[1]), fq(a[0] * b[1] + a[1] * b[0])];
}
function f2eq(a, b) { return a[0] === b[0] && a[1] === b[1]; }
function f2inv(a) {
  var d = fqInv(fq(a[0] * a[0] + a[1] * a[1]));
  return [fq(a[0] * d), fq(-a[1] * d)];
}
function f2div(a, b) { return f2mul(a, f2inv(b)); }
function f2mulScalar(a, k) { return [fq(a[0] * k), fq(a[1] * k)]; }
function f12zero() { return new Array(12).fill(0n); }
function f12one() { var a = new Array(12).fill(0n); a[0] = 1n; return a; }
function f12fromFq(v) { var a = new Array(12).fill(0n); a[0] = fq(v); return a; }
function f12isZero(a) { for (var i = 0; i < 12; i++) if (a[i] !== 0n) return false; return true; }
function f12eq(a, b) { for (var i = 0; i < 12; i++) if (a[i] !== b[i]) return false; return true; }
function f12add(a, b) { var r = new Array(12); for (var i = 0; i < 12; i++) r[i] = fq(a[i] + b[i]); return r; }
function f12sub(a, b) { var r = new Array(12); for (var i = 0; i < 12; i++) r[i] = fq(a[i] - b[i]); return r; }
function f12neg(a) { var r = new Array(12); for (var i = 0; i < 12; i++) r[i] = fq(-a[i]); return r; }
function f12mul(a, b) {
  var c = new Array(23).fill(0n);
  for (var i = 0; i < 12; i++) {
    if (a[i] === 0n) continue;
    for (var j = 0; j < 12; j++) if (b[j] !== 0n) c[i + j] += a[i] * b[j];
  }
  for (var i = 22; i >= 12; i--) {
    if (c[i] === 0n) continue;
    var v = c[i] % BLS_P;
    c[i - 6] += 2n * v;
    c[i - 12] -= 2n * v;
    c[i] = 0n;
  }
  var r = new Array(12);
  for (var i = 0; i < 12; i++) r[i] = fq(c[i]);
  return r;
}
var BLS_F12_MOD = (function () {
  var m = new Array(13).fill(0n);
  m[12] = 1n; m[6] = BLS_P - 2n; m[0] = 2n;   /* w^12 - 2w^6 + 2 */
  return m;
})();
function polyDeg(p) { for (var i = p.length - 1; i >= 0; i--) if (p[i] !== 0n) return i; return -1; }
function polyTrim(p) { var d = polyDeg(p); return d < 0 ? [0n] : p.slice(0, d + 1); }
function polyMul(a, b) {
  var c = new Array(a.length + b.length - 1).fill(0n);
  for (var i = 0; i < a.length; i++) { if (a[i] === 0n) continue; for (var j = 0; j < b.length; j++) c[i + j] += a[i] * b[j]; }
  for (var i = 0; i < c.length; i++) c[i] = fq(c[i]);
  return polyTrim(c);
}
function polySub(a, b) {
  var n = Math.max(a.length, b.length), c = new Array(n).fill(0n);
  for (var i = 0; i < n; i++) { var x = a[i] === undefined ? 0n : a[i]; var y = b[i] === undefined ? 0n : b[i]; c[i] = fq(x - y); }
  return polyTrim(c);
}
function polyDivMod(a, b) {
  var r = a.slice(), q = new Array(Math.max(1, a.length - b.length + 1)).fill(0n);
  var db = polyDeg(b), inv = fqInv(b[db]);
  while (polyDeg(r) >= db && polyDeg(r) >= 0) {
    var dr = polyDeg(r), coef = fq(r[dr] * inv), shift = dr - db;
    q[shift] = fq(coef);
    for (var i = 0; i <= db; i++) r[i + shift] = fq(r[i + shift] - coef * b[i]);
    r = polyTrim(r);
    if (polyDeg(r) < 0) break;
  }
  return [polyTrim(q), polyTrim(r)];
}
function f12inv(a) {
  var r0 = BLS_F12_MOD.slice(), r1 = polyTrim(a.slice());
  var s0 = [0n], s1 = [1n];
  while (polyDeg(r1) > 0) {
    var qr = polyDivMod(r0, r1);
    var tr = r1; r1 = polySub(r0, polyMul(qr[0], r1)); r0 = tr;
    var ts = s1; s1 = polySub(s0, polyMul(qr[0], s1)); s0 = ts;
    if (polyDeg(r1) === 0 && r1[0] === 0n) break;
  }
  if (polyDeg(r1) !== 0) throw new Error('FQ12 求逆失败');
  var invLead = fqInv(r1[0]);
  var res = new Array(12).fill(0n);
  for (var i = 0; i < s1.length && i < 12; i++) res[i] = fq(s1[i] * invLead);
  return res;
}
function f12div(a, b) { return f12mul(a, f12inv(b)); }
function f12sqr(a) { return f12mul(a, a); }
function f12pow(a, e) {
  var res = f12one(), base = a.slice();
  while (e > 0n) {
    if (e & 1n) res = f12mul(res, base);
    base = f12sqr(base);
    e >>= 1n;
  }
  return res;
}
/* ---- 曲线点：标准射影坐标 (x:y:z)，满足 y^2 z = x^3 + b z^3 ---- */
function g1IsInf(p) { return p[2] === 0n; }
function g2IsInf(p) { return p[2][0] === 0n && p[2][1] === 0n; }
function g1Double(pt) {
  var x = pt[0], y = pt[1], z = pt[2];
  var W = fq(3n * x * x), S = fq(y * z), B = fq(x * y * S), H = fq(W * W - 8n * B);
  var S2 = fq(S * S);
  return [fq(2n * H * S), fq(W * (4n * B - H) - 8n * y * y * S2), fq(8n * S * S2)];
}
function g1Add(p1, p2) {
  if (p1[2] === 0n) return p2;
  if (p2[2] === 0n) return p1;
  var x1 = p1[0], y1 = p1[1], z1 = p1[2], x2 = p2[0], y2 = p2[1], z2 = p2[2];
  var U1 = fq(y2 * z1), U2 = fq(y1 * z2), V1 = fq(x2 * z1), V2 = fq(x1 * z2);
  if (V1 === V2 && U1 === U2) return g1Double(p1);
  if (V1 === V2) return [1n, 1n, 0n];
  var U = fq(U1 - U2), V = fq(V1 - V2), V2sq = fq(V * V), V2V2 = fq(V2sq * V2), V3 = fq(V * V2sq);
  var W = fq(z1 * z2), A = fq(U * U * W - V3 - 2n * V2V2);
  return [fq(V * A), fq(U * (V2V2 - A) - V3 * U2), fq(V3 * W)];
}
function g1Mul(pt, n) {
  if (n === 0n) return [1n, 1n, 0n];
  var res = [1n, 1n, 0n], base = pt.slice(), e = n;
  while (e > 0n) {
    if (e & 1n) res = g1Add(res, base);
    base = g1Double(base);
    e >>= 1n;
  }
  return res;
}
function g1Normalize(pt) {
  if (pt[2] === 0n) return null;
  var iz = fqInv(pt[2]);
  return [fq(pt[0] * iz), fq(pt[1] * iz)];
}
function g2Double(pt) {
  var x = pt[0], y = pt[1], z = pt[2];
  var W = f2mulScalar(x, 3n); W = f2mul(W, x);   /* 3x^2 */
  var S = f2mul(y, z), B = f2mul(f2mul(x, y), S), H = f2sub(f2mul(W, W), f2mulScalar(B, 8n));
  var S2 = f2mul(S, S);
  var newx = f2mulScalar(f2mul(H, S), 2n);
  var newy = f2sub(f2mul(W, f2sub(f2mulScalar(B, 4n), H)), f2mulScalar(f2mul(f2mul(y, y), S2), 8n));
  var newz = f2mulScalar(f2mul(S, S2), 8n);
  return [newx, newy, newz];
}
function g2Add(p1, p2) {
  if (f2eq(p1[2], F2_ZERO)) return p2;
  if (f2eq(p2[2], F2_ZERO)) return p1;
  var x1 = p1[0], y1 = p1[1], z1 = p1[2], x2 = p2[0], y2 = p2[1], z2 = p2[2];
  var U1 = f2mul(y2, z1), U2 = f2mul(y1, z2), V1 = f2mul(x2, z1), V2 = f2mul(x1, z2);
  if (f2eq(V1, V2) && f2eq(U1, U2)) return g2Double(p1);
  if (f2eq(V1, V2)) return [F2_ONE, F2_ONE, F2_ZERO];
  var U = f2sub(U1, U2), V = f2sub(V1, V2), Vsq = f2mul(V, V), VsqV2 = f2mul(Vsq, V2), V3 = f2mul(V, Vsq);
  var W = f2mul(z1, z2), A = f2sub(f2sub(f2mul(f2mul(U, U), W), V3), f2mulScalar(VsqV2, 2n));
  return [f2mul(V, A), f2sub(f2mul(U, f2sub(VsqV2, A)), f2mul(V3, U2)), f2mul(V3, W)];
}
function g2Mul(pt, n) {
  if (n === 0n) return [F2_ONE, F2_ONE, F2_ZERO];
  var res = [F2_ONE, F2_ONE, F2_ZERO], base = [pt[0].slice(), pt[1].slice(), pt[2].slice()], e = n;
  while (e > 0n) {
    if (e & 1n) res = g2Add(res, base);
    base = g2Double(base);
    e >>= 1n;
  }
  return res;
}
function g2Normalize(pt) {
  if (f2eq(pt[2], F2_ZERO)) return null;
  var iz = f2inv(pt[2]);
  return [f2mul(pt[0], iz), f2mul(pt[1], iz)];
}
function g2Neg(pt) { return [pt[0].slice(), f2neg(pt[1]), pt[2].slice()]; }
function blsTwist(pt) {
  var _x = pt[0], _y = pt[1], _z = pt[2];
  var xc = [fq(_x[0] - _x[1]), _x[1]];
  var yc = [fq(_y[0] - _y[1]), _y[1]];
  var zc = [fq(_z[0] - _z[1]), _z[1]];
  var nx = f12zero(); nx[1] = fq(xc[0]); nx[7] = fq(xc[1]);
  var ny = f12zero(); ny[0] = fq(yc[0]); ny[6] = fq(yc[1]);
  var nz = f12zero(); nz[3] = fq(zc[0]); nz[9] = fq(zc[1]);
  return [nx, ny, nz];
}
function blsLinefunc(P1, P2, T) {
  var x1 = P1[0], y1 = P1[1], z1 = P1[2];
  var x2 = P2[0], y2 = P2[1], z2 = P2[2];
  var xt = T[0], yt = T[1], zt = T[2];
  var mNum = f12sub(f12mul(y2, z1), f12mul(y1, z2));
  var mDen = f12sub(f12mul(x2, z1), f12mul(x1, z2));
  if (!f12isZero(mDen)) {
    return [f12sub(f12mul(mNum, f12sub(f12mul(xt, z1), f12mul(x1, zt))),
                   f12mul(mDen, f12sub(f12mul(yt, z1), f12mul(y1, zt)))),
            f12mul(f12mul(mDen, zt), z1)];
  } else if (f12isZero(mNum)) {
    mNum = f12mulScalarFq(f12mul(x1, x1), 3n);
    mDen = f12mulScalarFq(f12mul(y1, z1), 2n);
    return [f12sub(f12mul(mNum, f12sub(f12mul(xt, z1), f12mul(x1, zt))),
                   f12mul(mDen, f12sub(f12mul(yt, z1), f12mul(y1, zt)))),
            f12mul(f12mul(mDen, zt), z1)];
  } else {
    return [f12sub(f12mul(xt, z1), f12mul(x1, zt)), f12mul(z1, zt)];
  }
}
function f12mulScalarFq(a, k) { var r = new Array(12); for (var i = 0; i < 12; i++) r[i] = fq(a[i] * k); return r; }
function blsMiller(Q, P) {
  if (g2IsInf(Q) || g1IsInf(P)) return f12one();
  var castP = [f12fromFq(P[0]), f12fromFq(P[1]), f12fromFq(P[2])];
  var twistQ = blsTwist(Q), twistR = twistQ;
  var R = [Q[0].slice(), Q[1].slice(), Q[2].slice()];
  var fNum = f12one(), fDen = f12one();
  /* ate_loop_count 的最高位（63）在标准 Miller 循环里是隐含的，故从 62 开始 */
  for (var i = 62; i >= 0; i--) {
    var ln = blsLinefunc(twistR, twistR, castP);
    fNum = f12mul(f12mul(fNum, fNum), ln[0]);
    fDen = f12mul(f12mul(fDen, fDen), ln[1]);
    R = g2Double(R);
    twistR = blsTwist(R);
    if (BLS_PBE[i] === 1) {
      ln = blsLinefunc(twistR, twistQ, castP);
      fNum = f12mul(fNum, ln[0]);
      fDen = f12mul(fDen, ln[1]);
      R = g2Add(R, Q);
      twistR = blsTwist(R);
    }
  }
  return f12div(fNum, fDen);
}
var BLS_FINAL_EXP = (BLS_P * BLS_P * BLS_P * BLS_P * BLS_P * BLS_P * BLS_P * BLS_P * BLS_P * BLS_P * BLS_P * BLS_P - 1n) / BLS_R;
function blsPairing(Q, P) {
  var f = blsMiller(Q, P);
  return f12pow(f, BLS_FINAL_EXP);
}

/* ============================================================
 * BLS 签名（BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_）
 * hash_to_G1：expand_message_xmd → SSWU → 3-Isogeny → 清余因子
 * 常量全部来自 vec_swu.json 运行时注入（由 py_ecc 导出）
 * ============================================================ */
var SWU = null;
function blsInitSwu(cfg) {
  SWU = {
    A: BigInt(cfg.ISO_11_A), B: BigInt(cfg.ISO_11_B), Z: BigInt(cfg.ISO_11_Z),
    SQRT: BigInt(cfg.SQRT_MINUS_11_CUBED),
    MAP: cfg.ISO_11_MAP_COEFFICIENTS.map(function (r) { return r.map(BigInt); }),
    H_EFF: BigInt(cfg.H_EFF_G1), L: cfg.L, DST: cfg.DST
  };
}

function blsCat(parts) {
  var n = 0, i;
  for (i = 0; i < parts.length; i++) n += parts[i].length;
  var o = new Uint8Array(n), pos = 0;
  for (i = 0; i < parts.length; i++) { o.set(parts[i], pos); pos += parts[i].length; }
  return o;
}

/* RFC 9380 expand_message_xmd */
function blsExpandMsgXmd(msg, dst, lenOut) {
  /* RFC 9380：b_in_bytes = 摘要长度(32)，r_in_bytes = 哈希【块大小 64】不是摘要长度 */
  var bInBytes = 32, rInBytes = 64, ell = Math.ceil(lenOut / bInBytes);
  if (ell > 255) throw new Error('expand_message_xmd 过长');
  var dstPrime = concatBytes(dst, new Uint8Array([dst.length]));
  var zPad = new Uint8Array(rInBytes);
  var lIB = new Uint8Array([(lenOut >> 8) & 0xff, lenOut & 0xff]);
  var b0 = sha256Bytes(blsCat([zPad, msg, lIB, new Uint8Array([0]), dstPrime]));
  var bVals = [sha256Bytes(blsCat([b0, new Uint8Array([1]), dstPrime]))];
  for (var i = 2; i <= ell; i++) {
    var xored = new Uint8Array(bInBytes);
    for (var j = 0; j < bInBytes; j++) xored[j] = b0[j] ^ bVals[i - 2][j];
    bVals.push(sha256Bytes(blsCat([xored, new Uint8Array([i]), dstPrime])));
  }
  var out = new Uint8Array(lenOut), pos = 0;
  for (var i = 0; i < bVals.length && pos < lenOut; i++)
    for (var j = 0; j < bVals[i].length && pos < lenOut; j++) out[pos++] = bVals[i][j];
  return out;
}
function fqPow(a, e) {
  var res = 1n, base = fq(a);
  while (e > 0n) { if (e & 1n) res = fq(res * base); base = fq(base * base); e >>= 1n; }
  return res;
}
function blsSqrtDiv(u, v) {
  var temp = fq(u * v);
  var result = fq(temp * fqPow(fq(temp * fq(v * v)), (BLS_P - 3n) / 4n));
  return [fq(result * result * v - u) === 0n, result];
}
/* RFC 9380 的 sgn0 对 m=1 是【最低位奇偶性】x % 2，不是 "x > (p-1)/2"。
   py_ecc 明确写的是 return self.n % 2。我第一版写错，导致 y 的符号取反判断全错。 */
function fqSgn0(a) { a = fq(a); return Number(a % 2n); }
function blsSwuG1(t) {
  var A = SWU.A, B = SWU.B, Z = SWU.Z;
  var t2 = fq(t * t), isoZt2 = fq(Z * t2), temp = fq(isoZt2 + fq(isoZt2 * isoZt2));
  var den = fq(-(A * temp));
  temp = fq(temp + 1n);
  var num = fq(B * temp);
  if (den === 0n) den = fq(Z * A);
  var v = fq(den * den * den);
  var u = fq(fq(num * num * num) + fq(A * num * fq(den * den)) + fq(B * v));
  var sd = blsSqrtDiv(u, v), isRoot = sd[0], y = sd[1];
  if (!isRoot) { y = fq(y * fq(t * t * t) * SWU.SQRT); num = fq(num * isoZt2); }
  if (fqSgn0(t) !== fqSgn0(y)) y = fq(-y);
  y = fq(y * den);
  return [num, y, den];
}
function blsIsoMapG1(x, y, z) {
  var zp = [], cur = z;
  for (var i = 0; i < 15; i++) { zp.push(cur); cur = fq(cur * z); }
  var mv = [0n, 0n, 0n, 0n];
  for (var i = 0; i < 4; i++) {
    var ki = SWU.MAP[i];
    mv[i] = ki[ki.length - 1];
    for (var j = 0; j < ki.length - 1; j++) mv[i] = fq(mv[i] * x + zp[j] * ki[ki.length - 2 - j]);
  }
  mv[1] = fq(mv[1] * z);
  mv[2] = fq(mv[2] * y);
  mv[3] = fq(mv[3] * z);
  return [fq(mv[0] * mv[3]), fq(mv[1] * mv[2]), fq(mv[1] * mv[3])];
}
function blsHashToG1(msg) {
  if (!SWU) throw new Error('SWU 常量未初始化');
  /* DST 是 ASCII，直接按字节编码；哈希用主工程已有的纯 JS SHA-256（sha256Bytes）。
     注意不能依赖 strToBytes（UTF-8 编码对非 ASCII 会膨胀，且顺序依赖主文件加载）。 */
  var dstBytes = new Uint8Array(SWU.DST.length);
  for (var di = 0; di < SWU.DST.length; di++) dstBytes[di] = SWU.DST.charCodeAt(di) & 0xff;
  var prb = blsExpandMsgXmd(msg, dstBytes, 2 * SWU.L);
  var us = [];
  for (var i = 0; i < 2; i++) {
    var v = 0n;
    for (var j = 0; j < SWU.L; j++) v = (v << 8n) | BigInt(prb[i * SWU.L + j]);
    us.push(fq(v));
  }
  var q0 = blsIsoMapG1.apply(null, blsSwuG1(us[0]));
  var q1 = blsIsoMapG1.apply(null, blsSwuG1(us[1]));
  var r = g1Add(q0, q1);
  return g1Mul(r, SWU.H_EFF);
}
function blsSkToPk(sk) { return g2Mul(BLS_G2, sk % BLS_R); }
function blsSign(sk, msg) { return g1Mul(blsHashToG1(msg), sk % BLS_R); }
function blsVerify(pk, msg, sig) {
  if (g2IsInf(pk) || g1IsInf(sig)) return false;
  var H = blsHashToG1(msg);
  return f12eq(blsPairing(pk, H), blsPairing(BLS_G2, sig));
}

function blsFqToBytes(v) {
  var x = fq(v), out = new Uint8Array(48);
  for (var i = 47; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}
function blsFqFromBytes(b) {
  var v = 0n;
  for (var i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
  return fq(v);
}
function blsG1ToBytes(P) {
  var n = g1Normalize(P);
  if (!n) throw new Error('G1 点为无穷远');
  return blsCat([blsFqToBytes(n[0]), blsFqToBytes(n[1])]);
}
function blsG1FromBytes(b) {
  if (b.length !== 96) throw new Error('G1 点应为 96 字节（未压缩），收到 ' + b.length);
  var P = [blsFqFromBytes(b.subarray(0, 48)), blsFqFromBytes(b.subarray(48, 96)), 1n];
  var y2 = fq(P[1] * P[1]), x3b = fq(P[0] * P[0] * P[0] + BLS_B);
  if (y2 !== x3b) throw new Error('G1 点不在曲线上');
  return P;
}
function blsG2ToBytes(P) {
  var n = g2Normalize(P);
  if (!n) throw new Error('G2 点为无穷远');
  return blsCat([blsFqToBytes(n[0][0]), blsFqToBytes(n[0][1]),
                 blsFqToBytes(n[1][0]), blsFqToBytes(n[1][1])]);
}
function blsG2FromBytes(b) {
  if (b.length !== 192) throw new Error('G2 点应为 192 字节（未压缩），收到 ' + b.length);
  var P = [[blsFqFromBytes(b.subarray(0, 48)), blsFqFromBytes(b.subarray(48, 96))],
           [blsFqFromBytes(b.subarray(96, 144)), blsFqFromBytes(b.subarray(144, 192))], [1n, 0n]];
  var y2 = f2mul(P[1], P[1]);
  var x3 = f2mul(f2mul(P[0], P[0]), P[0]);
  var rhs = f2add(x3, [fq(BLS_B2[0]), fq(BLS_B2[1])]);
  if (!f2eq(y2, rhs)) throw new Error('G2 点不在曲线上');
  return P;
}
function blsBytesToSk(b) {
  var v = 0n;
  for (var i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
  return v % BLS_R;
}

if (typeof SWU_ISO11_MAP !== 'undefined') {
  blsInitSwu({
    ISO_11_A: SWU_ISO11_A.toString(), ISO_11_B: SWU_ISO11_B.toString(),
    ISO_11_Z: SWU_ISO11_Z.toString(), SQRT_MINUS_11_CUBED: SWU_SQRT_M11_CUBED.toString(),
    H_EFF_G1: SWU_H_EFF_G1.toString(), L: SWU_L, DST: SWU_DST,
    ISO_11_MAP_COEFFICIENTS: SWU_ISO11_MAP.map(function (r) { return r.map(String); })
  });
}
