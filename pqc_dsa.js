/* ============================================================
 * ML-DSA（FIPS 204，NIST 后量子数字签名，原 CRYSTALS-Dilithium）
 * 参考实现 dilithium_py 对齐
 * q = 8380417，原根 175，n = 256
 * ============================================================ */
/* 注意：crypto_core.js 里已有全局 var DSA_Q（经典 DSA 的 1024 位大素数，BigInt 类型）。
   ML-DSA 必须用带前缀的名字，否则会被那个 BigInt 覆盖，
   在 NTT 里抛出 "Cannot mix BigInt and other types"。 */
var MLDSA_Q = 8380417;
function dq(v) { v = v % MLDSA_Q; return v < 0 ? v + MLDSA_Q : v; }
/* 扩展欧几里得求模逆（标准形式）。
   我第一版把迭代变量的更新顺序写错了，直接算出 undefined 导致整文件加载失败。 */
function dsaModInv(a, m) {
  var oldR = a, r = m, oldS = 1, s = 0;
  while (r !== 0) {
    var q = Math.floor(oldR / r);
    var tr = oldR - q * r; oldR = r; r = tr;
    var ts = oldS - q * s; oldS = s; s = ts;
  }
  return ((oldS % m) + m) % m;
}
var MLDSA_NTT_F = (function () {
  var m = 8380417n, oldR = 256n, r = m, oldS = 1n, s = 0n;
  while (r !== 0n) {
    var q = oldR / r;
    var tr = oldR - q * r; oldR = r; r = tr;
    var ts = oldS - q * s; oldS = s; s = ts;
  }
  return Number(((oldS % m) + m) % m);
})();
var MLDSA_ZETAS = (function () {
  var z = new Float64Array(256);
  for (var i = 0; i < 256; i++) {
    var br = 0, v = i;
    for (var b = 0; b < 8; b++) { br = (br << 1) | (v & 1); v >>= 1; }
    var p = 1;
    for (var e = 0; e < br; e++) p = (p * 1753) % MLDSA_Q;
    z[i] = p;
  }
  return z;
})();
function dsaToNTT(c) {
  var k = 0, l = 128;
  while (l > 0) {
    var start = 0;
    while (start < 256) {
      k++;
      var zeta = MLDSA_ZETAS[k], j = start;
      for (j = start; j < start + l; j++) {
        var t = dq(zeta * c[j + l]), u = c[j];
        c[j + l] = dq(u - t); c[j] = dq(u + t);
      }
      start = j + l;   /* JS 循环退出时 j=start+l；Python 是 start+l-1 故原文写 j+l+1 */
    }
    l >>= 1;
  }
  return c;
}
function dsaFromNTT(c) {
  var l = 1, k = 256;
  while (l < 256) {
    var start = 0;
    while (start < 256) {
      k--;
      var zeta = -MLDSA_ZETAS[k], j = start;
      for (j = start; j < start + l; j++) {
        var t = c[j], u = c[j + l];
        c[j] = dq(t + u);
        c[j + l] = dq(dq(t - u) * zeta);
      }
      start = j + l;
    }
    l <<= 1;
  }
  for (var i = 0; i < 256; i++) c[i] = dq(c[i] * MLDSA_NTT_F);
  return c;
}
function dsaReducePm(r, n) { r = r % n; if (r > (n >> 1)) r -= n; return r; }
function dsaDecompose(r, a) {
  var rp = dq(r), r0 = dsaReducePm(rp, a);
  if (rp - r0 === MLDSA_Q - 1) return [0, r0 - 1];
  return [Math.floor((rp - r0) / a), r0];
}
function dsaHighBits(r, a) { return dsaDecompose(r, a)[0]; }
function dsaLowBits(r, a) { return dsaDecompose(r, a)[1]; }
function dsaMakeHint(z, r, a) { return dsaHighBits(r, a) !== dsaHighBits(r + z, a) ? 1 : 0; }
function dsaUseHint(h, r, a) {
  var m = Math.floor((MLDSA_Q - 1) / a), d = dsaDecompose(r, a);
  if (h === 1) return d[1] > 0 ? (d[0] + 1) % m : (d[0] - 1 + m) % m;
  return d[0];
}
/* 范数界检查：注意 x>>31 在负数时是算术右移，与 Python 任意精度行为一致 */
function dsaNormBad(n_, b) {
  var x = dq(n_);
  x = ((MLDSA_Q - 1) >> 1) - x;
  x = x ^ (x >> 31);
  x = ((MLDSA_Q - 1) >> 1) - x;
  return x >= b;
}
function dsaRejNTT(rho, i, j) {
  var buf = shake128Digest(concatBytes(rho, new Uint8Array([j, i])), 2048);
  var out = new Float64Array(256), p = 0;
  for (var c = 0; c < 256; c++) {
    var v;
    do { v = (buf[p] | (buf[p + 1] << 8) | (buf[p + 2] << 16)) & 0x7FFFFF; p += 3; } while (!(v < MLDSA_Q));
    out[c] = v;
  }
  return out;
}
function dsaSampleInBall(seed, tau) {
  var buf = shake256Digest(seed, 1024), p = 0, signInt = 0n;
  for (var i = 0; i < 8; i++) signInt |= BigInt(buf[p++]) << BigInt(8 * i);
  var coeffs = new Float64Array(256);
  for (var i = 256 - tau; i < 256; i++) {
    var j;
    do { j = buf[p++]; } while (j > i);
    coeffs[i] = coeffs[j];
    coeffs[j] = 1 - 2 * Number(signInt & 1n);
    signInt >>= 1n;
  }
  return coeffs;
}
function dsaRejBounded(rhoPrime, idx, eta) {
  var seed = concatBytes(rhoPrime, new Uint8Array([idx & 0xff, (idx >> 8) & 0xff]));
  var buf = shake256Digest(seed, 512), coeffs = new Float64Array(256), i = 0, p = 0;
  function cfhb(j) { if (eta === 2 && j < 15) return 2 - (j % 5); if (j < 9 && eta === 4) return 4 - j; return false; }
  while (i < 256) {
    var b = buf[p++], c0 = cfhb(b % 16);
    if (c0 !== false) { coeffs[i] = c0; i++; }
    var c1 = cfhb(Math.floor(b / 16));
    if (c1 !== false && i < 256) { coeffs[i] = c1; i++; }
  }
  return coeffs;
}
function dsaSampleMask(rhoP, i, kappa, gamma1) {
  var bitCount = (gamma1 === (1 << 17)) ? 18 : 20;
  var totalBytes = (gamma1 === (1 << 17)) ? 576 : 640;
  var kk = kappa + i;
  var seed = concatBytes(rhoP, new Uint8Array([kk & 0xff, (kk >> 8) & 0xff]));
  var xof = shake256Digest(seed, totalBytes), r = 0n;
  for (var b = totalBytes - 1; b >= 0; b--) r = (r << 8n) | BigInt(xof[b]);
  var mask = (1n << BigInt(bitCount)) - 1n, coeffs = new Float64Array(256);
  for (var k = 0; k < 256; k++) coeffs[k] = gamma1 - Number((r >> BigInt(bitCount * k)) & mask);
  return coeffs;
}
function dsaBitPack(coeffs, nBits, nBytes) {
  var r = 0n, nb = BigInt(nBits);
  for (var i = coeffs.length - 1; i >= 0; i--) { r <<= nb; r |= BigInt(coeffs[i]); }
  var out = new Uint8Array(nBytes);
  for (var j = 0; j < nBytes; j++) { out[j] = Number(r & 0xffn); r >>= 8n; }
  return out;
}
function dsaBitUnpack(bytes, nBits) {
  var r = 0n;
  for (var i = bytes.length - 1; i >= 0; i--) r = (r << 8n) | BigInt(bytes[i]);
  var mask = (1n << BigInt(nBits)) - 1n, out = new Float64Array(256);
  for (var k = 0; k < 256; k++) out[k] = Number((r >> BigInt(nBits * k)) & mask);
  return out;
}
/* ---- 参数集（FIPS 204） ---- */
var MLDSA_PARAMS = {
  44: { k: 4, l: 4, eta: 2, tau: 39, omega: 80, gamma1: 1 << 17, gamma2: 95232, beta: 78, d: 13, ct: 32 },
  65: { k: 6, l: 5, eta: 4, tau: 49, omega: 55, gamma1: 1 << 19, gamma2: 261888, beta: 196, d: 13, ct: 48 },
  87: { k: 8, l: 7, eta: 2, tau: 60, omega: 75, gamma1: 1 << 19, gamma2: 261888, beta: 120, d: 13, ct: 64 }
};
function dsaMat(rho, k, l) {
  var A = [];
  for (var i = 0; i < k; i++) { A.push([]); for (var j = 0; j < l; j++) A[i].push(dsaRejNTT(rho, i, j)); }
  return A;
}
function dsaMatVecNTT(A, v) {
  var k = A.length, out = [];
  for (var i = 0; i < k; i++) {
    var acc = new Float64Array(256);
    for (var j = 0; j < A[i].length; j++) {
      var a = A[i][j], b = v[j];
      for (var c = 0; c < 256; c++) acc[c] = dq(acc[c] + a[c] * b[c]);
    }
    out.push(acc);
  }
  return out;
}
function dsaScaleNTT(a, b) { var r = new Float64Array(256); for (var i = 0; i < 256; i++) r[i] = dq(a[i] * b[i]); return r; }
function dsaVecAdd(a, b) { var r = new Float64Array(256); for (var i = 0; i < 256; i++) r[i] = dq(a[i] + b[i]); return r; }
function dsaVecSub(a, b) { var r = new Float64Array(256); for (var i = 0; i < 256; i++) r[i] = dq(a[i] - b[i]); return r; }
function dsaVecNeg(a) { var r = new Float64Array(256); for (var i = 0; i < 256; i++) r[i] = dq(-a[i]); return r; }
function dsaScaleConst(a, s) { var r = new Float64Array(256); for (var i = 0; i < 256; i++) r[i] = dq(a[i] * s); return r; }

/* FIPS 204 的消息域分离：M' = 0x00 || len(ctx) || ctx || msg
   我一开始直接用原始 msg，导致自身自洽但与所有标准实现不互通——
   这类「自己跑得通、一互操作就挂」的错误最危险。 */
function mldsaMPrime(msg, ctx) {
  ctx = ctx || new Uint8Array(0);
  if (ctx.length > 255) throw new Error('ctx 不能超过 255 字节');
  return mlkemCat([new Uint8Array([0, ctx.length]), ctx, msg]);
}

function mldsaKeygen(level) {
  var P = MLDSA_PARAMS[level], k = P.k, l = P.l;
  var zeta = crypto.getRandomValues(new Uint8Array(32));
  var seed = shake256Digest(concatBytes(zeta, new Uint8Array([k, l])), 128);
  var rho = seed.subarray(0, 32), rhoP = seed.subarray(32, 96), K = seed.subarray(96, 128);
  var A = dsaMat(rho, k, l);
  var s1 = [], s2 = [];
  for (var i = 0; i < l; i++) s1.push(dsaRejBounded(rhoP, i, P.eta));
  for (var i = 0; i < k; i++) s2.push(dsaRejBounded(rhoP, l + i, P.eta));
  var s1h = s1.map(function (p) { return dsaToNTT(p.slice()); });
  var t = dsaMatVecNTT(A, s1h).map(function (p) { return dsaFromNTT(p.slice()); });
  for (var i = 0; i < k; i++) t[i] = dsaVecAdd(t[i], s2[i]);
  var t1 = [], t0 = [];
  for (var i = 0; i < k; i++) {
    var pow = 1 << P.d, r1 = new Float64Array(256), r0 = new Float64Array(256);
    for (var c = 0; c < 256; c++) {
      var r = dq(t[i][c]), rr0 = dsaReducePm(r, pow);
      r1[c] = (r - rr0) >> P.d; r0[c] = rr0;
    }
    t1.push(r1); t0.push(r0);
  }
  var pkParts = [rho];
  for (var i = 0; i < k; i++) pkParts.push(dsaBitPack(t1[i], 10, 320));
  var pk = mlkemCat(pkParts);
  var tr = shake256Digest(pk, 64);
  var skParts = [rho, K, tr];
  for (var i = 0; i < l; i++) skParts.push(dsaBitPack(s1[i].map(function (x) { return P.eta - x; }), P.eta === 2 ? 3 : 4, P.eta === 2 ? 96 : 128));
  for (var i = 0; i < k; i++) skParts.push(dsaBitPack(s2[i].map(function (x) { return P.eta - x; }), P.eta === 2 ? 3 : 4, P.eta === 2 ? 96 : 128));
  for (var i = 0; i < k; i++) skParts.push(dsaBitPack(t0[i].map(function (x) { return (1 << 12) - x; }), 13, 416));
  return { pk: pk, sk: mlkemCat(skParts) };
}
function mldsaSign(level, sk, msg, rnd) {
  var P = MLDSA_PARAMS[level], k = P.k, l = P.l;
  var sb = 96, off = 0;
  var rho = sk.subarray(0, 32), K = sk.subarray(32, 64), tr = sk.subarray(64, 128);
  off = 128;
  var sz = P.eta === 2 ? 96 : 128, nBits = P.eta === 2 ? 3 : 4;
  var s1 = [], s2 = [], t0 = [];
  for (var i = 0; i < l; i++) { s1.push(dsaBitUnpack(sk.subarray(off, off + sz), nBits).map(function (x) { return P.eta - x; })); off += sz; }
  for (var i = 0; i < k; i++) { s2.push(dsaBitUnpack(sk.subarray(off, off + sz), nBits).map(function (x) { return P.eta - x; })); off += sz; }
  for (var i = 0; i < k; i++) { t0.push(dsaBitUnpack(sk.subarray(off, off + 416), 13).map(function (x) { return (1 << 12) - x; })); off += 416; }
  var s1h = s1.map(function (p) { return dsaToNTT(p.slice()); });
  var s2h = s2.map(function (p) { return dsaToNTT(p.slice()); });
  var t0h = t0.map(function (p) { return dsaToNTT(p.slice()); });
  var A = dsaMat(rho, k, l);
  var mu = shake256Digest(concatBytes(tr, mldsaMPrime(msg)), 64);
  var rhoP = shake256Digest(mlkemCat([K, rnd, mu]), 64);
  var kappa = 0, alpha = P.gamma2 << 1;
  for (var guard = 0; guard < 1000; guard++) {
    var y = [];
    for (var i = 0; i < l; i++) y.push(dsaSampleMask(rhoP, i, kappa, P.gamma1));
    var yh = y.map(function (p) { return dsaToNTT(p.slice()); });
    var w = dsaMatVecNTT(A, yh).map(function (p) { return dsaFromNTT(p.slice()); });
    kappa += l;
    var w1 = w.map(function (p) { var r = new Float64Array(256); for (var c = 0; c < 256; c++) r[c] = dsaHighBits(p[c], alpha); return r; });
    var w1Parts = w1.map(function (p) { return dsaBitPack(p, P.gamma2 === 95232 ? 6 : 4, P.gamma2 === 95232 ? 192 : 128); });
    var cTilde = shake256Digest(mlkemCat([mu].concat(w1Parts)), P.ct);
    var c = dsaSampleInBall(cTilde, P.tau);
    var ch = dsaToNTT(c.slice());
    var z = [], bad = false;
    for (var i = 0; i < l; i++) {
      var cs1 = dsaFromNTT(dsaScaleNTT(s1h[i], ch));
      z.push(dsaVecAdd(y[i], cs1));
      for (var c = 0; c < 256; c++) if (dsaNormBad(z[i][c], P.gamma1 - P.beta)) { bad = true; break; }
      if (bad) break;
    }
    if (bad) continue;
    var cs2 = [], r0 = [];
    bad = false;
    for (var i = 0; i < k; i++) {
      cs2.push(dsaFromNTT(dsaScaleNTT(s2h[i], ch)));
      var diff = dsaVecSub(w[i], cs2[i]);
      var rr = new Float64Array(256);
      for (var c = 0; c < 256; c++) rr[c] = dsaLowBits(diff[c], alpha);
      r0.push(rr);
      for (var c = 0; c < 256; c++) if (dsaNormBad(rr[c], P.gamma2 - P.beta)) { bad = true; break; }
      if (bad) break;
    }
    if (bad) continue;
    var ct0 = [];
    bad = false;
    for (var i = 0; i < k; i++) {
      ct0.push(dsaFromNTT(dsaScaleNTT(t0h[i], ch)));
      for (var c = 0; c < 256; c++) if (dsaNormBad(ct0[i][c], P.gamma2)) { bad = true; break; }
      if (bad) break;
    }
    if (bad) continue;
    var h = [], sum = 0;
    for (var i = 0; i < k; i++) {
      var neg = dsaVecNeg(ct0[i]);
      var target = dsaVecAdd(dsaVecSub(w[i], cs2[i]), ct0[i]);
      var hp = new Float64Array(256);
      for (var c = 0; c < 256; c++) { hp[c] = dsaMakeHint(neg[c], target[c], alpha); sum += hp[c]; }
      h.push(hp);
    }
    if (sum > P.omega) continue;
    var zBytes = [], zNB = P.gamma1 === (1 << 17) ? 18 : 20, zNBs = P.gamma1 === (1 << 17) ? 576 : 640;
    /* z 的系数经 dq 规约在 [0, q)，负数会用 q-5 这样的形式表示。
       直接写 gamma1 - x 会得到 -8249340 这种负数，BigInt 打包出来全是错值。
       参考实现用的是【模 q 减法】_sub_mod_q(gamma_1, c)，必须照做。 */
    for (var i = 0; i < l; i++) zBytes.push(dsaBitPack(z[i].map(function (x) { return dq(P.gamma1 - x); }), zNB, zNBs));
    var packed = [], offsets = [];
    for (var i = 0; i < k; i++) {
      for (var c = 0; c < 256; c++) if (h[i][c] === 1) packed.push(c);
      offsets.push(packed.length);
    }
    var padLen = P.omega - offsets[offsets.length - 1];
    for (var i = 0; i < padLen; i++) packed.push(0);
    var hBytes = new Uint8Array(P.omega + k);
    for (var i = 0; i < P.omega; i++) hBytes[i] = packed[i] === undefined ? 0 : packed[i];
    for (var i = 0; i < k; i++) hBytes[P.omega + i] = offsets[i];
    return mlkemCat([cTilde].concat(zBytes).concat([hBytes]));
  }
  throw new Error('ML-DSA 签名拒绝循环超出上限');
}
function mldsaVerify(level, pk, msg, sig) {
  var P = MLDSA_PARAMS[level], k = P.k, l = P.l;
  var wNB = P.gamma2 === 95232 ? 6 : 4, wNBs = P.gamma2 === 95232 ? 192 : 128;
  var zNB = P.gamma1 === (1 << 17) ? 18 : 20, zNBs = P.gamma1 === (1 << 17) ? 576 : 640;
  var expSig = P.ct + zNBs * l + P.omega + k;
  var expPk = 32 + 320 * k;
  if (pk.length !== expPk) return false;
  if (sig.length !== expSig) return false;
  var rho = pk.subarray(0, 32);
  var t1 = [];
  for (var i = 0; i < k; i++) t1.push(dsaBitUnpack(pk.subarray(32 + i * 320, 32 + (i + 1) * 320), 10));
  var cTilde = sig.subarray(0, P.ct);
  var hBytes = sig.subarray(sig.length - (P.omega + k), sig.length);
  var offsets = [0];
  for (var i = 0; i < k; i++) offsets.push(hBytes[P.omega + i]);
  for (var i = 0; i < k; i++) if (offsets[i] > offsets[i + 1]) return false;
  if (offsets[k] > P.omega) return false;
  for (var i = offsets[k]; i < P.omega; i++) if (hBytes[i] !== 0) return false;
  var h = [];
  for (var i = 0; i < k; i++) {
    var hp = new Float64Array(256);
    for (var j = offsets[i]; j < offsets[i + 1]; j++) hp[hBytes[j]] = 1;
    h.push(hp);
  }
  var sumH = 0;
  for (var i = 0; i < k; i++) for (var c = 0; c < 256; c++) sumH += h[i][c];
  if (sumH > P.omega) return false;
  var z = [];
  for (var i = 0; i < l; i++) {
    var seg = dsaBitUnpack(sig.subarray(P.ct + i * zNBs, P.ct + (i + 1) * zNBs), zNB);
    z.push(new Float64Array(seg.map(function (x) { return P.gamma1 - x; })));
    for (var c = 0; c < 256; c++) if (dsaNormBad(z[i][c], P.gamma1 - P.beta)) return false;
  }
  var A = dsaMat(rho, k, l);
  var tr = shake256Digest(pk, 64);
  var mu = shake256Digest(concatBytes(tr, mldsaMPrime(msg)), 64);
  var c = dsaSampleInBall(cTilde, P.tau);
  var ch = dsaToNTT(c.slice());
  var zh = z.map(function (p) { return dsaToNTT(p.slice()); });
  var t1h = t1.map(function (p) { return dsaToNTT(dsaScaleConst(p, 1 << P.d)); });
  var Az = dsaMatVecNTT(A, zh);
  var ct1 = [];
  for (var i = 0; i < k; i++) ct1.push(dsaScaleNTT(t1h[i], ch));
  var diff = [];
  for (var i = 0; i < k; i++) diff.push(dsaFromNTT(dsaVecSub(Az[i], ct1[i])));
  var wp = [];
  for (var i = 0; i < k; i++) {
    var r = new Float64Array(256);
    for (var c = 0; c < 256; c++) r[c] = dsaUseHint(h[i][c], diff[i][c], 2 * P.gamma2);
    wp.push(r);
  }
  var wpParts = wp.map(function (p) { return dsaBitPack(p, wNB, wNBs); });
  var check = shake256Digest(mlkemCat([mu].concat(wpParts)), P.ct);
  if (check.length !== cTilde.length) return false;
  for (var i = 0; i < check.length; i++) if (check[i] !== cTilde[i]) return false;
  return true;
}
