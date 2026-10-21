/* ============================================================
 * ML-KEM（FIPS 203，NIST 后量子密钥封装机制）
 * 参考实现：kyber_py（声明 FIPS 203 一致性），本实现逐字节对齐
 * ============================================================ */
var MLKEM_Q = 3329;
/* 关键：主工程的 concatBytes 只接受 2 个参数，多传的会被静默丢弃
   （本项目已在 Argon2 的 H0 处踩过一次同样的坑）。
   这里统一用可折叠的变参版本，避免密文/公钥末尾字段被静默截断。 */
function mlkemCat(parts) {
  var out = parts[0];
  for (var i = 1; i < parts.length; i++) out = concatBytes(out, parts[i]);
  return out;
}
function mlkemP(k) {
  if (k === 2) return { k: 2, eta1: 3, eta2: 2, du: 10, dv: 4 };
  if (k === 3) return { k: 3, eta1: 2, eta2: 2, du: 10, dv: 4 };
  if (k === 4) return { k: 4, eta1: 2, eta2: 2, du: 11, dv: 5 };
  throw new Error('ML-KEM 只支持 512 / 768 / 1024');
}
function sha3Hash(bits, input, outLen) {
  // rate = 200 - 2*容量字节 = 200 - bits/4
  //   224→144   256→136   384→104   512→72
  // 旧写法只区分 512/非512，384 会错用 136（=SHA3-256 的 rate），结果完全不是 SHA3-384
  var rate = 200 - bits / 4;
  var A = kecStateNew();
  keccakAbsorb(A, input, rate, 0x06);
  return keccakStateToBytes(A, rate / 8).subarray(0, outLen);
}
function sha3_256(b) { return sha3Hash(256, b, 32); }
function sha3_512(b) { return sha3Hash(512, b, 64); }
function sha3_512split(b) { var h = sha3_512(b); return [h.subarray(0, 32), h.subarray(32, 64)]; }

var MLKEM_ZETAS = (function () {
  var z = new Int32Array(128);
  for (var i = 0; i < 128; i++) {
    var br = 0, v = i;
    for (var b = 0; b < 7; b++) { br = (br << 1) | (v & 1); v >>= 1; }
    var p = 1;
    for (var e = 0; e < br; e++) p = (p * 17) % 3329;
    z[i] = p;
  }
  return z;
})();
function mlkemMod(v) { v %= 3329; return v < 0 ? v + 3329 : v; }
/* 注意：底层是 Int32Array（上限 2^31）。Python 用任意精度整数，7 层蝶形后
   系数可膨胀到 ~3329^7，不逐层取模会静默截断高位。
   加减乘对取模是同态的，逐层取模与最后统一取模等价。 */
function mlkemToNTT(c) {
  var k = 1, l = 128;
  while (l >= 2) {
    var start = 0;
    while (start < 256) {
      var zeta = MLKEM_ZETAS[k]; k++;
      var j = start;
      for (j = start; j < start + l; j++) {
        var t = mlkemMod(zeta * c[j + l]);
        var u = c[j];
        c[j + l] = mlkemMod(u - t);
        c[j] = mlkemMod(u + t);
      }
      /* Python 的 for 结束后 j = start+l-1（故原文写 start = j+l+1）；
         JS 的 for 结束后 j = start+l，照抄会每轮多跳 1 位。这里必须写成 j+l。 */
      start = j + l;
    }
    l = l >> 1;
  }
  for (var i = 0; i < 256; i++) c[i] = mlkemMod(c[i]);
  return c;
}
function mlkemFromNTT(c) {
  var l = 2, k = 127;
  while (l <= 128) {
    var start = 0;
    while (start < 256) {
      var zeta = MLKEM_ZETAS[k]; k--;
      var j = start;
      for (j = start; j < start + l; j++) {
        var t = c[j], u = c[j + l];
        c[j] = mlkemMod(t + u);
        c[j + l] = mlkemMod(zeta * mlkemMod(u - t));
      }
      start = j + l;      /* 同上：JS 循环变量退出值与 Python 差 1 */
    }
    l = l << 1;
  }
  for (var i = 0; i < 256; i++) c[i] = mlkemMod(c[i] * 3303);
  return c;
}
function mlkemBaseMul(a, b) {
  var r = new Int32Array(256);
  for (var i = 0; i < 128; i++) {
    var z = MLKEM_ZETAS[64 + (i >> 1)];
    if (i & 1) z = -z;
    var a0 = a[2 * i], a1 = a[2 * i + 1], b0 = b[2 * i], b1 = b[2 * i + 1];
    r[2 * i] = mlkemMod(a0 * b0 + z * a1 * b1);
    r[2 * i + 1] = mlkemMod(a1 * b0 + a0 * b1);
  }
  return r;
}
function mlkemByteEncode(coeffs, d) {
  var out = new Uint8Array(256 * d / 8);
  for (var i = 0; i < 256; i++) {
    var v = coeffs[i];
    for (var j = 0; j < d; j++) {
      var pos = i * d + j;
      out[pos >> 3] |= ((v >> j) & 1) << (pos & 7);
    }
  }
  return out;
}
function mlkemByteDecode(bytes, d) {
  var out = new Int32Array(256);
  for (var i = 0; i < 256; i++) {
    var v = 0;
    for (var j = 0; j < d; j++) {
      var pos = i * d + j;
      v |= ((bytes[pos >> 3] >> (pos & 7)) & 1) << j;
    }
    out[i] = v;
  }
  return out;
}
function mlkemCompress(x, d) { return mlkemMod(Math.round(Math.pow(2, d) * x / 3329)) % Math.pow(2, d); }
function mlkemDecompress(y, d) { return Math.round(3329 * y / Math.pow(2, d)); }
function mlkemCBD(prfBytes, eta) {
  var out = new Int32Array(256), bits = [];
  for (var i = 0; i < prfBytes.length; i++)
    for (var b = 0; b < 8; b++) bits.push((prfBytes[i] >> b) & 1);
  for (var i = 0; i < 256; i++) {
    var a = 0, c = 0;
    for (var j = 0; j < eta; j++) { a += bits[2 * i * eta + j]; c += bits[2 * i * eta + eta + j]; }
    /* 必须归一化到 [0, q)：参考实现里 -1 存成 3328。
       若保留负值，ByteEncode 时 JS 按补码取位，编码出的位模式就完全不同。 */
    out[i] = mlkemMod(a - c);
  }
  return out;
}
/* PRF(eta, sigma, N) = SHAKE256(sigma || N, 64*eta) */
function mlkemPRF(eta, sigma, N) {
  return shake256Digest(concatBytes(sigma, new Uint8Array([N])), 64 * eta);
}
function mlkemSampleNTT(rho, i, j) {
  /* XOF 必须取 840 字节（5 个 rate 块，rate=168），不能只取 504。
     拒绝采样每个候选的接受率仅 3329/4096 ≈ 81.3%，336 个候选的期望接受数
     约 273、标准差约 7.2，取不够 256 个的概率约 0.8%——一旦发生，剩余系数
     会静默留 0，表现为「偶发的单个向量失败」，极难定位。
     参考实现实测 _xof 输出即为 840 字节。 */
  var buf = shake128Digest(concatBytes(rho, new Uint8Array([j, i])), 840);
  var c = new Int32Array(256), m = 0, k = 0;
  while (m < 256 && k + 3 <= buf.length) {
    var d1 = buf[k] + 256 * (buf[k + 1] % 16);
    var d2 = Math.floor(buf[k + 1] / 16) + 16 * buf[k + 2];
    k += 3;
    if (d1 < 3329) c[m++] = d1;
    if (d2 < 3329 && m < 256) c[m++] = d2;
  }
  if (m < 256) throw new Error('XOF 拒绝采样未填满 256 个系数（不应发生）');
  return c;
}
function mlkemAdd(a, b) { var r = new Int32Array(256); for (var i = 0; i < 256; i++) r[i] = mlkemMod(a[i] + b[i]); return r; }
function mlkemMatTVec(A, v, k, transpose) {
  var out = [];
  for (var i = 0; i < k; i++) {
    var acc = new Int32Array(256);
    for (var j = 0; j < k; j++) {
      var Aij = transpose ? A[j][i] : A[i][j];
      var t = mlkemBaseMul(Aij, v[j]);
      acc = mlkemAdd(acc, t);
    }
    out.push(acc);
  }
  return out;
}
function mlkemPKEKeygen(k, d) {
  var P = mlkemP(k);
  var g = sha3_512split(concatBytes(d, new Uint8Array([k])));
  var rho = g[0], sigma = g[1];
  var A = [];
  for (var i = 0; i < k; i++) { A.push([]); for (var j = 0; j < k; j++) A[i].push(mlkemSampleNTT(rho, i, j)); }
  var s = [], e = [], N = 0;
  for (var i = 0; i < k; i++) s.push(mlkemCBD(mlkemPRF(P.eta1, sigma, N++), P.eta1));
  for (var i = 0; i < k; i++) e.push(mlkemCBD(mlkemPRF(P.eta1, sigma, N++), P.eta1));
  var sHat = s.map(function (p) { return mlkemToNTT(p.slice()); });
  var eHat = e.map(function (p) { return mlkemToNTT(p.slice()); });
  var tHat = mlkemMatTVec(A, sHat, k, false);
  for (var i = 0; i < k; i++) tHat[i] = mlkemAdd(tHat[i], eHat[i]);
  /* FIPS 203 算法 13：ek = ByteEncode_12(t̂) ‖ ρ，dk = ByteEncode_12(ŝ)。
     两者编码的都是【NTT 域】系数，不是标准域——我先前做了一次 from_ntt 又编了原始 s，
     结果 ek/dk 都跟参考实现对不上。 */
  var ekParts = [], dkParts = [];
  for (var i = 0; i < k; i++) ekParts.push(mlkemByteEncode(tHat[i], 12));
  for (var i = 0; i < k; i++) dkParts.push(mlkemByteEncode(sHat[i], 12));
  var ek = mlkemCat(ekParts.concat([rho]));
  var dkPKE = mlkemCat(dkParts);
  return { ek: ek, dkPKE: dkPKE };
}
function mlkemPKEEncrypt(k, ek, m, rnd) {
  var P = mlkemP(k);
  var tBytes = ek.subarray(0, 384 * k), rho = ek.subarray(384 * k, 384 * k + 32);
  var tHat = [];
  for (var i = 0; i < k; i++) tHat.push(mlkemByteDecode(tBytes.subarray(i * 384, (i + 1) * 384), 12));
  var A = [];
  for (var i = 0; i < k; i++) { A.push([]); for (var j = 0; j < k; j++) A[i].push(mlkemSampleNTT(rho, i, j)); }
  var r = [], e1 = [], N = 0;
  for (var i = 0; i < k; i++) r.push(mlkemCBD(mlkemPRF(P.eta1, rnd, N++), P.eta1));
  for (var i = 0; i < k; i++) e1.push(mlkemCBD(mlkemPRF(P.eta2, rnd, N++), P.eta2));
  var e2 = mlkemCBD(mlkemPRF(P.eta2, rnd, N++), P.eta2);
  var rHat = r.map(function (p) { return mlkemToNTT(p.slice()); });
  var uHat = mlkemMatTVec(A, rHat, k, true);          /* A^T · r */
  var u = [];
  for (var i = 0; i < k; i++) u.push(mlkemAdd(mlkemFromNTT(uHat[i]), e1[i]));
  var vHat = new Int32Array(256);
  for (var i = 0; i < k; i++) vHat = mlkemAdd(vHat, mlkemBaseMul(tHat[i], rHat[i]));
  var v = mlkemAdd(mlkemFromNTT(vHat), e2);
  var mu = mlkemByteDecode(m, 1);
  for (var i = 0; i < 256; i++) v[i] = mlkemMod(v[i] + mlkemDecompress(mu[i], 1));
  var cU = [], cV;
  for (var i = 0; i < k; i++) cU.push(mlkemByteEncode(u[i].map(function (x) { return mlkemCompress(x, P.du); }), P.du));
  cV = mlkemByteEncode(v.map(function (x) { return mlkemCompress(x, P.dv); }), P.dv);
  return mlkemCat(cU.concat([cV]));
}
function mlkemPKEDecrypt(k, dkPKE, c) {
  var P = mlkemP(k);
  var duBytes = 32 * P.du * k;
  var u = [], v;
  for (var i = 0; i < k; i++) {
    var seg = mlkemByteDecode(c.subarray(i * 32 * P.du, (i + 1) * 32 * P.du), P.du);
    u.push(Int32Array.from(Array.prototype.map.call(seg, function (x) { return mlkemDecompress(x, P.du); })));
  }
  var vSeg = mlkemByteDecode(c.subarray(duBytes, duBytes + 32 * P.dv), P.dv);
  v = Int32Array.from(Array.prototype.map.call(vSeg, function (x) { return mlkemDecompress(x, P.dv); }));
  var s = [];
  for (var i = 0; i < k; i++) s.push(mlkemByteDecode(dkPKE.subarray(i * 384, (i + 1) * 384), 12));
  var acc = new Int32Array(256);
  for (var i = 0; i < k; i++) acc = mlkemAdd(acc, mlkemBaseMul(s[i], mlkemToNTT(u[i].slice())));
  /* 关键：mlkemFromNTT 是【原地】修改。若写成 mlkemFromNTT(acc)[i] 放在循环里，
     逆变换会被重复施加 256 次，结果全成垃圾。必须先算一次再取用。 */
  var w = mlkemFromNTT(acc.slice());
  var m = new Int32Array(256);
  for (var i = 0; i < 256; i++) m[i] = mlkemCompress(mlkemMod(v[i] - w[i]), 1);
  return mlkemByteEncode(m, 1);
}
function mlkemKeygen(k) {
  var d = crypto.getRandomValues(new Uint8Array(32));
  var z = crypto.getRandomValues(new Uint8Array(32));
  var r = mlkemPKEKeygen(k, d);
  var h = sha3_256(r.ek);
  var dk = mlkemCat([r.dkPKE, r.ek, h, z]);
  return { ek: r.ek, dk: dk };
}
function mlkemEncaps(k, ek) {
  var m = crypto.getRandomValues(new Uint8Array(32));
  var g = sha3_512split(concatBytes(m, sha3_256(ek)));
  var Kbar = g[0], r = g[1];
  var c = mlkemPKEEncrypt(k, ek, m, r);
  return { c: c, K: Kbar };
}
function mlkemDecaps(k, dk, c) {
  var dkPKE = dk.subarray(0, 384 * k);
  var ek = dk.subarray(384 * k, 768 * k + 32);
  var h = dk.subarray(768 * k + 32, 768 * k + 64);
  var z = dk.subarray(768 * k + 64);
  var mp = mlkemPKEDecrypt(k, dkPKE, c);
  var g = sha3_512split(concatBytes(mp, h));
  var Kbar2 = g[0], r2 = g[1];
  var c2 = mlkemPKEEncrypt(k, ek, mp, r2);
  /* 常量时间比较：不能用 for+break，那会在首个不匹配字节处提前退出，
     通过计时泄漏「密文是否被篡改」，构成 FO 变换的选择密文攻击面。
     长度不同时先做异或置位，再逐字节累积差异，全程无分支。 */
  var diff = c2.length ^ c.length;
  var n = c.length < c2.length ? c.length : c2.length;
  for (var i = 0; i < n; i++) diff |= c2[i] ^ c[i];
  var same = (diff === 0);
  return same ? Kbar2 : shake256Digest(concatBytes(z, c), 32);
}
