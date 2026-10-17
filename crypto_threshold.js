/* ============================================================
 * 门限密码：FROST（RFC 9591）+ GG20（ECDSA 门限签名）
 * ------------------------------------------------------------
 * 本文件由原 frost_core.js 与 gg20_core.js 合并而成 —— 两者同属
 * 「多方协作签名」这一族，分开反而不便对照。
 *
 * FROST   —— RFC 9591（已成正式标准）Ed25519 版本，官方 14 组向量全过。
 *            推荐用于新系统。
 * GG20    —— 2023 年披露的 Alpha-Rays 攻击针对的正是 GG18/GG20 实现，
 *            且本实现【只含算术核心】（Paillier + MtA），没有原论文的
 *            范围证明、MtA 正确性证明、一致性证明，挡不住恶意参与者。
 *            已挂 🔴 严重提示，建议改用 FROST。
 *
 * ⚠ 历史 bug：frost_core.js 里的 fqMul/fqAdd/fqInv 等（模 2^255-19）
 *   与 BLS12-381 基域的同名运算【重名冲突】，后者被覆盖后 BLS 配对直接崩，
 *   报「G2 点不在曲线上」。只有 FROST 与 BLS 同时加载才暴露。
 *   已全部加 edq 前缀。
 * ⚠ FROST 的群阶是 2^252 + 27742317777372353535851937790883648493，
 *   【不是】2^252 - 1（差约 2.8e37），现在按定义算而非写死。
 * ============================================================ */
/* ============================================================
 * FROST（RFC 9591）—— Ed25519 / SHA-512 套件，纯 JS 实现
 * 含 Ed25519 的 twisted Edwards 点运算（a = -1）
 * ============================================================ */
var FROST_CTX = 'FROST-ED25519-SHA512-v1';
var ED_P = (1n << 255n) - 19n;
/* 群阶 L = 2^252 + 27742317777372353535851937790883648493
   我第一版凭记忆写成 2^252 - 1（…570602495），与真实值差约 2.8e37，
   导致 scReduce 的模数错误、所有标量运算结果都不对。
   这个常量必须按定义计算，不能靠记忆。 */
var ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;
var ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;

function edqMod(a) { var r = a % ED_P; return r < 0n ? r + ED_P : r; }
function edqMul(a, b) { return edqMod(a * b); }
function edqAdd(a, b) { return edqMod(a + b); }
function edqSub(a, b) { return edqMod(a - b); }
function edqInv(a) {
  var e = ED_P - 2n, r = 1n, b = edqMod(a);
  while (e > 0n) { if (e & 1n) r = edqMul(r, b); b = edqMul(b, b); e >>= 1n; }
  return r;
}
function edqPow(a, e) {
  var r = 1n, b = edqMod(a);
  while (e > 0n) { if (e & 1n) r = edqMul(r, b); b = edqMul(b, b); e >>= 1n; }
  return r;
}
function edqSqrt(u) {
  var v = edqPow(u, (ED_P + 3n) / 8n);
  var vv = edqMul(v, v);
  if (vv === u) return v;
  if (vv === edqSub(0n, u)) return edqMul(v, edqPow(2n, (ED_P - 1n) / 4n));
  return null;
}
var ED_B = (function () {
  var y = edqMul(4n, edqInv(5n));
  var y2 = edqMul(y, y);
  var num = edqSub(y2, 1n);
  var den = edqAdd(edqMul(ED_D, y2), 1n);
  var x = edqSqrt(edqMul(num, edqInv(den)));
  /* 基点必须取 x 为【偶数】的那个平方根（标准 B 的 x 最低位为 0）。
     edqSqrt 可能返回负分支，导致序列化最后字节多出 0x80。 */
  if ((x & 1n) === 1n) x = edqSub(0n, x);
  return [x, y];
})();
function edAdd(P, Q) {
  if (P === null) return Q;
  if (Q === null) return P;
  var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1];
  var k = edqMul(ED_D, edqMul(x1, edqMul(x2, edqMul(y1, y2))));
  var x3 = edqMul(edqAdd(edqMul(x1, y2), edqMul(x2, y1)), edqInv(edqAdd(1n, k)));
  var y3 = edqMul(edqAdd(edqMul(y1, y2), edqMul(x1, x2)), edqInv(edqSub(1n, k)));
  return [x3, y3];
}
function edDouble(P) { return edAdd(P, P); }
function edNeg(P) { return P === null ? null : [edqSub(0n, P[0]), P[1]]; }
function edMul(P, k) {
  k = ((k % ED_L) + ED_L) % ED_L;
  var R = null, Q = P;
  while (k > 0n) {
    if (k & 1n) R = edAdd(R, Q);
    Q = edDouble(Q);
    k >>= 1n;
  }
  return R;
}

/* ============================================================
 * 快速标量乘 edMulFast —— 扩展坐标 (X:Y:Z:T)，全程无模逆
 * ------------------------------------------------------------
 * 动因：edAdd 每次做 2 次 edqInv（模幂，约 380 次 BigInt 模乘），
 *   一次标量乘要 ~190 次模逆，实测 35 ms；Ristretto255 编码再叠加
 *   invsqrt，界面上单次运算达 92 ms，而同结构的 Decaf448 仅 3 ms。
 *   实测确认：模逆次数就是瓶颈，不是算法结构问题。
 *
 * 做法：仿射 -> 扩展坐标 (x=X/Z, y=Y/Z, T=XY/Z)，加法/倍点只做乘法，
 *   最后转回仿射只做 1 次模逆。标量乘的模逆次数 190 -> 1。
 *
 * 公式（add-2008-hwcd / dbl-2008-hwcd，本曲线 a = -1）已与【上方
 *   被 FROST / RFC 9591 官方向量验证过的 edAdd / edMul】做等价对照：
 *   基点标量乘 60 组随机 + 40 组生成点 + 点加 40 组 + 倍点 20 组
 *   + k=0/1/L-1 边界，共 163/163 逐坐标一致。
 *
 * 注意：不改动 edAdd / edMul 本身 —— FROST 仍走已验证的旧路径。
 * ============================================================ */
function edToProj(P) {
  return P === null ? [0n, 1n, 1n, 0n] : [P[0], P[1], 1n, edqMul(P[0], P[1])];
}
function edProjAdd(P, Q) {
  if (P[2] === 0n) return Q;
  if (Q[2] === 0n) return P;
  var X1 = P[0], Y1 = P[1], Z1 = P[2], T1 = P[3];
  var X2 = Q[0], Y2 = Q[1], Z2 = Q[2], T2 = Q[3];
  var a = edqMul(X1, X2);
  var b = edqMul(Y1, Y2);
  var c = edqMul(ED_D, edqMul(T1, T2));
  var d = edqMul(Z1, Z2);
  var e = edqSub(edqMul(edqAdd(X1, Y1), edqAdd(X2, Y2)), edqAdd(a, b));
  var f = edqSub(d, c);
  var g = edqAdd(d, c);
  var h = edqAdd(b, a);             /* a = -1 时 H = B + A */
  return [edqMul(e, f), edqMul(g, h), edqMul(f, g), edqMul(e, h)];
}
function edProjDbl(P) {
  var X1 = P[0], Y1 = P[1], Z1 = P[2];
  var a = edqMul(X1, X1);
  var b = edqMul(Y1, Y1);
  var c = edqMul(2n, edqMul(Z1, Z1));
  var d = edqSub(0n, a);            /* a = -1 时 D = -A */
  var e = edqSub(edqMul(edqAdd(X1, Y1), edqAdd(X1, Y1)), edqAdd(a, b));
  var g = edqAdd(d, b);
  var f = edqSub(g, c);
  var h = edqSub(d, b);
  return [edqMul(e, f), edqMul(g, h), edqMul(f, g), edqMul(e, h)];
}
function edProjMul(P, k) {
  k = ((k % ED_L) + ED_L) % ED_L;
  var R = [0n, 1n, 1n, 0n], Q = edToProj(P);
  while (k > 0n) {
    if (k & 1n) R = edProjAdd(R, Q);
    Q = edProjDbl(Q);
    k >>= 1n;
  }
  return R;
}
/* 扩展坐标 -> 仿射（仅此一处模逆） */
function edProjToAff(R) {
  if (R[2] === 0n) return null;
  var zi = edqInv(R[2]);
  return [edqMul(R[0], zi), edqMul(R[1], zi)];
}
function edMulFast(P, k) { return edProjToAff(edProjMul(P, k)); }
/* 标量乘后再加一个点，全程扩展坐标 —— 用于 Ristretto 的「B·k + Q」 */
function edMulFastAdd(P, k, Q) {
  return edProjToAff(edProjAdd(edProjMul(P, k), edToProj(Q)));
}
/* 多标量乘 sum(si·Pi)：全程扩展坐标，末尾 1 次模逆。
   原实现每点一次 edMul（190 次模逆）+ 一次 edAdd（2 次模逆），
   1000 个点的 MSM 要 ~19 万次模逆 —— 这是 Bulletproofs 慢的根因。 */
function edMultiScalarMul(points, scalars) {
  var acc = [0n, 1n, 1n, 0n];
  for (var i = 0; i < scalars.length; i++) {
    if (scalars[i] === 0n) continue;
    var Pi = points[i];
    if (Pi === null) return null;
    acc = edProjAdd(acc, edProjMul(Pi, scalars[i]));
  }
  return edProjToAff(acc);
}

function edSerialize(P) {
  var y = P[1], x = P[0], o = new Uint8Array(32);
  for (var i = 0; i < 32; i++) { o[i] = Number(y & 0xffn); y >>= 8n; }
  if ((x & 1n) === 1n) o[31] |= 0x80;
  return o;
}
function edDeserialize(b) {
  if (b.length !== 32) return null;
  var y = 0n, c = Uint8Array.from(b);
  var sign = (c[31] >> 7) & 1;
  c[31] &= 0x7f;
  for (var i = 31; i >= 0; i--) y = (y << 8n) | BigInt(c[i]);
  if (y >= ED_P) return null;
  var y2 = edqMul(y, y);
  var num = edqSub(y2, 1n);
  var den = edqAdd(edqMul(ED_D, y2), 1n);
  var x = edqSqrt(edqMul(num, edqInv(den)));
  if (x === null) return null;
  if ((x & 1n) !== BigInt(sign)) x = edqSub(0n, x);
  return [x, y];
}
function scReduce(b) { var v = 0n; for (var i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v % ED_L; }
function scLe(v) { var o = new Uint8Array(32); v = ((v % ED_L) + ED_L) % ED_L; for (var i = 0; i < 32; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; }
function scInv(a) {
  var e = ED_L - 2n, r = 1n, b = ((a % ED_L) + ED_L) % ED_L;
  while (e > 0n) { if (e & 1n) r = (r * b) % ED_L; b = (b * b) % ED_L; e >>= 1n; }
  return r;
}
function frostCat(parts) {
  var n = 0, i;
  for (i = 0; i < parts.length; i++) n += parts[i].length;
  var o = new Uint8Array(n), p = 0;
  for (i = 0; i < parts.length; i++) { o.set(parts[i], p); p += parts[i].length; }
  return o;
}
function frostH1(m) { return scReduce(sha512Digest(frostCat([strToBytes(FROST_CTX + 'rho'), m]))); }
function frostH2(m) { return scReduce(sha512Digest(m)); }
function frostH3(m) { return scReduce(sha512Digest(frostCat([strToBytes(FROST_CTX + 'nonce'), m]))); }
function frostH4(m) { return sha512Digest(frostCat([strToBytes(FROST_CTX + 'msg'), m])); }
function frostH5(m) { return sha512Digest(frostCat([strToBytes(FROST_CTX + 'com'), m])); }
function frostNonceGen(secret, randBytes) { return frostH3(frostCat([randBytes, scLe(secret)])); }
function frostShamirSplit(secret, t, n) {
  var coeffs = [secret];
  for (var i = 1; i < t; i++) coeffs.push(scReduce(sha512Digest(crypto.getRandomValues(new Uint8Array(32)))));
  var shares = [];
  for (var x = 1; x <= n; x++) {
    var px = 0n, xb = BigInt(x);
    for (var j = coeffs.length - 1; j >= 0; j--) px = (px * xb + coeffs[j]) % ED_L;
    shares.push(px);
  }
  return { shares: shares, coeffs: coeffs };
}
function frostLagrange(id, ids) {
  var num = 1n, den = 1n, xi = BigInt(id);
  for (var i = 0; i < ids.length; i++) {
    var xj = BigInt(ids[i]);
    if (xj === xi) continue;
    num = (num * (xj % ED_L)) % ED_L;
    den = (den * fqModL(xj - xi)) % ED_L;
  }
  return (num * scInv(den)) % ED_L;
}
function fqModL(a) { var r = a % ED_L; return r < 0n ? r + ED_L : r; }
function frostEncodeCommList(list) {
  var parts = [];
  for (var i = 0; i < list.length; i++) parts.push(frostCat([scLe(BigInt(list[i].id)), list[i].D, list[i].E]));
  return frostCat(parts);
}
function frostBindingFactor(pkBytes, msg, commitmentList, id) {
  return frostH1(frostCat([pkBytes, frostH4(msg), frostH5(frostEncodeCommList(commitmentList)), scLe(BigInt(id))]));
}
function frostTrustedDealer(secret, t, n) {
  var sp = frostShamirSplit(secret, t, n), shares = {}, i;
  for (i = 0; i < n; i++) shares[i + 1] = sp.shares[i];
  return { shares: shares, groupPublicKey: edSerialize(edMulFast(ED_B, secret)), secret: secret, coeffs: sp.coeffs };
}
/* 第一轮：每个参与者生成 nonce 与承诺 */
function frostRoundOne(skShare, randH, randB) {
  var d = frostNonceGen(skShare, randH), e = frostNonceGen(skShare, randB);
  return { d: d, e: e, D: edSerialize(edMulFast(ED_B, d)), E: edSerialize(edMulFast(ED_B, e)) };
}
function frostRoundTwo(skShare, r1, rho, lambda, challenge) {
  var v = (r1.d + ((r1.e * rho) % ED_L) + ((lambda * skShare) % ED_L) * challenge) % ED_L;
  return ((v % ED_L) + ED_L) % ED_L;
}
function frostGroupCommitment(commitmentList, bindingFactors) {
  var acc = [0n, 1n, 1n, 0n];
  for (var i = 0; i < commitmentList.length; i++) {
    var id = commitmentList[i].id;
    var rho = null;
    for (var j = 0; j < bindingFactors.length; j++) if (bindingFactors[j][0] === id) rho = bindingFactors[j][1];
    if (rho === null) throw new Error('缺少参与者 ' + id + ' 的绑定因子');
    var D = edDeserialize(commitmentList[i].D), E = edDeserialize(commitmentList[i].E);
    if (!D || !E) throw new Error('承诺点无法反序列化');
    /* 全程扩展坐标累加：n 个参与者只做 1 次模逆（原为 2n+2n 次） */
    acc = edProjAdd(acc, edToProj(D));
    acc = edProjAdd(acc, edProjMul(E, rho));
  }
  return edProjToAff(acc);
}
function frostAggregate(R, sigShares) {
  var z = 0n;
  for (var i = 0; i < sigShares.length; i++) z = (z + sigShares[i]) % ED_L;
  return frostCat([edSerialize(R), scLe(z)]);
}
/* 标准 Ed25519 验证：8*z*B == 8*R + 8*c*pk */
function frostVerify(sig, msg, pkBytes) {
  if (sig.length !== 64) return false;
  var R = edDeserialize(sig.subarray(0, 32)), A = edDeserialize(pkBytes);
  if (!R || !A) return false;
  var z = scReduce(sig.subarray(32, 64));
  if (z >= ED_L) return false;
  var c = frostH2(frostCat([sig.subarray(0, 32), pkBytes, msg]));
  /* 原写法 edMul(edMul(A, c), 8n) 是【两次】标量乘 —— 标量可先合并为 c*8。
     两侧各一次 MSM，模逆从 ~570 次降到 2 次。 */
  var lhs = edMulFast(ED_B, (z * 8n) % ED_L);
  var rhs = edMultiScalarMul([R, A], [8n, (c * 8n) % ED_L]);
  return edEqual(lhs, rhs);
}
function edEqual(P, Q) {
  if (P === null || Q === null) return P === Q;
  return P[0] === Q[0] && P[1] === Q[1];
}
function frostSign(msg, skShares, participantIds, pkBytes, randMap) {
  var list = [], r1s = {}, i;
  for (i = 0; i < participantIds.length; i++) {
    var id = participantIds[i];
    var rand = randMap ? randMap[id] : [crypto.getRandomValues(new Uint8Array(32)), crypto.getRandomValues(new Uint8Array(32))];
    var r1 = frostRoundOne(skShares[id], rand[0], rand[1]);
    r1s[id] = r1;
    list.push({ id: id, D: r1.D, E: r1.E });
  }
  var bf = [];
  for (i = 0; i < participantIds.length; i++) bf.push([participantIds[i], frostBindingFactor(pkBytes, msg, list, participantIds[i])]);
  var R = frostGroupCommitment(list, bf);
  var c = frostH2(frostCat([edSerialize(R), pkBytes, msg]));
  var shares = [];
  for (i = 0; i < participantIds.length; i++) {
    var id2 = participantIds[i], rho = bf[i][1];
    var lam = frostLagrange(id2, participantIds);
    shares.push(frostRoundTwo(skShares[id2], r1s[id2], rho, lam, c));
  }
  return frostAggregate(R, shares);
}

/* ============================================================
 * GG20 阈值 ECDSA（Gennaro & Goldfeder 2020, ACM CCS）
 * t-of-n：任意 t 个参与者合作才能产生一个标准 ECDSA 签名，
 * 少于 t 个无法签名，且全程不重建完整私钥。
 *
 * ⚠️ 本实现只覆盖协议的【算术核心】（Paillier + MtA + 份额聚合），
 *    刻意省略了原论文中的零知识证明（范围证明 / MtA 证明 / 一致性证明）。
 *    缺少这些证明正是 Alpha-Rays（2023）攻击的切入点。
 *    详见页面「安全提示」。仅用于学习与协议演示，勿用于真实资产。
 * ============================================================ */
var GG20_CURVE = 'k1';

function gg20ModInv(a, m) {
  var g = m, x = 0n, x1 = 1n, r = ((a % m) + m) % m;
  if (r === 0n) return null;
  while (r > 1n) {
    var q = g / r, t = g - q * r;
    g = r; r = t;
    var t2 = x - q * x1;
    x = x1; x1 = t2;
  }
  return ((x1 % m) + m) % m;
}
function gg20Powm(b, e, m) {
  var r = 1n, a = ((b % m) + m) % m;
  e = e < 0n ? -e : e;
  while (e > 0n) { if (e & 1n) r = (r * a) % m; a = (a * a) % m; e >>= 1n; }
  return r;
}
function gg20RandBits(bits) {
  var nb = Math.ceil(bits / 8), b = crypto.getRandomValues(new Uint8Array(nb));
  var v = 0n;
  for (var i = 0; i < nb; i++) v = (v << 8n) | BigInt(b[i]);
  v |= (1n << BigInt(bits - 1));
  return v;
}
function gg20IsPrime(n, rounds) {
  if (n < 2n) return false;
  var small = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
  for (var i = 0; i < small.length; i++) {
    if (n === small[i]) return true;
    if (n % small[i] === 0n) return false;
  }
  var d = n - 1n, s = 0n;
  while ((d & 1n) === 0n) { d >>= 1n; s++; }
  for (var r = 0; r < (rounds || 24); r++) {
    var a = 2n + (gg20RandBits(Math.min(64, n.toString(2).length - 1)) % (n - 3n));
    var x = gg20Powm(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    var ok = false;
    for (var j = 1n; j < s; j++) {
      x = (x * x) % n;
      if (x === n - 1n) { ok = true; break; }
    }
    if (!ok) return false;
  }
  return true;
}
function gg20GenPrime(bits) {
  for (var t = 0; t < 2000; t++) {
    var c = gg20RandBits(bits) | 1n;
    if (gg20IsPrime(c, 20)) return c;
  }
  throw new Error('素数生成失败');
}
function gg20Gcd(a, b) { while (b) { var t = a % b; a = b; b = t; } return a; }

function gg20PaillierKey(bits) {
  bits = bits || 1024;
  var half = bits >> 1, p, q, guard = 0;
  do {
    p = gg20GenPrime(half);
    q = gg20GenPrime(half);
    guard++;
  } while (p === q || gg20Gcd(p * q, (p - 1n) * (q - 1n)) !== 1n && guard < 50);
  var n = p * q, n2 = n * n;
  var lam = ((p - 1n) * (q - 1n)) / gg20Gcd(p - 1n, q - 1n);
  return { p: p, q: q, n: n, n2: n2, lam: lam, mu: gg20ModInv(lam, n), bits: bits };
}
function gg20Enc(pk, m, r) {
  m = ((m % pk.n) + pk.n) % pk.n;
  if (typeof r === 'undefined') r = 2n + (gg20RandBits(pk.bits - 8) % (pk.n - 3n));
  var g = (1n + pk.n) % pk.n2;
  return (gg20Powm(g, m, pk.n2) * gg20Powm(r, pk.n, pk.n2)) % pk.n2;
}
function gg20Dec(pk, c) {
  var u = gg20Powm(c, pk.lam, pk.n2);
  var L = (u - 1n) / pk.n;
  return ((L * pk.mu) % pk.n + pk.n) % pk.n;
}
function gg20AddEnc(pk, c1, c2) { return (c1 * c2) % pk.n2; }
function gg20MulEnc(pk, c, k) { return gg20Powm(c, k, pk.n2); }

/* MtA：A 持 a，B 持 b，产出 α(归A) 与 β(归B)，满足 α + β ≡ a·b (mod q)。
   必须【用加法】构造补偿项：c = Enc(a)^b · Enc(β')。
   我第一版写成 Enc(-β')，在 Paillier 明文空间 mod N 下会得到
   α' = N + (a·b - β')，再 mod q 后与 β' 相加并不等于 a·b ——
   只要 a·b < β'（小数值测试时几乎必然）就会出错。
   改为加法形式后 α' = a·b + β' 精确无环绕（需 a·b + β' < N，
   即 Paillier 模数位数 > 2·log2(q) + 安全余量），β 取 -β' mod q，
   于是 α + β ≡ a·b + β' - β' ≡ a·b (mod q)。 */
function gg20MtA(pkA, a, pkB, b, q) {
  var cA = gg20Enc(pkA, a);
  var betaP = gg20RandBits(q.toString(2).length) % q;
  var c = gg20AddEnc(pkA, gg20MulEnc(pkA, cA, b), gg20Enc(pkA, betaP));
  var alpha = gg20Dec(pkA, c) % q;
  var beta = (q - betaP) % q;
  return { alpha: alpha, beta: beta };
}

function gg20ShamirSplit(secret, t, n, q) {
  var coeffs = [((secret % q) + q) % q], i;
  for (i = 1; i < t; i++) coeffs.push(gg20RandBits(q.toString(2).length) % q);
  var shares = [];
  for (var x = 1; x <= n; x++) {
    var px = 0n, xb = BigInt(x);
    for (var j = coeffs.length - 1; j >= 0; j--) px = (px * xb + coeffs[j]) % q;
    shares.push(px);
  }
  return { shares: shares, coeffs: coeffs };
}
function gg20Lagrange(id, ids, q) {
  var num = 1n, den = 1n, xi = BigInt(id);
  for (var i = 0; i < ids.length; i++) {
    var xj = BigInt(ids[i]);
    if (xj === xi) continue;
    num = (num * (xj % q)) % q;
    var d = ((xj - xi) % q + q) % q;
    den = (den * d) % q;
  }
  return (num * gg20ModInv(den, q)) % q;
}

function gg20Sign(msgHash, shares, ids, t, n, paillierBits) {
  var curve = CURVES[GG20_CURVE], q = curve.n, G = { x: curve.gx, y: curve.gy };
  var i, j;
  paillierBits = paillierBits || 1024;
  /* Paillier 明文空间必须容纳 a·b + β'（约 2·log2(q) 位），否则 mod N 环绕会使 MtA 结果错误 */
  if (paillierBits < 2 * q.toString(2).length + 128)
    throw new Error('Paillier 模数至少需 ' + (2 * q.toString(2).length + 128) + ' 位，当前 ' + paillierBits + ' 位');
  var pks = [];
  for (i = 0; i < ids.length; i++) pks.push(gg20PaillierKey(paillierBits || 1024));
  var w = [], x = [];
  for (i = 0; i < ids.length; i++) {
    x.push(shares[i]);
    w.push((gg20Lagrange(ids[i], ids, q) * shares[i]) % q);
  }
  var k = [], gamma = [];
  for (i = 0; i < ids.length; i++) {
    k.push(1n + (gg20RandBits(q.toString(2).length) % (q - 1n)));
    gamma.push(1n + (gg20RandBits(q.toString(2).length) % (q - 1n)));
  }
  var delta = [];
  for (i = 0; i < ids.length; i++) {
    var d = (k[i] * gamma[i]) % q;
    for (j = 0; j < ids.length; j++) {
      if (i === j) continue;
      var mt = gg20MtA(pks[i], k[i], pks[j], gamma[j], q);
      d = (d + mt.alpha) % q;         /* i 方持有 */
      delta[j] = ((delta[j] || 0n) + mt.beta) % q;
    }
    delta[i] = ((delta[i] || 0n) + d) % q;
  }
  var deltaAll = 0n;
  for (i = 0; i < delta.length; i++) deltaAll = (deltaAll + delta[i]) % q;
  var Gamma = null;
  for (i = 0; i < ids.length; i++) {
    var gi = curve.mul(gamma[i], G);
    Gamma = Gamma ? curve.add(Gamma, gi) : gi;
  }
  var deltaInv = gg20ModInv(deltaAll, q);
  var R = curve.mul(deltaInv, Gamma);
  var r = R.x % q;
  if (r === 0n) throw new Error('r 为零，请重试');
  var s = 0n, sigma = [];
  for (i = 0; i < ids.length; i++) sigma.push((k[i] * w[i]) % q);
  for (i = 0; i < ids.length; i++) {
    for (j = 0; j < ids.length; j++) {
      if (i === j) continue;
      var mt2 = gg20MtA(pks[i], k[i], pks[j], w[j], q);
      sigma[i] = (sigma[i] + mt2.alpha) % q;
      sigma[j] = (sigma[j] + mt2.beta) % q;
    }
  }
  for (i = 0; i < ids.length; i++) s = (s + msgHash * k[i] + r * sigma[i]) % q;
  if (s === 0n) throw new Error('s 为零，请重试');
  return { r: r, s: s, R: R };
}

/* ---- 标准 ECDSA 验证（GG20 形式：s*R == m*G + r*Q）---- */
function gg20Verify(msgHash, sig, pubPoint) {
  var curve = CURVES[GG20_CURVE], q = curve.n, G = { x: curve.gx, y: curve.gy };
  if (!sig || !sig.r || !sig.s) return false;
  if (sig.r <= 0n || sig.r >= q || sig.s <= 0n || sig.s >= q) return false;
  var sInv = gg20ModInv(sig.s, q);
  if (sInv === null) return false;
  /* 标准 ECDSA：u1 = m*s^-1, u2 = r*s^-1, 点 = u1*G + u2*Q，其 x == r */
  var P1 = curve.mul((msgHash * sInv) % q, G);
  var P2 = curve.mul((sig.r * sInv) % q, pubPoint);
  var Pt = curve.add(P1, P2);
  if (!Pt) return false;
  return (Pt.x % q) === (sig.r % q);
}
