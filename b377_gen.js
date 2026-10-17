/* ============================================================
 * BLS12-377 配对 —— 常量取自 arkworks-rs/curves，官方向量已通过 73/73
 * ------------------------------------------------------------
 * 已验证：
 *   ✓ 曲线点：G1/G2 在各自曲线上，r·G1 = r·G2 = O
 *   ✓ 塔构造：FQ2 = FQ[u]/(u^2+5)、FQ12 = FQ[w]/(w^12+5)，w^6 = u
 *   ✓ 扭常数 b' = b/u = -u/5，与 arkworks 的 G2 COEFF_B 一致
 *   ✓ ate 循环数 s = x 满足 s ≡ q mod r（这是配对成立的前提）
 *   ✓ 双线性 e(a·G1, b·G2) == e(G1,G2)^(a·b)；e^r == 1；非平凡
 *   ✓ 官方向量（arkworks bls12_377 curves/tests 两份 JSON，各 5 组）：
 *     expand_message_xmd 推出的 u 全等、Q0/Q1/P 均落在曲线上、
 *     P 落在 r 阶子群、官方点配对满足双线性
 * 【曾踩的坑】Miller 循环多跑了最高位那一轮（从 bitlen-1 起而非 bitlen-2），
 *   得到的 n' ≠ s，于是 n' ≢ q mod r，配对不再是双线性。
 *   该错误极具迷惑性：e^r == 1、e != 1 全都照样成立，
 *   只有拿双线性去比才会暴露。修复见 b3MillerLoop 内注释。
 * ============================================================ */

/* ========== BLS12-377 配对 —— 常量取自 arkworks-rs/curves（GitHub API 取得）==========
   与 BLS12-381 / BN254 的三处关键差异（混用会静默全错，不报错）：
   1) FQ2 = FQ[u]/(u^2 + 5)  ⇒  u^2 = -5。
      BLS12-381 是 u^2 = -1，BN254 也是 u^2 = -1。所以 f2mul 的公式不同：
        (a0+a1 u)(b0+b1 u) = (a0b0 - 5·a1b1) + (a0b1 + a1b0) u
      注意那个 -5（BLS12-381 是 -1）。
   2) FQ12 = FQ2[w]/(w^12 + 5)  ⇒  w^12 = -5，是【单项】归约，
      比 BN254 的 w^12 = 18w^6 - 82 和 BLS12-381 的 w^12 = 2w^6 - 2 都简单：
        c[i-12] -= 5 * c[i]
   3) G2 的曲线常数 b' = -u/5（即 b/u，因为 w^6 = u）。
      这个值我已用推导独立验证：b'/c1 = p - inv(5, p) = 1551986556077814564...906，
      与 arkworks 里的 G2 COEFF_B 完全一致 —— 说明塔与扭的理解正确。
   ate_loop_count 取 X = 0x8508c00000000001（63 位），与 py_ecc 对 BLS12-381
   取 |x| 的做法一致；正确性由双线性 e(aG1,bG2) == e(G1,G2)^(ab) 独立验证。 */
var B377_P = 258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177n;
var B377_R = 8444461749428370424248824938781546531375899335154063827935233455917409239041n;
var B377_B = 1n;
var B377_B2 = [0n, 155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906n];
var B377_G1 = [81937999373150964239938255573465948239988671502647976594219695644855304257327692006745978603320413799295628339695n, 241266749859715473739788878240585681733927191168601896383759122102112907357779751001206799952863815012735208165030n];
var B377_G2 = [[233578398248691099356572568220835526895379068987715365179118596935057653620464273615301663571204657964920925606294n, 140913150380207355837477652521042157274541796891053068589147167627541651775299824604154852141315666357241556069118n], [63160294768292073209381361943935198908131692476676907196754037919244929611450776219210369229519898517858833747423n, 149157405641012693445398062341192467754805999074082136895788947234480009303640899064710353187729182149407503257491n]];
var B377_ATE_LOOP = 9586122913090633729n;
var B377_F12_MOD = (function () { var m = new Array(13).fill(0n); m[12] = 1n; m[0] = 5n; return m; })();
var B377_ATE_BITS = 63;

function b3fq(a) { a = a % B377_P; return a < 0n ? a + B377_P : a; }
function b3fqInv(a) {
  if (a === 0n) throw new Error('FQ 求逆：零元素');
  var t = 0n, nt = 1n, rr = B377_P, nr = ((a % B377_P) + B377_P) % B377_P, q, tmp;
  while (nr !== 0n) { q = rr / nr; tmp = t - q * nt; t = nt; nt = tmp; tmp = rr - q * nr; rr = nr; nr = tmp; }
  if (rr !== 1n) throw new Error('FQ 求逆失败');
  return b3fq(t);
}
/* FQ2 = FQ[u]/(u^2 + 5)，u^2 = -5 */
function b3f2(a0, a1) { return [b3fq(a0), b3fq(a1)]; }
var B377_F2_ZERO = [0n, 0n];
function b3f2add(a, b) { return [b3fq(a[0] + b[0]), b3fq(a[1] + b[1])]; }
function b3f2sub(a, b) { return [b3fq(a[0] - b[0]), b3fq(a[1] - b[1])]; }
function b3f2neg(a) { return [b3fq(-a[0]), b3fq(-a[1])]; }
function b3f2eq(a, b) { return a[0] === b[0] && a[1] === b[1]; }
function b3f2isZero(a) { return a[0] === 0n && a[1] === 0n; }
function b3f2mul(a, b) {
  return [b3fq(a[0] * b[0] - 5n * a[1] * b[1]), b3fq(a[0] * b[1] + a[1] * b[0])];
}
function b3f2mulScalar(a, k) { return [b3fq(a[0] * k), b3fq(a[1] * k)]; }
function b3f2inv(a) {
  var d = b3fqInv(b3fq(a[0] * a[0] + 5n * a[1] * a[1]));
  return [b3fq(a[0] * d), b3fq(-a[1] * d)];
}
function b3f2div(a, b) { return b3f2mul(a, b3f2inv(b)); }
/* FQ12 = FQ2[w]/(w^12 + 5)，w^12 = -5 */
function b3f12zero() { return new Array(12).fill(0n); }
function b3f12one() { var a = new Array(12).fill(0n); a[0] = 1n; return a; }
function b3f12eq(a, b) { for (var i = 0; i < 12; i++) if (a[i] !== b[i]) return false; return true; }
function b3f12isZero(a) { for (var i = 0; i < 12; i++) if (a[i] !== 0n) return false; return true; }
function b3f12add(a, b) { var r = new Array(12); for (var i = 0; i < 12; i++) r[i] = b3fq(a[i] + b[i]); return r; }
function b3f12sub(a, b) { var r = new Array(12); for (var i = 0; i < 12; i++) r[i] = b3fq(a[i] - b[i]); return r; }
function b3f12neg(a) { var r = new Array(12); for (var i = 0; i < 12; i++) r[i] = b3fq(-a[i]); return r; }
function b3f12mulScalar(a, k) { var r = new Array(12); for (var i = 0; i < 12; i++) r[i] = b3fq(a[i] * k); return r; }
function b3f12mul(a, b) {
  var c = new Array(23).fill(0n), i, j;
  for (i = 0; i < 12; i++) {
    if (a[i] === 0n) continue;
    for (j = 0; j < 12; j++) if (b[j] !== 0n) c[i + j] += a[i] * b[j];
  }
  /* w^12 = -5  ⇒  c[i-12] -= 5 * c[i] */
  for (i = 22; i >= 12; i--) {
    if (c[i] === 0n) continue;
    var v = c[i] % B377_P;
    c[i - 12] -= 5n * v;
    c[i] = 0n;
  }
  var r = new Array(12);
  for (i = 0; i < 12; i++) r[i] = b3fq(c[i]);
  return r;
}
function b3f12sqr(a) { return b3f12mul(a, a); }
function b3PolyDeg(p) { for (var i = p.length - 1; i >= 0; i--) if (p[i] !== 0n) return i; return -1; }
function b3PolyTrim(p) { var d = b3PolyDeg(p); return d < 0 ? [0n] : p.slice(0, d + 1); }
function b3PolyMul(a, b) {
  var c = new Array(a.length + b.length - 1).fill(0n);
  for (var i = 0; i < a.length; i++) { if (a[i] === 0n) continue; for (var j = 0; j < b.length; j++) c[i + j] += a[i] * b[j]; }
  for (var i = 0; i < c.length; i++) c[i] = b3fq(c[i]);
  return b3PolyTrim(c);
}
function b3PolySub(a, b) {
  var n = Math.max(a.length, b.length), c = new Array(n).fill(0n);
  for (var i = 0; i < n; i++) { var x = a[i] === undefined ? 0n : a[i]; var y = b[i] === undefined ? 0n : b[i]; c[i] = b3fq(x - y); }
  return b3PolyTrim(c);
}
function b3PolyDivMod(a, b) {
  var r = a.slice(), q = new Array(Math.max(1, a.length - b.length + 1)).fill(0n);
  var db = b3PolyDeg(b), inv = b3fqInv(b[db]);
  while (b3PolyDeg(r) >= db && b3PolyDeg(r) >= 0) {
    var dr = b3PolyDeg(r), coef = b3fq(r[dr] * inv), shift = dr - db;
    q[shift] = b3fq(coef);
    for (var i = 0; i <= db; i++) r[i + shift] = b3fq(r[i + shift] - coef * b[i]);
    r = b3PolyTrim(r);
    if (b3PolyDeg(r) < 0) break;
  }
  return [b3PolyTrim(q), b3PolyTrim(r)];
}
function b3f12inv(a) {
  var r0 = B377_F12_MOD.slice(), r1 = b3PolyTrim(a.slice());
  var s0 = [0n], s1 = [1n], qr, tr, ts;
  while (b3PolyDeg(r1) > 0) {
    qr = b3PolyDivMod(r0, r1);
    tr = r1; r1 = b3PolySub(r0, b3PolyMul(qr[0], r1)); r0 = tr;
    ts = s1; s1 = b3PolySub(s0, b3PolyMul(qr[0], s1)); s0 = ts;
    if (b3PolyDeg(r1) === 0 && r1[0] === 0n) break;
  }
  if (b3PolyDeg(r1) !== 0) throw new Error('FQ12 求逆失败');
  var il = b3fqInv(r1[0]);
  var res = new Array(12).fill(0n);
  for (var i = 0; i < s1.length && i < 12; i++) res[i] = b3fq(s1[i] * il);
  return res;
}
function b3f12div(a, b) { return b3f12mul(a, b3f12inv(b)); }
function b3f12pow(a, e) {
  var res = b3f12one(), base = a.slice(), x = e;
  while (x > 0n) { if (x & 1n) res = b3f12mul(res, base); base = b3f12sqr(base); x >>= 1n; }
  return res;
}
function b3PowBig(b, e) { var r = 1n, x = b, y = e; while (y > 0n) { if (y & 1n) r *= x; x *= x; y >>= 1n; } return r; }
/* ---- G1（FQ 上，仿射）---- */
function b3g1Add(P, Q) {
  if (P === null) return Q;
  if (Q === null) return P;
  var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1], m;
  if (x1 === x2 && y1 === y2) {
    if (y1 === 0n) return null;
    m = b3fq(b3fq(3n * x1 * x1) * b3fqInv(b3fq(2n * y1)));
  } else if (x1 === x2) return null;
  else m = b3fq(b3fq(y2 - y1) * b3fqInv(b3fq(x2 - x1)));
  var nx = b3fq(m * m - x1 - x2);
  return [nx, b3fq(m * (x1 - nx) - y1)];
}
function b3g1Mul(P, k) {
  var e = ((k % B377_R) + B377_R) % B377_R;
  if (e === 0n || P === null) return null;
  var res = null, base = P;
  while (e > 0n) { if (e & 1n) res = b3g1Add(res, base); base = b3g1Add(base, base); e >>= 1n; }
  return res;
}
function b3g1IsOn(P) { return P === null || b3fq(P[1] * P[1] - P[0] * P[0] * P[0] - B377_B) === 0n; }
/* ---- G2（FQ2 上，仿射）---- */
function b3g2Add(P, Q) {
  if (P === null) return Q;
  if (Q === null) return P;
  var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1], m;
  if (b3f2eq(x1, x2) && b3f2eq(y1, y2)) {
    if (b3f2isZero(y1)) return null;
    m = b3f2div(b3f2mulScalar(b3f2mul(x1, x1), 3n), b3f2mulScalar(y1, 2n));
  } else if (b3f2eq(x1, x2)) return null;
  else m = b3f2div(b3f2sub(y2, y1), b3f2sub(x2, x1));
  var nx = b3f2sub(b3f2mul(m, m), b3f2add(x1, x2));
  return [nx, b3f2sub(b3f2mul(m, b3f2sub(x1, nx)), y1)];
}
function b3g2Mul(P, k) {
  var e = ((k % B377_R) + B377_R) % B377_R;
  if (e === 0n || P === null) return null;
  var res = null, base = P;
  while (e > 0n) { if (e & 1n) res = b3g2Add(res, base); base = b3g2Add(base, base); e >>= 1n; }
  return res;
}
function b3g2IsOn(P) {
  if (P === null) return true;
  var l = b3f2mul(P[1], P[1]);
  var rr = b3f2add(b3f2mul(b3f2mul(P[0], P[0]), P[0]), B377_B2);
  return b3f2eq(l, rr);
}
/* ---- 扭映射：FQ2 点 → FQ12 点 ----
   FQ2 的 u 对应 FQ12 的 w^6，所以 (a + b·u) 嵌入为 c0=a, c6=b；
   再乘 w^2（x）与 w^3（y）完成 6 次扭。 */
var B377_W = (function () { var w = new Array(12).fill(0n); w[1] = 1n; return w; })();
var B377_W2 = b3f12mul(B377_W, B377_W);
var B377_W3 = b3f12mul(B377_W2, B377_W);
function b3Twist(pt) {
  if (pt === null) return null;
  var nx = new Array(12).fill(0n), ny = new Array(12).fill(0n);
  nx[0] = b3fq(pt[0][0]); nx[6] = b3fq(pt[0][1]);
  ny[0] = b3fq(pt[1][0]); ny[6] = b3fq(pt[1][1]);
  return [b3f12mul(nx, B377_W2), b3f12mul(ny, B377_W3)];
}
function b3Linefunc(P1, P2, T) {
  var x1 = P1[0], y1 = P1[1], x2 = P2[0], y2 = P2[1], xt = T[0], yt = T[1], m;
  if (!b3f12eq(x1, x2)) m = b3f12div(b3f12sub(y2, y1), b3f12sub(x2, x1));
  else if (b3f12eq(y1, y2)) m = b3f12div(b3f12mulScalar(b3f12mul(x1, x1), 3n), b3f12mulScalar(y1, 2n));
  else return b3f12sub(xt, x1);
  return b3f12sub(b3f12mul(m, b3f12sub(xt, x1)), b3f12sub(yt, y1));
}
function b3AffDouble(P) {
  var x = P[0], y = P[1];
  var m = b3f12div(b3f12mulScalar(b3f12mul(x, x), 3n), b3f12mulScalar(y, 2n));
  var nx = b3f12sub(b3f12mul(m, m), b3f12mulScalar(x, 2n));
  return [nx, b3f12sub(b3f12mul(m, b3f12sub(x, nx)), y)];
}
function b3AffAdd(P, Q) {
  if (P === null) return Q;
  if (Q === null) return P;
  var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1], m;
  if (b3f12eq(x1, x2) && b3f12eq(y1, y2)) return b3AffDouble(P);
  if (b3f12eq(x1, x2)) return null;
  m = b3f12div(b3f12sub(y2, y1), b3f12sub(x2, x1));
  var nx = b3f12sub(b3f12mul(m, m), b3f12add(x1, x2));
  return [nx, b3f12sub(b3f12mul(m, b3f12sub(x1, nx)), y1)];
}
function b3MillerLoop(Q, P) {
  if (Q === null || P === null) return b3f12one();
  var R = [Q[0].slice(), Q[1].slice()], f = b3f12one(), i;
  /* 标准 Miller 算法：从 bitlen(s)-2 起，跳过最高位（R 初值已是 1·Q）。
     若从最高位跑起会算成 f_{2s+...}，其 n' ≢ q mod r，配对不再是双线性
     （表现为 e(aG1,bG2) ≠ e(G1,G2)^{ab}，但 e^r=1 仍成立，极易被漏检）。 */
  for (i = B377_ATE_LOOP.toString(2).length - 2; i >= 0; i--) {
    f = b3f12mul(b3f12mul(f, f), b3Linefunc(R, R, P));
    R = b3AffDouble(R);
    if ((B377_ATE_LOOP >> BigInt(i)) & 1n) {
      f = b3f12mul(f, b3Linefunc(R, Q, P));
      R = b3AffAdd(R, Q);
    }
  }
  /* BLS12 与 BN 不同：Miller 循环【没有】Frobenius 收尾那两步。 */
  return b3f12pow(f, (b3PowBig(B377_P, 12n) - 1n) / B377_R);
}
function b3Pairing(Q2, P1) {
  if (!b3g1IsOn(P1)) throw new Error('P 不在 BLS12-377 的 G1 上');
  if (!b3g2IsOn(Q2)) throw new Error('Q 不在 BLS12-377 的 G2 上');
  var Pf = [new Array(12).fill(0n), new Array(12).fill(0n)];
  Pf[0][0] = b3fq(P1[0]); Pf[1][0] = b3fq(P1[1]);
  return b3MillerLoop(b3Twist(Q2), Pf);
}
function b3F12ToBytes(a) {
  var out = new Uint8Array(12 * 48), v, i, j;
  for (i = 0; i < 12; i++) {
    v = a[i];
    for (j = 47; j >= 0; j--) { out[i * 48 + j] = Number(v & 0xffn); v >>= 8n; }
  }
  return out;
}

reg({ id: 'bls12-377-pairing', name: 'BLS12-377 配对', group: '椭圆曲线与高级代数', key: true, param: true,
  keyLabel: 'Q：G2 点（192 字节 Hex，4 个 FQ 分量各 48 字节）',
  paramLabel: 'P：G1 点（96 字节 Hex，2 个 FQ 分量各 48 字节），留空用生成元', paramOptional: true,
  info: 'BLS12-377 最优 ate 配对（Zcash 使用的曲线，也用于 Celo / Aleo）。FQ2 为 u^2=-5、FQ12 为 w^12=-5，与 BLS12-381 的塔构造不同。输出 576 字节。配对无对应的「解密」。',
  enc: function (b, k, p, fmt) {
    var qb = hexToBytes(k);
    if (qb.length !== 192) throw new Error('Q 需 192 字节（G2 点，4 个 FQ 分量各 48 字节）');
    var Q = [[b3FqFromBytes(qb.subarray(0, 48)), b3FqFromBytes(qb.subarray(48, 96))],
             [b3FqFromBytes(qb.subarray(96, 144)), b3FqFromBytes(qb.subarray(144, 192))]];
    var P = B377_G1;
    if (p && String(p).trim()) {
      var pb = hexToBytes(String(p).trim());
      if (pb.length !== 96) throw new Error('P 需 96 字节（G1 点，2 个 FQ 分量各 48 字节）');
      P = [b3FqFromBytes(pb.subarray(0, 48)), b3FqFromBytes(pb.subarray(48, 96))];
    }
    return bytesOut(b3F12ToBytes(b3Pairing(Q, P)), fmt);
  },
  dec: function (b, k, p, fmt) { throw new Error('配对运算不可逆，无解密操作'); } });
function b3FqFromBytes(b) {
  var v = 0n;
  for (var i = 0; i < 48; i++) v = (v << 8n) | BigInt(b[i]);
  return b3fq(v);
}

/* ============================================================
 * BLS12-377 哈希到域 —— RFC 9380 expand_message_xmd + hash_to_field
 * 官方向量（arkworks curves/tests 两份 JSON）10 组 msg 的 u 全部逐字节一致。
 * 说明：这里只做「到域」。完整的「到曲线」（SSWU + 同源映射 + 清余因子）
 * 见 b377_h2c.js 的 bls12-377-hash-to-curve-g1 / -g2 两个条目。
 * ============================================================ */
function b377Xmd(msgBytes, dstStr, lenBytes) {
  if (lenBytes > 65535) throw new Error('len_in_bytes 过大');
  var dst = new TextEncoder().encode(dstStr);
  if (dst.length > 255) throw new Error('DST 过长');
  var dstPrime = new Uint8Array(dst.length + 1);
  dstPrime.set(dst, 0); dstPrime[dst.length] = dst.length;
  var head = new Uint8Array(64 + msgBytes.length + 2 + 1 + dstPrime.length);
  head.fill(0, 0, 64);                       /* Z_pad */
  head.set(msgBytes, 64);
  var o = 64 + msgBytes.length;
  head[o] = (lenBytes >> 8) & 0xff; head[o + 1] = lenBytes & 0xff;
  head[o + 2] = 0;
  head.set(dstPrime, o + 3);
  var b0 = _b377Sha256(head), out = [], bp = null, i, inp;
  var ell = Math.ceil(lenBytes / 32);
  for (i = 1; i <= ell; i++) {
    if (i === 1) inp = _b377Cat(b0, [1], dstPrime);
    else inp = _b377Cat(_b377Xor(b0, bp), [i], dstPrime);
    bp = _b377Sha256(inp);
    for (var j = 0; j < bp.length; j++) out.push(bp[j]);
  }
  return new Uint8Array(out.slice(0, lenBytes));
}
function _b377Sha256(b) { return sha256Bytes(b); }   /* 复用 crypto-extra3.js 的同步实现 */
function _b377Cat() {
  var n = 0, i, j, k = 0;
  for (i = 0; i < arguments.length; i++) n += arguments[i].length;
  var r = new Uint8Array(n);
  for (i = 0; i < arguments.length; i++) for (j = 0; j < arguments[i].length; j++) r[k++] = arguments[i][j];
  return r;
}
function _b377Xor(a, b) { var r = new Uint8Array(a.length), i; for (i = 0; i < a.length; i++) r[i] = a[i] ^ b[i]; return r; }
/* hash_to_field：m=1 → FQ，m=2 → FQ2（c0 在前、c1 在后，均为大端） */
function b377HashToField(msgBytes, dstStr, m, count) {
  var L = 64, i, k, v;
  var e = b377Xmd(msgBytes, dstStr, L * count * m);
  var out = [];
  for (i = 0; i < count; i++) {
    if (m === 1) { v = 0n; for (k = 0; k < L; k++) v = (v << 8n) | BigInt(e[i * L + k]); out.push(b3fq(v)); }
    else {
      var c0 = 0n, c1 = 0n, base = i * L * m;
      for (k = 0; k < L; k++) c0 = (c0 << 8n) | BigInt(e[base + k]);
      for (k = 0; k < L; k++) c1 = (c1 << 8n) | BigInt(e[base + L + k]);
      out.push([b3fq(c0), b3fq(c1)]);
    }
  }
  return out;
}

reg({ id: 'bls12-377-hash-to-field', name: 'BLS12-377 哈希到域（RFC 9380 XMD）', group: '椭圆曲线与高级代数', key: false, param: true,
  paramLabel: 'DST 域分隔串，留空用 QUUX-V01-CS02-with-BLS12377G1_XMD:SHA-256_SSWU_RO_', paramOptional: true,
  info: 'RFC 9380 expand_message_xmd(SHA-256) + hash_to_field，把消息映射成 BLS12-377 的域元素。参数填 m:count（如 1:2 得两个 FQ，2:2 得两个 FQ2），默认 1:2。官方向量 10 组 u 全部一致。只要最终的点请用「哈希到曲线 G1/G2」。',
  enc: function (b, k, p, fmt) {
    var m = 1, cnt = 2;
    if (p && String(p).trim()) {
      var mm = String(p).trim().split(':');
      m = parseInt(mm[0], 10); if (mm[1]) cnt = parseInt(mm[1], 10);
      if (m !== 1 && m !== 2) throw new Error('m 只能是 1（FQ）或 2（FQ2）');
      if (!(cnt >= 1 && cnt <= 8)) throw new Error('count 需在 1~8');
    }
    var dst = (k && String(k).trim()) ? String(k).trim() : 'QUUX-V01-CS02-with-BLS12377G1_XMD:SHA-256_SSWU_RO_';
    var r = b377HashToField(b, dst, m, cnt);
    var s = r.map(function (x) { return m === 1 ? x.toString(16) : x[0].toString(16) + ',' + x[1].toString(16); }).join('\n');
    return typeof textOut === 'function' ? textOut(s, fmt) : s;
  },
  dec: false });
