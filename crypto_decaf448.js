/* ============================================================
 * Decaf448（RFC 9496 §5）—— Ed448-Goldilocks 的素数阶商群
 * ------------------------------------------------------------
 * 与 ristretto255 同源：点还是 edwards448 上的点，只是改用 Decaf 编码
 * 规则把 4 阶余因子商掉，得到素数阶群、编码唯一。
 * 群运算直接复用 crypto_curve448.js 里【已由 RFC 8032 官方向量与
 * cryptography 交叉验证过】的 ed448Add / ed448Mul。
 *
 * ⚠ 常量自证（不凭记忆，用关系式校验）：
 *     ONE_MINUS_D   = 39082  == 1 - d          （d = -39081）
 *     ONE_MINUS_TWO_D = 78163 == 1 - 2d
 *     SQRT_MINUS_D^2  == -d
 *     INVSQRT_MINUS_D^2 * (-d) == 1
 *   四项全部通过。
 *
 * ⚠ 与 ristretto255 的三处结构性差异（照抄 ristretto 会全错）：
 *   1) 编码长度 56 字节（ristretto 是 32）；
 *   2) SQRT_RATIO_M1 用指数 (p-3)/4 而非 (p-5)/8；
 *   3) ENCODE 用的是 (x0+t0)(x0-t0) 与 ONE_MINUS_D，
 *      而 ristretto 用的是 (z0+y0)(z0-y0) 与 INVSQRT_A_MINUS_D。
 * ============================================================ */
var DC_D = (ED448_P - 39081n) % ED448_P;
var DC_ONE_MINUS_D = 39082n;
var DC_ONE_MINUS_TWO_D = 78163n;
var DC_SQRT_MINUS_D = 98944233647732219769177004876929019128417576295529901074099889598043702116001257856802131563896515373927712232092845883226922417596214n;
var DC_INVSQRT_MINUS_D = 315019913931389607337177038330951043522456072897266928557328499619017160722351061360252776265186336876723201881398623946864393857820716n;

function dcMod(a) { var v = a % ED448_P; return v < 0n ? v + ED448_P : v; }
function dcIsNeg(x) { return (x & 1n) === 1n; }
function dcAbs(x) { return dcIsNeg(x) ? dcMod(-x) : x; }
/* decaf448 的 SQRT_RATIO_M1：r = u*(u*v)^((p-3)/4)；check = v*r^2 == u ? */
function dcSqrtRatioM1(u, v) {
  var e = (ED448_P - 3n) / 4n;
  var r = dcMod(u * ed448PowMod(dcMod(u * v), e));
  var check = dcMod(v * dcMod(r * r));
  return { wasSquare: check === dcMod(u), r: dcAbs(r) };
}
function dcFromAffine(P) { return [P[0], P[1], 1n, dcMod(P[0] * P[1])]; }
function dcToAffine(rep) { var zi = ed448Inv(rep[2]); return [dcMod(rep[0] * zi), dcMod(rep[1] * zi)]; }
/* ENCODE：内部表示 -> 56 字节 */
function dcEncode(rep) {
  var x0 = rep[0], y0 = rep[1], z0 = rep[2], t0 = rep[3];
  var u1 = dcMod(dcMod(x0 + t0) * dcMod(x0 - t0));
  var invsqrt = dcSqrtRatioM1(1n, dcMod(u1 * dcMod(DC_ONE_MINUS_D * dcMod(x0 * x0)))).r;
  var ratio = dcAbs(dcMod(dcMod(invsqrt * u1) * DC_SQRT_MINUS_D));
  var u2 = dcMod(dcMod(DC_INVSQRT_MINUS_D * ratio) * z0 - t0);
  var s = dcAbs(dcMod(DC_ONE_MINUS_D * dcMod(dcMod(invsqrt * x0) * u2)));
  var out = new Uint8Array(56), v = s;
  for (var i = 0; i < 56; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
/* DECODE：56 字节 -> 内部表示 */
function dcDecode(b) {
  if (b.length !== 56) throw new Error('Decaf448 点需 56 字节，当前 ' + b.length + ' 字节');
  var s = 0n;
  for (var i = 55; i >= 0; i--) s = (s << 8n) | BigInt(b[i]);
  if (s >= ED448_P) throw new Error('Decaf448 编码值 >= p');
  if (dcIsNeg(s)) throw new Error('Decaf448 编码值为负（最低位为 1）');
  var ss = dcMod(s * s);
  var u1 = dcMod(1n + ss);
  var u2 = dcMod(dcMod(u1 * u1) - dcMod(4n * dcMod(DC_D * ss)));
  var sr = dcSqrtRatioM1(1n, dcMod(u2 * dcMod(u1 * u1)));
  if (!sr.wasSquare) throw new Error('Decaf448 解码失败：非平方');
  var u3 = dcAbs(dcMod(dcMod(dcMod(2n * s) * sr.r) * dcMod(u1 * DC_SQRT_MINUS_D)));
  var x = dcMod(dcMod(u3 * sr.r) * dcMod(u2 * DC_INVSQRT_MINUS_D));
  var y = dcMod(dcMod(1n - ss) * dcMod(sr.r * u1));
  return [x, y, 1n, dcMod(x * y)];
}
function dcEncodeAffine(P) { return dcEncode(dcFromAffine(P)); }
/* one-way map：56 字节 -> 内部表示 */
function dcMap(inBytes) {
  var t = 0n;
  for (var i = 55; i >= 0; i--) t = (t << 8n) | BigInt(inBytes[i]);
  t = dcMod(t);
  var r = dcMod(-dcMod(t * t));
  var u0 = dcMod(DC_D * dcMod(r - 1n));
  var u1 = dcMod(dcMod(u0 + 1n) * dcMod(u0 - r));
  var sr = dcSqrtRatioM1(DC_ONE_MINUS_TWO_D, dcMod(dcMod(r + 1n) * u1));
  var v = sr.r, vPrime = sr.wasSquare ? v : dcMod(t * v);
  var sgn = sr.wasSquare ? 1n : -1n;
  var s = dcMod(vPrime * dcMod(r + 1n));
  var w0 = dcMod(2n * dcAbs(s));
  var w1 = dcMod(dcMod(s * s) + 1n);
  var w2 = dcMod(dcMod(s * s) - 1n);
  var w3 = dcMod(dcMod(dcMod(dcMod(vPrime * s) * dcMod(r - 1n)) * DC_ONE_MINUS_TWO_D) + sgn);
  return [dcMod(w0 * w3), dcMod(w2 * w1), dcMod(w1 * w3), dcMod(w0 * w2)];
}

/* ============================================================
 * 界面注册
 * ------------------------------------------------------------
 * ⚠ 基点：Decaf448 的规范生成元 = [2]·(Ed448 的基点)。
 *   实测确认：用 Ed448 基点直接算 k=1 得到 9022bbe9…，而 RFC 9496
 *   附录 B.1 的 B[1] 是 6666…66 3333…33 —— 恰好等于 [2k] 中的 k=1。
 *   即 Decaf448 生成元是 Ed448 基点的【两倍点】。若照抄 Ed448 基点，
 *   B[1..15] 会整体错位一格，且【不报错】，只有对表才发现。
 * ============================================================ */
var DC_G = ed448Mul(2n, [ED448_BX, ED448_BY, 1n, dcMod(ED448_BX * ED448_BY)]);
function dcScalar(k) {
  var t = String(k || '').trim().replace(/^0x/i, '');
  if (/^[0-9a-fA-F]+$/.test(t)) { var v = BigInt('0x' + t) % ED448_L; return v < 0n ? v + ED448_L : v; }
  var h = sha512Digest(strToBytes(String(k)));
  var v2 = 0n;
  for (var i = 55; i >= 0; i--) v2 = (v2 << 8n) | BigInt(h[i % h.length]);
  return ((v2 % ED448_L) + ED448_L) % ED448_L;
}
reg({ id: 'decaf448', name: 'Decaf448 群运算', group: '椭圆曲线与高级代数', key: true, param: true,
  keyLabel: '标量 k（Hex 或任意字符串派生）',
  paramLabel: '点加法：另一个 Decaf448 点的 112 位 Hex（留空则输出 G·k）', paramOptional: true,
  info: 'Decaf448（RFC 9496 §5）：Ed448-Goldilocks 的素数阶商群，56 字节编码、编码唯一，消除 4 阶余因子。已用 RFC 9496 附录 B.1 的 B[1..15] 全部 15 组验证，并验证解码往返与编码幂等。群运算复用已由 RFC 8032 官方向量与 cryptography 交叉验证过的 Ed448 加法。',
  enc: function (b, k, p, fmt) {
    var P = ed448Mul(dcScalar(k), DC_G);
    if (p && String(p).trim()) {
      var Q = dcToAffine(dcDecode(hexToBytes(String(p).trim())));
      P = ed448Add(P, [Q[0], Q[1], 1n, dcMod(Q[0] * Q[1])]);
    }
    return bytesOut(dcEncodeAffine(ed448Affine(P)), fmt);
  },
  dec: function (b, k, p, fmt) {
    var raw = (ArrayBuffer.isView(b)) ? new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength)) : bytesIn(b, fmt);
    if (raw.length !== 56) throw new Error('需 56 字节的 Decaf448 编码，当前 ' + raw.length + ' 字节');
    var rep = dcDecode(raw);
    if (bytesToHex(dcEncode(rep)) !== bytesToHex(raw)) throw new Error('该编码不是规范的 Decaf448 表示');
    var A = dcToAffine(rep);
    return '合法且规范的 Decaf448 点\\n  x = 0x' + A[0].toString(16) + '\\n  y = 0x' + A[1].toString(16);
  } });

reg({ id: 'decaf448-dh', name: 'Decaf448 密钥协商', group: '非对称加密', key: true, param: true,
  keyLabel: '己方标量 a（Hex 或任意字符串）', paramLabel: '对方 Decaf448 公钥（112 位 Hex）',
  info: 'Decaf448 上的 Diffie-Hellman：己方标量 a × 对方点 Q。群本身是素数阶，无需额外"清除余因子"步骤。加密与解密同一操作。',
  enc: function (b, k, p, fmt) {
    if (!p || !String(p).trim()) throw new Error('请在参数栏填入对方公钥（112 位 Hex）');
    var Q = dcToAffine(dcDecode(hexToBytes(String(p).trim())));
    return bytesOut(dcEncodeAffine(ed448Affine(ed448Mul(dcScalar(k), [Q[0], Q[1], 1n, dcMod(Q[0] * Q[1])]))), fmt);
  },
  dec: function (b, k, p, fmt) { return this.enc(b, k, p, fmt); } });
