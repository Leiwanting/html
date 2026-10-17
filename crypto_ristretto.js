/* ============================================================
 * Ristretto255（RFC 9496）—— Ed25519 曲线的素数阶商群
 * ------------------------------------------------------------
 * 为什么单独成文件：Ristretto255 的点就是 Ed25519 曲线上的点
 *   （-x^2 + y^2 = 1 + d x^2 y^2），只是改用 Ristretto 的编码规则
 *   对 4 阶/8 阶余因子做等价类归一化。所以【点运算直接复用
 *   crypto_threshold.js 里已由 FROST / RFC 9591 验证过的 edAdd / edMul】，
 *   本文件只实现：编码、解码、one-way map。
 *
 * ⚠ 常量自证（本项目的一贯做法，不凭记忆、不照抄单一来源）：
 *     SQRT_M1^2        == -1
 *     ONE_MINUS_D_SQ   == 1 - d^2
 *     D_MINUS_ONE_SQ   == (d - 1)^2
 *     INVSQRT_A_MINUS_D^2 * (a - d) == 1      （a = -1）
 *     SQRT_AD_MINUS_ONE^2 == a*d - 1
 *   最后一项【救了一次】：两次抓取 RFC 9496 得到的值不一致
 *     (2506306896095468...  vs  2506306895338462...)
 *   用 s^2 == a*d-1 判定，前者错、后者对。若照抄第一个值，
 *   one-way map 会全错且不报错。
 * ============================================================ */
var RIST_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
var RIST_SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
var RIST_INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578n;
var RIST_SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235n;
var RIST_ONE_MINUS_D_SQ = 1159843021668779879193775521855586647937357759715417654439879720876111806838n;
var RIST_D_MINUS_ONE_SQ = 40440834346308536858101042469323190826248399146238708352240133220865137265952n;

function ristIsNeg(x) { return (x & 1n) === 1n; }
function ristAbs(x) { return ristIsNeg(x) ? edqSub(0n, x) : x; }
/* SQRT_RATIO_M1：求 sqrt(u/v)；若 u/v 非平方则返回 sqrt(M1 * u/v) 并标记 was_square=FALSE */
function ristSqrtRatioM1(u, v) {
  var P58 = (1n << 252n) - 3n;            /* (p - 5) / 8 */
  var v3 = edqMul(edqMul(v, v), v);
  var v7 = edqMul(edqMul(v3, v3), v);
  var r = edqMul(edqMul(u, v3), edqPow(edqMul(u, v7), P58));
  var check = edqMul(v, edqMul(r, r));
  var correct = check === u;
  var flipped = check === edqSub(0n, u);
  var flippedI = check === edqMul(edqSub(0n, u), RIST_SQRT_M1);
  if (flipped || flippedI) r = edqMul(RIST_SQRT_M1, r);
  r = ristAbs(r);
  return { wasSquare: correct || flipped, r: r };
}
/* one-way map：32 字节 -> 内部表示 (x, y, z, t) */
function ristMap(inBytes) {
  var b = Uint8Array.from(inBytes);
  b[31] &= 0x7f;                           /* 掩码最高位 */
  var t = 0n;
  for (var i = 31; i >= 0; i--) t = (t << 8n) | BigInt(b[i]);
  t = edqMod(t);
  var r = edqMul(RIST_SQRT_M1, edqMul(t, t));
  var u = edqMul(edqAdd(r, 1n), RIST_ONE_MINUS_D_SQ);
  var v = edqMul(edqSub(edqSub(0n, 1n), edqMul(r, RIST_D)), edqAdd(r, RIST_D));
  var sr = ristSqrtRatioM1(u, v), s = sr.r;
  var sPrime = edqSub(0n, ristAbs(edqMul(s, t)));
  s = sr.wasSquare ? s : sPrime;
  var c = sr.wasSquare ? edqSub(0n, 1n) : r;
  var N = edqSub(edqMul(edqMul(c, edqSub(r, 1n)), RIST_D_MINUS_ONE_SQ), v);
  var w0 = edqMul(edqMul(2n, s), v);
  var w1 = edqMul(N, RIST_SQRT_AD_MINUS_ONE);
  var w2 = edqSub(1n, edqMul(s, s));
  var w3 = edqAdd(1n, edqMul(s, s));
  return [edqMul(w0, w3), edqMul(w2, w1), edqMul(w1, w3), edqMul(w0, w2)];
}
/* ============================================================
 * 64 字节 one-way map：from_uniform_bytes（RFC 9496 §4.3.4）
 * ------------------------------------------------------------
 * ⚠ 严重陷阱：它【不等于】对 64 字节直接调一次 ristMap。
 *   规范原文："1. Compute P1 as MAP(b[0:32]). 2. Compute P2 as MAP(b[32:64]).
 *             3. Return P1 + P2."
 *   即两次 32 字节 MAP 再相加。我此前直接把 64 字节丢给 ristMap，
 *   后者只读前 32 字节 —— 等于永远只算了 P1，P2 被静默丢弃。
 *   不报错、字节数也对，只有官方向量能暴露。
 *   由于 PedersenGens.B_blinding 与全部 G/H 生成器都走这条路，
 *   该错误会让整条 Bulletproofs 验证链全盘失败。
 * ============================================================ */
function ristFromUniformBytes(b) {
  if (b.length !== 64) throw new Error('from_uniform_bytes 需要 64 字节，当前 ' + b.length);
  var A = ristToAffine(ristMap(b.subarray(0, 32)));
  var B = ristToAffine(ristMap(b.subarray(32, 64)));
  return edAdd(A, B);
}
/* 仿射点 [x,y] -> 内部表示 (x, y, 1, xy) */
function ristFromAffine(P) {
  return [P[0], P[1], 1n, edqMul(P[0], P[1])];
}
/* 内部表示 -> 仿射点（只在需要时用于群运算） */
function ristToAffine(rep) {
  var zi = edqInv(rep[2]);
  return [edqMul(rep[0], zi), edqMul(rep[1], zi)];
}
/* 编码：内部表示 -> 32 字节 */
function ristEncode(rep) {
  var x0 = rep[0], y0 = rep[1], z0 = rep[2], t0 = rep[3];
  var u1 = edqMul(edqAdd(z0, y0), edqSub(z0, y0));
  var u2 = edqMul(x0, y0);
  var invsqrt = ristSqrtRatioM1(1n, edqMul(u1, edqMul(u2, u2))).r;
  var den1 = edqMul(invsqrt, u1);
  var den2 = edqMul(invsqrt, u2);
  var zInv = edqMul(edqMul(den1, den2), t0);
  var ix0 = edqMul(x0, RIST_SQRT_M1);
  var iy0 = edqMul(y0, RIST_SQRT_M1);
  var enchanted = edqMul(den1, RIST_INVSQRT_A_MINUS_D);
  var rotate = ristIsNeg(edqMul(t0, zInv));
  var x = rotate ? iy0 : x0;
  var y = rotate ? ix0 : y0;
  var z = z0;
  var denInv = rotate ? enchanted : den2;
  if (ristIsNeg(edqMul(x, zInv))) y = edqSub(0n, y);
  var s = ristAbs(edqMul(denInv, edqSub(z, y)));
  var out = new Uint8Array(32), v = s;
  for (var i = 0; i < 32; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
/* 解码：32 字节 -> 内部表示，失败返回 null */
function ristDecode(b) {
  if (b.length !== 32) throw new Error('Ristretto255 点需 32 字节');
  var s = 0n;
  for (var i = 31; i >= 0; i--) s = (s << 8n) | BigInt(b[i]);
  if (s >= ED_P) throw new Error('Ristretto255 编码值 >= p');
  if (ristIsNeg(s)) throw new Error('Ristretto255 编码值为负（最低位为 1）');
  var ss = edqMul(s, s);
  var u1 = edqSub(1n, ss);
  var u2 = edqAdd(1n, ss);
  var u2sqr = edqMul(u2, u2);
  var v = edqSub(edqSub(0n, edqMul(RIST_D, edqMul(u1, u1))), u2sqr);
  var sr = ristSqrtRatioM1(1n, edqMul(v, u2sqr));
  if (!sr.wasSquare) throw new Error('Ristretto255 解码失败：非平方');
  var denX = edqMul(sr.r, u2);
  var denY = edqMul(edqMul(sr.r, denX), v);
  var x = ristAbs(edqMul(edqMul(2n, s), denX));
  var yy = edqMul(u1, denY);
  var t = edqMul(x, yy);
  if (ristIsNeg(t)) throw new Error('Ristretto255 解码失败：t 为负');
  if (yy === 0n) throw new Error('Ristretto255 解码失败：y = 0');
  return [x, yy, 1n, t];
}
/* 编码仿射点（Ed25519 曲线点）的便捷入口 */
function ristEncodeAffine(P) { return ristEncode(ristFromAffine(P)); }
/* 标量乘：k 为 BigInt 或 32/64 字节 */
function ristScalarMulBase(scalarBytes) {
  var k = scReduce(Uint8Array.from(scalarBytes));
  return ristEncodeAffine(edMulFast(ED_B, k));
}

/* ============================================================
 * 界面注册：Ristretto255
 * ------------------------------------------------------------
 * Ristretto255 相对 Ed25519 的核心价值：它是【素数阶】群。
 * Ed25519 曲线阶 = 8·L，余因子 8 会导致小子群攻击与"同公钥多签名"问题；
 * Ristretto255 对余因子做等价类归一化，编码唯一、群阶就是 L。
 * ============================================================ */
function ristParseScalar(k) {
  var t = String(k || '').trim().replace(/^0x/i, '');
  if (/^[0-9a-fA-F]+$/.test(t)) {
    var v = BigInt('0x' + t) % ED_L;
    return v < 0n ? v + ED_L : v;
  }
  /* 非 Hex：按口令派生（与项目其它算法"密钥栏兼容任意字符串"的约定一致） */
  return scReduce(sha512Digest(strToBytes(String(k))));
}
function ristParsePoint(p) {
  var t = String(p || '').trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{64}$/.test(t)) throw new Error('Ristretto255 点需 64 位 Hex（32 字节）');
  return ristDecode(hexToBytes(t));
}
reg({ id: 'ristretto255', name: 'Ristretto255 群运算', group: '椭圆曲线与高级代数', key: true, param: true,
  keyLabel: '标量 k（Hex 或任意字符串派生）',
  paramLabel: '点加法：另一个点的 64 位 Hex（留空则输出 B·k）', paramOptional: true,
  info: 'Ristretto255（RFC 9496）：Ed25519 曲线的【素数阶商群】，消除 8 阶余因子，编码唯一。已用 RFC 9496 附录 A.2 的 B[1..15] 全部 15 组向量验证，并验证商群等价性（P 与 P+T 编码相同）、加法同态与 one-way map。群运算复用 FROST（RFC 9591）已验证的 Edwards 加法。',
  enc: function (b, k, p, fmt) {
    var s = ristParseScalar(k);
    var pStr = p && String(p).trim();
    if (pStr) {
      /* 标量乘 + 点加：全程扩展坐标，末尾只做 1 次模逆 */
      var Q = ristToAffine(ristParsePoint(p));
      return bytesOut(ristEncodeAffine(edMulFastAdd(ED_B, s, Q)), fmt);
    }
    return bytesOut(ristEncodeAffine(edMulFast(ED_B, s)), fmt);
  },
  dec: function (b, k, p, fmt) {
    /* 解密方向：把输入当作 Ristretto255 点做【合法性校验 + 规范化】 */
    /* 输入可能是密文字符串，也可能已解码成字节（测试/程序调用）——两种都支持 */
    var raw = (b instanceof Uint8Array || (typeof Uint8Array !== 'undefined' && ArrayBuffer.isView(b))) ? new Uint8Array(b.buffer || b) : bytesIn(b, fmt);
    if (raw.length !== 32) throw new Error('需 32 字节的 Ristretto255 编码，当前 ' + raw.length + ' 字节');
    var rep = ristDecode(raw);
    var canon = ristEncode(rep);
    if (bytesToHex(canon) !== bytesToHex(raw)) throw new Error('该编码不是规范的 Ristretto255 表示');
    var aff = ristToAffine(rep);
    return '合法且规范的 Ristretto255 点\n  x = 0x' + aff[0].toString(16) + '\n  y = 0x' + aff[1].toString(16);
  } });

reg({ id: 'ristretto255-dh', name: 'Ristretto255 密钥协商', group: '非对称加密', key: true, param: true,
  keyLabel: '己方标量 a（Hex 或任意字符串）',
  paramLabel: '对方 Ristretto255 公钥（64 位 Hex）',
  info: 'Ristretto255 上的 Diffie-Hellman：己方标量 a × 对方点 Q = 共享点。相比 X25519 无需"清除余因子"步骤，因为 Ristretto255 本身就是素数阶群。加密与解密同一操作。',
  enc: function (b, k, p, fmt) {
    var a = ristParseScalar(k);
    if (!p || !String(p).trim()) throw new Error('请在参数栏填入对方公钥（64 位 Hex）');
    var Q = ristToAffine(ristParsePoint(p));
    return bytesOut(ristEncodeAffine(edMulFast(Q, a)), fmt);
  },
  dec: function (b, k, p, fmt) {
    var a = ristParseScalar(k);
    if (!p || !String(p).trim()) throw new Error('请在参数栏填入对方公钥（64 位 Hex）');
    var Q = ristToAffine(ristParsePoint(p));
    return bytesOut(ristEncodeAffine(edMulFast(Q, a)), fmt);
  } });
