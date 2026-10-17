/* ============================================================
 * KZG 多项式承诺（Kate-Zaverucha-Goldberg）
 * ------------------------------------------------------------
 * 依赖：crypto_pairing_bn254.js 里【已与 py_ecc 逐系数比对 8/8】的
 *   bnG1Add / bnG1Mul / bnG2Add / bnG2Mul / bnPairing。
 *
 * 原理：
 *   可信设置 SRS：{[s^i]_1}_{i=0..n}  与  {[1]_2, [s]_2}      （s 为秘密，须丢弃）
 *   承诺   C  = Σ f_i · [s^i]_1  = [f(s)]_1
 *   开放   y  = f(x)
 *   证明   π  = [q(s)]_1，其中 q(X) = (f(X) - y) / (X - x)
 *   验证   e(C - [y]_1, [1]_2) == e(π, [s]_2 - [x]_2)
 *
 * ⚠ 两个易错点（本轮实测）：
 *   1) 商多项式用【综合除法】时必须【从高次向低次】降次：
 *        q[i-1] = tmp[i];  tmp[i-1] += q[i-1]·x
 *      方向反了不报错，但 q 全错，验证必然失败。
 *   2) 验证等式的右侧是 e(π, [s]_2 − [x]_2)，即【G2 侧做减法】；
 *      写成 e(π, [x]_2 − [s]_2) 会得到逆元，e 值不相等。
 *      两者只差一个逆，肉眼分不出来，只有比对才暴露。
 * ============================================================ */
var KZG_R = BN_R;

/* ---- 序列化：G1 64 字节（x||y），G2 128 字节（x.c0||x.c1||y.c0||y.c1）---- */
/* ⚠ 自包含：bigToBytes/bigFromBytes 定义在 crypto_core.js 的 IIFE 内部，
   跨文件取不到（typeof 为 undefined），故本文件自带一份。 */
function kzgB2B(bi, len) {
  var h = bi.toString(16);
  if (h.length % 2) h = '0' + h;
  while (h.length < len * 2) h = '00' + h;
  var o = new Uint8Array(len);
  for (var i = 0; i < len; i++) o[i] = parseInt(h.substr(i * 2, 2), 16);
  return o;
}
function kzgH2B(hex) {
  var c = String(hex).replace(/[^0-9a-fA-F]/g, '');
  if (c.length % 2) c = '0' + c;
  return c ? BigInt('0x' + c) : 0n;
}
function kzgG1ToBytes(P) {
  if (P === null) return new Uint8Array(64);
  return concatBytes(kzgB2B(P[0], 32), kzgB2B(P[1], 32));
}
function kzgG1FromBytes(b) {
  if (b.length !== 64) throw new Error('G1 点需 64 字节，当前 ' + b.length);
  if (bytesToHex(b) === '00'.repeat(64)) return null;
  return [kzgH2B(bytesToHex(b.subarray(0, 32))), kzgH2B(bytesToHex(b.subarray(32, 64)))];
}
function kzgG2ToBytes(P) {
  var o = new Uint8Array(128);
  if (P === null) return o;
  var parts = [P[0][0], P[0][1], P[1][0], P[1][1]];
  for (var i = 0; i < 4; i++) o.set(kzgB2B(parts[i], 32), i * 32);
  return o;
}
function kzgG2FromBytes(b) {
  if (b.length !== 128) throw new Error('G2 点需 128 字节，当前 ' + b.length);
  var w = [];
  for (var i = 0; i < 4; i++) w.push(kzgH2B(bytesToHex(b.subarray(i * 32, i * 32 + 32))));
  return [[w[0], w[1]], [w[2], w[3]]];
}
/* ---- 多项式 ---- */
function kzgEval(f, x) {
  var y = 0n, xp = 1n;
  for (var i = 0; i < f.length; i++) { y = (y + f[i] * xp) % KZG_R; xp = xp * x % KZG_R; }
  return y;
}
/* 综合除法求 q，使 (X - x)·q(X) == f(X) - y。返回 null 表示不能整除 */
function kzgQuotient(f, y, x) {
  var deg = f.length - 1;
  var tmp = f.slice();
  tmp[0] = (tmp[0] - y) % KZG_R;
  if (tmp[0] < 0n) tmp[0] += KZG_R;
  var q = new Array(deg);
  for (var i = deg; i >= 1; i--) {
    q[i - 1] = tmp[i];
    tmp[i - 1] = (tmp[i - 1] + q[i - 1] * x) % KZG_R;
  }
  return tmp[0] === 0n ? q : null;
}
/* ---- 可信设置（测试/演示用；真实场景必须由多方仪式产生且销毁 s）---- */
function kzgSetup(secretS, n) {
  var s = ((secretS % KZG_R) + KZG_R) % KZG_R;
  var g1 = [], pw = 1n;
  for (var i = 0; i <= n; i++) { g1.push(bnG1Mul(BN_G1, pw)); pw = pw * s % KZG_R; }
  return { g1: g1, g2_1: BN_G2, g2_s: bnG2Mul(BN_G2, s), n: n };
}
/* ---- 承诺 / 证明 / 验证 ---- */
function kzgCommit(srs, f) {
  var C = null;
  for (var i = 0; i < f.length; i++) C = bnG1Add(C, bnG1Mul(srs.g1[i], f[i] % KZG_R));
  return C;
}
function kzgProve(srs, f, x) {
  var y = kzgEval(f, x);
  var q = kzgQuotient(f, y, x);
  if (q === null) throw new Error('商多项式不整除（f(x) 与实际值不符）');
  var pi = null;
  for (var i = 0; i < q.length; i++) pi = bnG1Add(pi, bnG1Mul(srs.g1[i], q[i] % KZG_R));
  return { y: y, pi: pi };
}
function kzgVerify(srs, C, x, y, pi) {
  var lhs = bnPairing(srs.g2_1, bnG1Add(C, bnG1Neg(bnG1Mul(BN_G1, y % KZG_R))));
  var rhs = bnPairing(bnG2Add(srs.g2_s, bnG2Neg(bnG2Mul(srs.g2_1, x % KZG_R))), pi);
  return bn12eq(lhs, rhs);
}
function bnG1Neg(P) { return P === null ? null : [P[0], bnfq(-P[1])]; }
/* ⚠ 这里踩过坑：G2 点取负只应取负【y 坐标】，我一度写成两个坐标都取负
   [bn2neg(P[0]), bn2neg(P[1])]。结果仍是一个「合法」点（不报错），
   但等于把点映射到了无关位置，配对等式恒不成立。
   正确形式与 G1 一样：[P[0], -P[1]]。 */
function bnG2Neg(P) { return P === null ? null : [P[0], bn2neg(P[1])]; }

/* ============================================================
 * 界面注册
 * ------------------------------------------------------------
 * 界面上把「多项式」放在输入框（十进制或 0x 十六进制，逗号/空格分隔，
 * 低次在前），把可信设置的秘密 s 放在密钥栏（演示用），把求值点 x
 * 放在参数栏。
 *
 * ⚠ 安全提示：真实 KZG 的可信设置必须由多方仪式产生并销毁 s。
 *   本实现的 s 由用户直接给出，仅用于学习与协议验证，不可用于生产。
 * ============================================================ */
function kzgParsePoly(str) {
  var t = String(str || '').trim();
  if (!t) throw new Error('请填写多项式系数（低次在前，逗号或空格分隔）');
  var parts = t.split(/[\s,]+/).filter(function (s) { return s.length; });
  return parts.map(function (s) {
    var neg = false, v = s.trim();
    if (v[0] === '-') { neg = true; v = v.slice(1); }
    /* ⚠ 必须先校验再转换：BigInt('abc') 会抛 SyntaxError，
       错误信息是引擎给的，用户看不懂；先正则拦下才能给出明确提示。 */
    if (!/^\d+$/.test(v) && !/^0x[0-9a-fA-F]+$/i.test(v)) throw new Error('系数 "' + s + '" 不是整数');
    var n = BigInt(v);
    return neg ? (KZG_R - (n % KZG_R)) % KZG_R : n % KZG_R;
  });
}
function kzgParseScalar(t) {
  var s = String(t || '').trim();
  if (!s) throw new Error('请填写标量');
  var n = /^0x[0-9a-fA-F]+$/i.test(s) ? BigInt(s) : (/^\d+$/.test(s) ? BigInt(s) : null);
  if (n === null) throw new Error('标量需为十进制整数或 0x 开头的十六进制');
  return ((n % KZG_R) + KZG_R) % KZG_R;
}
reg({ id: 'kzg-commit', name: 'KZG 多项式承诺（BN254）', group: '椭圆曲线与高级代数',
  key: true, param: true, paramOptional: true,
  keyLabel: '可信设置秘密 s（演示用，仅测试）',
  paramLabel: '求值点 x（留空则用随机值）',
  info: 'BN254 上的 KZG 多项式承诺。\n【输入】系数（低次在前）；【密钥】s；【参数】求值点 x。\n⚠ 真实可信设置须多方仪式产生并销毁 s，此处仅供学习。',
  enc: function (b, k, p, fmt) {
    var f = kzgParsePoly(bytesToStr(b instanceof Uint8Array ? b : strToBytes(String(b))));
    var s = kzgParseScalar(k);
    var x = p && String(p).trim() ? kzgParseScalar(p)
      : ((kzgH2B(bytesToHex(crypto.getRandomValues(new Uint8Array(32)))) % KZG_R) + KZG_R) % KZG_R;
    var srs = kzgSetup(s, f.length - 1);
    var C = kzgCommit(srs, f);
    var pr = kzgProve(srs, f, x);
    if (!kzgVerify(srs, C, x, pr.y, pr.pi)) throw new Error('内部一致性检查失败：承诺未能通过验证');
    return bytesOut(concatBytes(
      kzgG1ToBytes(C),
      kzgB2B(pr.y, 32),
      kzgG1ToBytes(pr.pi)
    ), fmt);
  },
  dec: function (b, k, p, fmt) {
    /* 解密方向：给定 承诺‖y‖证明（160 字节）与 s、x，独立复算并给出验证结论 */
    /* 输入可能是字符串，也可能已解码成字节 —— 两种都支持 */
    var raw = ArrayBuffer.isView(b)
      ? new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength))
      : bytesIn(b, fmt);
    if (raw.length !== 160) throw new Error('需 160 字节（承诺 64 + y 32 + 证明 64），当前 ' + raw.length + ' 字节');
    var C = kzgG1FromBytes(raw.subarray(0, 64));
    var y = kzgH2B(bytesToHex(raw.subarray(64, 96)));
    var pi = kzgG1FromBytes(raw.subarray(96, 160));
    var s = kzgParseScalar(k);
    if (!p || !String(p).trim()) throw new Error('验算请在参数栏填求值点 x');
    var x = kzgParseScalar(p);
    var srs = kzgSetup(s, 0);
    var ok = kzgVerify(srs, C, x, y, pi);
    return 'KZG 验证结果：' + (ok ? '✓ 通过' : '✗ 失败（承诺、y 或证明不匹配）') +
      '\n  承诺 C = ' + bytesToHex(kzgG1ToBytes(C)) +
      '\n  求值点 x = 0x' + x.toString(16) +
      '\n  声明值 y = 0x' + y.toString(16) +
      '\n  证明   π = ' + bytesToHex(kzgG1ToBytes(pi));
  } });

reg({ id: 'kzg-pairing', name: 'BN254 配对', group: '椭圆曲线与高级代数',
  key: true, param: true,
  keyLabel: 'G2 点 Q（128 位 Hex）', paramLabel: 'G1 点 P（64 位 Hex）',
  info: 'BN254（alt_bn128）最优 ate 配对 e(P, Q)，输出 FQ12 元素 384 字节。已与 py_ecc 逐系数比对 8/8 并验证双线性 e(aG1,bG2)=e(G1,G2)^(ab)。以太坊 precompile 0x8 用的就是这条曲线。',
  enc: function (b, k, p, fmt) {
    var Q = kzgG2FromBytes(hexToBytes(String(k).trim()));
    var P = kzgG1FromBytes(hexToBytes(String(p).trim()));
    return bytesOut(bnF12ToBytes(bnPairing(Q, P)), fmt);
  },
  dec: function (b, k, p, fmt) { return this.enc(b, k, p, fmt); } });
