/* ============================================================
 * SPAKE2+ —— 增强型口令认证密钥交换（RFC 9383，P-256）
 * ------------------------------------------------------------
 * ⚠ 规范编号纠正：SPAKE2+ 是 RFC 9383，RFC 9382 是【SPAKE2】（非增强）。
 *   我最初凭记忆写成 9382，抓规范时才发现错了一整个 RFC。
 *
 * 增强（Augmented）的含义：服务器只存 (w0, L=w1·P)，【不存明文口令】，
 *   口令泄露不会让攻击者冒充客户端。这是它与 SPAKE2 的本质差别。
 *
 * 协议流程（Prover=客户端持 w0,w1；Verifier=服务器持 w0,L）：
 *   X = x·P + w0·M        （Prover → Verifier）
 *   Y = y·P + w0·N        （Verifier → Prover）
 *   Prover : Z = x·(Y − w0·N),  V = w1·(Y − w0·N)
 *   Verifier: Z = y·(X − w0·M),  V = y·L
 *   （两侧得到同一个 Z = x·y·P，同一个 V = w1·y·P = y·L）
 *
 * 密钥派生：
 *   K_main = SHA-256(TT)
 *   K_confirmP || K_confirmV = HKDF(nil, K_main, "ConfirmationKeys")  64 字节
 *   K_shared                 = HKDF(nil, K_main, "SharedKey")         32 字节
 *   confirmP = HMAC(K_confirmP, Y)      confirmV = HMAC(K_confirmV, X)
 * ============================================================ */
'use strict';

/* P-256 的 M / N 常量（未压缩，65 字节）
 * ------------------------------------------------------------
 * RFC 9383 正文只给了【压缩】形式：M=02886e…、N=03d8bb…
 * 本文件需要的未压缩点由 x 坐标解方程 y² = x³ −3x + b 得到：
 *   取模平方根后用 02/03 前缀（y 的奇偶）选定正确分支。
 * 自证：两点都在曲线上，且算出的 y 奇偶与 RFC 给的 02/03 前缀一致。 */
var SPAKE_M_HEX =
  '04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f' +
  '5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20';
var SPAKE_N_HEX =
  '04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49' +
  '07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7';

var SPAKE_P256 = (typeof CURVES !== 'undefined' && CURVES.p256) ? CURVES.p256 : null;

function spakeCurve() {
  if (!SPAKE_P256) throw new Error('P-256 曲线不可用（CURVES.p256 未定义）');
  return SPAKE_P256;
}
function spakeM() { return spakeCurve().bytesToPoint(hexToBytes(SPAKE_M_HEX)); }
function spakeN() { return spakeCurve().bytesToPoint(hexToBytes(SPAKE_N_HEX)); }

/* 8 字节【小端】长度前缀 —— RFC 9383 的 len() 定义
 * ⚠ 陷阱：写成大端会让 TT 全错，而 confirm 值对不上时极难定位。 */
function spakeLen(bytes) {
  var n = bytes.length, out = new Uint8Array(8), i;
  for (i = 0; i < 8; i++) {
    var d = Math.pow(2, 8 * i);
    out[i] = Math.floor(n / d) % 256;
  }
  return out;
}
function spakeEncode(bytes) { return concatBytes(spakeLen(bytes), bytes); }
function spakeEncodeBig(v, byteLen) { return spakeEncode(bigToBytes(v, byteLen)); }

/* 未压缩点编码（固定 65 字节，含 0x04 前缀） */
function spakePointBytes(P) { return spakeCurve().pointToBytes(P, false); }

/* ---- 两侧各自的第一轮消息 ---- */
function spakeProverShare(w0, x) {
  var C = spakeCurve();
  var P = { x: C.gx, y: C.gy };
  return C.add(C.mul(x, P), C.mul(w0, spakeM()));
}
function spakeVerifierShare(w0, y) {
  var C = spakeCurve();
  var P = { x: C.gx, y: C.gy };
  return C.add(C.mul(y, P), C.mul(w0, spakeN()));
}

/* ---- 共享值 ---- */
/* Prover 侧：已知 w0, w1, x，收到 Y */
function spakeProverShared(w0, w1, x, Y) {
  var C = spakeCurve();
  var t = C.add(Y, C.neg(C.mul(w0, spakeN())));   /* Y − w0·N */
  return { Z: C.mul(x, t), V: C.mul(w1, t) };
}
/* Verifier 侧：已知 w0, L, y，收到 X */
function spakeVerifierShared(w0, L, y, X) {
  var C = spakeCurve();
  var t = C.add(X, C.neg(C.mul(w0, spakeM())));   /* X − w0·M */
  return { Z: C.mul(y, t), V: C.mul(y, L) };
}

/* ---- 密钥派生 ---- */
function spakeDerive(ctx, idProver, idVerifier, X, Y, Z, V, w0) {
  var C = spakeCurve();
  var TT = concatBytes(
    spakeEncode(strToBytes(ctx || '')),
    spakeEncode(strToBytes(idProver || '')),
    spakeEncode(strToBytes(idVerifier || '')),
    spakeEncode(hexToBytes(SPAKE_M_HEX)),
    spakeEncode(hexToBytes(SPAKE_N_HEX)),
    spakeEncode(spakePointBytes(X)),
    spakeEncode(spakePointBytes(Y)),
    spakeEncode(spakePointBytes(Z)),
    spakeEncode(spakePointBytes(V)),
    spakeEncodeBig(w0, C.byteLen)
  );
  var Kmain = sha256Bytes(TT);
  var ck = hkdfSha256(Kmain, null, strToBytes('ConfirmationKeys'), 64);
  var KconfirmP = ck.subarray(0, 32), KconfirmV = ck.subarray(32, 64);
  var Kshared = hkdfSha256(Kmain, null, strToBytes('SharedKey'), 32);
  return {
    TT: TT, Kmain: Kmain,
    KconfirmP: KconfirmP, KconfirmV: KconfirmV, Kshared: Kshared,
    confirmP: hmacSha256(KconfirmP, spakePointBytes(Y)),
    confirmV: hmacSha256(KconfirmV, spakePointBytes(X))
  };
}

/* ============================================================
 * 界面注册
 * ------------------------------------------------------------
 * 三个条目对应 SPAKE2+ 的完整生命周期：注册 → Prover → Verifier。
 * ⚠ RFC 9383 【未规定】 PBKDF 的选择（原文："The choice of PBKDF is
 *   omitted"），注册条目里的 PBKDF2-SHA256 仅作演示，实际部署应按
 *   应用自身的规范选取（如 Argon2id / scrypt / 带 Pepper 的 HKDF）。
 * ============================================================ */
function spakeRandScalar() {
  var C = spakeCurve(), b = new Uint8Array(C.byteLen + 8), i, v;
  crypto.getRandomValues(b);
  v = 0n;
  for (i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
  return (v % (C.n - 1n)) + 1n;
}
/* bigToHex 是 crypto_core.js IIFE 内的局部函数，跨文件取不到
   （本项目已多次踩此坑：bigFromBytes / bigToHex / SM2_CURVE 均为局部）。
   这里用全局可用的 bigToBytes 自行实现。 */
function spakeScalarHex(v) { return bytesToHex(bigToBytes(v, spakeCurve().byteLen)); }
function spakeFromBytes(b) {
  var v = 0n, i;
  for (i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
  return v;
}

/* 参数栏格式：对方share [; context [; idProver [; idVerifier]]]
 * ⚠ context 与双方身份必须参与 TT，否则存在跨协议重用与反射攻击。
 *   官方向量之所以带 Context/idProver/idVerifier，正是为此。
 *   留空则按空字符串处理（仅演示用）。 */
function spakeParseParam(p) {
  var seg = String(p == null ? '' : p).split(';');
  return {
    share: (seg[0] || '').trim(),
    ctx:   (seg[1] || '').trim(),
    idP:   (seg[2] || '').trim(),
    idV:   (seg[3] || '').trim()
  };
}

/* 逗号/空白分隔的 Hex 列表 */
function spakeSplitHex(s, n, what) {
  var parts = String(s).split(/[,\s;]+/).filter(function (x) { return x.length; });
  if (parts.length < n) throw new Error(what + '：需要 ' + n + ' 个 Hex 值，当前 ' + parts.length);
  return parts.map(function (h) {
    h = h.replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]+$/.test(h)) throw new Error(what + '：不是合法 Hex -> ' + h.slice(0, 16));
    return bigFromHex(h);
  });
}
function spakePointFromHex(h, what) {
  h = String(h).trim().replace(/^0x/i, '').replace(/\s+/g, '');
  var b;
  try { b = hexToBytes(h); } catch (e) { throw new Error(what + '：不是合法 Hex'); }
  try { return spakeCurve().bytesToPoint(b); }
  catch (e) { throw new Error(what + '：不是合法的 P-256 未压缩点（应以 04 开头，65 字节）'); }
}

if (typeof reg === 'function') {
  /* 1. 注册：口令 → (w0, w1, L)。服务器只存 w0 与 L，不存口令。 */
  reg({
    id: 'spake2p-register', name: 'SPAKE2+ 注册（口令 → w0/w1/L）', group: '非对称加密',
    key: true, param: true, paramOptional: true,
    keyLabel: '口令（任意字符串）', paramLabel: '盐 Salt（Hex，留空用默认值）',
    info: '把口令转为 SPAKE2+ 注册记录：输出 w0/L（给服务器）与 w1（给客户端）。服务器不存明文口令。',
    enc: function (b, k, p, fmt) {
      var pw = (b instanceof Uint8Array || ArrayBuffer.isView(b)) ? new Uint8Array(b) : strToBytes(String(b));
      if (!pw.length) throw new Error('请输入口令');
      var salt = (p && String(p).trim())
        ? hexToBytes(String(p).trim().replace(/^0x/i, ''))
        : strToBytes('SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256');
      var C = spakeCurve();
      var dk = pbkdf2Sha256(pw, salt, 10000, 64);
      var w0 = spakeFromBytes(dk.subarray(0, 32)) % C.n;
      var w1 = (spakeFromBytes(dk.subarray(32, 64)) % (C.n - 1n)) + 1n;  /* w1 ≠ 0，否则 L 是无穷远点 */
      var L = C.mul(w1, { x: C.gx, y: C.gy });
      return [
        '【交给服务器】w0 = ' + spakeScalarHex(w0),
        '【交给服务器】L  = ' + bytesToHex(spakePointBytes(L)),
        '【交给客户端】w1 = ' + spakeScalarHex(w1)
      ].join('\n');
    },
    dec: function (b, k, p, fmt) { return this.enc(b, k, p, fmt); }
  });

  /* 2. Prover（客户端） */
  reg({
    id: 'spake2p-prover', name: 'SPAKE2+ Prover（客户端）', group: '非对称加密',
    key: true, param: true,
    keyLabel: 'w0, w1, x（Hex 逗号分隔；x 留空则随机）',
    paramLabel: '对方 shareV/Y（65 字节 Hex）[; context [; idProver [; idVerifier]]]',
    info: 'SPAKE2+ 客户端。填 w0/w1/x 与对方 share，得到 K_shared。⚠ RFC 9383 未规定 PBKDF 选择，注册条目的 PBKDF2 仅供演示。',
    enc: function (b, k, p, fmt) {
      var v = spakeSplitHex(k, 2, 'w0,w1');
      var w0 = v[0], w1 = v[1];
      var x = (v.length > 2 && String(k).split(/[,\s;]+/).filter(function (s) { return s.length; })[2] !== undefined)
        ? v[2] : spakeRandScalar();
      var pm = spakeParseParam(p);
      if (!pm.share) throw new Error('需要对方的 shareV / Y');
      var Y = spakePointFromHex(pm.share, 'shareV');
      var X = spakeProverShare(w0, x);
      var sh = spakeProverShared(w0, w1, x, Y);
      var D = spakeDerive(pm.ctx, pm.idP, pm.idV, X, Y, sh.Z, sh.V, w0);
      return [
        '【发出】shareP / X = ' + bytesToHex(spakePointBytes(X)),
        '【共享】K_shared    = ' + bytesToHex(D.Kshared),
        '【确认】confirmP    = ' + bytesToHex(D.confirmP),
        '（x = ' + spakeScalarHex(x) + '）'
      ].join('\n');
    },
    dec: function (b, k, p, fmt) { return this.enc(b, k, p, fmt); }
  });

  /* 3. Verifier（服务器） */
  reg({
    id: 'spake2p-verifier', name: 'SPAKE2+ Verifier（服务器）', group: '非对称加密',
    key: true, param: true,
    keyLabel: 'w0, L, y（Hex 逗号分隔；y 留空则随机；L 为未压缩点）',
    paramLabel: '对方 shareP/X（65 字节 Hex）[; context [; idProver [; idVerifier]]]',
    info: 'SPAKE2+ 服务端。填 w0/L/y 与对方 share，得到 K_shared。需与客户端结果一致才算协商成功。',
    enc: function (b, k, p, fmt) {
      var parts = String(k).split(/[,\s;]+/).filter(function (s) { return s.length; });
      if (parts.length < 2) throw new Error('w0,L：需要至少 w0 与 L 两个值');
      var w0 = bigFromHex(parts[0]);
      var L = spakePointFromHex(parts[1], 'L');
      var y = (parts.length > 2) ? bigFromHex(parts[2]) : spakeRandScalar();
      var pm = spakeParseParam(p);
      if (!pm.share) throw new Error('需要对方的 shareP / X');
      var X = spakePointFromHex(pm.share, 'shareP');
      var Y = spakeVerifierShare(w0, y);
      var sh = spakeVerifierShared(w0, L, y, X);
      var D = spakeDerive(pm.ctx, pm.idP, pm.idV, X, Y, sh.Z, sh.V, w0);
      return [
        '【发出】shareV / Y = ' + bytesToHex(spakePointBytes(Y)),
        '【共享】K_shared    = ' + bytesToHex(D.Kshared),
        '【确认】confirmV    = ' + bytesToHex(D.confirmV),
        '（y = ' + spakeScalarHex(y) + '）'
      ].join('\n');
    },
    dec: function (b, k, p, fmt) { return this.enc(b, k, p, fmt); }
  });
}
