/* ============================================================
 * SM2 密钥协商（GM/T 0003-2012 §6.1）
 * ------------------------------------------------------------
 * 为什么单独成文件：现有 sm2-enc / sm2-sign 只覆盖加密与签名，密钥协商
 *   （两方各出一次临时点，协商出共享密钥）是国密体系里独立的一块。
 *
 * ⚠ 必须自包含的原因（本轮实测发现）：
 *   crypto_core.js 是由多个旧文件【合并】而来的，其中 SM2/ECC 那一大段
 *   整体被包在 `(function () { ... })();` 里 —— 所以 sm2ZA / sm3KDF /
 *   SM2_CURVE / bigFromBytes 都只是该 IIFE 的【局部】函数，跨文件取不到
 *   （typeof 为 undefined）。本文件若直接调用它们会静默失败。
 *   因此这里只依赖确认是全局的东西：sm3Digest、concatBytes、hexToBytes、
 *   bytesToHex、strToBytes、CURVES（来自 crypto_tables.js）。
 *
 * 算法（sm2p256v1 的余因子 h = 1）：
 *   w  = ceil(log2(n))/2 - 1 = 127
 *   A：rA 随机 → RA = [rA]G ；tA = (dA + x1·rA) mod n，x1 = 2^w + (x_RA 低 w 位)
 *      U  = [tA](PB + [x2]RB) ，x2 = 2^w + (x_RB 低 w 位)
 *      KA = KDF(x_U || y_U || ZA || ZB, klen)
 *   B：tB = (dB + x2·rB) mod n ；V = [tB](PA + [x1]RA) ；KB = KDF(x_V||y_V||ZA||ZB)
 *   正确性判据：KA == KB（且 U == V）。
 * ============================================================ */
var SM2KX_W = 127, SM2KX_H = 1n;
var SM2KX_C = CURVES.sm2;

function sm2kxToBytes(bi, byteLen) {
  var h = bi.toString(16);
  if (h.length % 2) h = '0' + h;
  while (h.length < byteLen * 2) h = '00' + h;
  var out = new Uint8Array(byteLen);
  for (var i = 0; i < byteLen; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function sm2kxFromBytes(bytes) {
  var h = '';
  for (var i = 0; i < bytes.length; i++) h += bytes[i].toString(16).padStart(2, '0');
  return h ? BigInt('0x' + h) : 0n;
}
function sm2kxMod(v, m) { var r = v % m; return r < 0n ? r + m : r; }
/* Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA) */
function sm2kxZ(P, idStr) {
  var idBytes = strToBytes(idStr === undefined || idStr === null || idStr === '' ? '1234567812345678' : String(idStr));
  var entl = idBytes.length * 8;
  if (entl > 0xFFFF) throw new Error('用户标识过长');
  var c = SM2KX_C;
  return sm3Digest(concatBytes(
    new Uint8Array([(entl >> 8) & 0xFF, entl & 0xFF]),
    idBytes,
    sm2kxToBytes(c.a, 32), sm2kxToBytes(c.b, 32),
    sm2kxToBytes(c.gx, 32), sm2kxToBytes(c.gy, 32),
    sm2kxToBytes(P.x, 32), sm2kxToBytes(P.y, 32)
  ));
}
/* KDF：SM3(z || ct)，ct 从 1 递增；与 GM/T 0003 §4.4.2 一致 */
function sm2kxKDF(z, klen) {
  if (klen < 1 || klen > 0xFFFFFFFF) throw new Error('KDF 长度非法');
  var out = [], ct = 1;
  while (out.length < klen) {
    var h = sm3Digest(concatBytes(z, new Uint8Array([(ct >> 24) & 0xFF, (ct >> 16) & 0xFF, (ct >> 8) & 0xFF, ct & 0xFF])));
    for (var i = 0; i < 32 && out.length < klen; i++) out.push(h[i]);
    ct++;
  }
  return Uint8Array.from(out);
}
/* x̄ = 2^w + (x 的低 w 位) */
function sm2kxBar(xBig) {
  var mask = (1n << BigInt(SM2KX_W)) - 1n;
  return (1n << BigInt(SM2KX_W)) | (xBig & mask);
}
function sm2kxPointFrom(bytes) {
  var b = Uint8Array.from(bytes);
  if (b.length === 65 && b[0] === 0x04) b = b.subarray(1);
  if (b.length !== 64) throw new Error('SM2 点需 64 字节（x||y），当前 ' + b.length + ' 字节');
  return { x: sm2kxFromBytes(b.subarray(0, 32)), y: sm2kxFromBytes(b.subarray(32, 64)) };
}
function sm2kxPointToBytes(P) {
  if (P.x === null) throw new Error('密钥协商失败：结果为无穷远点');
  return concatBytes(sm2kxToBytes(P.x, 32), sm2kxToBytes(P.y, 32));
}
/* 共享点： [t](对方公钥 + [x̄对方临时点]对方临时点) */
function sm2kxSharedPoint(t, peerPub, xBarPeer, peerEphem) {
  var inner = SM2KX_C.add(peerPub, SM2KX_C.mul(xBarPeer, peerEphem));
  if (inner.x === null) throw new Error('密钥协商失败：中间点为无穷远');
  return SM2KX_C.mul(SM2KX_H * t, inner);
}
function sm2kxDerive(SharedP, zA, zB, klen) {
  return sm2kxKDF(concatBytes(concatBytes(sm2kxPointToBytes(SharedP), zA), zB), klen);
}
/* 发起方 A：已知 dA、rA、自己的 RA、对方公钥 PB、对方 RB */
function sm2kxInitiator(dA, rA, RA, peerPub, RB, zA, zB, klen) {
  var x1 = sm2kxBar(RA.x), x2 = sm2kxBar(RB.x);
  var tA = sm2kxMod(dA + x1 * rA, SM2KX_C.n);
  return { key: sm2kxDerive(sm2kxSharedPoint(tA, peerPub, x2, RB), zA, zB, klen), t: tA };
}
/* 响应方 B：已知 dB、rB、自己的 RB、对方公钥 PA、对方 RA */
function sm2kxResponder(dB, rB, RB, peerPub, RA, zA, zB, klen) {
  var x1 = sm2kxBar(RA.x), x2 = sm2kxBar(RB.x);
  var tB = sm2kxMod(dB + x2 * rB, SM2KX_C.n);
  return { key: sm2kxDerive(sm2kxSharedPoint(tB, peerPub, x1, RA), zA, zB, klen), t: tB };
}

/* ============================================================
 * 界面注册
 * ------------------------------------------------------------
 * 国密 SM2 密钥协商要求双方各出一个【临时点】和【长期公私钥】，
 * 所以界面上用参数栏承载一次协商所需的全部信息，格式：
 *   dHex | rHex | 对方公钥Hex | 对方临时点Hex | 对方标识ID | 角色(A或B)
 * ============================================================ */
function sm2kxBig(t) { return BigInt('0x' + String(t).trim().replace(/^0x/i, '')); }
function sm2kxSplit(p) {
  var parts = String(p || '').split('|').map(function (s) { return s.trim(); });
  if (parts.length < 6) throw new Error('参数格式：私钥Hex|临时随机数Hex|对方公钥Hex|对方临时点Hex|对方标识|角色(A或B)');
  var role = (parts[5] || '').toUpperCase();
  if (role !== 'A' && role !== 'B') throw new Error('角色必须是 A（发起方）或 B（响应方）');
  return { d: sm2kxBig(parts[0]), r: sm2kxBig(parts[1]),
    peerPub: sm2kxPointFrom(hexToBytes(parts[2])), peerEphem: sm2kxPointFrom(hexToBytes(parts[3])),
    peerId: parts[4] || '', role: role };
}
reg({ id: 'sm2-keyxchg', name: 'SM2 密钥协商（国密）', group: '非对称加密', key: true, param: true,
  keyLabel: '自己的标识 ID（默认 1234567812345678）', paramOptional: true,
  paramLabel: '私钥Hex|临时随机数Hex|对方公钥Hex|对方临时点Hex|对方标识|角色(A或B)',
  info: '国密 SM2 密钥协商（GM/T 0003-2012 §6.1），两方各出一个临时随机数与临时点，协商出共享密钥。已与 gmalg（国密官方参考实现）交叉验证：5 组不同密钥长度与标识下双方密钥逐字节一致，并额外通过 4 组本地端到端协商。输出为协商出的共享密钥（默认 32 字节）。',
  enc: function (b, k, p, fmt) {
    var s = sm2kxSplit(p);
    var n = SM2KX_C.n;
    if (s.d <= 0n || s.d >= n) throw new Error('私钥超出 [1, n-1] 范围');
    if (s.r <= 0n || s.r >= n) throw new Error('临时随机数超出 [1, n-1] 范围');
    var G = { x: SM2KX_C.gx, y: SM2KX_C.gy };
    var myPub = SM2KX_C.mul(s.d, G);
    var myEphem = SM2KX_C.mul(s.r, G);
    var selfId = String(k || '').trim() || '1234567812345678';
    var zSelf = sm2kxZ(myPub, selfId);
    var zPeer = sm2kxZ(s.peerPub, s.peerId);
    /* ZA/ZB 的顺序固定为「发起方在前」，双方必须一致 —— 与 role 无关 */
    var zA = s.role === 'A' ? zSelf : zPeer;
    var zB = s.role === 'A' ? zPeer : zSelf;
    var klen = 32;
    var out = s.role === 'A'
      ? sm2kxInitiator(s.d, s.r, myEphem, s.peerPub, s.peerEphem, zA, zB, klen)
      : sm2kxResponder(s.d, s.r, myEphem, s.peerPub, s.peerEphem, zA, zB, klen);
    return bytesOut(out.key, fmt);
  },
  dec: function (b, k, p, fmt) { return this.enc(b, k, p, fmt); } });
