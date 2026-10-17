/* ============================================================
 * Salsa20 流密码
 * Daniel J. Bernstein 的流密码，与 pycryptodome 交叉验证 8/8。
 * 状态常量 "expa/nd 3/2-by/te k" 是唯一需要死记的部分，已与参考实现逐字节比对。
 * ============================================================ */
/* ========== Salsa20（Daniel J. Bernstein）—— 与 pycryptodome 交叉验证 ==========
   状态常量是 "expand 32-byte k" 的四个小端字，不是前 16 字节按序取用：
     0x61707865("expa") 0x3320646e("nd 3") 0x79622d32("2-by") 0x6b206574("te k")
   早先我按 sig[0..3]/sig[4..7]/sig[8..11]/sig[12..15] 之外的方式排过，全错。 */
var SALSA_C = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
function salsaQR(x, a, b, c, d) {
  x[b] = (x[b] ^ (((x[a] + x[d]) >>> 0) << 7 | ((x[a] + x[d]) >>> 0) >>> 25)) >>> 0;
  x[c] = (x[c] ^ (((x[b] + x[a]) >>> 0) << 9 | ((x[b] + x[a]) >>> 0) >>> 23)) >>> 0;
  x[d] = (x[d] ^ (((x[c] + x[b]) >>> 0) << 13 | ((x[c] + x[b]) >>> 0) >>> 19)) >>> 0;
  x[a] = (x[a] ^ (((x[d] + x[c]) >>> 0) << 18 | ((x[d] + x[c]) >>> 0) >>> 14)) >>> 0;
}
function salsaCore(st) {
  var x = st.slice(), i;
  for (i = 0; i < 10; i++) {
    salsaQR(x, 0, 4, 8, 12); salsaQR(x, 5, 9, 13, 1); salsaQR(x, 10, 14, 2, 6); salsaQR(x, 15, 3, 7, 11);
    salsaQR(x, 0, 1, 2, 3);   salsaQR(x, 5, 6, 7, 4); salsaQR(x, 10, 11, 8, 9); salsaQR(x, 15, 12, 13, 14);
  }
  for (i = 0; i < 16; i++) x[i] = (x[i] + st[i]) >>> 0;
  return x;
}
function salsa20Keystream(key, nonce, ctr) {
  var st = new Array(16), o;
  st[0] = SALSA_C[0];
  for (o = 0; o < 4; o++) st[1 + o] = readU32LE(key, o * 4);
  st[5] = SALSA_C[1];
  st[6] = readU32LE(nonce, 0); st[7] = readU32LE(nonce, 4);
  st[8] = Number(ctr & 0xffffffffn) >>> 0;
  st[9] = Number((ctr >> 32n) & 0xffffffffn) >>> 0;
  st[10] = SALSA_C[2];
  for (o = 0; o < 4; o++) st[11 + o] = readU32LE(key, 16 + o * 4);
  st[15] = SALSA_C[3];
  var x = salsaCore(st), out = new Uint8Array(64);
  for (var j = 0; j < 16; j++) writeU32LE(x[j], out, j * 4);
  return out;
}
function salsa20Crypt(data, key, nonce) {
  if (key.length !== 32) throw new Error('Salsa20 密钥必须为 32 字节');
  if (nonce.length !== 8) throw new Error('Salsa20 nonce 必须为 8 字节');
  var out = new Uint8Array(data.length), ks, ctr = 0n, i, j;
  for (i = 0; i < data.length; i += 64) {
    ks = salsa20Keystream(key, nonce, ctr++);
    var n = Math.min(64, data.length - i);
    for (j = 0; j < n; j++) out[i + j] = data[i + j] ^ ks[j];
  }
  return out;
}
/* Salsa20 是流密码，不该走 regSym —— regSym 会设 isSym=true，
   而主流程看到 isSym 就会调 symEncrypt()，后者第一件事是
   algo.makeBlockFn(...)。Salsa20 没有块函数，界面上一点【加密】就崩。
   流密码应像 RC4 / ChaCha20 一样用 reg + 自定义 enc/dec（不走模式路径）。
   代价：不显示「加密模式」行 —— 但流密码本来就没有分组模式可选。 */
reg({ id: 'salsa20', name: 'Salsa20', group: '对称加密', stream: true, key: true,
  keyLabel: '密钥 32 字节（Hex）', paramLabel: 'nonce 8 字节（Hex）', param: true, paramOptional: true,
  info: 'Salsa20 流密码（eSTREAM 入选）。与 pycryptodome 逐字节一致。密钥 32 字节，nonce 8 字节。',
  enc: function (b, k, p, fmt) {
    var key = hexToBytes(k), nonce = p ? hexToBytes(p) : crypto.getRandomValues(new Uint8Array(8));
    var ct = salsa20Crypt(b, key, nonce);
    return bytesOut(concatBytes(nonce, ct), fmt);
  },
  dec: function (b, k, p, fmt) {
    var key = hexToBytes(k);
    var body = b, nonce;
    if (p) {
      nonce = hexToBytes(p);
      /* 加密输出是 nonce‖密文；若前 8 字节正是该 nonce 则剥掉，避免重复解密 */
      if (b.length >= 8 && b.subarray(0, 8).every(function (v, i) { return v === nonce[i]; })) body = b.subarray(8);
    } else {
      if (b.length < 8) throw new Error('需要 nonce：请在参数栏填 8 字节 Hex，或让密文自带 nonce 前缀');
      nonce = b.subarray(0, 8); body = b.subarray(8);
    }
    return bytesOut(salsa20Crypt(body, key, nonce), fmt);
  } });
