/* ============================================================
 * SPECK-128/128 —— NSA 轻量分组密码（与 Simon 是姊妹算法）
 * 块 128 位、密钥 128 位、32 轮（注意：Simon128/128 是 68 轮，两者不同）。
 * 轮函数只用 加法 / 异或 / 循环移位，在软件里通常明显快于 Simon。
 *
 * 关键实现点：
 *  1) 32 轮，alpha=8（rotr）、beta=3（rotl）。写成 Simon 的 68 轮会得到一个
 *     长度正确、能往返、但跟官方对不上的结果。
 *  2) 字节序小端：y = 明文低 8 字节、x = 明文高 8 字节（按小端读成 64 位字）。
 *     输出时 y 写回低 8 字节、x 写回高 8 字节。
 *  3) 密钥调度：ks[0] = 密钥低字，l[0] = 密钥高字；
 *     l' = (rotr(l,8) + k) ^ i；k' = rotl(k,3) ^ l'。轮常数 i 是【异或】进 l'。
 *  4) 解密是 y = rotr(y^x, 3)；x = rotl((x^ks[i]) - y, 8)，减法需 mod 2^64。
 *
 * 向量来源：官方 C 实现（inmcm/Simon_Speck_Ciphers）tests.c 的 speck128_128
 *   官方向量，并用同一 C 实现在本沙盒编译后生成 50 组随机向量交叉验证。
 *   注意：该仓库附带的 Python 移植与 C 在 128/128 上一致，
 *   我最初因【从源码里抄向量时漏掉一个字节】而误判两者冲突，实为参照物抄错。
 * ============================================================ */
(function () {
  var M64 = (1n << 64n) - 1n;
  var SPECK_ROUNDS = 32, AL = 8, BE = 3;
  function rotl64(x, n) { return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64; }
  function rotr64(x, n) { return rotl64(x, 64 - n); }
  function readWordLE(b, o) { var v = 0n; for (var i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]); return v; }
  function writeWordLE(v, b, o) { for (var i = 0; i < 8; i++) { b[o + i] = Number(v & 0xffn); v >>= 8n; } }

  function speckKeySchedule(keyBytes) {
    var ks = [readWordLE(keyBytes, 0)];   /* 低字 */
    var ls = [readWordLE(keyBytes, 8)];   /* 高字 */
    for (var i = 0; i < SPECK_ROUNDS - 1; i++) {
      var nl = ((rotr64(ls[i], AL) + ks[i]) & M64) ^ BigInt(i);
      var nk = rotl64(ks[i], BE) ^ nl;
      ls.push(nl); ks.push(nk);
    }
    return ks;
  }
  function speckEncryptBlock(block, ks) {
    var y = readWordLE(block, 0), x = readWordLE(block, 8);
    for (var i = 0; i < ks.length; i++) {
      x = ((rotr64(x, AL) + y) & M64) ^ ks[i];
      y = rotl64(y, BE) ^ x;
    }
    var out = new Uint8Array(16);
    writeWordLE(y, out, 0); writeWordLE(x, out, 8);
    return out;
  }
  function speckDecryptBlock(block, ks) {
    var y = readWordLE(block, 0), x = readWordLE(block, 8);
    for (var i = ks.length - 1; i >= 0; i--) {
      y = rotr64(y ^ x, BE);
      x = rotl64(((x ^ ks[i]) - y) & M64, AL);
    }
    var out = new Uint8Array(16);
    writeWordLE(y, out, 0); writeWordLE(x, out, 8);
    return out;
  }
  function speckMakeBlockFn(keyBytes) {
    var ks = speckKeySchedule(keyBytes);
    return { enc: function (b) { return speckEncryptBlock(b, ks); },
             dec: function (b) { return speckDecryptBlock(b, ks); } };
  }
  globalThis.SPECK = { makeBlockFn: speckMakeBlockFn, KS: speckKeySchedule };
  if (typeof regSym === 'function') {
    regSym({ id: 'speck128', name: 'SPECK-128/128（NSA 轻量分组密码）', group: '对称加密',
      blockSize: 16, keyLen: 16, makeBlockFn: speckMakeBlockFn,
      info: 'NSA 2013 年发布的轻量分组密码，块 128 位、密钥 128 位、32 轮。轮函数只用加法/异或/循环移位，软件实现通常比姊妹算法 Simon 更快。' });
  } else if (typeof reg === 'function') {
    reg({ id: 'speck128', name: 'SPECK-128/128（NSA 轻量分组密码）', group: '对称加密',
      key: true, isSym: true, blockSize: 16, keyLen: 16, makeBlockFn: speckMakeBlockFn,
      info: 'NSA 2013 年发布的轻量分组密码，块 128 位、密钥 128 位、32 轮。' });
  }
})();
