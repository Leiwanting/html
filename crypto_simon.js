/* ============================================================
 * Simon-128/128 —— NSA 轻量分组密码（Beaulieu / Shors / Smith 等，2013）
 * 块 128 位、密钥 128 位、68 轮。与 SPECK 是姊妹算法：Simon 为软件/硬件均衡优化，
 * 轮函数只用了与、异或、循环移位三种操作。
 *
 * 关键实现点（都是从官方参考实现的密钥调度里逐条核对出来的）：
 *  1) 轮数不是 32。Simon128/128 是【68 轮】——SPECK128/128 才是 32 轮，
 *     当初按 32 写会得到一个长度正确、完全自洽但跟官方对不上的结果。
 *  2) 字节序是【小端】：明文字节流的第 0 字节是 64 位字的最低字节。
 *     加密时 x = 高 8 字节小端、y = 低 8 字节小端；输出同理反写回。
 *     大端小端在这里不报错，只是密文全错——必须靠向量才能定。
 *  3) 密钥调度的 rs_3 是 rotr(k,3)，rs_1 是 rotr(rs_3,1)，
 *     常量 c = 2^64-4 与 z 序列当前位异或（是异或，不是加法）。
 *  4) key_schedule[i] 取的是队列【右端】（初始最后一个字），不是左端。
 *
 * 向量来源：NSA 官方配套 C 实现 tests.c 中的 speck/simon 测试向量
 *   （Simon128/128：key 000102…0f，明文 " travellers desc"
 *     → bc0b4ef82a83aa653ffe541e1e1b6849），并用 Python 参考实现复算一致。
 * 64 位运算用 BigInt（轮数多、每轮运算少，BigInt 开销可接受）。
 * ============================================================ */
(function () {
  var M64 = (1n << 64n) - 1n;
  var SIMON_ROUNDS = 68;
  var SIMON_Z = 0x3369f885192c0ef5n;   /* z 序列，62 位循环取用 */
  var SIMON_C = M64 ^ 3n;              /* 2^64 - 4 */

  function rotl64(x, n) { return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64; }
  function rotr64(x, n) { return rotl64(x, 64 - n); }
  function readWordLE(b, o) {
    var v = 0n;
    for (var i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]);
    return v;
  }
  function writeWordLE(v, b, o) {
    for (var i = 0; i < 8; i++) { b[o + i] = Number(v & 0xffn); v >>= 8n; }
  }

  function simonKeySchedule(keyBytes) {
    /* 小端：x = 高 8 字节，y = 低 8 字节；队列初始为 [x, y] */
    var reg = [readWordLE(keyBytes, 8), readWordLE(keyBytes, 0)];
    var ks = [];
    for (var i = 0; i < SIMON_ROUNDS; i++) {
      var rs3 = rotr64(reg[0], 3);
      var rs1 = rotr64(rs3, 1);
      var cz = SIMON_C ^ ((SIMON_Z >> BigInt(i % 62)) & 1n);
      var nk = cz ^ rs1 ^ rs3 ^ reg[reg.length - 1];
      ks.push(reg.pop());      /* 取右端 */
      reg.unshift(nk);
    }
    return ks;
  }

  function simonEncryptBlock(block, ks) {
    var x = readWordLE(block, 8), y = readWordLE(block, 0);
    for (var i = 0; i < ks.length; i++) {
      var nx = ks[i] ^ (((rotl64(x, 1) & rotl64(x, 8)) ^ y) ^ rotl64(x, 2));
      y = x; x = nx;
    }
    var out = new Uint8Array(16);
    writeWordLE(y, out, 0); writeWordLE(x, out, 8);
    return out;
  }
  function simonDecryptBlock(block, ks) {
    var x = readWordLE(block, 8), y = readWordLE(block, 0);
    for (var i = ks.length - 1; i >= 0; i--) {
      var ny = ((ks[i] ^ x) ^ rotl64(y, 2)) ^ (rotl64(y, 1) & rotl64(y, 8));
      x = y; y = ny;
    }
    var out = new Uint8Array(16);
    writeWordLE(y, out, 0); writeWordLE(x, out, 8);
    return out;
  }
  function simonMakeBlockFn(keyBytes) {
    var ks = simonKeySchedule(keyBytes);
    return { enc: function (b) { return simonEncryptBlock(b, ks); },
             dec: function (b) { return simonDecryptBlock(b, ks); } };
  }

  globalThis.SIMON = { makeBlockFn: simonMakeBlockFn, KS: simonKeySchedule };

  if (typeof regSym === 'function') {
    regSym({ id: 'simon128', name: 'Simon-128/128（NSA 轻量分组密码）', group: '对称加密',
      blockSize: 16, keyLen: 16, makeBlockFn: simonMakeBlockFn,
      info: 'NSA 2013 年发布的轻量分组密码，块 128 位、密钥 128 位、68 轮。轮函数只用与/异或/循环移位，硬件面积极小。注意块是 128 位，与 AES 相同，可直接套用 CBC/CTR 等模式。' });
  } else if (typeof reg === 'function') {
    reg({ id: 'simon128', name: 'Simon-128/128（NSA 轻量分组密码）', group: '对称加密',
      key: true, isSym: true, blockSize: 16, keyLen: 16, makeBlockFn: simonMakeBlockFn,
      info: 'NSA 2013 年发布的轻量分组密码，块 128 位、密钥 128 位、68 轮。轮函数只用与/异或/循环移位，硬件面积极小。' });
  }
})();
