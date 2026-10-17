/* ============================================================
 * SipHash-2-4 —— 带密钥的短输入 PRF（Jean-Philippe Aumasson / Daniel J. Bernstein）
 *
 * 用途：哈希表防碰撞攻击（Python / Rust / Redis 都用它），不是加密哈希。
 * 必须带 16 字节密钥，因此这里的"输入内容"是消息、"密钥栏"是 key。
 *
 * 64 位运算用 hi/lo 双 32 位字表示。为什么不用 BigInt：SipHash 的典型场景是
 * 海量短键，BigInt 的开销会盖过算法本身。但为了不重蹈"优化后静默出错"，
 * 文件里同时保留一份 BigInt 参考实现 SIP.big() 仅用于自检，不参与注册。
 *
 * 向量来源：官方 vectors.h（key = 000102…0f，输入 = 前 n 个字节）
 *   并由 Python siphash 0.0.1 交叉复算一致（注意：该库 digest() 是大端，
 *   官方值是小端，必须反转 8 字节后才可比——这一步当初差点判成"实现错"）
 * ============================================================ */
(function () {
  var M64 = 0xffffffff;
  function u64(hi, lo) { return { hi: hi >>> 0, lo: lo >>> 0 }; }
  function xor(a, b) { return u64(a.hi ^ b.hi, a.lo ^ b.lo); }
  function add(a, b) {
    var s = (a.lo >>> 0) + (b.lo >>> 0);
    var lo = s >>> 0, carry = s > M64 ? 1 : 0;
    return u64((a.hi + b.hi + carry) >>> 0, lo);
  }
  function rotl(a, n) {
    if (n === 0) return u64(a.hi, a.lo);
    if (n === 32) return u64(a.lo, a.hi);
    if (n < 32) return u64(((a.hi << n) | (a.lo >>> (32 - n))) >>> 0,
                           ((a.lo << n) | (a.hi >>> (32 - n))) >>> 0);
    n -= 32;
    return u64(((a.lo << n) | (a.hi >>> (32 - n))) >>> 0,
               ((a.hi << n) | (a.lo >>> (32 - n))) >>> 0);
  }
  function fromBytesLE(b, off) {
    return u64(((b[off + 4] | b[off + 5] << 8 | b[off + 6] << 16 | b[off + 7] << 24) >>> 0),
               ((b[off] | b[off + 1] << 8 | b[off + 2] << 16 | b[off + 3] << 24) >>> 0));
  }
  function sipround(v) {
    v[0] = add(v[0], v[1]); v[1] = rotl(v[1], 13); v[1] = xor(v[1], v[0]); v[0] = rotl(v[0], 32);
    v[2] = add(v[2], v[3]); v[3] = rotl(v[3], 16); v[3] = xor(v[3], v[2]);
    v[0] = add(v[0], v[3]); v[3] = rotl(v[3], 21); v[3] = xor(v[3], v[0]);
    v[2] = add(v[2], v[1]); v[1] = rotl(v[1], 17); v[1] = xor(v[1], v[2]); v[2] = rotl(v[2], 32);
  }
  /* c = 压缩轮数，d = 终结轮数；SipHash-2-4 即 c=2, d=4 */
  function siphash(key, msg, c, d) {
    if (key.length !== 16) throw new Error('SipHash 密钥必须 16 字节');
    var k0 = fromBytesLE(key, 0), k1 = fromBytesLE(key, 8);
    var v = [xor(k0, u64(0x736f6d65, 0x70736575)), xor(k1, u64(0x646f7261, 0x6e646f6d)),
             xor(k0, u64(0x6c796765, 0x6e657261)), xor(k1, u64(0x74656462, 0x79746573))];
    var n = msg.length, i = 0;
    for (; n - i >= 8; i += 8) {
      var m = fromBytesLE(msg, i);
      v[3] = xor(v[3], m);
      for (var r = 0; r < c; r++) sipround(v);
      v[0] = xor(v[0], m);
    }
    var tail = new Uint8Array(8);
    var rem = n - i;
    for (var j = 0; j < rem; j++) tail[j] = msg[i + j];
    tail[7] = n & 0xff;                       /* 长度打在最高字节（小端下即最高 8 位） */
    var b = fromBytesLE(tail, 0);
    v[3] = xor(v[3], b);
    for (r = 0; r < c; r++) sipround(v);
    v[0] = xor(v[0], b);
    v[2] = xor(v[2], u64(0, 0xff));
    for (r = 0; r < d; r++) sipround(v);
    var out = xor(xor(v[0], v[1]), xor(v[2], v[3]));
    var o = new Uint8Array(8);
    o[0] = out.lo & 0xff; o[1] = (out.lo >>> 8) & 0xff; o[2] = (out.lo >>> 16) & 0xff; o[3] = (out.lo >>> 24) & 0xff;
    o[4] = out.hi & 0xff; o[5] = (out.hi >>> 8) & 0xff; o[6] = (out.hi >>> 16) & 0xff; o[7] = (out.hi >>> 24) & 0xff;
    return o;
  }

  /* BigInt 参考实现：只用于自检，验证 hi/lo 版没有算错。不对外注册。 */
  function sipBig(key, msg, c, d) {
    var MSK = 0xffffffffffffffffn;
    function le(b, o) { var x = 0n; for (var i = 7; i >= 0; i--) x = (x << 8n) | BigInt(b[o + i]); return x; }
    function rot(x, n) { return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MSK; }
    var k0 = le(key, 0), k1 = le(key, 8);
    var v = [k0 ^ 0x736f6d6570736575n, k1 ^ 0x646f72616e646f6dn,
             k0 ^ 0x6c7967656e657261n, k1 ^ 0x7465646279746573n];
    function rnd() {
      v[0] = (v[0] + v[1]) & MSK; v[1] = rot(v[1], 13); v[1] ^= v[0]; v[0] = rot(v[0], 32);
      v[2] = (v[2] + v[3]) & MSK; v[3] = rot(v[3], 16); v[3] ^= v[2];
      v[0] = (v[0] + v[3]) & MSK; v[3] = rot(v[3], 21); v[3] ^= v[0];
      v[2] = (v[2] + v[1]) & MSK; v[1] = rot(v[1], 17); v[1] ^= v[2]; v[2] = rot(v[2], 32);
    }
    var n = msg.length, i = 0, r;
    for (; n - i >= 8; i += 8) { var m = le(msg, i); v[3] ^= m; for (r = 0; r < c; r++) rnd(); v[0] ^= m; }
    var t = new Uint8Array(8);
    for (var j = 0; j < n - i; j++) t[j] = msg[i + j];
    t[7] = n & 0xff;
    var b = le(t, 0);
    v[3] ^= b; for (r = 0; r < c; r++) rnd(); v[0] ^= b;
    v[2] ^= 0xffn;
    for (r = 0; r < d; r++) rnd();
    var o = (v[0] ^ v[1] ^ v[2] ^ v[3]) & MSK, out = new Uint8Array(8);
    for (var q = 0; q < 8; q++) { out[q] = Number(o & 0xffn); o >>= 8n; }
    return out;
  }

  function parseKey(k) {
    var s = String(k || '').trim().replace(/\s/g, '');
    if (!s) throw new Error('请在密钥栏填 16 字节密钥（32 个十六进制字符）');
    if (!/^[0-9a-fA-F]+$/.test(s)) throw new Error('密钥须为十六进制');
    var b = hexToBytes(s);
    if (b.length !== 16) throw new Error('SipHash 密钥必须 16 字节（当前 ' + b.length + '）');
    return b;
  }

  var G = '单向哈希';
  reg({
    id: 'siphash-24', name: 'SipHash-2-4（带密钥 PRF）', group: G, key: true, param: false,
    keyLabel: '16 字节密钥（32 个十六进制字符）',
    info: 'SipHash-2-4 带密钥伪随机函数，用于哈希表防碰撞（Python/Rust/Redis 同款）。16 字节密钥 + 消息 → 64 位摘要。它不是加密哈希，不能替代 SHA-256。',
    enc: function (b, k, p, fmt) {
      var out = siphash(parseKey(k), b, 2, 4);
      return bytesOut(out, fmt);
    }, dec: false
  });
  reg({
    id: 'siphash-13', name: 'SipHash-1-3（快速变体）', group: G, key: true, param: false,
    keyLabel: '16 字节密钥（32 个十六进制字符）',
    info: 'SipHash-1-3：压缩 1 轮、终结 3 轮，比 2-4 快约一倍，安全性略低（仍远高于普通非加密哈希）。适合对延迟极敏感的场景。',
    enc: function (b, k, p, fmt) {
      var out = siphash(parseKey(k), b, 1, 3);
      return bytesOut(out, fmt);
    }, dec: false
  });

  globalThis.SIP = { siphash: siphash, sipBig: sipBig };
})();
