/* ============================================================
 * LION(SHA-160,RC4,64) / ChaCha_RNG
 * ------------------------------------------------------------
 * 实现与向量均取自 Botan 2.19.5：
 *   src/tests/data/block/lion.vec        LION 官方向量（1 组）
 *   src/tests/data/rng/chacha_rng.vec    ChaCha_RNG 官方向量（21 组）
 * 语义逐行照官方 C++ 源码：
 *   src/lib/block/lion/lion.cpp + lion.h
 *   src/lib/rng/chacha_rng/chacha_rng.cpp + chacha_rng.h
 *   src/lib/rng/stateful_rng/stateful_rng.cpp
 *   src/lib/stream/rc4/rc4.cpp（SKIP=0，set_key 后 m_position=0）
 *   src/lib/stream/chacha/chacha.cpp（set_iv(nullptr,0)→初态全零）
 *
 * 【LION 三个易错点，第一版全栽过】
 *   1) left_size() = 哈希输出长度（20），不是 block_size/2；
 *      right_size() = 64 - 20 = 44。
 *   2) key_schedule 里 half = key.length/2 = 16，而 m_key1/m_key2
 *      被 resize 到 left_size()=20 并先清零，故后 4 字节恒为 0。
 *   3) 第二轮用的是【第一轮加密后的右半输出】经哈希得到的 buffer，
 *      与 key2 异或后作新密钥；解密则先 key2 后 key1。
 *
 * 【ChaCha_RNG 调用顺序（靠反推官方向量确定）】
 *   add_entropy(EI) → add_entropy(EIR) → generate(64, AI1)【丢弃】
 *   → generate(64, AI2)【= Out】
 *   即 Botan/NIST CAVS 的「连续两次生成、Out 取第二次」；第一组无
 *   AdditionalInput 时，被丢弃的第一次生成恰好消耗 64 字节，这解释
 *   了为什么 Out 落在 keystream 偏移 96 而非 32 处。
 *   update() 语义：CK' = HMAC(HK, input)；HK' = ChaCha20(CK') 前 32 字节。
 * ============================================================ */
(function () {
  'use strict';
  if (typeof ALGOS === 'undefined') return;
  function G(n) { return (typeof window !== 'undefined' ? window : globalThis)[n]; }

  var OTP = G('OTP');
  var sha1 = OTP && OTP.sha1Bytes;
  var hmacSha256 = G('hmacSha256');
  var chacha20Stream = G('chacha20Stream');

  function hexB(s) { return G('hexToBytes')(String(s || '').replace(/\s/g, '')); }
  function out(b, fmt) { return G('bytesOut')(b, fmt); }

  function xor(a, b) {
    var o = new Uint8Array(a.length), i;
    for (i = 0; i < a.length; i++) o[i] = a[i] ^ b[i];
    return o;
  }

  /* ============ RC4 密钥流（Botan SKIP=0，PRGA 直接从头开始） ============ */
  function rc4Ks(key, n) {
    var S = new Uint8Array(256), i, j = 0, t, k;
    for (i = 0; i < 256; i++) S[i] = i;
    for (i = 0; i < 256; i++) {
      j = (j + S[i] + key[i % key.length]) & 255;
      t = S[i]; S[i] = S[j]; S[j] = t;
    }
    var outp = new Uint8Array(n), i2 = 0, j2 = 0;
    for (k = 0; k < n; k++) {
      i2 = (i2 + 1) & 255;
      j2 = (j2 + S[i2]) & 255;
      t = S[i2]; S[i2] = S[j2]; S[j2] = t;
      outp[k] = S[(S[i2] + S[j2]) & 255];
    }
    return outp;
  }

  /* ============ LION（可变块长分组密码构造，此处 64 字节块） ============ */
  var LION_BS = 64, LION_LEFT = 20, LION_RIGHT = 44;

  function lionSplitKey(key) {
    var half = key.length >> 1;
    var k1 = new Uint8Array(LION_LEFT), k2 = new Uint8Array(LION_LEFT);
    var n = Math.min(half, LION_LEFT);
    k1.set(key.subarray(0, n));
    k2.set(key.subarray(half, half + n));
    return [k1, k2];
  }

  function lionCore(inp, key, enc) {
    if (!sha1) throw new Error('SHA-1 内核未加载');
    if (!key.length) throw new Error('请填密钥');
    if (inp.length === 0) return new Uint8Array(0);
    if (inp.length % LION_BS !== 0) {
      throw new Error('LION 块长 64 字节，输入长度必须是 64 的倍数（当前 ' + inp.length + '）');
    }
    var ks = lionSplitKey(key);
    var k1 = ks[0], k2 = ks[1];
    /* 加密顺序 key1→key2，解密顺序 key2→key1 */
    var kA = enc ? k1 : k2, kB = enc ? k2 : k1;
    var outp = new Uint8Array(inp.length);
    var off, L, R, buf, outR, h, newL, ksBytes, i;
    for (off = 0; off < inp.length; off += LION_BS) {
      L = inp.subarray(off, off + LION_LEFT);
      R = inp.subarray(off + LION_LEFT, off + LION_BS);

      buf = xor(L, kA);
      ksBytes = rc4Ks(buf, LION_RIGHT);
      outR = new Uint8Array(LION_RIGHT);
      for (i = 0; i < LION_RIGHT; i++) outR[i] = R[i] ^ ksBytes[i];

      h = sha1(outR);
      newL = xor(L, h.subarray(0, LION_LEFT));
      outp.set(newL, off);
      outp.set(outR, off + LION_LEFT);

      buf = xor(newL, kB);
      ksBytes = rc4Ks(buf, LION_RIGHT);
      for (i = 0; i < LION_RIGHT; i++) outp[off + LION_LEFT + i] = outR[i] ^ ksBytes[i];
    }
    return outp;
  }

  ALGOS.push({
    id: 'lion', name: 'LION（SHA-1+RC4，64 字节块）', group: '对称加密',
    key: true, param: true,
    keyLabel: '密钥（Hex，2~40 字节；偶数长度）',
    paramLabel: '留空加密；填 decrypt 解密',
    info: 'Anderson-Biham 的 LION 构造：哈希+流密码拼出可变块长分组密码。此处为 Botan 官方配置 Lion(SHA-160,RC4,64)：左 20 字节经哈希流异或，右 44 字节经两次 RC4。\n【易错】left_size 是哈希输出长度 20 而非块长一半；输入须为 64 的倍数。\n【验证】Botan 官方 lion.vec 1/1，另加 24 组交叉向量全过。',
    enc: function (b, k, p, fmt) {
      var key = hexB(k);
      var dec = /dec/i.test(String(p || ''));
      return out(lionCore(b, key, !dec), fmt);
    },
    dec: function (s, k, p, fmt) {
      var key = hexB(k);
      return out(lionCore(G('bytesIn')(s, fmt), key, false), fmt);
    }
  });

  /* ============ ChaCha_RNG ============ */
  var ZERO12 = new Uint8Array(12);

  function CRNG() {
    if (!hmacSha256 || !chacha20Stream) throw new Error('HMAC-SHA256 或 ChaCha20 内核未加载');
    this.hk = new Uint8Array(32);          /* clear_state: HMAC key = 全零 */
    this.ck = hmacSha256(this.hk, new Uint8Array(0));
    this.pos = 0;
  }
  CRNG.prototype.upd = function (inp) {
    this.ck = hmacSha256(this.hk, inp);    /* CK' = HMAC(HK, input) */
    this.hk = chacha20Stream(this.ck, ZERO12, 0, 32);  /* HK' = ChaCha20(CK') 前 32 字节 */
    this.pos = 32;
  };
  CRNG.prototype.gen = function (n, addin) {
    if (addin && addin.length) this.upd(addin);
    var ks = chacha20Stream(this.ck, ZERO12, 0, this.pos + n);
    var o = ks.slice(this.pos, this.pos + n);
    this.pos += n;
    return o;
  };

  ALGOS.push({
    id: 'chacha-rng', name: 'ChaCha_RNG（Botan 专有 DRBG）', group: '单向哈希',
    key: true, param: true,
    keyLabel: 'EntropyInput 熵输入（Hex）',
    paramLabel: 'EntropyInputReseed(Hex), 输出字节数, AdditionalInput1(Hex), AdditionalInput2(Hex)',
    info: 'Botan 自有 ChaCha_RNG：update 时 CK\'=HMAC(HK,input)、HK\'=ChaCha20(CK\') 前 32 字节，输出即 ChaCha20 密钥流。\n【调用顺序】注入熵、重播种、连续两次生成，Out 取第二次。\n【验证】Botan rng/chacha_rng.vec 21/21。\n【注意】非标准构造，仅供复现与教学。',
    enc: function (b, k, p, fmt) {
      var ent = hexB(k);
      if (!ent.length) throw new Error('请填 EntropyInput（Hex）');
      var ps = String(p || '').split(',');
      var reseed = hexB(ps[0] || '');
      var len = parseInt(ps[1], 10); if (isNaN(len) || len < 1) len = 64;
      if (len > 65536) throw new Error('输出长度过大（上限 64 KB）');
      var ai1 = hexB(ps[2] || ''), ai2 = hexB(ps[3] || '');
      var r = new CRNG();
      r.upd(ent);
      if (reseed.length) r.upd(reseed);
      r.gen(64, ai1);                 /* 第一次生成被丢弃（CAVS 流程） */
      return out(r.gen(len, ai2), fmt);
    }
  });
})();
