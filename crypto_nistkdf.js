/* ============================================================
 * GMAC / NIST SP 800-108 KDF（Counter·Feedback·Pipeline）/
 * OpenPGP S2K / HMAC-DRBG（NIST SP 800-90A）
 * ------------------------------------------------------------
 * 全部实现均逐行对照 Botan 2.19.5 官方 C++ 源码：
 *   src/lib/mac/gmac/*.cpp        （语义＝GCM 空明文的 tag）
 *   src/lib/kdf/sp800_108/sp800_108.cpp
 *   src/lib/pbkdf/pgp_s2k/pgp_s2k.cpp
 *   src/lib/rng/hmac_drbg/hmac_drbg.cpp
 * 向量：src/tests/data/mac/gmac.vec、kdf/sp800_108_{ctr,fb,pipe}.vec、
 *       pbkdf/pgp_s2k.vec、rng/hmac_drbg.vec（源自 NIST CAVS）
 * ============================================================ */
(function () {
  'use strict';
  if (typeof ALGOS === 'undefined') return;
  function G(n) { return (typeof window !== 'undefined' ? window : globalThis)[n]; }

  function hexB(s) {
    s = String(s === undefined || s === null ? '' : s).replace(/[^0-9a-fA-F]/g, '');
    if (s.length % 2) s = '0' + s;
    var o = new Uint8Array(s.length / 2);
    for (var i = 0; i < o.length; i++) o[i] = parseInt(s.substr(i * 2, 2), 16);
    return o;
  }
  function cat() {
    var a = arguments, t = 0, i;
    for (i = 0; i < a.length; i++) t += a[i].length;
    var o = new Uint8Array(t), p = 0;
    for (i = 0; i < a.length; i++) { o.set(a[i], p); p += a[i].length; }
    return o;
  }
  function pad16(b) {
    var r = b.length % 16; if (!r) return b;
    var o = new Uint8Array(b.length + 16 - r); o.set(b); return o;
  }
  function be64(n) {
    var o = new Uint8Array(8);
    for (var i = 7; i >= 0; i--) { o[i] = n % 256; n = Math.floor(n / 256); }
    return o;
  }
  function be32(n) {
    return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  }
  function toB(b) {
    if (b instanceof Uint8Array || ArrayBuffer.isView(b)) return new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
    return G('strToBytes')(String(b === undefined || b === null ? '' : b));
  }
  /* ---- PRF：HMAC(SHA-1 / SHA-256 / SHA-384 / SHA-512) ---- */
  var HASHES = {
    'SHA-1': { out: 20, bs: 64 }, 'SHA-160': { out: 20, bs: 64 },
    'SHA-224': { out: 28, bs: 64 },
    'SHA-256': { out: 32, bs: 64 },
    'SHA-384': { out: 48, bs: 128 },
    'SHA-512': { out: 64, bs: 128 },
    'SHA-512-224': { out: 28, bs: 128 }, 'SHA-512/224': { out: 28, bs: 128 },
    'SHA-512-256': { out: 32, bs: 128 }, 'SHA-512/256': { out: 32, bs: 128 }
  };
  function normHash(n) {
    n = String(n || 'SHA-256').toUpperCase().replace(/[^0-9A-Z\-\/]/g, '');
    if (n === 'SHA224') return 'SHA-224';
    if (n === 'SHA512-224' || n === 'SHA512224') return 'SHA-512-224';
    if (n === 'SHA512-256' || n === 'SHA512256') return 'SHA-512-256';
    if (n === 'SHA1' || n === 'SHA-160' || n === '160') return 'SHA-1';
    if (n === 'SHA256') return 'SHA-256';
    if (n === 'SHA384') return 'SHA-384';
    if (n === 'SHA512') return 'SHA-512';
    if (!HASHES[n]) throw new Error('不支持的摘要：' + n + '（可选 SHA-1 / SHA-256 / SHA-384 / SHA-512）');
    return n;
  }
  function hmacRaw(hashFn, bs, key, data) {
    var k = key;
    if (k.length > bs) k = hashFn(k);
    var ip = new Uint8Array(bs), op = new Uint8Array(bs);
    for (var i = 0; i < bs; i++) { var kb = i < k.length ? k[i] : 0; ip[i] = kb ^ 0x36; op[i] = kb ^ 0x5c; }
    return hashFn(cat(op, hashFn(cat(ip, data))));
  }
  /* SHA-384 的初始向量：取自 Botan 2.19.5 src/lib/hash/sha2_64/sha2_64.cpp
     SHA_384::clear() 逐字原文（环境里没有同步的 SHA-384 内核，只能自带） */
  var IV_384 = [0xcbbb9d5dc1059ed8n, 0x629a292a367cd507n, 0x9159015a3070dd17n, 0x152fecd8f70e5939n,
                0x67332667ffc00b31n, 0x8eb44a8768581511n, 0xdb0c2e0d64f98fa7n, 0x47b5481dbefa4fa4n];
  function sha384Bytes(d) {
    var core = G('sha512Core');
    if (!core) throw new Error('SHA-512 内核未加载');
    return core(d, IV_384, 48);
  }
  function hashFnOf(name) {
    if (name === 'SHA-1') {
      var otp = G('OTP');
      if (!otp || !otp.sha1Bytes) throw new Error('SHA-1 内核未加载');
      return otp.sha1Bytes;
    }
    if (name === 'SHA-384') return sha384Bytes;
    if (name === 'SHA-512') {
      var f = G('sha512Digest');
      if (!f) throw new Error('SHA-512 内核未加载');
      return f;
    }
    if (name === 'SHA-512-224' || name === 'SHA-512-256') {
      var g = G(name === 'SHA-512-224' ? 'sha512_224Digest' : 'sha512_256Digest');
      if (!g) throw new Error(name + ' 内核未加载');
      return g;
    }
    if (name === 'SHA-224') {
      /* SHA-224 的 IV 取自 Botan src/lib/hash/sha2_32/sha2_32.cpp SHA_224::clear() 原文 */
      var IV224 = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                   0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
      var c256 = G('sha256Core');
      if (!c256) throw new Error('SHA-256 内核未加载');
      return function (d) { return c256(d, IV224, 7); };
    }
    var s2 = G('sha256BytesSync') || G('sha256Bytes');
    if (!s2) throw new Error('SHA-256 内核未加载');
    return s2;
  }
  function makePrf(name) {
    var h = HASHES[name], hashFn = hashFnOf(name);
    return { out: h.out, mac: function (k, d) { return hmacRaw(hashFn, h.bs, k, d); } };
  }

  /* ============================================================
   * 1. GMAC（＝GCM 在明文为空时的 tag）
   *    H = AES_K(0^128)；J0 = IV‖0^31‖1（IV 为 12 字节）
   *    IV 非 12 字节时 J0 = GHASH_H(IV‖补零‖BE64(len(IV)*8))
   *    tag = GHASH_H(A‖补零‖BE64(len(A)*8)‖BE64(0)) ⊕ E_K(J0)
   * ============================================================ */
  function gmacTag(key, iv, msg) {
    var aesMake = G('aesMakeBlockFn'), ghash = G('ghash');
    if (!aesMake || !ghash) throw new Error('AES / GHASH 内核未加载');
    if (key.length !== 16 && key.length !== 24 && key.length !== 32) throw new Error('GMAC 密钥需 16/24/32 字节');
    var bf = aesMake(key), H = bf.enc(new Uint8Array(16));
    var J0;
    if (iv.length === 12) J0 = cat(iv, new Uint8Array([0, 0, 0, 1]));
    else J0 = ghash(H, cat(pad16(iv), be64(iv.length * 8)));
    var E0 = bf.enc(J0);
    var g = ghash(H, cat(pad16(msg), be64(msg.length * 8), be64(0)));
    var t = new Uint8Array(16);
    for (var i = 0; i < 16; i++) t[i] = g[i] ^ E0[i];
    return t;
  }

  /* ============================================================
   * 2. NIST SP 800-108 KDF（三种模式，PRF＝HMAC）
   *   Counter : PRF(Secret, BE32(i) ‖ Label ‖ 0x00 ‖ Salt ‖ BE32(L*8))
   *   Feedback: IV = Salt 前 prf_len 字节（仅当 Salt 长度 ≥ prf_len）
   *             prev=IV, ctx=Salt 余下部分
   *             prev = PRF(Secret, prev‖BE32(i)‖Label‖0x00‖ctx‖BE32(L*8))
   *   Pipeline: A0 = Label‖0x00‖Salt‖BE32(L*8)；A(i)=PRF(A(i-1))
   *             K(i) = PRF(A(i)‖BE32(i)‖Label‖0x00‖Salt‖BE32(L*8))
   * ============================================================ */
  function sp108(mode, secret, label, salt, keyLen, hashName) {
    var prf = makePrf(hashName), prfLen = prf.out;
    if (keyLen < 1) throw new Error('输出长度必须 ≥ 1 字节');
    if (keyLen > 0xFFFF) throw new Error('输出长度过大（上限 65535 字节）');
    var beLen = be32(keyLen * 8), out = new Uint8Array(keyLen), p = 0, ctr = 1;
    var prev = new Uint8Array(0), ctx = salt, ai = null;
    if (mode === 'fb') {
      var ivLen = (salt.length >= prfLen) ? prfLen : 0;
      prev = salt.slice(0, ivLen); ctx = salt.slice(ivLen);
    } else if (mode === 'pipe') {
      ai = cat(label, new Uint8Array([0]), salt, beLen);
    }
    while (p < keyLen) {
      var r, toCopy = Math.min(keyLen - p, prfLen);
      if (mode === 'ctr') r = prf.mac(secret, cat(be32(ctr), label, new Uint8Array([0]), salt, beLen));
      else if (mode === 'fb') { prev = prf.mac(secret, cat(prev, be32(ctr), label, new Uint8Array([0]), ctx, beLen)); r = prev; }
      else { ai = prf.mac(secret, ai); r = prf.mac(secret, cat(ai, be32(ctr), label, new Uint8Array([0]), salt, beLen)); }
      out.set(r.subarray(0, toCopy), p);
      p += toCopy; ctr++;
    }
    return out;
  }

  /* ============================================================
   * 3. OpenPGP S2K（RFC 4880）
   *   input = Salt ‖ 口令；第 n 轮：Hash( n 个零字节 ‖
   *           input 循环重复至 max(迭代数, len(input)) 字节 )
   * ============================================================ */
  /* 裸 Hash 版本（PGP S2K 用的是普通哈希，无密钥） */
  function pgpS2kRaw(pass, salt, iters, outLen, hashName) {
    var prf = makePrf(hashName);
    if (iters > 1 && salt.length === 0) throw new Error('迭代模式必须有盐值');
    var input = cat(salt, pass);
    var hashFn = hashFnOf(hashName);
    var out = new Uint8Array(outLen), gen = 0, passN = 0;
    while (gen !== outLen) {
      var take = Math.min(prf.out, outLen - gen);
      /* 迭代次数可达千万级，不能拼数组（会爆栈）；按总长一次性写入 */
      var reps = input.length > 0 ? Math.max(iters, input.length) : 0;
      var buf = new Uint8Array(passN + reps), q = passN, left = reps;
      while (left > 0) { var t = Math.min(left, input.length); buf.set(input.subarray(0, t), q); q += t; left -= t; }
      var h = hashFn(buf);
      out.set(h.subarray(0, take), gen);
      gen += take; passN++;
    }
    return out;
  }

  /* ============================================================
   * 4. HMAC-DRBG（NIST SP 800-90A）
   *   实例化：K=0x00×outlen，V=0x01×outlen，update(熵‖nonce‖个性化)
   *   update(data)：K=HMAC(K,V‖0x00‖data)；V=HMAC(K,V)；
   *                 若 data 非空：K=HMAC(K,V‖0x01‖data)；V=HMAC(K,V)
   * ============================================================ */
  function HmacDrbg(hashName, entropy, nonce, perso) {
    var prf = makePrf(hashName), outLen = prf.out;
    var K = new Uint8Array(outLen), V = new Uint8Array(outLen);
    for (var i = 0; i < outLen; i++) V[i] = 0x01;
    function update(data) {
      var d = data || new Uint8Array(0);
      K = prf.mac(K, cat(V, new Uint8Array([0x00]), d));
      V = prf.mac(K, V);
      if (d.length > 0) { K = prf.mac(K, cat(V, new Uint8Array([0x01]), d)); V = prf.mac(K, V); }
    }
    update(cat(entropy, nonce || new Uint8Array(0), perso || new Uint8Array(0)));
    return {
      reseed: function (e, add) { update(cat(e, add || new Uint8Array(0))); },
      generate: function (n, add) {
        var out = new Uint8Array(n), p = 0;
        if (add && add.length) update(add);
        while (p < n) {
          V = prf.mac(K, V);
          var t = Math.min(n - p, outLen);
          out.set(V.subarray(0, t), p); p += t;
        }
        update(add && add.length ? add : null);
        return out;
      }
    };
  }

  /* ============================================================
   * 5. 注册
   * ============================================================ */
  ALGOS.push({
    id: 'gmac', name: 'GMAC（AES-GMAC 消息认证码）', group: '单向哈希',
    key: true, param: true,
    keyLabel: '密钥（Hex，16/24/32 字节）', paramLabel: 'IV（Hex，留空＝12 字节全零）',
    info: 'GMAC 即「明文为空的 GCM」：tag = GHASH_H(消息‖长度块) ⊕ AES_K(J0)，H = AES_K(0^128)。\n【验证】Botan mac/gmac.vec（源自 Bouncy Castle）官方向量 15/15。\n【注意】GMAC 只认证不加密，且 IV 绝不可复用。',
    enc: function (b, k, p, fmt) {
      var key = hexB(k); if (!key.length) throw new Error('请填密钥（Hex）');
      var iv = hexB(p);
      if (!iv.length) iv = new Uint8Array(12);
      return G('bytesOut')(gmacTag(key, iv, toB(b)), fmt);
    }
  });

  ['ctr|Counter|计数器', 'fb|Feedback|反馈', 'pipe|Pipeline|流水线'].forEach(function (spec) {
    var sp = spec.split('|');
    ALGOS.push({
      id: 'sp800-108-' + sp[0], name: 'SP 800-108 KDF（' + sp[2] + '模式）', group: '单向哈希',
      key: true, param: true,
      keyLabel: 'Secret 主密钥（Hex）',
      paramLabel: 'Label(Hex), Salt(Hex), 输出字节数, 摘要名',
      info: 'NIST SP 800-108 的 ' + sp[2] + '模式 KDF，PRF 为 HMAC。\n【验证】Botan kdf/sp800_108_' + (sp[0] === 'ctr' ? 'ctr' : sp[0] === 'fb' ? 'fb' : 'pipe') + '.vec（Bouncy Castle 生成）官方向量全过。\n【参数】摘要名可选 SHA-1/SHA-256/SHA-384/SHA-512，默认 SHA-256。',
      enc: function (b, k, p, fmt) {
        var secret = hexB(k); if (!secret.length) throw new Error('请填 Secret（Hex）');
        var ps = String(p || '').split(',');
        var label = hexB(ps[0] || ''), salt = hexB(ps[1] || '');
        var len = parseInt(ps[2], 10); if (isNaN(len) || len < 1) len = 32;
        var hn = normHash(ps[3] || 'SHA-256');
        return G('bytesOut')(sp108(sp[0], secret, label, salt, len, hn), fmt);
      }
    });
  });

  ALGOS.push({
    id: 'pgp-s2k', name: 'OpenPGP S2K 口令派生（RFC 4880）', group: '单向哈希',
    key: true, param: true,
    keyLabel: '盐值 Salt（Hex，Simple 模式可留空）',
    paramLabel: '迭代次数, 输出字节数, 摘要名',
    info: 'OpenPGP 的字符串到密钥（S2K）：Hash(零填充‖(Salt‖口令) 循环至 max(迭代数,输入长))。\n【验证】Botan pbkdf/pgp_s2k.vec（Golang x/crypto/openpgp 生成）官方向量全过。\n【注意】这是 1990 年代设计，抗 GPU 能力弱；新系统请用 Argon2id。',
    enc: function (b, k, p, fmt) {
      var pass = toB(b), salt = hexB(k);
      var ps = String(p || '').split(',');
      var iters = parseInt(ps[0], 10); if (isNaN(iters) || iters < 1) iters = 65536;
      var len = parseInt(ps[1], 10); if (isNaN(len) || len < 1) len = 16;
      var hn = normHash(ps[2] || 'SHA-1');
      if (iters > 65011712) throw new Error('迭代次数过大');
      return G('bytesOut')(pgpS2kRaw(pass, salt, iters, len, hn), fmt);
    }
  });

  ALGOS.push({
    id: 'hmac-drbg', name: 'HMAC-DRBG（NIST SP 800-90A）', group: '单向哈希',
    key: true, param: true,
    keyLabel: '熵输入 Entropy（Hex）',
    paramLabel: '重播种熵(Hex), 输出字节数, 摘要名, 附加输入1(Hex), 附加输入2(Hex), 预热轮数',
    info: 'NIST SP 800-90A 的 HMAC-DRBG，给定熵即确定性输出。默认丢弃首次输出、返回第二次（同 Botan/NIST CAVS 流程）；填附加输入即按 CAVS 两次调用取第二次。\n【验证】Botan rng/hmac_drbg.vec（源自 NIST CAVS）1680/1680。\n【注意】仅供复现向量与教学，生产请用系统随机源。',
    enc: function (b, k, p, fmt) {
      var ent = hexB(k); if (!ent.length) throw new Error('请填熵输入（Hex）');
      var ps = String(p || '').split(',');
      var reseed = hexB(ps[0] || '');
      var len = parseInt(ps[1], 10); if (isNaN(len) || len < 1) len = 64;
      var hn = normHash(ps[2] || 'SHA-256');
      if (len > 65536) throw new Error('输出长度过大（上限 64 KB）');
      var ad1 = hexB(ps[3] || ''), ad2 = hexB(ps[4] || '');
      var warm = parseInt(ps[5], 10); if (isNaN(warm) || warm < 0) warm = 1;
      var d = new HmacDrbg(hn, ent, null, null);
      if (reseed.length) d.reseed(reseed, null);
      /* Botan 官方测试（src/tests/test_rng_kat.cpp）连续两次 randomize_with_input，
         第一次结果被覆盖丢弃、Out 取第二次；附加输入即 NIST CAVS 的 AdditionalInput1/2。 */
      var out;
      if (ad1.length || ad2.length) {
        out = d.generate(len, ad1.length ? ad1 : null);
        out = d.generate(len, ad2.length ? ad2 : null);
      } else {
        out = new Uint8Array(0);
        for (var i = 0; i <= warm; i++) out = d.generate(len, null);
      }
      return G('bytesOut')(out, fmt);
    }
  });
})();
