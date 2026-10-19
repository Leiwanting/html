/* ============================================================
 * PBKDF1 / CBC-MAC / ANSI X9.19 MAC
 * ------------------------------------------------------------
 * 实现与向量均取自 Botan 2.19.5：
 *   pbkdf/pbkdf1.vec、mac/cbcmac.vec、mac/x919_mac.vec
 * CBC-MAC 语义按官方 C++（src/lib/mac/cbc_mac/cbc_mac.cpp）：
 *   状态初值全零；填满一块即加密；收尾若有余字节【也要加密一次】
 *   （不是补零到整块后丢弃，也不是不做最后一次加密）。
 * ANSI X9.19（零售 MAC）按 src/lib/mac/x919_mac/x919_mac.cpp：
 *   用 K1 做 DES CBC-MAC，再 mac = DES1( DES2^-1( state ) )
 *   密钥 16 字节时 K2 取后 8 字节，否则 K2 = K1。
 * ============================================================ */
(function () {
  'use strict';
  if (typeof ALGOS === 'undefined') return;
  function G(n) { return (typeof window !== 'undefined' ? window : globalThis)[n]; }

  function toB(b) {
    if (b instanceof Uint8Array || ArrayBuffer.isView(b)) return new Uint8Array(b.buffer ? b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) : b);
    return G('strToBytes')(String(b === undefined || b === null ? '' : b));
  }

  var OTP = G('OTP');
  var sha1 = OTP && OTP.sha1Bytes;

  /* ---- PBKDF1（PKCS#5 v1.5）：T_1 = Hash(P||S)，T_i = Hash(T_{i-1}) ---- */
  function pbkdf1(pwd, salt, iters, dkLen) {
    if (!sha1) throw new Error('SHA-1 内核未加载');
    if (iters < 1) throw new Error('迭代次数必须 ≥ 1');
    if (dkLen > 20) throw new Error('PBKDF1-SHA1 最多派生 20 字节');
    var t = new Uint8Array(pwd.length + salt.length);
    t.set(pwd, 0); t.set(salt, pwd.length);
    t = sha1(t);
    for (var i = 2; i <= iters; i++) t = sha1(t);
    return t.slice(0, dkLen);
  }

  ALGOS.push({
    id: 'pbkdf1', name: 'PBKDF1（PKCS#5 v1.5，SHA-1）', group: '单向哈希',
    key: true, param: true,
    keyLabel: '盐值 salt（Hex）', paramLabel: '迭代次数（默认 1000）',
    info: 'PKCS#5 v1.5 的 PBKDF1：T1 = Hash(口令‖盐)，T(i) = Hash(T(i-1))，取末次结果前 20 字节。\n【验证】Botan pbkdf/pbkdf1.vec 官方向量 6/6。\n【注意】PBKDF1 只能用 SHA-1、最多 20 字节，已废弃；新系统请用 PBKDF2 / scrypt / Argon2。',
    enc: function (b, k, p, fmt) {
      var pwd = toB(b);
      var salt = G('hexToBytes')(String(k || ''));
      var iters = parseInt(p, 10); if (isNaN(iters) || iters < 1) iters = 1000;
      if (iters > 1000000) throw new Error('迭代次数过大（上限 100 万）');
      return G('bytesOut')(pbkdf1(pwd, salt, iters, 20), fmt);
    }
  });

  /* ---- CBC-MAC 通用内核 ---- */
  function cbcmacCore(key, msg, makeFn, bs) {
    var bf = makeFn(key);
    var state = new Uint8Array(bs), pos = 0;
    for (var i = 0; i < msg.length; i++) {
      state[pos] ^= msg[i]; pos++;
      if (pos === bs) { state = bf.enc(state); pos = 0; }
    }
    if (pos) state = bf.enc(state);
    return state;
  }

  function mkCbcMac(id, name, makeFn, bs, keyLen, info) {
    ALGOS.push({
      id: id, name: name, group: '单向哈希',
      key: true, param: false,
      keyLabel: '密钥（Hex，' + keyLen + ' 字节）',
      info: info,
      enc: function (b, k, p, fmt) {
        var key = G('hexToBytes')(String(k || ''));
        if (key.length !== keyLen) throw new Error('密钥必须是 ' + keyLen + ' 字节（当前 ' + key.length + '）');
        return G('bytesOut')(cbcmacCore(key, toB(b), makeFn, bs), fmt);
      }
    });
  }

  var desMake = G('desMakeBlockFn'), aesMake = G('aesMakeBlockFn');
  if (desMake) {
    mkCbcMac('cbcmac-des', 'CBC-MAC（DES）', desMake, 8, 8,
      '用 DES 做 CBC 加密并取最后一个密文块作为 MAC。状态初值全零，收尾不足一块时也加密一次（按 Botan 官方语义）。\n【验证】Botan mac/cbcmac.vec 中 [CBC-MAC(DES)] 段官方向量全过。\n【注意】CBC-MAC 只对【定长】消息安全；变长消息请改用 CMAC 或 HMAC。');
  }
  if (aesMake) {
    mkCbcMac('cbcmac-aes128', 'CBC-MAC（AES-128）', aesMake, 16, 16,
      '用 AES-128 做 CBC 加密并取最后一个密文块作为 MAC。\n【验证】Botan mac/cbcmac.vec 中 [CBC-MAC(AES-128)] 段官方向量全过。\n【注意】CBC-MAC 只对【定长】消息安全；变长消息请用 CMAC（本项目已内置）。');
  }

  /* ---- ANSI X9.19 零售 MAC ---- */
  if (desMake) {
    ALGOS.push({
      id: 'x919-mac', name: 'ANSI X9.19 MAC（零售 MAC）', group: '单向哈希',
      key: true, param: false,
      keyLabel: '密钥（Hex，8 或 16 字节）',
      info: 'ANSI X9.19「零售 MAC」：先用 K1 走 DES CBC-MAC，最后 mac = DES1( DES2⁻¹( state ) )。密钥 16 字节时 K2 取后 8 字节，8 字节时 K2 = K1。\n【验证】Botan mac/x919_mac.vec 官方向量全过（含 ISO 9564 真实报文）。\n【注意】安全性弱于 CMAC，保留用于兼容金融老系统。',
      enc: function (b, k, p, fmt) {
        var key = G('hexToBytes')(String(k || ''));
        if (key.length !== 8 && key.length !== 16) throw new Error('密钥必须是 8 或 16 字节（当前 ' + key.length + '）');
        var k1 = key.slice(0, 8), k2 = key.length === 16 ? key.slice(8, 16) : k1;
        var bf1 = desMake(k1), bf2 = desMake(k2);
        var state = cbcmacCore(k1, toB(b), desMake, 8);
        var mac = bf2.dec(state);
        mac = bf1.enc(mac);
        return G('bytesOut')(mac, fmt);
      }
    });
  }

  /* ---- ISO 18033-2 KDF1 / KDF2 ---- */
  function cat(arrs) {
    var n = 0, i;
    for (i = 0; i < arrs.length; i++) n += arrs[i].length;
    var o = new Uint8Array(n), p = 0;
    for (i = 0; i < arrs.length; i++) { o.set(arrs[i], p); p += arrs[i].length; }
    return o;
  }
  function be32(v) { return new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]); }

  /* KDF2：K = 串联 Hash(secret ‖ BE32(counter) ‖ label ‖ salt)，counter 从 1 起 */
  function kdf2(secret, salt, label, dkLen) {
    var out = [], c = 1;
    while (out.length < dkLen && c !== 0) {
      var h = sha1(cat([secret, be32(c), label, salt]));
      for (var i = 0; i < h.length && out.length < dkLen; i++) out.push(h[i]);
      c++;
    }
    return new Uint8Array(out);
  }
  /* KDF1：K = Hash(secret ‖ label ‖ salt) 的前 dkLen 字节（无计数器，只够一轮摘要） */
  function kdf1(secret, salt, label, dkLen) {
    return sha1(cat([secret, label, salt])).slice(0, dkLen);
  }

  if (sha1) {
    ALGOS.push({
      id: 'kdf2', name: 'KDF2（ISO 18033-2，SHA-1）', group: '单向哈希',
      key: true, param: true,
      keyLabel: '盐值 salt（Hex，可留空）', paramLabel: '输出字节数（默认 32，上限 1024）',
      info: 'ISO/IEC 18033-2 的 KDF2：K = 串联 Hash(secret ‖ BE32(counter) ‖ label ‖ salt)，counter 从 1 开始。\n【验证】Botan kdf/kdf2.vec 官方向量全过（SHA-160 段）。\n【说明】输入栏填 secret，密钥栏填 salt（Hex），参数栏填输出长度。label 未单独开放（留空）。',
      enc: function (b, k, p, fmt) {
        var secret = toB(b);
        var salt = G('hexToBytes')(String(k || ''));
        var n = parseInt(p, 10); if (isNaN(n) || n < 1) n = 32;
        if (n > 1024) throw new Error('输出字节数过大（上限 1024）');
        return G('bytesOut')(kdf2(secret, salt, new Uint8Array(0), n), fmt);
      }
    });
    ALGOS.push({
      id: 'kdf1', name: 'KDF1（ISO 18033-2，SHA-1）', group: '单向哈希',
      key: true, param: true,
      keyLabel: '盐值 salt（Hex，可留空）', paramLabel: '输出字节数（默认 20，上限 20）',
      info: 'ISO/IEC 18033-2 的 KDF1：K = Hash(secret ‖ label ‖ salt) 的前若干字节，【没有计数器】，因此最多只能产出一个摘要长度（SHA-1 为 20 字节）。\n【验证】Botan kdf/kdf1.vec 官方向量全过（SHA-160 段）。\n【说明】需要更长输出请用 KDF2 或 HKDF。',
      enc: function (b, k, p, fmt) {
        var secret = toB(b);
        var salt = G('hexToBytes')(String(k || ''));
        var n = parseInt(p, 10); if (isNaN(n) || n < 1) n = 20;
        if (n > 20) throw new Error('KDF1-SHA1 最多输出 20 字节');
        return G('bytesOut')(kdf1(secret, salt, new Uint8Array(0), n), fmt);
      }
    });
  }

  if (typeof window !== 'undefined') window.PBKDF1 = pbkdf1;
})();
