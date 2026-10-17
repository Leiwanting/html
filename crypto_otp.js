/* ============================================================
 * HOTP / TOTP —— 一次性口令（RFC 4226 / RFC 6238）
 *
 * 为什么这里要自带一份 SHA-1：工具箱里的 SHA-1 走浏览器原生 crypto.subtle，
 * 是异步的；而 OTP 必须同步算（RFC 4226 向量的主力就是 HMAC-SHA-1）。
 * SHA-256 / SHA-512 复用 crypto_modes.js 的 hmacBytesSync，不重复造轮子。
 *
 * 密钥（secret）三态解析，优先级：hex: > raw: > Base32（OTP 行业默认）
 *   —— 这一条不能省：RFC 4226 的 secret 是 ASCII "12345678901234567890"，
 *      它本身也全由 Base32 合法字符组成，若不做前缀区分会被静默误判。
 *
 * 向量来源：RFC 4226 附录 D、RFC 6238 附录 B（均由 pyotp 2.10 交叉复算一致）
 * ============================================================ */
(function () {
  /* ---------- SHA-1（FIPS 180-1）同步实现 ---------- */
  function sha1Bytes(msg) {
    var H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    var ml = msg.length * 8;
    /* ⚠ 总长必须是 ceil((len+9)/64)*64：len+1(0x80)+8(长度字段)。
       旧写法 floor((len+9)/64)+1 在 len ≡ 55 (mod 64) 时会【多算一整块】，
       例如 len=55（55+9=64 正好一块，无需补块）被算成 128，
       结果静默全错——HOTP/TOTP 走 HMAC 时内部长度是 64+len，
       所以消息长度 ≡ 55 (mod 64) 的 TOTP 会验不上。 */
    var total = Math.ceil((msg.length + 9) / 64) * 64;
    var buf = new Uint8Array(total);
    buf.set(msg);
    buf[msg.length] = 0x80;
    var dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, Math.floor(ml / 4294967296));
    dv.setUint32(total - 4, ml >>> 0);
    var W = new Array(80);
    for (var off = 0; off < total; off += 64) {
      for (var t = 0; t < 16; t++) W[t] = dv.getUint32(off + t * 4);
      for (t = 16; t < 80; t++) {
        var v = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
        W[t] = (v << 1) | (v >>> 31);
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f, k, tmp;
      for (t = 0; t < 80; t++) {
        if (t < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (t < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        tmp = (((a << 5) | (a >>> 27)) + f + e + k + W[t]) >>> 0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = tmp;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0;
      H[3] = (H[3] + d) >>> 0; H[4] = (H[4] + e) >>> 0;
    }
    var out = new Uint8Array(20);
    var odv = new DataView(out.buffer);
    for (var i = 0; i < 5; i++) odv.setUint32(i * 4, H[i]);
    return out;
  }

  /* ---------- 通用 HMAC ---------- */
  function hmacLocal(hashFn, blockSize, key, msg) {
    var k = key;
    if (k.length > blockSize) k = hashFn(k);
    var ipad = new Uint8Array(blockSize), opad = new Uint8Array(blockSize);
    for (var i = 0; i < blockSize; i++) {
      var kb = i < k.length ? k[i] : 0;
      ipad[i] = kb ^ 0x36; opad[i] = kb ^ 0x5c;
    }
    return hashFn(concatBytes(opad, hashFn(concatBytes(ipad, msg))));
  }
  function otpHmac(alg, key, msg) {
    if (alg === 'sha1') return hmacLocal(sha1Bytes, 64, key, msg);
    if (alg === 'sha256') return hmacLocal(sha256BytesSync, 64, key, msg);
    if (alg === 'sha512') return hmacLocal(sha512Digest, 128, key, msg);
    throw new Error('不支持的算法：' + alg + '（可选 sha1 / sha256 / sha512）');
  }

  /* ---------- Base32（RFC 4648，无填充） ---------- */
  var B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function b32decode(s) {
    s = String(s).toUpperCase().replace(/[\s=]/g, '');
    var bits = 0, acc = 0, out = [];
    for (var i = 0; i < s.length; i++) {
      var v = B32.indexOf(s[i]);
      if (v < 0) throw new Error('Base32 含非法字符：' + s[i]);
      acc = (acc << 5) | v; bits += 5;
      if (bits >= 8) { out.push((acc >> (bits - 8)) & 0xff); bits -= 8; }
    }
    return new Uint8Array(out);
  }
  function b32encode(b) {
    var s = '', bits = 0, acc = 0;
    for (var i = 0; i < b.length; i++) {
      acc = (acc << 8) | b[i]; bits += 8;
      while (bits >= 5) { s += B32[(acc >> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits) s += B32[(acc << (5 - bits)) & 31];
    return s;
  }

  /* ---------- secret 解析：hex: / raw: / Base32 ---------- */
  function parseSecret(s) {
    s = String(s || '').trim();
    if (!s) throw new Error('请在密钥栏填写共享密钥（Base32，或 hex:… / raw:…）');
    if (/^hex:/i.test(s)) {
      var h = s.slice(4).replace(/\s/g, '');
      if (!/^[0-9a-fA-F]+$/.test(h) || h.length % 2) throw new Error('hex: 后需偶数个十六进制字符');
      return hexToBytes(h);
    }
    if (/^raw:/i.test(s)) return strToBytes(s.slice(4));
    return b32decode(s);
  }

  /* ---------- 动态截断（RFC 4226 §5.4） ---------- */
  function truncate(mac, digits) {
    var off = mac[mac.length - 1] & 0x0f;
    var bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
    var mod = 1;
    for (var i = 0; i < digits; i++) mod *= 10;
    var code = String(bin % mod);
    while (code.length < digits) code = '0' + code;
    return code;
  }
  function hotpAt(secret, counter, digits, alg) {
    var msg = new Uint8Array(8);
    var dv = new DataView(msg.buffer);
    dv.setUint32(0, Math.floor(counter / 4294967296));
    dv.setUint32(4, counter >>> 0);
    return truncate(otpHmac(alg, secret, msg), digits);
  }
  function parseAlg(x, def) {
    var a = String(x || '').trim().toLowerCase();
    if (!a) return def;
    if (a !== 'sha1' && a !== 'sha256' && a !== 'sha512') throw new Error('算法只支持 sha1 / sha256 / sha512');
    return a;
  }
  function parseDigits(x, def) {
    var d = String(x || '').trim();
    if (!d) return def;
    d = parseInt(d, 10);
    if (!(d >= 6 && d <= 8)) throw new Error('位数须为 6~8');
    return d;
  }

  var G = '单向哈希';

  reg({
    id: 'hotp', name: 'HOTP 一次性口令（RFC 4226）', group: G, key: true, param: true,
    keyLabel: '共享密钥（Base32，或 hex:… / raw:…）',
    paramLabel: '计数器[，位数 6~8[，算法 sha1/sha256/sha512]]',
    info: '基于计数器的事件型一次性口令（RFC 4226）。每认证一次计数器 +1，服务端需容忍少量超前窗口。密钥优先按 Base32 解析；原样 ASCII 请用 raw: 前缀，十六进制用 hex: 前缀。',
    enc: function (b, k, p) {
      var sec = parseSecret(k);
      var parts = String(p || '').split(',');
      var counter = parseInt(String(parts[0] || '').trim(), 10);
      if (isNaN(counter) || counter < 0) throw new Error('参数栏首位须填非负计数器');
      var digits = parseDigits(parts[1], 6);
      var alg = parseAlg(parts[2], 'sha1');
      return hotpAt(sec, counter, digits, alg);
    },
    dec: function (input, k, p) {
      /* 反向当作"校验"用：把待验口令粘到输入栏，与计算值比对 */
      var sec = parseSecret(k);
      var parts = String(p || '').split(',');
      var counter = parseInt(String(parts[0] || '').trim(), 10);
      if (isNaN(counter) || counter < 0) throw new Error('参数栏首位须填非负计数器');
      var digits = parseDigits(parts[1], 6);
      var alg = parseAlg(parts[2], 'sha1');
      var want = hotpAt(sec, counter, digits, alg);
      var got = String(input || '').trim();
      return (got === want ? '✓ 匹配' : '✗ 不匹配') + '（期望 ' + want + '，输入 ' + (got || '空') + '）';
    }
  });

  reg({
    id: 'totp', name: 'TOTP 时间型口令（RFC 6238）', group: G, key: true, param: true,
    keyLabel: '共享密钥（Base32，或 hex:… / raw:…）',
    paramLabel: '可空；或 位数[，算法[，步长秒[，Unix 时间]]]',
    info: '基于时间的一次性口令（RFC 6238），Google/微软验证器即此。默认 6 位、30 秒步长、HMAC-SHA1。参数栏留空即取当前时间；填 Unix 时间可复现确定值。',
    enc: function (b, k, p) {
      var sec = parseSecret(k);
      var parts = String(p || '').split(',');
      var digits = parseDigits(parts[0], 6);
      var alg = parseAlg(parts[1], 'sha1');
      var period = parseInt(String(parts[2] || '').trim(), 10);
      if (isNaN(period) || period <= 0) period = 30;
      var t = parseInt(String(parts[3] || '').trim(), 10);
      if (isNaN(t) || t < 0) t = Math.floor(Date.now() / 1000);
      var counter = Math.floor(t / period);
      var code = hotpAt(sec, counter, digits, alg);
      var left = period - (t % period);
      return code + '\n（计数器 T=' + counter + '，本窗口剩余 ' + left + ' 秒）';
    },
    dec: function (input, k, p) {
      var sec = parseSecret(k);
      var parts = String(p || '').split(',');
      var digits = parseDigits(parts[0], 6);
      var alg = parseAlg(parts[1], 'sha1');
      var period = parseInt(String(parts[2] || '').trim(), 10);
      if (isNaN(period) || period <= 0) period = 30;
      var t = parseInt(String(parts[3] || '').trim(), 10);
      if (isNaN(t) || t < 0) t = Math.floor(Date.now() / 1000);
      var c = Math.floor(t / period);
      var got = String(input || '').trim();
      /* 时间型必须容忍前后各一个窗口的时钟偏差 */
      var win = [c - 1, c, c + 1].map(function (x) { return hotpAt(sec, x, digits, alg); });
      return (win.indexOf(got) >= 0 ? '✓ 匹配' : '✗ 不匹配') + '（当前窗口 ' + win[1] + '，已容忍 ±1 窗口）';
    }
  });

  globalThis.OTP = {
    sha1Bytes: sha1Bytes, otpHmac: otpHmac, hotpAt: hotpAt,
    b32encode: b32encode, b32decode: b32decode, parseSecret: parseSecret,
    truncate: truncate
  };
})();
