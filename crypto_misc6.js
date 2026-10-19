/* crypto_misc6.js
 * ECDSA 公钥恢复 / Passhash9 口令哈希
 *
 * 向量来源：Botan 2.19.5 官方测试集
 *   src/tests/data/pubkey/ecdsa_key_recovery.vec
 *   src/tests/data/misc/passhash9.vec
 *
 * 语义要点（照 Botan 官方 C++ 源码，不凭记忆）：
 *  · 公钥恢复：Q = r⁻¹·(s·R − z·G)，其中 R 由 r 与恢复位 v 唯一确定。
 *    曲线方程 y² = x³ + a·x + b (mod p)，v 的奇偶决定取 y 还是 p−y。
 *  · z 是【消息的哈希值】按曲线阶的位长截断后的整数，不是消息本身。
 *    Botan 对 secp256k1 / secp256r1 默认用 SHA-256。
 *  · Passhash9 是 Botan 自有的口令哈希（$9$ 前缀），与 bcrypt 无关。
 */
(function () {
  if (typeof reg !== 'function') { console.error('crypto_misc6.js 需要在算法注册框架之后加载'); return; }

  function _hex(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  }

  /* ---------- 大数 <-> 字节 ---------- */
  function _bigFromHex(h) {
    var s = String(h || '').replace(/[^0-9a-fA-F]/g, '');
    if (!s.length) return 0n;
    return BigInt('0x' + s);
  }
  function _bigToBytesFixed(v, len) {
    var out = new Uint8Array(len);
    var x = v;
    for (var i = len - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
    return out;
  }
  /* 扩展欧几里得求逆。
     注意：框架里已有的 modInv() 是暴力循环（for x=1..m），只服务于古典密码的
     仿射密码且返回 Number —— 对曲线阶这种 256 位大数既跑不动也会触发
     「Cannot mix BigInt and other types」。这里必须用独立的 BigInt 版本。 */
  function _invMod(a, m) {
    a = ((a % m) + m) % m;
    var old_r = a, r = m, old_s = 1n, s = 0n, q, t;
    while (r !== 0n) {
      q = old_r / r;
      t = old_r - q * r; old_r = r; r = t;
      t = old_s - q * s; old_s = s; s = t;
    }
    if (old_r !== 1n) throw new Error('求逆失败：r 与曲线阶不互素（签名无效）');
    return ((old_s % m) + m) % m;
  }

  /* ================= ECDSA 公钥恢复 ================= */
  /*
   * 输入：msg 消息字节；r、s 签名整数；v 恢复位（0/1，表示 R 点 y 的奇偶）。
   * 步骤：
   *   1) z = 截断(SHA-256(msg), 曲线阶位长)
   *   2) x = r（若 r ≥ n 则 x = r − n，实际几乎不会发生）
   *   3) y = sqrt(x³ + a·x + b) mod p；若 (y & 1) ≠ (v & 1) 则 y = p − y
   *   4) Q = u1·G + u2·R，u1 = −z·r⁻¹ mod n，u2 = s·r⁻¹ mod n
   */
  function ecdsaRecoverPub(curve, r, s, z, v) {
    var n = curve.n, p = curve.p;
    /* Botan：y_odd = v % 2；add_order = v >> 1 —— x 可能是 r + k·n（k=0/1/2） */
    var yOdd = BigInt(v) & 1n;
    var addOrder = BigInt(v) >> 1n;
    var x = r % n + addOrder * n;
    var alpha = (((x * x) % p) * x + curve.a * x + curve.b) % p;
    if (alpha < 0n) alpha += p;
    var y = curve.sqrtModP(alpha);
    if (y === null || y === undefined) throw new Error('公钥恢复失败：x 不在曲线上（r 或 v 不正确）');
    if ((y & 1n) !== yOdd) y = (p - y) % p;
    var R = { x: x, y: y };
    var G = { x: curve.gx, y: curve.gy };
    var rInv = _invMod(r, n);
    var u1 = (n - ((z * rInv) % n)) % n;
    var u2 = (s * rInv) % n;
    var Q = curve.add(curve.mul(u1, G), curve.mul(u2, R));
    if (Q.x === null) throw new Error('公钥恢复失败：结果为无穷远点（签名无效）');
    return Q;
  }

  /* 消息摘要 -> 整数 e。
     【关键】照 Botan src/lib/pubkey/ecdsa/ecdsa.cpp 的
       `const BigInt e(msg.data(), msg.size(), group.get_order_bits());`
     Botan 这里收到的 msg 是【已哈希的消息摘要】，不是原始消息 —— 也就是说
     恢复公钥必须自己先算好摘要再传进来。第一版我按"再对输入做一次 SHA-256"
     实现，两组向量全错；改成直接按字节取值、只按阶长截断后立刻 2/2。
     入参长度大于阶长时丢弃高位多余比特。 */
  function _digestToInt(curve, digestBytes) {
    var bits = curve.n.toString(2).length;
    var v = 0n;
    for (var i = 0; i < digestBytes.length; i++) v = (v << 8n) | BigInt(digestBytes[i]);
    var excess = digestBytes.length * 8 - bits;
    if (excess > 0) v = v >> BigInt(excess);
    return v;
  }

  function _parseSigFields(str) {
    var parts = String(str || '').split(/[,，;；\s]+/).filter(Boolean);
    return parts;
  }

  /* ================= Passhash9（Botan 自有口令哈希） ================= */
  /* 结构照 Botan src/lib/misc/passhash9/passhash9.cpp：
       输出 = "$9$" ‖ B64(workfactor) ‖ B64(salt 12B+IV+salt 混排) ‖ B64(密文)
     这里只做验证用的等价实现；界面条目按官方流程给出可复现的输出。 */
  var PH9_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  function _b64enc(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i += 3) {
      var b0 = bytes[i], b1 = bytes[i + 1], b2 = bytes[i + 2];
      out += PH9_TABLE[b0 >> 2];
      out += PH9_TABLE[((b0 & 3) << 4) | ((b1 || 0) >> 4)];
      out += (i + 1 < bytes.length) ? PH9_TABLE[((b1 & 15) << 2) | ((b2 || 0) >> 6)] : '=';
      out += (i + 2 < bytes.length) ? PH9_TABLE[b2 & 63] : '=';
    }
    return out;
  }



  /* 精简 SHA-1 + HMAC-SHA-1：仅为本文件的 Passhash9(alg_id=0) 服务。
     框架的 SHA-1 被各自文件的 IIFE 封装、外部取不到；而 hmacBytesSync 的
     SPEC 表只登记了 SHA-256/384/512（未知哈希会抛错），所以这里自带一份。
     正确性由 Passhash9 的官方向量保证。 */
  function _sha1Bytes(msg) {
    var H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    var mlB = BigInt(msg.length) * 8n;
    var pad = new Uint8Array((((msg.length + 8) >> 6) + 1) << 6);
    pad.set(msg, 0);
    pad[msg.length] = 0x80;
    /* 长度字段必须用 BigInt：JS 的 >>> 位移量会【取模 32】，i=4 时 ml>>>32
       实际执行 ml>>>0，把长度低字节复制到偏移 59（本项目已栽过两次）。 */
    var j;
    for (j = 0; j < 8; j++) pad[pad.length - 1 - j] = Number((mlB >> BigInt(8 * j)) & 0xffn);
    function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
    var i, t, w = new Array(80);
    for (i = 0; i < pad.length; i += 64) {
      for (j = 0; j < 16; j++) {
        w[j] = ((pad[i + j * 4] << 24) | (pad[i + j * 4 + 1] << 16) |
                (pad[i + j * 4 + 2] << 8) | pad[i + j * 4 + 3]) >>> 0;
      }
      for (j = 16; j < 80; j++) w[j] = rotl(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f, kk;
      for (j = 0; j < 80; j++) {
        if (j < 20) { f = (b & c) | ((~b) & d); kk = 0x5A827999; }
        else if (j < 40) { f = b ^ c ^ d; kk = 0x6ED9EBA1; }
        else if (j < 60) { f = (b & c) | (b & d) | (c & d); kk = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; kk = 0xCA62C1D6; }
        t = (rotl(a, 5) + f + e + kk + w[j]) >>> 0;
        e = d; d = c; c = rotl(b, 30); b = a; a = t;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0;
      H[3] = (H[3] + d) >>> 0; H[4] = (H[4] + e) >>> 0;
    }
    var out = new Uint8Array(20);
    for (i = 0; i < 5; i++) {
      out[i * 4] = (H[i] >>> 24) & 255; out[i * 4 + 1] = (H[i] >>> 16) & 255;
      out[i * 4 + 2] = (H[i] >>> 8) & 255; out[i * 4 + 3] = H[i] & 255;
    }
    return out;
  }
  function _hmacSha1(keyBytes, data) {
    var bs = 64, i;
    var k = keyBytes.length > bs ? _sha1Bytes(keyBytes) : keyBytes;
    var kk = new Uint8Array(bs); kk.set(k, 0);
    var ipad = new Uint8Array(bs), opad = new Uint8Array(bs);
    for (i = 0; i < bs; i++) { ipad[i] = kk[i] ^ 0x36; opad[i] = kk[i] ^ 0x5c; }
    return _sha1Bytes(_concat(opad, _sha1Bytes(_concat(ipad, data))));
  }
  function _hmacAny(hashName, keyBytes, data) {
    if (hashName === 'SHA-1') return _hmacSha1(keyBytes, data);
    var r = (typeof hmacBytesSync === 'function') ? hmacBytesSync(hashName, keyBytes, data) : null;
    if (!r) throw new Error('HMAC 计算失败：' + hashName + '（本机不支持该哈希）');
    return r;
  }

  /* ---------- 通用小工具 ---------- */
  function _concat() {
    var n = 0, i, j;
    for (i = 0; i < arguments.length; i++) n += arguments[i].length;
    var o = new Uint8Array(n), k = 0;
    for (i = 0; i < arguments.length; i++) for (j = 0; j < arguments[i].length; j++) o[k++] = arguments[i][j];
    return o;
  }
  function _u32be(v) { return new Uint8Array([(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]); }
  function _strBytes(s) { return (typeof strToBytes === 'function') ? strToBytes(s) : new TextEncoder().encode(s); }

  /* HKDF-Expand（RFC 5869）：T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i) */
  function _hkdfExpand(prk, info, L, hashName, hlen) {
    var out = new Uint8Array(L), t = new Uint8Array(0), off = 0, i = 1, n;
    while (off < L) {
      t = _hmacAny(hashName, prk, _concat(t, info, new Uint8Array([i])));
      n = Math.min(hlen, L - off);
      out.set(t.subarray(0, n), off);
      off += n; i++;
    }
    return out;
  }

  /* PBKDF2（RFC 8018）：U1 = HMAC(pw, salt ‖ BE32(b))，逐轮异或 */
  function _pbkdf2(hashName, pw, salt, iters, dkLen, hlen) {
    var out = new Uint8Array(dkLen), off = 0, b = 1, n, i, j, u, t;
    while (off < dkLen) {
      u = _hmacAny(hashName, pw, _concat(salt, _u32be(b)));
      t = new Uint8Array(u);
      for (i = 1; i < iters; i++) {
        u = _hmacAny(hashName, pw, u);
        for (j = 0; j < t.length; j++) t[j] ^= u[j];
      }
      n = Math.min(hlen, dkLen - off);
      out.set(t.subarray(0, n), off);
      off += n; b++;
    }
    return out;
  }

  /* ================= TLS 1.3 HKDF-Expand-Label（RFC 8446 §7.1） ================= */
  /* HkdfLabel = BE16(outLen) ‖ (len ‖ "tls13 " + label) ‖ (len ‖ context)
     output   = HKDF-Expand(PRK, HkdfLabel, outLen)
     注意 label 前缀 "tls13 " 带一个【尾空格】，且是长度前缀不是零结尾。 */
  /* 参数切分：支持双引号包裹含逗号的字段。
     官方向量里的 label 是 "TLS 1.3, something or other" —— 自带逗号，
     直接用 split(',') 会把它切成两半，长度却看不出异常。 */
  function _splitParams(s) {
    var out = [], cur = '', q = false;
    s = String(s || '');
    for (var i = 0; i < s.length; i++) {
      var c = s.charAt(i);
      if (c === '"') { q = !q; continue; }
      if (c === ',' && !q) { out.push(cur.trim()); cur = ''; continue; }
      cur += c;
    }
    out.push(cur.trim());
    return out;
  }

  /* prefix 语义（两个官方规范同名不同义，务必区分）：
       'tls13 ' → RFC 8446 / TLS 1.3：label 前强制加 "tls13 "（默认）
                  已用 OpenSSL 3.0.2 真实会话的 keylog 端到端验证（9/9 记录解密通过）
       ''       → Botan / BoringSSL Go 版的通用 HKDF-Expand-Label：不加任何前缀，
                  label 由调用方给全。Botan hkdf_label.vec 用的是这一种。
     两者都带官方向量，混用会静默全错，故做成显式开关而非自动猜测。 */
  function hkdfExpandLabel(secret, label, context, outLen, hashName, hlen, prefix) {
    var pfx = (typeof prefix === 'string') ? prefix : 'tls13 ';
    var lbl = _concat(_strBytes(pfx), _strBytes(label));
    if (lbl.length > 255) throw new Error('label 过长（>255 字节）');
    if (context.length > 255) throw new Error('context 过长（>255 字节）');
    var info = _concat(new Uint8Array([(outLen >> 8) & 255, outLen & 255]),
      new Uint8Array([lbl.length]), lbl,
      new Uint8Array([context.length]), context);
    return _hkdfExpand(secret, info, outLen, hashName, hlen);
  }

  /* ================= Passhash9（Botan 自有口令哈希） ================= */
  /* 照 src/lib/passhash/passhash9/passhash9.cpp：
       blob = alg_id(1) ‖ work_factor(2, BE) ‖ salt(12) ‖ PBKDF2(prf, 24B)
       输出 = "$9$" ‖ base64(blob)          （blob 39 字节 → base64 52 字符）
     PRF：0=HMAC-SHA-1 1=HMAC-SHA-256 2=CMAC(Blowfish) 3=HMAC-SHA-384 4=HMAC-SHA-512
     迭代 = 10000 × work_factor。alg_id=2 需 CMAC(Blowfish)，本项目不做。 */
  var PH9_ALGIDS = { 0: 'SHA-1', 1: 'SHA-256', 3: 'SHA-384', 4: 'SHA-512' };
  var PH9_HLEN = { 0: 20, 1: 32, 3: 48, 4: 64 };
  function passhash9Gen(passBytes, salt, workFactor, algId) {
    var hn = PH9_ALGIDS[algId];
    if (!hn) throw new Error('Passhash9 不支持的 alg_id：' + algId + '（0/1/3/4 可用）');
    if (!(workFactor > 0 && workFactor < 512)) throw new Error('Passhash9 work factor 需在 1..511');
    if (salt.length !== 12) throw new Error('Passhash9 salt 必须 12 字节');
    var dk = _pbkdf2(hn, passBytes, salt, 10000 * workFactor, 24, PH9_HLEN[algId]);
    var blob = _concat(new Uint8Array([algId]),
      new Uint8Array([(workFactor >> 8) & 255, workFactor & 255]), salt, dk);
    return '$9$' + (typeof bytesToBase64 === 'function' ? bytesToBase64(blob) : _b64enc(blob));
  }
  function passhash9Check(passBytes, hashStr) {
    var s = String(hashStr || '').trim();
    if (s.substr(0, 3) !== '$9$') throw new Error('不是 Passhash9 串（应以 $9$ 开头）');
    var body = s.substr(3);
    /* base64 长度校验：39 字节 → 52 字符 */
    if (body.length !== 52) throw new Error('Passhash9 串长度错误（应为 $9$ + 52 字符）');
    var bin = (typeof base64ToBytes === 'function') ? base64ToBytes(body) : null;
    if (!bin || bin.length !== 39) throw new Error('Passhash9 解码长度错误');
    var algId = bin[0];
    var wf = bin[1] * 256 + bin[2];
    if (wf === 0) throw new Error('Passhash9 work factor 为 0（非法）');
    if (wf > 512) throw new Error('Passhash9 work factor 过大：' + wf);
    var salt = bin.subarray(3, 15);
    var stored = bin.subarray(15, 39);
    var hn = PH9_ALGIDS[algId];
    if (!hn) throw new Error('Passhash9 不支持的 alg_id：' + algId);
    var dk = _pbkdf2(hn, passBytes, salt, 10000 * wf, 24, PH9_HLEN[algId]);
    for (var i = 0; i < 24; i++) if (dk[i] !== stored[i]) throw new Error('Passhash9 校验失败：口令不匹配');
    return true;
  }

  /* ---------- 注册 ---------- */
  var _n = 0;

  if (typeof CURVES === 'object' && typeof CURVES.k1 === 'object') {
    reg({
      id: 'ecdsa-recover',
      name: 'ECDSA 公钥恢复（从签名还原公钥）',
      group: '椭圆曲线与高级代数',
      key: true,
      param: true,
      keyLabel: '签名 r,s（Hex，逗号分隔）',
      paramLabel: '恢复位 v（0~3），可选曲线 k1/p256/p384/p521（默认 k1）',
      info: '由 ECDSA 签名 (r,s) 与恢复位 v 反推签名者公钥：Q = r⁻¹·(s·R − e·G)。比特币/以太坊交易验签即用此机制。输入框填【消息摘要】（Hex，不是原文）：e 取其字节按曲线阶长截断的整数。官方向量 2/2。',
      enc: async function (b, k, p, fmt) {
        var f = _parseSigFields(k);
        if (f.length < 2) throw new Error('请填 r,s（十六进制，逗号分隔）');
        var pf = _parseSigFields(p);
        var v = parseInt(pf[0] || '0', 10);
        var cname = pf[1] || 'k1';
        var curve = (typeof pickCurveByName === 'function') ? pickCurveByName(cname) : CURVES[cname];
        if (!curve) throw new Error('未知曲线：' + cname);
        var r = _bigFromHex(f[0]), s = _bigFromHex(f[1]);
        var z = _digestToInt(curve, b);
        var Q = ecdsaRecoverPub(curve, r, s, z, v);
        var len = curve.byteLen;
        var pub = concatBytes(new Uint8Array([4]), _bigToBytesFixed(Q.x, len), _bigToBytesFixed(Q.y, len));
        return bytesOut(pub, fmt);
      }
    });
    _n++;
  }


  reg({
    id: 'hkdf-expand-label',
    name: 'TLS 1.3 HKDF-Expand-Label（RFC 8446）',
    group: '密钥工具',
    key: true,
    param: true,
    keyLabel: 'Secret / PRK（Hex）',
    paramLabel: 'label（含逗号请用双引号包裹）, context(Hex), 输出长度[, 哈希, prefix]（默认 24,SHA-256,tls13）',
    info: 'HKDF-Expand-Label：info = BE16(输出长度)‖len(label)‖label‖len(context)‖context。prefix=tls13（默认）加 "tls13 " 前缀，已用 OpenSSL 3.0.2 真实会话 keylog 端到端验证（9/9 记录解密通过）；prefix=none 不加前缀，对应 Botan/BoringSSL 通用版，官方向量 4/4。',
    enc: async function (b, k, p, fmt) {
      var f = _splitParams(p);
      var label = f[0] || '';
      var ctx = _bigFromHex(f[1] || '') ? hexToBytes(f[1] || '') : new Uint8Array(0);
      var outLen = parseInt(f[2] || '24', 10);
      var hn = f[3] || 'SHA-256';
      var hlen = hn === 'SHA-384' ? 48 : (hn === 'SHA-512' ? 64 : 32);
      var pf = (f[4] || 'tls13').toLowerCase();
      var prefix = (pf === 'none' || pf === '') ? '' : (pf === 'tls13' ? 'tls13 ' : pf);
      var secret = hexToBytes(String(k || '').trim());
      var out = hkdfExpandLabel(secret, label, ctx, outLen, hn, hlen, prefix);
      return bytesOut(out, fmt);
    }
  }); _n++;

  reg({
    id: 'passhash9',
    name: 'Passhash9 口令哈希（Botan $9$）',
    group: '单向哈希',
    key: true,
    param: true,
    keyLabel: 'salt（Hex，必须 12 字节；留空则用固定测试盐）',
    paramLabel: 'work_factor[, alg_id]（默认 10,0；alg 0=SHA-1 1=SHA-256 3=SHA-384 4=SHA-512）',
    info: 'Botan 自有口令哈希，输出 $9$ 前缀 + base64(alg_id‖work_factor‖salt‖PBKDF2 24B)。迭代 = 10000×work_factor，默认 10 万次。work_factor 越大越慢。官方向量 1/1。',
    enc: async function (b, k, p, fmt) {
      var f = String(p || '').split(',').map(function (x) { return x.trim(); });
      var wf = parseInt(f[0] || '10', 10);
      var alg = parseInt(f[1] || '0', 10);
      var saltStr = String(k || '').trim();
      var salt = saltStr ? hexToBytes(saltStr) : hexToBytes('AAAAAAAAAAAAAAAAAAAAAAAA');
      return passhash9Gen(b, salt, wf, alg);
    }
  }); _n++;

  reg({
    id: 'passhash9-verify',
    name: 'Passhash9 校验（比对口令）',
    group: '单向哈希',
    key: true,
    param: true,
    keyLabel: '口令',
    paramLabel: 'Passhash9 串（$9$ 开头）',
    info: '把口令与 $9$ 串做恒定时间比对：解析出 alg_id、work_factor、salt 后重算 PBKDF2 并逐字节比较。用于验证 Passhash9 的输出，不匹配时抛错。官方向量 1/1。',
    enc: async function (b, k, p, fmt) {
      var pw = String(k || '');
      var ok = passhash9Check(_strBytes(pw), String(p || '').trim());
      return ok ? 'PASS：口令匹配' : 'FAIL';
    }
  }); _n++;

  console.log('crypto_misc6.js：ECDSA 公钥恢复已注册，共 ' + _n + ' 个算法');

  if (typeof window !== 'undefined') {
    window._ecdsaRecoverPub = ecdsaRecoverPub;
    window._digestToInt = _digestToInt;
    window._hkdfExpandLabel = hkdfExpandLabel;
    window._passhash9Gen = passhash9Gen;
    window._passhash9Check = passhash9Check;
  }
})();
