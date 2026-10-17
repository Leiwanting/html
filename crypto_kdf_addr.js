/* ============================================================
 * bcrypt / Bech32 / Bech32m / Shamir 门限（4 类新算法）
 *
 * bcrypt   —— 向量来自 python-bcrypt 官方 test.py 与 spring-security
 *             BCryptTests.java（两者互相印证）。
 *             依赖项目已导出的 blowfishFreshConstants / blowfishEncipherWords
 *             （Blowfish 常量由 π 的十六进制在运行时算出，不硬编码）。
 * Bech32   —— BIP-173 官方向量（bitcoin/bips 仓库 Test vectors 章节）。
 * Bech32m  —— BIP-350：常量 0x2bc830a3，其余与 Bech32 同构。
 * Shamir   —— GF(256)（多项式 0x11B），无外部向量，靠自证：
 *             任意 t 份可还原、t-1 份不可还原、份额编号必须从 1 起。
 *
 * ⚠ 两处「不报错、只静默全错」的坑，改动时务必先读这段：
 *   1) bcrypt 的 Base64 字母表是 ./A-Za-z0-9（Unix crypt 变体），
 *      不是标准 Base64 的 A-Za-z0-9+/。用错字母表输出长度完全正常。
 *   2) Bech32 的 polymod 中 chk 必须保持无符号（>>> 0），
 *      否则 top = chk >> 25 会算术右移出负值，校验和恒错。
 * ============================================================ */
(function () {
  if (typeof ALGOS === 'undefined' || typeof reg !== 'function') {
    console.error('crypto_kdf_addr.js 需要在 Encryption_and_decryption_logic.js 之后加载');
    return;
  }

  /* ---------- 通用小工具（本文件自带，避免跨文件局部函数取不到） ---------- */
  function toStr(b) {
    if (typeof b === 'string') return b;
    if (b == null) return '';
    if (typeof bytesToStr === 'function') return bytesToStr(new Uint8Array(b));
    var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return s;
  }
  function toBytes(b) {
    if (typeof b === 'string') return typeof strToBytes === 'function' ? strToBytes(b) : (function () { var o = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) o[i] = b.charCodeAt(i) & 0xff; return o; })();
    return new Uint8Array(b);
  }
  function h2b(h) {
    var c = String(h).replace(/[^0-9a-fA-F]/g, '');
    if (c.length % 2) c = '0' + c;
    var o = new Uint8Array(c.length / 2);
    for (var i = 0; i < o.length; i++) o[i] = parseInt(c.substr(i * 2, 2), 16);
    return o;
  }
  function b2h(b) { return typeof bytesToHex === 'function' ? bytesToHex(b) : Array.prototype.map.call(b, function (x) { return (x < 16 ? '0' : '') + x.toString(16); }).join(''); }

  /* ============================================================
   * 1. bcrypt
   * ============================================================ */
  /* Unix crypt 风格的 Base64 字母表 —— 与标准 Base64 不同，不可混用 */
  var B64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var B64_INV = (function () { var m = {}; for (var i = 0; i < B64.length; i++) m[B64[i]] = i; return m; })();

  function b64enc(d) {
    var rs = '', off = 0, c1, c2;
    while (off < d.length) {
      c1 = d[off++] & 0xff;
      rs += B64[c1 >> 2];
      c1 = (c1 & 0x03) << 4;
      if (off >= d.length) { rs += B64[c1]; break; }
      c2 = d[off++] & 0xff;
      c1 |= (c2 >> 4) & 0x0f;
      rs += B64[c1];
      c1 = (c2 & 0x0f) << 2;
      if (off >= d.length) { rs += B64[c1]; break; }
      c2 = d[off++] & 0xff;
      c1 |= (c2 >> 6) & 0x03;
      rs += B64[c1];
      rs += B64[c2 & 0x3f];
    }
    return rs;
  }
  function b64dec(s, maxolen) {
    var o = new Uint8Array(maxolen), olen = 0, off = 0, c1, c2, c3, c4;
    while (off < s.length - 1 && olen < maxolen) {
      c1 = B64_INV[s[off++]]; c2 = B64_INV[s[off++]];
      if (c1 === undefined || c2 === undefined) break;
      o[olen++] = ((c1 << 2) | ((c2 & 0x30) >> 4)) & 0xff;
      if (olen >= maxolen || off >= s.length) break;
      c3 = B64_INV[s[off++]];
      if (c3 === undefined) break;
      o[olen++] = (((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2)) & 0xff;
      if (olen >= maxolen || off >= s.length) break;
      c4 = B64_INV[s[off++]];
      if (c4 === undefined) break;
      o[olen++] = (((c3 & 0x03) << 6) | c4) & 0xff;
    }
    return o.subarray(0, olen);
  }

  /* EksBlowfishSetup —— 严格按 OpenBSD bcrypt.c 第 160~166 行：
       initstate → expandstate(data=salt, key=key) → rounds × (expand0state(key); expand0state(salt))
     两个扩展函数不可互换，这是此前 24 种变体全错的根本原因：
       · expandstate  ：P 盒用【key】异或；加密流每步把【data(salt)】的 word XOR 进 datal/datar
       · expand0state ：P 盒用【key】异或；加密流是纯 Blowfish，不混入任何 data
     参考：raw.githubusercontent.com/openbsd/src/master/lib/libc/crypt/bcrypt.c */
  function eksSetup(keyBytes, salt16, cost) {
    var fc = globalThis.blowfishFreshConstants();
    var P = fc.P, S = fc.S;

    /* Blowfish_stream2word：j 在调用间持续推进（官方用 u_int16_t *current） */
    function stream2word(data, cur) {
      var temp = 0;
      for (var i = 0; i < 4; i++, cur.v++) {
        if (cur.v >= data.length) cur.v = 0;
        temp = ((temp << 8) | (data[cur.v] & 0xff)) >>> 0;
      }
      return temp >>> 0;
    }

    function expandState(data, key) {
      var cur = { v: 0 }, i, k, r;
      for (i = 0; i < 18; i++) P[i] = (P[i] ^ stream2word(key, cur)) >>> 0;
      cur = { v: 0 };
      var datal = 0, datar = 0;
      for (i = 0; i < 18; i += 2) {
        datal = (datal ^ stream2word(data, cur)) >>> 0;
        datar = (datar ^ stream2word(data, cur)) >>> 0;
        r = globalThis.blowfishEncipherWords(datal, datar, P, S);
        datal = r[0] >>> 0; datar = r[1] >>> 0;
        P[i] = datal; P[i + 1] = datar;
      }
      for (i = 0; i < 4; i++) {
        for (k = 0; k < 256; k += 2) {
          datal = (datal ^ stream2word(data, cur)) >>> 0;
          datar = (datar ^ stream2word(data, cur)) >>> 0;
          r = globalThis.blowfishEncipherWords(datal, datar, P, S);
          datal = r[0] >>> 0; datar = r[1] >>> 0;
          S[i * 256 + k] = datal; S[i * 256 + k + 1] = datar;
        }
      }
    }

    function expand0State(key) {
      var cur = { v: 0 }, i, k, r;
      for (i = 0; i < 18; i++) P[i] = (P[i] ^ stream2word(key, cur)) >>> 0;
      var datal = 0, datar = 0;
      for (i = 0; i < 18; i += 2) {
        r = globalThis.blowfishEncipherWords(datal, datar, P, S);
        datal = r[0] >>> 0; datar = r[1] >>> 0;
        P[i] = datal; P[i + 1] = datar;
      }
      for (i = 0; i < 4; i++) {
        for (k = 0; k < 256; k += 2) {
          r = globalThis.blowfishEncipherWords(datal, datar, P, S);
          datal = r[0] >>> 0; datar = r[1] >>> 0;
          S[i * 256 + k] = datal; S[i * 256 + k + 1] = datar;
        }
      }
    }

    expandState(salt16, keyBytes);
    var rounds = 1 << cost, i2;
    for (i2 = 0; i2 < rounds; i2++) {
      expand0State(keyBytes);
      expand0State(salt16);
    }
    return { P: P, S: S };
  }

  var MAGIC = 'OrpheanBeholderScryDoubt';

  function bcryptHash(pw, saltB64_22, cost, minor) {
    if (typeof globalThis.blowfishFreshConstants !== 'function') throw new Error('Blowfish 常量接口不可用');
    var salt = b64dec(saltB64_22, 16);
    if (salt.length !== 16) throw new Error('salt 需 22 个 Base64 字符（16 字节）');
    var pwBytes = toBytes(pw);
    /* $2a/$2b/$2y 都在口令末尾补一个 NUL（jBCrypt: minor >= 'a'） */
    var kb = new Uint8Array(pwBytes.length + 1);
    kb.set(pwBytes); kb[pwBytes.length] = 0;
    var st = eksSetup(kb, salt, cost);
    var ctext = toBytes(MAGIC);
    for (var k = 0; k < 64; k++) {
      for (var b = 0; b < 3; b++) {
        var off = b * 8;
        var r = globalThis.blowfishEncipherWords(
          ((ctext[off] << 24) | (ctext[off + 1] << 16) | (ctext[off + 2] << 8) | ctext[off + 3]) >>> 0,
          ((ctext[off + 4] << 24) | (ctext[off + 5] << 16) | (ctext[off + 6] << 8) | ctext[off + 7]) >>> 0,
          st.P, st.S);
        var L = r[0] >>> 0, R = r[1] >>> 0;
        /* 读用大端（stream2word），但官方写回是小端 —— 顺序反了不报错、只静默全错 */
        ctext[off + 3] = L & 0xff; ctext[off + 2] = (L >>> 8) & 0xff;
        ctext[off + 1] = (L >>> 16) & 0xff; ctext[off] = (L >>> 24) & 0xff;
        ctext[off + 7] = R & 0xff; ctext[off + 6] = (R >>> 8) & 0xff;
        ctext[off + 5] = (R >>> 16) & 0xff; ctext[off + 4] = (R >>> 24) & 0xff;
      }
    }
    /* 关键：salt 与 hash 必须【分别】Base64 编码再拼接。
       拼接成一个 39 字节数组再编码会得到 52 字符，且前 22 位是 salt ——
       这与标准 bcrypt 完全不同（长度只差 1，极易漏检）。 */
    return '$2' + minor + '$' + (cost < 10 ? '0' + cost : cost) + '$'
      + b64enc(salt) + b64enc(ctext.subarray(0, 23));
  }

  function parseHash(h) {
    var m = /^\$(2[abxy])\$(\d{2})\$([.\/A-Za-z0-9]{22})([.\/A-Za-z0-9]{31})$/.exec(String(h).trim());
    if (!m) throw new Error('不是合法的 bcrypt 串（应形如 $2a$06$<22字符salt><31字符hash>）');
    return { minor: m[1][2], cost: parseInt(m[2], 10), salt: m[3], hash: m[4] };
  }

  /* ============================================================
   * 2. Bech32 / Bech32m（BIP-173 / BIP-350）
   * ============================================================ */
  var CS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  var CONST_B32 = 1, CONST_B32M = 0x2bc830a3;

  function polymod(values) {
    var chk = 1;
    for (var i = 0; i < values.length; i++) {
      var top = chk >>> 25;                       /* 必须无符号右移 */
      chk = (((chk & 0x1ffffff) << 5) ^ values[i]) >>> 0;
      for (var j = 0; j < 5; j++) if (((top >> j) & 1) !== 0) chk = (chk ^ GEN[j]) >>> 0;
    }
    return chk >>> 0;
  }
  function hrpExpand(hrp) {
    var out = [], i;
    for (i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
    out.push(0);
    for (i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
    return out;
  }
  function mkChecksum(hrp, data, c) {
    var pm = polymod(hrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0])) ^ c;
    pm = pm >>> 0;
    var out = [];
    for (var i = 0; i < 6; i++) out.push((pm >>> (5 * (5 - i))) & 31);
    return out;
  }
  function convertbits(data, from, to, pad) {
    var acc = 0, bits = 0, ret = [], maxv = (1 << to) - 1;
    for (var i = 0; i < data.length; i++) {
      var v = data[i];
      if (v < 0 || (v >> from) !== 0) throw new Error('数据值超出 ' + from + ' 位');
      acc = (acc << from) | v; bits += from;
      while (bits >= to) { bits -= to; ret.push((acc >> bits) & maxv); }
    }
    if (pad) { if (bits > 0) ret.push((acc << (to - bits)) & maxv); }
    else if (bits >= from || ((acc << (to - bits)) & maxv)) throw new Error('存在多余填充位');
    return ret;
  }
  function bechEncode(hrp, dataBytes, c) {
    var values = convertbits(Array.prototype.slice.call(dataBytes), 8, 5, true);
    var all = values.concat(mkChecksum(hrp, values, c));
    var s = hrp + '1';
    for (var i = 0; i < all.length; i++) s += CS[all[i]];
    return s;
  }
  function bechDecode(str, c) {
    var s = String(str).trim();
    if (s.length > 90) throw new Error('总长度超过 90（BIP-173 上限）');
    if (s.toLowerCase() !== s && s.toUpperCase() !== s) throw new Error('不允许大小写混用');
    s = s.toLowerCase();
    /* 分隔符取最后一个 '1'：HRP 内不能含 1，数据部分也不能含 1 */
    var pos = s.lastIndexOf('1');
    if (pos < 1 || pos + 7 > s.length) throw new Error('分隔符 "1" 位置非法或校验和过短');
    var hrp = s.slice(0, pos), d = s.slice(pos + 1);
    for (var i = 0; i < hrp.length; i++) {
      var o = hrp.charCodeAt(i);
      if (o < 33 || o > 126) throw new Error('HRP 含非法字符（须 33..126）');
    }
    var values = [];
    for (var j = 0; j < d.length; j++) {
      var idx = CS.indexOf(d[j]);
      if (idx < 0) throw new Error('数据部分含非法字符 "' + d[j] + '"');
      values.push(idx);
    }
    if (polymod(hrpExpand(hrp).concat(values)) !== c) throw new Error('校验和不一致');
    var bytes = convertbits(values.slice(0, values.length - 6), 5, 8, false);
    return { hrp: hrp, bytes: new Uint8Array(bytes) };
  }

  /* ============================================================
   * 3. Shamir 门限（GF(256)，多项式 0x11B）
   * ============================================================ */
  var GF_EXP = new Uint8Array(512), GF_LOG = new Uint8Array(256);
  (function () {
    var x = 1;
    for (var i = 0; i < 255; i++) { GF_EXP[i] = x; GF_LOG[x] = i; x ^= (x << 1) ^ ((x & 0x80) ? 0x1b : 0); x &= 0xff; }
    for (var k = 255; k < 512; k++) GF_EXP[k] = GF_EXP[k - 255];
  })();
  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return GF_EXP[GF_LOG[a] + GF_LOG[b]];
  }
  function gfDiv(a, b) {
    if (b === 0) throw new Error('GF(256) 除零');
    if (a === 0) return 0;
    return GF_EXP[(GF_LOG[a] + 255 - GF_LOG[b]) % 255];
  }
  function gfRand() {
    var v = new Uint8Array(1);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(v);
    else v[0] = Math.floor(Math.random() * 256);
    return v[0] & 0xff;
  }
  /* 份额编号必须从 1 起 —— i=0 会让份额直接等于秘密本身 */
  function sssSplit(secretBytes, t, n) {
    if (t < 2) throw new Error('门限 t 至少为 2');
    if (n < t) throw new Error('总份数 n 不能小于 t');
    if (n > 255) throw new Error('最多 255 份（份额编号为 1 字节）');
    var shares = [];
    for (var i = 1; i <= n; i++) { var s = new Uint8Array(secretBytes.length); shares.push(s); }
    for (var b = 0; b < secretBytes.length; b++) {
      var coef = new Uint8Array(t);
      coef[0] = secretBytes[b];
      for (var c = 1; c < t; c++) coef[c] = gfRand();
      for (var x = 1; x <= n; x++) {
        var acc = 0, xp = 1;
        for (var d = 0; d < t; d++) { acc ^= gfMul(coef[d], xp); xp = gfMul(xp, x); }
        shares[x - 1][b] = acc;
      }
    }
    return shares;
  }
  function sssRecover(shares, t) {
    if (shares.length < t) throw new Error('至少需要 ' + t + ' 份，当前只有 ' + shares.length + ' 份');
    var xs = shares.map(function (s) { return s.x; });
    var seen = {};
    for (var i = 0; i < xs.length; i++) {
      if (seen[xs[i]]) throw new Error('份额编号重复：' + xs[i]);
      seen[xs[i]] = 1;
    }
    var len = shares[0].data.length;
    for (var i2 = 1; i2 < shares.length; i2++) {
      if (shares[i2].data.length !== len) throw new Error('各份长度不一致');
    }
    var use = shares.slice(0, t);
    var out = new Uint8Array(len);
    for (var b = 0; b < len; b++) {
      var acc = 0;
      for (var i3 = 0; i3 < t; i3++) {
        var xi = use[i3].x, yi = use[i3].data[b], num = 1, den = 1;
        for (var j = 0; j < t; j++) {
          if (j === i3) continue;
          var xj = use[j].x;
          num = gfMul(num, xj);               /* Π x_j */
          den = gfMul(den, xi ^ xj);          /* Π (x_i - x_j) = Π (x_i ^ x_j) in GF(2^8) */
        }
        acc ^= gfMul(yi, gfDiv(num, den));
      }
      out[b] = acc;
    }
    return out;
  }
  function parseShares(text) {
    var lines = String(text).split(/[\r\n]+/).map(function (s) { return s.trim(); }).filter(function (s) { return s.length; });
    var out = [];
    for (var i = 0; i < lines.length; i++) {
      var m = /^(\d{1,3})\s*[:\-]\s*([0-9a-fA-F]+)$/.exec(lines[i]);
      if (!m) throw new Error('第 ' + (i + 1) + ' 行无法解析，应形如 "3:a1b2c3"（编号:十六进制）');
      out.push({ x: parseInt(m[1], 10), data: h2b(m[2]) });
    }
    if (!out.length) throw new Error('没有可识别的份额');
    return out;
  }

  /* ============================================================
   * 4. 注册
   * ============================================================ */
  var BC_INFO = 'bcrypt 口令哈希（EksBlowfish）。加密：口令 + 参数栏「cost,salt22」生成散列；解密：把待验散列贴进输入、密钥栏填口令，输出 ✓/✗。cost 每 +1 耗时翻倍，建议 10~12（默认 6，浏览器勿超 16）。向量：python-bcrypt 官方 test.py 16 组全过。';

  reg({
    id: 'bcrypt', name: 'bcrypt 口令哈希', group: '单向哈希',
    key: true, keyLabel: '口令（明文）',
    param: true, paramLabel: 'cost,salt22（如 06,DCq7YPn5Rq63x1Lad4cll.；salt 留空则随机）',
    info: BC_INFO,
    enc: function (b, k, p) {
      var pw = k || '';
      var parts = String(p || '').split(',');
      var cost = parseInt(String(parts[0] || '').trim(), 10);
      if (isNaN(cost)) cost = 6;
      if (cost < 4 || cost > 16) throw new Error('cost 需在 4..16（默认 6；每 +1 耗时翻倍）');
      var salt = String(parts[1] || '').trim();
      if (!salt) {
        var rb = new Uint8Array(16);
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(rb);
        else for (var i = 0; i < 16; i++) rb[i] = Math.floor(Math.random() * 256);
        salt = b64enc(rb);
      }
      if (salt.length !== 22) throw new Error('salt 须为 22 个字符（Base64 变体 ./A-Za-z0-9）');
      return bcryptHash(pw, salt, cost, 'a');
    },
    dec: function (input, k) {
      var h = parseHash(toStr(input));
      var got = bcryptHash(k || '', h.salt, h.cost, h.minor);
      var ok = got.slice(-31) === h.hash;
      return (ok ? '✓ 口令匹配' : '✗ 口令不匹配') + '（cost=' + h.cost + '，已按原 salt 重算）';
    }
  });

  var B32_INFO = 'Bech32 地址编码（BIP-173，比特币原生隔离见证地址用）。加密：输入 Hex，参数栏填人类可读前缀（如 bc）→ 输出 bech32；解密：输入 bech32 → 输出前缀与数据 Hex。向量来自 BIP-173 官方 Test vectors。';
  var B32M_INFO = 'Bech32m 地址编码（BIP-350），校验和常量改为 0x2bc830a3，用于 Taproot 等见证版本 1+。用法同 Bech32。⚠ 与 Bech32 不兼容：同一数据用两种编码得到的串不同。';

  function mkBech(id, name, c, info) {
    reg({
      id: id, name: name, group: '编码',
      key: false, param: true, paramLabel: '人类可读前缀 HRP（如 bc / tb；编码时必填）',
      info: info,
      enc: function (b, k, p) {
        var hrp = String(p || '').trim();
        if (!hrp) throw new Error('参数栏需填 HRP（人类可读前缀，如 bc）');
        var txt = toStr(b).trim();
        if (!txt) return bechEncode(hrp, new Uint8Array(0), c);
        return bechEncode(hrp, h2b(txt), c);
      },
      dec: function (input) {
        var r = bechDecode(toStr(input), c);
        return 'HRP: ' + r.hrp + '\n数据(Hex): ' + (r.bytes.length ? b2h(r.bytes) : '（空）');
      }
    });
  }
  mkBech('bech32', 'Bech32 地址编码（BIP-173）', CONST_B32, B32_INFO);
  mkBech('bech32m', 'Bech32m 地址编码（BIP-350）', CONST_B32M, B32M_INFO);

  var SSS_INFO = 'Shamir 秘密共享（GF(256)，AES 域多项式 0x11B）。加密：输入秘密，参数栏填「t,n」拆成 n 份（编号从 1 起，任意 t 份可还原）；解密：粘贴任意 t 份（每行「编号:Hex」），参数栏填 t。⚠ 少于 t 份会静默给出错误结果而非报错；编号从 0 起会让第 0 份直接等于秘密。';

  reg({
    id: 'sss-split', name: 'Shamir 门限拆分（SSS）', group: '分布式与门限密码',
    key: false, param: true, paramLabel: 't,n（如 3,5：5 份中任意 3 份可还原）',
    info: SSS_INFO, dec: false,
    enc: function (b, k, p) {
      var parts = String(p || '').split(',');
      var t = parseInt(String(parts[0] || '').trim(), 10);
      var n = parseInt(String(parts[1] || '').trim(), 10);
      if (isNaN(t) || isNaN(n)) throw new Error('参数栏需填「t,n」，如 3,5');
      var data = toBytes(b);
      if (!data.length) throw new Error('请输入要拆分的秘密');
      var sh = sssSplit(data, t, n);
      var lines = [];
      for (var i = 0; i < sh.length; i++) lines.push((i + 1) + ':' + b2h(sh[i]));
      return '门限 ' + t + '/' + n + '（秘密 ' + data.length + ' 字节）\n' + lines.join('\n');
    }
  });

  reg({
    id: 'sss-recover', name: 'Shamir 门限还原（SSS）', group: '分布式与门限密码',
    key: false, param: true, paramLabel: 't（门限，如 3）',
    info: 'Shamir 秘密共享还原（GF(256)）。输入区粘贴份额，每行一条「编号:Hex」，参数栏填门限 t。⚠ 份数不足时不会报错，只会给出错误结果。',
    enc: false,
    dec: function (input, k, p) {
      var t = parseInt(String(p || '').trim(), 10);
      if (isNaN(t)) throw new Error('参数栏需填门限 t');
      var sh = parseShares(toStr(input));
      var out = sssRecover(sh, t);
      var s = '';
      for (var i = 0; i < out.length; i++) s += String.fromCharCode(out[i]);
      var printable = /^[\x20-\x7e\r\n\t]*$/.test(s);
      return (printable ? s : b2h(out)) + (printable ? '' : '\n（非可打印内容，已输出 Hex）');
    }
  });

  globalThis.KDFADDR = {
    bcryptHash: bcryptHash, b64enc: b64enc, b64dec: b64dec,
    bechEncode: bechEncode, bechDecode: bechDecode, polymod: polymod,
    sssSplit: sssSplit, sssRecover: sssRecover, gfMul: gfMul, gfDiv: gfDiv
  };
})();
