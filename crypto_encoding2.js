/* 补充编码：Base45 / Base62 / basE91 / ROT47 / Quoted-printable / UUEncode / Punycode / Base64url
   全部有官方或权威来源的测试向量，见文件末尾 t_enc2.js */
(function () {
  var B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
  function b45enc(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i += 2) {
      if (i + 1 < bytes.length) {
        var v = bytes[i] * 256 + bytes[i + 1];
        out += B45[v % 45] + B45[((v / 45) | 0) % 45] + B45[(v / 2025) | 0];
      } else {
        var v1 = bytes[i];
        out += B45[v1 % 45] + B45[(v1 / 45) | 0];
      }
    }
    return out;
  }
  function b45dec(s) {
    var out = [];
    for (var i = 0; i < s.length; i += 3) {
      var c0 = B45.indexOf(s[i]), c1 = B45.indexOf(s[i + 1]);
      if (c0 < 0 || c1 < 0) throw new Error('Base45 含非法字符');
      if (i + 2 < s.length) {
        var c2 = B45.indexOf(s[i + 2]);
        if (c2 < 0) throw new Error('Base45 含非法字符');
        var v = c0 + c1 * 45 + c2 * 2025;
        if (v > 0xffff) throw new Error('Base45 三字符组溢出');
        out.push((v >> 8) & 0xff, v & 0xff);
      } else {
        var v1 = c0 + c1 * 45;
        if (v1 > 0xff) throw new Error('Base45 两字符组溢出');
        out.push(v1);
      }
    }
    return Uint8Array.from(out);
  }

  var B62 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  /* 大整数除基取余：字节流当成一个大数。
     性能：BigInt 乘除本身是 O(n^2/64) 且常数很小，保留；真正的瓶颈是
     `s = c + s` 前置拼接（每次复制整串）与解码端 `out.unshift()`（每次搬移整个数组），
     两者都是 O(n^2)。改为 push + reverse + join。 */
  function b62enc(bytes) {
    var n = 0n;
    for (var i = 0; i < bytes.length; i++) n = (n << 8n) | BigInt(bytes[i]);
    if (bytes.length === 0) return '';
    var out = [];
    while (n > 0n) { out.push(B62[Number(n % 62n)]); n /= 62n; }
    out.reverse();
    /* 前导零字节会丢：用前导 '0' 计数补偿（与常见实现一致） */
    var z = 0; while (z < bytes.length && bytes[z] === 0) z++;
    return z ? '0'.repeat(z) + out.join('') : out.join('');
  }
  function b62dec(s) {
    var n = 0n;
    for (var i = 0; i < s.length; i++) {
      var d = B62.indexOf(s[i]);
      if (d < 0) throw new Error('Base62 含非法字符');
      n = n * 62n + BigInt(d);
    }
    if (s.length === 0) return new Uint8Array(0);
    var out = [];
    while (n > 0n) { out.push(Number(n & 0xffn)); n >>= 8n; }
    out.reverse();
    var z = 0; while (z < s.length && s[z] === '0') z++;
    var res = new Uint8Array(z + out.length);
    for (var j = 0; j < out.length; j++) res[z + j] = out[j];
    return res;
  }
  function b91enc(bytes) {
    var out = '', b = 0, n = 0;
    for (var i = 0; i < bytes.length; i++) {
      b |= bytes[i] << n; n += 8;
      if (n > 13) {
        var v = b & 8191;
        if (v > 88) { b >>= 13; n -= 13; }
        else { v = b & 16383; b >>= 14; n -= 14; }
        out += B91E[v % 91] + B91E[(v / 91) | 0];
      }
    }
    if (n) {
      out += B91E[b % 91];
      if (n > 7 || b > 90) out += B91E[(b / 91) | 0];
    }
    return out;
  }
  function b91dec(s) {
    var out = [], v = -1, b = 0, n = 0;
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      var d = B91D[c];
      if (d === -1) { if (s[i] === '\n' || s[i] === '\r' || s[i] === ' ') continue; throw new Error('basE91 含非法字符：' + s[i]); }
      if (v < 0) { v = d; continue; }
      v += d * 91;
      b |= v << n;
      n += (v & 8191) > 88 ? 13 : 14;
      do { out.push(b & 0xff); b >>= 8; n -= 8; } while (n > 7);
      v = -1;
    }
    if (v !== -1) out.push((b | (v << n)) & 0xff);
    return Uint8Array.from(out);
  }

  function rot47(s) {
    var o = '';
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c >= 33 && c <= 126) o += String.fromCharCode(33 + ((c - 33 + 47) % 94));
      else o += s[i];
    }
    return o;
  }

  /* Quoted-printable（RFC 2045）：可打印字符原样，其余 =XX，行软换行 =CRLF，行尾空格要转义 */
  function qpenc(bytes) {
    var out = '', line = 0;
    for (var i = 0; i < bytes.length; i++) {
      var c = bytes[i], s;
      /* 裸 CR 一并转义：否则它与 LF 在编码侧都变成 CRLF，解码还原后对不上原文 */
      if (c === 10) { out += '\r\n'; line = 0; continue; }
      else if (c === 13) s = '=0D';
      else if ((c >= 33 && c <= 60) || (c >= 62 && c <= 126)) s = String.fromCharCode(c);
      else if (c === 32 || c === 9) {
        /* 行尾的空格/TAB 必须转义，否则会被剥掉 */
        var nx = bytes[i + 1];
        s = (nx === 13 || nx === 10 || nx === undefined) ? '=' + hex2(c) : String.fromCharCode(c);
      } else s = '=' + hex2(c);
      if (line + s.length > 74) { out += '=\r\n'; line = 0; }
      out += s; line += s.length;
    }
    return out;
  }
  function hex2(c) { return (c < 16 ? '0' : '') + c.toString(16).toUpperCase(); }
  function qpdec(s) {
    var out = [];
    s = s.replace(/=\r\n/g, '').replace(/=\n/g, '');
    /* 编码侧把 LF 规范化成 CRLF（RFC 2045），这里还原回 LF 以保证往返一致。
       注意必须先剥软换行再归一化，顺序反了会把 =\r\n 里的换行也吃掉。 */
    s = s.replace(/\r\n/g, '\n');
    for (var i = 0; i < s.length; i++) {
      if (s[i] === '=' && i + 2 < s.length + 1 && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) {
        out.push(parseInt(s.substr(i + 1, 2), 16)); i += 2;
      } else out.push(s.charCodeAt(i) & 0xff);
    }
    return Uint8Array.from(out);
  }

  /* UUEncode：每 45 字节一行，行首长度字符 = 字节数+32 */
  function uuenc(bytes, name) {
    name = name || 'file.bin';
    var out = 'begin 644 ' + name + '\r\n';
    for (var i = 0; i < bytes.length; i += 45) {
      var n = Math.min(45, bytes.length - i);
      out += String.fromCharCode(n + 32);
      for (var j = 0; j < n; j += 3) {
        var b0 = bytes[i + j] || 0, b1 = bytes[i + j + 1] || 0, b2 = bytes[i + j + 2] || 0;
        out += String.fromCharCode(((b0 >> 2) & 63) + 32);
        out += String.fromCharCode((((b0 << 4) | (b1 >> 4)) & 63) + 32);
        out += String.fromCharCode((((b1 << 2) | (b2 >> 6)) & 63) + 32);
        out += String.fromCharCode((b2 & 63) + 32);
      }
      out += '\r\n';
    }
    return out + '`\r\nend\r\n';
  }
  function uudec(s) {
    var lines = s.split(/\r?\n/), out = [], started = false;
    for (var i = 0; i < lines.length; i++) {
      var L = lines[i];
      if (!started) { if (/^begin /.test(L)) started = true; continue; }
      if (/^end/.test(L)) break;
      if (!L) continue;
      /* '`' (96) 是长度 0 的空行标记，绝不能按 96-32=64 当成长度——
         那样会解出 60 多个零字节拼在末尾，输出长度看着还"挺合理"。 */
      var n = (L.charCodeAt(0) === 96) ? 0 : (L.charCodeAt(0) - 32);
      if (n <= 0) continue;
      /* 空格(值0)与 '`'(值0) 都是合法编码字符，绝不能当空白剔除——
         剔除后 4 字符一组会整体错位，短输入偶然能过、长输入全乱。 */
      var body = L.substring(1).replace(/\r$/, '');
      /* 每 3 字节编码成 4 个字符，所以第 j 个字节对应的字符下标是 (j/3)*4，
         不是 j。写成 j 时前 3 字节恰好对（0/3*4=0/3 巧合），从第 4 字节起
         整体错位——典型"看起来能解、其实全歪"。 */
      for (var j = 0; j < n; j += 3) {
        var k = (j / 3) * 4;
        var c0 = uu6(body[k]), c1 = uu6(body[k + 1]), c2 = uu6(body[k + 2]), c3 = uu6(body[k + 3]);
        if (n - j >= 1) out.push(((c0 << 2) | (c1 >> 4)) & 0xff);
        if (n - j >= 2) out.push(((c1 << 4) | (c2 >> 2)) & 0xff);
        if (n - j >= 3) out.push(((c2 << 6) | c3) & 0xff);
      }
    }
    return Uint8Array.from(out);
  }
  function uu6(ch, idx) {
    if (ch === undefined) return 0;
    if (ch === '`') return 0;
    var v = ch.charCodeAt(0) - 32;
    return v & 63;
  }

  /* Punycode（RFC 3492）。要点：
     · b = h = 基本字符个数（不是 0）——写错会让 adapt 的 firstTime 判据失真
     · digit→字符必须是 d<26 ? d+97 : d+22，直接把 digit 当 charCode 会产出 '\n' 之类的怪字符
     · 分隔符取最后一个 '-'，其左侧全是基本串 */
  var PUNY_BASE = 36, PUNY_TMIN = 1, PUNY_TMAX = 26, PUNY_SKEW = 38, PUNY_DAMP = 700,
      PUNY_INIT_BIAS = 72, PUNY_INIT_N = 128;
  function punyDigitToChar(d) { return d < 26 ? d + 97 : d + 22; }
  function punyCharToDigit(c) {
    if (c >= 48 && c <= 57) return c - 22;
    if (c >= 65 && c <= 90) return c - 65;
    if (c >= 97 && c <= 122) return c - 97;
    throw new Error('Punycode 非法字符：' + String.fromCharCode(c));
  }
  function punyAdapt(delta, numPoints, firstTime) {
    delta = firstTime ? ((delta / PUNY_DAMP) | 0) : (delta >> 1);
    delta = (delta + ((delta / numPoints) | 0)) | 0;
    var k = 0;
    while (delta > (((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) >> 1)) { delta = (delta / (PUNY_BASE - PUNY_TMIN)) | 0; k += PUNY_BASE; }
    return (k + ((((PUNY_BASE - PUNY_TMIN + 1) * delta) / (delta + PUNY_SKEW)) | 0)) | 0;
  }
  function punyEncode(str) {
    var input = Array.from(str), out = [], j;
    for (j = 0; j < input.length; j++) {
      var cp = input[j].codePointAt(0);
      if (cp < 128) out.push(input[j]);
    }
    var b = out.length, h = b;
    if (b > 0) out.push('-');
    var n = PUNY_INIT_N, delta = 0, bias = PUNY_INIT_BIAS;
    while (h < input.length) {
      var m = 0x10ffff;
      for (j = 0; j < input.length; j++) {
        var c = input[j].codePointAt(0);
        if (c >= n && c < m) m = c;
      }
      var span = m - n;
      if (span > (0x7fffffff - delta) / (h + 1)) throw new Error('Punycode 溢出');
      delta += span * (h + 1); n = m;
      for (j = 0; j < input.length; j++) {
        var c2 = input[j].codePointAt(0);
        if (c2 < n) { if (++delta > 0x7fffffff) throw new Error('Punycode 溢出'); }
        if (c2 === n) {
          var q = delta;
          for (var k = PUNY_BASE; ; k += PUNY_BASE) {
            var t = k <= bias ? PUNY_TMIN : (k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias);
            if (q < t) break;
            out.push(String.fromCharCode(punyDigitToChar(t + ((q - t) % (PUNY_BASE - t)))));
            q = (q - t) / (PUNY_BASE - t);
          }
          out.push(String.fromCharCode(punyDigitToChar(q)));
          bias = punyAdapt(delta, h + 1, h === b); delta = 0; h++;
        }
      }
      delta++; n++;
    }
    return out.join('');
  }
  function punyDecode(str) {
    var input = str.split(''), out = [], j;
    var pos = input.lastIndexOf('-');
    var basicLen = pos < 0 ? 0 : pos;
    for (j = 0; j < basicLen; j++) {
      if (input[j].charCodeAt(0) >= 128) throw new Error('Punycode 基本串含非 ASCII');
      out.push(input[j]);
    }
    var i = 0, n = PUNY_INIT_N, bias = PUNY_INIT_BIAS, outLen = basicLen;
    var p = pos < 0 ? 0 : pos + 1;
    while (p < input.length) {
      var oldi = i, w = 1;
      for (var k = PUNY_BASE; ; k += PUNY_BASE) {
        var d = punyCharToDigit(input[p].charCodeAt(0)); p++;
        if (d > (0x7fffffff - i) / w) throw new Error('Punycode 溢出');
        i += d * w;
        var t = k <= bias ? PUNY_TMIN : (k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias);
        if (d < t) break;
        var wt = PUNY_BASE - t;
        if (w > 0x7fffffff / wt) throw new Error('Punycode 溢出');
        w *= wt;
      }
      bias = punyAdapt(i - oldi, outLen + 1, oldi === 0);
      if (((i / (outLen + 1)) | 0) > 0x7fffffff - n) throw new Error('Punycode 溢出');
      n += (i / (outLen + 1)) | 0;
      i %= (outLen + 1);
      out.splice(i, 0, String.fromCodePoint(n));
      i++; outLen++;
    }
    return out.join('');
  }

  function b64urlEnc(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function b64urlDec(s) {
    s = String(s).replace(/-/g, '+').replace(/_/g, '/').trim();
    while (s.length % 4) s += '=';
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  var G = '编码';
  reg({ id: 'base45', name: 'Base45', group: G, key: false, param: false,
    info: 'RFC 草案 Base45，二维码疫苗证书用。2 字节→3 字符，1 字节→2 字符。',
    enc: function (b) { return b45enc(b); },
    dec: function (s) { return b45dec(String(s).replace(/[\r\n]+$/, '')); } });
  reg({ id: 'base62', name: 'Base62', group: G, key: false, param: false,
    info: '0-9a-zA-Z 共 62 字符，常用于短链接。',
    enc: function (b) { return b62enc(b); }, dec: function (s) { return b62dec(String(s).trim()); } });
  reg({ id: 'base91', name: 'basE91', group: G, key: false, param: false,
    info: 'basE91（Joachim Henke），比 Base64 更省空间，输出含符号。',
    enc: function (b) { return b91enc(b); }, dec: function (s) { return b91dec(String(s)); } });
  reg({ id: 'rot47', name: 'ROT47', group: G, key: false, param: false,
    info: 'ASCII 33~126 范围内旋转 47 位，含数字与符号。',
    enc: function (b) { return rot47(bytesToStr(b)); }, dec: function (s) { return strToBytes(rot47(String(s))); } });
  reg({ id: 'quoted-printable', name: 'Quoted-printable', group: G, key: false, param: false,
    info: 'RFC 2045 邮件编码。非可打印字节写成 =XX，行末空格与 TAB 也会转义。',
    enc: function (b) { return qpenc(b); }, dec: function (s) { return qpdec(String(s)); } });
  reg({ id: 'uuencode', name: 'UUEncode', group: G, key: false, param: false,
    info: '传统 Unix 二进制编码，含 begin/end 包裹行。',
    enc: function (b) { return uuenc(b); }, dec: function (s) { return uudec(String(s)); } });
  reg({ id: 'punycode', name: 'Punycode', group: G, key: false, param: false,
    info: 'RFC 3492，国际化域名编码（输入 Unicode 文字，输出 xn-- 后的部分）。',
    enc: function (b) { return punyEncode(bytesToStr(b)); }, dec: function (s) { return strToBytes(punyDecode(String(s).trim())); } });
  reg({ id: 'base64url', name: 'Base64url', group: G, key: false, param: false,
    info: 'RFC 4648 §5，URL/文件名安全变体（- 与 _，无填充 =），JWT 用。',
    enc: function (b) { return b64urlEnc(b); }, dec: function (s) { return b64urlDec(String(s)); } });

  globalThis.ENC2 = { b45enc: b45enc, b45dec: b45dec, b62enc: b62enc, b62dec: b62dec,
    b91enc: b91enc, b91dec: b91dec, punyEncode: punyEncode, punyDecode: punyDecode,
    qpenc: qpenc, qpdec: qpdec, uuenc: uuenc, uudec: uudec,
    b64urlEnc: b64urlEnc, b64urlDec: b64urlDec };
})();
