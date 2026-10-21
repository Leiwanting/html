/* ============================================================
 * age v1（age-encryption.org/v1）X25519 —— 密钥生成 / 加密 / 解密
 * ============================================================
 * 参照物：FiloSottile/age v1.2.1 官方仓库
 *   testdata/example.age + testdata/example_keys.txt
 *   age_test.go 明确：该私钥解密该文件应得到 "Black lives matter."
 *
 * ⚠ 本文件此前有 3 个 bug，都是「能自洽、一碰官方就错」的类型：
 *   1) header MAC 少算了 "---"
 *      官方 format.MarshalWithoutMAC 在末尾写入 footerPrefix = "---"，
 *      MAC 覆盖的是 [版本行 + 全部 stanza + "---"]，不含空格和 MAC 本身。
 *      少算这 3 个字节 → 任何官方文件都判为「被篡改」。
 *   2) STREAM 分块 nonce 的 final 标志位置错了
 *      官方 internal/stream/stream.go：
 *        setLastChunkFlag: nonce[len(nonce)-1] = 1   ← 最后 1 字节
 *        incNonce:         从 nonce[10] 往 nonce[0] 递增 ← 前 11 字节是 88 位大端计数器
 *      我原先写成 nonce[0]=1 + 计数器放 nonce[4..12]，自洽能过、官方全错。
 *   3) base64 有填充
 *      官方用 base64.RawStdEncoding.Strict()（无 '='）。带 '=' 官方直接拒绝。
 * ============================================================ */
var AGE_V1 = 'age-encryption.org/v1';
var AGE_X25519_LABEL = 'age-encryption.org/v1/X25519';
var AGE_BASE_POINT = (function () { var b = new Uint8Array(32); b[0] = 9; return b; })();
var AGE_CHUNK = 65536;

/* ---- bech32（BIP-173 变体：age 私钥用大写 HRP + 大写串） ---- */
var AGE_B32_CS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function ageBech32Polymod(v) {
  var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  var chk = 1;
  for (var i = 0; i < v.length; i++) {
    var top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v[i];
    for (var j = 0; j < 5; j++) if ((top >> j) & 1) chk ^= GEN[j];
  }
  return chk;
}
function ageBech32HrpExpand(h) {
  var out = [], i;
  for (i = 0; i < h.length; i++) out.push(h.charCodeAt(i) >> 5);
  out.push(0);
  for (i = 0; i < h.length; i++) out.push(h.charCodeAt(i) & 31);
  return out;
}
function ageBech32Encode(hrp, data) {
  var vals = [], acc = 0, bits = 0, i;
  for (i = 0; i < data.length; i++) {
    acc = (acc << 8) | data[i]; bits += 8;
    while (bits >= 5) { bits -= 5; vals.push((acc >> bits) & 31); }
  }
  if (bits) vals.push((acc << (5 - bits)) & 31);
  var comb = ageBech32HrpExpand(hrp).concat(vals), chk = ageBech32Polymod(comb.concat([0, 0, 0, 0, 0, 0])) ^ 1;
  var cs = [];
  for (i = 0; i < 6; i++) cs.push((chk >> (5 * (5 - i))) & 31);
  var s = hrp + '1';
  for (i = 0; i < vals.length; i++) s += AGE_B32_CS[vals[i]];
  for (i = 0; i < 6; i++) s += AGE_B32_CS[cs[i]];
  return s;
}
function ageBech32Decode(s) {
  s = String(s || '').trim();
  if (s.toLowerCase() !== s && s.toUpperCase() !== s) throw new Error('bech32 不允许大小写混用');
  var idx = s.lastIndexOf('1');
  if (idx < 1) throw new Error('不是合法的 bech32 串（缺少分隔符 "1"）：' + s.slice(0, 20));
  var hrp = s.slice(0, idx).toLowerCase(), data = s.slice(idx + 1).toLowerCase();
  var vals = [];
  for (var i = 0; i < data.length; i++) {
    var p = AGE_B32_CS.indexOf(data[i]);
    if (p < 0) throw new Error('bech32 含非法字符：' + data[i]);
    vals.push(p);
  }
  if (vals.length < 6) throw new Error('bech32 校验和过短');
  if (ageBech32Polymod(ageBech32HrpExpand(hrp).concat(vals)) !== 1) throw new Error('bech32 校验和不正确');
  vals = vals.slice(0, vals.length - 6);
  var bits = 0, acc = 0, out = [];
  for (i = 0; i < vals.length; i++) {
    acc = (acc << 5) | vals[i]; bits += 5;
    while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
  }
  return { hrp: hrp, data: new Uint8Array(out) };
}
/* ---- base64：age 用 RawStdEncoding（无 '='） ---- */
function ageB64(bytes) {
  return bytesToBase64(bytes).replace(/=+$/, '');
}
function ageB64Dec(s) { return base64ToBytes(String(s).trim()); }
/* ---- armor（age -a）：把整个 .age 文件再 base64 一遍，64 列折行 ---- */
function ageArmor(fileBytes) {
  var b = bytesToBase64(fileBytes), lines = [];
  for (var i = 0; i < b.length; i += 64) lines.push(b.slice(i, i + 64));
  return '-----BEGIN AGE ENCRYPTED FILE-----\n' + lines.join('\n') + '\n-----END AGE ENCRYPTED FILE-----\n';
}
function ageDearmor(text) {
  var m = String(text).match(/-----BEGIN AGE ENCRYPTED FILE-----([\s\S]*?)-----END AGE ENCRYPTED FILE-----/);
  if (!m) return null;
  return base64ToBytes(m[1].replace(/\s+/g, ''));
}
async function ageIdentityToPublic(priv32) {
  return await x25519Derive(priv32, AGE_BASE_POINT);
}
/* ---- 解析 age 文件头 ----
   MAC 覆盖范围 = [首行 … 最后一个 stanza 的换行] + "---"
   逐字节 latin1 拼接（每字节一字符），索引与字节偏移 1:1。 */
function ageParseHeader(buf) {
  var text = '', i;
  for (i = 0; i < buf.length; i++) text += String.fromCharCode(buf[i]);
  var idx = text.indexOf('\n--- ');
  if (idx < 0) throw new Error('不是 age v1 文件：找不到 "--- " MAC 行');
  var head = text.slice(0, idx + 1);            /* 含 stanza 后的换行 */
  var covered = head + '---';                    /* ← 官方 footerPrefix */
  var rest = text.slice(idx + 1);                /* 从 "--- " 开始 */
  var nl = rest.indexOf('\n');
  if (nl < 0) throw new Error('age 文件头格式错误：MAC 行后没有换行');
  var macB64 = rest.slice(4, nl).trim();
  var bodyStart = idx + 1 + nl + 1;
  var lines = head.split('\n');
  lines.pop();
  var stanzas = [];
  for (i = 1; i < lines.length; i++) {
    if (lines[i].indexOf('-> ') !== 0) continue;
    var parts = lines[i].slice(3).split(' ');
    var body = '';
    for (var j = i + 1; j < lines.length; j++) {
      if (lines[j].indexOf('-> ') === 0) break;
      body += lines[j];
      i = j;
    }
    stanzas.push({ type: parts[0], args: parts.slice(1), bodyB64: body.trim() });
  }
  return { version: lines[0], covered: covered, macB64: macB64, stanzas: stanzas, body: buf.subarray(bodyStart) };
}
/* STREAM nonce：前 11 字节 = 88 位大端计数器，第 12 字节 = final 标志 */
function ageChunkNonce(counter, isLast) {
  var n = new Uint8Array(12), c = counter, q;
  for (q = 10; q >= 0; q--) { n[q] = c % 256; c = Math.floor(c / 256); }
  if (isLast) n[11] = 1;
  return n;
}
function ageParseIdentity(s) {
  s = String(s || '').trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return hexToBytes(s);
  var d = ageBech32Decode(s);
  if (d.hrp.replace(/-$/, '') !== 'age-secret-key') throw new Error('不是 age 私钥（hrp 应为 AGE-SECRET-KEY，实际是 ' + d.hrp + '）');
  if (d.data.length !== 32) throw new Error('age 私钥必须 32 字节，实际 ' + d.data.length);
  return d.data;
}
function ageParseRecipient(s) {
  s = String(s || '').trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return hexToBytes(s);
  var d = ageBech32Decode(s);
  if (d.hrp !== 'age') throw new Error('不是 age 收件人公钥（hrp 应为 age，实际是 ' + d.hrp + '）');
  if (d.data.length !== 32) throw new Error('age 收件人公钥必须 32 字节，实际 ' + d.data.length);
  return d.data;
}
async function ageDecrypt(buf, identity) {
  var priv = ageParseIdentity(identity);
  var myPub = await ageIdentityToPublic(priv);
  var h = ageParseHeader(buf);
  if (h.version !== AGE_V1) throw new Error('不是 age v1 文件（首行是 "' + h.version + '"）');
  var st = null;
  for (var i = 0; i < h.stanzas.length; i++) if (h.stanzas[i].type === 'X25519') { st = h.stanzas[i]; break; }
  if (!st) throw new Error('age 文件里没有 X25519 收件人 stanza（本工具目前只支持 X25519）');
  var eph = ageB64Dec(st.args[0]);
  var wrapped = ageB64Dec(st.bodyB64);
  if (eph.length !== 32) throw new Error('X25519 ephemeral share 应 32 字节，实际 ' + eph.length);
  if (wrapped.length !== 32) throw new Error('wrapped file key 应 32 字节，实际 ' + wrapped.length);
  var shared = await x25519Derive(priv, eph);
  var wrapKey = hkdfSha256(shared, concatBytes(eph, myPub), strToBytes(AGE_X25519_LABEL), 32);
  var fileKey = chacha20Poly1305Decrypt(wrapped.subarray(0, 16), wrapped.subarray(16), wrapKey, new Uint8Array(12), new Uint8Array(0));
  var macKey = hkdfSha256(fileKey, new Uint8Array(0), strToBytes('header'), 32);
  var expect = ageB64Dec(h.macB64), actual = hmacSha256(macKey, strToBytes(h.covered));
  var bad = actual.length !== expect.length;
  for (i = 0; i < actual.length && !bad; i++) if (actual[i] !== expect[i]) bad = true;
  if (bad) throw new Error('age 文件头 MAC 校验失败：文件被篡改，或私钥不是该文件的收件人');
  if (h.body.length < 16) throw new Error('age payload 过短（缺少 16 字节 nonce）');
  var streamKey = hkdfSha256(fileKey, h.body.subarray(0, 16), strToBytes('payload'), 32);
  var data = h.body.subarray(16);
  var out = [], counter = 0;
  for (var o = 0; o < data.length; ) {
    var isLast = (o + AGE_CHUNK + 16 >= data.length);
    var take = isLast ? (data.length - o - 16) : AGE_CHUNK;
    if (take < 0) throw new Error('age STREAM 数据长度不合法（最后一块不含完整 16 字节 tag）');
    out.push(chacha20Poly1305Decrypt(data.subarray(o, o + take), data.subarray(o + take, o + take + 16),
      streamKey, ageChunkNonce(counter, isLast), new Uint8Array(0)));
    o += take + 16; counter++;
    if (isLast) break;
  }
  var total = 0;
  for (i = 0; i < out.length; i++) total += out[i].length;
  var res = new Uint8Array(total), pos = 0;
  for (i = 0; i < out.length; i++) { res.set(out[i], pos); pos += out[i].length; }
  return res;
}
async function ageEncrypt(plain, recipient, armor) {
  var rPub = ageParseRecipient(recipient);
  var sk = crypto.getRandomValues(new Uint8Array(32));
  sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
  var eph = await ageIdentityToPublic(sk);
  var shared = await x25519Derive(sk, rPub);
  var wrapKey = hkdfSha256(shared, concatBytes(eph, rPub), strToBytes(AGE_X25519_LABEL), 32);
  var fileKey = crypto.getRandomValues(new Uint8Array(16));
  var enc = chacha20Poly1305Encrypt(fileKey, wrapKey, new Uint8Array(12), new Uint8Array(0));
  var wrapped = concatBytes(enc.ciphertext, enc.tag);
  var head = AGE_V1 + '\n-> X25519 ' + ageB64(eph) + '\n' + ageB64(wrapped) + '\n';
  var macKey = hkdfSha256(fileKey, new Uint8Array(0), strToBytes('header'), 32);
  var mac = hmacSha256(macKey, strToBytes(head + '---'));
  var header = head + '--- ' + ageB64(mac) + '\n';
  var pNonce = crypto.getRandomValues(new Uint8Array(16));
  var streamKey = hkdfSha256(fileKey, pNonce, strToBytes('payload'), 32);
  var parts = [], counter = 0;
  /* 官方 stream.Writer：只有「缓冲区满且还有数据」才刷非末块，
     所以明文正好是 65536 的整数倍时不会多出一块空的末块。 */
  for (var o = 0; o <= plain.length; o += AGE_CHUNK) {
    var take = Math.min(AGE_CHUNK, plain.length - o);
    var isLast = (o + take >= plain.length);
    var e = chacha20Poly1305Encrypt(plain.subarray(o, o + take), streamKey, ageChunkNonce(counter, isLast), new Uint8Array(0));
    parts.push(e.ciphertext, e.tag);
    counter++;
    if (isLast) break;
  }
  var file = concatBytes(strToBytes(header), pNonce, concatBytes.apply(null, parts));
  return armor ? strToBytes(ageArmor(file)) : file;
}
/* ---------------- 注册 ---------------- */
(function () {
  var INFO = 'age v1 文件加密（X25519 收件人）：临时 X25519 → HKDF-SHA256 得 wrap key → ChaCha20-Poly1305 封装 16 字节 file key → header MAC=HMAC-SHA256(头+"---") → 载荷=16 字节 nonce‖STREAM(64KiB 分块)。参照 age v1.2.1 官方 testdata。';
  reg({
    id: 'age-enc', name: 'age 加密（v1 / X25519 收件人）', group: '非对称加密',
    key: true, param: true, dec: false,
    keyLabel: '收件人公钥（age1… 或 64 位 Hex）',
    paramLabel: '参数：填 armor 则输出 PEM 装甲文本（默认输出二进制 .age 文件的 base64）',
    info: INFO,
    enc: async function (b, k, p, fmt) {
      var plain = typeof b === 'string' ? new TextEncoder().encode(b) : new Uint8Array(b);
      if (!k || !String(k).trim()) throw new Error('请填收件人公钥（age1…）');
      var armor = /armor/i.test(String(p || ''));
      var file = await ageEncrypt(plain, String(k).trim(), armor);
      if (armor) return new TextDecoder().decode(file);
      return { text: bytesToBase64(file), textInfo: 'age v1 文件共 ' + file.length + ' 字节（base64）。保存为 .age 后可用官方 age / rage 解密。' };
    }
  });
  reg({
    id: 'age-dec', name: 'age 解密（v1 / X25519 身份）', group: '非对称加密',
    key: true, param: false, enc: false,
    keyLabel: '身份私钥（AGE-SECRET-KEY-1… 或 64 位 Hex）',
    info: 'age v1 文件解密。先校验 header MAC（不匹配直接报错，不会返回错误明文），再按 64KiB 分块解 STREAM。输入框填 .age 文件内容：可以是原始文本、base64，或 -----BEGIN AGE ENCRYPTED FILE----- 装甲文本。参照 FiloSottile/age v1.2.1。',
    dec: async function (text, k, p, fmt) {
      var s = String(text || '');
      var buf = null;
      var arm = ageDearmor(s);
      if (arm) buf = arm;
      if (!buf) {
        var b64 = null;
        try { b64 = base64ToBytes(s.trim()); } catch (e) { b64 = null; }
        if (b64 && b64.length >= AGE_V1.length &&
            new TextDecoder().decode(b64.subarray(0, AGE_V1.length)) === AGE_V1) buf = b64;
      }
      if (!buf) buf = new TextEncoder().encode(s);
      if (!k || !String(k).trim()) throw new Error('请填身份私钥（AGE-SECRET-KEY-1…）');
      var pt = await ageDecrypt(buf, String(k).trim());
      return bytesOut(pt, fmt);
    }
  });
  reg({
    id: 'age-keygen', name: 'age 密钥对生成（v1 身份 + 收件人）', group: '密钥工具',
    key: false, param: false, dec: false,
    info: '生成 age v1 的 X25519 身份：随机 32 字节并按 X25519 规范钳位（sk[0]&=248, sk[31]&=127, sk[31]|=64），公钥 = 基点(9) 的标量乘。私钥编码为 bech32（HRP = AGE-SECRET-KEY-，大写串），公钥编码为 bech32（HRP = age，小写串），与官方 age-keygen 格式一致。',
    enc: async function () {
      var sk = crypto.getRandomValues(new Uint8Array(32));
      sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
      var pk = await ageIdentityToPublic(sk);
      var ident = ageBech32Encode('AGE-SECRET-KEY-', sk).toUpperCase();
      var recip = ageBech32Encode('age', pk);
      return '身份私钥（务必保密）：\n' + ident +
        '\n\n收件人公钥（发给对方用于加密）：\n' + recip +
        '\n\n私钥 Hex: ' + bytesToHex(sk) + '\n公钥 Hex: ' + bytesToHex(pk);
    }
  });
})();
