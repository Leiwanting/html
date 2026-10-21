/* ============================================================
 * age v1（age-encryption.org/v1）X25519 —— 加密 / 解密
 * ============================================================
 * 规范要点（与 age v1.2.1 源码核对）：
 *   salt      = ephemeral_share ‖ recipient_public      （64 字节，不是 32）
 *   wrap_key  = HKDF-SHA256(ikm=shared, salt=salt, info="age-encryption.org/v1/X25519", 32)
 *   wrapped   = ChaCha20-Poly1305(wrap_key, nonce=12×0x00).seal(file_key 16B)  → 32 字节
 *   mac_key   = HKDF-SHA256(ikm=file_key, salt="", info="header", 32)
 *               ⚠ 用 file_key 而不是 shared_secret —— 只有能解出 file_key 的人才能改 header
 *   header MAC= HMAC-SHA256(mac_key, 除 "--- " 行之外的整个 header)
 *   payload   = 16 字节随机 nonce ‖ STREAM(ChaCha20-Poly1305)
 *   stream_key= HKDF-SHA256(ikm=file_key, salt=payload_nonce, info="payload", 32)
 *   STREAM 块 nonce = 12 字节：nonce[0]=1 表示最后一块，nonce[4..12] 是大端块序号（从 0 起）
 * 参照物：age 官方仓库 testdata/example.age（用官方私钥必须解出 "Black lives matter."）
 * ============================================================ */
var AGE_V1 = 'age-encryption.org/v1';
var AGE_X25519_LABEL = 'age-encryption.org/v1/X25519';
var AGE_BASE_POINT = (function () { var b = new Uint8Array(32); b[0] = 9; return b; })();

function ageBech32Decode(s) {
  var CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  s = String(s || '').trim();
  var idx = s.lastIndexOf('1');
  if (idx < 1) throw new Error('不是合法的 bech32 串（缺少分隔符 "1"）：' + s.slice(0, 20));
  var hrp = s.slice(0, idx), data = s.slice(idx + 1).toLowerCase();
  /* 校验和校验 */
  function polymod(v) {
    var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    var chk = 1;
    for (var i = 0; i < v.length; i++) {
      var top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v[i];
      for (var j = 0; j < 5; j++) if ((top >> j) & 1) chk ^= GEN[j];
    }
    return chk;
  }
  function hrpExpand(h) {
    var out = [];
    for (var i = 0; i < h.length; i++) out.push(h.charCodeAt(i) >> 5);
    out.push(0);
    for (var i = 0; i < h.length; i++) out.push(h.charCodeAt(i) & 31);
    return out;
  }
  var vals = [];
  for (var i = 0; i < data.length; i++) {
    var p = CHARSET.indexOf(data[i]);
    if (p < 0) throw new Error('bech32 含非法字符：' + data[i]);
    vals.push(p);
  }
  if (polymod(hrpExpand(hrp.toLowerCase()).concat(vals)) !== 1) throw new Error('bech32 校验和不正确');
  /* 去 6 位校验和 → 5 位组 → 8 位字节 */
  vals = vals.slice(0, vals.length - 6);
  var bits = 0, acc = 0, out = [];
  for (var i = 0; i < vals.length; i++) {
    acc = (acc << 5) | vals[i]; bits += 5;
    while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
  }
  return { hrp: hrp, data: new Uint8Array(out) };
}
async function ageIdentityToPublic(priv32) {
  return await x25519Derive(priv32, AGE_BASE_POINT);
}
/* 解析 age 文件头。
   MAC 覆盖的范围是「首行到 wrapped key 行（含其换行）」，不含 "--- " 那一行。
   逐字节 latin1 拼接（每个字节一个字符，索引与字节偏移 1:1），避免多字节错位。 */
function ageParseHeader(buf) {
  var text = '';
  for (var i = 0; i < buf.length; i++) text += String.fromCharCode(buf[i]);
  var idx = text.indexOf('\n--- ');
  if (idx < 0) throw new Error('不是 age v1 文件：找不到 "--- " MAC 行');
  var headerNoMac = text.slice(0, idx + 1);           /* 含 MAC 行之前的最后一个 \n */
  var rest = text.slice(idx + 1);
  var nl = rest.indexOf('\n');
  if (nl < 0) throw new Error('age 文件头格式错误：MAC 行后没有换行');
  var macLine = rest.slice(0, nl);                     /* "--- <mac>" */
  var macB64 = macLine.slice(4).trim();
  var bodyStart = idx + 1 + nl + 1;                    /* payload 起始字节偏移 */
  var lines = headerNoMac.split('\n');
  lines.pop();                                          /* 末尾空串 */
  var stanzas = [];
  for (var k = 1; k < lines.length; k++) {
    if (lines[k].indexOf('-> ') === 0) {
      var parts = lines[k].slice(3).split(' ');
      stanzas.push({ type: parts[0], args: parts.slice(1), bodyB64: (lines[k + 1] || '').trim() });
      k++;
    }
  }
  return { version: lines[0], headerNoMac: headerNoMac, macB64: macB64, stanzas: stanzas, body: buf.subarray(bodyStart) };
}
async function ageDecrypt(buf, identityPrivHexOrBech32) {
  var priv;
  var s = String(identityPrivHexOrBech32 || '').trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) priv = hexToBytes(s);
  else {
    var d = ageBech32Decode(s);
    if (d.hrp.toUpperCase().replace(/-$/, '') !== 'AGE-SECRET-KEY') throw new Error('不是 age 私钥（hrp 应为 AGE-SECRET-KEY，实际是 ' + d.hrp + '）');
    priv = d.data;
  }
  if (priv.length !== 32) throw new Error('age 私钥必须是 32 字节，当前 ' + priv.length);
  var myPub = await ageIdentityToPublic(priv);
  var h = ageParseHeader(buf);
  if (h.version !== AGE_V1) throw new Error('不是 age v1 文件（首行是 "' + h.version + '"）');
  var st = null;
  for (var i = 0; i < h.stanzas.length; i++) if (h.stanzas[i].type === 'X25519') { st = h.stanzas[i]; break; }
  if (!st) throw new Error('age 文件里没有 X25519 收件人 stanza（本工具目前只支持 X25519）');
  var eph = base64ToBytes(st.args[0]);
  var wrapped = base64ToBytes(st.bodyB64);
  if (eph.length !== 32) throw new Error('X25519 ephemeral share 应为 32 字节，实际 ' + eph.length);
  var shared = await x25519Derive(priv, eph);
  var salt = concatBytes(eph, myPub);
  var wrapKey = hkdfSha256(shared, salt, strToBytes(AGE_X25519_LABEL), 32);
  if (wrapped.length !== 32) throw new Error('wrapped file key 应为 32 字节，实际 ' + wrapped.length);
  var fileKey = chacha20Poly1305Decrypt(wrapped.subarray(0, 16), wrapped.subarray(16), wrapKey, new Uint8Array(12), new Uint8Array(0));
  /* header MAC */
  var macKey = hkdfSha256(fileKey, new Uint8Array(0), strToBytes('header'), 32);
  var expect = base64ToBytes(h.macB64);
  var actual = hmacSha256(macKey, strToBytes(h.headerNoMac));
  var bad = actual.length !== expect.length;
  for (var i = 0; i < actual.length && !bad; i++) if (actual[i] !== expect[i]) bad = true;
  if (bad) throw new Error('age 文件头 MAC 校验失败：文件被篡改或私钥不匹配');
  /* payload */
  if (h.body.length < 16) throw new Error('age payload 过短');
  var pNonce = h.body.subarray(0, 16);
  var streamKey = hkdfSha256(fileKey, pNonce, strToBytes('payload'), 32);
  var data = h.body.subarray(16);
  var CHUNK = 65536;
  var out = [];
  var counter = 0;
  for (var o = 0; o < data.length; ) {
    var isLast = (o + CHUNK + 16 >= data.length);
    var remain = data.length - o;
    var take = isLast ? (remain - 16) : CHUNK;
    if (take < 0) throw new Error('age STREAM 数据长度不合法');
    var ct = data.subarray(o, o + take);
    var tag = data.subarray(o + take, o + take + 16);
    var n = new Uint8Array(12);
    n[0] = isLast ? 1 : 0;
    for (var q = 0; q < 8; q++) n[4 + q] = (counter >>> (8 * (7 - q))) & 0xff;
    var blk = chacha20Poly1305Decrypt(ct, tag, streamKey, n, new Uint8Array(0));
    out.push(blk);
    o += take + 16; counter++;
  }
  var total = 0;
  for (var i = 0; i < out.length; i++) total += out[i].length;
  var res = new Uint8Array(total), pos = 0;
  for (var i = 0; i < out.length; i++) { res.set(out[i], pos); pos += out[i].length; }
  return res;
}
async function ageEncrypt(plain, recipientBech32) {
  var d = ageBech32Decode(recipientBech32);
  if (d.hrp !== 'age') throw new Error('不是 age 收件人公钥（hrp 应为 age，实际是 ' + d.hrp + '）');
  var rPub = d.data;
  if (rPub.length !== 32) throw new Error('age 收件人公钥必须是 32 字节，实际 ' + rPub.length);
  var kp = await x25519GenKeyPair();
  var eph = kp.pub;
  var shared = await x25519Derive(kp.priv, rPub);
  var salt = concatBytes(eph, rPub);
  var wrapKey = hkdfSha256(shared, salt, strToBytes(AGE_X25519_LABEL), 32);
  var fileKey = crypto.getRandomValues(new Uint8Array(16));
  var enc = chacha20Poly1305Encrypt(fileKey, wrapKey, new Uint8Array(12), new Uint8Array(0));
  var wrapped = concatBytes(enc.ciphertext, enc.tag);
  var headerNoMac = AGE_V1 + '\n-> X25519 ' + bytesToBase64(eph) + '\n' + bytesToBase64(wrapped) + '\n';
  var macKey = hkdfSha256(fileKey, new Uint8Array(0), strToBytes('header'), 32);
  var mac = hmacSha256(macKey, strToBytes(headerNoMac));
  var header = headerNoMac + '--- ' + bytesToBase64(mac) + '\n';
  var pNonce = crypto.getRandomValues(new Uint8Array(16));
  var streamKey = hkdfSha256(fileKey, pNonce, strToBytes('payload'), 32);
  var CHUNK = 65536, parts = [], counter = 0;
  for (var o = 0; o <= plain.length; o += CHUNK) {
    var take = Math.min(CHUNK, plain.length - o);
    var isLast = (o + take >= plain.length);
    var n = new Uint8Array(12);
    n[0] = isLast ? 1 : 0;
    for (var q = 0; q < 8; q++) n[4 + q] = (counter >>> (8 * (7 - q))) & 0xff;
    var blk = plain.subarray(o, o + take);
    var e = chacha20Poly1305Encrypt(blk, streamKey, n, new Uint8Array(0));
    parts.push(e.ciphertext, e.tag);
    counter++;
    if (isLast) break;
  }
  return concatBytes(strToBytes(header), pNonce, concatBytes.apply(null, parts));
}
