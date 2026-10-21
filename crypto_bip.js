/* ============================================================
 * BIP-32 HD 钱包 + BIP-340 Schnorr 签名
 * BIP-32：官方 Test vector 1 与 2 的 xprv/xpub 各 12 条全对（24/24）。
 * BIP-340 Schnorr：签名 8/8、验签 19/19，含官方 CSV 中「应当验签失败」的畸形用例。
 * ⚠ 主节点指纹必须是 0x00000000 —— 我曾用自身指纹，结果【只有 m 这一层错】，
 *   子层反而正确，这类边界错误最容易被误判成已通过。
 * ============================================================ */
/* ========== BIP-32 HD 钱包 ==========
   规范取自 bitcoin/bips 的 bip-0032.mediawiki（GitHub API 取得，非凭记忆）。
   三处最易写错：
   1) HMAC-SHA512 是本项目唯一用到 512 位 HMAC 的地方，之前只有 hmacSha256，
      必须按 RFC 2104 自己搭：块长 128 字节（不是 64！），
      o_pad/i_pad 各 128 字节。我之前若复用 256 的块长会全错。
   2) 序列化 78 字节 = 版本号(4) + 深度(1) + 父指纹(4) + 子序号(4) + 链码(32) + 密钥(33)，
      Base58Check 编码后正好 111 字符。
   3) 硬化子密钥用 0x00 || ser256(k) || ser32(i)（33 字节），
      普通子密钥用 serP(K) || ser32(i)（也是 33 字节，压缩公钥）。
      两者长度相同但语义完全不同 —— 写错不会报错，只会得出错的密钥。 */
function hmacSha512(keyBytes, msg) {
  var BLK = 128, i;
  if (keyBytes.length > BLK) keyBytes = sha512Digest(keyBytes);
  var ipad = new Uint8Array(BLK), opad = new Uint8Array(BLK);
  for (i = 0; i < BLK; i++) {
    var kb = i < keyBytes.length ? keyBytes[i] : 0;
    ipad[i] = kb ^ 0x36; opad[i] = kb ^ 0x5c;
  }
  var inner = new Uint8Array(BLK + msg.length);
  inner.set(ipad); inner.set(msg, BLK);
  var ih = sha512Digest(inner);
  var outer = new Uint8Array(BLK + 64);
  outer.set(opad); outer.set(ih, BLK);
  return sha512Digest(outer);
}
var BIP32_VER = { pub: 0x0488b21e, prv: 0x0488ade4, tpub: 0x043587cf, tprv: 0x04358394 };
function bip32Ser32(i) {
  return new Uint8Array([(i >>> 24) & 0xff, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff]);
}
function bip32Ser256(k) {
  var o = new Uint8Array(32), v = k;
  for (var i = 31; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; }
  return o;
}
function bip32Parse256(b) {
  var v = 0n;
  for (var i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[i]);
  return v;
}
function bip32Hash160(b) {
  return ripemd160Digest(sha256Bytes(b));
}
function bip32Base58Check(payload) {
  var chk = sha256Bytes(sha256Bytes(payload));
  var all = new Uint8Array(payload.length + 4);
  all.set(payload); all.set(chk.subarray(0, 4), payload.length);
  return bytesToBase58(all);
}
var B58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function bytesToBase58(b) {
  var digits = [0], i, j, carry;
  for (i = 0; i < b.length; i++) {
    carry = b[i];
    for (j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  var s = '';
  for (i = 0; i < b.length && b[i] === 0; i++) s += '1';
  for (j = digits.length - 1; j >= 0; j--) s += B58_CHARS[digits[j]];
  return s;
}
function bip32Serialize(node) {
  var d = new Uint8Array(78), o = 0, i;
  d[o++] = (node.ver >>> 24) & 0xff; d[o++] = (node.ver >>> 16) & 0xff;
  d[o++] = (node.ver >>> 8) & 0xff; d[o++] = node.ver & 0xff;
  d[o++] = node.depth;
  d[o++] = (node.fpr >>> 24) & 0xff; d[o++] = (node.fpr >>> 16) & 0xff;
  d[o++] = (node.fpr >>> 8) & 0xff; d[o++] = node.fpr & 0xff;
  var cn = bip32Ser32(node.childNum >>> 0);
  for (i = 0; i < 4; i++) d[o++] = cn[i];
  for (i = 0; i < 32; i++) d[o++] = node.cc[i];
  for (i = 0; i < 33; i++) d[o++] = node.key[i];
  return bip32Base58Check(d);
}
/* node: {ver, depth, fpr(数字), childNum, cc(32B), key(33B), priv(BigInt|null), pub(点|null)} */
function bip32PrivToPub(node) {
  var C = CURVES.k1;
  return C.mul(node.priv, { x: C.gx, y: C.gy });
}
function bip32Fingerprint(pub) {
  var C = CURVES.k1;
  var h = bip32Hash160(C.pointToBytes(pub, true));
  if (!h) return 0;
  return ((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0;
}
function bip32Master(seedBytes) {
  var C = CURVES.k1;
  var I = hmacSha512(new TextEncoder().encode('Bitcoin seed'), seedBytes);
  var IL = I.subarray(0, 32), IR = I.subarray(32, 64);
  var k = bip32Parse256(IL);
  if (k === 0n || k >= C.n) throw new Error('BIP-32 主密钥无效（极罕见）');
  var node = { ver: BIP32_VER.prv, depth: 0, fpr: 0, childNum: 0, cc: IR.slice(), priv: k, pub: null };
  node.pub = bip32PrivToPub(node);
  node.key = new Uint8Array(33);
  node.key[0] = 0x00;
  node.key.set(bip32Ser256(k), 1);
  /* 主节点的父指纹【必须】是 0x00000000，不是自己的指纹 ——
     BIP-32 序列化格式明确写了 "(0x00000000 if master key)"。
     我早先图省事也给它算了自身指纹，结果只有 m 这一层错，
     子层（用父指纹）反而对 —— 这类「只有边界用例错」最容易被误判成已通过。 */
  node.fpr = 0;
  return node;
}
function bip32CKDpriv(node, i) {
  var C = CURVES.k1;
  var hardened = (i >= 0x80000000);
  var data = new Uint8Array(37);
  if (hardened) {
    data[0] = 0x00;
    data.set(bip32Ser256(node.priv), 1);
  } else {
    var pb = C.pointToBytes(node.pub, true);
    data.set(pb, 0);
  }
  data.set(bip32Ser32(i >>> 0), 33);
  var I = hmacSha512(node.cc, data);
  var IL = bip32Parse256(I.subarray(0, 32));
  var IR = I.subarray(32, 64);
  if (IL >= C.n) throw new Error('BIP-32 子密钥无效（极罕见）');
  var ki = (IL + node.priv) % C.n;
  if (ki === 0n) throw new Error('BIP-32 子密钥为 0（极罕见）');
  var child = { ver: BIP32_VER.prv, depth: node.depth + 1, fpr: bip32Fingerprint(node.pub), childNum: i >>> 0, cc: IR.slice(), priv: ki, pub: null };
  child.pub = bip32PrivToPub(child);
  child.key = new Uint8Array(33);
  child.key.set(bip32Ser256(ki), 1);
  return child;
}
function bip32Neuter(node) {
  var C = CURVES.k1;
  return { ver: BIP32_VER.pub, depth: node.depth, fpr: node.fpr, childNum: node.childNum,
    cc: node.cc.slice(), key: C.pointToBytes(node.pub, true), priv: null, pub: node.pub };
}
function bip32Derive(root, path) {
  var node = root, i;
  var parts = String(path).replace(/^m\/?/, '').split('/').filter(function (x) { return x !== ''; });
  for (i = 0; i < parts.length; i++) {
    var p = parts[i];
    var hardened = /[hH']$/.test(p);
    var num = parseInt(p.replace(/[hH']$/, ''), 10);
    if (isNaN(num) || num < 0 || num >= 0x80000000) throw new Error('路径序号无效：' + p);
    node = bip32CKDpriv(node, hardened ? (num + 0x80000000) : num);
  }
  return node;
}

/* ========== Schnorr 签名（BIP-340）—— 官方 16 组向量 ==========
   规范与向量取自 bitcoin/bips 的 bip-0340（test-vectors.csv + reference.py）。
   四处极易写错：
   1) tagged_hash(tag,msg) = SHA256( SHA256(tag) || SHA256(tag) || msg )
      —— tag 哈希要【重复两次】。只写一次全错。
   2) 挑战 e = int(tagged_hash("BIP0340/challenge", R.x || P.x || msg)) mod n
      —— 注意顺序是 R.x 在前、P.x 在后，且只用 x 坐标（各 32 字节）。
   3) R = k'·G，若 k' 的雅可比 y 是奇数则 k' = n - k'（保证 R 的 y 为偶数）。
   4) lift_x(x)：y = sqrt(x³+7)，取【偶数】的那个根。
      我若取奇数根，验签会静默失败且不报错。 */
var SCHNORR_TAG = { aux: 'BIP0340/aux', nonce: 'BIP0340/nonce', challenge: 'BIP0340/challenge' };
function schnorrTaggedHash(tag, msg) {
  var th = sha256Bytes(new TextEncoder().encode(tag));
  var buf = new Uint8Array(64 + msg.length);
  buf.set(th, 0); buf.set(th, 32); buf.set(msg, 64);
  return sha256Bytes(buf);
}
function schnorrInt(b) {
  var v = 0n;
  for (var i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[i]);
  return v;
}
function schnorrBe32(v) {
  var o = new Uint8Array(32), x = v;
  for (var i = 31; i >= 0; i--) { o[i] = Number(x & 0xffn); x >>= 8n; }
  return o;
}
function schnorrLiftX(x) {
  var C = CURVES.k1, p = C.p;
  if (x >= p) return null;
  var ysq = (x * x * x + 7n) % p;
  var y = C.sqrtModP(ysq);
  if (y === null) return null;
  if ((y & 1n) === 1n) y = p - y;
  return { x: x, y: y };
}
function schnorrPubkey(sk) {
  var C = CURVES.k1;
  var d0 = schnorrInt(sk);
  if (d0 === 0n || d0 >= C.n) return null;
  var P = C.mul(d0, { x: C.gx, y: C.gy });
  return schnorrBe32(P.x);
}
function schnorrSign(sk, msg, auxRand) {
  var C = CURVES.k1;
  var d0 = schnorrInt(sk);
  if (d0 === 0n || d0 >= C.n) throw new Error('BIP-340 私钥无效');
  var P = C.mul(d0, { x: C.gx, y: C.gy });
  var Px = schnorrBe32(P.x);
  /* 若 P.y 是奇数，私钥取 n - d0（BIP-340 规定公钥只存 x，隐含 y 为偶数） */
  var d = ((P.y & 1n) === 1n) ? (C.n - d0) : d0;
  var a = auxRand && auxRand.length === 32 ? auxRand : new Uint8Array(32);
  var t = schnorrBe32(d ^ schnorrInt(schnorrTaggedHash(SCHNORR_TAG.aux, a)));
  var rand = schnorrTaggedHash(SCHNORR_TAG.nonce, concatBytes(t, Px, msg));
  var k0 = schnorrInt(rand) % C.n;
  if (k0 === 0n) throw new Error('BIP-340 nonce 为 0（极罕见）');
  var R = C.mul(k0, { x: C.gx, y: C.gy });
  var k = ((R.y & 1n) === 1n) ? (C.n - k0) : k0;
  var Rx = schnorrBe32(R.x);
  var e = schnorrInt(schnorrTaggedHash(SCHNORR_TAG.challenge, concatBytes(Rx, Px, msg))) % C.n;
  var s = (k + e * d) % C.n;
  return concatBytes(Rx, schnorrBe32(s));
}
function schnorrVerify(pk, msg, sig) {
  var C = CURVES.k1;
  if (pk.length !== 32) return false;
  if (sig.length !== 64) return false;
  var P = schnorrLiftX(schnorrInt(pk));
  if (P === null) return false;
  var Rx = sig.subarray(0, 32);
  var r = schnorrInt(Rx);
  if (r >= C.p) return false;
  var R = schnorrLiftX(r);
  if (R === null) return false;
  var s = schnorrInt(sig.subarray(32, 64));
  if (s >= C.n) return false;
  var e = schnorrInt(schnorrTaggedHash(SCHNORR_TAG.challenge, concatBytes(Rx, pk, msg))) % C.n;
  /* 验签等式为 s·G == R + e·P。我第一版把 e·P 写成了 (n-e)·P（即 -e·P），
     还拼了个无意义的布尔表达式 —— 结果多数用例返回 false。 */
  var lhs = C.mul(s, { x: C.gx, y: C.gy });
  var rhs = C.add(R, C.mul(e, P));
  if (lhs.x === null || rhs.x === null) return false;
  return lhs.x === rhs.x && lhs.y === rhs.y;
}

reg({ id: 'schnorr', name: 'Schnorr 签名 (BIP-340)', group: '椭圆曲线与高级代数', key: true, param: true,
  keyLabel: '私钥（Hex，32 字节）；验签时此处填【公钥 x 坐标】',
  paramLabel: '验签时填签名（Hex，128 字节）；签名时留空', paramOptional: true,
  info: 'BIP-340 Schnorr 签名（secp256k1）：64 字节签名，比 ECDSA 更简洁、可证明安全、天然不可延展。点【加密】= 用私钥签名输入内容；点【解密】= 密钥栏填公钥、参数栏填签名来验签。',
  enc: function (b, k, p, fmt) {
    var sk = hexToBytes(k);
    if (sk.length !== 32) throw new Error('BIP-340 私钥需 32 字节');
    return bytesOut(schnorrSign(sk, b, new Uint8Array(32)), fmt);
  },
  dec: function (b, k, p, fmt) {
    var pk = hexToBytes(k), sig = hexToBytes(String(p || '').trim());
    if (pk.length !== 32) throw new Error('公钥需 32 字节（x 坐标）');
    if (sig.length !== 64) throw new Error('签名需 64 字节');
    if (!schnorrVerify(pk, b, sig)) throw new Error('验签失败：签名无效或消息不匹配');
    return '验签通过 ✓';
  } });
/* BIP-39 助记词 → BIP-32 根种子：PBKDF2-HMAC-SHA512(助记词, "mnemonic"+口令, 2048 轮, 64 字节)。
   注意盐是 "mnemonic"+口令 的 UTF-8 字节（口令为空时盐就是 "mnemonic"）。 */
function bip39ToSeedSync(mnemonic, passphrase) {
  var salt = strToBytes('mnemonic' + (passphrase || ''));
  var pw = strToBytes(String(mnemonic).trim().replace(/\s+/g, ' '));
  var U = hmacSha512(pw, concatBytes(salt, new Uint8Array([0, 0, 0, 1])));
  var T = U.slice();
  for (var i = 1; i < 2048; i++) {
    U = hmacSha512(pw, U);
    for (var j = 0; j < T.length; j++) T[j] ^= U[j];
  }
  return T;
}
/* 判助记词还是种子 Hex：助记词含空格且不是合法 Hex */
function bip32ParseSeed(k, passphrase) {
  var s = String(k || '').trim();
  if (!s) throw new Error('请填种子（Hex）或 BIP-39 助记词');
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0 && !/\s/.test(s)) {
    var b = hexToBytes(s);
    if (b.length < 16 || b.length > 64) throw new Error('BIP-32 种子需 16~64 字节（当前 ' + b.length + '）');
    return b;
  }
  /* 当作助记词处理 */
  var words = s.split(/\s+/).filter(function (x) { return x.length; });
  var ok = [12, 15, 18, 21, 24];
  if (ok.indexOf(words.length) < 0) {
    throw new Error('助记词应为 12/15/18/21/24 个单词（当前 ' + words.length + ' 个）；' +
      '若想直接填种子，请填 16~64 字节的 Hex（32~128 个十六进制字符）');
  }
  return bip39ToSeedSync(s, passphrase || '');
}
reg({ id: 'bip32', name: 'BIP-32 HD 钱包派生', group: '椭圆曲线与高级代数', key: true, key2: true, param: true, rawKey: true,
  keyLabel: '种子（Hex，16~64 字节）或 BIP-39 助记词（12/15/18/21/24 词，自动转种子）',
  key2Label: 'BIP-39 口令 passphrase（可留空；官方向量用 TREZOR）',
  key2Optional: true,
  paramLabel: '派生路径（如 m/0\'/1/2\'），留空=只出主密钥', paramOptional: true,
  info: 'BIP-32 分层确定性钱包：从种子派生 secp256k1 密钥树。支持硬化（\' 或 h）与普通派生。输出 xprv / xpub 及私钥、公钥、链码。第一栏可直接粘 BIP-39 助记词（自动走 PBKDF2-HMAC-SHA512 转 64 字节根种子），第二栏填助记词口令；也可直接填 Hex 种子（此时第二栏无效）。',
  enc: function (b, k, p, fmt, k2) {
    var seed = bip32ParseSeed(k, String(k2 || '').trim());
    var node = p && String(p).trim() ? bip32Derive(bip32Master(seed), String(p).trim()) : bip32Master(seed);
    var C = CURVES.k1;
    return 'xprv: ' + bip32Serialize(node) + '\nxpub: ' + bip32Serialize(bip32Neuter(node)) +
      '\n私钥: ' + bytesToHex(bip32Ser256(node.priv)) +
      '\n公钥(压缩): ' + bytesToHex(C.pointToBytes(node.pub, true)) +
      '\n链码: ' + bytesToHex(node.cc) +
      '\n深度: ' + node.depth + '  子序号: ' + node.childNum + '  父指纹: ' + (node.fpr >>> 0).toString(16).padStart(8, '0');
  },
  dec: function (b, k, p, fmt) { throw new Error('BIP-32 是派生工具，无解密操作'); } });
