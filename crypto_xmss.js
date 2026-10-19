/* XMSS —— RFC 8391 状态化哈希签名（NIST SP 800-208 批准的后量子签名）
 *
 * 官方向量：Botan 2.19.5 src/tests/data/pubkey/
 *   xmss_sig.vec   12 组（签名，4 个 h=10 参数集 × 消息长度 0/4/1000）
 *   xmss_verify.vec 36 组（验签，12 个参数集 × 3 种消息长度）
 * 参数与流程逐行照抄 Botan src/lib/pubkey/xmss/*.cpp。
 *
 * ⚠ 三个必须照官方、凭直觉会写错的点（本项目踩过）：
 *   1. PRF 的索引 concat(idx, 32) 是【32 字节】BE，不是 4 字节；
 *   2. WOTS 私钥 generate() 里 concat<size_t>(i, 32) 同样是【32 字节】；
 *   3. SHAKE 参数集用的是 SHAKE-128(256) 与 SHAKE-256(512)，
 *      不是"n=32 就用 SHAKE256"。n=32→SHAKE128、n=64→SHAKE256。
 */
(function () {
  /* ---------- 参数表（Botan xmss_parameters.cpp） ---------- */
  var P = {
    'SHA2_10_256':   { oid: 1,  n: 32, w: 16, len: 67,  h: 10, hash: 'SHA-256' },
    'SHA2_16_256':   { oid: 2,  n: 32, w: 16, len: 67,  h: 16, hash: 'SHA-256' },
    'SHA2_20_256':   { oid: 3,  n: 32, w: 16, len: 67,  h: 20, hash: 'SHA-256' },
    'SHA2_10_512':   { oid: 4,  n: 64, w: 16, len: 131, h: 10, hash: 'SHA-512' },
    'SHA2_16_512':   { oid: 5,  n: 64, w: 16, len: 131, h: 16, hash: 'SHA-512' },
    'SHA2_20_512':   { oid: 6,  n: 64, w: 16, len: 131, h: 20, hash: 'SHA-512' },
    'SHAKE_10_256':  { oid: 7,  n: 32, w: 16, len: 67,  h: 10, hash: 'SHAKE-128' },
    'SHAKE_16_256':  { oid: 8,  n: 32, w: 16, len: 67,  h: 16, hash: 'SHAKE-128' },
    'SHAKE_20_256':  { oid: 9,  n: 32, w: 16, len: 67,  h: 20, hash: 'SHAKE-128' },
    'SHAKE_10_512':  { oid: 10, n: 64, w: 16, len: 131, h: 10, hash: 'SHAKE-256' },
    'SHAKE_16_512':  { oid: 11, n: 64, w: 16, len: 131, h: 16, hash: 'SHAKE-256' },
    'SHAKE_20_512':  { oid: 12, n: 64, w: 16, len: 131, h: 20, hash: 'SHAKE-256' }
  };
  var BY_OID = {};
  for (var kk in P) BY_OID[P[kk].oid] = kk;

  function len1(n) { return Math.ceil(8 * n / 4); }
  function len2(n, w) { return Math.floor(Math.log(len1(n) * (w - 1)) / Math.log(w)) + 1; }

  /* ---------- 哈希 ----------
   * 性能要点：F/H/PRF 的输入长度固定（3n / 4n / 2n+32），
   * 用模块级 scratch 复用，避免每步都分配新数组。
   * 签名需约 200 万次哈希，逐次分配会让耗时从 3 秒涨到 27 秒。 */
  function dg(mode, buf, n) {
    if (mode === 'SHA-256') return sha256Core(buf, SHA256_IV, n / 4);
    if (mode === 'SHA-512') return sha512Core(buf, IV_512, n);
    if (mode === 'SHAKE-128') return shake128Digest(buf, n);
    if (mode === 'SHAKE-256') return shake256Digest(buf, n);
    throw new Error('XMSS: 未知哈希 ' + mode);
  }
  var _B = null;
  function bufs(n) {
    if (_B && _B.n === n) return _B;
    var i, b = { n: n, prf: new Uint8Array(2 * n + 32), f: new Uint8Array(3 * n), h: new Uint8Array(4 * n) };
    b.prf[n - 1] = 3;   // toByte(3, n)
    b.f[n - 1] = 0;     // toByte(0, n)
    b.h[n - 1] = 1;     // toByte(1, n)
    for (i = 0; i < n - 1; i++) { b.prf[i] = 0; b.f[i] = 0; b.h[i] = 0; }
    _B = b; return b;
  }
  function F(mode, n, key, data) {
    var b = bufs(n).f; b.set(key, n); b.set(data, 2 * n); return dg(mode, b, n);
  }
  function Hh(mode, n, key, data) {
    var b = bufs(n).h; b.set(key, n); b.set(data, 2 * n); return dg(mode, b, n);
  }
  function PRF(mode, n, key, data) {
    var b = bufs(n).prf; b.set(key, n); b.set(data, 2 * n); return dg(mode, b, n);
  }
  function cat(list) {
    var t = 0, i;
    for (i = 0; i < list.length; i++) t += list[i].length;
    var o = new Uint8Array(t), p = 0;
    for (i = 0; i < list.length; i++) { o.set(list[i], p); p += list[i].length; }
    return o;
  }
  var _H = {};   // HMSG 的 toByte(2, n) 前缀
  function hmsgPrefix(n) {
    if (_H[n]) return _H[n];
    var b = new Uint8Array(n); b[n - 1] = 2; return (_H[n] = b);
  }
  function HMSG(mode, n, r, root, idx, msg) {
    return dg(mode, cat([hmsgPrefix(n), r, root, idx, msg]), n);
  }

  /* ---------- Address（32 字节，Botan xmss_address.h） ---------- */
  function Anew() { return new Uint8Array(32); }
  function Acopy(a) { return new Uint8Array(a); }
  function AsetType(a, t) { a[15] = t; for (var i = 16; i < 32; i++) a[i] = 0; }
  function Au32(a, off, v) {
    a[off] = (v >>> 24) & 255; a[off + 1] = (v >>> 16) & 255;
    a[off + 2] = (v >>> 8) & 255; a[off + 3] = v & 255;
  }
  var AsetOTS = function (a, v) { Au32(a, 16, v); };      // hi32(2)
  var AsetLTree = function (a, v) { Au32(a, 16, v); };
  var AsetTreeHeight = function (a, v) { Au32(a, 20, v); }; // lo32(2)
  var AsetChain = function (a, v) { Au32(a, 20, v); };
  var AsetHash = function (a, v) { Au32(a, 24, v); };       // hi32(3)
  var AsetTreeIndex = function (a, v) { Au32(a, 24, v); };
  var AsetMask = function (a, v) { a[31] = v; };
  function Aheight(a) { return ((a[20] << 24) | (a[21] << 16) | (a[22] << 8) | a[23]) >>> 0; }
  function Aindex(a) { return ((a[24] << 24) | (a[25] << 16) | (a[26] << 8) | a[27]) >>> 0; }

  /* ---------- WOTS+ ---------- */
  function baseW(msg, outSize) {
    var res = [], inp = 0, total = 0, bits = 0;
    for (var i = 0; i < outSize; i++) {
      if (bits === 0) { total = msg[inp]; inp++; bits += 8; }
      bits -= 4;                       // lg_w = 4（w = 16）
      res.push((total >> bits) & 15);
    }
    return res;
  }
  function msgDigest(mode, n, w, msg, ln) {
    var l1 = len1(n), l2 = ln - l1;
    var md = baseW(msg, l1);
    var csum = 0;
    for (var i = 0; i < md.length; i++) csum += (w - 1 - md[i]);
    var nb = Math.ceil(l2 * 4 / 8);
    var sh = (8 - ((l2 * 4) % 8));
    if (sh !== 8) csum <<= sh;
    var cb = new Uint8Array(nb);
    for (var j = nb - 1; j >= 0; j--) { cb[j] = csum & 255; csum >>>= 8; }
    return md.concat(baseW(cb, l2));
  }
  function chain(mode, n, w, seed, res, start, steps, adrs) {
    var i;
    for (i = start; i < start + steps && i < w; i++) {
      AsetHash(adrs, i);
      AsetMask(adrs, 1);
      var bm = PRF(mode, n, seed, adrs);
      for (var t = 0; t < n; t++) res[t] ^= bm[t];
      AsetMask(adrs, 0);
      var key = PRF(mode, n, seed, adrs);
      res = F(mode, n, key, res);
    }
    return res;
  }
  function wotsGen(mode, n, privSeed, ln) {
    var out = [], idx = new Uint8Array(32);
    for (var i = 0; i < ln; i++) {
      idx.fill(0); Au32(idx, 28, i);            // concat<size_t>(i, 32)：32 字节 BE
      out.push(PRF(mode, n, privSeed, idx));
    }
    return out;
  }
  function wotsAt(mode, n, wotsSeed, adrs, ln) {
    return wotsGen(mode, n, PRF(mode, n, wotsSeed, adrs), ln);
  }
  function wotsPK(mode, n, w, seed, sk, adrs, ln) {
    var pk = [];
    for (var i = 0; i < ln; i++) {
      AsetChain(adrs, i);
      pk.push(chain(mode, n, w, seed, sk[i], 0, w - 1, adrs));
    }
    return pk;
  }

  /* ---------- 树 ---------- */
  function randHash(mode, n, seed, left, right, adrs) {
    AsetMask(adrs, 0); var key = PRF(mode, n, seed, adrs);
    AsetMask(adrs, 1); var bml = PRF(mode, n, seed, adrs);
    AsetMask(adrs, 2); var bmr = PRF(mode, n, seed, adrs);
    var cx = new Uint8Array(2 * n), i;
    for (i = 0; i < n; i++) { cx[i] = left[i] ^ bml[i]; cx[i + n] = right[i] ^ bmr[i]; }
    return Hh(mode, n, key, cx);
  }
  function ltree(mode, n, seed, pk, adrs, ln) {
    var L = ln;
    AsetTreeHeight(adrs, 0);
    while (L > 1) {
      for (var i = 0; i < (L >> 1); i++) {
        AsetTreeIndex(adrs, i);
        pk[i] = randHash(mode, n, seed, pk[2 * i], pk[2 * i + 1], adrs);
      }
      if (L & 1) pk[L >> 1] = pk[L - 1];
      L = (L >> 1) + (L & 1);
      AsetTreeHeight(adrs, Aheight(adrs) + 1);
    }
    return pk[0];
  }
  // Botan 的栈式 tree_hash_subtree，与 RFC 8391 treeHash 等价
  function treeHash(mode, n, w, ln, seed, wotsSeed, start, tgt, adrs0) {
    var nodes = new Array(tgt + 1), levels = new Array(tgt + 1), level = 0;
    var last = (1 << tgt) + start, i;
    for (i = 0; i <= tgt; i++) levels[i] = 0;
    for (i = start; i < last; i++) {
      var a = Acopy(adrs0);
      AsetType(a, 0); AsetOTS(a, i);
      var sk = wotsAt(mode, n, wotsSeed, a, ln);
      var pk = wotsPK(mode, n, w, seed, sk, a, ln);
      AsetType(a, 1); AsetLTree(a, i);
      nodes[level] = ltree(mode, n, seed, pk, a, ln);
      levels[level] = 0;
      AsetType(a, 2); AsetTreeHeight(a, 0); AsetTreeIndex(a, i);
      while (level > 0 && levels[level] === levels[level - 1]) {
        AsetTreeIndex(a, (Aindex(a) - 1) >> 1);
        nodes[level - 1] = randHash(mode, n, seed, nodes[level - 1], nodes[level], a);
        levels[level - 1]++; level--;
        AsetTreeHeight(a, Aheight(a) + 1);
      }
      level++;
    }
    return nodes[level - 1];
  }

  /* ---------- 密钥解析 ---------- */
  function parseSK(raw, n) {
    var skLen = 8 + 4 * n;   // oid(4)+root(n)+pseed(n)+idx(4)+prf(n)+wseed(n)
    if (raw.length !== skLen) throw new Error('XMSS 私钥长度应为 ' + skLen + ' 字节，实为 ' + raw.length);
    var oid = ((raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]) >>> 0;
    var o = 4, name = BY_OID[oid];
    if (!name) throw new Error('未知 XMSS 参数集 OID：' + oid);
    if (P[name].n !== n) n = P[name].n;
    var root = raw.subarray(o, o + n); o += n;
    var pseed = raw.subarray(o, o + n); o += n;
    var leaf = ((raw[o] << 24) | (raw[o + 1] << 16) | (raw[o + 2] << 8) | raw[o + 3]) >>> 0; o += 4;
    var prf = raw.subarray(o, o + n); o += n;
    var wseed = raw.subarray(o, o + n); o += n;
    return { name: name, oid: oid, root: root, pseed: pseed, leaf: leaf, prf: prf, wseed: wseed };
  }

  /* ---------- 签名 ---------- */
  function xmssSign(raw, msg, name) {
    var p = P[name];
    if (!p) throw new Error('未知参数集：' + name);
    var n = p.n, w = p.w, ln = p.len, mode = p.hash;
    var sk = parseSK(raw, n);
    var idx32 = new Uint8Array(32); Au32(idx32, 28, sk.leaf);   // concat(idx, 32)
    var rnd = PRF(mode, n, sk.prf, idx32);
    var idxN = new Uint8Array(n); Au32(idxN, n - 4, sk.leaf);
    var mh = HMSG(mode, n, rnd, sk.root, idxN, msg);

    var a0 = Anew(); AsetType(a0, 2);
    var auth = [], j;
    for (j = 0; j < p.h; j++) {
      var b = 1 << j, k = ((sk.leaf / b) | 0) ^ 1;
      auth.push(treeHash(mode, n, w, ln, sk.pseed, sk.wseed, k * b, j, a0));
    }
    var a2 = Anew(); AsetType(a2, 0); AsetOTS(a2, sk.leaf);
    var wsig = wotsSign(mode, n, w, ln, sk.wseed, sk.pseed, mh, a2);
    var out = [idx32.subarray(28, 32), rnd];
    for (j = 0; j < ln; j++) out.push(wsig[j]);
    for (j = 0; j < p.h; j++) out.push(auth[j]);
    return { sig: cat(out), leaf: sk.leaf, next: sk.leaf + 1 };
  }
  function wotsSign(mode, n, w, ln, wotsSeed, seed, msg, adrs) {
    var md = msgDigest(mode, n, w, msg, ln);
    var sk = wotsAt(mode, n, wotsSeed, adrs, ln), out = [];
    for (var i = 0; i < ln; i++) {
      AsetChain(adrs, i);
      out.push(chain(mode, n, w, seed, sk[i], 0, md[i], adrs));
    }
    return out;
  }

  /* ---------- 验签 ---------- */
  function xmssVerify(pkRaw, msg, sig, name) {
    var p = P[name];
    if (!p) throw new Error('未知参数集：' + name);
    var n = p.n, w = p.w, ln = p.len, mode = p.hash, i;
    var oid = ((pkRaw[0] << 24) | (pkRaw[1] << 16) | (pkRaw[2] << 8) | pkRaw[3]) >>> 0;
    if (BY_OID[oid] !== name) throw new Error('公钥 OID(' + oid + ') 与所选参数集 ' + name + ' 不符');
    var root = pkRaw.subarray(4, 4 + n), pseed = pkRaw.subarray(4 + n, 4 + 2 * n);
    if (pkRaw.length !== 4 + 2 * n) throw new Error('公钥长度应为 ' + (4 + 2 * n) + ' 字节，实为 ' + pkRaw.length);
    var expLen = 4 + n + ln * n + p.h * n;
    if (sig.length !== expLen) throw new Error('签名长度应为 ' + expLen + ' 字节，实为 ' + sig.length);
    var o = 0;
    var leaf = ((sig[0] << 24) | (sig[1] << 16) | (sig[2] << 8) | sig[3]) >>> 0; o = 4;
    var rnd = sig.subarray(o, o + n); o += n;
    var wsig = []; for (i = 0; i < ln; i++) { wsig.push(sig.subarray(o, o + n)); o += n; }
    var auth = []; for (i = 0; i < p.h; i++) { auth.push(sig.subarray(o, o + n)); o += n; }

    var idxN = new Uint8Array(n); Au32(idxN, n - 4, leaf);
    var mh = HMSG(mode, n, rnd, root, idxN, msg);

    var a = Anew(); AsetType(a, 0); AsetOTS(a, leaf);
    var md = msgDigest(mode, n, w, mh, ln);
    var pk = [];
    for (i = 0; i < ln; i++) {
      AsetChain(a, i);
      pk.push(chain(mode, n, w, pseed, wsig[i], md[i], w - 1 - md[i], a));
    }
    AsetType(a, 1); AsetLTree(a, leaf);
    var node = ltree(mode, n, pseed, pk, a, ln);
    AsetType(a, 2);
    for (i = 0; i < p.h; i++) {
      AsetTreeHeight(a, i); AsetTreeIndex(a, leaf >> i);
      node = ((leaf >> i) & 1) === 0
        ? randHash(mode, n, pseed, node, auth[i], a)
        : randHash(mode, n, pseed, auth[i], node, a);
    }
    var ok = node.length === root.length;
    if (ok) for (i = 0; i < n; i++) if (node[i] !== root[i]) { ok = false; break; }
    return { ok: ok, root: node, idx: leaf };
  }

  /* ---------- 密钥生成（仅 h=10，树高 20 需百万级叶子，浏览器不现实） ---------- */
  function xmssKeygen(name, seedBytes) {
    var p = P[name];
    if (!p) throw new Error('未知参数集：' + name);
    if (p.h !== 10) throw new Error('密钥生成仅支持 h=10 参数集（' + name + ' 的 h=' + p.h + ' 需 ' + (1 << p.h) + ' 个叶子，浏览器不现实）');
    var n = p.n, w = p.w, ln = p.len, mode = p.hash;
    var rnd = (seedBytes && seedBytes.length >= 3 * n)
      ? seedBytes : (function () {
        var b = new Uint8Array(3 * n);
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(b);
        else for (var i = 0; i < b.length; i++) b[i] = (Math.random() * 256) | 0;
        return b;
      })();
    var pseed = rnd.subarray(0, n), prf = rnd.subarray(n, 2 * n), wseed = rnd.subarray(2 * n, 3 * n);
    var a0 = Anew(); AsetType(a0, 2);
    var root = treeHash(mode, n, w, ln, pseed, wseed, 0, p.h, a0);
    var oidB = new Uint8Array(4); Au32(oidB, 0, p.oid);
    var leaf0 = new Uint8Array(4);
    return {
      sk: cat([oidB, root, pseed, leaf0, prf, wseed]),
      pk: cat([oidB, root, pseed])
    };
  }

  globalThis.XMSS = {
    PARAMS: P, BY_OID: BY_OID, sign: xmssSign, verify: xmssVerify,
    keygen: xmssKeygen, parseSK: parseSK
  };
})();

/* ---------- 界面条目 ---------- */
(function () {
  if (typeof reg !== 'function') return;
  var NAMES = ['SHA2_10_256', 'SHA2_16_256', 'SHA2_20_256', 'SHA2_10_512', 'SHA2_16_512', 'SHA2_20_512',
               'SHAKE_10_256', 'SHAKE_16_256', 'SHAKE_20_256', 'SHAKE_10_512', 'SHAKE_16_512', 'SHAKE_20_512'];
  function pickName(s) {
    if (!s) return 'SHA2_10_256';
    var t = String(s).trim().replace(/^XMSS-/, '').toUpperCase();
    if (XMSS.PARAMS[t]) return t;
    throw new Error('未知参数集：' + s + '（可选：' + NAMES.join(' / ') + '）');
  }
  function hexToBytes(s) {
    var t = String(s || '').replace(/[\s,:]/g, '').replace(/^0[xX]/, '');
    if (t.length % 2) throw new Error('十六进制长度必须为偶数');
    if (!/^[0-9a-fA-F]*$/.test(t)) throw new Error('含非十六进制字符');
    var o = new Uint8Array(t.length / 2);
    for (var i = 0; i < o.length; i++) o[i] = parseInt(t.substr(i * 2, 2), 16);
    return o;
  }
  function toHex(u) {
    var s = '';
    for (var i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
    return s;
  }
  function split(s) { return String(s || '').split(',').map(function (x) { return x.trim(); }).filter(function (x) { return x; }); }

  reg({
    id: 'xmss-verify',
    name: 'XMSS 验签（RFC 8391 后量子哈希签名）',
    group: '后量子密码',
    key: true, param: true,
    keyLabel: '公钥（Hex，68 或 132 字节）',
    paramLabel: '签名（Hex）+ 参数集，逗号分隔；默认 SHA2_10_256',
    info: '验证 XMSS 签名：由 WOTS+ 签名还原叶子公钥 → L-tree → 沿认证路径上溯 → 比对根。属状态化哈希签名（NIST SP 800-208 批准），安全性仅依赖哈希函数。官方向量 36/36（12 个参数集）。',
    enc: async function (b, k, p, fmt) {
      var pk = hexToBytes(k);
      var pf = split(p);
      var sig = hexToBytes(pf[0] || '');
      var name = pickName(pf[1]);
      var r = XMSS.verify(pk, b, sig, name);
      return { text: '验签结果：' + (r.ok ? '有效 ✓' : '无效 ✗') + '\n签名索引 idx = ' + r.idx + '\n计算出的根 = ' + toHex(r.root) };
    }
  });

  reg({
    id: 'xmss-sign',
    name: 'XMSS 签名（RFC 8391，仅 h=10）',
    group: '后量子密码',
    key: true, param: true,
    keyLabel: '私钥（Hex，136 或 264 字节）',
    paramLabel: '参数集，默认 SHA2_10_256',
    info: 'XMSS 签名：消息经 H_msg 绑定随机量与根 → WOTS+ 签名 + 认证路径。⚠ 状态化：同一 leaf index 复用会导致私钥泄露，签名后须把私钥内索引 +1。官方向量 12/12。仅支持 h=10（h=16/20 需数万至百万叶子）。',
    enc: async function (b, k, p, fmt) {
      var sk = hexToBytes(k);
      var name = pickName(split(p)[0]);
      var r = XMSS.sign(sk, b, name);
      return { text: '签名（' + r.sig.length + ' 字节）:\n' + toHex(r.sig) +
        '\n\n使用 leaf index = ' + r.leaf + '，下次请用 ' + r.next };
    }
  });

  reg({
    id: 'xmss-keygen',
    name: 'XMSS 密钥生成（RFC 8391，仅 h=10）',
    group: '后量子密码',
    param: true,
    paramLabel: '参数集，默认 SHA2_10_256',
    info: '生成 XMSS 密钥对：私钥含 OID‖根‖公钥种子‖索引‖PRF‖WOTS 种子，公钥为 OID‖根‖公钥种子。需建 1024 叶子的 Merkle 树（每叶一个 WOTS+ 公钥），耗时数秒。仅支持 h=10。',
    enc: async function (b, k, p, fmt) {
      var name = pickName(split(p)[0]);
      var r = XMSS.keygen(name, b && b.length ? b : null);
      return { text: '参数集 = XMSS-' + name + '\n公钥（' + r.pk.length + ' 字节）:\n' + toHex(r.pk) +
        '\n\n私钥（' + r.sk.length + ' 字节）:\n' + toHex(r.sk) };
    }
  });
})();
