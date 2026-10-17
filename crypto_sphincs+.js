/* ============================================================
 * SPHINCS+-SHAKE-256-128f (robust) —— round-3 变体
 * 对齐 PySPX 0.5.0（其内部源文件为 thash_shake_robust.c）
 *
 * 参数：n=16 h=66 d=22 h'=3 log_t=6 k=33 a=6 w=16 len=35
 *       PK=32  SK=64  SIG=17088
 *
 * 关键规范要点（全部经 ref/ 官方 C 源码核对）：
 *  1. thash 是 robust 变体：bitmask = shake(pk_seed‖ADRS, blocks*n)，
 *     输出 = shake(pk_seed‖ADRS‖(in XOR bitmask), n)
 *  2. XMSS 叶子 = T_len(pk_seed, WOTSPK地址, wots_pk)，一次 35 块压缩
 *     （不是多轮 l_tree）
 *  3. prf_addr = SHAKE256(pk_seed ‖ ADRS ‖ sk_seed, n)
 *  4. prf_msg = SHAKE256(sk_prf ‖ optrand ‖ m, n)
 *  5. H_msg（SHAKE 变体）不用 MGF1，单次 squeeze 34 字节
 *  6. ADRS：layer(0..3) tree(4..15，12 字节) type(16..19) word5..7(20..31)
 *     全部大端；setType 只改 type，不清零后续字段
 *  7. 公钥 root = 最顶层 layer=d-1 的第 0 棵树
 *  8. FORS：k 棵树共享同一个 keypair 地址(= leaf idx)，
 *     tree_index = idx_i + i*64（跨树连续计数）
 * ============================================================ */
var SPX_N = 16, SPX_H = 66, SPX_D = 22, SPX_HP = SPX_H / SPX_D;   /* 3 */
var SPX_K = 33, SPX_A = 6, SPX_T = 1 << SPX_A;                    /* 64 */
var SPX_W = 16, SPX_LEN1 = 32, SPX_LEN2 = 3, SPX_LEN = 35;
var SPX_SIGBYTES = 17088, SPX_PKBYTES = 32, SPX_SKBYTES = 64;
var SPX_FORS_MSG = Math.ceil(SPX_K * SPX_A / 8);                  /* 25 */
var SPX_TREE_BITS = SPX_H - SPX_HP;                               /* 63 */
var SPX_TREE_BYTES = Math.ceil(SPX_TREE_BITS / 8);                /* 8 */
var SPX_LEAF_BYTES = Math.ceil(SPX_HP / 8);                       /* 1 */
var SPX_DGST = SPX_FORS_MSG + SPX_TREE_BYTES + SPX_LEAF_BYTES;    /* 34 */

var A_WOTS = 0, A_WOTSPK = 1, A_HASHTREE = 2,
    A_FORSTREE = 3, A_FORSPK = 4, A_WOTSPRF = 5, A_FORSPRF = 6;

function adrNew() { return new Uint8Array(32); }
function adrCopy(a) { return new Uint8Array(a); }
function spxU32be(a, o, v) { a[o] = (v >>> 24) & 0xff; a[o + 1] = (v >>> 16) & 0xff; a[o + 2] = (v >>> 8) & 0xff; a[o + 3] = v & 0xff; }
function setLayer(a, v) { spxU32be(a, 0, v); }
function setTree(a, v) { v = BigInt(v); spxU32be(a, 4, 0); spxU32be(a, 8, Number((v >> 32n) & 0xffffffffn)); spxU32be(a, 12, Number(v & 0xffffffffn)); }
function setType(a, v) { spxU32be(a, 16, v); }        /* 只改 type，不清零 */
function setKeyPair(a, v) { spxU32be(a, 20, v); }
function setChain(a, v) { spxU32be(a, 24, v); }
function setHash(a, v) { spxU32be(a, 28, v); }
function setTreeHeight(a, v) { spxU32be(a, 24, v); }
function setTreeIndex(a, v) { spxU32be(a, 28, v); }
function copyKeypair(dst, src) { dst.set(src.subarray(0, 24), 0); }  /* layer+tree+keypair */

function spxCat(parts) {
  var n = 0, i;
  for (i = 0; i < parts.length; i++) n += parts[i].length;
  var o = new Uint8Array(n), p = 0;
  for (i = 0; i < parts.length; i++) { o.set(parts[i], p); p += parts[i].length; }
  return o;
}
/* robust tweakable hash：out = shake(pk_seed‖ADRS‖(in XOR bitmask), n) */
function spxThash(pkSeed, adrs, input, blocks) {
  var pre = spxCat([pkSeed, adrs]);
  var bm = shake256Digest(pre, blocks * SPX_N);
  var x = new Uint8Array(input.length);
  for (var i = 0; i < input.length; i++) x[i] = input[i] ^ bm[i];
  return shake256Digest(spxCat([pre, x]), SPX_N);
}
function spxF(pkSeed, adrs, m) { return spxThash(pkSeed, adrs, m, 1); }
function spxH(pkSeed, adrs, m1, m2) { return spxThash(pkSeed, adrs, spxCat([m1, m2]), 2); }
function spxT(pkSeed, adrs, m, l) { return spxThash(pkSeed, adrs, m, l); }
function spxPRF(pkSeed, skSeed, adrs) { return shake256Digest(spxCat([pkSeed, adrs, skSeed]), SPX_N); }
function spxPRFmsg(skPrf, optRand, m) { return shake256Digest(spxCat([skPrf, optRand, m]), SPX_N); }
function spxHmsg(R, pk, m) { return shake256Digest(spxCat([R, pk, m]), SPX_DGST); }
function bytesToUll(b, off, nb) { var v = 0n; for (var i = 0; i < nb; i++) v = (v << 8n) | BigInt(b[off + i]); return v; }

function wotsGenSk(pkSeed, skSeed, adrs) {
  var sk = [];
  for (var i = 0; i < SPX_LEN; i++) {
    var a = adrCopy(adrs); setChain(a, i); setHash(a, 0); setType(a, A_WOTSPRF);
    sk.push(spxPRF(pkSeed, skSeed, a));
  }
  return sk;
}
function wotsGenPk(pkSeed, skSeed, adrs) {
  var sk = wotsGenSk(pkSeed, skSeed, adrs), pk = new Uint8Array(SPX_LEN * SPX_N);
  for (var i = 0; i < SPX_LEN; i++) {
    var a = adrCopy(adrs); setType(a, A_WOTS); setChain(a, i);
    var t = sk[i];
    for (var j = 0; j < SPX_W - 1; j++) { setHash(a, j); t = spxF(pkSeed, a, t); }
    pk.set(t, i * SPX_N);
  }
  return pk;
}
function baseW(input, outLen) {
  var out = [], inIdx = 0, bits = 0, total = 0;
  for (var c = 0; c < outLen; c++) {
    if (bits === 0) { total = input[inIdx++]; bits = 8; }
    bits -= 4;
    out.push((total >> bits) & (SPX_W - 1));
  }
  return out;
}
function chainLengths(msg) {
  var b = baseW(msg, SPX_LEN1), csum = 0, i;
  for (i = 0; i < SPX_LEN1; i++) csum += SPX_W - 1 - b[i];
  csum = csum << ((8 - ((SPX_LEN2 * 4) % 8)) % 8);
  var cb = new Uint8Array([(csum >> 8) & 0xff, csum & 0xff]);
  return b.concat(baseW(cb, SPX_LEN2));
}
function wotsSign(msg, pkSeed, skSeed, adrs) {
  var sk = wotsGenSk(pkSeed, skSeed, adrs), m = chainLengths(msg);
  var sig = new Uint8Array(SPX_LEN * SPX_N);
  for (var i = 0; i < SPX_LEN; i++) {
    var a = adrCopy(adrs); setType(a, A_WOTS); setChain(a, i);
    var t = sk[i];
    for (var j = 0; j < m[i]; j++) { setHash(a, j); t = spxF(pkSeed, a, t); }
    sig.set(t, i * SPX_N);
  }
  return sig;
}
function wotsPkFromSig(sig, msg, pkSeed, adrs) {
  var m = chainLengths(msg), pk = new Uint8Array(SPX_LEN * SPX_N);
  for (var i = 0; i < SPX_LEN; i++) {
    var a = adrCopy(adrs); setType(a, A_WOTS); setChain(a, i);
    var t = sig.subarray(i * SPX_N, (i + 1) * SPX_N);
    for (var j = m[i]; j < SPX_W - 1; j++) { setHash(a, j); t = spxF(pkSeed, a, t); }
    pk.set(t, i * SPX_N);
  }
  return pk;
}
function xmssLeaf(pkSeed, adrs, wotsPk) {
  var a = adrCopy(adrs); setType(a, A_WOTSPK);
  return spxT(pkSeed, a, wotsPk, SPX_LEN);
}
function xmssTree(pkSeed, skSeed, adrs) {
  var lv = [], cur = [], i;
  for (i = 0; i < (1 << SPX_HP); i++) {
    var w = adrCopy(adrs); setKeyPair(w, i);
    cur.push(xmssLeaf(pkSeed, w, wotsGenPk(pkSeed, skSeed, w)));
  }
  lv.push(cur);
  for (var h = 1; h <= SPX_HP; h++) {
    var next = [];
    for (i = 0; i < (cur.length >> 1); i++) {
      var a = adrCopy(adrs); setType(a, A_HASHTREE); setTreeHeight(a, h); setTreeIndex(a, i);
      next.push(spxH(pkSeed, a, cur[2 * i], cur[2 * i + 1]));
    }
    lv.push(next); cur = next;
  }
  return lv;
}
function xmssSign(msg, pkSeed, skSeed, adrs, kp) {
  var w = adrCopy(adrs); setKeyPair(w, kp);
  var sig = wotsSign(msg, pkSeed, skSeed, w);
  var lv = xmssTree(pkSeed, skSeed, adrs), auth = [], nodeIdx = kp;
  for (var h = 0; h < SPX_HP; h++) { auth.push(lv[h][nodeIdx ^ 1]); nodeIdx >>= 1; }
  return { sig: sig, auth: auth, root: lv[SPX_HP][0] };
}
function xmssPkFromSig(sig, auth, msg, pkSeed, adrs, kp) {
  var w = adrCopy(adrs); setKeyPair(w, kp);
  var node = xmssLeaf(pkSeed, w, wotsPkFromSig(sig, msg, pkSeed, w)), nodeIdx = kp;
  for (var h = 0; h < SPX_HP; h++) {
    var a = adrCopy(adrs); setType(a, A_HASHTREE); setTreeHeight(a, h + 1); setTreeIndex(a, nodeIdx >> 1);
    node = (nodeIdx & 1) ? spxH(pkSeed, a, auth[h], node) : spxH(pkSeed, a, node, auth[h]);
    nodeIdx >>= 1;
  }
  return node;
}

function messageToIndices(m) {
  var idx = [], off = 0;
  for (var i = 0; i < SPX_K; i++) {
    var v = 0;
    for (var j = 0; j < SPX_A; j++) { v ^= ((m[off >> 3] >> (off & 7)) & 1) << j; off++; }
    idx.push(v);
  }
  return idx;
}
function forsGenSk(pkSeed, skSeed, adrs, treeIdx) {
  var a = adrCopy(adrs); setType(a, A_FORSPRF); setTreeHeight(a, 0); setTreeIndex(a, treeIdx);
  return spxPRF(pkSeed, skSeed, a);
}
function forsLeaf(pkSeed, skSeed, adrs, treeIdx) {
  var a = adrCopy(adrs); setType(a, A_FORSPRF); setTreeHeight(a, 0); setTreeIndex(a, treeIdx);
  var sk = spxPRF(pkSeed, skSeed, a);
  setType(a, A_FORSTREE);
  return spxF(pkSeed, a, sk);
}
function forsTree(pkSeed, skSeed, adrs, treeIdx) {
  var lv = [], cur = [], i;
  for (i = 0; i < SPX_T; i++) cur.push(forsLeaf(pkSeed, skSeed, adrs, treeIdx * SPX_T + i));
  lv.push(cur);
  for (var h = 1; h <= SPX_A; h++) {
    var next = [], off = treeIdx * (SPX_T >> h);
    for (i = 0; i < (cur.length >> 1); i++) {
      var a = adrCopy(adrs); setType(a, A_FORSTREE); setTreeHeight(a, h); setTreeIndex(a, off + i);
      next.push(spxH(pkSeed, a, cur[2 * i], cur[2 * i + 1]));
    }
    lv.push(next); cur = next;
  }
  return lv;
}
function forsSign(md, pkSeed, skSeed, adrs) {
  var idx = messageToIndices(md), sig = [], auth = [];
  for (var i = 0; i < SPX_K; i++) {
    var off = i * SPX_T;
    sig.push(forsGenSk(pkSeed, skSeed, adrs, idx[i] + off));
    var lv = forsTree(pkSeed, skSeed, adrs, i), a = [], nodeIdx = idx[i];
    for (var h = 0; h < SPX_A; h++) { a.push(lv[h][nodeIdx ^ 1]); nodeIdx >>= 1; }
    auth.push(a);
  }
  var roots = [];
  for (var q = 0; q < SPX_K; q++) { var lvq = forsTree(pkSeed, skSeed, adrs, q); roots.push(lvq[SPX_A][0]); }
  var pa = adrCopy(adrs); setType(pa, A_FORSPK);
  return { sig: sig, auth: auth, idx: idx, pk: spxT(pkSeed, pa, spxCat(roots), SPX_K) };
}
function forsPkFromSig(sig, auth, md, pkSeed, adrs) {
  var idx = messageToIndices(md), roots = [];
  for (var i = 0; i < SPX_K; i++) {
    var off = i * SPX_T;
    var a0 = adrCopy(adrs); setType(a0, A_FORSTREE); setTreeHeight(a0, 0); setTreeIndex(a0, idx[i] + off);
    var node = spxF(pkSeed, a0, sig[i]), nodeIdx = idx[i];
    for (var h = 0; h < SPX_A; h++) {
      var a = adrCopy(adrs); setType(a, A_FORSTREE); setTreeHeight(a, h + 1);
      setTreeIndex(a, i * (SPX_T >> (h + 1)) + (nodeIdx >> 1));
      node = (nodeIdx & 1) ? spxH(pkSeed, a, auth[i][h], node) : spxH(pkSeed, a, node, auth[i][h]);
      nodeIdx >>= 1;
    }
    roots.push(node);
  }
  var pa = adrCopy(adrs); setType(pa, A_FORSPK);
  return spxT(pkSeed, pa, spxCat(roots), SPX_K);
}

function spxGenKeypair(seed48) {
  var skSeed = seed48.subarray(0, 16), pkSeed = seed48.subarray(32, 48);
  var a = adrNew(); setLayer(a, SPX_D - 1); setTree(a, 0n);
  var root = xmssTree(pkSeed, skSeed, a)[SPX_HP][0];
  return { sk: spxCat([seed48, root]), pk: spxCat([pkSeed, root]) };
}
function spxIndices(md) {
  var tree = bytesToUll(md, SPX_FORS_MSG, SPX_TREE_BYTES) & ((1n << BigInt(SPX_TREE_BITS)) - 1n);
  var leaf = md[SPX_FORS_MSG + SPX_TREE_BYTES] & ((1 << SPX_HP) - 1);
  return { tree: tree, leaf: leaf };
}
function spxSign(msg, sk, optRand) {
  optRand = optRand || new Uint8Array(SPX_N);
  var skSeed = sk.subarray(0, 16), skPrf = sk.subarray(16, 32),
      pkSeed = sk.subarray(32, 48), pk = sk.subarray(32, 64);
  var R = spxPRFmsg(skPrf, optRand, msg);
  var md = spxHmsg(R, pk, msg);
  var idx = spxIndices(md);
  var fa = adrNew(); setLayer(fa, 0); setTree(fa, idx.tree); setKeyPair(fa, idx.leaf);
  var fs = forsSign(md, pkSeed, skSeed, fa);
  /* FORS 部分按【树】交错排列：sk[0] ‖ auth[0](a个) ‖ sk[1] ‖ auth[1] …
     每棵占 (1+a)*n = 112 字节。
     我第一版写成「33 个 sk 连续、再 33 组 auth 连续」，总量虽同为 3696，
     但顺序错，导致 PySPX 无法验签。 */
  var parts = [R];
  for (var i = 0; i < SPX_K; i++) { parts.push(fs.sig[i]); parts.push(spxCat(fs.auth[i])); }
  var m = fs.pk;
  for (var layer = 0; layer < SPX_D; layer++) {
    var a = adrNew(); setLayer(a, layer); setTree(a, idx.tree >> BigInt(SPX_HP * layer));
    var kp = (layer === 0) ? idx.leaf
           : Number((idx.tree >> BigInt(SPX_HP * (layer - 1))) & ((1n << BigInt(SPX_HP)) - 1n));
    var xs = xmssSign(m, pkSeed, skSeed, a, kp);
    parts.push(xs.sig);
    parts.push(spxCat(xs.auth));
    m = xs.root;
  }
  var tot = 0; for (var q = 0; q < parts.length; q++) tot += parts[q].length;
  if (typeof globalThis !== 'undefined' && globalThis.__SPXDBG) {
    console.log('[dbg] parts 数=' + parts.length + ' 总计=' + tot +
      ' 明细前6=' + parts.slice(0, 6).map(function (z) { return z.length; }).join(','));
  }
  return spxCat(parts);
}
function spxVerify(msg, sig, pk) {
  if (!sig || sig.length !== SPX_SIGBYTES || !pk || pk.length !== SPX_PKBYTES) return false;
  var pkSeed = pk.subarray(0, 16), pkRoot = pk.subarray(16, 32);
  var R = sig.subarray(0, SPX_N);
  var md = spxHmsg(R, pk, msg);
  var idx = spxIndices(md);
  var pos = SPX_N, fsig = [], fauth = [], i;
  for (i = 0; i < SPX_K; i++) {
    fsig.push(sig.subarray(pos, pos + SPX_N)); pos += SPX_N;
    var aa = [];
    for (var h = 0; h < SPX_A; h++) { aa.push(sig.subarray(pos, pos + SPX_N)); pos += SPX_N; }
    fauth.push(aa);
  }
  var fa = adrNew(); setLayer(fa, 0); setTree(fa, idx.tree); setKeyPair(fa, idx.leaf);
  var m = forsPkFromSig(fsig, fauth, md, pkSeed, fa);
  for (var layer = 0; layer < SPX_D; layer++) {
    var a = adrNew(); setLayer(a, layer); setTree(a, idx.tree >> BigInt(SPX_HP * layer));
    var kp = (layer === 0) ? idx.leaf
           : Number((idx.tree >> BigInt(SPX_HP * (layer - 1))) & ((1n << BigInt(SPX_HP)) - 1n));
    var xsig = sig.subarray(pos, pos + SPX_LEN * SPX_N); pos += SPX_LEN * SPX_N;
    var auth = [];
    for (var hh = 0; hh < SPX_HP; hh++) { auth.push(sig.subarray(pos, pos + SPX_N)); pos += SPX_N; }
    m = xmssPkFromSig(xsig, auth, m, pkSeed, a, kp);
  }
  for (i = 0; i < SPX_N; i++) if (m[i] !== pkRoot[i]) return false;
  return true;
}
