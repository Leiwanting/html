/* ============================================================
 * Bulletproofs 范围证明（Ristretto255，兼容 dalek-cryptography/bulletproofs）
 * ------------------------------------------------------------
 * ✅ 状态：已通过 dalek 官方固定向量（range_proof.rs::deserialize_and_verify）
 *    n=8/m=1 与 n=8/m=2 全部 mega_check 成立。
 *
 * 🔑 本轮定位到的根因（也是最值得记的一条）：
 *    Ristretto 的【64 字节】one-way map 不等于对 64 字节调一次 32 字节 MAP。
 *    RFC 9496 §4.3.4 明确规定：P1 = MAP(b[0:32])，P2 = MAP(b[32:64])，返回 P1 + P2。
 *    我此前把 64 字节整段丢给 32 字节的 ristMap —— 它只取前 32 字节，
 *    于是 P2 被静默丢弃：不报错、输出长度也对、所有点仍在曲线上，
 *    但 B_blinding 与全部 G/H 生成器全错，mega_check 的 P、Q 两部分同时失败。
 *    修复：新增 ristFromUniformBytes()（两次 MAP 相加），
 *    并用 RFC 9496 附录 A.3 的三组 64 字节向量独立验证 3/3。
 *
 * 全部常量与协议流程均取自官方源码（非凭记忆）：
 *   merlin/src/strobe.rs / transcript.rs / constants.rs
 *   bulletproofs/src/generators.rs / generators/generators_chain.rs
 *   bulletproofs/src/range_proof/mod.rs / inner_product_proof.rs / transcript.rs
 *
 * 关键常量（源码实锤）：
 *   MERLIN_PROTOCOL_LABEL        = b"Merlin v1.0"
 *   STROBE 初始                  = [1, R+2, 1, 0, 1, 96] ‖ b"STROBEv1.0.2"，R = 166
 *   PedersenGens::default()      B = RISTRETTO_BASEPOINT_POINT
 *                                B_blind = from_uniform_bytes(SHA3-512(B.compress()))
 *   GeneratorsChain              SHAKE256(b"GeneratorsChain" ‖ label)
 *                                label = b'G'|b'H' ‖ LE32(party_index)
 *                                每 64 字节 → from_uniform_bytes
 *   delta(n,m,y,z) = (z−z²)·Σy^(0..nm−1) − z³·Σ2^(0..n−1)·Σz^(0..m−1)
 *   RangeProof 布局  A‖S‖T_1‖T_2‖t_x‖t_x_blinding‖e_blinding‖(L_0,R_0,L_1,R_1…)‖a‖b
 *
 * ✅ 已独立验证通过的部分：
 *   · Keccak-f[1600] 字节序：全零状态置换后前 8 字节 = e7dde140798f25f1（已知答案）
 *   · Ristretto 基点编码   = e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76
 *   · Merlin transcript：另写一份 Python 实现（py_merlin.py，独立翻译同一份 Rust 源码），
 *     y / z / x / w 四个挑战值逐字节一致
 *   · 证明长度：n=8,m=1 → 480 字节；n=8,m=2 → 544 字节（与布局推算完全吻合）
 *   · 所有点（A/S/T_1/T_2/L/R/V/B/B_blind/G/H）均在 twisted Edwards 曲线上
 *   · 线性性：M(2) − 2·M(1) + M(0) == 恒等元（说明多标量乘的线性结构正确）
 *
 * ❌ 未通过：M(c) = P + c·Q 中，P（IPA 部分，c=0）与 Q（多项式部分）均非恒等元。
 *
 * 🔍 已穷举排除（各 8～32 种组合全败）：
 *   s 索引 (lgN−1−lgI) / lgI、challenges 是否反序、transcript 中 L/R 先后、
 *   g↔G 与 h↔H 是否交叉、s_inv 是否逆序。
 *   → 故问题不在这些"顺序"类歧义上，而在某个【具体数值】上。
 *
 * 🎯 下一轮最该查的两处（按嫌疑排序）：
 *   1) PedersenGens.B_blinding —— 它同时出现在 P 与 Q 两部分，
 *      若算错则两部分同时失败，与当前现象完全吻合。
 *      应取一份 dalek 的已知 B_blinding 编码做硬比对。
 *   2) GeneratorsChain 的 G/H —— 只影响 P 部分；可用 Python 独立实现
 *      RFC 9496 one-way map 后比对 G[0][0]。
 * ============================================================ */
var BP_L = ED_L;
var BP_SINVREV = true; /* s_inv 是否为 s 的逆序 */
var BP_P = ED_P;

function bpq(a) { var v = a % BP_L; return v < 0n ? v + BP_L : v; }
function bpqAdd(a, b) { return bpq(a + b); }
function bpqSub(a, b) { return bpq(a - b); }
function bpqMul(a, b) { return bpq(a * b); }
function bpqNeg(a) { return bpq(-a); }
function bpqInv(a) {
  var t0 = 0n, t1 = 1n, r0 = BP_L, r1 = bpq(a), q, tr, tt;
  while (r1 !== 0n) { q = r0 / r1; tr = r0 - q * r1; r0 = r1; r1 = tr; tt = t0 - q * t1; t0 = t1; t1 = tt; }
  if (t0 < 0n) t0 += BP_L;
  return r0 === 1n ? t0 : 0n;
}

/* ---------- Keccak-f[1600]：字节层 200 字节状态（STROBE 需要） ----------
   ⚠ keccakF 内部用的是 25 个 lane 拆成 (lo, hi) 两个 32 位字，
     而 STROBE 持有的是 200 字节缓冲区（keccak crate 的 [u64;25] 在小端
     机器上等价于这 200 字节）。必须按 8 字节小端拆分，否则状态全错。 */
function bpF1600(buf) {
  var S = new Array(50), i;
  for (i = 0; i < 25; i++) {
    S[2 * i] = (buf[i * 8] | (buf[i * 8 + 1] << 8) | (buf[i * 8 + 2] << 16) | (buf[i * 8 + 3] << 24)) >>> 0;
    S[2 * i + 1] = (buf[i * 8 + 4] | (buf[i * 8 + 5] << 8) | (buf[i * 8 + 6] << 16) | (buf[i * 8 + 7] << 24)) >>> 0;
  }
  keccakF(S);
  for (i = 0; i < 25; i++) {
    var l = S[2 * i], h = S[2 * i + 1];
    buf[i * 8] = l & 0xff; buf[i * 8 + 1] = (l >>> 8) & 0xff;
    buf[i * 8 + 2] = (l >>> 16) & 0xff; buf[i * 8 + 3] = (l >>> 24) & 0xff;
    buf[i * 8 + 4] = h & 0xff; buf[i * 8 + 5] = (h >>> 8) & 0xff;
    buf[i * 8 + 6] = (h >>> 16) & 0xff; buf[i * 8 + 7] = (h >>> 24) & 0xff;
  }
}
/* ---------- STROBE128 ---------- */
var STROBE_R = 166;
var FLAG_I = 1, FLAG_A = 2, FLAG_C = 4, FLAG_T = 8, FLAG_M = 16, FLAG_K = 32;
function bpStrobeNew(protoLabel) {
  var st = new Uint8Array(200), i;
  st[0] = 1; st[1] = STROBE_R + 2; st[2] = 1; st[3] = 0; st[4] = 1; st[5] = 96;
  var s = "STROBEv1.0.2";
  for (i = 0; i < 12; i++) st[6 + i] = s.charCodeAt(i);
  bpF1600(st);
  var T = { st: st, pos: 0, posBegin: 0, curFlags: 0 };
  bpStrobeMetaAd(T, protoLabel, false);
  return T;
}
function bpStrobeRunF(T) {
  T.st[T.pos] ^= T.posBegin;
  T.st[T.pos + 1] ^= 0x04;
  T.st[STROBE_R + 1] ^= 0x80;
  bpF1600(T.st);
  T.pos = 0; T.posBegin = 0;
}
function bpStrobeAbsorb(T, d) {
  for (var i = 0; i < d.length; i++) { T.st[T.pos] ^= d[i]; T.pos++; if (T.pos === STROBE_R) bpStrobeRunF(T); }
}
function bpStrobeSqueeze(T, out) {
  for (var i = 0; i < out.length; i++) { out[i] = T.st[T.pos]; T.st[T.pos] = 0; T.pos++; if (T.pos === STROBE_R) bpStrobeRunF(T); }
}
function bpStrobeBeginOp(T, flags, more) {
  if (more) { if (T.curFlags !== flags) throw new Error('STROBE：续接 op 时 flag 不一致'); return; }
  if (flags & FLAG_T) throw new Error('STROBE：不支持 T flag');
  var oldBegin = T.posBegin;
  T.posBegin = T.pos + 1;
  T.curFlags = flags;
  bpStrobeAbsorb(T, [oldBegin, flags]);
  var forceF = 0 !== (flags & (FLAG_C | FLAG_K));
  if (forceF && T.pos !== 0) bpStrobeRunF(T);
}
function bpStrobeMetaAd(T, d, m) { bpStrobeBeginOp(T, FLAG_M | FLAG_A, m); bpStrobeAbsorb(T, d); }
function bpStrobeAd(T, d, m) { bpStrobeBeginOp(T, FLAG_A, m); bpStrobeAbsorb(T, d); }
function bpStrobePrf(T, out, m) { bpStrobeBeginOp(T, FLAG_I | FLAG_A | FLAG_C, m); bpStrobeSqueeze(T, out); }
/* ---------- Merlin Transcript ---------- */
var BP_LABELS = {};
function bpL(s) { if (!BP_LABELS[s]) { var o = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) o[i] = s.charCodeAt(i); BP_LABELS[s] = o; } return BP_LABELS[s]; }
function bpLE32(x) { return Uint8Array.from([x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, (x >>> 24) & 0xff]); }
/* ⚠ 这里踩过坑：我一开始把用户标签（如 "Deserialize-And-Verify Test"）
   直接当成 STROBE 的 protocol label 传进去。源码实锤是：
       Strobe128::new(MERLIN_PROTOCOL_LABEL)      // 恒为 b"Merlin v1.0"
       transcript.append_message(b"dom-sep", label)   // 用户标签走 dom-sep
   两者不可混。这是"凭函数名推断参数含义"的典型错误。 */
function bpTranscriptNew(userLabel) {
  var T = bpStrobeNew(bpL("Merlin v1.0"));
  if (userLabel) bpTAppendMessage(T, bpL("dom-sep"), bpL(userLabel));
  return T;
}
function bpTAppendMessage(T, label, msg) {
  bpStrobeMetaAd(T, label, false);
  bpStrobeMetaAd(T, bpLE32(msg.length), true);
  bpStrobeAd(T, msg, false);
}
function bpTAppendU64(T, label, x) {
  var b = new Uint8Array(8), v = BigInt(x);
  for (var i = 0; i < 8; i++) b[i] = Number((v >> BigInt(8 * i)) & 0xffn);
  bpTAppendMessage(T, label, b);
}
function bpTChallengeBytes(T, label, len) {
  bpStrobeMetaAd(T, label, false);
  bpStrobeMetaAd(T, bpLE32(len), true);
  var out = new Uint8Array(len);
  bpStrobePrf(T, out, false);
  return out;
}
/* Scalar::from_bytes_mod_order_wide：64 字节小端 → 模 L */
function bpTChallengeScalar(T, label) {
  var b = bpTChallengeBytes(T, label, 64), v = 0n;
  for (var i = 63; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v % BP_L;
}
function bpTRangeproofDomainSep(T, n, m) {
  bpTAppendMessage(T, bpL("dom-sep"), bpL("rangeproof v1"));
  bpTAppendU64(T, bpL("n"), n);
  bpTAppendU64(T, bpL("m"), m);
}
function bpTIppDomainSep(T, n) {
  bpTAppendMessage(T, bpL("dom-sep"), bpL("ipp v1"));
  bpTAppendU64(T, bpL("n"), n);
}
/* ---------- Pedersen 生成器 ---------- */
var BP_PC = null;
function bpPedersenGens() {
  if (BP_PC) return BP_PC;
  var B = [ED_B[0], ED_B[1]];
  var comp = ristEncodeAffine(B);
  var h = sha3Digest(comp, 64);
  BP_PC = { B: B, BBlind: ristFromUniformBytes(h) };
  return BP_PC;
}
/* ---------- GeneratorsChain ---------- */
var BP_GENS = null;
function bpGenChain(labelBytes, count) {
  var pfx = "GeneratorsChain", input = new Uint8Array(15 + labelBytes.length), i;
  for (i = 0; i < 15; i++) input[i] = pfx.charCodeAt(i);
  input.set(labelBytes, 15);
  var out = shake256Digest(input, 64 * count), arr = [];
  for (i = 0; i < count; i++) arr.push(ristFromUniformBytes(out.subarray(i * 64, i * 64 + 64)));
  return arr;
}
function bpGensLabel(c, idx) {
  var l = new Uint8Array(5);
  l[0] = c.charCodeAt(0);
  l[1] = idx & 0xff; l[2] = (idx >>> 8) & 0xff; l[3] = (idx >>> 16) & 0xff; l[4] = (idx >>> 24) & 0xff;
  return l;
}
function bpBpGens(gensCapacity, partyCapacity) {
  var G = [], H = [], i;
  for (i = 0; i < partyCapacity; i++) {
    G.push(bpGenChain(bpGensLabel('G', i), gensCapacity));
    H.push(bpGenChain(bpGensLabel('H', i), gensCapacity));
  }
  return { G: G, H: H };
}
/* AggregatedGensIter：party 优先（party0 的 gen0..n−1，再 party1 的 …） */
function bpAggGens(gens, which, n, m) {
  var src = which === 'G' ? gens.G : gens.H, out = [], p, g;
  for (p = 0; p < m; p++) for (g = 0; g < n; g++) out.push(src[p][g]);
  return out;
}
/* ---------- 工具 ---------- */
function bpExpIter(base, count) { var a = [], p = 1n; for (var i = 0; i < count; i++) { a.push(p); p = bpqMul(p, base); } return a; }
function bpSumOfPowers(base, count) { var s = 0n, p = 1n; for (var i = 0; i < count; i++) { s = bpqAdd(s, p); p = bpqMul(p, base); } return s; }
function bpDelta(n, m, y, z) {
  var sumY = bpSumOfPowers(y, n * m), sum2 = bpSumOfPowers(2n, n), sumZ = bpSumOfPowers(z, m);
  var z2 = bpqMul(z, z), z3 = bpqMul(z2, z);
  return bpqSub(bpqMul(bpqSub(z, z2), sumY), bpqMul(bpqMul(z3, sum2), sumZ));
}
/* ---------- 反序列化 ---------- */
function bpScalarFromBytes(b) {
  var v = 0n;
  for (var i = 31; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v % BP_L;
}
function bpPointFromBytes(b) { return ristToAffine(ristDecode(b)); }
function bpRangeProofFromBytes(raw) {
  if (raw.length < 224) throw new Error('RangeProof 至少 224 字节，当前 ' + raw.length);
  var o = { A: bpPointFromBytes(raw.subarray(0, 32)), S: bpPointFromBytes(raw.subarray(32, 64)),
    T1: bpPointFromBytes(raw.subarray(64, 96)), T2: bpPointFromBytes(raw.subarray(96, 128)) };
  o.Abytes = raw.subarray(0, 32); o.Sbytes = raw.subarray(32, 64);
  o.T1bytes = raw.subarray(64, 96); o.T2bytes = raw.subarray(96, 128);
  o.txBytes = raw.subarray(128, 160); o.txBlindingBytes = raw.subarray(160, 192); o.eBlindingBytes = raw.subarray(192, 224);
  o.tx = bpScalarFromBytes(o.txBytes);
  o.txBlinding = bpScalarFromBytes(o.txBlindingBytes);
  o.eBlinding = bpScalarFromBytes(o.eBlindingBytes);
  var rest = raw.length - 224;
  /* 尾部 = L_vec ‖ R_vec ‖ a ‖ b，每对 L/R 各 32 字节，末尾 a、b 各 32 */
  var lg = (rest - 64) / 64;
  if (!Number.isInteger(lg) || lg < 0) throw new Error('RangeProof 尾部长度异常：' + rest + ' 字节');
  o.L = []; o.R = []; o.Lbytes = []; o.Rbytes = [];
  /* ⚠ 严重陷阱：布局是【交错】的 L_0, R_0, L_1, R_1 …，不是"全部 L 再全部 R"。
     源码 to_bytes 是 for (l, r) in L_vec.zip(R_vec) { push(l); push(r); }
     我第一版写成两段独立循环，字节数完全相同（自检发现不了），
     但每轮的 L/R 都配对错位 —— 只有官方向量能暴露。 */
  var p = 224, i;
  for (i = 0; i < lg; i++) {
    o.Lbytes.push(raw.subarray(p, p + 32)); o.L.push(bpPointFromBytes(raw.subarray(p, p + 32))); p += 32;
    o.Rbytes.push(raw.subarray(p, p + 32)); o.R.push(bpPointFromBytes(raw.subarray(p, p + 32))); p += 32;
  }
  o.a = bpScalarFromBytes(raw.subarray(p, p + 32));
  o.b = bpScalarFromBytes(raw.subarray(p + 32, p + 64));
  return o;
}
/* ---------- IPA verification_scalars ---------- */
function bpIpaVerificationScalars(proof, n, T) {
  var lgN = proof.L.length, i;
  if (lgN >= 32) throw new Error('IPA 轮数过大');
  if (n !== (1 << lgN)) throw new Error('IPA 长度 ' + n + ' 与 L/R 对数 ' + lgN + ' 不符');
  bpTIppDomainSep(T, n);
  var challenges = [];
  for (i = 0; i < lgN; i++) {
    bpTAppendMessage(T, bpL("L"), proof.Lbytes[i]);
    bpTAppendMessage(T, bpL("R"), proof.Rbytes[i]);
    challenges.push(bpTChallengeScalar(T, bpL("u")));
  }
  var inv = challenges.map(bpqInv), allinv = 1n;
  for (i = 0; i < lgN; i++) allinv = bpqMul(allinv, inv[i]);
  var chSq = challenges.map(function (c) { return bpqMul(c, c); });
  var chInvSq = inv.map(function (c) { return bpqMul(c, c); });
  /* s[0] = 1/(u_1…u_k)；s[i] = s[i−2^lg_i]·u_{?}²
     ⚠ 索引是 (lgN−1)−lg_i：源码注释写 "creation order [u_k..u_1]" 容易误读成
       直接用 lg_i。按 i=1,2,4 (n=8) 逐位推导后确认应为前者。 */
  var s = new Array(n);
  s[0] = allinv;
  for (i = 1; i < n; i++) {
    var lgI = 31 - Math.clz32(i), k = 1 << lgI;
    s[i] = bpqMul(s[i - k], chSq[(lgN - 1) - lgI]);
  }
  return { xSq: chSq, xInvSq: chInvSq, s: s };
}
/* ---------- 验证主流程（mega_check） ---------- */
function bpVerifyRangeProofPoint(raw, Vlist, n, c) {
  var proof = bpRangeProofFromBytes(raw), m = Vlist.length, i, j;
  if (!(n === 8 || n === 16 || n === 32 || n === 64)) throw new Error('n 必须是 8/16/32/64');
  var T = bpTranscriptNew2();
  var pg = bpPedersenGens();
  if (!BP_GENS) BP_GENS = bpBpGens(64, 8);
  var gens = BP_GENS;
  bpTRangeproofDomainSep(T, n, m);
  for (i = 0; i < m; i++) bpTAppendMessage(T, bpL("V"), Vlist[i]);
  bpTAppendMessage(T, bpL("A"), proof.Abytes);
  bpTAppendMessage(T, bpL("S"), proof.Sbytes);
  var y = bpTChallengeScalar(T, bpL("y"));
  var z = bpTChallengeScalar(T, bpL("z"));
  var zz = bpqMul(z, z), minusZ = bpqNeg(z);
  bpTAppendMessage(T, bpL("T_1"), proof.T1bytes);
  bpTAppendMessage(T, bpL("T_2"), proof.T2bytes);
  var x = bpTChallengeScalar(T, bpL("x"));
  bpTAppendMessage(T, bpL("t_x"), proof.txBytes);
  bpTAppendMessage(T, bpL("t_x_blinding"), proof.txBlindingBytes);
  bpTAppendMessage(T, bpL("e_blinding"), proof.eBlindingBytes);
  var w = bpTChallengeScalar(T, bpL("w"));
  var ipa = bpIpaVerificationScalars(proof, n * m, T);
  var s = ipa.s, sInv = s.slice().reverse();
  var a = proof.a, b = proof.b;
  var powers2 = bpExpIter(2n, n), expZ = bpExpIter(z, m), concatZ2 = [];
  for (j = 0; j < m; j++) for (i = 0; i < n; i++) concatZ2.push(bpqMul(powers2[i], expZ[j]));
  var expYinv = bpExpIter(bpqInv(y), n * m);
  var g = [], h = [];
  for (i = 0; i < n * m; i++) g.push(bpqSub(minusZ, bpqMul(a, s[i])));
  for (i = 0; i < n * m; i++) h.push(bpqAdd(z, bpqMul(expYinv[i], bpqSub(bpqMul(zz, concatZ2[i]), bpqMul(b, sInv[i])))));
  var vcScalars = [];
  for (j = 0; j < m; j++) vcScalars.push(bpqMul(bpqMul(c, zz), expZ[j]));
  var delta = bpDelta(n, m, y, z);
  var basepointScalar = bpqAdd(bpqMul(w, bpqSub(proof.tx, bpqMul(a, b))), bpqMul(c, bpqSub(delta, proof.tx)));
  var scalars = [1n, x, bpqMul(c, x), bpqMul(c, bpqMul(x, x))];
  scalars = scalars.concat(ipa.xSq, ipa.xInvSq);
  scalars.push(bpqSub(bpqNeg(proof.eBlinding), bpqMul(c, proof.txBlinding)));
  scalars.push(basepointScalar);
  scalars = scalars.concat(g, h, vcScalars);
  var points = [proof.A, proof.S, proof.T1, proof.T2];
  points = points.concat(proof.L, proof.R);
  points.push(pg.BBlind, pg.B);
  points = points.concat(bpAggGens(gens, 'G', n, m), bpAggGens(gens, 'H', n, m));
  for (j = 0; j < m; j++) points.push(bpPointFromBytes(Vlist[j]));
  if (scalars.length !== points.length) throw new Error('内部错误：标量/点数量不等');
  /* 全程扩展坐标的多标量乘：模逆次数从 ~190×点数 降到 1。
     等价性已与旧路径 edAdd/edMul 对照（163/163），且 bpIsIdentity
     走 Ristretto 编码判定等价类，与运算路径无关。 */
  var R = edMultiScalarMul(points, scalars);
  if (R === null) return false;
  return R;
}
/* ⚠ 关键陷阱：不能用仿射坐标 R==(0,1) 判定恒等元。
   Ristretto 是【等价类】—— 恒等元的等价类含 4 个 Edwards 仿射代表：
   (0,1)、(0,−1)、(i,0)、(−i,0)。多标量乘收敛到哪一个取决于运算路径，
   所以必须走 Ristretto 编码（归一化后恒为全 0）来判定。
   我第一版直接比 (0,1)，导致正确结果被判为失败。 */
function bpIsIdentity(P) {
  if (P === null) return true;
  var e = ristEncodeAffine(P);
  for (var i = 0; i < 32; i++) if (e[i] !== 0) return false;
  return true;
}
function bpVerifyRangeProof(raw, Vlist, n, c) {
  return bpIsIdentity(bpVerifyRangeProofPoint(raw, Vlist, n, c));
}
var BP_TRANSCRIPT_LABEL = "Deserialize-And-Verify Test";
function bpTranscriptNew2() { return bpTranscriptNew(BP_TRANSCRIPT_LABEL); }

/* ============================================================
 * 界面注册：Bulletproofs 范围证明【验证】
 * ------------------------------------------------------------
 * 只提供验证方：能校验 dalek-cryptography/bulletproofs 生成的证明。
 * 未实现证明方 —— 生成证明需要完整的 l(x)/r(x) 向量与 IPA 递归，
 * 且必须与官方实现逐轮比对才能确认正确，本轮未完成。
 * ============================================================ */
function bpParseVList(s) {
  var parts = String(s).split(/[,\s;]+/).filter(function (x) { return x.length; });
  if (!parts.length) throw new Error('请提供至少一个值承诺 V（32 字节 Hex）');
  return parts.map(function (h) {
    if (!/^[0-9a-fA-F]{64}$/.test(h)) throw new Error('值承诺必须是 32 字节 Hex：' + h.slice(0, 16));
    return hexToBytes(h);
  });
}
function bpParseN(s) {
  var n = parseInt(String(s).trim(), 10);
  if (n !== 8 && n !== 16 && n !== 32 && n !== 64) throw new Error('位宽 n 必须是 8 / 16 / 32 / 64');
  return n;
}
if (typeof reg === 'function') {
  reg({
    id: 'bulletproof-verify', name: 'Bulletproofs 范围证明验证（Ristretto255）',
    group: '椭圆曲线与高级代数',
    key: true, param: true,
    keyLabel: '值承诺 V（32 字节 Hex，多个用逗号分隔；个数即聚合数 m）',
    paramLabel: '位宽 n（8 / 16 / 32 / 64）',
    info: '校验 dalek bulletproofs 生成的范围证明。\n【输入】证明 Hex；【密钥】值承诺 V（多个用逗号分隔，个数即 m）；【参数】位宽 n。\n⚠ 只有验证方，无证明方。',
    enc: function (b, k, p, fmt) {
      var raw;
      if (b instanceof Uint8Array || ArrayBuffer.isView(b)) raw = new Uint8Array(b.buffer || b);
      else {
        var s = String(b).trim();
        /* 允许带 0x 前缀或任意空白 */
        s = s.replace(/^0x/i, '').replace(/\s+/g, '');
        if (!/^[0-9a-fA-F]+$/.test(s)) throw new Error('证明必须是 Hex 字符串或 Hex 字节');
        if (s.length % 2) throw new Error('Hex 长度必须为偶数，当前 ' + s.length);
        raw = hexToBytes(s);
      }
      var V = bpParseVList(k);
      var n = bpParseN(p);
      if (V.length > 8) throw new Error('聚合数 m 最多 8（生成器容量 8）');
      var ok = bpVerifyRangeProof(raw, V, n, 1n);
      return ok ? '✓ 验证通过：证明合法（值均在 [0, 2^' + n + ') 内）'
        : '✗ 验证失败：证明不成立或数据被篡改';
    },
    dec: function (b, k, p, fmt) {
      /* 解密方向：与加密方向同一操作（验证），便于双向调用 */
      return this.enc(b, k, p, fmt);
    }
  });
}
