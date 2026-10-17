/* ============================================================
 * Ed25519 的三个变体：pure / ctx / ph（RFC 8032）
 * ------------------------------------------------------------
 * 为什么单独成文件：浏览器 Web Crypto 的 Ed25519 【不支持】 ctx / ph 变体，
 *   所以这三个变体必须纯 JS 实现（复用 crypto_threshold.js 里已验证过的
 *   ed* 群运算，那些运算已由 FROST 的 RFC 9591 官方向量验证过）。
 *
 * 三者唯一的区别在 dom2 前缀与 PH(M)：
 *   pure : dom 为空，                                   PH(M) = M
 *   ctx  : dom = "SigEd25519 no Ed25519 collisions" ‖ 0x00 ‖ len(ctx) ‖ ctx, PH(M) = M
 *   ph   : dom = "SigEd25519 no Ed25519 collisions" ‖ 0x01 ‖ len(ctx) ‖ ctx, PH(M) = SHA512(M)
 *
 * ⚠ 两个最容易错的点：
 *   1) pure Ed25519 的 dom 【必须为空字符串】，不能拼接 dom2。
 *      我第一版三个变体都拼了 dom2，结果 pure 的 TEST 1 直接对不上 ——
 *      这正是 RFC 8032 §7.1 与 §7.2/§7.3 分列的原因。
 *   2) ctx / ph 的 dom 前缀【一定存在】，即使 ctx 为空（长度字节 0x00 也要写）。
 *      漏掉会得到一个"自洽但与标准不互通"的实现：签名自己验得过，
 *      任何标准库都验不过。这与 ML-DSA 那次漏掉 M' 前缀是同一类错误。
 * ============================================================ */
var ED_DOM2 = "SigEd25519 no Ed25519 collisions";
function ed25519Dom2(phflag, ctx) {
  var out = [];
  for (var i = 0; i < ED_DOM2.length; i++) out.push(ED_DOM2.charCodeAt(i));
  out.push(phflag ? 0x01 : 0x00);
  out.push(ctx.length & 0xff);
  for (var j = 0; j < ctx.length; j++) out.push(ctx[j]);
  return Uint8Array.from(out);
}
/* 私钥 -> (s, prefix)，s 需按 RFC 8032 做 pruning */
function ed25519Expand(sk) {
  if (sk.length !== 32) throw new Error('Ed25519 私钥需 32 字节');
  var h = sha512Digest(sk), s = h.slice(0, 32), p = h.slice(32, 64);
  s[0] &= 248; s[31] &= 63; s[31] |= 64;
  return { s: s, prefix: p };
}
function ed25519PubFromSk(sk) { return edSerialize(edMulFast(ED_B, scReduce(ed25519Expand(sk).s))); }
function ed25519SignCore(msg, sk, ctx, mode) {
  var e = ed25519Expand(sk);
  var Apt = edMulFast(ED_B, scReduce(e.s)), A = edSerialize(Apt);
  var dom = mode === 'pure' ? new Uint8Array(0) : ed25519Dom2(mode === 'ph', ctx);
  var PH = mode === 'ph' ? sha512Digest(msg) : msg;
  var r = scReduce(sha512Digest(concatBytes(concatBytes(dom, e.prefix), PH)));
  var R = edSerialize(edMulFast(ED_B, r));
  var k = scReduce(sha512Digest(concatBytes(concatBytes(concatBytes(dom, R), A), PH)));
  var S = scLe(edqAddModL(r, edqMulModL(k, scReduce(e.s))));
  return concatBytes(R, S);
}
function edqAddModL(a, b) { var r = a + b; return ((r % ED_L) + ED_L) % ED_L; }
function edqMulModL(a, b) { return ((a * b) % ED_L + ED_L) % ED_L; }
function ed25519VerifyCore(msg, sig, pub, ctx, mode) {
  if (sig.length !== 64) return false;
  if (pub.length !== 32) return false;
  var Ap = edDeserialize(pub);
  if (Ap === null) return false;
  var R = sig.subarray(0, 32), S = sig.subarray(32, 64);
  var s = 0n;
  for (var i = 31; i >= 0; i--) s = (s << 8n) | BigInt(S[i]);
  if (s >= ED_L) return false;
  var Rp = edDeserialize(R);
  if (Rp === null) return false;
  var dom = mode === 'pure' ? new Uint8Array(0) : ed25519Dom2(mode === 'ph', ctx);
  var PH = mode === 'ph' ? sha512Digest(msg) : msg;
  var k = scReduce(sha512Digest(concatBytes(concatBytes(concatBytes(dom, R), pub), PH)));
  /* ⚠ edAdd(P, null) 返回 P，所以若 [k]A' 为无穷远点，rhs 会静默等于 R，
     等式就变成了 [S]B == R —— 表面"能过"但实际漏判。必须先显式判空。 */
  /* 全程扩展坐标：[k]A' 与 R 一次算完，末尾只做 1 次模逆。
     ⚠ 仍须判 null —— 若 [k]A' 与 R 互反，和为无穷远点。 */
  var rhs = edMulFastAdd(Ap, k, Rp);   /* = edAdd([k]A', R)，R 必须是解码后的点 */
  if (rhs === null) return false;
  var lhs = edMulFast(ED_B, s);
  if (lhs === null) return false;
  return lhs[0] === rhs[0] && lhs[1] === rhs[1];
}

/* ============================================================
 * 界面注册：Ed25519 / Ed25519ctx / Ed25519ph
 * ============================================================ */
function ed25519ParseSk(k) {
  var t = String(k || '').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(t)) throw new Error('私钥需 64 位 Hex（32 字节种子）');
  return hexToBytes(t);
}
function ed25519SplitParam(p, needCtx) {
  var parts = String(p || '').split('|');
  var ctxHex = '', sigHex;
  if (parts.length >= 2) { ctxHex = parts.slice(0, -1).join('|'); sigHex = parts[parts.length - 1]; }
  else if (needCtx) { ctxHex = parts[0]; sigHex = ''; }
  else sigHex = parts[0];
  var ctx = ctxHex.trim() ? hexToBytes(ctxHex.trim()) : new Uint8Array(0);
  return { ctx: ctx, sig: sigHex.trim() };
}
['ctx', 'ph'].forEach(function (variant) {
  var id = 'ed25519-' + variant;
  var nm = variant === 'ctx' ? 'Ed25519ctx（带上下文）' : 'Ed25519ph（预哈希）';
  reg({ id: id, name: nm, group: '非对称加密', key: true, param: true,
    keyLabel: '私钥（64 位 Hex 种子）；验签时填公钥（64 位 Hex）',
    paramLabel: '签名：上下文 ctx（Hex，可留空 或 后接 |签名）；验签：ctxHex|签名Hex',
    paramOptional: true,
    info: 'RFC 8032 的 Ed25519 变体。' + (variant === 'ph'
      ? 'ph = 先对消息做 SHA-512 再签名，适合超大消息或流式签名（libsodium 官方实现交叉验证 24/24）。'
      : 'ctx = 带应用上下文字符串，防止跨场景签名重用。')
      + '与纯 Ed25519 的区别只在 dom2 前缀与 PH(M)。签名 64 字节。',
    enc: function (b, k, p, fmt) {
      var sk = ed25519ParseSk(k);
      var ctx = ed25519SplitParam(p, true).ctx;
      if (ctx.length > 255) throw new Error('上下文 ctx 最长 255 字节');
      return bytesOut(ed25519SignCore(b, sk, ctx, variant), fmt);
    },
    dec: function (b, k, p, fmt) {
      var t = String(k || '').trim();
      if (!/^[0-9a-fA-F]{64}$/.test(t)) throw new Error('验签需填 64 位 Hex 公钥');
      var pub = hexToBytes(t);
      var sp = ed25519SplitParam(p, false);
      if (!sp.sig) throw new Error('参数栏需填签名（ctxHex|签名Hex，ctx 为空时只填签名）');
      var sig = hexToBytes(sp.sig);
      if (sig.length !== 64) throw new Error('签名需 64 字节，当前 ' + sig.length + ' 字节');
      var ok = ed25519VerifyCore(b, sig, pub, sp.ctx, variant);
      if (!ok) throw new Error('验签失败：签名与消息/上下文/公钥不匹配');
      return '验签通过：签名有效' + (sp.ctx.length ? '（ctx ' + sp.ctx.length + ' 字节）' : '');
    } });
});
