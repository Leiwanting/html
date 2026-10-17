/* ============================================================
 * FF3 格式保留加密（NIST SP 800-38G）
 * 加密后保持原有的长度与字符集（如卡号仍是卡号）。
 * ⚠ FF3 已被 NIST 在 2025 年从 SP 800-38G 中移除（tweak 调度攻击），
 *   已挂 🔴 严重提示：仅建议用于解密遗留数据，新系统请用 FF1。
 * 关键参数（全部由官方原文核对，非凭记忆）：u = ceil(n/2)、P 用【异或】拼接、
 * B 编码固定 12 字节、密钥需三重反转 CIPH_REVB(K)。
 * ============================================================ */
/* ========== FF3（NIST SP 800-38G）—— 官方样本 + 逐轮中间值双重验证 ==========
   规范要点（每处写错都会全盘皆错，均已用 NIST 官方逐步追踪值核对）：
     u = ceil(n/2)，v = n-u       —— 不是 floor
     P = (W ⊕ [i]^4) ‖ [NUM_radix(REV(B))]^12   —— W 与轮号【异或】；B 编码成【12】字节
     S = REVB(CIPH_REVB(K)(REVB(P)))  —— 密钥 / 输入 / 输出【三重字节反转】
     c = (NUM_radix(REV(A)) + y) mod radix^m
     C = REV(STR_radix^m(c))，然后 A=B, B=C
   官方 Round#0：P=[250,51,10,115,0,0,0,0,0,0,0,0,0,1,129,205]，c=237106499
   官方 Round#1：P 前 4 字节 [216,231,146,11] = D8E7920A ⊕ 00000001 */
function ff3RevBytes(b) { var o = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) o[i] = b[b.length - 1 - i]; return o; }
function ff3RevArr(a) { return a.slice().reverse(); }
function ff3Core(keyBytes, tweakBytes, digits, radix, encrypt) {
  var n = digits.length;
  if (tweakBytes.length !== 8) throw new Error('FF3 的 tweak 必须为 8 字节（64 位）');
  if (n < 2 || n > 56) throw new Error('FF3 明文长度需在 2 ~ 56 之间');
  if (radix < 2 || radix > 65536) throw new Error('radix 需在 2 ~ 65536 之间');
  /* CIPH_REVB(K)：AES 的密钥本身要字节反转 */
  var aesFn = ff1AesEcbFn(ff3RevBytes(keyBytes));
  var u = Math.ceil(n / 2), v = n - u;
  var A = digits.slice(0, u), B = digits.slice(u);
  var TL = tweakBytes.subarray(0, 4), TR = tweakBytes.subarray(4, 8);
  var r = BigInt(radix), i, j;
  for (i = 0; i < 8; i++) {
    var rd = encrypt ? i : 7 - i;
    var m = (rd % 2 === 0) ? u : v;
    var W = (rd % 2 === 0) ? TR : TL;
    /* Feistel 的【加密】用 B 算 y、加到 A 上，然后 A<-B, B<-C；
       【解密】必须反过来：用 A 算 y（因为上一轮的 B 就是本轮的 A），
       从 B 里减掉 y 还原出上一轮的 A，再 A<-C, B<-A。
       早先我解密时也套用「P 用 B、A<-B,B<-C」，导致解密完全不对。 */
    var src = encrypt ? B : A;
    var P = new Uint8Array(16);
    for (j = 0; j < 4; j++) P[j] = W[j] ^ (j === 3 ? rd : 0);   /* W ⊕ [i]^4 */
    var bb = ff1B(ff1NumRadix(ff3RevArr(src), radix), 12);
    for (j = 0; j < 12; j++) P[4 + j] = bb[j];
    var S = ff3RevBytes(aesFn.enc(ff3RevBytes(P)));
    var y = ff1Num(S);
    var mod = r ** BigInt(m);
    var base = encrypt ? A : B;
    var c = encrypt ? ((ff1NumRadix(ff3RevArr(base), radix) + y) % mod)
                    : ((ff1NumRadix(ff3RevArr(base), radix) - y) % mod);
    if (c < 0n) c += mod;
    var C = ff3RevArr(ff1StrRadix(m, c, radix));
    if (encrypt) { A = B; B = C; } else { A = C; B = src; }
  }
  return A.concat(B);
}


/* 界面条目：FF3 格式保留加密 */
reg({ id: 'ff3', name: 'FF3 格式保留加密', group: '对称加密', key: true,
  keyLabel: 'AES 密钥（Hex，16/24/32 字节）',
  paramLabel: '参数：radix,tweak(8字节Hex)  例：10,D8E7920AFA330A73',
  param: true, paramOptional: true,
  info: 'FF3（NIST SP 800-38G）：16 位卡号加密后仍是 16 位数字。⚠ 原始 FF3 已被 NIST 于 2025 年移除（tweak 调度攻击），遗留数据解密可用，新系统请用 FF1。',
  enc: function (b, k, p, fmt) { return ff3Entry(b, k, p, true); },
  dec: function (b, k, p, fmt) { return ff3Entry(b, k, p, false); } });
function ff3Entry(b, k, p, encrypt) {
  var parts = String(p || '10,').split(',');
  var radix = parseInt(parts[0], 10) || 10;
  var twStr = (parts[1] || '').trim();
  var tw = twStr ? hexToBytes(twStr) : new Uint8Array(8);
  if (tw.length !== 8) { var t2 = new Uint8Array(8); t2.set(tw.subarray(0, Math.min(8, tw.length))); tw = t2; }
  var key = hexToBytes(k);
  var s = bytesToStr(b, 'utf8').trim();
  var digits = [], i, c;
  for (i = 0; i < s.length; i++) {
    c = s.charCodeAt(i);
    if (c >= 48 && c <= 57) digits.push(c - 48);
    else if (c >= 97 && c <= 122) digits.push(c - 87);
    else if (c >= 65 && c <= 90) digits.push(c - 65);
    else throw new Error('FF3 输入只能包含 0-9 / a-z / A-Z');
    if (digits[i] >= radix) throw new Error('字符 "' + s[i] + '" 超出 radix=' + radix);
  }
  var out = ff3Core(key, tw, digits, radix, encrypt);
  return out.map(function (d) { return d < 10 ? String.fromCharCode(48 + d) : String.fromCharCode(87 + d); }).join('');
}
if (typeof SEC_RULES === 'object') SEC_RULES.ff3 = { level: 'danger', msg: 'FF3 已被 NIST 于 2025 年从 SP 800-38G 移除（tweak 调度攻击）。仅建议用于解密遗留数据，新系统请用 FF1。' };

/* ⚠ 这里曾同时漏写 key:true 与 param:true，导致【私钥框和公钥框都不显示】，
   Ed448 签名在界面上完全无法使用（比 X448 更严重）。同样由 t_label_switch.js 扫出。 */
reg({ id: 'ed448', name: 'Ed448 签名', group: '椭圆曲线与高级代数', keyLen: 57,
  key: true, keyOptional: true, param: true, paramOptional: true,
  keyLabel: '私钥 57 字节（Hex）', paramLabel: '验签：「签名Hex,公钥Hex」（公钥可省略，省略则用私钥推导）',
  info: 'Ed448（RFC 8032）：448 位 Edwards 曲线，SHAKE256 哈希。私钥/公钥 57 字节，签名 114 字节。用法：密钥栏留空点【加密】生成密钥对；签名时输入区放消息、密钥栏放私钥；验签时输入区放消息、参数栏放「签名Hex,公钥Hex」。',
  enc: function (b, k, p, fmt) {
    var s = String(k || '').trim();
    if (!s) {
      /* 留空则生成新密钥对——与 X448/X25519 行为一致，否则用户拿到输入框也无从下手。
         RFC 8032：Ed448 私钥就是 57 字节随机数，公钥由基点标量乘导出（无需 clamp）。 */
      var sk = crypto.getRandomValues(new Uint8Array(57));
      return '私钥（Hex，57 字节）：' + bytesToHex(sk) +
        '\n公钥（Hex，57 字节）：' + bytesToHex(ed448PublicFromPriv(sk)) +
        '\n（签名时把私钥填密钥栏；验签时把公钥填参数栏）';
    }
    var sk = hexToBytes(s);
    if (sk.length !== 57) throw new Error('Ed448 私钥必须为 57 字节（114 位 Hex）');
    return bytesOut(ed448Sign(b, sk), fmt);
  },
  /* ⚠ 原实现里 var msg = p ? new Uint8Array(0) : new Uint8Array(0) —— 两个分支都返回空数组，
     导致【待签消息恒为空】。后果：签名非消息时验签必然失败，且失败原因极难定位
     （看起来像签名算法错，实际是消息没传进去）。
     改法：输入区统一放待签消息（签名/验签含义一致），参数栏用「签名Hex,公钥Hex」。
     沿用项目内已有惯例（如 nonceHex[,aadHex]）。 */
  dec: function (b, k, p, fmt) {
    var ps = String(p || '').trim();
    var parts = ps.split(',');
    var sigHex = (parts[0] || '').trim();
    var pubHex = (parts[1] || '').trim();
    var sig = hexToBytes(sigHex);
    if (sig.length !== 114) throw new Error('参数栏需填「签名Hex,公钥Hex」：签名 114 字节（228 位 Hex），公钥可省略（省略则用密钥栏私钥推导）');
    var pub = pubHex ? hexToBytes(pubHex) : ed448PublicFromPriv(hexToBytes(String(k || '').trim()));
    if (pub.length !== 57) throw new Error('公钥必须为 57 字节（114 位 Hex）');
    return ed448Verify(b, sig, pub) ? '验签通过（Ed448 / RFC 8032）' : '验签失败（消息或签名不匹配）';
  } });
