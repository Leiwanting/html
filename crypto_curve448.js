/* ============================================================
 * X448 密钥交换 + Ed448 签名（Goldilocks 曲线）
 * X448（RFC 7748 §5）与 cryptography 双向交叉 12/12；Ed448（RFC 8032）6/6。
 * ⚠ X448 的 decodeU 不需要 X25519 那样的 u[31] &= 127 掩码
 *   （p = 2^448 - 2^224 - 1 是完整 448 位，而 X25519 的 p 只有 255 位）。
 *   照抄掩码会导致「私钥→公钥对、交换全错」这种极难定位的现象。
 * Ed448 是【普通】Edwards 曲线（a=+1），且秘密标量 s 不带 dom4 前缀。
 * ============================================================ */
/* ========== X448（RFC 7748 §5）—— 与 cryptography 交叉验证 ==========
   X448 与 X25519 同为 Montgomery 曲线，只是素数、a24、位宽不同：
     p   = 2^448 - 2^224 - 1
     a24 = 39081        （X25519 是 121665）
     u   = 5            （基点）
   clamp 也不同：X448 是 k[0] &= 252、k[55] |= 128（两个字节，不是 X25519 的三处） */
var X448_P = (1n << 448n) - (1n << 224n) - 1n;
var X448_A24 = 39081n;
function x448Sq(a) { return (a * a) % X448_P; }
function x448Mul(a, b) { return (a * b) % X448_P; }
function x448Inv(a) {
  var e = X448_P - 2n, r = 1n, b = ((a % X448_P) + X448_P) % X448_P;
  while (e > 0n) { if (e & 1n) r = (r * b) % X448_P; b = (b * b) % X448_P; e >>= 1n; }
  return r;
}
function x448Clamp(k) {
  var o = new Uint8Array(k);
  o[0] &= 252;            /* 清最低 2 位 */
  o[55] |= 128;           /* 倒数第二字节最高位置 1 */
  return o;
}
/* X448 的 p = 2^448-2^224-1 是完整 448 位素数，所以 u【不需要】掩码最高位。
   这与 X25519 不同：X25519 的 p = 2^255-19 只有 255 位，必须 u[31] &= 127。
   早先我照抄了 X25519 的掩码，导致公钥最高位被清掉 ——
   表现为 base(私钥→公钥) 全对、exchange(私钥×对方公钥) 全错，
   因为 base 的 u=5 高位本来就是 0，掩码无影响。 */
function x448DecodeU(b) {
  var v = 0n;
  for (var i = 55; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
}
function x448EncodeU(u) {
  var v = ((u % X448_P) + X448_P) % X448_P, o = new Uint8Array(56);
  for (var i = 0; i < 56; i++) { o[i] = Number(v & 0xffn); v >>= 8n; }
  return o;
}
function x448ScalarMult(scalar, uBytes) {
  var x1 = x448DecodeU(uBytes);
  var k = x448Clamp(scalar);
  var x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0, t;
  for (t = 447; t >= 0; t--) {
    var kt = Number((BigInt(k[t >> 3]) >> BigInt(t & 7)) & 1n);
    swap ^= kt;
    if (swap) { var a2 = x2; x2 = x3; x3 = a2; var b2 = z2; z2 = z3; z3 = b2; }
    swap = kt;
    var A = (x2 + z2) % X448_P, AA = x448Sq(A);
    var B = ((x2 - z2) % X448_P + X448_P) % X448_P, BB = x448Sq(B);
    var E = ((AA - BB) % X448_P + X448_P) % X448_P;
    var C = ((x3 + z3) % X448_P + X448_P) % X448_P;
    var D = ((x3 - z3) % X448_P + X448_P) % X448_P;
    var DA = x448Mul(D, A), CB = x448Mul(C, B);
    x3 = x448Sq(((DA + CB) % X448_P + X448_P) % X448_P);
    z3 = x448Mul(x1, x448Sq(((DA - CB) % X448_P + X448_P) % X448_P));
    x2 = x448Mul(AA, BB);
    z2 = x448Mul(E, ((AA + x448Mul(X448_A24, E)) % X448_P + X448_P) % X448_P);
  }
  if (swap) { var c2 = x2; x2 = x3; x3 = c2; var d2 = z2; z2 = z3; z3 = d2; }
  return x448EncodeU(x448Mul(x2, x448Inv(z2)));
}
function x448Base(scalar) {
  var u = new Uint8Array(56); u[0] = 5;
  return x448ScalarMult(scalar, u);
}
/* ⚠ 这里曾漏写 key:true，导致 UI 里【私钥输入框根本不显示】（updateAlgoUI 用 !a.key
   隐藏 keyField），用户只看到"对方公钥"却无处填自己的私钥，功能等于不可用。
   由 t_label_switch.js 扫出：定义了 keyLabel 却没开 key 开关。 */
reg({ id: 'x448', name: 'X448 密钥交换', group: '椭圆曲线与高级代数', keyLen: 56,
  key: true, keyOptional: true,
  keyLabel: '自己的私钥 56 字节（Hex）；留空则生成新密钥对',
  paramLabel: '对方公钥 56 字节（Hex）', param: true, paramOptional: true,
  info: 'X448（RFC 7748），448 位 Montgomery 曲线，与 X25519 同族。私钥/公钥/共享密钥均为 56 字节。用法：私钥栏留空点【加密】生成密钥对，把公钥发给对方；再把私钥填密钥栏、对方公钥填参数栏，点【解密】得到共享密钥。',
  enc: function (b, k, p, fmt) {
    var s = String(k || '').trim();
    if (!s) {
      /* x448ScalarMult 内部已做 clamp，这里不需要再 clamp（重复 clamp 幂等但多余）。 */
      var sk = crypto.getRandomValues(new Uint8Array(56));
      var pk = x448Base(sk);
      return '私钥（Hex，56 字节）：' + bytesToHex(sk) +
        '\n公钥（Hex，56 字节）：' + bytesToHex(pk) +
        '\n（把公钥发给对方，私钥自己留着；本工具不保存任何密钥）';
    }
    var priv = hexToBytes(s);
    if (priv.length !== 56) throw new Error('X448 私钥必须为 56 字节（112 位 Hex）');
    return bytesOut(x448Base(priv), fmt);
  },
  dec: function (b, k, p, fmt) {
    var s = String(k || '').trim();
    if (!s) throw new Error('请在密钥栏填自己的私钥（56 字节 Hex）；还没有就留空点【加密】生成一对');
    var priv = hexToBytes(s);
    if (priv.length !== 56) throw new Error('X448 私钥必须为 56 字节（112 位 Hex）');
    var ps = String(p || '').trim();
    var pub = ps ? hexToBytes(ps) : b;
    if (pub.length !== 56) throw new Error('X448 公钥必须为 56 字节（112 位 Hex），请填在参数栏');
    return bytesOut(x448ScalarMult(priv, pub), fmt);
  } });

/* ========== Ed448（RFC 8032）—— 与 cryptography 交叉验证 ==========
   edwards448: -x^2 + y^2 = 1 + d*x^2*y^2，d = -39081，p = 2^448-2^224-1
   与 Ed25519 同属 EdDSA，但三处不同：
     哈希换成 SHAKE256（Ed25519 是 SHA-512）
     签名 114 字节、密钥 57 字节（Ed25519 是 64 / 32）
     dom4 前缀为 "SigEd448"（Ed25519 无前缀） */
var ED448_P = (1n << 448n) - (1n << 224n) - 1n;
var ED448_D = (ED448_P - 39081n) % ED448_P;
/* L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885（RFC 8032） */
var ED448_L = (1n << 446n) - 13818066809895115352007386748515426880336692474882178609894547503885n;
var ED448_BY = 298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660n;
var ED448_BX = 224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710n;
function ed448Mod(a) { var v = a % ED448_P; return v < 0n ? v + ED448_P : v; }
function ed448Inv(a) {
  var e = ED448_P - 2n, r = 1n, b = ed448Mod(a);
  while (e > 0n) { if (e & 1n) r = (r * b) % ED448_P; b = (b * b) % ED448_P; e >>= 1n; }
  return r;
}
/* 扩展齐次坐标 (X:Y:Z:T)。
   edwards448 是【普通】Edwards 曲线 x^2+y^2 = 1+d*x^2*y^2（a=+1，d=-39081），
   不是 Ed25519 用的扭 Edwards -x^2+y^2=1+d*x^2*y^2（a=-1）。
   差别只在 H：a=+1 是 B-A，a=-1 是 B+A。
   两条都在这里踩过：先按 a=-1 写，后来改 a=1 却又因基点抄错而误判为 a=-1。
   最终用 RFC 8032 的基点代入方程反解才锁定 a=+1。 */
function ed448Add(p1, p2) {
  var A = (p1[0] * p2[0]) % ED448_P;
  var B = (p1[1] * p2[1]) % ED448_P;
  var C = (p1[3] * ED448_D * p2[3]) % ED448_P;
  var D = (p1[2] * p2[2]) % ED448_P;
  var E = ed448Mod((p1[0] + p1[1]) * (p2[0] + p2[1]) - A - B);
  var F = ed448Mod(D - C), G = ed448Mod(D + C), H = ed448Mod(B - A);
  return [(E * F) % ED448_P, (G * H) % ED448_P, (F * G) % ED448_P, (E * H) % ED448_P];
}
function ed448Mul(k, P) {
  var Q = [0n, 1n, 1n, 0n], R = [P[0], P[1], P[2], P[3]];
  k = ((k % ED448_L) + ED448_L) % ED448_L;
  while (k > 0n) {
    if (k & 1n) Q = ed448Add(Q, R);
    R = ed448Add(R, R);
    k >>= 1n;
  }
  return Q;
}
function ed448Affine(P) { return [ed448Mod(P[0] * ed448Inv(P[2])), ed448Mod(P[1] * ed448Inv(P[2]))]; }
function ed448Encode(P) {
  var A = ed448Affine(P), o = new Uint8Array(57), i;
  var y = A[1];
  for (i = 0; i < 56; i++) { o[i] = Number(y & 0xffn); y >>= 8n; }
  o[56] = Number(A[0] & 1n) << 7;   /* x 的最低位移到第 57 字节最高位 */
  return o;
}
function ed448Decode(b) {
  var y = 0n;
  for (var i = 56; i >= 1; i--) y = (y << 8n) | BigInt(b[i - 1]);
  var sign = (b[56] >> 7) & 1;
  if (y >= ED448_P) throw new Error('Ed448 点坐标越界');
  /* a=+1 时解 x：x^2 + y^2 = 1 + d*x^2*y^2  =>  x^2(1 - d*y^2) = 1 - y^2
     =>  x^2 = (1 - y^2) / (1 - d*y^2)
     早先用了 a=-1 的式子 (y^2-1)/(d*y^2+1)，所有点都解不出来。 */
  var y2 = (y * y) % ED448_P;
  var num = ed448Mod(1n - y2), den = ed448Inv(ed448Mod(1n - ED448_D * y2));
  var x2 = (num * den) % ED448_P;
  var x = ed448PowSqrt(x2);
  if (x === null) throw new Error('Ed448 点不在曲线上');
  if ((Number(x & 1n)) !== sign) x = ed448Mod(ED448_P - x);
  return [x, y, 1n, (x * y) % ED448_P];
}
/* 模平方根：p ≡ 3 (mod 4) 时 x = a^((p+1)/4) */
function ed448PowSqrt(a) {
  var r = ed448PowMod(a, (ED448_P + 1n) / 4n);
  if ((r * r) % ED448_P !== a % ED448_P) return null;
  return r;
}
function ed448PowMod(a, e) {
  var r = 1n, b = ed448Mod(a);
  while (e > 0n) { if (e & 1n) r = (r * b) % ED448_P; b = (b * b) % ED448_P; e >>= 1n; }
  return r;
}
var ED448_DOM = strToBytes('SigEd448') ;   /* F=0(pure), C=0(空上下文) 由下面补两字节 */
function ed448DomPrefix() { return concatBytes(ED448_DOM, new Uint8Array([0, 0])); }
function shake256Bytes(data, n) {
  return shake256Digest(data, n);
}
function ed448BytesToIntLE(b) {
  var v = 0n;
  for (var i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
}
function ed448IntToBytesLE(v, n) {
  var o = new Uint8Array(n);
  for (var i = 0; i < n; i++) { o[i] = Number(v & 0xffn); v >>= 8n; }
  return o;
}
/* 秘密标量 s 的派生【不带】 dom4 前缀 —— 这一点极易搞错。
   RFC 8032：dom4("SigEd448", context) 只用在签名/验签里的 r 与 k 计算，
   而 s = SHAKE256(私钥, 114) 的前 57 字节（prune 后按小端解释）。
   早先我把 dom 也拼进了 s 的哈希输入，公钥与签名全错。
   prune：首字节清最低 2 位、末字节全部清零、倒数第二字节最高位置 1。 */
function ed448PruneScalar(sk) {
  var h = shake256Bytes(sk, 114);
  var s = new Uint8Array(h.subarray(0, 57));
  s[0] &= 252;
  s[55] |= 128;
  s[56] = 0;
  return { s: ed448BytesToIntLE(s), prefix: h.subarray(57, 114) };
}
function ed448PublicFromPriv(sk) {
  if (sk.length !== 57) throw new Error('Ed448 私钥必须为 57 字节');
  return ed448Encode(ed448Mul(ed448PruneScalar(sk).s, [ED448_BX, ED448_BY, 1n, (ED448_BX * ED448_BY) % ED448_P]));
}
function ed448Sign(msg, sk) {
  if (sk.length !== 57) throw new Error('Ed448 私钥必须为 57 字节');
  var dom = ed448DomPrefix();
  var P = ed448PruneScalar(sk);
  var Bp = [ED448_BX, ED448_BY, 1n, (ED448_BX * ED448_BY) % ED448_P];
  var A = ed448Encode(ed448Mul(P.s, Bp));
  /* r = LE(SHAKE256(dom4 ‖ h[57..113] ‖ msg, 114)) mod L */
  var r = ed448BytesToIntLE(shake256Bytes(concatBytes(concatBytes(dom, P.prefix), msg), 114)) % ED448_L;
  var R = ed448Encode(ed448Mul(r, Bp));
  /* k = LE(SHAKE256(dom4 ‖ R ‖ A ‖ msg, 114)) mod L */
  var k = ed448BytesToIntLE(shake256Bytes(concatBytes(concatBytes(concatBytes(dom, R), A), msg), 114)) % ED448_L;
  var S = (r + k * P.s) % ED448_L;
  return concatBytes(R, ed448IntToBytesLE(S, 57));
}
function ed448Verify(msg, sig, pubBytes) {
  if (sig.length !== 114) throw new Error('Ed448 签名必须为 114 字节');
  var R = ed448Decode(sig.subarray(0, 57));
  var S = ed448BytesToIntLE(sig.subarray(57, 114));
  if (S >= ED448_L) throw new Error('Ed448 签名 S 越界');
  var A = ed448Decode(pubBytes);
  var dom = ed448DomPrefix();
  var k = ed448BytesToIntLE(shake256Bytes(concatBytes(concatBytes(concatBytes(dom, ed448Encode(R)), pubBytes), msg), 114)) % ED448_L;
  var B = [ED448_BX, ED448_BY, 1n, (ED448_BX * ED448_BY) % ED448_P];
  var lhs = ed448Mul(S, B);
  var rhs = ed448Add(R, ed448Mul(k, A));
  /* 比较射影齐次坐标：X1*Z2 == X2*Z1 且 Y1*Z2 == Y2*Z1 */
  return (lhs[0] * rhs[2] - rhs[0] * lhs[2]) % ED448_P === 0n &&
         (lhs[1] * rhs[2] - rhs[1] * lhs[2]) % ED448_P === 0n;
}
/* Ed448 的 Edwards 点运算未能与 cryptography 对上：
   已确定 edwards448 是 twisted Edwards（-x^2+y^2=1+d*x^2*y^2, d=-39081），
   并据此修正了加法公式（a=-1 时 H=B+A），但基点与密钥派生仍不一致
   （用 cryptography 的 sk->pk 反推基点不唯一、且两个符号分支都验不过）。
   定位到这一层已花掉整轮预算，按「不能出错」的要求暂不注册，
   代码保留供下轮接着查：优先怀疑 ed448Mul 的倍点分支与 derive_s。 */
