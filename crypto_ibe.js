/* ============================================================
 * Boneh-Franklin 基于身份加密（IBE），跑在 BN254 上
 * 参考：Boneh & Franklin, "Identity-Based Encryption from the Weil Pairing" (SIAM 2001)
 * 注意：BN254 是 type-3（非对称）配对，G1 ≠ G2，两侧不能互换：
 *   · 公钥侧 Ppub ∈ G2，身份点 Q_ID ∈ G1
 *   · 私钥 d_ID = s·Q_ID ∈ G1，密文头 U = r·P2 ∈ G2
 *   · 配对一律 e(G2, G1)，即 bnPairing(G2点, G1点)
 * 若把 G1/G2 写反，bnPairing 会抛"不在曲线上"，但若是自己算的点就可能静默出错。
 * ============================================================ */
(function () {
  var P2 = BN_G2, P1 = BN_G1;
  var INF1 = 'INF';

  /* bigToHex / bigFromBytes 是 crypto_core.js IIFE 内的局部函数，跨文件取不到
     （本项目已第 3 次踩这个坑：SM2 的 sm2ZA、KZG 的 bigToBytes）。这里写本地版本。 */
  function u256(v) {
    v = ((v % BN_P) + BN_P) % BN_P;
    var o = new Uint8Array(32);
    for (var i = 31; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; }
    return o;
  }
  function hex32(v) { return bytesToHex(u256(v)); }
  function g1ToBytes(P) { return concatBytes(u256(P[0]), u256(P[1])); }
  function g1FromBytes(b) {
    if (b.length !== 64) throw new Error('G1 点需 64 字节');
    var P = [bnFqFromBytes(b.subarray(0, 32)), bnFqFromBytes(b.subarray(32, 64))];
    if (!bnG1IsOn(P)) throw new Error('G1 点不在曲线上');
    return P;
  }
  function g2ToBytes(Q) {
    return concatBytes(concatBytes(u256(Q[0][0]), u256(Q[0][1])), concatBytes(u256(Q[1][0]), u256(Q[1][1])));
  }
  function g2FromBytes(b) {
    if (b.length !== 128) throw new Error('G2 点需 128 字节');
    return [[bnFqFromBytes(b.subarray(0, 32)), bnFqFromBytes(b.subarray(32, 64))],
            [bnFqFromBytes(b.subarray(64, 96)), bnFqFromBytes(b.subarray(96, 128))]];
  }
  /* FQ 开平方：BN254 的 p ≡ 3 (mod 4)，故 sqrt(a) = a^((p+1)/4)。
     算完必须回代验证，否则非剩余也会被"开方"出一个看似合理的假值。 */
  var BN_P1_4 = (BN_P + 1n) / 4n;
  function fqPow(a, e) {
    var r = 1n, b = bnfq(a);
    while (e > 0n) { if (e & 1n) r = bnfq(r * b); b = bnfq(b * b); e >>= 1n; }
    return r;
  }
  function fqSqrt(a) {
    a = bnfq(a);
    if (a === 0n) return 0n;
    var y = fqPow(a, BN_P1_4);
    return bnfq(y * y) === a ? y : null;
  }
  /* H1：身份字符串 → G1 点（try-and-increment） */
  function hashToG1(idBytes) {
    for (var ctr = 0; ctr < 256; ctr++) {
      var h = sha256Bytes(concatBytes(idBytes, new Uint8Array([ctr & 0xff])));
      var x = 0n, i;
      for (i = 0; i < 32; i++) x = (x << 8n) | BigInt(h[i]);
      x = bnfq(x);
      var y2 = bnfq(bnfq(bnfq(x * x) * x) + BN_B);
      var y = fqSqrt(y2);
      if (y === null) continue;
      /* 取 y 为偶数的分支，保证同一身份恒得同一点 */
      if (y % 2n === 1n) y = bnfq(-y);
      var P = [x, y];
      if (bnG1IsOn(P)) return P;
    }
    throw new Error('H1 未在 256 次尝试内命中曲线点');
  }
  function concatBytes(a, b) {
    var o = new Uint8Array(a.length + b.length);
    o.set(a, 0); o.set(b, a.length); return o;
  }
  /* H2：GT 元素 → 比特流（SHA-256 计数器模式 KDF） */
  function hashGT(g, len) {
    var seed = bnF12ToBytes(g), out = new Uint8Array(len), off = 0, ctr = 0;
    while (off < len) {
      var blk = sha256Bytes(concatBytes(seed, new Uint8Array([ctr++ & 0xff])));
      for (var i = 0; i < 32 && off < len; i++) out[off++] = blk[i];
    }
    return out;
  }
  function xorBytes(a, b) {
    var o = new Uint8Array(a.length);
    for (var i = 0; i < a.length; i++) o[i] = a[i] ^ b[i % b.length];
    return o;
  }
  function frRand() {
    var b = crypto.getRandomValues(new Uint8Array(32));
    var v = 0n;
    for (var i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[i]);
    return (v % (BN_R - 1n)) + 1n;
  }
  function frFromHex(s) {
    s = String(s).trim().replace(/\s/g, '');
    var b = hexToBytes(s);
    if (b.length !== 32) throw new Error('主私钥需 32 字节 Hex（64 个十六进制字符）');
    var v = 0n;
    for (var i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[i]);
    if (v === 0n || v >= BN_R) throw new Error('主私钥不在有效范围内');
    return v;
  }
  function frToHex(v) { return bytesToHex(u256(v)); }

  var G = '非对称加密';
  reg({ id: 'ibe-setup', name: 'IBE 主密钥生成（Boneh-Franklin）', group: G, key: false, param: false,
    info: 'Boneh-Franklin 基于身份加密的主密钥建立。输出主私钥 s（必须离线保管）与公开参数 Ppub = s·P₂（可公开）。之后任何身份的私钥都由 s 派生。',
    enc: function (b) {
      var s = frRand();
      var Ppub = bnG2Mul(P2, s);
      return 's（主私钥，务必保密）: ' + frToHex(s) + '\nPpub（公开参数，128 字节 G2 点）: ' + bytesToHex(g2ToBytes(Ppub));
    }, dec: false });

  reg({ id: 'ibe-extract', name: 'IBE 用户私钥提取', group: G, key: true, param: true,
    keyLabel: '主私钥 s（32 字节 Hex）', paramLabel: '身份 ID（如 alice@example.com）',
    info: '用主私钥为某个身份派生私钥 d_ID = s·H₁(ID) ∈ G1。身份可以是邮箱、手机号等任意字符串——这正是 IBE 无需证书的原因。输出 64 字节 G1 点。',
    enc: function (b, k, p, fmt) {
      var s = frFromHex(k);
      var id = strToBytes(String(p || ''));
      if (!id.length) throw new Error('请在参数栏填写身份 ID');
      var d = bnG1Mul(hashToG1(id), s);
      return bytesOut(g1ToBytes(d), fmt);
    }, dec: false });

  reg({ id: 'ibe-encrypt', name: 'IBE 加密（向某身份）', group: G, key: true, param: true,
    keyLabel: 'Ppub 公开参数（128 字节 Hex）', paramLabel: '接收方身份 ID',
    info: 'Boneh-Franklin IBE 加密。无需对方证书，只要知道身份字符串即可加密。密文 = U(r·P₂，128 字节) ‖ 密文主体。⚠ BF-IBE 只能加密短消息（此处用 XOR 流），实际应封装一个对称密钥。',
    enc: function (b, k, p, fmt) {
      var Ppub = g2FromBytes(hexToBytes(String(k).replace(/\s/g, '')));
      var id = strToBytes(String(p || ''));
      if (!id.length) throw new Error('请在参数栏填写接收方身份 ID');
      var Q = hashToG1(id), r = frRand();
      var U = bnG2Mul(P2, r);
      var g = bnPairing(Ppub, Q);          /* e(s·P₂, Q) = e(P₂,Q)^s */
      var gr = bn12Pow(g, r);              /* 提升到 r 次幂 */
      var mask = hashGT(gr, b.length);
      var ct = concatBytes(g2ToBytes(U), xorBytes(b, mask));
      return bytesOut(ct, fmt);
    }, dec: false });

  reg({ id: 'ibe-decrypt', name: 'IBE 解密（用自己的私钥）', group: G, key: true, param: false,
    keyLabel: '自己的私钥 d_ID（64 字节 Hex）',
    info: '用 IBE 用户私钥解密。取密文头 128 字节作为 U，计算 e(d_ID, U) 还原掩码。若身份不匹配，解出来是乱码而非报错——这是 IBE 的常见特性。',
    dec: function (str, k, p, fmt) {
      var d = g1FromBytes(hexToBytes(String(k).replace(/\s/g, '')));
      var ct = bytesIn(String(str), fmt);
      if (ct.length < 128) throw new Error('密文至少 128 字节（含 128 字节的 U）');
      var U = g2FromBytes(ct.subarray(0, 128));
      var body = ct.subarray(128);
      var g = bnPairing(U, d);             /* e(r·P₂, s·Q) = e(P₂,Q)^(rs) */
      var mask = hashGT(g, body.length);
      return bytesOut(xorBytes(body, mask), fmt);
    }, enc: false });

  /* FQ12 幂：把配对结果提升到 k 次——BF-IBE 里 g^r 必须这么算，
     不能"把 r 乘到点上再配对"（那得到的是 e(P,Q)^(r) 而非 g^r）。 */
  function bn12Pow(a, k) {
    var r = bn12one(), b = a.slice();
    k = ((k % BN_R) + BN_R) % BN_R;
    while (k > 0n) { if (k & 1n) r = bn12mul(r, b); b = bn12mul(b, b); k >>= 1n; }
    return r;
  }
  globalThis.IBE = { hashToG1: hashToG1, hashGT: hashGT, bn12Pow: bn12Pow,
    g1ToBytes: g1ToBytes, g1FromBytes: g1FromBytes, g2ToBytes: g2ToBytes, g2FromBytes: g2FromBytes,
    fqSqrt: fqSqrt };
})();
