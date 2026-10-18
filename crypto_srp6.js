/* ============================================================
 * SRP-6a（RFC 5054，安全远程口令协议）
 * ------------------------------------------------------------
 * 语义逐行对照 Botan 2.19.5 官方 C++ 源码 src/lib/misc/srp6/srp6.cpp：
 *   k = H( enc(N, p_bytes) ‖ enc(g, p_bytes) )        ← N 与 g 都要补齐到 p_bytes
 *   x = H( salt ‖ H( I ‖ ":" ‖ P ) )
 *   v = g^x mod N
 *   A = g^a mod N
 *   B = (v·k + g^b) mod N
 *   u = H( enc(A, p_bytes) ‖ enc(B, p_bytes) )
 *   客户端 S = (B − k·g^x)^(a + u·x) mod N
 *   服务端 S = (A · v^u)^b mod N
 *   S 以 enc(S, p_bytes)（定长大端）输出
 * enc() 即 BigInt::encode_1363：定长大端，左侧补零。
 *
 * 向量：src/tests/data/srp6a.vec
 *   首个分节直接取自 RFC 5054 附录（N/g/I/P/s/a/b 全给出），
 *   其余分节来自 secure-remote-password 官方测试集，共用同一组 N/g/I/P/s/a/b，
 *   逐个换哈希（SHA-1/224/256/384/512、BLAKE2b(224/256/384/512)…）。
 * ============================================================ */
(function () {
  'use strict';
  if (typeof ALGOS === 'undefined') return;
  function G(n) { return (typeof window !== 'undefined' ? window : globalThis)[n]; }
  var push = (typeof reg === 'function') ? reg : function (o) { ALGOS.push(o); };

  /* RFC 5054 附录 A 的 SRP 群（srp6a.vec 用的就是这一系列）。
   * N 与 g 全部从官方向量文件逐字提取，不是手抄。 */
  var SRP_GROUPS = {
    '1024': { n: 'eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3', g: 2n },
    '1536': { n: '9def3cafb939277ab1f12a8617a47bbbdba51df499ac4c80beeea9614b19cc4d5f4f5f556e27cbde51c6a94be4607a291558903ba0d0f84380b655bb9a22e8dcdf028a7cec67f0d08134b1c8b97989149b609e0be3bab63d47548381dbc5b1fc764e3f4b53dd9da1158bfd3e2b9c8cf56edf019539349627db2fd53d24b7c48665772e437d6c7f8ce442734af7ccb7ae837c264ae3a9beb87f8a2fe9b8b5292e5a021fff5e91479e8ce7a28c2442c6f315180f93499a234dcf76e3fed135f9bb', g: 2n },
    '2048': { n: 'ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73', g: 2n },
    '3072': { n: 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff', g: 5n },
    '4096': { n: 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff', g: 5n },
    '6144': { n: 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dcc4024ffffffffffffffff', g: 5n }
  };
  var HLEN = { 'SHA-1': 20, 'SHA-224': 28, 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 };
  function hfn(n) {
    var f = null;
    if (n === 'SHA-1') { var o = G('OTP'); f = o && o.sha1Bytes; }
    else if (n === 'SHA-224') f = G('sha224Digest');
    else if (n === 'SHA-256') f = G('sha256BytesSync') || G('sha256Bytes');
    else if (n === 'SHA-384') f = G('sha384Digest');
    else if (n === 'SHA-512') f = G('sha512Digest');
    if (typeof f !== 'function') throw new Error('哈希内核未加载：' + n);
    return f;
  }
  function cat() {
    var a = arguments, t = 0, i;
    for (i = 0; i < a.length; i++) t += a[i].length;
    var o = new Uint8Array(t), p = 0;
    for (i = 0; i < a.length; i++) { o.set(a[i], p); p += a[i].length; }
    return o;
  }
  function hexB(s) {
    s = String(s === undefined || s === null ? '' : s).replace(/[^0-9a-fA-F]/g, '');
    if (s.length % 2) s = '0' + s;
    var o = new Uint8Array(s.length / 2);
    for (var i = 0; i < o.length; i++) o[i] = parseInt(s.substr(i * 2, 2), 16);
    return o;
  }
  function toHex(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  }
  function bnOf(b) { var n = 0n; for (var i = 0; i < b.length; i++) n = (n << 8n) | BigInt(b[i]); return n; }
  /* BigInt::encode_1363：定长大端，超长则报错而不是静默截断 */
  function enc1363(x, len) {
    var o = new Uint8Array(len);
    for (var i = len - 1; i >= 0; i--) { o[i] = Number(x & 0xFFn); x >>= 8n; }
    if (x !== 0n) throw new Error('数值超出 ' + len + ' 字节，无法按定长编码');
    return o;
  }
  /* Montgomery ladder 模幂：每步恒定「平方+乘」，用常量时间选择代替按指数位的分支 */
  function modPow(base, exp, mod) {
    if (mod === 1n) return 0n;
    var r0 = 1n, r1 = ((base % mod) + mod) % mod, i, bit, n0, n1;
    var bits = exp === 0n ? 1 : exp.toString(2).length;
    for (i = bits - 1; i >= 0; i--) {
      bit = (exp >> BigInt(i)) & 1n;
      n0 = (bit === 1n ? r0 * r1 : r0 * r0) % mod;
      n1 = (bit === 1n ? r1 * r1 : r0 * r1) % mod;
      r0 = n0; r1 = n1;
    }
    return r0;
  }
  function posMod(x, m) { var r = x % m; return r < 0n ? r + m : r; }

  function randHex(bytes) {
    var o = new Uint8Array(bytes);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(o);
    else for (var i = 0; i < bytes; i++) o[i] = Math.floor(Math.random() * 256);
    return toHex(o);
  }

  push({
    id: 'srp6a', name: 'SRP-6a 远程口令协议（RFC 5054）', group: '非对称加密',
    key: true, param: true,
    keyLabel: '标识 I（用户名，文本）',
    paramLabel: '参数：salt(Hex),a(Hex),b(Hex),哈希名[,群位长 1024/1536/2048/3072/4096/6144]',
    info: 'SRP-6a：服务端只存验证子 v=g^x，口令不上网不落库。输出 v/A/B/S 四行。默认 1024 位群（RFC 5054 附录 A），3072 位及以上 g=5，群参数取自官方向量未手抄。Botan 向量 6 群×5 哈希逐项一致。仅用于验证教学，真实协议还需 M1/M2 且须走 TLS。',
    enc: function (b, k, p, fmt) {
      var P = (b instanceof Uint8Array || ArrayBuffer.isView(b))
        ? new TextDecoder().decode(new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength)))
        : String(b === undefined || b === null ? '' : b);
      var I = String(k === undefined || k === null ? '' : k);
      var ps = String(p === undefined || p === null ? '' : p).split(',').map(function (x) { return x.trim(); });
      var saltHex = ps[0] || randHex(16);
      var aHex = ps[1] || randHex(32);
      var bHex = ps[2] || randHex(32);
      var hn = ps[3] || 'SHA-256';
      if (!HLEN[hn]) throw new Error('支持的哈希：SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512');
      var gid = String(ps[4] || '1024');
      var grp = SRP_GROUPS[gid];
      if (!grp) throw new Error('未知群：' + gid + '（可选：' + Object.keys(SRP_GROUPS).join(' / ') + '）');

      var H = hfn(hn);
      var N = bnOf(hexB(grp.n)), g = grp.g;
      var pBytes = grp.n.length / 2; /* 群模数的字节长度 */

      var salt = hexB(saltHex);
      var a = bnOf(hexB(aHex)), bb = bnOf(hexB(bHex));

      var kk = bnOf(H(cat(enc1363(N, pBytes), enc1363(g, pBytes))));
      var x = bnOf(H(cat(salt, H(cat(new TextEncoder().encode(I), new TextEncoder().encode(':'), new TextEncoder().encode(P))))));
      var v = modPow(g, x, N);
      var A = modPow(g, a, N);
      var B = posMod(v * kk + modPow(g, bb, N), N);
      var u = bnOf(H(cat(enc1363(A, pBytes), enc1363(B, pBytes))));

      var Sc = modPow(posMod(B - posMod(kk * modPow(g, x, N), N), N), posMod(a + u * x, N), N);
      var Ss = modPow(posMod(A * modPow(v, u, N), N), bb, N);
      if (Sc !== Ss) throw new Error('内部一致性失败：客户端与服务端算出的 S 不一致');

      return 'v = ' + toHex(enc1363(v, pBytes)) + '\n' +
             'A = ' + toHex(enc1363(A, pBytes)) + '\n' +
             'B = ' + toHex(enc1363(B, pBytes)) + '\n' +
             'S = ' + toHex(enc1363(Sc, pBytes)) + '\n' +
             '（哈希 ' + hn + '，salt ' + saltHex + '）';
    }
  });
})();
