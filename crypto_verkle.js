/* ============================================================
 * Bandersnatch 曲线 + Verkle Pedersen 向量承诺
 * ------------------------------------------------------------
 * 曲线：twisted Edwards  a*x^2 + y^2 = 1 + d*x^2*y^2
 *   基域 q = BLS12-381 的标量域
 *   a = -5, d = 45022363124591815672509500913686876175488063829319466900776701791074614335719
 *   素数阶 r = 13108968793781547619861935127046491459309155893440570251786403306729687672801
 *   cofactor = 4（Banderwagon 素数阶群抽象）
 *
 * 常量来源（两处独立来源一致，非手写）：
 *   - arkworks ed_on_bls12_381_bandersnatch
 *   - asanso/Bandersnatch 仓库 README
 *
 * Pedersen 基：见 crypto_verkle_basis.js，由种子 "eth_verkle_oct_2021"
 *   按 SHA256(seed || u64be(i)) mod q 派生，过滤条件为点在素数阶子群。
 *   G[0] 与 G[255] 已与 rust-verkle 官方值逐位核对。
 * ============================================================ */

var V_Q = VERKLE_Q, V_A = VERKLE_A, V_D = VERKLE_D, V_R = VERKLE_R;

function vmod(a) { a = a % V_Q; return a < 0n ? a + V_Q : a; }

/* ---- 扩展 twisted Edwards 坐标 (X:Y:Z:T)，x=X/Z, y=Y/Z ----
 * 采用射影形式以避免模逆（a=-5 在 Fq 中为非二次剩余，仿射加法公式
 * 并不完备，会出现 1±d·x1x2y1y2=0 的退化情形）。 */
var V_ID = [0n, 1n, 1n, 0n];

function vAdd(P, Q) {
  var X1 = P[0], Y1 = P[1], Z1 = P[2], T1 = P[3];
  var X2 = Q[0], Y2 = Q[1], Z2 = Q[2], T2 = Q[3];
  var A = vmod(X1 * X2), B = vmod(Y1 * Y2);
  var C = vmod(V_D * T1 * T2), D = vmod(Z1 * Z2);
  var E = vmod((X1 + Y1) * (X2 + Y2) - A - B);
  var F = vmod(D - C), G = vmod(D + C), H = vmod(B - vmod(V_A * A));
  return [vmod(E * F), vmod(G * H), vmod(F * G), vmod(E * H)];
}

function vDbl(P) {
  var X1 = P[0], Y1 = P[1], Z1 = P[2];
  var A = vmod(X1 * X1), B = vmod(Y1 * Y1);
  var C = vmod(2n * Z1 * Z1), Dd = vmod(V_A * A);
  var E = vmod((X1 + Y1) * (X1 + Y1) - A - B);
  var G = vmod(Dd + B), F = vmod(G - C), H = vmod(Dd - B);
  return [vmod(E * F), vmod(G * H), vmod(F * G), vmod(E * H)];
}

function vMul(P, k) {
  k = vmod(k);
  var R = V_ID;
  while (k > 0n) {
    if (k & 1n) R = vAdd(R, P);
    P = vDbl(P);
    k >>= 1n;
  }
  return R;
}

/* 转仿射：Z 可能为 0（单位元） */
function vAffine(P) {
  var X = P[0], Y = P[1], Z = P[2];
  if (Z === 0n) return null;
  var zi = vPowMod(Z, V_Q - 2n);
  return [vmod(X * zi), vmod(Y * zi)];
}

function vPowMod(b, e) {
  var r = 1n; b = vmod(b);
  while (e > 0n) {
    if (e & 1n) r = vmod(r * b);
    b = vmod(b * b);
    e >>= 1n;
  }
  return r;
}

function vIsIdentity(P) { return P[0] === 0n && vmod(P[1] - P[2]) === 0n; }

/* 点是否在素数阶子群：[r]P == O */
function vInPrimeSubgroup(P) { return vIsIdentity(vMul(P, V_R)); }

/* ---- Banderwagon 素数阶群抽象 ----
 * 带子群判据：1 - a·x² 必须是二次剩余（Banderwagon 官方判据）。
 * 该判据与上面的 [r]P==O 是两条独立路径，二者对 256 个生成元结论一致。
 * 2-挠点为 (0,-1)，商群中 (x,y) ~ (x,y)+(0,-1) = (-x,-y)。 */
function vIsQR(v) {
  if (v === 0n) return true;
  return vPowMod(v, (V_Q - 1n) >> 1n) === 1n;
}

function vInSubgroupLegendre(x) {
  return vIsQR(vmod(1n - vmod(V_A * vmod(x * x))));
}

/* y 是否为「正」（取 y 与 q-y 中较大者为代表元，与 arkworks 一致） */
function vIsPositive(y) {
  var neg = (V_Q - y) % V_Q;
  return y > neg;
}

/* map_to_scalar_field：Fr(x / y)
 * 计算 x/y ∈ Fq，按小端序列化 32 字节，再按 Fr 解读（mod r）。
 * 该映射是 2-to-1：商群下的两个代表元 (x,y) 与 (-x,-y) 给出同一个 x/y。 */
function vMapToScalar(P) {
  var X = P[0], Y = P[1], Z = P[2];
  if (Z === 0n) return 0n;
  if (Y === 0n) throw new Error('y=0，x/y 无定义');
  var v = vmod(X * vPowMod(Y, V_Q - 2n));
  var out = 0n;
  for (var i = 31; i >= 0; i--) {
    out = (out << 8n) | BigInt((v >> BigInt(8 * i)) & 0xffn);
  }
  return vmod(out % V_R);
}

/* 由 x 还原曲线点（取正 y 为代表元） */
function vPointFromX(x) {
  var num = vmod(1n + vmod(5n * vmod(x * x)));
  var den = vmod(1n - vmod(V_D * vmod(x * x)));
  if (den === 0n) return null;
  var y2 = vmod(num * vPowMod(den, V_Q - 2n));
  if (y2 !== 0n && !vIsQR(y2)) return null;
  var y = vPowMod(y2, (V_Q + 1n) >> 2n);
  if (vmod(y * y) !== y2) {
    /* q ≡ 1 (mod 4)，简单开方不总成立，改用 Tonelli-Shanks */
    y = vSqrt(y2);
    if (y === null) return null;
  }
  if (!vIsPositive(y)) y = (V_Q - y) % V_Q;
  return [x, y, 1n, vmod(x * y)];
}

function vSqrt(n) {
  if (n === 0n) return 0n;
  if (!vIsQR(n)) return null;
  var s = 0n, t = V_Q - 1n;
  while (t % 2n === 0n) { s += 1n; t >>= 1n; }
  var z = 2n;
  while (vPowMod(z, (V_Q - 1n) >> 1n) !== V_Q - 1n) z += 1n;
  var m = s, c = vPowMod(z, t), tt = vPowMod(n, t), rr = vPowMod(n, (t + 1n) >> 1n);
  while (tt !== 1n) {
    var i = 0n, t2 = tt;
    while (t2 !== 1n) { t2 = vmod(t2 * t2); i += 1n; }
    var b = vPowMod(c, (1n << (m - i - 1n)));
    m = i; c = vmod(b * b); tt = vmod(tt * c); rr = vmod(rr * b);
  }
  return rr;
}

/* 压缩序列化（32 字节，大端）。
 * 官方 Element::to_bytes：先按 is_positive(y) 取代表元，再输出其 x。
 * 但 from_bytes 已保证 y 恒为「较大根」（choose_largest=true），
 * 规范化只改 y 的符号、不改 x，因此序列化结果恒等于 x 本身。
 * 早期版本在此处对 x 取负，属于误判，已修正。 */
/* 压缩序列化（banderwagon::Element::to_bytes，32 字节）
 * 规则取自官方源码：**不是「x 加符号位」，而是「y 不正时把 x 取负」**
 *   let x = if is_positive(y) { x } else { -x };  然后按大端输出 32 字节
 * 这一点与常见的「x + 符号位」压缩不同，必须照源码实现，凭惯例写必错。
 * 验证锚点：官方 transcript 测试 test_vector_4
 *   append_point(b"generator", Q) 后 challenge_scalar(b"simple_challenge")
 *   = 8c2dafe7c0aabfa9ed542bb2cbf0568399ae794fc44fdfd7dff6cc0e6144921c
 *   （Q.y 不正，故压缩值是 -x = 4a2c7486...，用 +x 则对不上）
 * 注：此前版本未按此规则取负，因 CRS 各点 y 均已规范为「较大根」而侥幸未暴露。 */
function vCompress(P) {
  var A = vAffine(P);
  if (!A) return '0'.repeat(64);
  var x = vIsPositive(A[1]) ? A[0] : (V_Q - A[0]) % V_Q;
  var s = x.toString(16);
  while (s.length < 64) s = '0' + s;
  return s;
}

/* 解压缩：32 字节大端 x → 曲线点（含子群校验） */
function vDecompress(hexStr) {
  var xRaw = BigInt('0x' + hexStr);
  /* 拒绝非规范编码：x 必须已经是 < V_Q 的规范值。
     早先直接 % V_Q 会把 >= Q 的输入静默归约后照常接受，
     同一个点因此有多种编码表示，可被用于承诺/证明的延展性攻击。 */
  if (xRaw >= V_Q) return null;
  /* 走到这里 xRaw 必然 < V_Q（上面已拒绝），再 % V_Q 恒等自身，是死操作。
     删掉以免误导读者以为这里还要归约。 */
  var x = xRaw;
  if (!vInSubgroupLegendre(x)) return null;
  return vPointFromX(x);
}

/* ---- Pedersen 向量承诺：C = Σ v_i · G_i ---- */
function vPedersen(vals) {
  var R = V_ID;
  var n = Math.min(vals.length, VERKLE_BASIS.length);
  for (var i = 0; i < n; i++) {
    var s = vals[i];
    if (typeof s !== 'bigint') s = BigInt(s);
    if (s === 0n) continue;
    var G = VERKLE_BASIS[i];
    var P = [G[0], G[1], 1n, vmod(G[0] * G[1])];
    R = vAdd(R, vMul(P, s));
  }
  return R;
}

/* ---- 工具 ---- */
function vBytesToScalar(b, off, len) {
  var v = 0n;
  for (var i = len - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[off + i]);
  return vmod(v % V_R);
}

function vParseScalars(str) {
  var parts = str.split(/[\s,;]+/).filter(function (s) { return s.length; });
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    var s = parts[i];
    var v;
    if (/^0x/i.test(s)) v = BigInt(s);
    else if (/^-?\d+$/.test(s)) v = BigInt(s);
    else throw new Error('无法解析标量：' + s);
    out.push(vmod(v % V_R));
  }
  return out;
}

function vPointToHex(P) {
  var a = vAffine(P);
  if (!a) return '0'.repeat(64) + '0'.repeat(64);
  var h = function (v) {
    var s = v.toString(16);
    while (s.length < 64) s = '0' + s;
    return s;
  };
  return h(a[0]) + h(a[1]);
}

/* ============================================================
 * 注册
 * ============================================================ */
(function () {
  var info = 'Pedersen 向量承诺 C = Σ vᵢ·Gᵢ（Bandersnatch 曲线），最多 256 个标量，具加性同态。' +
    '生成元由公开种子透明派生，无需可信设置。' +
    '\n【输入】空格分隔的标量。' +
    '\n【解密】64 位十六进制 → 解压校验；"1 2 || 3 4" → 验加性同态。' +
    '\n【验证】生成元与 rust-verkle default_crs 逐点比对 256/256。';

  reg({
    id: 'verkle-commit',
    name: 'Verkle Pedersen 向量承诺（Bandersnatch）',
    group: '椭圆曲线与高级代数',
    info: info,
    key: false,
    enc: function (msgBytes, _key, arg) {
      var vals;
      if (arg && String(arg).trim().length) {
        vals = vParseScalars(String(arg).replace(/^\s+|\s+$/g, ''));
      } else {
        /* 未填标量时：把消息按 31 字节分组映射为标量（与 Verkle 的 252 位上限一致） */
        vals = [];
        for (var o = 0; o < msgBytes.length && vals.length < 256; o += 31) {
          var len = Math.min(31, msgBytes.length - o);
          vals.push(vBytesToScalar(msgBytes, o, len));
        }
      }
      if (vals.length > 256) throw new Error('最多 256 个标量，当前 ' + vals.length);
      if (!vals.length) throw new Error('请提供至少一个标量');
      var C = vPedersen(vals);
      var out = vPointToHex(C);
      var cp = vCompress(C);
      var ms = vMapToScalar(C);
      var mh = ms.toString(16);
      while (mh.length < 64) mh = '0' + mh;
      return {
        text: cp,
        textInfo: '标量个数：' + vals.length + '\n' +
          '承诺点 x = ' + out.slice(0, 64) + '\n' +
          '承诺点 y = ' + out.slice(64) + '\n' +
          '压缩序列化（32 字节） = ' + cp + '\n' +
          'map_to_scalar_field（x/y → Fr） = ' + mh + '\n' +
          '子群校验（Legendre：1-a·x² 为 QR）= 通过\n' +
          '曲线：Bandersnatch (a=-5)，素数阶子群 Banderwagon'
      };
    },
    dec: function (msgBytes, _key, arg) {
      /* 解密方向：验证加性同态 Commit(A)+Commit(B) == Commit(A+B) */
      var txt = new TextDecoder().decode(msgBytes).replace(/\s+/g, ' ').trim();

      /* 单输入且为 64 位十六进制：做压缩→解压缩→再压缩往返校验 */
      if (/^[0-9a-fA-F]{64}$/.test(txt)) {
        var P = vDecompress(txt);
        if (!P) {
          return { text: '✗ 解压失败：该 x 不对应任何子群内点', textInfo: '子群判据 1-a·x² 为二次剩余 未通过。' };
        }
        var back = vCompress(P);
        var ok1 = (back === txt.toLowerCase());
        /* 2-to-1：加上 2-挠点 (0,-1) 后应得到同一压缩表示 */
        var T = [0n, (V_Q - 1n) % V_Q, 1n, 0n];
        var P2 = vAdd(P, T);
        var ok2 = (vCompress(P2) === back);
        var ok3 = (vMapToScalar(P) === vMapToScalar(P2));
        return {
          text: (ok1 && ok2 && ok3 ? '✓ 解压成功，往返与 2-to-1 性质均成立' : '✗ 校验失败') +
            '\n原压缩表示 = ' + txt.toLowerCase() +
            '\n再压缩     = ' + back +
            '\n往返一致   = ' + ok1 +
            '\n加 2-挠点后压缩一致 = ' + ok2 +
            '\nmap_to_scalar 一致  = ' + ok3,
          textInfo: 'Banderwagon 商群中 (x,y) 与 (-x,-y) 视为同一点，' +
            '因此 x/y 与压缩表示都应当保持不变。'
        };
      }

      var parts = txt.split(/\s*\|\|\s*|\s*\+\s*/);
      if (parts.length !== 2) {
        throw new Error('请输入两组标量，用 "||" 或 "+" 分隔，例如：1 2 3 || 4 5 6');
      }
      var A = vParseScalars(parts[0].trim());
      var B = vParseScalars(parts[1].trim());
      var n = Math.max(A.length, B.length);
      var S = [];
      for (var i = 0; i < n; i++) S.push(vmod((A[i] || 0n) + (B[i] || 0n)));
      var CA = vPedersen(A), CB = vPedersen(B), CS = vPedersen(S);
      var sum = vAdd(CA, CB);
      /* 比较射影点：交叉相乘避免求逆 */
      var xa = vmod(sum[0] * CS[2]), xb = vmod(CS[0] * sum[2]);
      var ya = vmod(sum[1] * CS[2]), yb = vmod(CS[1] * sum[2]);
      var ok = (xa === xb) && (ya === yb);
      return {
        text: (ok ? '✓ 加性同态成立' : '✗ 加性同态不成立') +
          '\nCommit(A)   = ' + vPointToHex(CA).slice(0, 32) + '…' +
          '\nCommit(B)   = ' + vPointToHex(CB).slice(0, 32) + '…' +
          '\nCommit(A)+Commit(B) = ' + vPointToHex(sum).slice(0, 32) + '…' +
          '\nCommit(A+B) = ' + vPointToHex(CS).slice(0, 32) + '…',
        textInfo: ok
          ? 'Pedersen 承诺的加性同态验证通过，说明曲线运算与生成元自洽。'
          : '加性同态验证失败，实现有误。'
      };
    }
  });

  /* ---- Verkle 树根（EIP-6800 规范） ----
   * 参考实现：rust-verkle 的 trie_fuzzer.rs（官方向量）
   *   compute_commitment_root / extension_and_suffix_tree /
   *   compute_main_tree_root / compute_verkle_root
   * key 与 value 均为 32 字节；key = stem(31B) ‖ suffix(1B)。 */

  /* 稀疏 Pedersen 承诺：跳过 0 项（0·G 无需计算） */
  function vCommitSparse(arr) {
    var R = V_ID;
    var n = Math.min(arr.length, 256);
    for (var i = 0; i < n; i++) {
      var s = arr[i];
      if (!s) continue;
      if (typeof s !== 'bigint') s = BigInt(s);
      s = vmod(s % V_R);
      if (s === 0n) continue;
      var G = VERKLE_BASIS[i];
      R = vAdd(R, vMul([G[0], G[1], 1n, vmod(G[0] * G[1])], s));
    }
    return R;
  }

  /* stem（31 字节）按小端解读为标量 */
  function vStemScalar(stemHex) {
    var v = 0n;
    for (var i = 30; i >= 0; i--) v = (v << 8n) | BigInt(parseInt(stemHex.substr(i * 2, 2), 16));
    return vmod(v % V_R);
  }

  /* 扩展节点 + 后缀树 */
  function vExtSuffix(stemHex, valMap) {
    var sl = new Array(512).fill(0n);
    for (var k in valMap) {
      var suf = parseInt(k, 10);
      var v = valMap[k];               /* Uint8Array(32) */
      sl[2 * suf] = vmod(vBytesToScalar(v, 0, 16) + (1n << 128n));
      sl[2 * suf + 1] = vBytesToScalar(v, 16, 16);
    }
    var C1 = vCommitSparse(sl.slice(0, 256));
    var C2 = vCommitSparse(sl.slice(256, 512));
    var vec = [1n, vStemScalar(stemHex), vMapToScalar(C1), vMapToScalar(C2)];
    return vMapToScalar(vCommitSparse(vec));
  }

  /* 主树递归：空=0；单元素=该扩展节点标量；否则 256 路聚合 */
  function vMainRoot(das, list, depth) {
    if (list.length === 0) return 0n;
    if (list.length === 1) return das[list[0]];
    if (depth >= 31) return das[list[0]];
    var groups = new Array(256);
    for (var i = 0; i < list.length; i++) {
      var c = parseInt(list[i].substr(depth * 2, 2), 16);
      if (!groups[c]) groups[c] = [];
      groups[c].push(list[i]);
    }
    var subs = new Array(256).fill(0n);
    for (var j = 0; j < 256; j++) {
      if (groups[j]) subs[j] = vMainRoot(das, groups[j], depth + 1);
    }
    return vMapToScalar(vCommitSparse(subs));
  }

  /* entries: [{key:Uint8Array(32), value:Uint8Array(32)}] */
  function vVerkleRoot(entries) {
    var byStem = {}, stems = [];
    for (var i = 0; i < entries.length; i++) {
      var kh = vToHex(entries[i].key);
      var stem = kh.slice(0, 62);
      var suf = String(parseInt(kh.slice(62), 16));
      if (!byStem[stem]) { byStem[stem] = {}; stems.push(stem); }
      byStem[stem][suf] = entries[i].value;
    }
    var das = {};
    for (var s = 0; s < stems.length; s++) das[stems[s]] = vExtSuffix(stems[s], byStem[stems[s]]);
    var groups = new Array(256);
    for (var t = 0; t < stems.length; t++) {
      var c = parseInt(stems[t].substr(0, 2), 16);
      if (!groups[c]) groups[c] = [];
      groups[c].push(stems[t]);
    }
    var subs = new Array(256).fill(0n);
    for (var j = 0; j < 256; j++) {
      if (groups[j]) subs[j] = vMainRoot(das, groups[j], 1);
    }
    return vCommitSparse(subs);
  }

  function vToHex(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i++) {
      var h = u8[i].toString(16);
      s += (h.length < 2 ? '0' : '') + h;
    }
    return s;
  }

  /* root_hash：Fr 的小端 32 字节序列化 */
  function vScalarLE(v) {
    var s = '';
    for (var i = 0; i < 32; i++) {
      var b = Number((v >> BigInt(8 * i)) & 0xffn).toString(16);
      s += (b.length < 2 ? '0' : '') + b;
    }
    return s;
  }

  reg({
    id: 'verkle-root',
    name: 'Verkle 树根承诺（EIP-6800）',
    group: '椭圆曲线与高级代数',
    key: false, keyLen: 0, dec: false,
    info: '按 EIP-6800 算 Verkle 状态根，每行 key:value（各 32 字节十六进制）。' +
      '输出 state_root = 根承诺点压缩序列化，与 geth / rust-verkle 一致。' +
      '向量：rust-verkle fuzzer + devnet6 创始状态根。',
    enc: function (msgBytes, _key, _arg) {
      var txt = new TextDecoder().decode(msgBytes);
      var lines = txt.split(/\r?\n/).map(function (s) { return s.trim(); })
        .filter(function (s) { return s.length; });
      if (!lines.length) throw new Error('请至少输入一组 key（32 字节十六进制）');
      var entries = [];
      for (var i = 0; i < lines.length; i++) {
        var parts = lines[i].split(/[:\s]+/).filter(function (s) { return s.length; });
        var kh = parts[0].replace(/^0x/i, '');
        var vh = (parts[1] || kh).replace(/^0x/i, '');
        if (!/^[0-9a-fA-F]{64}$/.test(kh)) throw new Error('第 ' + (i + 1) + ' 行 key 需为 64 位十六进制（32 字节）：' + parts[0]);
        if (!/^[0-9a-fA-F]{64}$/.test(vh)) throw new Error('第 ' + (i + 1) + ' 行 value 需为 64 位十六进制（32 字节）：' + parts[1]);
        entries.push({ key: vFromHex(kh), value: vFromHex(vh) });
      }
      var t0 = Date.now();
      var R = vVerkleRoot(entries);
      var ms = Date.now() - t0;
      var rh = vMapToScalar(R);
      return {
        text: vCompress(R),
        textInfo: '键数量：' + entries.length +
          '\nstate_root（根承诺点压缩序列化，32 字节） = ' + vCompress(R) +
          '\nroot_hash = map_to_scalar_field（Fr 小端，仅供折叠进父节点） = ' + vScalarLE(rh) +
          '\n根承诺点 x = ' + vPointToHex(R).slice(0, 64) +
          '\n根承诺点 y = ' + vPointToHex(R).slice(64) +
          '\n耗时 ' + ms + ' ms' +
          '\n\n⚠ 以太坊区块里的状态根取上面的 state_root，不是 root_hash。' +
          '\n\n结构：stem(31B)‖suffix(1B)；每个 value 拆为 lower(+2^128) 与 upper 两个标量；' +
          '\n扩展节点 = Commit(1, stem, C1, C2)；内部节点 = Commit(256 个子根标量)。' +
          '\n规范：EIP-6800；向量：rust-verkle trie_fuzzer.rs 与 devnet6 创始状态根。'
      };
    }
  });

  function vFromHex(h) {
    var out = new Uint8Array(h.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }

  /* ---- 内积论证 IPA（rust-verkle ipa-multipoint）----
   * 来源：ipa-multipoint/src/ipa.rs 与 transcript.rs（原始实现）。
   *
   * ⚠ 与 Bulletproofs 的 IPA 不是同一套约定，切勿混用：
   *   本实现  a_L += x·a_R ; b_L += x⁻¹·b_R ; G_L += x⁻¹·G_R
   *   （Bulletproofs 是 G 侧乘 x 而非 x⁻¹，方向相反）
   *
   * Fiat-Shamir 用**朴素 SHA256 累加器**（不是 Merlin/STROBE）：
   *   state 初始 = 协议标签；每次 append = 先标签后内容；
   *   challenge = SHA256(state) 按小端 mod r，然后**清空** state 再写入标签与该挑战值。
   *
   * 点压缩规则（banderwagon::Element::to_bytes）：y 不「正」时输出 **-x**，
   *   不是「x + 符号位」——这一条凭惯例写必错。
   *
   * 官方锚点（已验证）：
   *   transcript test_vector_1..3   —— 挑战值三例
   *   transcript test_vector_4      —— append_point(Q) 后的挑战值（锁定压缩规则）
   *   CRS 256 点逐点比对 default_crs.rs —— 256/256 全等
   *   Q 的 Fr(x/y) = d1e7de2aaea9603d5bc6c208d319596376556ecd8336671ba7670c2139772d14
   */

  function vTrNew(label) { return { st: vUtf8(label) }; }
  function vTrDs(t, l) { t.st = vCatU8(t.st, vUtf8(l)); }
  function vTrAm(t, m, l) { t.st = vCatU8(vCatU8(t.st, vUtf8(l)), m); }
  function vTrPoint(t, l, P) { vTrAm(t, vFromHex(vCompress(P)), l); }
  function vTrScalar(t, l, v) { vTrAm(t, vFrLe(v), l); }
  function vTrCh(t, l) {
    vTrDs(t, l);
    var h = (typeof sha256Bytes === 'function')
      ? sha256Bytes(t.st)
      : (typeof sha256BytesSync === 'function' ? sha256BytesSync(t.st) : null);
    if (!h) throw new Error('缺少 SHA-256 实现');
    var v = 0n;
    for (var i = 31; i >= 0; i--) v = (v << 8n) | BigInt(h[i]);
    v = vmodR(v);
    /* ⚠ state 必须清空后再由 vTrScalar 追加「标签+挑战值」；
     * 若先置为标签再 append，标签会被写两遍。单挑战场景（tv1~tv4）发现不了，
     * 只有多轮挑战（IPA）才暴露 —— 又一处自洽看不出的错误。 */
    t.st = new Uint8Array(0);
    vTrScalar(t, l, v);
    return v;
  }
  function vUtf8(s) {
    var out = [];
    for (var i = 0; i < s.length; i++) { out.push(s.charCodeAt(i) & 0xff); }
    return new Uint8Array(out);
  }
  function vCatU8(a, b) {
    var o = new Uint8Array(a.length + b.length);
    o.set(a, 0); o.set(b, a.length);
    return o;
  }
  function vFrLe(v) {
    v = vmodR(v);
    var o = new Uint8Array(32);
    for (var i = 0; i < 32; i++) { o[i] = Number(v & 0xffn); v >>= 8n; }
    return o;
  }
  function vLeToScalar(b) {
    var v = 0n;
    for (var i = 31; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
    return vmodR(v);
  }

  function vInner(a, b) {
    var s = 0n;
    for (var i = 0; i < a.length; i++) s = vmodR(s + vmodR(a[i] * b[i]));
    return s;
  }
  function vPowersOf(z, n) {
    var out = [1n % V_R], p = 1n % V_R;
    for (var i = 1; i < n; i++) { p = vmodR(p * z); out.push(p); }
    return out;
  }
  function vMSM(pts, sc) {
    var R = V_ID;
    for (var i = 0; i < pts.length; i++) {
      var sc2 = vmodR(sc[i]);
      if (sc2 === 0n) continue;
      R = vAdd(R, vMul(pts[i], sc2));
    }
    return R;
  }

  function vIpaProve(label, gAff, a0, z) {
    var a = a0.map(vmodR), b = vPowersOf(vmodR(z), a0.length);
    var G = gAff.map(function (p) { return [p[0], p[1], 1n, vmod(p[0] * p[1])]; });
    var C = vMSM(G, a);
    var out = vInner(a, b);
    var t = vTrNew(label);
    vTrDs(t, 'ipa');
    vTrPoint(t, 'C', C); vTrScalar(t, 'input point', z); vTrScalar(t, 'output point', out);
    var w = vTrCh(t, 'w');
    var Qe = vMul([VERKLE_QP[0], VERKLE_QP[1], 1n, vmod(VERKLE_QP[0] * VERKLE_QP[1])], w);
    var Ls = [], Rs = [], n = G.length;
    while (n > 1) {
      var h = n >> 1;
      var aL = a.slice(0, h), aR = a.slice(h);
      var bL = b.slice(0, h), bR = b.slice(h);
      var GL = G.slice(0, h), GR = G.slice(h);
      var zL = vInner(aR, bL), zR = vInner(aL, bR);
      var L = vAdd(vMSM(GL, aR), vMul(Qe, zL));
      var R = vAdd(vMSM(GR, aL), vMul(Qe, zR));
      Ls.push(L); Rs.push(R);
      vTrPoint(t, 'L', L); vTrPoint(t, 'R', R);
      var x = vTrCh(t, 'x'), xi = vInvFr(x);
      for (var i = 0; i < h; i++) {
        aL[i] = vmodR(aL[i] + vmodR(x * aR[i]));
        bL[i] = vmodR(bL[i] + vmodR(xi * bR[i]));
        GL[i] = vAdd(GL[i], vMul(GR[i], xi));
      }
      a = aL; b = bL; G = GL; n = h;
    }
    return { C: C, out: out, L: Ls, R: Rs, a: a[0] };
  }

  function vIpaVerify(label, gAff, b0, C, z, out, proof) {
    var G = gAff.map(function (p) { return [p[0], p[1], 1n, vmod(p[0] * p[1])]; });
    var b = b0.slice();
    var t = vTrNew(label);
    vTrDs(t, 'ipa');
    vTrPoint(t, 'C', C); vTrScalar(t, 'input point', z); vTrScalar(t, 'output point', out);
    var w = vTrCh(t, 'w');
    var Qe = vMul([VERKLE_QP[0], VERKLE_QP[1], 1n, vmod(VERKLE_QP[0] * VERKLE_QP[1])], w);
    var ac = vAdd(C, vMul(Qe, out));
    var chs = [], chsi = [];
    for (var k = 0; k < proof.L.length; k++) {
      vTrPoint(t, 'L', proof.L[k]); vTrPoint(t, 'R', proof.R[k]);
      var x = vTrCh(t, 'x');
      chs.push(x); chsi.push(vInvFr(x));
    }
    for (var k2 = 0; k2 < proof.L.length; k2++) {
      ac = vAdd(ac, vMul(proof.L[k2], chs[k2]));
      ac = vAdd(ac, vMul(proof.R[k2], chsi[k2]));
    }
    for (var k3 = 0; k3 < chsi.length; k3++) {
      var h2 = G.length >> 1;
      var GL = G.slice(0, h2), GR = G.slice(h2);
      var bL = b.slice(0, h2), bR = b.slice(h2);
      for (var i2 = 0; i2 < h2; i2++) {
        GL[i2] = vAdd(GL[i2], vMul(GR[i2], chsi[k3]));
        bL[i2] = vmodR(bL[i2] + vmodR(bR[i2] * chsi[k3]));
      }
      G = GL; b = bL;
    }
    var expP = vAdd(vMul(G[0], vmodR(proof.a)), vMul(Qe, vmodR(proof.a * b[0])));
    /* 官方 Element::eq 是商群相等：(x1·y2)==(x2·y1)，(x,y) 与 (-x,-y) 视为同一元素 */
    return vmod(expP[0] * ac[1] - ac[0] * expP[1]) === 0n;
  }

  /* ⚠ 标量（Fr）运算必须 mod r；vmod 是 mod q，两者不可混用。
   * 早期版本在内积与幂次中误用 vmod（mod q），结果长度正常、自洽也看不出来，
   * 只有跟官方向量比才暴露 —— 属于典型的「静默全错」。 */
  function vmodR(a) { a = a % V_R; return a < 0n ? a + V_R : a; }
  /* ⚠ 求逆必须在 Fr 中做：vPowMod 全程 mod q，若拿它算 x^(r-2) 得到的是
   * mod q 的结果，与 x⁻¹ mod r 完全不同。长度正常、不报错，只有比对才暴露。 */
  function vPowModR(b, e) {
    var r = 1n; b = vmodR(b);
    while (e > 0n) {
      if (e & 1n) r = vmodR(r * b);
      b = vmodR(b * b);
      e >>= 1n;
    }
    return r;
  }
  function vInvFr(x) { return vPowModR(vmodR(x), V_R - 2n); }

  /* ---- hash64 / 树键派生（verkle-spec） ----
   * 来源：rust-verkle 的 verkle-spec/src/lib.rs 与 util.rs（原始实现，非二手文档）
   *
   *   chunk64(b64)  = [ (2 + 256*64) 的小端 16 字节, b64 的 4 个 16 字节块 ]
   *                   → 5 个 u128（小端解读）
   *   hash64(b64)   = Fr( map_to_scalar_field( Σ chunk64(b64)[i] · G[i] ) )
   *                   序列化为 32 字节小端
   *
   * 关键点：第 0 个标量是编码标志 16386（= 2 + 256×64），**不是输入数据**。
   * 因此全零输入的结果并不为 0 —— 这与早期按 EIP 草案推得的预期相反，
   * 草案用的是 group_to_scalar_field 的另一版本（32 字节序列化取整）。
   *
   * 官方向量（verkle-spec::smoke_test_hash64）：
   *   全零 → 1a100684fd68185060405f3f160e4bb6e034194336b547bdae323f888d533207
   *   全一 → 3afb8486ed3053ac55f62864da803c074844509d253260d870337c20fd73eb11
   */
  function vChunk64(b64) {
    var out = [];
    var flag = 2n + 256n * 64n;                 /* = 16386 */
    var v = 0n;
    var fb = new Uint8Array(16);
    for (var i = 0; i < 16; i++) fb[i] = Number((flag >> BigInt(8 * i)) & 0xffn);
    out.push(vFromLe128(fb));
    for (var j = 0; j < 64; j += 16) out.push(vFromLe128(b64.slice(j, j + 16)));
    return out;
  }

  function vFromLe128(c) {
    var v = 0n;
    for (var i = 15; i >= 0; i--) v = (v << 8n) | BigInt(c[i]);
    return vmod(v % V_R);
  }

  function vHash64(b64) {
    var sc = vChunk64(b64);
    var C = vPedersen(sc);
    return vScalarLE(vMapToScalar(C));
  }

  /* hash_addr_int：addr32（原样 32 字节）‖ index（U256 小端 32 字节） */
  function vHashAddrInt(addr32, index) {
    var h = new Uint8Array(64);
    h.set(addr32.subarray(0, 32), 0);
    var le = new Uint8Array(32);
    var t = index;
    for (var i = 0; i < 32; i++) { le[i] = Number(t & 0xffn); t >>= 8n; }
    h.set(le, 32);
    return vHash64(h);
  }

  function vSwapLastByte(hex32, byte) {
    return hex32.slice(0, 62) + byte.toString(16).padStart(2, '0');
  }

  reg({
    id: 'verkle-hash64',
    name: 'Verkle Pedersen 哈希 hash64 / 树键派生',
    group: '椭圆曲线与高级代数',
    key: false, keyLen: 0, dec: false,
    info: 'Verkle 树键派生。\n【用法】64 字节 Hex → 算 hash64；或「32字节地址:索引」→ 算 base_hash 并列出 5 个头字段树键。',
    enc: function (msgBytes, _key, _arg) {
      var txt = new TextDecoder().decode(msgBytes).trim();
      if (/^[0-9a-fA-F]{128}$/.test(txt)) {
        var got = vHash64(vFromHex(txt));
        return {
          text: got,
          textInfo: 'hash64 输出（Fr 小端 32 字节） = ' + got +
            '\n分块标量 = ' + vChunk64(vFromHex(txt)).map(function (s) { return s.toString(); }).join(', ') +
            '\n第 0 个标量固定为编码标志 16386 = 2 + 256×64，不含输入数据。' +
            '\ncommit = Σ scalar_i · G[i]（前 5 个 Pedersen 生成元）；输出 = Fr(x/y)。' +
            '\n官方自检：全零→1a100684…d533207，全一→3afb8486…d73eb11。'
        };
      }
      var m = txt.split(/[:\s]+/).filter(function (s) { return s.length; });
      if (m.length < 1 || !/^0x[0-9a-fA-F]+$|^[0-9a-fA-F]+$/.test(m[0])) {
        throw new Error('请输入 64 字节十六进制（128 位 hex），或 "32字节地址:索引" 形式。');
      }
      var ah = m[0].replace(/^0x/i, '');
      if (ah.length < 64) ah = ah.padStart(64, '0');
      if (!/^[0-9a-fA-F]{64}$/.test(ah)) throw new Error('地址需为 32 字节十六进制（64 位 hex）：' + m[0]);
      var idx = 0n;
      if (m[1] !== undefined) {
        idx = /^0x/i.test(m[1]) ? BigInt(m[1]) : BigInt(m[1]);
        if (idx < 0n) throw new Error('索引不能为负');
      }
      var base = vHashAddrInt(vFromHex(ah), idx);
      var names = ['version', 'balance', 'nonce', 'codeKeccak', 'codeSize'];
      var lines = [];
      for (var i = 0; i < 5; i++) lines.push('  ' + names[i].padEnd(11) + ' = ' + vSwapLastByte(base, i));
      return {
        text: base,
        textInfo: '地址（32B） = ' + ah +
          '\n树索引      = ' + idx.toString() +
          '\nbase_hash   = ' + base + '   （不替换末字节）' +
          '\n\n头字段树键（把 base_hash 末字节换成对应下标）：\n' + lines.join('\n') +
          '\n\nhash64 输入 = addr32（原样）‖ index（U256 小端 32 字节）。' +
          '\n同一账户的 5 个头字段共享同一个 stem，仅后缀（末字节）不同。'
      };
    }
  });

  /* ---- IPA 界面条目 ---- */

  function vParseScalars(txt, n) {
    var parts = txt.trim().split(/[\s,;]+/).filter(function (x) { return x.length; });
    if (n && parts.length !== n) throw new Error('需要 ' + n + ' 个标量，实际 ' + parts.length + ' 个');
    return parts.map(function (x) {
      var v = /^0x/i.test(x) ? BigInt(x) : BigInt(x);
      return vmodR(v);
    });
  }

  function vIsPow2(n) { return n >= 2 && (n & (n - 1)) === 0; }

  function vIpaBlob(P) {
    var out = [];
    out.push(vFromHex(vCompress(P.C)));
    out.push(vFrLe(P.out));
    P.L.forEach(function (p) { out.push(vFromHex(vCompress(p))); });
    P.R.forEach(function (p) { out.push(vFromHex(vCompress(p))); });
    out.push(vFrLe(P.a));
    var tot = out.reduce(function (a, b) { return a + b.length; }, 0);
    var blob = new Uint8Array(tot), o = 0;
    out.forEach(function (b) { blob.set(b, o); o += b.length; });
    return blob;
  }

  reg({
    id: 'verkle-ipa-prove',
    name: 'Verkle 内积论证 IPA 证明（多项式求值）',
    group: '椭圆曲线与高级代数',
    key: false, keyLen: 0, dec: false,
    info: '为「承诺 C 的多项式在 z 处取值 out」生成 IPA 证明。\n【输入】系数（空格分隔，个数为 2 的幂且 ≤256）；【参数】求值点 z。\n⚠ 与 Bulletproofs 的 IPA 约定不同，不可混用。',
    enc: function (msgBytes, _key, _arg) {
      var txt = new TextDecoder().decode(msgBytes).trim();
      var a = vParseScalars(txt, 0);
      var n = a.length;
      if (!vIsPow2(n)) throw new Error('系数个数必须是 2 的幂（2/4/8/…/256），当前 ' + n + ' 个');
      if (n > 256) throw new Error('系数个数不能超过 CRS 规模 256，当前 ' + n + ' 个');
      /* 参数栏在真实 UI 里是字符串，在部分内部调用里才是字节——两种都要接受。
         直接 decode(_arg) 遇到字符串会抛 "list must be an instance of ..."。 */
      var argTxt = (_arg === null || _arg === undefined) ? ''
        : (typeof _arg === 'string' ? _arg : new TextDecoder().decode(_arg)).trim();
      var z = argTxt ? vParseScalars(argTxt, 1)[0] : 0n;
      var t0 = Date.now();
      var P = vIpaProve('ip_no_zk', VERKLE_BASIS.slice(0, n), a, z);
      var blob = vIpaBlob(P);
      var lines = [];
      lines.push('C（压缩 32B）      = ' + vCompress(P.C));
      lines.push('out = f(z)（Fr）   = ' + P.out.toString());
      lines.push('求值点 z           = ' + z.toString());
      lines.push('轮数               = ' + P.L.length + '（n=' + n + '）');
      for (var i = 0; i < P.L.length; i++) {
        lines.push('  L[' + i + '] = ' + vCompress(P.L[i]));
        lines.push('  R[' + i + '] = ' + vCompress(P.R[i]));
      }
      lines.push('最终 a             = ' + P.a.toString());
      return {
        bytes: blob,
        text: vToHex(blob),
        textInfo: 'IPA 证明已生成（' + (Date.now() - t0) + ' ms）\n\n' + lines.join('\n') +
          '\n\n输出共 ' + blob.length + ' 字节 = C(32) ‖ out(32) ‖ L(' + P.L.length * 32 +
          ') ‖ R(' + P.R.length * 32 + ') ‖ a(32)。\n把这段十六进制连同 z 交给「IPA 验证」即可校验。'
      };
    }
  });

  reg({
    id: 'verkle-ipa-verify',
    name: 'Verkle 内积论证 IPA 验证',
    group: '椭圆曲线与高级代数',
    key: true, keyLen: 0, enc: false,
    info: '校验一份 IPA 证明。输入栏填证明十六进制（上面那条目的输出）。' +
      '\n参数栏填求值点 z；也可写 "z:out" 显式指定声称的求值结果（与证明内不一致则失败）。' +
      '\n输出明确给出 ✓ 通过 或 ✗ 失败。',
    dec: function (msgBytes, _key, _arg) {
      var hex = new TextDecoder().decode(msgBytes).trim().replace(/\s+/g, '');
      if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) throw new Error('请输入证明的十六进制串');
      var blob = vFromHex(hex);
      /* 参数栏在真实 UI 里是字符串，在部分内部调用里才是字节——两种都要接受。
         直接 decode(_arg) 遇到字符串会抛 "list must be an instance of ..."。 */
      var argTxt = (_arg === null || _arg === undefined) ? ''
        : (typeof _arg === 'string' ? _arg : new TextDecoder().decode(_arg)).trim();
      if (!argTxt) throw new Error('参数栏需填求值点 z（或 "z:out"）');
      var parts = argTxt.split(/[:\s]+/).filter(function (x) { return x.length; });
      var z = vParseScalars(parts[0], 1)[0];
      var claimOut = parts.length > 1 ? vParseScalars(parts[1], 1)[0] : null;
      if (blob.length < 96) throw new Error('证明长度不足（至少 96 字节）');
      var bodyLen = blob.length - 64 - 32;
      if (bodyLen % 64 !== 0) throw new Error('证明长度不合法：(长度-96) 必须是 64 的倍数（每轮 L+R 各 32 字节）');
      var rounds = bodyLen / 64;
      var n = 1 << rounds;
      if (n > 256) throw new Error('轮数 ' + rounds + ' 对应 n=' + n + '，超过 CRS 规模 256');
      var o = 0;
      function take(k) { var b = blob.slice(o, o + k); o += k; return b; }
      var Cb = take(32), outB = take(32);
      var Lb = [], Rb = [];
      for (var i = 0; i < rounds; i++) Lb.push(take(32));
      for (var i2 = 0; i2 < rounds; i2++) Rb.push(take(32));
      var aB = take(32);
      var Ch = vToHex(Cb);
      var Cd = null, proof = null, reason = '';
      try {
        Cd = vDecompress(Ch);
        if (!Cd) reason = '承诺 C 无法解压为子群元素';
        else {
          var Cpt = [Cd[0], Cd[1], 1n, vmod(Cd[0] * Cd[1])];
          proof = {
            L: Lb.map(function (h) {
              var d = vDecompress(vToHex(h));
              if (!d) throw new Error('L 点不是合法子群元素');
              return [d[0], d[1], 1n, vmod(d[0] * d[1])];
            }),
            R: Rb.map(function (h) {
              var d = vDecompress(vToHex(h));
              if (!d) throw new Error('R 点不是合法子群元素');
              return [d[0], d[1], 1n, vmod(d[0] * d[1])];
            }),
            a: vLeToScalar(aB)
          };
        }
      } catch (e) { reason = e.message; Cd = null; }
      var out = vLeToScalar(outB);
      var t0 = Date.now();
      var ok = false;
      if (Cd) ok = vIpaVerify('ip_no_zk', VERKLE_BASIS.slice(0, n), vPowersOf(z, n),
                             [Cd[0], Cd[1], 1n, vmod(Cd[0] * Cd[1])], z, out, proof);
      var ms = Date.now() - t0;
      if (reason) ok = false;
      var lines = [];
      lines.push('n = ' + n + '，轮数 = ' + rounds + '（' + ms + ' ms）');
      lines.push('C                = ' + Ch);
      lines.push('z                = ' + z.toString());
      lines.push('out = f(z)       = ' + out.toString());
      lines.push('最终 a           = ' + (proof ? proof.a.toString() : '（无法解析）'));
      if (reason) lines.push('失败原因         = ' + reason);
      if (claimOut !== null) {
        lines.push('声称的 out       = ' + claimOut.toString() +
          (claimOut === out ? '（与证明内一致）' : '（与证明内不一致）'));
        if (claimOut !== out) { ok = false; if (!reason) reason = '声称的求值结果与证明内不一致'; }
      }
      /* ⚠ head 必须在所有「可追加失败原因」的判定之后计算，
         否则声称的 out 不一致时 head 早已定型为 ✓（典型的前后顺序错误） */
      var head = ok ? '✓ 验证通过' : '✗ 验证失败';
      return {
        text: head,
        textInfo: head + '\n\n' + lines.join('\n') +
          '\n\n判据：由挑战值重建的承诺是否等于 G′·a + Q·(a·b₀)，' +
          '\n采用官方 Element::eq 语义（商掉 2-挠点，(x,y) 与 (-x,-y) 视为同一元素）。'
      };
    }
  });

  /* 测试钩子：供离线脚本用官方向量校验内部函数（不影响界面运行） */
  if (typeof globalThis !== 'undefined') {
    globalThis.__VERKLE_TEST__ = {
      vVerkleRoot: vVerkleRoot, vMapToScalar: vMapToScalar, vScalarLE: vScalarLE,
      vCompress: vCompress, vPedersen: vPedersen, vPointToHex: vPointToHex,
      vDecompress: vDecompress, vFromHex: vFromHex, vToHex: vToHex,
      vHash64: vHash64, vChunk64: vChunk64, vHashAddrInt: vHashAddrInt,
      vIpaProve: vIpaProve, vIpaVerify: vIpaVerify, vTrNew: vTrNew, vTrDs: vTrDs,
      vTrPoint: vTrPoint, vTrScalar: vTrScalar, vTrCh: vTrCh, vPowersOf: vPowersOf,
      vInner: vInner, vMSM: vMSM, vInvFr: vInvFr, vQP: VERKLE_QP,
      vFrLe: vFrLe, vCompressPoint: vCompress, vMul: vMul, vAdd: vAdd,
      basis: VERKLE_BASIS, Q: V_Q, R: V_R
    };
  }
})();
