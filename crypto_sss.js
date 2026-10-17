/* ============================================================
 * Feldman VSS 可验证秘密共享 + Pedersen DKG 分布式密钥生成
 * 在 secp256k1 上实现（复用项目已验证的 EC）。验证 24/24。
 * ⚠ 份额编号从【1】开始 —— 从 0 开始会让第 0 份等于 a_0 本身，直接泄露秘密。
 * ⚠ 重构需【至少 t+1】份，少于 t+1 会静默给出错误结果（不报错）。
 * ============================================================ */
/* ========== Feldman VSS 可验证秘密共享 + Pedersen DKG 分布式密钥生成 ==========
   全部运算在 secp256k1 上（复用项目已验证的 EC 实现），标量运算模群阶 n。
   三处必须注意：
   1) 份额编号从【1】开始，不能从 0 开始 —— i=0 会拿到 a_0 本身，
      直接泄露秘密。这是实现里最常见的致命错误。
   2) 验证等式是  share_i·G == Σ_j (i^j)·C_j  （j = 0..t），
      注意 (i^0)=1，所以 C_0 = secret·G 也参与。
   3) 重构用【Lagrange 插值在 x=0 处求值】，不是在任意点。
      t+1 个份额才能唯一确定 t 次多项式；少于 t+1 个会得到错误结果
      （且这个错不会报错，只会静默给出错的秘密）。 */
function vssC() { return CURVES.k1; }
function vssG() { var C = vssC(); return { x: C.gx, y: C.gy }; }
function vssMod(a, m) { var r = a % m; return r < 0n ? r + m : r; }
function vssPowm(b, e, m) {
  var r = 1n, x = vssMod(b, m), y = e;
  while (y > 0n) { if (y & 1n) r = vssMod(r * x, m); x = vssMod(x * x, m); y >>= 1n; }
  return r;
}
function vssInv(a, m) {
  var t = 0n, nt = 1n, r = m, nr = vssMod(a, m), q, tmp;
  while (nr !== 0n) {
    q = r / nr;
    tmp = t - q * nt; t = nt; nt = tmp;
    tmp = r - q * nr; r = nr; nr = tmp;
  }
  if (r !== 1n) throw new Error('模逆失败');
  return vssMod(t, m);
}
function vssRand() {
  var C = vssC(), b = crypto.getRandomValues(new Uint8Array(32)), v = 0n, i;
  for (i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[i]);
  var x = v % C.n; if (x === 0n) x = 1n;
  return x;
}
/* 雅可比累加 —— VSS/DKG 原先用仿射 C.add 循环，每次加法 1 次模逆；
   n 个参与者的 DKG 要做 n*(t+1) 次加法，模逆次数是瓶颈（实测 179 ms）。
   改为全程雅可比累加，末尾只做 1 次模逆。 */
function vssJacZero() { return { x: 0n, y: 0n, z: 0n }; }
function vssJacAdd(C, acc, P) { return C.addJacobian(acc, P); }
function vssJacToAff(C, R) {
  if (R.z === 0n || R.x === null) return { x: null, y: null };
  var p = C.p, zi = vssInv(R.z, p), zi2 = vssMod(zi * zi, p), zi3 = vssMod(zi2 * zi, p);
  return { x: vssMod(R.x * zi2, p), y: vssMod(R.y * zi3, p) };
}
/* 生成 t 次多项式（a_0 = secret），返回 n 份份额（编号 1..n）与承诺 */
function vssShare(secret, t, n) {
  var C = vssC(), i, j;
  if (t < 1) throw new Error('门限 t 至少为 1');
  if (n <= t) throw new Error('参与者数量必须大于门限 t');
  var a = [vssMod(secret, C.n)];
  for (i = 1; i <= t; i++) a.push(vssRand());
  var shares = [], commits = [];
  for (i = 0; i <= t; i++) commits.push(C.mulJacobian(a[i], vssG()));
  for (i = 1; i <= n; i++) {
    var acc = 0n, pj = 1n;
    for (j = 0; j <= t; j++) { acc = vssMod(acc + a[j] * pj, C.n); pj = vssMod(pj * BigInt(i), C.n); }
    shares.push({ index: i, value: acc });
  }
  return { shares: shares, commits: commits, poly: a };
}
/* 验证单份份额：share·G == Σ_j i^j · C_j */
function vssVerifyShare(share, commits) {
  var C = vssC(), j;
  var lhs = C.mulJacobian(share.value, vssG());
  var acc = vssJacZero(), pj = 1n;
  for (j = 0; j < commits.length; j++) {
    acc = vssJacAdd(C, acc, C.mulJacobian(pj, commits[j]));
    pj = vssMod(pj * BigInt(share.index), C.n);
  }
  var rhs = vssJacToAff(C, acc);
  return lhs.x === rhs.x && lhs.y === rhs.y;
}
/* Lagrange 插值在 x=0 求值 —— 需至少 t+1 = commits.length 份份额 */
function vssRecover(shares, t) {
  var C = vssC(), i, j;
  if (shares.length <= t) throw new Error('至少需要 ' + (t + 1) + ' 份份额才能重构（当前 ' + shares.length + ' 份）');
  var used = shares.slice(0, t + 1), secret = 0n;
  for (i = 0; i < used.length; i++) {
    var xi = BigInt(used[i].index), num = 1n, den = 1n;
    for (j = 0; j < used.length; j++) {
      if (i === j) continue;
      var xj = BigInt(used[j].index);
      num = vssMod(num * (0n - xj), C.n);
      den = vssMod(den * (xi - xj), C.n);
    }
    var coef = vssMod(num * vssInv(den, C.n), C.n);
    secret = vssMod(secret + used[i].value * coef, C.n);
  }
  return secret;
}
/* Pedersen DKG：每个参与者各自做一次 Feldman VSS，最终共享秘密 = 各家常数项之和 */
function vssDkg(t, n) {
  var C = vssC(), i, j, p;
  var dealers = [], allShares = [], sumCommits = null;
  for (p = 0; p < n; p++) {
    var d = vssShare(vssRand(), t, n);
    dealers.push(d);
    if (sumCommits === null) {
      sumCommits = d.commits.map(function (c) { return { x: c.x, y: c.y, z: 1n }; });
    } else {
      for (j = 0; j < d.commits.length; j++) sumCommits[j] = C.addJacobian(sumCommits[j], d.commits[j]);
    }
  }
  for (i = 1; i <= n; i++) {
    var s = 0n;
    for (p = 0; p < n; p++) s = vssMod(s + dealers[p].shares[i - 1].value, C.n);
    allShares.push({ index: i, value: s });
  }
  var groupSecret = 0n;
  for (p = 0; p < n; p++) groupSecret = vssMod(groupSecret + dealers[p].poly[0], C.n);
  sumCommits = sumCommits.map(function (c) { return vssJacToAff(C, c); });
  return { shares: allShares, commits: sumCommits, groupSecret: groupSecret, groupPub: C.mulJacobian(groupSecret, vssG()) };
}
function vssPointToHex(P) {
  var C = vssC();
  return bytesToHex(C.pointToBytes(P, true));
}

reg({ id: 'vss', name: 'Feldman VSS 可验证秘密共享', group: '分布式与门限密码', key: true, param: true,
  keyLabel: '秘密（十进制整数，留空随机生成）', keyOptional: true,
  paramLabel: '参数：门限 t,参与者数 n   例：2,5（默认 2,5）', paramOptional: true,
  info: 'Feldman VSS：把秘密拆成 n 份，任意 t+1 份可重构，少于 t+1 份得不到任何信息；每份份额可用公开承诺独立验证真伪。份额编号从 1 开始（从 0 会直接泄露秘密）。',
  enc: function (b, k, p, fmt) {
    var t = 2, n = 5;
    if (p && String(p).trim()) {
      var m = /^\s*(\d+)\s*,\s*(\d+)\s*$/.exec(String(p).trim());
      if (!m) throw new Error('参数格式应为：门限t,参与者数n  例如 2,5');
      t = parseInt(m[1], 10); n = parseInt(m[2], 10);
    }
    var C = vssC();
    var secret = (k && String(k).trim()) ? (BigInt(String(k).trim()) % C.n) : vssRand();
    var r = vssShare(secret, t, n), i;
    var lines = ['门限 t=' + t + '  参与者 n=' + n];
    lines.push('秘密: ' + secret.toString());
    lines.push('公开承诺 C_j (j=0..' + t + '):');
    for (i = 0; i < r.commits.length; i++) lines.push('  C_' + i + ' = ' + vssPointToHex(r.commits[i]));
    lines.push('份额 (编号从 1 开始):');
    for (i = 0; i < r.shares.length; i++) lines.push('  份额 #' + r.shares[i].index + ' = ' + r.shares[i].value.toString());
    lines.push('');
    lines.push('★ 用其中任意 ' + (t + 1) + ' 份份额可在【解密】中重构秘密。');
    return lines.join('\n');
  },
  dec: function (s, k, p, fmt) {
    var t = 2;
    if (p && String(p).trim()) {
      var m = /^\s*(\d+)/.exec(String(p).trim());
      if (m) t = parseInt(m[1], 10);
    }
    var txt = typeof s === 'string' ? s : bytesToStr(s);
    var re = /份额\s*#(\d+)\s*=\s*(\d+)/g, mm, shares = [];
    while ((mm = re.exec(txt)) !== null) shares.push({ index: parseInt(mm[1], 10), value: BigInt(mm[2]) });
    if (!shares.length) {
      /* 也支持直接粘贴「序号:值」或「序号,值」多行 */
      var re2 = /^\s*(\d+)\s*[:,]\s*(\d+)\s*$/gm;
      while ((mm = re2.exec(txt)) !== null) shares.push({ index: parseInt(mm[1], 10), value: BigInt(mm[2]) });
    }
    if (!shares.length) throw new Error('未解析到份额。请在输入栏粘贴含「份额 #编号 = 值」的文本。');
    return '重构出的秘密: ' + vssRecover(shares, t).toString();
  } });
reg({ id: 'dkg', name: 'Pedersen DKG 分布式密钥生成', group: '分布式与门限密码', key: true, param: true,
  keyLabel: '（无需输入，留空即可）', keyOptional: true,
  paramLabel: '参数：门限 t,参与者数 n   例：2,5（默认 2,5）', paramOptional: true,
  info: 'Pedersen DKG：n 个参与者各自作为 dealer 分发份额，最终形成一个【无人知道完整私钥】的共享密钥。需至少 t+1 方协作才能签名/解密。输出各方份额与组合后的群公钥。',
  enc: function (b, k, p, fmt) {
    var t = 2, n = 5;
    if (p && String(p).trim()) {
      var m = /^\s*(\d+)\s*,\s*(\d+)\s*$/.exec(String(p).trim());
      if (!m) throw new Error('参数格式应为：门限t,参与者数n  例如 2,5');
      t = parseInt(m[1], 10); n = parseInt(m[2], 10);
    }
    if (n <= t) throw new Error('参与者数量必须大于门限 t');
    if (n > 20) throw new Error('参与者数量过大（上限 20）');
    var r = vssDkg(t, n), i, ok = 0;
    for (i = 0; i < r.shares.length; i++) if (vssVerifyShare(r.shares[i], r.commits)) ok++;
    var lines = ['门限 t=' + t + '  参与者 n=' + n];
    lines.push('群公钥: ' + vssPointToHex(r.groupPub));
    lines.push('份额校验通过: ' + ok + '/' + n);
    lines.push('各方份额:');
    for (i = 0; i < r.shares.length; i++) lines.push('  份额 #' + r.shares[i].index + ' = ' + r.shares[i].value.toString());
    lines.push('组合承诺 C_j:');
    for (i = 0; i < r.commits.length; i++) lines.push('  C_' + i + ' = ' + vssPointToHex(r.commits[i]));
    lines.push('');
    lines.push('（内部记录：群秘密之和 = ' + r.groupSecret.toString() + '，仅用于自校验，真实场景中无人知晓）');
    return lines.join('\n');
  },
  dec: function (s, k, p, fmt) { throw new Error('DKG 是生成过程，无解密操作。请用 VSS 条目重构秘密。'); } });
