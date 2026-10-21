# 加密工具箱 CHANGELOG

正式名 **Aegis**（埃癸斯：希腊神话中宙斯与雅典娜的神盾），缩写 **AGS**。

> 内部代号沿革：**ARGUS**（阿格斯·百眼）是本项目的 v0.x 代号，因"100 个算法"
> 而起。算法早已过百，该代号已降级，仅保留在本文件与 `Encryption_and_decryption_logic.js`
> 头部注释中，不再对外展示。

---

## v0.9 — 基础框架

- 对称加密：AES-128/192/256、DES、3DES、SM4、RC5、RC6、RC4、ChaCha20、Blowfish、IDEA
- 单向哈希：MD5、SHA-1、SHA-2 家族、SM3
- 分组模式：ECB / CBC / CFB / OFB / CTR
- 输出格式：Hex、Base64

### 修正的历史缺陷

- **Blowfish**：S 盒未过密钥，且轮数多算一轮 —— 与标准库完全对不上，已重写
- **IDEA**：模乘、密钥扩展移位方向、轮内交换时机三处均错，已重写
  > 这两个算法在 v0.9 之前的实现是坏的，此前加密的密文无法解回

---

## v1.0 — 算法扩展

| 批次 | 新增 |
|---|---|
| 一 | Twofish-128/256、Camellia-128/256、ECC 通用加密、ECDH、ElGamal、SM2 加解密/签名、ECDSA、DSA |
| 二 | **Twofish-192、Camellia-192**（此前漏注册，底层一直支持） |
| 三 | SHA-224（纯 JS）、SHA3-256/512（Keccak）、GCM、ChaCha20-Poly1305、BLAKE2b、RIPEMD-160、HMAC、PBKDF2、HKDF、scrypt、TEA/XTEA/XXTEA、GOST Magma、6 种古典密码 |
| 四 | Streebog-256/512、SHAKE128/256、cSHAKE128/256、KMAC128/256、CMAC-AES、Kuznyechik、Serpent、AES-CCM |
| 五 | 14 种输出格式、XTS 模式、Argon2id/i/d |
| 六 | GCM/CCM/SIV 模式、9 种填充与严格校验、PCBC/LRW/CTS/CFB8/CFB1、OpenSSL/CryptoJS/PGP/JWE 容器、密钥 PEM 导出 |
| 七 | 口令派生改用 PBKDF2(210000)、ECDSA/DSA 改用 RFC 6979 确定性 k、弱算法警告、内置自检、X25519 |
| 八 | OCB 模式、**修复 EAX**（三处独立错误叠加） |
| 九 | KDF 扩至 7 档：PBKDF2 五种摘要（含 SM3）、Argon2 三型、scrypt、**bcrypt** |
| 十 | 统一安全审计（三级提示：严重/警告/说明） |
| 十一 | **SEED**（RFC 4269，与 OpenSSL 60 组随机比对） |
| 十二 | **ARIA**-128/192/256（RFC 5794，S 盒与轮常量由 1/π 计算自证） |
| 十三 | CRC32/CRC32C、Adler32、RSA-PSS、**FF1** 格式保留加密、MD4 |
| 十四 | CSS 精致化、BLAKE3 接入验证 |
| 十五 | **ML-KEM**-512/768/1024（后量子 KEM） |
| 十六 | **ML-DSA**-44/65/87（后量子签名） |
| 十七 | **BLS12-381** 配对与 BLS 签名 |
| 十八 | **SPHINCS+**（SHAKE-128f robust 变体） |
| 十九 | **FROST**（RFC 9591）、**GG20**（保留但标为「严重」） |
| 二十 | 算法选择器重做：八大分类折叠 + 顶部模糊搜索 + 历史 |
| 二十一 | Keccak / AES 性能优化 |
| 二十二 | hi/lo 推广至 BLAKE2b/Streebog、大文件分片/进度/取消、手写 Web Worker |

---

## 重要变更记录

### 破坏性变更

| 版本 | 变更 |
|---|---|
| v1.0 一 | Blowfish / IDEA 重写 —— **旧密文无法解回** |
| v1.0 五 | IV 不再拼在密文头部，改为自动回写到 IV 输入框；旧格式解密时自动回退兼容 |
| v1.0 十 | 对称加密默认模式改为 **AES-GCM**（原 CBC） |
| v1.0 十 | 口令派生默认改为 PBKDF2-SHA256(210000) —— 需切 legacy 才能解旧密文 |

### 安全提示

- **ECB**、**DES/3DES/RC4**、**MD4/MD5/SHA-1**、**宽松填充校验**标为「严重」
- 只提供保密不防篡改的模式（CBC/CFB/OFB/CTR 等）标为「警告」
- **GG20** 标为「严重」：Alpha-Rays（2023）攻击面，本实现仅含算术核心，
  未实现原论文的范围证明与 MtA 正确性证明 —— 建议改用 FROST

---

## 已知限制

- **ARIA** 仅有 RFC 官方 KAT 验证，未像 SEED 那样再跑 OpenSSL 随机比对
  （OpenSSL 3.0.2 的 ARIA 实际取不到）
- **SPHINCS+ 签名约 3.7 秒**（C 实现约 100ms），验签很快；签名长 17088 字节
- **Whirlpool** 未实现：三个版本 S-box 混乱，无可信来源
- **FHE（BFV/CKKS）** 未实现：真实现是 SEAL/OpenFHE 量级，玩具版会误导
- **Web Worker** 在 `file://` 下会被浏览器拦截，自动回退主线程（起 http 服务可启用）

---

## 验证

| 项目 | 结果 |
|---|---|
| 压力测试 | 2222 / 2222 |
| Bug 搜索 | 335 / 335 |
| 端到端注册 | 16 / 16 |
| 分片异步 | 47 / 47 |
| 安全提示 | 30 / 30 |
| console.error | 0 |

## 第二十八批：分类归拢 + 第二轮性能优化

### 分类归拢
- 统一分组名：`椭圆曲线`→`椭圆曲线与高级代数`、`后量子`→`后量子密码`、
  `非对称与密钥协商`→`非对称加密`（SPAKE2+ 三个条目）
- `algo_picker.js` 的分类规则从「按 id 白名单」改为「按 group 驱动 + 少量 id 覆盖」
  - 原白名单导致新增算法忘了登记就静默掉进「其他」，一度有 **23 个项目被误分**
  - 现在落入兜底的为 **0**

### 性能优化（64KB，同预热方法取最快，新旧公平 A/B）
| 算法 | 优化前 | 优化后 | 倍率 |
|---|---|---|---|
| GOST 28147-89 | 122.8 ms | 1.3 ms | **93.5×** |
| Kuznyechik | 32.3 ms | 3.7 ms | **8.7×** |
| 3DES | 124.5 ms | 21.2 ms | **5.9×** |
| DES | 41.9 ms | 7.5 ms | **5.6×** |
| Whirlpool | 21.3 ms | 13.1 ms | **1.6×** |

- **GOST**：S 盒预合成 4 张 256 项字节表，轮函数改 32 位字运算
- **Kuznyechik**：L/L⁻¹ 预合成为 32 位字表（线性变换拆成 16 个基向量异或）；
  轮常数 C 提到模块级（与密钥无关，原先每次密钥调度重算 32 次 L）
- **DES/3DES**：γ 与 SP 盒预合成，轮函数改 32 位字
- **Whirlpool**：γ+π+θ 合成为 WT 表，消除每轮数组分配

### 本轮修掉的 bug
- **DES 第 7 组 E 扩展取位偏移一位**：`R & 0x0f` 取的是 bit29..32，实际要 bit28..31
- **DES 解密子密钥 `.reverse()` 用错对象**：对扁平 Uint8Array 直接 reverse 会把
  每轮内部的 8 个组也倒过来，正确做法是只反转【轮序】（`desRevRounds`）。
  DES 漏改、3DES 已改，表现为加密全对、解密全错
- **E 扩展两处环绕位方向**：第 0 组 bit32 在【最高】位，第 7 组两个环绕位在【低 2 位】
- **Whirlpool 期望值凭记忆写错**：`message digest` 尾部记错、`a-z` 少写一个字符。
  靠【新旧等价对照】判定，而不是改实现去凑期望值

### 验证
- GOST 官方 12/12；DES 官方 4/4 + 对照旧实现 40/40；3DES 对照 20/20
- Kuznyechik 官方向量 ✓ + 新旧等价 50/50
- Whirlpool 新旧等价 39/39 + 官方 6/6 + 1e6×'a'
- 压力测试 2222/0，端到端 16/16，149 个算法无重复，console.error 0

## 第三十批：第四轮性能优化（块密码内核收尾）

| 算法 | 优化前 | 优化后 | 倍率 |
|---|---|---|---|
| **DES** | 7.06 ms | **1.78 ms** | **4.0×** |
| **3DES** | 10.4 ms | **4.2 ms** | **2.5×** |
| **IDEA**（解密） | 9.8 ms | **2.1 ms** | **4.7×** |
| **IDEA**（加密） | 5.2 ms | **2.0 ms** | **2.6×** |
| **ARIA**（解密） | 11.4 ms | **1.97 ms** | **5.8×** |
| **Magma** | 3.2 ms | **1.3 ms** | **2.7×** |
| **Serpent** | 3.0 ms | **2.0 ms** | **1.5×** |

（64KB，同一预热方法、独立进程取最快）

### 各算法的改动
- **DES / 3DES**：把 IP 与 FP 两个 64 位置换按【源字节】预合成为 8 张 256 项表
  （`DES_IPL/R`、`DES_FPH/L`）。原先每块要 `bytesToBits → permuteBits → desWord32 ×2`
  和 `desBits32 ×2 → permuteBits → bitsToBytes`：6 个临时数组、约 400 次逐比特搬运，
  比 16 轮 Feistel 本身还贵。现在 IP 与 FP 各只需 16 次查表、零分配。
- **IDEA**：① 模 `2^16+1` 乘法改用整数归约（低 16 位减小 16 位），去掉浮点取模；
  ② 解密子密钥（8 轮 × 4 次扩展欧几里得 = 每块 32 次求逆）提到密钥装配时算一次。
- **ARIA**：解密轮补上 `ariaDecRoundInto`。此前只有加密轮做了展开，解密仍在用
  通用 `ariaAInto`（16×7 次二维索引），导致**解密比加密慢 4.8 倍**。
- **Magma**：8 行 × 16 值 S 盒预合成为 4 张 256 项字节表（与 GOST 28147 同思路，
  但两者半字节序不同，不能共用）。
- **Serpent**：S 盒与线性变换改为写入复用暂存区，消除每块 63 次数组分配。

### 本轮修掉的 bug
- **自己写的 IDEA 参考实现错了**：我另写了一份 Python 参考实现用于交叉验证，
  40 组全不匹配。逐步对账后发现是我的参考实现把「MA 输出 → 状态」的次序写错：
  标准是 `x1^=t5, x2^=t6, x3^=t5, x4^=t6` 再交换 x2/x3，即新序 `[a^t4, c^t4, b^t5, d^t5]`。
  **原实现是对的**。这是本项目第 N 次「自己造的尺子是歪的」，幸而未据此改坏实现。
- **ARIA 插入新函数时括号位置算错**：新函数被塞进了 `ariaAInto` 的函数体内部，
  直接报 `ariaDecRoundInto is not defined`。
- **Magma 的半字节序与 GOST 不同**：Magma 的半字节 i 走 `SBOX[i]`（正序），
  而 GOST 28147 的字节序是【反】的。两者混用不报错、只静默算错。

### 验证
- IDEA：独立 Python 参考向量 40/40；新旧等价+往返 400/400；含 0x0000 字边界 200/200
- ARIA：RFC 5794 附录 A 6/6；解密新旧逐字节等价 300/300；边界 6/6
- Magma：预合成表 vs 逐半字节 1024/1024；新旧整块等价+往返 400/400；RFC 8891 向量 ✓
- DES：IP/FP 查表 vs 逐比特 4096/4096 + 随机整块 500/500；官方向量 ✓；
  3DES 往返 300/300；3DES 与「三次独立 DES」对照 200/200
- Serpent：pyserpent 官方向量 18/18；新旧等价 300/300
- 压力测试相关：bug 搜索二 487/0、三 335/0；全量加载 149 个算法无重复，console.error 0

### 说明
- 交付包**已从解压目录独立验证**：31/31 脚本加载成功、149 个算法、0 重复、
  0 console.error，DES 与 Magma 官方向量在解压目录下复算通过。

---

## 第二十九批：第三轮性能优化（BigInt 内核清理）

### 性能（64KB，同预热方法取最快，新旧公平 A/B）
| 算法 | 优化前 | 优化后 | 倍率 |
|---|---|---|---|
| SHA-512 | 34.9 ms | 4.4 ms | **7.9×** |
| SHA-512/224 | 34.7 ms | 4.5 ms | **7.7×** |
| SHA-512/256 | 34.8 ms | 4.5 ms | **7.7×** |
| ARIA-128 | 9.9 ms | 1.9 ms | **5.32×** |
| BLAKE2b | 12.2 ms | 3.6 ms | **3.4×** |
| 3DES（在上一批基础上再） | 21.7 ms | 11.7 ms | **1.86×** |
| Streebog-512 | 8.1 ms | 4.6 ms | **1.75×** |

- **SHA-512 家族**：原 `sha512Core` 整个用 BigInt 做 64 位运算。这是本轮最大的发现——
  标准 SHA-512 走浏览器原生所以只要 0.1ms，把 SHA-512/224 与 /256 慢到 35ms 的事实
  **掩盖了好几轮**。改成 hi/lo 双 32 位字。
- **ARIA**：把「SL（按字节位置选 4 个 S 盒之一）+ A（7 字节异或）」完全展开成
  16 行直写表达式，消除每轮 3 次数组分配与 16×7 次二维索引解引用。
- **BLAKE2b**：`b2bAdd`/`b2bRotr` 原来都返回 `[lo,hi]` 数组，每块产生上千个短命数组。
  改为内联加法 + 按 32/24/16/63 四个常量特化旋转，v/m 改用 Uint32Array 复用缓冲。
- **3DES**：三次 `desCryptBlock` 各做一次 IP/FP，中间两次的 FP 与下一次的 IP 互为逆而抵消。
  合并为一次 IP + 三次 16 轮核心 + 一次 FP。
- **Streebog**：T 表扁平化为 `TFLAT[r*256+idx]`，内层 8 次查表展开，
  输出用同一 buffer 上的 Uint32 视图直接写字（省掉逐字节拆分）。

### 本轮修掉的 bug
- **SHA-512 轮状态只更新了高位、漏了低位**：`bh=ah` 却没有 `bl=al`（其余 g/f/e/d/c 同理）。
  表现极其隐蔽——输出长度完全正常、自洽性检查看不出来，只有跟参考实现比对才暴露。
  第一轮 T1/T2 是对的，第二轮开始全错。
- **SHA-512 输出字节组装按 i<32 切分**：每个 64 位字是「4 字节 hi + 4 字节 lo」【交错】存放，
  不是前 32 字节全 hi。错误版本会得到每 4 字节重复的假输出（长度对、看着合理）。
- **误删 ariaFO / ariaFE**：重写 ARIA 时把密钥调度仍在使用的两个函数删掉了。
  补全后 ARIA 才恢复。

### 验证
- SHA-512 / SHA-512/224 / SHA-512/256 各 16 组与 Python `hashlib` 交叉：48/48
- BLAKE2b 与 `hashlib.blake2b` 18/18；压缩函数新旧等价 200/200
- Streebog-512/256 各 13 组与 `gostcrypto` 交叉：26/26
- ARIA 新旧等价 60/60（16/24/32 字节密钥）+ RFC 5794 附录 A 6/6
- 3DES 新旧输出一致 256/256 + 对照 20/20；DES 对照 40/40
- Whirlpool 6/6 + 1e6×'a'；GOST 12/12；Kuznyechik 50/50 + 官方向量
- 压力测试 2222/0，端到端 16/16，149 个算法无重复，console.error 0

### 说明
- Whirlpool 仍是最慢的哈希（约 13.8 ms/64KB）。它的轮函数已展开、无分配，
  剩余开销是算法本身的固有结构（10 轮状态 + 10 轮密钥，每轮 512 次查表）。

## 第三十一批：Ristretto255 / Bulletproofs 提速（消除模逆瓶颈）

### 背景：一个被"同族对比"暴露出来的性能问题
在给全部 149 个算法做速度普查时发现一个刺眼的不对称：
- Ristretto255 标量→点：**92.05 ms**
- Decaf448 标量→点：**3.00 ms**

两者算法结构完全相同（Edwards 曲线的素数阶商群），却差 30 倍。
这种"同族不同速"通常意味着某一侧走了非预期的慢路径。

### 根因：确认是模逆次数，不是算法结构
插桩统计：一次 edMul 要调用 **190 次 edqInv**（模逆 = 模幂 ≈ 380 次 BigInt 模乘）。
190 × 380 ≈ 7.2 万次模乘，实测 35 ms —— 与观测值吻合。
edAdd 每次做 2 次模逆，double-and-add 循环 255 轮，模逆就成了绝对瓶颈。

### 做法：扩展坐标（X:Y:Z:T），全程无模逆
仿射 → 扩展坐标（x=X/Z, y=Y/Z, T=XY/Z），加法/倍点只做乘法，
末尾转回仿射只做 **1 次** 模逆。标量乘的模逆次数 190 → 1。

公式采用 add-2008-hwcd / dbl-2008-hwcd（本曲线 a = -1）。
**不凭记忆信任公式**：与上方已被 FROST / RFC 9591 官方向量验证过的
edAdd / edMul 做等价对照 —— 基点标量乘 60 组随机 + 生成点 40 组
+ 点加 40 组 + 倍点 20 组 + k=0/1/L-1 边界，**163/163 逐坐标一致**。

新增函数（crypto_threshold.js）：
- `edToProj` / `edProjAdd` / `edProjDbl` / `edProjMul` / `edProjToAff`
- `edMulFast(P,k)` —— 单标量乘
- `edMulFastAdd(P,k,Q)` —— 标量乘后再加点，全程扩展坐标
- `edMultiScalarMul(points,scalars)` —— 多标量乘，末尾 1 次模逆

**不改动 edAdd / edMul 本身**，FROST 仍走已验证的旧路径。

### 顺带：Bulletproofs 的 MSM 是同一个病根
bpMsm 原本是 `R = edAdd(R, edMul(Pi, si))` 逐点累加 ——
每个点 190 次模逆 + 每次加法 2 次模逆，1000 个点的 MSM 约 19 万次模逆。
改用 edMultiScalarMul 后降到 1 次。

### 成绩（同进程公平 A/B，预热后取最快）
| 算法 | 优化前 | 优化后 | 倍率 |
|---|---|---|---|
| Ristretto255 标量→点 | 92.05 ms | **1.17 ms** | **78.7×** |
| Ristretto255 DH | 75.79 ms | 1.44 ms | **52.6×** |
| Bulletproofs n=8 | 2572 ms | **27 ms** | **93.6×** |
| Bulletproofs n=16 | 4325 ms | **44 ms** | **97.6×** |
| Bulletproofs n=32 | 7586 ms | **74 ms** | **102.5×** |

### 一个必须记下的教训：差点交出一份假成绩
第一次测"优化后 1.30 ms"时，我用的标量是 `0000…0007`（值 7）——
只有 3 次倍点，几乎不触发模逆，**测出 1.30 ms 纯属侥幸**。
而优化前的 92 ms 用的是满 256 位标量。两者输入不同，对比无效。

更严重的是：work/ 与 dist/ 是**两份独立文件**，我改动写进了 dist/，
但所有测试脚本都跑在 work/ —— 意味着那批"通过"的测试验证的是旧代码。

修正：把 3 个文件同步到 work/，并用与优化前**完全相同**的满标量 H(32) 重测，
才得到可信的 1.17 ms。教训是两句话：
1. A/B 必须同输入 —— 尤其密码学里"输入规模"直接决定运算量
2. 改完 dist 要同步 work，否则测试验证的是另一份代码

### 验证（全部在 work/ 同步后执行，并最终在解压目录复算）
- Ristretto255 完整测试 **60/60**（含 RFC 9496 附录 A.2 的 B[1..15]、商群等价性、one-way map）
- Ristretto255 界面 **12/12**
- FROST vs RFC 9591 官方向量 **14/14**（确认未波及已验证路径）
- Bulletproofs 官方固定向量 **16/16**（n=8/16/32/64 × m=1/2/4/8），篡改末字节正确拒绝
- 端到端注册 **16/16**，算法 149 个无重复，console.error 0
- 解压目录独立加载 31/31 成功，Ristretto255 输出复算 2.62 ms

### 说明
- Bulletproofs 的 n=64/m=8 仍较慢（单次多标量乘约 1000 项），但已从分钟级降到秒级。
- 这次没有新增算法，149 个保持不变。

## 第三十二批：新增 HQC（Hamming Quasi-Cyclic）后量子 KEM

### 成果
算法 149 → 152，新增 `hqc128` / `hqc192` / `hqc256` 三个条目（后量子密码组）。
HQC 是 NIST 于 2025-03 选为 ML-KEM 备份的码基 KEM（非格路线，IR 8545）。

### 验证（全部对官方 KAT，非自洽）
| 项目 | 结果 |
|---|---|
| 官方 KAT（pk/sk/ct/ss/decaps 四项） | HQC-128 **20/20**、192 **5/5**、256 **2/2** |
| 自身往返（随机密钥） | 9/9 |
| 篡改密文 → 隐式拒绝 | 5/5（返回不同伪随机值，不抛错） |
| 尺寸 | 与官方规格逐项一致 |
| 解压目录独立复算 | 32/32 脚本加载，界面往返 ✓ |

KAT 来源：`PQCkemKAT_{2321,4602,7333}.rsp`（C 参考实现生成）。
交叉参考：hqc-py（其 keygen/encaps 已过官方 KAT；decrypt/decaps 是 TODO 占位，故解码器自己实现）。

### 四个 bug，每个都是"静默全错"型

**1. 循环移位必须模 n，不能按 word 级模 (nw*32)**
n = 17669 / 35851 / 57637 都不是 32 的倍数（17669 % 32 = 5），
word 级循环会把最后一个字的无效位绕回低位。
表现：采样、哈希、seed 派生全对，**只有 s = h·y + x 全错**。

**2. GF(2^8) 表生成漏了清溢出位**
`x ^= 0x1d` 应为 `(x<<1) & 0xff` 后按最高位决定是否 `^0x1d`
（等价 `x ^= 0x11d`）。我第一版让 α^8 = 285 而非标准的 29，
**整张表从 i=8 起全错**。RS 校验字节因此完全不对，长度却正常。

**3. RM 软判决的符号约定反了**
soft 初值 `-repeat` 再每个 1 `+2`，使"位为 1"映射成正值；
而相关式 Σ soft[j]·(-1)^{f_a(j)} 用的是"位为 1 → 负"。
后果：**低 7 位全对、只有 bit7 反**，无噪声自测就 46/46 全错。

**4. 域分隔符是"追加一个字节"，不是 NIST 标准后缀**
G/H/I/J 分别是 SHA3-512/256(input ‖ 0x00/0x01/0x02/0x03)。
另外 GF(2^8) 本原多项式是 **0x11D**，不是 AES 的 0x11B —— 混用不报错。

### 一个反直觉但被实测确认的事实
解密残余噪声 = r2·x + r1·y + e，实测 **34.2%**（6042/17664），
远超 RM(1,7) 唯一解码半径 31/128 = 24%。
这曾让我怀疑公式推导有误，于是用真实 KAT 数据反推验证：
v + Truncate(u·y) 与真实 em 的距离确实是 34.2%，且 ss 与 KAT 完全匹配。

结论是 ML 解码不等于唯一解码：RM(1,7) 只有 256 个码字，
正确码字相关值 ≈ 128 − 2×43 = 42，而 255 个错误码字的相关最大值
≈ σ·2.7 ≈ 30（σ = √128 ≈ 11.3），42 > 30，故 34% 错误下仍可正确解码。
**不要用"唯一解码半径"去判断可行性**。

### 说明
- HQC 规格仍在定稿中（FIPS 207 草案，预计 2026/2027），info 已标注不建议用于生产。
- RM 解码目前是 128×128 暴力相关（每符号），HQC-128 解封装约 20 ms，可接受；
  如需提速可换成 FHT。

## 第三十三批：Verkle IPA 内积论证（rust-verkle ipa-multipoint）

算法 155 → 157（新增 verkle-ipa-prove / verkle-ipa-verify）。

### 验证
- transcript 官方测试 test_vector_1~4：4/4（含 append_point 的压缩格式锁定）
- CRS 256 点逐点比对 default_crs.rs：256/256 全等（此前只有首尾两个锚点）
- Q 的 Fr(x/y) = d1e7de2a…d14，与官方 consistent_group_to_field 一致
- IPA 证明：n=8/32/256 共 4 组，C/out/L/R/a 逐项与独立 Python 参考实现一致
- 篡改 C / z / a 均判失败；声称错误 out 判失败
- devnet6 创世状态根复算仍匹配（vCompress 改动后回归）

### 四个 bug（全部「不报错、自洽看不出」）
1. **点压缩规则记错** — 官方是「y 不正时输出 -x」，不是「x + 符号位」。
   此前版本恒输出 x，因 CRS 各点 y 均为「较大根」而侥幸未暴露。
2. **标量运算误用 mod q** — 内积、幂次、fold 都用 vmod（mod q）而非 mod r。
3. **Fr 求逆误用 vPowMod** — 它全程 mod q，算 x^(r-2) 得到的不是 x⁻¹ mod r。
4. **transcript 清空后重复写标签** — ch 里先置 st=label 再 append，标签被写两遍。
   单挑战场景（tv1~tv4）发现不了，只有多轮挑战的 IPA 才暴露。

### 另记
- `head`（✓/✗ 结论）原本在「声称 out 不一致」判定之前定型，导致该情形误报通过；已挪到最后。
- IPA 与本项目的 Bulletproofs 约定不同（G 侧乘 x⁻¹ 而非 x），二者不可混用。

---

## 第三十三批：椭圆曲线标量乘全面雅可比化（性能）

### 根因：模逆次数
仿射 `EC.add` 每步 1 次 `binv`（扩展欧几里得，数百次 BigInt 模乘）；
256 位标量乘 ≈ 384 次模逆。项目里 `EC.prototype.mulJacobian` 早已存在
（全程雅可比、末尾 1 次模逆），但 **所有调用点仍在用仿射 `mul`** ——
两条路径并存，快的那条没人用。

### 做法
`EC.prototype.mul` 改为委托 `mulJacobian`；原实现保留为 `mulAffine` 供回退。
等价性先验证再改：**348/348**（P-256 / P-384 / P-521 / SM2 四条曲线 ×
边界 k ∈ {0,1,2,3,n-1,n,n+1} × 基点与非基点 × 40 组随机）。

### 实测（同脚本 A/B，切换 mul / mulAffine）

| 项目 | 优化前 | 优化后 | 倍率 |
|---|---|---|---|
| Ed25519ctx 签名 | 247.40 ms | 2.81 ms | 88× |
| Ed25519ph 签名 | 248.73 ms | 2.85 ms | 87× |
| Ed25519ctx 验签 | 250.57 ms | 3.83 ms | 65× |
| frostVerify | 259.33 ms | 3.71 ms | 69.8× |
| frostGroupCommitment (t=2,n=5) | 631.64 ms | 10.45 ms | 60.5× |
| vssVerifyShare | 11.03 ms | 1.15 ms | 9.6× |
| vssDkg (t=2,n=5) | 27.89 ms | 17.75 ms | 1.6× |
| BIP-32 派生 m/0'/1/2' | 44.19 ms | 4.72 ms | 9.4× |
| keygen SM2 | 11.01 ms | 1.22 ms | 9.1× |
| keygen ECC P-256 | 10.68 ms | 1.34 ms | 7.9× |
| P-256 标量乘 | 10.53 ms | 1.05 ms | 10.1× |

### 连带修掉的两处浪费
- `frostVerify` 原写 `edMul(edMul(A, c), 8n)` —— **两次**标量乘，标量可先合并为 `c*8`。
- `frostGroupCommitment` 循环内 n 次 `edMul` + 2n 次 `edAdd`（各 2 次模逆），
  改为全程扩展坐标累加，模逆 190n+ → 1。
- `crypto_core.js` 里 FROST 恢复群公钥的循环同样改为雅可比累加。

### 影响面
所有走 `CURVES[*].mul` 的算法自动受益：SM2 加解密/签名/密钥协商、
ElGamal、ECC-ECDH/ECIES/ECDSA、DSA、Schnorr、BIP-32、VSS/DKG。
Ed25519 系（edMul/edAdd）改用已验证的 `edMulFast` / `edMulFastAdd`
（扩展坐标，163/163 等价对照）。

### 回归
FROST RFC 9591 14/14、VSS/DKG 24/24、BIP-32 24/24、Schnorr 8/8 + 19/19、
SM2 密钥协商 28/28、SM9 45/72/18/6、SPAKE2+ 9/9、HPKE 10/10、KZG 60/60、
BN254 24/24、BLS12-381 45/45、Ristretto255 60/60、Decaf448 31/31、
Ed25519ctx 29/29、Ed25519ph 24/24、扩展坐标等价 163/163、
AES 8/8、Whirlpool 6/6 + 39/39、ZUC 36/36、GCM-SIV 3/3、FF1 10/10、
ML-KEM 9/9、ML-DSA 45/45、SPHINCS+ 5/5、Bulletproofs 官方 16/16。
解压目录独立验证：34/34 脚本加载、157 算法无重复、ctx/ph 签名验签通过。

---

## 第三十三批：HOTP / TOTP / SipHash（180 → 184 个算法）

新增 4 个条目，全部有权威向量。

| 条目 | id | 向量来源 |
|---|---|---|
| HOTP 一次性口令 | `hotp` | RFC 4226 附录 D（10 组） |
| TOTP 时间型口令 | `totp` | RFC 6238 附录 B（SHA-1/256/512 × 6 组） |
| SipHash-2-4 | `siphash-24` | 官方 `vectors.h` + Python siphash 0.0.1 交叉 |
| SipHash-1-3 | `siphash-13` | hi/lo 与 BigInt 实现等价对照 |

### 为什么自带一份 SHA-1
工具箱里的 SHA-1 走浏览器原生 `crypto.subtle`，是**异步**的；而 OTP 必须同步算
（RFC 4226 向量的主力就是 HMAC-SHA-1）。SHA-256/512 复用 `hmacBytesSync`，不重复造轮子。
SHA-1 本地实现用 hashlib 交叉验证：`""`/`"abc"`/`"quick brown fox"`/56 字节长输入，
以及 RFC 2202 的 HMAC-SHA1 前两组，全部命中。

### 密钥三态解析（不能省）
`hex:` > `raw:` > Base32（OTP 行业默认）。
原因：RFC 4226 的 secret 是 ASCII `"12345678901234567890"`，
它**本身也全由 Base32 合法字符组成**，若不做前缀区分会被静默误判成 Base32。

### 又一次"参照物错了"
SipHash 第一版测试 6/6 失败。我没有改实现，而是核对了 Python `siphash` 库的输出——
**两者逐字节完全相同**。真正的原因是我把期望值写成了"把字节序列按大端读成的整数"
（`726fdb47dd0e0e31`），而官方 `vectors.h` 存的是 `uint8_t out[8]` 字节序列
（`31 0e 0e dd 47 db 6f 72`）。**是同一值的两种表示，期望值写法错了。**
另外第 6 组（n=5）我凭记忆写的 `6b7d4b0c8b6bd6a1` 也是错的，Python 给出的是
`8da699cd64557618`——这已是本项目第 N 次栽在"凭记忆写常量"。

### SipHash 的字节序教训
Python `siphash` 库的 `digest()` 输出与官方字节序列一致（无需反转）。
第一版我误判成"库输出大端、需反转"，差点据此把正确的实现改坏。

### 验证
- SHA-1 4 组 + HMAC 3 组（RFC 2202）
- RFC 4226 10/10、RFC 6238 18/18（三种摘要 × 6 个时间点）
- SipHash 官方 16/16 + 随机交叉 60/60（Python 生成）+ hi/lo 等价 162/162
- 界面入口 45/45（含参数解析、8 位、sha256/512、±1 窗口容忍、4 种非法输入均友好报错）
- 解压目录独立复算：40/40 脚本加载、184 算法无重复、向量 36/36

### 健壮性
遍历 184 个条目（跳过 25 个已知慢算法：KDF/后量子/配对类）做空输入与非法输入调用：
252 次调用、**0 崩溃、0 异步未捕获错误**。

### 备注
jsdom 全量压力测试在本环境跑不完（阶段 B 分组密码 × 模式 × 填充 × 长度组合过慢），
本轮改用轻量健壮性检查替代，结论见上。

---

## 第三十四批：Bech32 / Bech32m / Shamir 门限 / Merkle 树（188 → 194）

### 新增算法（6 个）

| 条目 | 向量来源 | 验证 |
|---|---|---|
| bech32（BIP-173） | bitcoin/bips 仓库 Test vectors 章节 | 7 组有效 + 10 组无效 + 51 零字节 |
| bech32m（BIP-350） | 常量 0x2bc830a3（与 Bech32 同构） | 往返 + 与 Bech32 互不兼容 |
| sss-split（GF(256)） | 无外部向量，结构自证 | 10 种 t 组合 + 单字节 256 值 + 随机 200 组 |
| sss-recover | 同上 | 同上 |
| merkle-root（RFC 6962） | 无外部向量，结构自证 | 15 种叶子数对独立参考 + 提升规则 |
| merkle-proof | 同上 | 13 叶子逐一验证 + 篡改必失败 |

### bcrypt：做了但撤下（重要）

实现了完整的 EksBlowfish（密钥扩展 + 64 次加密 + Unix crypt Base64），
但**官方向量一组也对不上**。排查过程：

1. 先验证 Blowfish 内核 —— 3 组标准向量全过（含 26 字节密钥），P/S 常量正确
2. 写了一份**独立的 Python 参考实现**，结果与 JS **逐字节相同**
   → 说明不是实现 bug，是流程理解有偏差
3. 枚举 8 种密钥扩展顺序 → 全不匹配
4. 枚举字节序（大端/小端）、NUL 后缀 → 全不匹配
5. 枚举 24 种组合（salt 初始化 / 顺序 / 白化）→ **无一匹配**

按本项目「没验证就不上线」的规矩，**从 ALGOS 移除**。实现保留在
`crypto_kdf_addr.js` 里（已注释掉注册），日后拿到权威源码可继续排查。

**教训**：两条独立实现（JS + Python）得出相同结果，只能证明「实现自洽」，
不能证明「实现正确」——它俩可能错在同一个共同的错误前提上。
要打破这种僵局，必须拿到第三方的、结构不同的正确输出。

### 挖出的 bug

**1. bcrypt 的 Base64 必须分别编码 salt 与 hash**

```js
b64enc(salt) + b64enc(ctext.subarray(0, 23))   // 对：22 + 31 字符
b64enc(concat(salt, ctext23))                   // 错：52 字符，且前 22 位是 salt
```

两者只差 1 个字符长度，属于「看着几乎一样、实际全错」的典型。

**2. Bech32 的 polymod 中 chk 必须保持无符号**

```js
var top = chk >>> 25;                            // 对
var top = chk >> 25;                             // 错：chk 为负时算术右移
```

**3. Bech32 缺少总长度 ≤ 90 的检查**（BIP-173 上限），
导致 `an84characters...` 这条官方「应拒绝」的用例被误接受。

### 验证

从 zip 解压目录独立复算：脚本 43/43 加载成功、194 个算法无重复、
Bech32/Shamir 58/0、Merkle 25/0、bcrypt 确认不在注册表中。

## 第三十四批：bcrypt 修复 + BIP-39（算法 194 → 197）

### bcrypt（撤下后重新上线，16/16 官方向量）
此前 24 种密钥扩展变体全部失败，根因是**没拿到官方源码、纯靠猜**。
本轮直接下载 OpenBSD 官方 `lib/libc/crypt/bcrypt.c` 与 `blowfish.c` 逐行移植。

真正的原因有两处，此前 24 种组合一种都没碰到：
1. `Blowfish_expandstate(c, data, key)` 有两个不同作用的入参：
   - **P 盒用 `key` 异或**（`P[i] ^= stream2word(key)`）
   - **加密流用 `data`**：每步 `datal ^= stream2word(data)` 后再 encipher
   我此前把两者写成同一个数组，且从不把 data 混进流。
2. 循环体用的是 `expand0state`（只做 P 异或 + **纯**加密流，不混 data），
   与 `expandstate` 不可互换。

另外两处：
- 输出字节序：读用大端（stream2word），但官方**写回是小端**。反了不报错、只静默全错。
- Blowfish 常量结构体是 **S 在前、P 在后**（`blf_ctx { S[4][256]; P[18]; }`），
  提取时取反过一次，靠 P[0]==0x243f6a88 / P[1]==0x85a308d3 自证纠正。

又一次"凭记忆写参照物"：我记的 P[17]=0x3ac372e6 是错的，官方为 0x8979fb1b。

### BIP-39（新增 2 个算法）
- 词表：bitcoin/bips 官方 `bip-0039/english.txt`（2048 词，首 abandon / 末 zoo）
- 向量：trezor/python-mnemonic 官方 `vectors.json`，english 24 组
- 验证：熵→词 24/24、词→熵 24/24、篡改必被拒 24/24、PBKDF2 种子 24/24

### 又踩到 script 标签未闭合（同类第 2 次）
`crypto_merkle.js` 的 `<script>` 标签未闭合，把新插入的两个 BIP-39 脚本吞进正文，
导致词表没加载。与之前 crypto_hqc.js 那个完全同类，靠 t_all.js 的标签结构检查定位。

### 经验
"两份独立实现结果一致"只能证明自洽，不能证明正确——它们可能错在同一个前提上。
要打破僵局必须有结构不同的第三方正确输出（本轮即 OpenBSD 官方 C 源码）。

---

## 第三十五批：Adiantum 长度保持加密（4 个新算法，197 → 201）

### 突破：拿到 Google 官方实现与向量
用户给的直链在我这边全部 403 / 超时（`classic.mceliece.org`、`ntruprime.cr.yp.to` 返回
`Request denied`，`raw.githubusercontent.com` 连接超时）。改用 **codeload 整包**成功：
`codeload.github.com/google/adiantum/tar.gz/refs/heads/master`（注意是 master，main 分支 404）。

包内含 `python/` 官方实现与 **`test_vectors/ours/`** 官方向量：
Adiantum 180×3 组、NH 15 组、NHPoly1305 30 组、XChaCha12/20 各 25 组。
在沙盒装 `pycryptodomex` 后，官方 Python 实现可直接跑通并自我校验 180/180 ——
这意味着我有了**可无限生成新向量的权威参照**，不再是"自己造尺子"。

### 验证（385/385 全通过）
| 项目 | 结果 |
|---|---|
| Adiantum XChaCha12-AES256 | 180/180 |
| Adiantum XChaCha20-AES256 | 180/180 |
| XChaCha12（含 offset 0/1/1023/1024/2048） | 25/25 |
| NH | 15/15 |
| NHPoly1305 | 30/30 |

### 新增算法
`adiantum`（XChaCha12-AES256，标准变体）、`adiantum20`（20 轮）、
`xchacha12`（流密码，nonce‖密文）、`nhpoly1305`（泛哈希）。

### 规范细节（全部由官方源码确认，非推测）
- **XChaCha**：`subkey = HChaCha(key, nonce[0:16])`，再 `ChaCha(subkey, nonce[16:24])`，
  轮数由 variant 继承（XChaCha12 = HChaCha12 + ChaCha12）
- **nonce 填充**：`nonce + b'\1' + b'\0'*(24-len-1)`。派生子密钥时 nonce 为空 → `01 00×23`
- **子密钥布局**：`[block_key(32), rt(16), rm(16), nh_key(1072)]`，共 1136 字节
- **NH**：unit 16 / messagemax 1024 / key 1072 / passes 4 / stride 2，输出 4×uint64 = **32 字节**
  （注意：`lengths()['hash']` 写的是 16，与实际输出 32 不符，该字段未被使用——按实际返回值）
- **长度编码**：`8*len(msg)` 即**比特数**，16 字节小端，拼在 tweak 前
- **`_hash` 返回整数和**：`ht + hm` 是普通整数相加（各自 mod 2^130-5），
  不是字节拼接；`_block_add` 再截断到 128 位

### 踩到的坑
1. **NHPoly1305 与 Adiantum 内部哈希不是一回事**。
   独立 NHPoly1305 的 key 是 1088 = `r(16) ‖ NHkey(1072)`，只有一个 r；
   而 Adiantum 内部用**两个** r（rt 处理长度+tweak，rm 处理 NH 输出）。
   我最初把 Adiantum 的 rt/rm/nhkey 拼成 1104 字节去套 1088 的检查，直接抛错。
2. XChaCha 向量里的 `offset` 是**起始块计数**（0/1/1023/1024/2048），界面入口用不到，
   但测试必须支持——否则 25 组里只有 5 组能过。为此暴露了 `__xchachaTest` 钩子。

### 未注册
Adiantum XChaCha8 有官方向量但未注册条目（非标准变体，避免条目膨胀）。

## 第三十六批：XChaCha8 补齐 + 官方源深抓

### 新增算法（203）
- `adiantum8`  Adiantum（XChaCha8-AES256）
- `xchacha8`   XChaCha8 流密码

### 验证
- Adiantum 三变体 180×3/180（Google 官方 python 实现 + test_vectors/ours/）
- XChaCha12 / XChaCha8 各 25/25（含 offset 0/1/1023/1024/2048）
- XChaCha8 走注册入口往返 9/9（长度 0/1/15/16/63/64/65/200/1024）
- NH 15/15、NHPoly1305 30/30
- **解压目录独立复算 599/599**
- t_all：46/46 脚本、203 算法无重复、缺 enc/dec 0、超 200 字说明 0

### 官方源深抓结果
| 目标 | 结果 |
|---|---|
| Google Adiantum 包（codeload） | ✓ 已有，含 XChaCha8 向量 |
| Linux `crypto/testmgr.h`（raw.githubusercontent） | ✗ 超时，仅 313 字节错误页 |
| `classic.mceliece.org` tar.gz | ✗ 403（带 UA 仍 403） |
| `ntruprime.cr.yp.to` tar.gz | ✗ 403；Wayback 归档也 403 |
| **PQClean（codeload）** | ✓ **3.6MB，含 mceliece348864/348864f/460896/460896f + hqc 三档** |
| OpenSSH（codeload） | ✓ 1.9MB，但只有 `kexsntrup761x25519.c`，无 sntrup761 内核实现 |

### 突破：Classic McEliece 参考实现已可自产向量
编译 PQClean `mceliece348864/clean`（`cc -O2 -std=c99 -I../../../common`，
链接 `sha2.c aes.c nistseedexpander.c fips202.c sp800-185.c`）成功。
用确定性 splitmix64 替换 `PQCLEAN_randombytes` 后生成 2 组 KAT：

```
pk=261120  sk=6492  ct=96  ss=32
round0 ct=068dd2b5e2918cf4ed592c77a153e0fb5033dbc908c534244dbf82bc1a25cdae...
round0 ss=ccdade1bd832dba571586386cab1ec84b90d455cd672a12fc7b7360abb937788
round1 ss=be1d821c9203251e27b862e252fa1710d249c10677aa2f91c3146b88cee72d0f
dec_match = 1（两组均自洽）
```

二进制已固化：`mce{0,1}.pk` / `mce{0,1}.sk`，随交付包分发。

### 教训
- `if (NS) {}` 残留行导致编译失败 —— 宏当标识符用，编译期即报错（好在这次是硬失败）
- 链接 PQClean 必须补 `fips202.c` + `sp800-185.c`，少了报 `undefined reference to shake256`
- wayback 的 `web/2023id_/` 对 cr.yp.to 同样 403，该站屏蔽归档

### 仍未拿到
sntrup761（ntruprime）、FrodoKEM、BIKE、BLS12-377 参考实现与向量

## 第三十七批 · BLS12-377 配对攻下（算法 203 → 205）

### 新增算法（2）
- **bls12-377-pairing** —— BLS12-377 最优 ate 配对
- **bls12-377-hash-to-field** —— RFC 9380 expand_message_xmd(SHA-256) + hash_to_field

### 根因：Miller 循环多跑了最高位（本次核心突破）
原实现 `for (i = bitlen(s)-1; i >= 0; i--)`，比标准算法多一轮。
标准 Miller 应从 **bitlen(s)-2** 起：R 的初值已是 1·Q，最高位无需再处理。

多跑一轮后算出的 n' ≠ s，于是 **n' ≢ q mod r**，配对不再是双线性。

**这个 bug 极具迷惑性**：e^r == 1、e != 1、G1/G2 在曲线上、r·G=O
全部照样成立 —— 单看这些"健康检查"完全发现不了，
只有拿 `e(a·G1, b·G2) == e(G1,G2)^(a·b)` 去比才会暴露。
上一轮记录里"已排除 X / 6X+2 / 6X-2 / 2X / 3X+1 / X±1 均失败"，
其实**循环数一直是对的（s = x，且已验证 p ≡ x mod r）**，
错的从来是循环起点。

### 验证（官方向量 73/73）
来源：arkworks-rs/curves `bls12_377/src/curves/tests/` 两份 JSON（各 5 组）
- `expand_message_xmd` 推出的 u：G1 10 组 + G2 20 组，全部逐字节一致
- 官方 Q0 / Q1 / P 均落在本实现的曲线上（G1 15 + G2 15）
- 官方 P 均落在 r 阶子群（r·P = O，G1 5 + G2 5）
- 官方点配对满足双线性 + 非平凡 + e^r = 1
- 自身性质 12/12、注册入口 6/6

### 常量来源（arkworks-rs/curves 源码原文，非估算）
```
Fq = 258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177
Fr = 8444461749428370424248824938781546531375899335154063827935233455917409239041
X  = 0x8508c00000000001（正）   TWIST_TYPE = D
FQ2 = FQ[u]/(u^2+5)   FQ12 = FQ[w]/(w^12+5)，w^6 = u
G1 b = 1      G2 b' = b/u = -u/5 = [0, 1551986556077814564...906]
```
与 BLS12-381 / BN254 的三处关键差异（混用会静默全错、不报错）：
`u^2 = -5`（那两家是 -1）、`w^12 = -5`（那两家是二次归约）、G2 扭常数不同。

### 本轮踩的坑（3 个，全是"看着对"类）
1. **测试脚本 msg 编码** —— JSON 里 msg 是 ASCII 原文（"abc"），
   我按 `Buffer.from(msg,"hex")` 解，`"abc"` 被当成 hex 变成 0xAB。
   空消息恰好不受影响，所以只有非空 msg 的 8 组报错。
2. **G2 坐标两种写法** —— JSON 里 FQ2 有时是 `"c0,c1"` 字符串、
   有时是 `{c0,c1}` 对象，解析器要都兼容。
3. **G2 的 hash_to_field 长度** —— m=2 时
   `len_in_bytes = 64 × count × m`，按 m=1 算会取错字节区间。

### 未完成（诚实标注）
**哈希到曲线**未实现：BLS12-377 的 G1/G2 为 A=0，
标准 SSWU（要求 ab ≠ 0）需配合同源映射（arkworks `g1_swu_iso.rs`），
工程量大。已实现并验证的是**到域**这一步。
两条注册说明里均已写明"仅到域，不到曲线"。

### 其他
- `b377_gen.js` 首次接入 index.html：脚本 47/47、算法 205 无重复
- 说明超 200 字：0 条
- 解压目录独立复算：脚本 47/47、配对与向量 9/9

---

## 第三十七批：BLS12-377 哈希到曲线（SSWU + 同源映射） + dist 引用缺失修复

**算法数 205 → 207**（新增 `bls12-377-hash-to-curve-g1` / `-g2`）

### 官方向量：208/208 全过
向量来源：arkworks-rs/curves `bls12_377/src/curves/tests/` 两份 JSON
（`BLS12377G1_XMD-SHA-256_SSWU_RO_.json`、`BLS12377G2_XMD-SHA-256_SSWU_RO_.json`）。

| 项 | G1 | G2 |
|---|---|---|
| 向量组数 | 5 | 5 |
| u（hash_to_field） | 10/10 | 10/10 |
| Q0/Q1（同源映射后） | 10/10 | 10/10 |
| P（清余因子后） | 5/5 | 5/5 |
| 小计 | **108/108** | |

另验：P 在曲线上、P 在 r 阶子群（`r·P = O`）。

### ⚠ 发现上一轮的一个严重交付缺陷
**`dist/index.html` 里根本没有引用 `b377_gen.js`**。
文件虽然打进了包，但没被 `<script>` 加载 ——
也就是说上一轮交付的包里，**BLS12-377 配对 / 哈希到域这两个条目在界面上压根不存在**。

这与之前 XCB 那次是同一类问题（script 标签层面的错误），
区别在于上次是"标签没闭合被吞"，这次是"压根没写引用"。
已把 `work/index.html` 同步到 `dist`，两行引用补齐。

**教训**：算法文件存在 ≠ 条目可用。以后每次新增条目后，
必须在 **dist 目录**（而非 work）跑一次 `t_all.js` 数算法总数。

### 四个关键实现细节（全部取自 arkworks 源码原文，非估算）
1. **SSWU 的 Z 就是 `SWUConfig::ZETA`** —— arkworks 用了 `Z = ZETA` 的特化。
   G1 为 `-11`、G2 为 `12 + u`。不要用其他值。
2. **清余因子用「有效余因子 h_eff」，不是完整余因子。**
   - G1：`h_eff = x − 1 = 9586122913090633728`，**不是** `(x−1)²/3`
   - G2：`g2.rs` 测试里那个 10×u64 的 h_eff 常数
   写成完整余因子会得到"也在曲线上、也在子群"但**与官方不一致**的点 ——
   这类错误极具迷惑性，常规健康检查全部照常通过。
3. **parity 取「第一个非零分量」的奇偶** —— G1 即最低位；
   G2 先看 c0、c0 为 0 才看 c1。
4. **官方 JSON 里的 Q0/Q1 是同源映射【之后】的点**（在 `y²=x³+B` 上），
   不是 SSWU 直接在 E' 上的输出。一开始按 E' 比对 10/10 全败，
   靠"期望点到底落在哪条曲线上"这个判据定位。

### 踩的坑
- **`b3g1Mul` / `b3g2Mul` 内部对 k 做了 `mod r`**，清余因子时**绝不能**用
  （G2 的 h_eff 有 590 位，mod r 后完全不同）。新增 `b3g1MulRaw` / `b3g2MulRaw`。
- **p ≡ 1 mod 4**，FQ 开方不能用 `x^((p+1)/4)`，必须 Tonelli-Shanks。
- **FQ2 开方**：`t = sqrt(a² + 5b²)`（norm 到 FQ 必为 QR），
  再取 `c² = (a ± t)/2` 中是 QR 的那个，`d = b/(2c)`。
  取哪个根无所谓 —— SSWU 末尾的 parity 调整会统一符号。
- 早期调试脚本 `t_b377.js` 硬编码的点不在曲线上（曲线参数定稿前的遗留），
  已删除，避免以后误判为回归失败。

### 其他
- `b377_h2c.js` 接入 index.html：脚本 48/48、**算法 207 无重复**、说明超 200 字 0 条
- `hash-to-field` 的 info 已更新（原写"仅到域，不到曲线，尚未实现"，现改为指向新条目）
- 打包脚本 `_pack.sh` 现在显式复制 `testvectors/`，保证解压后可独立复算
- 速度：G1 哈希到曲线约 9 ms/次，G2 约 46 ms/次
- 解压目录独立复算：脚本 48/48、hash-to-curve 108/108、入口 17/17、配对向量 73/73

## 第三十八批：BLAKE2bp / BLAKE2sp（BLAKE2 并行变体）

算法数：209 → 211（新增 blake2bp、blake2sp）

### 向量来源
BLAKE2 官方包（github.com/BLAKE2/BLAKE2，codeload 整包下载）：
- ref/blake2bp-ref.c、ref/blake2sp-ref.c（官方参考实现）
- testvectors/blake2bp-kat.txt、blake2sp-kat.txt（各 256 组，密钥 00..3f，输入长度 0..255）
关键常量（IV / sigma / 旋转量 / 参数块布局）全部从源码逐字节提取，不凭记忆书写。

### 验证
- 官方 KAT：bp 256/256、sp 256/256
- 等价对照：hi/lo 快速版 vs BigInt 预言机，72 组（18 种长度 × 有/无密钥）全部一致
- 解压目录独立复算：24/24

### 关键实现要点
1. 消息按「块」轮转分配（bp 128B×4、sp 64B×8），不是按字节交错，也不是顺序切段
2. 叶子的 outlen 被强制设为 inner_length，与 root 不同
3. last_node：root 恒置，仅最后一个叶子置；决定末块 f[1] 是否全 1
4. 参数块为 packed struct：b 版 node_offset@8、node_depth@16、inner_length@17
5. root 不吸收密钥块，只在参数里记录 key_length

### 踩坑
1. **BLAKE2s 的 G 旋转量抄成了 BLAKE2b 的** —— 用了 32/24/16/63，官方是 16/12/8/7。
   表现是 sp 256 组全错。典型的"照抄兄弟实现"，且自洽检查发现不了。
2. **BigInt 版太慢** —— bp 初版 31.60 ms/64KB（项目内 blake2b 为 4.89）。
   改用 hi/lo 双 32 位字重写 BLAKE2b 内核后降到 3.20 ms（快 9.9 倍），
   sp 1.00 ms。改写前先用 BigInt 版做等价对照，改完逐组比对一致。
3. 上一轮"字节级交错分配"的猜测被官方源码证伪（实际是块级轮转）——
   再次印证：拿不到参考时先找参照物，不要靠推理定实现。

### 其他
- 交付包移除 mce*.pk/sk（此前误打包的 McEliece 测试二进制，无任何代码引用）
- 打包后文件数 59，index.html ✓

## 第三十九批：FrodoKEM 官方参考实现打通

**突破**：FrodoKEM-640-SHAKE 官方 C 实现在本沙盒编译运行成功，产出权威向量。
之前卡在"编译"这一步，现已解决。

**来源**：liboqs（Open Quantum Safe）内置 FrodoKEM 官方实现
`oqs/liboqs-main/src/kem/frodokem/external/`，12 个方案齐全（640/976/1344 × aes/shake，
含 eFrodo 变体）。

**编译要点**（自包含，未走 cmake）：
- 需提供 oqs/kem_frodokem.h、oqs/sha3.h、oqs/oqs.h、oqs/aes.h、oqs/sha3x4.h、oqs/common.h
- `OQS_MEM_BLACK_BOX` 是**宏** `#define OQS_MEM_BLACK_BOX(v) (void)v`，不是符号；
  按变量定义会导致段错误（被当函数调用）
- 不定义 OQS_DIST_X86_64_BUILD / OQS_USE_AVX2_INSTRUCTIONS 即走 portable 路径
- shake128 用 liboqs 自带 XKCP `KeccakP-1600-opt64.c`（权威），
  并与 Python hashlib.shake_128 交叉验证 **8/8 一致**（含 rate 边界 167/168/169）
- keypair_derand / enc_derand 是空壳（返回 OQS_ERROR），必须走 randombytes；
  用 splitmix64 确定性替换，**已验证两次运行输出完全相同**

**参数（取自 kem_frodokem.h 原文，非记忆）**：
pk=9616 sk=19888 ct=9752 ss=16（注：efrodokem 的 ct 是 9720，不可混用）

**结果**：keypair → encaps → decaps，**2/2 match=1**

**产物**：
- `work/ref/frodo/`：可复现的 C 源码 + 构建脚本
- `work/testvectors/frodo640shake_c.txt`：向量（pk/sk/ct/ss）

**未完成**：JS 实现（需移植矩阵运算、CDF 采样、pack/unpack），本轮预算耗尽，下轮继续。

## 第四十批：FrodoKEM-640-SHAKE（3 个新算法，211 → 214）

### 来源
- 实现：逐行移植自 liboqs 内置官方实现
  - `ext/frodo/kem.c`（主流程）、`ext/noise.c`（CDF 采样）、`ext/util.c`（pack/unpack）
  - `ext/frodo_macrify_reference.c`（A 按行生成，keygen 用）
  - `ext/frodo_macrify_shake_portable.c`（A 按列生成，encaps/decaps 用）
  - `ext/frodo_macrify_optimized.c`（mul_bs / mul_add_sb_plus_e / add / sub / key_encode / key_decode）
- 参数：`frodo640shake_params.h` 原文，N=640 NBAR=8 LOGQ=15 EXTRACTED_BITS=2
- 标准状态：ISO/IEC 18033-2:2006/Amd 2 已标准化；德国 BSI 与欧盟 ENISA 推荐的 Level 1 后量子算法

### 验证
- 官方向量（C 参考运行 round1）**pk / sk / ct / ss 逐字节 4/4 一致**
- 界面入口端到端 **9/9**：官方 sk+ct 解出官方 ss、封装→解封装往返、keygen 长度、错误输入友好报错
- 健壮性 **9/9**：3 组随机种子往返 + 篡改密文必得不同密钥 + 长度校验
- 从 zip 解压目录独立复算 **4/4**

### 关键实现点
- **A 矩阵在 keygen 里按行生成、在 encaps/decaps 里按列生成**——两处索引方向相反，
  混用会得出长度正确但内容全错的结果
- `sk_S` 只存 S 的前 N*NBAR 个 uint16（= 2*N*NBAR 字节），**不含 E**。
  C 里 `memcpy(sk_S, S, 2*PARAMS_N*PARAMS_NBAR)` 的单位是字节，极易写成 2 倍长度（第一版就写错了，
  表现为 RangeError: offset is out of bounds）
- 所有累加都在 uint16 上回绕（mod 2^16），最后打包时取低 15 位——两者等价，
  所以中途不需要 mask 到 q
- `rndBytes` 又是 crypto_core.js IIFE 内的局部函数（本项目第 4 次：sm2ZA / bigToBytes / bigToHex / rndBytes），
  文件内自带实现

### 速度
keygen 约 559 ms，encaps 约 526 ms，decaps 约 506 ms（BigInt Keccak，未优化）

### 未完成
sntrup761：官方源码已在 `dl/liboqs-main/src/kem/ntruprime/sntrup761_openssh/`（2151 行），
2 组向量已在 `work/testvectors/sntrup761_vectors.txt`（pk 1158 / sk 1763 / ct 1039 / ss 32）。
但那份 C 是 supercop 风格、含 600+ 行常量时间 crypto_int16 辅助函数，一轮内移植风险过高，下轮再做。

## 第四十一批：SM9 标识加密（IBE）

新增 3 个算法（214 → 217）：
- `sm9-keygen-enc` 加密密钥生成（msk_e / mpk_e / de）
- `sm9-kem` 标识密钥封装（封装 / 解封装）
- `sm9-enc` 标识公钥加密（KEM + DEM）

验证：与 gmalg 官方库交叉，私钥提取、封装 C1/K、解封装、DEM 密文逐字节一致 44/44；
签名 45/45、配对 18/18、塔域 72/72 回归通过，t_all 脚本 51/51、算法 217 无重复。

**关键修正：G2 字节序一直是反的。**
sm9G2ToHex / sm9HexToG2 原先按 (c0‖c1) 序列化，GM/T 0004 与 gmalg 均为
**高次在前 (c1‖c0)**。此前只用于内部自洽（配对、签名的 G2 输入由用户填），
所以从未暴露；一旦要与官方库交换私钥字节串，立刻错位。

## 第四十二批：输入框开关缺失修复（算法数仍 217）

用户反馈「X448 只给对方公钥，私钥往哪填」。根因是注册时漏写 `key: true`，
而 `updateAlgoUI` 用 `!a.key` 隐藏 keyField——标签文案写了，框却从不显示。

新增 `t_label_switch.js` 扫描「有 keyLabel/paramLabel 但开关未开」，一次扫出 9 个：

| 条目 | 缺失 | 后果 |
|---|---|---|
| **x448** | key | 无私钥框（用户报的） |
| **ed448** | key + param | **私钥框和公钥框都不显示，完全无法使用** |
| cshake128 / cshake256 | key | 定制串 S 无法填 |
| eme2 / xcb | param | 关联数据 AD 无法填 |
| cbc-essiv | param | 扇区号 LBA 无法填 |
| hctr2 | param | tweak 无法填 |

### 顺带挖出 ed448 一个更深的实现 bug
`var msg = p ? new Uint8Array(0) : new Uint8Array(0)` —— 两个分支都返回空数组，
**待签消息恒为空**，导致任何非空消息的签名都验不过。
改法：输入区统一放待签消息，参数栏用「签名Hex,公钥Hex」（沿用 nonceHex[,aadHex] 惯例）。

### X448 / ed448 增强
两者现在「密钥栏留空 → 生成新密钥对」，与 X25519 行为一致。

### ⚠ 测试陷阱（记在此以免重犯）
不要用 `node - <<EOF` 跑本项目脚本：stdin 方式下测试脚本的 `const` 会进入全局词法环境，
与 `Encryption_and_decryption_logic.js` 的同名 `const mk` 冲突，导致 logic.js 加载中断、
`SHA256_K` 等常量缺失，内置自检会**误报 14 项失败**。必须写成 .js 文件运行。

### 验证（全部从解压目录独立复算）
X448 对拍 Python cryptography 6/6；X448 入口 12/12；Ed448 11/11（含篡改消息/换公钥必失败）；
开关回归 22/22（留空仍工作 + 填参数行为正确）；内置自检 18/18；
脚本 51/51、算法 217 无重复、标签/开关不一致 0、说明超 200 字 0。

## 第四十三批：Keccak 提速 2.7×、新增 Ascon 家族（217 → 219）

### 一、Keccak 家族提速（SHA3/SHAKE/cSHAKE/KMAC 全部受益）
原实现内层循环每轮都在算 `(x+1)%5`、`(x+2)%5`、`(2x+3y)%5`（25×24=600 次取模/块），
并访问二维表 `KEC_ROT[x][y]`。改为加载时预计算扁平表：
- `KEC_ROTF[i]` ρ 旋转位数、`KEC_PI[i]` π 落点、`KEC_X1/X2[i]` χ 索引、`KEC_TP1/TM4` θ 索引
- θ 第二步与 ρ+π **合并**：直接读 S、异或 D、旋转、写 B，省去原来"先写回 S 再从 S 读"的 25 次写+25 次读
- 临时数组提到模块级复用（keccakF 无重入/并发），64KB 输入下省约 3000 次分配

等价性：优化前后 220 组输出逐字节一致；官方向量与依赖算法全过
（SPHINCS+ 5/5、ML-DSA 45/45、HQC 3/3、BLAKE3 21/21、SHA-3 正确性 6/6）。

| 条目 | 优化前 | 优化后 |
|---|---|---|
| sha3-256 | 4.63 ms | **1.72 ms** |
| sha3-512 | 6.20 ms | **3.25 ms** |
| shake128 / shake256 | 2.75 / 3.34 | **1.41 / 1.73** |
| cshake128 / cshake256 | 2.80 / 3.35 | **1.43 / 1.74** |
| kmac128 / kmac256 | — | **1.48 / 1.79** |

### 二、新增 Ascon-128a AEAD + Ascon-Hash256（各 1 条，共 2 条）
来源：官方 C 参考实现 `ascon-c`（codeload 整包下载），常量取自
`constants.h`（IV 拼装规则）、`round.h`（置换）、`aead.c` / `hash.c`（流程）。

- **ascon128a**：NIST SP 800-232 轻量级 AEAD。密钥 16B、nonce 16B、tag 16B、rate 16、pb 8。
  **官方 LWC KAT 1089/1089**（加密逐字节一致 + 解密往返 1089/1089）。
- **ascon-hash256**：32 字节摘要，rate 8，全程 P12。**官方 LWC KAT 1025/1025**。

官方 KAT 已固化进包（`testvectors/ascon128a_aead_kat.txt`、`ascon_hash256_kat.txt`），解压后可独立复算。

**Ascon-128（rate 8）未注册**：官方包里只有 128a 的 KAT，没有 rate=8 变体的独立向量。
按"没验证不上线"的规矩移除，不塞进列表。

### 三、踩坑记录
1. **测试脚本正则跨行匹配**（最隐蔽）：KAT 解析用 `PT\s*=\s*([0-9A-Fa-f]*)`，
   `\s*` 吃掉换行后，下一行的字段名 **"AD"** 被当成 PT 的值（A、D 都在 hex 字符集内）。
   表现为 1089 组里 65 组失败，且失败全部集中在 ad=1 或 pt=1 —— 一度以为是实现的边界 bug。
   改用 `^[ \t]*=[ \t]*([0-9A-Fa-f]*)[ \t]*$` + `m` 标志后 1089/1089 全过。
   **实现从头到尾是对的，错的是解析。**
2. **pypi 的 `ascon` 库不可信**：它对官方 KAT 第一组就对不上（旧版本实现）。
   差点拿它去验 Ascon-128。教训：第三方库必须先拿已知官方向量校准，再当参照物。
3. **Whirlpool 官方向量又被我记错**：`_wp_test.js` 里 "message digest" 和 62 字节那两条期望值是凭记忆写的，
   其中一条结尾是我编的 `...3a4b5c6d7e8f9`（**长度只有 125 个 hex 字符，根本不可能是 64 字节**）。
   已安装绑定官方 C 参考实现的独立包（`lib/nessie.h` 同源），交叉验证 **9/9 全过**，证明实现正确、期望值错误。
   现用该独立实现生成的 7 条权威向量替换，测试 **7/7**。
   **这是本项目第 N+1 次"参照物错了"，且同一条假数据曾被我发现过一次却没清理干净。**
4. **Whirlpool 预计算源索引表**：`((i-k+8)%8)*8+k` 改为查表 `WP_SRC`。
   等价性 500/500、官方向量 7/7，但 **速度无实质提升**（5.74 → 5.77 ms，噪声内）——JIT 本就优化掉了取模。
   保留改动（无害、更清晰），但不计入提速成果。

### 四、打包修复
`_pack.sh` 里仍残留 `mce0.pk/.sk`、`mce1.pk/.sk` 的复制逻辑（此前误打进交付包的东西），已移除。
现包 65 个文件，含 index.html / style.css，无 McEliece 二进制残留。

### 五、验证汇总
- 脚本加载 52/52、算法 **219 无重复**、说明超 200 字 **0 条**
- Ascon-128a 1089/1089 + Hash256 1025/1025
- SHA-3 正确性 6/6、Whirlpool 7/7、SPHINCS+ 5/5、ML-DSA 45/45、HQC 3/3、BLAKE3 21/21
- 全部从 **zip 解压目录**独立复算通过

## 第四十四批：Threefish-512 + Skein-512（6 个新算法，232 → 238）

### 一、新增条目
| id | 说明 | 官方向量 |
|---|---|---|
| `threefish512` | 块 64 字节、密钥 64 字节、tweak 128 位（入口固定置 0） | Botan threefish.vec 5/5（含 1 条带 tweak） |
| `skein512-224` | Skein-512 输出 224 位 | Botan skein.vec 256/256 |
| `skein512-256` | 输出 256 位 | 256/256 |
| `skein512-384` | 输出 384 位 | 256/256 |
| `skein512-512` | 输出 512 位 | 268/268 |
| `skein512-512-test` | 带个性化串 "Test" | 1/1 |

向量合计 **1049/1049**。

### 二、来源（全部照抄 Botan 2.19.5 官方源码，未凭记忆写常量）
- `src/lib/block/threefish_512/threefish_512.cpp`：轮常量、置换、密钥注入宏
- `src/lib/hash/skein/skein_512.cpp` + `.h`：UBI 流程、类型码（CONFIG=4 / PERSONAL=8 / MSG=48 / OUTPUT=63）、配置串
- 交叉验证另装了绑定官方 C 实现的 `pyskein`，先确认它与 Botan 向量一致才当参照物

### 三、踩坑（本批唯一一处实现 bug）
**JS 位移量取模 32**：配置串里输出位数写成 8 字节循环
```js
for (i = 0; i < 8; i++) cfg[8+i] = (outBits >>> (8*i)) & 0xff;
```
i=4 时 `>>> 32` 等价于 `>>> 0`，把低字节 0xE0 **复制到偏移 12**。
表现是「长度完全正确、只有内容错」——1037 组全错但看不出结构问题。
Botan 是 `store_le(uint32_t(output_bits), config_str+8)`，只写 4 字节，照抄后 1037/1037。

### 四、两个被澄清的"疑似 bug"（都不是 bug）
1. **Threefish 第 5 条向量有 `Tweak` 字段**：入口分组密码固定 tweak=0，
   该条需从内部函数验证（`_test` 钩子），已补进测试，**通过**。
2. **调试打印误导**：首版调试函数按 LE 字节序打印（lo 在前），
   而期望值是 64 位大端表示，一度误以为奇偶字高低位反了。
   改用 `hi<<32|lo` 打印后一致。**代码是对的，是打印方式错了**
   ——本项目第 N 次栽在"参照物/检查方式错了"。

### 五、验证
- 脚本加载 62/62、算法 **238 无重复**、说明超 200 字 **0 条**
- 从 zip 解压目录独立复算同样 1049/1049

## 第四十五批（2026-10-17）：PBKDF1 / CBC-MAC ×2 / X9.19 MAC / KDF1 / KDF2 + SHA-1 边界 bug

新增 6 个算法，238 → 244。

### 新增条目与向量
| 条目 | 向量来源 | 结果 |
|---|---|---|
| pbkdf1 | Botan pbkdf/pbkdf1.vec | 5/5 |
| cbcmac-des | Botan mac/cbcmac.vec [CBC-MAC(DES)] | 33/33 |
| cbcmac-aes128 | 同上 [CBC-MAC(AES-128)] | 48/48 |
| x919-mac | Botan mac/x919_mac.vec | 6/6 |
| kdf2 | Botan kdf/kdf2.vec [KDF2(SHA-160)] | 76/76 |
| kdf1 | Botan kdf/kdf1.vec [KDF1(SHA-160)] | 6/6 |

### ⚠ 挖出一个影响已有功能的真 bug：SHA-1 在 len ≡ 55 (mod 64) 时全错
crypto_otp.js 的 sha1Bytes 里总长写作 `floor((len+9)/64)+1`，
当 len+9 恰好是 64 的整数倍（即 len ≡ 55 mod 64）时会**多算一整块**。
- 直接后果：KDF2 第 29 组（secret 33 + counter 4 + salt 18 = 55 字节）算错，
  且是 76 组里**唯一**一组——典型的"大样本测不出来"。
- 波及范围：HOTP/TOTP 走 HMAC-SHA1 时内部长度是 64+len，
  所以**消息长度 ≡ 55 (mod 64) 的 TOTP 会验不上**（修复前 HMAC-SHA1 len55 实测不符）。
- 修复：`total = ceil((len+9)/64)*64`。
- 复验：0..130 共 131 种输入长度与 Node crypto 逐字节比对，0 处不一致；
  HOTP RFC 4226 10/10、TOTP RFC 6238 3/3 保持通过（无退化）。

### 其它
- 语义按 Botan 官方 C++ 移植：CBC-MAC 状态初值全零、收尾不足一块**也要加密一次**；
  X9.19 为 `mac = DES1( DES2⁻¹( state ) )`，密钥 16 字节时 K2 取后 8 字节。
- KDF2 = 串联 Hash(secret‖BE32(counter)‖label‖salt)，counter 从 1 起；
  KDF1 = Hash(secret‖label‖salt)，**无计数器**，故最多一个摘要长度（20 字节）。
- 测试的 PBKDF1 / KDF 期望长度按 Output 实际长度截取（Botan 向量里 dkLen 并不都是 20）。

### 回归（zip 解压目录独立复算）
脚本 63/63 加载、244 个算法无重复、说明超 200 字 0 条；
新算法向量 174/174；HOTP 10/10、TOTP 3/3、HMAC-SHA1 len55 ✓。

### 仍未做
HAVAL×3、CLEFIA（Botan 无对应 vec，需另找权威源）；
ECVRF、RSA 盲签名、DRBG、Paillier、BLS 聚合、sntrup761、BIKE/NTRU、
Picnic、AEGIS、PRESENT/LEA、XMSS/LMS、McEliece/FrodoKEM 更多参数集、MPC、FHE。

## 第四十六批：全量测速基准 + Base62 解码优化（算法 244 不变）

### 交付：列出全部算法清单并跑全量测速（64KB，取多次最优）
- 脚本 63/63、算法 244 无重复、说明超 200 字 0 条、解压目录独立复算通过。

### 优化尝试与结论（诚实记录失败）
1. **Base58「4 字节一块 + Int32Array」：失败，已回滚**
   迭代次数降到 1/4，但 `Int32Array` 上的浮点取模（`x % 58`）比整数位运算
   （`digits[j] << 8`）慢得多，抵消收益：10.4s → 13.1s。原实现保留。
2. **Base62「digits 数组法」：失败，已回滚**
   21.9s，反而比 BigInt 原实现的 3.8s 慢 5 倍。原因同上：JS 数组逐字节
   除法的常数远大于 BigInt 的 GMP 级批量运算。
3. **Base62 解码端：成功**
   原实现 `out.unshift()` 每次搬移整个数组（O(n^2)），改为 push + reverse；
   编码端 `s = c + s` 前置拼接同样改为 push + reverse + join。
   解码 64KB：691.71 ms（原实现 >3s）。编码 3794 ms 基本不变——
   说明编码瓶颈在 BigInt 逐字节建大数本身，不在拼接。

### 结论
Base58/Base62 是 O(n^2) 进制转换，64KB 下 10s / 3.8s 属 JS 合理水平。
真正提速需分治进制转换（Karatsuba 类），复杂度 O(n^1.58)，留作后续。
说明中已建议用于短数据（地址 / 短链），避免编码大文件。

## 第四十七批：GMAC / NIST SP 800-108 KDF / OpenPGP S2K / HMAC-DRBG

**新增 6 个算法（244 → 250）**：gmac、sp800-108-ctr、sp800-108-fb、sp800-108-pipe、pgp-s2k、hmac-drbg
**官方向量 2068/2068**（GMAC 15、SP 800-108 三种模式各 120、OpenPGP S2K 13、HMAC-DRBG 1680）

### 向量来源
全部取自 Botan 2.19.5 `src/tests/data/`：
`mac/gmac.vec`（Bouncy Castle 生成）、`kdf/sp800_108_{ctr,fb,pipe}.vec`（Bouncy Castle）、
`pbkdf/pgp_s2k.vec`（Golang x/crypto/openpgp）、`rng/hmac_drbg.vec`（源自 NIST CAVS drbgtestvectors）。
实现逐行对照 Botan 官方 C++：`sp800_108.cpp`、`pgp_s2k.cpp`、`hmac_drbg.cpp`；
SHA-224 / SHA-384 的初始向量分别从 `sha2_32.cpp` / `sha2_64.cpp` 的 `clear()` 原文提取。
向量已固化进包（`testvectors/`），解压后可独立复算。

### 关键语义（都不靠猜，来自源码）
- **GMAC**＝明文为空的 GCM tag：`GHASH_H(A‖补零‖BE64(lenA·8)‖BE64(0)) ⊕ E_K(J0)`；
  IV 为 12 字节时 `J0 = IV‖0^31‖1`，**否则走 GHASH 路径**（Botan 有一条 IV 只有 4 字节的向量专门覆盖）。
- **SP 800-108** 三种模式的分隔符 0x00、Counter 的 `BE32(i)` 前缀、结尾 `BE32(L·8)` 全部按源码；
  Feedback 的 IV 只在 `len(Salt) ≥ prf_len` 时取 Salt 前 prf_len 字节（否则为空），余下才是 ctx；
  Pipeline 的 `A(0)=Label‖0x00‖Salt‖BE32(L·8)`，`A(i)=PRF(A(i-1))`。
- **OpenPGP S2K** 每轮前置 `pass` 个零字节，输入按 `max(迭代数, len(input))` 循环重复。
- **HMAC-DRBG** 按 `test_rng_kat.cpp`：初始化 → 重播种 → **连续两次** `randomize_with_input`，
  第一次结果被覆盖丢弃，**Out 取第二次**；AdditionalInput1/2 分别喂给这两次调用。

### 踩的坑
1. **环境没有同步 SHA-384 内核**：`hmacBytesSync('SHA-384',…)` 内部返回 null，
   表现为"毫无征兆的 null 拼接崩溃"。改为自带 IV 调 `sha512Core`，并与 Node 的 SHA-384 对拍确认。
   同理补了 SHA-224 / SHA-512-224 / SHA-512-256，才覆盖满 1680 组。
2. **PGP S2K 爆栈**：迭代次数可达千万级，按"逐段 push 再 `cat.apply`"会
   `Maximum call stack size exceeded`。改为先算总长、一次性写入 Uint8Array。
3. **HMAC-DRBG 一开始全错**：只因漏了 `AdditionalInput1/2` 与"取第二次输出"这两点；
   用 Python 独立实现 960/960 复现后才定位——**又是我给的调用流程错，不是实现错**。
4. 测试脚本打印期望值时只截了 40 字符，一度以为 Out 是 20 字节，实际是 80 字节。

### 验证
- dist：脚本 64/64 加载、ALGOS 250 无重复、说明超 200 字 0 条
- 健壮性 48 次调用无非 Error 抛出；GMAC 篡改必变；DRBG 同输入确定性一致；
  SP800-108 输出长度精确；S2K 迭代模式无盐已拒绝
- **zip 解压目录独立复算：2068/2068**

---

## 第四十八批：侧信道加固（算法层）+ IDEA 官方向量补齐

### 背景

外部代码评审指出三处侧信道/健壮性问题，本轮按「能改的改掉、改不动的说清楚」处理。

### 1. Blowfish π 常量：运行时计算 → 硬编码 + 完整自检（已修）

原实现在初始化时用 BigInt 展开 π（Machin 公式）生成 P 盒 18 项 + S 盒 1024 项。
风险不在速度，而在**若展开精度不足会静默产生非标准常量**——能加解密、与自身往返全绿，
却与别的实现不互通，正是本项目最怕的那类 bug。

改为硬编码标准的 8336 位十六进制展开，启动时校验：

- 4 个锚点：P[0]=`243f6a88`、P[17]=`8979fb1b`、S[0]=`d1310ba6`、S[1023]=`3ac372e6`
- 3 个 FNV-1a 校验和：P 表、S 表、整表 1042 项

任一不符即抛错，不再静默。

> 附带发现：`3ac372e6` 正是之前 bcrypt 那轮我凭记忆误当成 P[17] 的值，它实际是 S[1023]。

### 2. modPow：平方-乘 → Montgomery ladder（已修）

原「平方-乘」**只在指数位为 1 时做乘法**，分支与私钥位相关。
ladder 每步恒定做「两次乘法 + 一次常量时间选择」：

```js
const sel = x1 ^ (m & (x1 ^ x2));   // m = 0n - bit，位为 1 → 全 1
x1 = (x1 * sel) % mod;
x2 = (x2 * sel) % mod;
```

推导出自同一式子：bit=1 时 `x1'=x1*x2, x2'=x2*x2`；bit=0 时 `x1'=x1*x1, x2'=x2*x1`，
两者都可写成 `x1'=x1*sel, x2'=x2*sel`，分支因此合并。

### 3. ideaMul：分支 → 全掩码（已修）

`a === 0` 与 `x < 0` 两个分支随输入变化。改为 `v & -(cond)` 掩码形式
（JS 中 `-(true) = -1` 位模式全 1、`-(false) = -0` 位模式全 0）。

### 无法规避的部分（已写入 README）

- BigInt 底层运算本身不是常量时间
- S 盒查表的缓存侧信道，JS 无任何手段防御
- **椭圆曲线标量乘仍是变时的**（SM2/SM9/BLS12-377/BN254/Ed25519/X448 等），
  改 ladder 需处理条件交换与无穷远点，风险高，单独排期，已在 README 明示

### 验证

| 项目 | 结果 |
|---|---|
| Blowfish × pycryptodome（200 组随机） | **200/200** |
| bcrypt × Python bcrypt 5.0（绑定 OpenBSD） | **7/7** |
| IDEA × ETH 官方向量（新固化） | **11/11**，解密往返 11/11 |
| IDEA 改造前后等价（确定明文 300 组） | **300/300** |
| modPow ladder × 平方-乘（3000 随机 + 8 边界） | **3008/3008** |
| ideaMul × 参考实现（全量 a × 8 个 b） | **524288/524288** |
| DH 协商端到端（含与独立幂比对） | **30/30** |
| 全量健康检查 | 脚本 **64/64**、算法 **250 无重复**、长说明 0 |

### 三个「参照物/调用姿势错了」

1. **IDEA 测试用随机明文** —— 改造前后对比时两次随机不同，误报 0/300。改确定性输入后 300/300。
2. **bcrypt 参数顺序** —— `enc(b, k, p)` 第一个是输入内容不是口令；我先传成 `enc(pw, salt)`，
   导致 salt 被忽略、cost 恒为 6。改用 `enc(null, pw, salt)` 后 7/7。
3. **bcrypt 参数格式** —— 是 `cost,salt22`，不是完整 `$2a$` 串，第一次按后者传同样被忽略。

### 新增文件

- `testvectors/idea_eth.txt` —— IDEA 官方向量（ETH 参考实现，多来源交叉确认），11 组
- `t_idea_kat.js` / `t_bcrypt_kat.js` / `t_ladder.js` / `t_bfsec.js` / `t_secfix.js`

### 同步

`dist/crypto_core.js` → `work/crypto_core.js`（两者算法 id 集合已确认完全一致后才覆盖）。

## 第四十九批：外部代码审查核实与修复

审查来自四位外部审阅者，逐条核实后区分「属实」「不成立」，并额外挖出一个审查未覆盖的真 bug。

### 确认属实并已修（6 条）
1. `pbkdf2Generic` 重复计算 —— 同一轮 U/T 完整算了两遍，第一次结果从未使用，
   `U0(a){return a;}` 是恒等空壳。功能正确（两次等价），性能翻倍浪费。删重复循环 + 空壳。
2. `x25519Derive` 空 if 块（1332-1333）—— 导致 WebCrypto 分支对 32 字节私钥永远不可达。删。
3. `ctsDec` 的 `pnPadded` —— 算完从未使用（后续用 `pn`）。删。
4. `mlkemDecaps` 的 c2/c 比较用 for+break —— 首个不匹配字节即退出，
   通过计时泄漏「密文是否被篡改」，构成 FO 变换的选择密文攻击面。改常量时间累积异或。
5. Frodo `ctSelect` 用三元表达式 —— 与函数名 ct 不符。改掩码选择。
6. `padTBC` 的 `if (p===0)` —— p 取值 1..bs 永不为 0，死分支。删并注明：
   长度对齐时补一整块是刻意为之（TBC 靠末字节取反识别，不补则去填充会误剥真实数据）。

### 不成立（2 条，有实测证据）
- **`mlkemCompress` 的 `% 2^d` 多余** —— 实测反驳：d=1 时有 832 个 x 使 `round(2^d*x/3329)`
  溢出到 2^d（如 x=3000 得 2，需 `%2` 回绕为 0）。该取模是标准 compress 公式的一部分，必要。
- **ZUC LFSR 模数** —— 实现已是 0x7fffffff（正确），源码注释里还记录着
  曾误写 0x80000000 的坑。无需修改。

### 额外发现（审查未覆盖，本轮最严重）
**PBKDF2 的 HMAC 迭代错误**：opad 只在最后一次补，中间每轮 Ui 缺 opad 层。
结果与 RFC 8018 / PKCS#5 v2 及 Node `pbkdf2Sync` **全不兼容**。
浏览器里因走 WebCrypto 而掩盖，SM3（pbkdf2Sm3）与 WebCrypto 回退路径则直接算错。
修正为每轮完整 HMAC 后，7 组参数（含多块、中文盐、4096 轮）与 Node 权威 7/7 一致。

判别方法：先复刻改动前逻辑与之对照，确认「旧版==新版但都!=Node」，
证明差异非本轮引入，是既有缺陷。

### 无法核实
第四批（HQC kemDecaps / Verkle vDecompress / IPA）描述过于笼统
（"参数传递""平方级复杂度""延展性漏洞"），且 IPA 在代码中无同名函数。
需审阅者给出具体函数名或行号才能定位。

### 验证（解压目录独立复算）
脚本加载 64/64、算法 250 无重复、PBKDF2 vs Node PASS、ML-KEM 往返+篡改 6/6、
Frodo 官方向量 pk/sk/ct/ss 全 PASS。

## 第五十三批：Devnet6 创始状态根验证（Verkle）

### 结论
用本项目的 Verkle 实现重算 rust-verkle 官方 devnet6 创始状态根，**逐字节命中**：

```
期望  = 1fbf85345a3cbba9a6d44f991b721e55620a22397c2a93ee8d5011136ac300ee
实算  = 1fbf85345a3cbba9a6d44f991b721e55620a22397c2a93ee8d5011136ac300ee
```

### 向量来源（权威，非自造）
- 数据：`crate-crypto/rust-verkle` → `verkle-spec/assets/devnet6_genesis.json`（278 个账户）
- 期望值：`verkle-spec/tests/devnet6.rs::genesis_state_root` 常量 `STATE_ROOT`
- 规范：`verkle-spec/src/{header,code,storage,parameters,util}.rs` 逐行对照

### 覆盖范围（1354 条 key:value）
| 部分 | 条数 | 涉及能力 |
|---|---|---|
| 账户头字段 | 278×4 | Pedersen hash64 键派生、swap_last_byte |
| code chunk | 209 | `chunkify_code`（含 PUSH1–PUSH32 跨块分析）+ keccak256 |
| storage slot | 31 | 大数偏移 `2^248 + slot` |
| code_size | 2 | U256 小端编码 |

同时验证了：`KECCAK_EMPTY`、地址 20→32 字节补零、`MAIN_STORAGE_OFFSET = 256^31`。

### ⚠ 实质发现：state_root ≠ root_hash
官方测试断言用的是 `root_commitment().serialize_compressed()`，
即**根承诺点的 Banderwagon 压缩序列化**；而此前界面主输出的是
`map_to_scalar_field` 的结果（Fr 小端）。两者**不是同一个值**：

```
state_root  = 1fbf85345a3cbba9a6d44f991b721e55620a22397c2a93ee8d5011136ac300ee
root_hash   = 70e409f642e358ccd90ff7527cdf98d815f02ae6439faaef4ae82005de5b8805
```

`map_to_scalar_field` 只用于把子节点承诺折叠进父节点，**不是区块里的状态根**。
已把主输出改为 state_root，root_hash 降为附注并在界面里写明区别。

### 踩坑（测试 harness，非实现）
1. 必须用**同一个 vm context** 逐文件加载。跨文件共享常量有的是 const/let，
   多次 `runInThisContext` 各开新脚本作用域会互相看不见，报假的「需要在
   Encryption_and_decryption_logic.js 之后加载」。
2. 算法注册走项目自己的全局 `ALGOS` 数组，外部 mock 的 `reg` 会被覆盖，
   读自建收集器只会得到 0 —— 必须读 `ALGOS`。
3. 浏览器 API 要 mock 齐（window.addEventListener / document / localStorage /
   btoa/atob），缺一个就在加载期抛「Cannot read properties of undefined」。

### 验证
- devnet6 走 **reg 注册的 enc 入口**（覆盖文本解析→建树→输出整条界面链路）：PASS
- 直调内部函数：PASS
- 全量：script 64/64、算法 250 无重复、说明超 200 字 0
- 从 **zip 解压目录**独立复算：devnet6 PASS、全量 OK、md5 与 dist 一致

### 需更新文件
```
crypto_verkle.js                    （唯一改动）
testvectors/devnet6_verkle.txt      （新增，176KB，可独立复算）
```
参考与生成脚本已固化在 `work/ref/devnet6/`（genesis.json、prep.py、run.js、devnet6_test.rs）。

## 第五十四批：SP 800-56A/56C、TLS PRF、X9.42、SRP-6a、CRC-24（244 → 257）

### 新增 7 个（上一批实现，本批完成收尾）
| id | 名称 | 官方向量 |
|---|---|---|
| sp800-56a | SP 800-56A 单步 KDF | Botan kdf/sp800_56a.vec 10 分节 |
| sp800-56c | SP 800-56C 两步 KDF | Botan kdf/sp800_56c.vec 4 组 |
| tls12-prf | TLS 1.2 PRF | Botan TLS-12-PRF 4 组 |
| tls-prf | TLS 1.0/1.1 PRF（MD5⊕SHA-1） | Botan TLS-PRF |
| x942-prf | ANSI X9.42 PRF | Botan kdf/x942_prf.vec 2 组 |
| srp6a | SRP-6a（RFC 5054） | Botan srp6a.vec 24 有效组 |
| crc24 | CRC-24（OpenPGP） | Botan hash/crc24.vec |

### 本批收尾内容
1. **说明超长归零**：6 条 info 超过项目自定的 200 字上限（srp6a 460、sp800-56c 295、sp800-56a 294、tls12-prf 278、x942-prf 250、crc24 240），压缩到 ~100-140 字，保留关键语义与验证结论。
2. **BUILD_INFO.algos 250 → 257**（dist 与 work 都已同步，work 此前还停在 223）。
3. **算法清单重新生成** 244 → 257，由脚本从 ALGOS 实际导出，不手抄。
4. 三个新文件（crypto_kdf_nist3.js / crypto_srp6.js / crypto_checksum2.js）此前只在 dist，已备份到 work。

### SKIP 24 的说明（不是失败）
srp6a.vec 共 48 组，其中 24 组用 BLAKE2b(224/256/384/512)，本条目只支持 SHA-1/224/256/384/512，故合理跳过。已脚本确认跳过项**全部**是 BLAKE2b，不是解析失败。

### 验证（从 zip 解压目录独立复算）
- 脚本加载 67/67、算法 257 无重复、说明超 200 字 0
- 官方向量 PASS 207 / FAIL 0 / SKIP 24
- 全部走 reg 注册的 enc 入口，覆盖界面整条链路

## 第五十六批：Classic McEliece 全 5 参数集 —— 封装/解封装官方向量 10/10

### 成果
5 个官方参数集（348864 / 460896 / 6688128 / 6960119 / 8192128）的
**封装（encaps）与解封装（decaps）全部通过官方向量，ct 与 ss 逐字节一致**：

```
348864   decaps PASS   encaps ct PASS ss PASS
460896   decaps PASS   encaps ct PASS ss PASS
6688128  decaps PASS   encaps ct PASS ss PASS
6960119  decaps PASS   encaps ct PASS ss PASS
8192128  decaps PASS   encaps ct PASS ss PASS
```

向量来源：PQClean clean 参考实现（`deps/PQClean-master/crypto_kem/mceliece<TAG>/clean`）
+ NIST AES256-CTR-DRBG，由 `mceall/katgen.c` 编译生成，已固化在 `mceall/kat/`。
复算入口：`work/mce_par/RUN.sh`（解压后可独立跑）。

### 核心突破：GFBITS=13 必须走 128 位 Benes
这是本轮最大的坑，也是之前声称"已做"却没做成的技术根因。

2^12 = 4096 bit = **64** × 64bit字 → 64 位 Benes（2*12-1 = 23 层）
2^13 = 8192 bit = **128** × 64bit字 → **128 位 Benes**（2*13-1 = 25 层）

两者**不是同一套代码**：128 位版把数据拆成 `r_int_v[0]/[1]` 两组各 64 字，
`layer_ex` 循环 128 个字（靠 C 数组内存连续把 `[2][64]` 当 `[128]` 用），
`layer_in` 分别对两组做、交替取 bits。25 层 × 512 字节 = 12800 = COND_BYTES，正好吻合。

实现在 `work/mce_par/b128.js`。**只换参数不改 Benes 位数，结果长度完全正确、过程无报错，
只有对官方向量才暴露** —— 典型的"自洽但全错"。

### 另外两个 bug（都是"参照物/理解错"，非实现错）
1. **6960119 的 syndrome 移位**：PK_NROWS = 1547，**不是 8 的倍数**（tail = 3），
   pk 行展开后要再做一次 `(row[j]<<tail)|(row[j-1]>>(8-tail))` 的从后往前移位。
   我第一版压根没读 pk 数据就去移位，结果全 0。
2. **8192128 的 gen_e 只取 SYS_T 个随机数**：因 SYS_N = 8192 = 2^GFBITS，
   所有 13 位数天然 < SYS_N，官方省掉了"取 2 倍再过滤"的策略（`#include "crypto_uint16.h"`
   都整个没了）。我按 SYS_T×2 个取，DRBG 消耗不同 → e 不同 → ct 错位。
   期间用"往返解密还原 e"定位到是 **e 不同而非 syndrome 错**，省了大量瞎猜。

### 参数表（全部取自 PQClean params.h / api.h 原文，未凭记忆）
| TAG | GFBITS | SYS_N | SYS_T | PK_ROW_BYTES | ct | pk | sk | Goppa 系数偏移 | bitrev |
|---|---|---|---|---|---|---|---|---|---|
| 348864 | 12 | 3488 | 64 | 340 | 96 | 261120 | 6492 | 3,1,0(×2) | >>4 |
| 460896 | 13 | 4608 | 96 | 420 | 156 | 524160 | 13608 | 10,9,6,0 | >>3 |
| 6688128 | 13 | 6688 | 128 | 628 | 208 | 1044992 | 13932 | 7,2,1,0 | >>3 |
| 6960119 | 13 | 6960 | 119 | 677 | 194 | 1047319 | 13948 | 8,0 | >>3 |
| 8192128 | 13 | 8192 | 128 | 816 | 208 | 1357824 | 14120 | 7,2,1,0 | >>3 |

GF(2^13) 的 gf_mul 约简常数与 GF(2^12) 完全不同
（13位: 0x1FF0000 / 0x000E000，移位 (>>9)^(>>10)^(>>12)^(>>13)）。
gf_inv 本轮统一用通用二进制幂 a^(2^m - 2)，正确性优先（348864 复验仍 PASS）。

### 尚未完成
- **密钥生成（keygen）**：需要参数化的 genpoly_gen（GF(2^13) 上的极小多项式）
  与 controlbits（w=13、n=8192 的递归），本轮未做。
- **未整合进 dist**：本轮成果在 `work/mce_par/`，界面算法数**未变**。

### 参考与脚本
```
work/mce_par/p.js      参数化核心（GF 运算 / supportGen / pkGen / decrypt）
work/mce_par/b128.js   128 位 Benes（GFBITS=13 专用）
work/mce_par/drbg.js   NIST AES256-CTR-DRBG（复现官方确定性随机）
work/mce_par/t_dec.js  解封装对拍
work/mce_par/t_enc.js  封装对拍
work/mce_par/RUN.sh    全 5 参数集一键复算
```

## 第五十七批：McEliece 6960119 pk 不匹配 —— 根因与修复

### 根因（JS 整数除法）
官方 pk_gen.c 输出循环：
```c
for (j = (PK_NROWS - 1) / 8; j < SYS_N/8 - 1; j++)
```
C 里 `int / int` 是整数除法：6960119 的 PK_NROWS=1547 → `(1547-1)/8 = 193`。
JS 直接照抄得到 **193.25**，用小数下标索引 Uint8Array 返回 `undefined`，
`undefined >> 3` = 0 → pk 几乎全零。
1047319 字节里仅 4139 字节"匹配"（都是 0，属巧合）。

修复：改用 `off = PK_NROWS >> 3`（= 193，与 C 整数除法结果一致）。

### 为什么只有 6960119 暴露
| 参数集 | GFBITS | SYS_T | PK_NROWS | %8 |
|---|---|---|---|---|
| 348864 | 12 | 64 | 768 | 0 |
| 460896 | 13 | 96 | 1248 | 0 |
| 6688128 | 13 | 128 | 1664 | 0 |
| **6960119** | 13 | **119** | **1547** | **3** |
| 8192128 | 13 | 128 | 2048 | 0 |

其余四个走 tail==0 分支（memcpy 等价路径），不经过这段循环，所以一直没暴露。
这又是一次"自洽发现不了、只有对官方向量才暴露"的类型。

### 验证（/data/mceall/kat/，PQClean clean + NIST AES256-CTR-DRBG）
```
keygen  sk MATCH  pk MATCH   ×5 参数集  = 10/10
348864  ✓✓   460896 ✓✓   6688128 ✓✓   6960119 ✓✓   8192128 ✓✓
encaps/decaps  6960119  ct PASS  ss PASS  dec PASS
```

### 未做
dist 整合（需浏览器端 AES-ECB DRBG + 5 套 UI 注册），本轮未做。
算法数未变。

## 第五十七批：McEliece 全 5 参数集整合进界面（算法 260 → 268）

- 新增 `dist/crypto_mceliece5.js`：参数化实现（GFBITS 12/13），含 128 位 Benes、GF(2^13) 极小多项式、Nassimi-Sahni controlbits
- 由 `work/build_mce5.js` 自动拼装：mcepar/b128.js + mcepar/p.js + work/mce_par/keygen.js，SHAKE256 取 dist 浏览器版（原 keygen.js 用 Buffer，浏览器不可用）
- 注册 8 个新条目：460896 / 6688128 / 6960119 / 8192128 的 KEM 与 keygen（348864 沿用原文件）
- 官方 KAT：keygen sk/pk 4/4 MATCH；官方密文解封装 4/4 PASS；官方公钥封装往返 4/4 PASS
- 耗时实测（Node）：keygen 460896 11s / 6688128 24s / 6960119 11s / 8192128 34s；封装与解封装均 < 0.3s
- 健康检查：script 69/69、算法 268 无重复、说明超 200 字 0
- 解压目录独立复算：4/4 PASS
- 坑：测试脚本第一版没把 DRBG 种子传进参数栏，keygen 报 DIFF——又是调用方式错，不是实现错


## 第五十七批：McEliece 浏览器致命缺陷修复（群友审查）

审查来源：交流群代码评审（针对 crypto_mceliece5.js）

### 1. 致命：process.env.* 残留（浏览器必崩）

`process` 是 Node 专有全局，浏览器中未定义。残留处：

- 715 行 `if (process.env.MCEDBG2)` —— 在 pkGen 末尾，**无条件求值**
- 766 / 776 行 `if (process.env.MCEDBG)` —— 在 keypair 重试循环内

后果：浏览器里一进密钥生成就抛 `ReferenceError: process is not defined`，
**McEliece 全部 4 个新参数集完全不可用**。

为何此前未暴露：测试全在 Node 里跑，`process.env` 存在且返回 undefined（falsy），
静默跳过。**只有模拟浏览器（无 process 的沙箱）才能发现**。

修复：改为文件内布尔常量 `var MCEDBG = false, MCEDBG2 = false;`

### 2. 恒假分支

862 行 `if (KEM_460896 && false) return;` —— 永假，删除。

### 3. 死代码

758 行 `skp = 0;` 紧接着被 `skp = 32 + 8;` 覆盖，删除。

### 4. int32sort 改用原生 TypedArray.sort

原实现 `Array.prototype.slice.call(sub)` → 拷贝 → 排序 → `set` 回写，
有额外分配开销。改为 `A.subarray(0, n).sort()`（Int32Array 原生为数值升序、原地）。

说明：官方 controlbits.c 用双调排序网络，此处输入为**公开置换**非秘密，
变时排序不构成侧信道风险，故用更快的原生实现（结果一致，已由 KAT 验证）。

### 5. tries > 8 抛错（保留，有意设计）

官方 `operations.c` 是 `while(1)` 无限重试。此处保留抛错上限，
目的是防止浏览器极端情况下无限卡死；8 次全失败概率可忽略。已核实为刻意取舍，非缺陷。

### 验证

浏览器沙箱模拟（vm context 内**故意不定义 process/require/Buffer**）：
```
加载成功，注册 8 个条目，process.env 残留 0
460896   keygen 4746ms   往返 195ms   pk/sk/ct 长度 OK  往返一致 OK  篡改改变 OK
6688128  keygen 34340ms  往返 296ms   同上
6960119  keygen 5739ms   往返 292ms   同上
8192128  keygen 36459ms  往返 363ms   同上
浏览器沙箱模拟: PASS 4 / FAIL 0
```

官方 KAT（NIST 标准种子 + PQClean clean 生成向量），用**修改后的 dist 文件**重跑：
```
460896   sk MATCH  pk MATCH
6688128  sk MATCH  pk MATCH
6960119  sk MATCH  pk MATCH
8192128  sk MATCH  pk MATCH
```

参数表 vs 官方 api.h 常量交叉核对 4/4 一致。

全量健康检查：script 69/69 加载、算法 268 唯一 268 重复 0、
说明超 200 字 0、McEliece 条目 10。

### 踩坑记录（本批 2 个，均为测试脚本自身问题）

1. **测试脚本调了两次 keygen**：第一次只取 sk、第二次取 pk，
   导致 pk 与 sk 不是一对，往返必然不一致 —— 表现为"全参数集往返失败"，
   极易误判为实现缺陷。修正为只调一次。

2. **测试脚本期望长度凭记忆填错**：把 6960119 / 8192128 的 sk 写成
   13908 / 14080（实为 13948 / 14120），误报"sk 长度不符"。
   已改为**从源码参数表解析**并与官方 api.h 交叉核对。
   这是本项目第 N 次"参照物错了"，教训：期望值一律从权威源解析，不手写。

### 顺带确认（无问题）

- 全 dist 扫描：`crypto_frodo.js` 的 `require('crypto')` 有 `typeof require === 'function'`
  守卫，浏览器中安全，无需处理。其余 crypto_*.js 无 Node 专有全局残留。

## 第五十八批（审查第 3 轮：crypto_mceliece5.js 三项清理）

评审指出三处（前轮修复后的残留），逐条核实**全部属实**：

1. **process.env 残留** —— 前轮已修（改为文件内布尔 `MCEDBG/MCEDBG2`），本轮复核无残留。
2. **变量重复声明** —— `var PARAMS = PM.PARAMS;` 在外层 IIFE 出现**两次**（第 433、439 行）。
   产生原因：`build_mce5.js` 拼装时，被拼入的密钥生成源码块自带一行 `var PARAMS = PM.PARAMS;`，
   而外层已有同名的声明。两者值相同，行为无害，但属重复声明。
   处理：删除靠后的一处（第 439 行）。
3. **死代码** —— `keypair()` 内 `var pi = new Int16Array(1 << GFBITS);` 分配后从未被读取，
   随即被 `pi = res.pi` 覆盖。改为 `var pi;`（不预分配）。
4. **重试逻辑不一致** —— `keypair()` 内部 `while(true)` + `tries > 8` 抛错（保留，防浏览器无限卡死）；
   而外层入口另有 4 处 `if (!res) throw "...请重试"`。由于 keypair 要么返回对象要么抛错，
   `!res` **永不可达**。已全部删除，统一为"内部重试、失败即抛错"单一契约。

### 注意（防止下次拼装丢失）
- `work/mce_par/keygen.js` 的 `pi` 死代码已同步修复。
- `keygen.js` 开头的 `var PARAMS = PM.PARAMS;` **保留**（它作为独立模块被 `t_keygen.js` require 时需要）。
  重复只在"拼装后"出现 —— 下次若重跑 `build_mce5.js`，需**重新删除靠后的那一处**。
- `work/build_mce5.js` 路径已指向旧的 `mcepar/` 目录，暂未改（避免改坏）。

### 验证
- 官方 KAT（用修改后的 dist 文件重跑）：460896 / 6688128 / 6960119 / 8192128 全部 **sk MATCH、pk MATCH**。
- 浏览器沙箱（无 process/require/Buffer）：加载成功、注册 8 条目、**PASS 4 / FAIL 0**，
  往返一致、篡改必变、参数表与官方一致。
- `node --check` 语法通过。

---

## 补记：第五十 / 五十一 / 五十二批（外部审查第 2~3 轮）与 sntrup761

> 这几批当时只更新了代码，没有写进 CHANGELOG，现补记。编号按实际发生顺序。

### 第五十批（审查第 2 轮）

外部审查指出三处，均属实且已修：

1. **HQC `kemDecaps` 的 for+break 比较** —— 上轮只改了 ML-KEM，HQC 这条漏了。
   for+break 在首个不匹配字节即退出，配合隐式拒绝会形成**解密预言机**：
   攻击者可通过计时判断「密文是否被篡改」。改为常量时间累积比较。
2. **`pbkdf2Generic` blockSize 写死 64** —— HMAC 的 blockSize 由具体哈希决定：
   SHA-512 / SHA-384 是 **128**，SHA-256 / SM3 才是 64。写死 64 导致
   **PBKDF2-SHA-512 / SHA-384 的回退路径算出与 RFC 8018 不一致的结果**。
   判别方式：复刻改动前逻辑做对照 ——
   `sha256 新==node YES / 旧==node YES / 新!=旧 否`；
   `sha512 新==node YES / 旧==node NO / 新!=旧 是` —— 证明是既有缺陷而非本轮改坏。
   浏览器因走 WebCrypto 掩盖了它，但 `pbkdf2Sm3` 与回退路径是实打实算错的。
3. **Verkle `vDecompress` 非规范编码** —— 原 `BigInt(hex) % V_Q` 会把 ≥ Q 的输入
   **静默归约后照常接受**，同一个点有多种编码表示，可用于承诺/证明的**延展性攻击**。
   改为先校验 `xRaw >= V_Q` 则拒绝。

同批另：`padTBC` 的 `if (p === 0)` 死分支删除（p 取值 1..bs）。

### 第五十一批（审查第 3 轮）

审查指出「blockSize 用 `outLen > 32` 反推属启发式」，**属实**：

| 哈希 | 输出 | 正确 blockSize | 启发式结果 |
|---|---|---|---|
| SHA-256 | 32 | 64 | 64 ✓ |
| SHA-512 | 64 | 128 | 128 ✓ |
| SHA-384 | 48 | 128 | 128 ✓ |
| Streebog-512 | 64 | **64** | 128 ✗ |
| SHA3-512 | 64 | **64** | 128 ✗ |

即**当前四个都碰巧对，但接 Streebog-512 / SHA3-512 会静默算错**。
改为调用方显式传参；另 `vDecompress` 的 `% V_Q` 已冗余（上面已拒绝 ≥Q），删除。

### 第五十二批：一次「假修」的承认

用户直接比对 md5，发现本批给出的 `crypto_modes.js` / `crypto_verkle.js`
**与上一轮同字节**（`e01cd600…` / `54e32d38…`）—— 即回复里声称的三处「已修」
**一条都没落地**，实际只改了 hqc / pqc_core / frodo 三个文件。

真改后 md5 变为 `ebbb16c1…`（modes）、`8fcd7916…`（verkle）。

**根因**：凭印象报改动清单、没有回头核对文件是否真的变了。
这是本项目反复出现的同一类错误（此前有「报 241 实际 232」「误报 CAST5 是 LGPL」
「误报 crypto_blowfish.js 存在」「声称 McEliece 4 套新增实际未落地」）。
**已定规矩：给改动清单前先跑一遍 md5 与上一版对比。**

### 第五十二批补：HMAC-SHA-384 同步路径一直是崩的

群友讨论 `pbkdf2Generic` / SHA-512 / SM3 / `vDecompress` / `padTBC` 时，
顺查发现**同款启发式在 `hmacBytesSync` 里还有一处**（RFC 6979 确定性 ECDSA 依赖它）。
改它时又发现：

**`crypto_core.js` 根本没有导出 `IV_384`** —— 只导出 IV_512 / IV_512_224 / IV_512_256，
所以 HMAC-SHA-384 那个分支**恒返回 null**：

```
HMAC-SHA-384 同步路径  → 直接崩
RFC 6979 + P-384       → 连带受影响
```

该常量此前只作为**局部变量**存在于 `crypto_nistkdf.js`，外部引用不到。
同样是既有缺陷，因浏览器走 WebCrypto 掩盖。

修复两处：
1. `hmacBytesSync` 改查表 + 未知抛错（不再用 outLen 反推）
2. `crypto_core.js` 补 `IV_384`（FIPS 180-4）+ `sha384Digest`

验证：HMAC 三哈希 × 3 种 keylen（含 130 字节触发 key 先哈希）9/9；
未知哈希 SHA3-512 / Streebog-512 / SM3 全部抛错 3/3 → 12/12；
关键回归 8/8（SHA-384 对 Node ✓、空输入 ✓、SHA-512 无退化 ✓、PBKDF2 同步/WebCrypto/SM3 ✓）。

### 第五十五批：sntrup761（3 个算法）

新增 sntrup761 密钥生成 / 封装 / 解封装。

- **官方向量 18/18**（pk / sk / ct / ss / 解密结果 / 长度逐字节一致）
- **往返 + 篡改 6/6**（密文动一字节即解出不同密钥，隐含拒绝生效）
- 界面入口 12/12

参照系是**官方参考实现在沙盒内编译**产出，不是自造。

挖出的两个 bug 都属「自洽测不出」类型：

1. **解包时多读一层** —— 某解码环节写成每次读 2 字节，官方是 1 个，多读 190 字节。
   不报错、不崩溃、中间数组看着也「合理」，就是结果不对。
2. **常量定义错** —— 把「密文主体长度」定义成含校验的 1039，官方是 1007，
   计算密钥时多喂 32 字节。**加密和解密都用了同一个错误值**，
   所以自己跟自己玩 100% 通过，只有与官方对照才暴露。

**同批承认**：上一轮声称的「McEliece 更多参数集」经核对 **dist 里只有 1 个，不是 5 个**，
那 4 套并未真正落地。与「报 241 实际 232」同类，后续单独补做（见第五十六/五十七批）。

另：为跑参照程序自写的 SHA-512 第一版结果全错 —— 填充时只清了前 8 个长度字节，
后 8 个是内存垃圾（空字符串时最明显）。修好后与 Python 标准库逐条对上，16 种长度全过。

---

## 第五十九批：LION 与 ChaCha_RNG（前两批判定"做不成"的两项，本批攻克）

上一批把这两项列为"不采纳/未做成"，理由是向量太少或调用语义无法确定。本批通过
精读 Botan 源码 + 反推官方向量，两项全部攻克并通过官方向量。

### 1. LION(SHA-160, RC4, 64) —— 新增算法

来源：Botan `src/tests/data/block/lion.vec`（1 组）+ `src/lib/block/lion/lion.cpp/h`。

**上一批失败的根因是三个结构误判，不是代码写错：**

| 项 | 上一批的误判 | 官方源码的实际语义 |
|---|---|---|
| `left_size()` | 当成 `block_size/2` = 32 | **= 哈希输出长度 = 20** |
| `right_size()` | 32 | **44**（= 64 − 20） |
| `key1/key2` 长度 | 16 字节（= key.length/2） | **20 字节**（resize 到 left_size 后清零，只填前 16，后 4 位恒为 0） |

关键点：`key_schedule` 里 `half = length/2 = 16`，但 `m_key1/m_key2` 被 `resize(left_size())`
即 20 字节并**先清零**再 copy，因此尾部 4 字节是补零而非密钥内容。

按此重写后**一次命中**官方向量（MATCH，逐字节）。

**向量扩充**：官方仅 1 组，不足以支撑回归。用按官方源码写的 Python 参考实现生成
24 组随机交叉向量（含 1/2/3 块），加密+解密往返全部自洽，固化进
`testvectors/lion_xvec.txt`。参考实现本身已被官方那 1 组锚定，故交叉向量可信。

### 2. ChaCha_RNG —— 新增算法

来源：Botan `src/tests/data/rng/chacha_rng.vec`（21 组）+ `chacha_rng.cpp` +
`stateful_rng.cpp` + `chacha.cpp`。

**上一批卡在"缺 tests/*.cpp，无法确定调用顺序"。本批用反推法定出：**

```
add_entropy(EI) → add_entropy(EIR) → generate(64, AI1)【丢弃】→ generate(64, AI2)【= Out】
```

即 Botan/NIST CAVS 的「连续两次生成、Out 取第二次」。判据：

- 第一组（EI = EIR = 全零、无 AdditionalInput）的 Out 精确落在 reseed 后
  keystream 的 **偏移 96** 而非 32 —— 差的那 64 字节正是被丢弃的第一次生成。
- 第二组（有 AI1/AI2）的 Out 前 32 与后 32 字节**同时**命中
  `HMAC(HKa1b, AI2)` 所在 keystream 的 off=32 与 off=64，证明两次 generate
  各自伴随一次 update，且 Out 只取第二次。

`update()` 语义照抄源码：`CK' = HMAC(HK, input)`；`HK' = ChaCha20(CK')` 前 32 字节。
`clear_state()` 的初始 HK 为全零，初始 CK = HMAC(全零 key, 空消息)。

结果：**21/21 全过**。

### 3. 本批我自己栽的坑：又把"标准值"记错了

验证 ChaCha_RNG 前先自测 ChaCha20，我拿记忆中的 keystream 标准值比对，
结果第 8 字节 `0x50` 对不上实现算出的 `0x40`，一度以为 ChaCha20 实现有错。

用 `cryptography` 库做独立裁判后确认：**实现是对的，是我记忆的"标准值"错了**。

这是本项目第 N 次"参照物错了"（此前有 Skein 位移量、bcrypt 参数格式、
RSA-KEM 的 C0/R、MCEDBG 等）。定下的规矩再次生效：
**期望值一律解析自官方文件或独立实现，不凭记忆手写。**

### 4. 验证数据（从 zip 解压目录独立复算）

```
脚本加载        71/71 成功
ALGOS           276   唯一 276   重复 0
说明超 200 字   0
LION            25 组 × 2（加密+解密）= 50   全过（含官方 1/1）
ChaCha_RNG      21 组   全过
健壮性          非法输入抛错 3/3
```

全部走 `reg` 注册的 `enc` 入口，覆盖「文本解析 → 算法 → 输出」整条界面链路。

### 5. 本批改动文件

| 文件 | 说明 |
|---|---|
| `crypto_lion_chacha.js` | **新增**，md5 `dbfe34eb4dae5b2d258207d065ded538` |
| `index.html` | 加一行 script 引用 |
| `Encryption_and_decryption_logic.js` | 版本号 274 → 276 |
| `算法清单.txt` | 重生成 |
| `testvectors/lion_xvec.txt` | **新增**，25 组（含官方 1 组） |
| `testvectors/chacha_rng.vec` | **新增**，Botan 官方 21 组 |


---

## 第六十一批：ECDSA 公钥恢复 / HKDF-Expand-Label / Passhash9（算法 282 → 286）

### 新增 4 个算法

| id | 名称 | 官方向量 |
|---|---|---|
| `ecdsa-recover` | ECDSA 公钥恢复（从签名还原公钥） | Botan `pubkey/ecdsa_key_recovery.vec` 2/2 |
| `hkdf-expand-label` | HKDF-Expand-Label（双语义） | Botan `hkdf_label.vec` 4/4 + OpenSSL 真实会话 9/9 |
| `passhash9` | Passhash9 口令哈希（Botan `$9$`） | Botan `passhash/passhash9.vec` 1/1 |
| `passhash9-verify` | Passhash9 校验（恒定时间比对） | 同上 1/1 |

### ⚠ 最重要的发现：HKDF-Expand-Label 有两个官方语义

`tls13 ` 前缀**不是**所有规范都加：

| 规范 | info 结构 | 验证来源 |
|---|---|---|
| RFC 8446（TLS 1.3） | `BE16(len)‖len(‖"tls13 "+label)‖"tls13 "+label‖len(ctx)‖ctx` | OpenSSL 3.0.2 真实会话 |
| Botan / BoringSSL Go 版 | `BE16(len)‖len(label)‖label‖len(ctx)‖ctx`（**无前缀**） | Botan `hkdf_label.vec` |

先用 Botan 向量跑，4/4 全错；而同一份代码解密真实 OpenSSL 会话却 9/9 全对 ——
两个方向相反的证据才逼出「同名不同义」的结论。**这与第五十四批 SP 800-56C
（展开步不是 56A 而是 108 Feedback）是同一类坑。**

处理：做成显式开关 `prefix=tls13`（默认，加前缀）/ `prefix=none`（不加），
**不自动猜测** —— 静默降级正是这类 bug 的根源。

### 权威验证：OpenSSL 真实 TLS 1.3 会话端到端

Botan 向量不足以证明 TLS 1.3 语义，故另建端到端链路：

1. `openssl s_server` / `s_client` 跑真实 TLS 1.3 握手（强制 `TLS_AES_128_GCM_SHA256`）
2. 用 `-keylogfile` 导出 OpenSSL **自己算出**的 traffic secret（权威参照物）
3. 用界面入口 `hkdf-expand-label` 派生 key/iv
4. 用 Python `cryptography` 的 AES-GCM 解密 Python 代理抓到的真实记录

结果：**9/9 条加密记录全部解密成功**（AES-GCM tag 校验通过 = key/iv/nonce/AAD 全对）：

| 记录 | 密钥 | 解出内容 |
|---|---|---|
| c2s #0 | CHS | ClientFinished（36B） |
| c2s #1 | CAS | close_notify alert（2B） |
| s2c #0~3 | SHS | EncryptedExtensions / Certificate / CertVerify / Finished |
| s2c #4~5 | SAS | NewSessionTicket ×2 |
| s2c #6 | SAS | close_notify alert（2B） |

### 踩坑（全部是「参照物错了」，实现本身没问题）

1. **TLS 1.3 的 seq_num 在每个密钥世代归零重置** —— 切换 handshake→application 密钥时
   seq 不连续。第一版按连续编号，application secret 那几条全判失败；改成按世代独立
   计数后立刻 9/9。
2. **握手记录用 handshake traffic secret，不是 application** —— 一开始把两条记录都用
   `CLIENT_TRAFFIC_SECRET_0` 去解，全失败。
3. **Passhash9 字段布局** —— 官方是 `alg_id(1)‖work_factor(2 字节 BE)‖salt(12)‖hash(24)`
   共 39 字节，我测试脚本按 `wf` 1 字节、`salt` 从偏移 2 解析，得到 wf=0 而抛错。
   **实现是对的，是解析错了。**
4. **`s_server` 不支持 `-keylogfile`**；且 `-naccept 1` 会把「就绪探测连接」当成真实连接
   而提前退出 —— 就绪检测改成纯等待。
5. **EAX/OCB 回归脚本没按 tagLen 比较** —— EAX 的 `got` 前缀与 `exp` 完全一致只是没截断；
   OCB 压根没传 `tagLen`。修脚本后 EAX 106/106、OCB 42/42（此前显示 104/2 与 41/1）。

### 顺带修的可用性缺陷

官方向量的 label 是 `TLS 1.3, something or other`，**自带逗号**，而入口用逗号分隔参数会被
切成两半（长度看不出异常）。新增 `_splitParams` 支持双引号包裹字段。

### 验证

```
脚本加载        73/73
ALGOS           286  唯一 286  重复 0
说明超 200 字   0
BUILD_INFO      algos 286 → 一致
misc6 官方向量  12/12（含界面入口 4/4）
EAX 106/106   OCB 42/42
TLS 1.3 端到端 9/9
```

---

## 第 63 批：分组密码密钥编排复用优化（NOEKEON / MISTY1 / KASUMI / Threefish-512）

### 背景

上一批修 CAST-256 时发现：它每个数据块都要重算一次密钥编排，64KB 数据 = 白算 4096 次。
顺着这个思路扫了全项目同类写法，定位到 4 个算法同样中招。

### 改动

| 文件 | 改动 |
|---|---|
| `crypto_noekeon.js` | 拆出 `noekeonEncKS/DecKS`，导出 `keySchedule`；原 `Enc/Dec(pt,key)` 保留为包装 |
| `crypto_misty1.js` | 同上，另在 `keySchedule` 里预切 4 段轮密钥（原来每块 subarray 4 次） |
| `crypto_kasumi.js` | 同上 |
| `crypto_skein.js` | 拆出 `tf512EncKS/DecKS`，导出 `tfSetKey` |
| `crypto_lightweight.js` | 新增 `mkKs()` 包装，noekeon/misty1/kasumi 改走它；threefish512 同理 |

保持向后兼容：所有 `*Enc(pt,key)` 原签名不变，测试脚本无需改。

### 提速（64KB，同一脚本 A/B、预热后）

| 算法 | 旧 | 新 | 提速 |
|---|---|---|---|
| MISTY1 | 12.7 ms | 1.5 ms | 8.3x |
| KASUMI | 7.0 ms | 2.4 ms | 2.9x |
| NOEKEON | 3.3 ms | 1.5 ms | 2.2x |
| Threefish-512 | 4.1 ms | 3.5 ms | 1.2x |

### 验证

- **复用安全性 2880/2880**：30 组随机密钥 × 6 块 × 加解密 × 4 算法，
  "复用同一 ks" 与 "每块新建 ks" 结果逐字节一致 → 确认 Enc/Dec 不污染 ks。
  关键风险点是 Threefish：`tfCore` 在 `feedfwd=false` 时不修改 `Kh/Kl`，已实测确认。
- **官方向量（优化后重跑）**：NOEKEON 1030/1030（Botan `noekeon.vec`）、
  Threefish-512 4/4（Botan `threefish.vec`，第 5 条带 Tweak 跳过，入口固定 tweak=0）、
  MISTY1 7/7（RFC 2994 App.A + NESSIE）、KASUMI 5/5（3GPP TS 35.203 Test Set 1）。
- **健康检查**：script 74/74 加载、ALGOS 289 唯一 289、说明超 200 字 0。

### 踩坑（全是测试脚本的问题，不是实现的问题）

1. **向量解析器没处理多块**：Botan `noekeon.vec` 有一组 `In` 是 192 字节（12 块）、
   `threefish.vec` 有一组是 128 字节（2 块）。我只加密第 1 块，
   表现为 "got 前 32 个 hex 与 exp 完全相同却判 FAIL" —— 又是"长度正确、内容部分对"。
2. **带 Tweak 的向量**：`threefish.vec` 最后一条有 `Tweak` 字段，
   分组密码入口固定 tweak=0，天然覆盖不到（此前用 `_test` 钩子验证），测试里显式跳过。
3. **首次测速受 JIT 预热影响**：第一轮 A/B 显示 Threefish 提速 10.95x、
   第二轮只有 1.19x。取第二轮（预热后）为准 —— 与上一批"ARIA 慢 20 倍"是同一类假象。

### 说明

本批只做优化，算法数不变（289）。


## 第六十二批：界面四栏扩容（密钥输入 / 加密模式 / 封装格式 / 口令派生 / 密文格式）+ IGE 模式

### 新增能力
- **密钥栏 6 种输入方式**：口令（KDF）、原始密钥 Hex / Base64 / 文本 UTF-8 / 十进制数组、随机生成（加密后回写实际密钥并切到 Hex 模式）。
- **加密模式 +1**：IGE（Infinite Garble Extension）。C_i = Enc(P_i ⊕ C_{i-1}) ⊕ P_{i-1}，IV 长 2×块长（前一半明文反馈初值、后一半密文反馈初值）。
- **封装格式 +4**：IV‖密文（前缀拼接）、OpenSSL 无盐（-nosalt，走 EVP_BytesToKey 但不带 Salted__ 头）、JSON 全参数（{v,alg,mode,pad,iv,salt,ct}）、PEM 装甲。
- **口令派生 +6**：PBKDF1、bcrypt-pbkdf、SP 800-56A 单步 KDF（HMAC）、SP 800-56C 两步 KDF、TLS 1.2 PRF、ANSI X9.42 PRF。前五个复用已有官方向量验证过的内核（kdf2/kdf5/kdf_nist3），只是把内核暴露给下拉框。
- **密文格式 14 → 23**：修复了「crypto_outfmt.js 合并的 9 种格式从未进下拉框」的老问题（core 末尾的 initFmtSelect 先执行，扩展格式合并在后），再新增 JSON 数组与 Base64（MIME 76 换行）两种可逆格式。
- 删除三个过时的批次说明面板（新增算法使用说明 / 第三批 / 第四批）。

### 挖到的两个 bug
1. **IGE 就地污染 IV**（致命）：igeEnc/igeDec 用 `iv.subarray(...)` 拿视图并 `set()`，反馈更新直接写回调用方的 IV。表现为加密成功、IV 框回写的却是「最后一个明文块 ‖ 最后一个密文块」，解密必然报「填充无效」。改为 `.slice()` 拷贝后修复。与之前 CAST-256 浅拷贝轮密钥是同一类。
2. **OpenSSL 无盐容器解密用错盐**：解密端 saltHex2 会回退到 _lastKdfSalt 残留值，掺进本应无盐的 EVP_BytesToKey。已在解密端对 openssl-nosalt 强制清空盐。

### 验证
- 端到端（DOM 桩 + 真实界面入口）：**39/39 通过**（容器 7、密钥模式 5、KDF 9、输出格式 11、模式 7，全部加密→取输出→解密→比对原文）。
- IGE：与独立 Python 实现（cryptography 库 AES-ECB 手搭）交叉验证 **10/10**（5 种长度 × 加解密）。
- 健康检查：脚本 **74/74** 加载、ALGOS **289 无重复**、说明超 200 字 **0**、OUT_FORMATS **23**。
- Base85 往返 65/65（上一批的修复确认在 dist 中）。

### 关于 IGE 的验证强度（如实说明）
OpenSSL 3 的 `enc` 命令已不提供 ige（`openssl list -cipher-algorithms` 无此条目），无法与官方直接对拍。当前证据是「按定义实现 + 与独立 Python 实现一致 + 往返自洽」，界面说明里已明确标注这一点。

---

## 第六十五批：MTProto 2.0（Telegram 云聊天协议）

新增 3 个条目（算法 289 → 292）：
- `mtproto-enc` MTProto 2.0 消息加密（Telegram）
- `mtproto-dec` MTProto 2.0 消息解密（Telegram）
- `mtproto-kdf` MTProto 2.0 密钥派生（auth_key + msg_key → aes_key / aes_iv）

### 规范来源（两份独立且一致）
1. core.telegram.org/mtproto §Defining AES Key and Initialization Vector
2. telethon 1.45.0 `telethon/network/mtprotostate.py::_calc_key`（生产级客户端库）

### 最容易写错的一处：KDF 是两个 SHA-256，不是四个
MTProto 2.0 只用：
```
sha256_a = SHA256(msg_key ‖ auth_key[x : x+36])
sha256_b = SHA256(auth_key[x+40 : x+76] ‖ msg_key)
aes_key  = a[0:8] ‖ b[8:24] ‖ a[24:32]
aes_iv   = b[0:8] ‖ a[8:24] ‖ b[24:32]
```
而 a/b/c/d **四个**哈希是已废弃的 MTProto 1.0（SHA-1）写法。凭 telethon 之外的记忆
写成四哈希版本会全错，且**自洽测试测不出来**（加解密两端对称），
只有与官方/第三方实现对照才暴露。x = 0 客户端 / 8 服务端。

其余要点：
- msg_key = SHA256(auth_key[88+x : 120+x] ‖ payload ‖ padding)[8:24]
  —— 2.0 的 padding **参与** msg_key 计算（1.0 不参与）
- auth_key_id = SHA1(auth_key)[12:20] —— 这里仍是 **SHA-1**，不是 SHA-256
- auth_key 低 1024 位（后 128 字节）不参与任何计算

### 踩坑：auth_key_id 的 64 位精度丢失
```
// 错：BigInt → Number 超过 2^53 丢精度，首字节被抹成 0x00（正确值 0x41）
var kid = le64(Number(rdU64(sha1(ak), 12)));
// 对：小端低 64 位就是摘要的第 12..19 字节，直接切片，不做数值转换
function authKeyId(ak) { return sha1(ak).subarray(12, 20); }
```

### 设计取舍：msg_key 校验失败时停止解析字段
msg_key 校验失败说明 body 全是垃圾，msg_length 是一个随机数，
继续解析必然抛「越界」，把真正的失败原因（方向或 auth_key 不对）掩盖掉。
现在直接返回失败报告并提示「把方向 c/s 换一下再试」。
副作用：方向填反也能得到明确诊断，而不是一句越界报错。

### 验证
- **telethon 本体**（pyaes 的 AES + telethon 自己的 IGE 与 _calc_key）交叉 24/24
- **Python 独立参考**（hashlib + cryptography 库 AES-ECB + 按 telethon 语义手写的 IGE）6/6
- 每组做 3 项检查：KDF 输出、完整报文逐字节、解密端 msg_key 校验 + data 还原 → **30/30**
- 判别测试 2/2：方向 c/s 填反 → 校验失败 ✓；改一个字节 → 校验失败 ✓
- 覆盖 x=0 与 x=8 双向、data 长度 0..1013、padding 12..1016

### 健康检查（从 zip 解压目录独立复算）
```
脚本 75/75 加载   ALGOS 292 无重复   说明超 200 字 0
MTProto 交叉 32/32
```

---

## 第六十六批：MTProto 1.0 + auth_key_id（算法 292 → 296）

在 `crypto_mtproto.js` 内新增 4 个条目：

| 条目 | 说明 |
|---|---|
| `mtproto1-enc` | MTProto 1.0 消息加密（已废弃，仅兼容验证） |
| `mtproto1-dec` | MTProto 1.0 消息解密 |
| `mtproto1-kdf` | MTProto 1.0 密钥派生（四个 SHA-1） |
| `mtproto-authkeyid` | auth_key_id / aux_hash 计算 |

### ⚠ 1.0 与 2.0 的三处差异，凭直觉必错

上一批已经踩过「凭记忆想起 a/b/c/d 四哈希其实是 1.0 的写法」。本批把它做成了 1.0 条目，
并把差异逐条钉死：

| 项 | MTProto 1.0 | MTProto 2.0 |
|---|---|---|
| msg_key | `SHA1(payload)[4:20]`，**不含 padding**、**不含 auth_key 片段** | `SHA256(auth_key[88+x:120+x]‖payload‖padding)[8:24]` |
| padding | **0..15** 字节 | 12..1024 字节 |
| KDF | **四个 SHA-1** | 两个 SHA-256 |

官方（core.telegram.org/mtproto）原文佐证：
> "In the older MTProto 1.0, the message key was computed as the lower 128 bits
>  of SHA-1 of the message body, excluding the padding bytes"
> "12..1024 padding bytes are used instead of 0..15 padding bytes in v.1.0"

### 参照物：这次找到了真正的第三方 v1 实现

telethon 1.45 早已移除 1.0 支持，所以第一批的「telethon 本体」参照物**对 1.0 无效**。
本批改用 **telethon 0.15.5**（MTProto 1.0 时代的生产客户端）：

```python
# telethon 0.15.5  telethon/helpers.py
def calc_key(shared_key, msg_key, client):
    x = 0 if client else 8
    sha1a = sha1(msg_key + shared_key[x:x + 32]).digest()
    sha1b = sha1(shared_key[x + 32:x + 48] + msg_key + shared_key[x + 48:x + 64]).digest()
    sha1c = sha1(shared_key[x + 64:x + 96] + msg_key).digest()
    sha1d = sha1(msg_key + shared_key[x + 96:x + 128]).digest()
    key = sha1a[0:8] + sha1b[8:20] + sha1c[4:16]
    iv  = sha1a[8:20] + sha1b[0:8] + sha1c[16:20] + sha1d[0:8]
    return key, iv

def calc_msg_key(data):
    return sha1(data).digest()[4:20]
```

参考实现**每次调用都与之硬断言**，不是跑通一次就算。另有两份外部源码交叉：
gotd/td `crypto/kdf_v1.go`、ferogram_crypto(Rust) `lib.rs`。

IGE 仍用 telethon 1.45 的 `AES.encrypt_ige/decrypt_ige`（pyaes，第三方）。
auth_key_id 与 telethon 的 `AuthKey` 类交叉（`key_id = SHA1(auth_key)[12:20]`，
`aux_hash = SHA1(auth_key)[0:8]`）。

### 判别测试（防止两套协议写混）

- 1.0 与 2.0 的 KDF 对同一 msg_key 输出**必须不同** ✓
- 用 2.0 解密条目去解 1.0 报文**必须失败** ✓
- 1.0 方向 c/s 填反 → msg_key 校验失败 ✓
- 改一个字节 → msg_key 校验失败 ✓

### 验证（从 zip 解压目录独立复算）
```
MTProto 1.0 / auth_key_id 官方向量  PASS 69  FAIL 0
MTProto 2.0 回归              PASS 32  FAIL 0
脚本 75/75 加载   ALGOS 296 唯一 296   说明超 200 字 0   BUILD_INFO 一致
```
52 组 v1 向量覆盖：x=0/x=8 双向、data 长度 0..1013、padding 长度 0..15 全部取值、
12 组 auth_key_id。

## 第六十七批：MTProto 全量独立复算（第 1 批收尾）

> 算法数不变（296）。本批不新增条目，只做「第 1 批 MTProto」的**独立复算验收**与清理。

### 一、为什么要单独跑一次

第六十六批把 1.0 与 auth_key_id 加进来时，验证是在生成向量的同一轮里做的。
本项目规矩：**改动与验证不在同一轮完成时，必须换一轮独立复算**，
避免「参照物与实现一起错」的共谋失效。本批从 dist 走 ALGOS 界面入口重跑全部 7 个条目。

### 二、复算结果：272 / 272

| 项 | 组数 | 结果 |
|---|---|---|
| MTProto 1.0 KDF（auth_key+msg_key → aes_key‖aes_iv） | 52 | PASS |
| MTProto 1.0 加密（完整报文逐字节） | 52 | PASS |
| MTProto 1.0 解密（msg_key 校验 + data 还原） | 52 | PASS |
| 判别：方向 c/s 填反 → 必须失败 | 1 | PASS |
| 判别：篡改密文一字节 → 必须失败 | 1 | PASS |
| auth_key_id + aux_hash | 12×2 | PASS |
| MTProto 2.0（Python 参考向量）KDF+enc+dec | 6×3 | PASS |
| MTProto 2.0（telethon 本体向量）KDF+enc+dec | 24×3 | PASS |

### 三、又栽在解析器上（第 N 次「参照物错了」）

第一遍跑 2.0 回归 **4/6 FAIL**，看着像 2.0 KDF 有方向性 bug。

实际是：**两份向量的 `client` 字段格式不同**——

```
mt/mtproto_ref.txt       写 1 / 0
mt/mtproto_telethon.txt  写 1 / 0
mt/mtproto1_ref.txt      写 01 / 00
```

我的脚本按字符串 `=== '01'` 判断，2.0 的两份文件全部被判反（x 取成 8 而非 0），
于是**全组方向相反**。改成 `parseInt(client, 16) !== 0` 后立刻全过。

**这不是实现的错，是解析器的错。** 教训再次确认：
期望值与字段格式一律解析确认，不凭对某一份文件的印象写死。

### 四、清理的死代码

`mtproto-enc` 的 `enc` 里留了一行实验期残留：

```js
var data = asHex ? hexToB(bToHex(inB(b)).length ? inB(b) : inB(b)) : inB(b);
```

三重嵌套、语义恒等于 `inB(b)`，且下一行 `if (asHex)` 立即重新赋值覆盖。
不影响结果（否则 272 组不会全过），但会误导后续维护。已改为 `new Uint8Array(0)`，
与紧随其后的 hex 分支保持一致。

### 五、交付

从 **zip 解压目录**独立复算：脚本 75/75、ALGOS 296 唯一 296、说明超 200 字 0、
BUILD_INFO 一致、MTProto 272/272。


---

## 第六十六批：协议 / 容器级封装（XSalsa20 · NaCl · Fernet · PASETO）

**新增 17 个条目，算法 296 → 313。官方向量 123/123，界面入口 23/23。**

### 一、新增条目

| 条目 | 参照物 |
|---|---|
| XSalsa20 流密码 | PyNaCl 1.6.2（libsodium `crypto_stream_xsalsa20`） |
| NaCl secretbox 封装 / 解封 | libsodium `crypto_secretbox_easy` |
| NaCl box 封装 / 解封 | libsodium `crypto_box_beforenm` + secretbox |
| NaCl sealed box 封装 / 解封 | libsodium `crypto_box_seal` |
| Fernet 加密 / 解密 | Python cryptography 50.0.1 |
| PASETO v4.local 加密 / 解密 | pyseto 1.10.0 |
| PASETO v2.local 加密 / 解密 | pyseto 1.10.0 |
| PASETO v4.public 签发 / 验签 | pyseto 1.10.0 |
| PASETO v2.public 签发 / 验签 | pyseto 1.10.0 |

本批是本项目第一次大规模接入「第三方生产库」级别的容器格式（此前多为算法原语）。

### 二、三个只有对拍才能发现的坑

**1. HSalsa20 的输出 word 次序不是 0..3 + 12..15**

直觉写法（也是我第一版）是取 `state[0..3] ‖ state[12..15]`。实际 NaCl/libsodium 取的是
**0, 5, 10, 15（常量槽）+ 6, 7, 8, 9（nonce 槽）**。

拿 libsodium 的 `crypto_core_hsalsa20` 直接对拍才定位到：固定输入下，
正确次序输出 `d0e0df78…`，错误次序输出 `d0e0df78973935d9…` —— **前 4 字节相同**，
极易误判成「某一轮写错」而不是「取错索引」。

**2. PyNaCl 的 `crypto_box_beforenm` 参数顺序是 (public_key, private_key)**

传反**不报错、不抛异常**，只是得到另一个密钥。因为 X25519 本身对称，
共享密钥那一步看不出问题，只有派生后的 beforenm 值不同才发现。

**3. Fernet 的 base64url 必须保留尾部 `=`**

框架里的 `b64urlEncode` 会去掉填充（PASETO 规范要求无填充，正确）。
Fernet 规范要求保留 —— 差异只在 token 最后 1~2 个字符，
且 `b64urlDecode` 能容忍缺失，所以「生成后自己再解一遍」完全测不出来，
只有跟 Python 的 token 字符串逐字符比才暴露。

### 三、另外三处

- **pyseto 的 v2 nonce 会被再派生一次**：`n = BLAKE2b(key=传入 nonce, msg=payload, 24)`，
  所以 token 里携带的 nonce ≠ 传入值。v4 没有这一层。
- **主流程解密走 `a.dec`**：解密类条目必须定义 `dec`，只写 `enc` 会直接抛
  "is not a function"。这与 CAST-256 那次是同一类「测试与界面用不同入口」的问题。
- **参数分割吃掉 JSON 的引号**：`_splitP` 原本无条件剥离 `"`，
  导致 footer `{"kid":"x"}` 变成 `{kid:x}`，静默产出错误 token。
  改成只在首尾是【配对】引号时才剥。

### 四、验证

从 **zip 解压目录**独立复算：脚本 76/76、ALGOS 313 唯一 313、说明超 200 字 0、
官方向量 123/123、界面入口 23/23（含篡改拒绝与错误密钥拒绝各 1 组）。


---

## 第六十七批：LMS / HSS（RFC 8554）—— SP 800-208 第二个状态化哈希签名

**新增 3 个条目，算法 313 → 316。官方向量 2 组（TC2 公钥生成 + TC1 验签），合计 21/21。**

### ⚠ 核心 bug：验签漏了叶子哈希层（D_LEAF）

`computeRoot` 的起点必须是【叶子哈希】
`H(I‖u32str(q+2^h)‖D_LEAF‖K_ots)`，**不是 K_ots 本身**。

漏掉这一层后 TC1 官方签名怎么算都对不上，我一度判定"本地向量残缺 / 层级对应不明"，
差点放弃这一批。补上叶子哈希后，TC1 官方签名立刻验过。

这类 bug 的自洽测试也会失败，所以它不算"静默错误"——但**误判成数据问题更危险**：
差点让一个本来能拿到的官方锚点被放弃。

### 四个凭直觉必错的点（已写进文件头注释）

1. 域分离常量是 **D_PBLC=0x8080 / D_MESG=0x8181 / D_LEAF=0x8282 / D_INTR=0x8383**，
   不是常见的 0x0000 / 0xffff；
2. LM-OTS 私钥 `x_q[i] = H(I‖u32str(q)‖u16str(i)‖u8str(0xff)‖SEED)`，
   **SEED 在最后**——与 XMSS 的 `PRF(sk_seed,…)` 结构完全不同；
3. 校验和要**左移 ls 位**再拼进 S（w=4 时 ls=4，w=8 时 ls=0）；
4. `coef(S,i,w)` 的字节索引是 `floor(i*w/8)`，不是 i。

### 官方向量

| 来源 | 内容 | 结果 |
|---|---|---|
| RFC 8554 Appendix F **TC2 顶层密钥** | SEED=558b8966… / I=d08fabd4… / H10+W4 → 树根 | == 官方 K `32a58885cd…` **逐字节** |
| RFC 8554 Appendix F **TC1 sig[0]** | H5+W8，被签消息是第二级 LMS 公钥的 56 字节序列化 | 验签 **VALID**；改消息 / 改签名 → INVALID |

TC2 建树 1024 叶 × 67 链，JS 耗时 1.6 秒。

### 参照物获取过程中的两个坑

- rfc-editor 与 datatracker 在本环境**均返回 403**，RFC 全文只能经页面提取；
- RFC 排版把每个 32 字节值**拆成两行 16 字节**，第一次提取只拿到前半截，
  导致签名比对全错。第二次明确要求"两行拼接成 64 hex"才拿全值。

### 验证（从 zip 解压目录独立复算）

```
脚本加载 77/77      ALGOS 316 唯一 316      说明超 200 字 0
LMS 官方向量 5/5    往返与篡改 6/6          界面入口 4/4
```


## 第六十八批：界面输入栏扩容（第二密钥栏）与三处缺陷修复

### 修复 1（致命）：单侧操作报 `a.enc is not a function`
`NaCl sealed box 解封`、`Fernet 解密` 等条目只注册了 `dec`。点「加密」时直接抛
`a.enc is not a function` —— 用户看到的只有一行内部错误，不知道该点哪个按钮。
已在 `runEnc` / `runDec` 入口加保护：

```
if (typeof a.enc !== 'function') throw new Error('「XXX」只有解密操作，请点「解密」按钮');
```

### 修复 2：非对称条目缺独立公钥栏
「己方私钥 + 对方公钥」此前挤在 key 与 param 两栏里，param 同时还要装 nonce、
派生路径等参数，标签语义混乱；且密钥模式下拉（口令 KDF）对这些条目仍然显示，
用户选「口令」会派生出完全错误的密钥。

- 新增 **`key2` 第二密钥栏**（`index.html` + `updateAlgoUI` + `els`），标签由
  `key2Label` 自定义，`key2Optional` 控制是否必填；`enc/dec` 签名追加第 5 个参数 `k2`。
- 新增 **`rawKey`** 标志：置位时隐藏「密钥模式」下拉，避免口令 KDF 污染原始密钥。
- 涉及条目：NaCl box 封装/解封、NaCl sealed box 封装/解封、BIP-32、
  Diffie-Hellman(MODP)、ECC-ECDH、ECC-ECIES、ElGamal、ECDH(P-256 PEM)。
- **向后兼容**：上述条目内部一律 `var peer = k2 || p`，旧脚本用 param 传公钥照常工作。

### 修复 3：BIP-32 无法填助记词
原先只能填 16~64 字节 Hex 种子。现在第一栏可直接粘 BIP-39 助记词
（12/15/18/21/24 词，自动走 PBKDF2-HMAC-SHA512 转 64 字节根种子），
第二栏填 BIP-39 口令 passphrase（官方向量用 `TREZOR`）。

新增 `bip39ToSeedSync()`：本项目此前只有异步 WebCrypto 版，BIP-32 是同步函数，
用 `hmacSha512` 手写 PBKDF2（2048 轮，块长 128，U1 异或累积）。
参照物为 Node `pbkdf2Sync` 独立实现，**TREZOR 口令与空口令两组均逐字节一致**。

### 顺带
- `doClear()` 补清 `key2`。
- NaCl sealed box 封装第二栏可指定临时私钥（留空随机），使密文可复现；
  解封第二栏可补对方公钥，用于密文前 32 字节已被剥离的场景。

### 验证
`t_ui_keys.js` **32/32**；全量健康检查：脚本 **77/77**、算法 **316 无重复**、
说明超 200 字 0。

---

## 第六十九批：B 组开工 —— BIKE（NIST Round 4）官方 KAT 就位

**本批状态：权威向量已产出并验证，JS 实现尚未开始（下一批做）。**

### 已完成

1. **编译官方源码并产出确定性 KAT**（三参数集）
   - 来源：`liboqs-main/src/kem/bike/additional_r4`（BIKE additional，2023-01-27）
   - 自建 shim：`OQS_SHA3_sha3_384` / `OQS_SHA3_shake256_inc_*`（KeccakP-1600-opt64 + 手写 sponge）
   - `OQS_randombytes` → splitmix64 确定性 PRNG（seed `0x1234567890abcdef`）
   - 产物：`testvectors/bike_l{1,3,5}.txt`，含 SK/PK/CT/SS 与 MATCH

2. **长度与 liboqs 头逐一对齐**

   | LEVEL | R_BITS | pk | sk | ct | ss |
   |---|---|---|---|---|---|
   | 1 | 12323 | 1541 | 5223 | 1573 | 32 |
   | 3 | 24659 | 3083 | 10105 | 3115 | 32 |
   | 5 | 40973 | 5122 | 16494 | 5154 | 32 |

3. **确定性验证**：三参数集各跑两次，`cmp` 完全一致；`MATCH=1`（封装/解封装自洽）

4. **⚠ 参照物自身必须可信**：手写的 SHA3 shim 用 Python `hashlib` 交叉验证 **4/4**
   （sha3_384 abc / 空 / 200 字节跨块；shake256 增量 400 字节）。
   不验证就当成权威锚点，会让整批结论建立在错误参照物上。

### 挖到的坑（已记录进 `work/bike_notes.md`）

- **采样是 Fisher-Yates，不是 rejection。** `bike_defs.h` 里的 `MAX_RAND_INDICES_T`
  （271/373/605）是本版本**未使用的旧版残留**。凭它写实现会全错。
- **`keypair_derand` / `encaps_derand` 在这个版本是 stub**，直接返回 `OQS_ERROR`。
  所以只能 patch 随机源（`get_seeds` → `OQS_randombytes`）来取得确定性，不能走 derand 接口。
- **`function_l` 是 SHA3-384 截断 32 字节**，不是 SHA-256。
- 编译 `KeccakP-1600-opt64.c` 很慢（>60s），已单独编译成 `keccak.o` 缓存复用。

### 未做

BIKE 的 JS 实现（gf2x Karatsuba / BGF decoder / 常量时间采样）尚未开始，
本批只是把「可验证的锚点」先立住 —— 没有官方 KAT 就没法判断实现对错。

## 第六十九批：Falcon（FN-DSA / FIPS 205）验签上线

### 新增
- `crypto_falcon.js`（新增文件）：Falcon-512 / Falcon-1024 签名验证，1 个界面条目 `falcon-verify`。
  算法数 316 → 317。参数集由签名头字节自动识别（0x39=512、0x3A=1024）。

### 参照物（官方 KAT）
- PQClean `crypto_sign/falcon-{512,1024}/clean` 编译产物，随机源换为 NIST AES256-CTR-DRBG（确定性）。
- Falcon-512：5 组；Falcon-1024：3 组。每组含 pk / sig / 消息 / 官方 verify 结论。
- 界面入口 10/10（走 reg 注册的真实链路），底层对拍 56/56（含篡改拒绝与健壮性）。
- 内置 SHAKE256 与 Python `hashlib.shake_256` 交叉校验 4/4。

### 为什么只做验签
验签路径（`vrfy.c` 的 `verify_raw`）全程整数运算：NTT + Montgomery 乘，不含浮点 FFT，
故可用 JS 精确复现。密钥生成与签名需要 ffLDL 树、浮点 FFT 与高斯采样，本轮未实现。

### 踩坑（三个，都是"语法照抄没问题、语义被 JS 改了"）
1. **C 的 uint32 右移 vs JS 的算术右移**。`hash_to_point_ct` 里 `wr -= 24578 & (((wr-24578)>>31)-1)`，
   C 中 `wr-24578` 为负时 uint32 下溢 → `>>31` 得 1；JS 负数 `>>31` 得 -1，mask 取反，
   结果 `hm` 全成 0xFFFE。必须先 `>>>0` 转 uint32 再 `>>>31`。
2. **int16 → uint32 的回绕**。`verify_raw` 里 `w = (uint32_t)s2[u]`，负数变 2^32+x，加 Q 后回绕
   正好是 x+Q。JS 需 `s2[u] >>> 0` 后再加，否则只加 1。
3. **`z * Q0I` 的 uint32 溢出**。`mq_montymul` 中该乘积在 C 会 mod 2^32（约 1.8e12），
   JS Number 不溢出，必须 `(x*y)>>>0` 逐步模拟。

### 测试脚本自身的两个错误（非实现问题，但会误导结论）
- C 侧 `MSG[33] = "…mlen=33!!"` 实际只有 32 字符，第 33 字节是 NUL；传 `mlen=33` 把空字节
  也算进消息，导致 C 与 JS/Python 三方 ks32 不一致。统一为 32 字节后一致。
- 界面测试用 `text.indexOf('VALID')>=0` 判定，而 "INVALID" 也含 "VALID" 子串，
  会把失败判成通过。改用 `indexOf('验签结果 = VALID')>=0` 精确匹配后重判。

### 验证
- 脚本加载 78/78，ALGOS 317 唯一 317，说明超 200 字 0。
- 向量已固化至 `testvectors/falcon_kat_512.txt`、`testvectors/falcon_kat_1024.txt`。

## 第七十批：FIPS-202 补齐 & Falcon 密钥生成/签名（进行中）

### 已交付
- **FIPS-202 补齐**：新增 `sha3-224` / `sha3-384` 两个条目（此前只有 256/512）。
- **修复 `sha3Digest` 的 rate 计算 bug**：原实现 `outLen === 32 ? 136 : 72`
  只覆盖 256/512；224/384 会落到 72（SHA3-512 的 rate）而算出 SHA3-512 的值。
  正确公式 `rate = 200 - 2*outLen`（224->144 / 256->136 / 384->104 / 512->72）。
  ——这正是此前 224/384 一直没开放的原因。
- 验证：Python hashlib（独立实现）3 组消息 × 4 种输出 = **12/12**。

### Falcon 官方 KAT 已就位（锚点）
编译 PQClean `crypto_sign/falcon-{512,1024}/clean`（官方 clean 实现），
把 `PQCLEAN_randombytes` 换成 splitmix64 确定性流，产出：
- 512：sk 1281 / pk 897 / sig，3 组（mlen=0,3,40），verify 3/3 OK
- 1024：sk 2305 / pk 1793 / sig，3 组，verify 3/3 OK
文件：`falcon_kat/kat_512.txt`、`falcon_kat/kat_1024.txt`

### 关键技术结论（决定后续能否做）
`inner.h` 中 `typedef uint64_t fpr` —— fpr **不是真正的定点数，而是用 uint64
位模式软件模拟 IEEE-754 double**。实测（C 对照，18×18 组合）：
```
add   total=324 diff=0
sub   total=324 diff=0
mul   total=324 diff=3    ← 全部为 1e±300 上/下溢
sqr   total=324 diff=18   ← 全部为 1e±300 上/下溢
div   total=324 diff=3    ← 全部为 1e±300 上/下溢
neg   total=324 diff=0
half  total=324 diff=0
sqrt  total=198 diff=0
```
**差异只在 1e±300 这类极端值出现**；Falcon 实际运算中 fpr 值域约 2^-30..2^30，
因此 **JS 可直接用 Number（double）精确复现 fpr**，无需 BigInt，性能也快。
`fpr_gm_tab`(2048 项) / `fpr_p2_tab`(11 项) 已提取为 double 数组。

### 未完成（下轮继续）
Falcon keygen / sign 的 JS 移植。难点不在浮点（已证明可用 Number），
而在 `keygen.c` 的整数部分：`modp_*`（Montgomery 域）与 `zint_*`（多精度大数）
约 1500 行，需逐个处理 JS 的 32 位截断语义；以及 `sign.c` 的
ffLDL 树 + 高斯采样 + ffSampling。已有官方 KAT 作锚点，可逐层对拍。

## 第七十批：Falcon 签名上线（密钥生成仍未完成）

### 新增
- `crypto_falcon_kg.js`（新增文件，index.html 已加引用）：Falcon 签名界面条目 `falcon-sign`。
  - 由私钥头字节自动识别参数集：0x59=Falcon-512、0x5A=Falcon-1024。
  - 流程复刻 PQClean `crypto_sign_signature` → `sign_dyn`：
    1. `trim_i8_decode` 解出 f / g / F，`complete_private` 推出 G；
    2. nonce(40B) 随机，`hm = hash_to_point_ct(SHAKE256(nonce‖msg))`；
    3. prng seed(48B) 随机，`SHAKE256(sd)` 流的第 k 段 56 字节作为第 k 次尝试的 PRNG 初态
       （复刻 `sign_dyn` 的 for(;;) 重试，而不是重新播种）；
    4. `comp_encode(s2)`，输出 `0x30+logn ‖ nonce ‖ enc`。
- 算法数 319 → 320。

### 验证
- 界面入口 `t_falcon_sign_ui.js` **13/13**：512 与 1024 签名后由**官方公钥**（PQClean 编译产出）走
  独立验签路径判定 VALID；改一个字符即判 INVALID；非法私钥头/空私钥给出可读报错。
- `t_full.js`（512/1024）底层对拍：f / g / F / G / hm 与官方中间值 **逐字节 MATCH**。
- 健康检查：script 79/79、ALGOS 320 无重复、说明超 200 字 0。

### 已知未完成：密钥生成
`keygen.c` 的 `solve_NTRU`（解 NTRU 方程 f·G − g·F = q）约 1500 行，
依赖 RNS 多精度整数（zint_*）、二进制扩展 GCD（zint_bezout）与逐层 Babai 取整回代。
本轮**未实现**，因此 `falcon-keygen` 条目未上线。已具备的锚点：
- `work/falcon/kat512_dbg.txt` / `kat1024_dbg.txt`：官方 f / g / F / G / h / sk / pk 全套中间值，
  可直接逐层对拍；
- 已确认算法骨架：范数递归 f₁=f·σ(f) 降到半维 → 最深层用扩欧求解 → 逐层 Babai 取整回代。

### 踩坑
- `drv.c` 里的 `sig2` **没有写入 nonce**（驱动脚本本身只写了 `sig[0]` 与 `comp_encode`），
  因此比对签名时必须跳过我方签名中的 40 字节 nonce，否则长度 652 vs 616 会被误判为失败。
- 官方 nonce 在 512 与 1024 两份 KAT 中**完全相同**（同一个 xorshift64* 初态），
  初见极易误判成"nonce 没生效"。
- 我的 `s2` 与官方 `s2` **不一致**（512/512 全不同），但签名本身有效（官方公钥验签 VALID）。
  原因是高斯采样器消耗随机流的顺序与官方不完全相同；Falcon 签名本身是随机化的，
  同一消息本就有多个合法签名，故不影响正确性，**但不能声称"与官方逐字节一致"**。

---

## 第七十七批：Falcon 密钥生成上线（算法 320 → 321）

`falcon-keygen` 条目已注册，Falcon-512 / 1024 均可生成密钥对。算法总数 **321**。

### 成果（可复算）

- 新增 `crypto_falcon_kg2.js`，`index.html` 已加引用。
- 界面入口测试 `t_falcon_keygen_ui.js`：**20/20 PASS**（512 / 1024 各：pk、sk 长度、
  官方种子下 pk 逐字节一致、自产密钥签名→验签 VALID、篡改消息 INVALID；
  外加随机种子、非法参数集、错误种子长度的报错）。
- 从 zip 解压目录独立复算同样 20/20。
- 健康检查：`script 80/80` 加载、`ALGOS 321` 无重复、说明超 200 字 **0**。

### 与官方的关系（必须说清）

同一 48 字节种子下：

```
f   逐系数 MATCH
g   逐系数 MATCH
h   逐系数 MATCH
pk  逐字节 MATCH        ← 公钥与官方完全一致
sk  仅 F 段不同（偏移 769 起，503/1281 字节）
```

**F 为什么不同**：`f·G − g·F = q` 的解不唯一——若 (F,G) 是一组解，则
`(F + f·t, G + g·t)` 对任意 t 都成立。官方用浮点迭代 Babai（scale_k 每轮减 25 bits，
只取最高 10 个 word），本项目用 BigInt 定点 negacyclic FFT 一次精确取整，
收敛路径不同 → 选中了另一个**同样合法**的解。实测本项目 |F|max=106、官方 74，
签名采样重试 1 次即通过，密钥有效（签名→验签 VALID）。

**因此不声称 sk 与官方逐字节一致**，只声称：f/g/h/pk 一致、密钥有效。

### 本批踩到的三个 bug（都是我自己的）

1. **`fpr` 数组布局搞错**：PQClean 的 FFT 数组长度是 `n = 1<<logn`，
   其中 `[0,hn)` 是实部、`[hn,n)` 是虚部，所有 `poly_*` 循环**只走 hn**。
   我写成 `2n` 长度、循环走 `n`，bnorm 恒不满足 → 64 次重试全部被拒，
   表现为"密钥生成永远失败"，极易误判成采样器有问题。
2. **`poly_mul_autoadj_fft` 是 `a *= b` 不是 `a *= |b|²`**：看名字容易想成 "auto-adjoint"，
   实际源码里就一行 `a[u] = fpr_mul(a[u], b[u])`。
3. **SHAKE 流被读完**：采样重试多时 64KB 缓冲耗尽，报 `Cannot convert undefined to a BigInt`。
   改成按需翻倍重新抽取（XOF 前缀一致，安全）。

### 参照物又错了一次

`kat512.txt` 的 pk 与 `dump512_first.txt` 的 h **种子不同**，没有可比性；
解出的 512 个值都落在 [6,12284] 里，看着"很像对的"，差点误判编码写错。
判据改成同一 seed 内部比对后才对上。

### 文件

- `dist/crypto_falcon_kg2.js`（新增，md5 `979425348a5ec3f1a14ecd5d45462567`）
- `dist/t_falcon_keygen_ui.js`（界面入口测试）
- `work/build_kg2.js`（组装脚本，从 `work/falcon_kg.js` + `gauss_tab.js` 内联生成）
- `work/t_keygen_e2e.js`（编码器对拍 + 链路测试）

---

## 第七十八批：Falcon 性能优化（2.1x ~ 5.9x，输出逐字节不变）

优化对象：`falcon-keygen`（512 / 1024）。**三个条目的输出与优化前完全一致
（7 个种子下 pk / sk 的 md5 全部相同），官方 pk 对拍仍然通过。**

### 实测提速

| 用例 | 优化前 | 优化后 | 倍数 |
|---|---|---|---|
| 512 seed off=11 | 5545 ms | 1093 ms | 5.1x |
| 512 seed off=100 | 5499 ms | 1013 ms | 5.4x |
| 512 seed off=200 | 2678 ms | 971 ms | 2.8x |
| 512 seed off=300 | 3322 ms | 788 ms | 4.2x |
| 512 seed off=400 | 5498 ms | 931 ms | 5.9x |
| 1024 seed off=0 | 6108 ms | 2716 ms | 2.2x |
| 1024 seed off=55 | 5987 ms | 2851 ms | 2.1x |

界面入口实测：512 约 0.8 s（原 1.3 s），1024 约 3.0 s（原 4.6 s）。

### 真正的瓶颈不是我以为的那个

先按阶段计时，结果和直觉相反：

```
512 off=11 总 4368ms  tries=31
  smallPoly 3019ms   bnorm 14ms   compute_pub 3ms   solveNTRU 772ms
```

`smallPoly` 占 69%。但把它从 BigInt 改成纯 Number（32 位分段比较，
GAUSS 表预拆 hi/lo）后**只快了 3%** —— 说明开销不在比较，而在它调用的字节流。

继续往下挖才找到真凶：**`crypto_falcon.js` 自带的 SHAKE256 只有 0.5 MB/s**。

```
shake256 0.25MB -> 581ms    1MB -> 1824ms    2MB -> 3976ms
```

原因是 `keccakF` 用 BigInt 实现，且 `rotl64(x, n)` 里每轮都做一次
`BigInt(n)` 转换（24 轮 × 25 lane = 600 次/置换）。密钥生成要抽 1~2 MB
随机流，SHAKE 一项就吃掉三分之二以上的时间。

### 改法

主文件 `Encryption_and_decryption_logic.js` 早就有 hi/lo 32 位的快
`keccakF`（`crypto_core.js` 一直在复用它，注释里写明"由主文件提供"），
只是 falcon 这份代码自带了一份 BigInt 版。改为优先走 `globalThis` 的快版本，
单独 `require` 本文件时回退到 BigInt 版（保持可独立运行）。

**踩的坑**：本文件的 IIFE 里有个同名的 BigInt `keccakF`，会**遮蔽**全局快版本。
第一版直接写 `keccakF(S0)`，把 `Int32Array` 状态喂给了 BigInt 版，
报 `Cannot mix BigInt and other types`。必须显式 `globalThis.keccakF`。

吞吐 0.5 → **6.7 MB/s**。

### 另外两处

1. **定点精度 4096 → 1024 位**。实测各层 Babai 所需的 k 位数差别极大
   （512：n=512 层仅 13 位，n=2 层 3139 位），固定 4096 让最耗时的大 n 层
   做了大量无用运算。降到 1024 后 7 个种子的 pk / sk **逐字节不变**。
   256 / 128 会失败（Babai 不精确 → 64 次重试），故 1024 保留 2 倍余量。

2. **GAUSS 表改用 BigInt 字面量**。原先用 Number 存 64 位整数
   （如 `1283868770400643928`），超出 53 位尾数会静默丢精度，
   再 `BigInt()` 转换只是把损失固化。影响概率约 1e-17，实际从未触发
   （改成 BigInt 后输出不变），但表述上不应依赖这点。

### 验证

- `shake256` vs Python `hashlib.shake_256`：**48/48**（输入 0/1/48/135/136/137/200/1000 字节
  × 输出 1/32/136/137/300/4096 字节，覆盖 rate 边界与跨块）
- 验签官方向量 **10/10**、签名 **13/13**、密钥生成 UI **20/20**
- 7 个种子 pk / sk md5 与优化前逐一相同；`pk == 官方 pk` 仍然成立
- 脚本加载 82/82、ALGOS 321 唯一 321、说明超 200 字 0

### 没做的

`solveNTRU` 在 1024 下仍占约 2.7 s 中的大部分。理论上可继续按层细分精度
（大 n 层只需 ~150 位），但动态精度试过：单靠"当前 F/G 量级 + 常数"定精度会
低估分母的动态范围（分母在某些 ζ 处可能接近奇异），导致 Babai 不精确、
64 次重试全失败。要做需要按"分母最小值"而非"分子最大值"定精度，留待后续。

### 文件

- `dist/crypto_falcon.js`（shake256 快路径）
- `dist/crypto_falcon_kg2.js`（PREC 1024 + GAUSS BigInt 字面量 + 纯 Number 采样）

## 第七十八批：Falcon 密钥生成 —— 与官方 PQClean 对拍（修正此前错误结论）

### ⚠ 先修正上一批的错误结论

上一批称"NIST KAT 22 个种子下与官方不一致，原因是缺浮点 bnorm 检查"——**该结论错误**。
真实原因是**我的测试脚本传参写错**：`enc(b, k, p)` 第一个参数是输入内容、第二个才是种子，
我却写成 `A.enc(sd, "")`，导致种子为空走随机分支，于是 f/g 自然对不上。
实现本身当时就是对的（`bnormOk` 一直在，也从未缺失）。

### 本批修复的真 bug

`poly_small_mkgauss` 在官方 C 中**每次调用都把 mod2 重置为 0**，f 与 g 各自独立累积。
原 JS 让 g 继承 f 结束时的 mod2，会使 g 的末系数奇偶校验判据出错。

### 官方对拍方法（可复算）

给 PQClean `keygen.c` 插桩输出每次重试的拒绝原因，编译为 `kgdiag` / `kgdiag1024`；
对拍后已把官方源码恢复原状（`keygen.c.orig`）。
参照值已固化进 `t_falcon_kg_official.js`，**解压后无需 C 编译器即可复算**。

### 对拍结果

| 项 | 结果 |
|---|---|
| 512 公钥 pk（8 组，重试 2~35 次） | **逐字节 MATCH** |
| 1024 公钥 pk（2 组） | **逐字节 MATCH** |
| 512 私钥 f、g 段（前 769 字节，3 组） | **MATCH** |
| 512 私钥 F 段（字节 769 起） | 不同（见下） |

**F 段差异是正当的**：`f·G − g·F = q` 的解不唯一，`(F+f·t, G+g·t)` 代进去同样成立。
本实现用 BigInt 定点 FFT 一次精确取整，官方用浮点迭代 Babai（scale_k 每轮减 25 bits），
两者收敛到不同的合法解。pk 一致说明 f/g/h 全对，密钥功能等价（签名→验签有效）。

### 过程中确认无误的几处

- 官方 SHAKE 流 == 标准 SHAKE256（与 Python hashlib 逐字节一致），小端 u64 一致
- JS 的 `shake256` 输出与官方一致
- GAUSS 表 27 项与官方一致
- JS 的 (hi,lo) 字典序比较逻辑，用 Python 严格复刻验证与官方一致
- `bnorm` 数值与官方逐位吻合（16832.516398366148 / 16653.528992414638）

### 其他

- 把 `bnorm` 累加顺序改为与官方一致（先加 a[u]² 再加 b[u]²）
- 两条说明精简到 200 字以内（verify 176 / keygen 183）
- keygen 的 info 改写为实测结论，去掉"尚未修复"的错误描述

### 验证

从 zip 解压目录独立复算：`t_falcon_kg_official.js` **PASS 13 / FAIL 0**；
健康检查 script 82/82、ALGOS 321 唯一 321、说明超 200 字 0、BUILD_INFO 一致。
