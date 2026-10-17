# Aegis Crypto Toolbox（加密 / 解密工具箱）

一个**纯前端、离线可用**的密码学工具箱，单页 HTML 应用，无需后端、无需联网、不上传任何数据。

当前内置 **250 个算法条目**，覆盖编码、哈希、对称加密、非对称、后量子、椭圆曲线与高级代数、门限密码、认证加密、校验和等门类。

- **许可**：MIT License（见 `LICENSE`）
- **第三方来源**：见 `THIRD_PARTY_NOTICES.md`
- **版本**：v1.0.0「Aegis / AGS」

---

## 快速开始

直接用浏览器打开 `index.html` 即可，**不需要构建、不需要服务器**。

```
git clone <仓库地址>
cd <仓库目录>
# 双击 index.html，或：
python3 -m http.server 8000   # 然后访问 http://localhost:8000
```

> 部分浏览器对 `file://` 下的 WebCrypto 有限制；若遇到「SHA-384 不可用」等提示，
> 用上面的本地服务器方式打开即可。

---

## 主要特性

- **纯前端**：所有运算在浏览器内完成，密钥与明文**不会离开本机**
- **离线可用**：不依赖 CDN、不请求网络
- **250 个算法**：从古典密码到后量子（ML-KEM / ML-DSA / SPHINCS+ / HQC / McEliece / FrodoKEM）
- **国密完整**：SM2（签名/加密/密钥协商）、SM3、SM4、SM9（标识密码）、ZUC-128
- **官方向量验证**：核心算法均对照 RFC / NIST / BIP / 3GPP / 官方参考实现验证
- **内置自检**：界面内置自检按钮，可一键检查各算法可用性

---

## 算法覆盖

| 门类 | 数量 | 代表 |
|---|---|---|
| 编码 | 24 | Base64/32/58/85/91、Bech32/32m、BIP-39、Punycode |
| 单向哈希 | 64 | SHA-2/3、BLAKE2/3、SM3、Streebog、Skein、Tiger、Whirlpool、Argon2 |
| 对称加密 | 63 | AES/ARIA/Camellia/SM4/Serpent/Twofish、Adiantum、Ascon、ChaCha20 |
| 非对称加密 | 30 | RSA-OAEP/PSS、SM2、SM9、IBE、SPAKE2+、HPKE |
| 后量子密码 | 15 | ML-KEM、ML-DSA、SPHINCS+、HQC、McEliece、FrodoKEM |
| 椭圆曲线与高级代数 | 22 | BLS12-381/377、BN254、Ed448/X448、KZG、Verkle、Bulletproofs |
| 校验和 / 认证加密 / 门限 / 古典 / 签名 / 密钥工具 | 32 | CRC 系列、Ascon-128a、Shamir、Feldman VSS、EdDSA、keygen |

完整清单见 `算法清单.txt`（项目根目录，含实测耗时）。

---

## 验证与质量

本项目对算法实现采取「**没有权威向量就不上线**」的原则：

- 优先使用 **RFC / NIST CAVP / BIP / 3GPP / 官方参考实现**提供的测试向量
- 拿不到官方向量时，编译官方 C 参考实现在沙盒内自产向量（如 McEliece、FrodoKEM、Adiantum）
- 关键算法做**双向**验证：不仅自己往返通过，还与独立实现（Python `gmalg`、`pycryptodome`、
  Botan、Google Adiantum 等）交叉比对字节一致性

测试脚本位于仓库中的 `t_*.js`，可用 Node 直接运行；`testvectors/` 存放已固化的官方向量。

---

## ⚠️ 安全免责声明

**本项目定位是密码学学习与工程验证工具，不是面向生产环境的安全产品。**

1. 部分算法**已被认为不安全**（DES、RC4、MD5、SHA-1、CAST5、RC2、Tiger 等），
   仅为兼容历史数据 / 教学对照而保留，界面内已标注安全提示，**请勿用于新系统**。
2. 未经专业安全审计，也未做侧信道防护（时序攻击等）加固。
3. 随机数依赖浏览器 `crypto.getRandomValues`；涉及高敏感场景请使用专业密码库。
4. 后量子算法中，部分参数集仍在标准化进程中，实现以官方参考版本为准。
5. **使用者需自行评估合规性风险，作者不对任何损失负责**（详见 `LICENSE` 的 AS IS 条款）。

---

## 第三方来源

实现过程参考了 Botan、Google Adiantum、Ascon 官方参考、BLAKE2 官方参考、liboqs、PQClean、
arkworks-rs、RHash、gmalg、TES、ocb3 等项目的**常量表与官方测试向量**，
以及 RFC / NIST / IEEE / BIP / 3GPP 的规范性数值。

详见 `THIRD_PARTY_NOTICES.md`，其中逐项列明原始许可证与兼容性。

需要说明的是：算法参数（S 盒、曲线参数、NIST 常量等）属于各标准组织公布的**规范性数值**，
为事实性数据，不受版权约束。

---

## 目录结构

```
index.html                     主界面
style.css                      样式
Encryption_and_decryption_logic.js   主逻辑与算法注册表
crypto_*.js                    各门类算法实现（按 index.html 中的顺序加载）
b377_*.js                      BLS12-377 配对与哈希到曲线
bls_const.js / pqc_*.js        配对常量与后量子核心
algo_picker.js                 算法选择逻辑
t_*.js                         测试脚本（Node 运行）
testvectors/                   固化的官方向量
attic/                         历史备份与开发中间产物（不参与分发）
LICENSE                        MIT 许可
THIRD_PARTY_NOTICES.md         第三方来源与许可声明
```

---

## 致谢

- 各标准组织（IETF、NIST、IEEE、3GPP、BIP）公开的规范与测试向量
- 上述开源密码学库的作者们
- 开发过程由 Laevatian 主导，AI 协作完成实现与验证

Copyright (c) 2026 Laevatian
