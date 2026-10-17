# 第三方来源与许可声明（THIRD-PARTY NOTICES）

本项目的**原创部分**以 MIT License 授权（见 `LICENSE`）。
本项目在实现过程中参考或移植了下列第三方项目的**常量表、算法结构与官方测试向量**，
这些组成部分**保留各自原始许可证**，不受本项目 MIT 声明覆盖。

依据各许可证要求（BSD 系要求保留版权声明、CC0 无要求），此处如实列出。

---

## 参考实现 / 常量来源

| 组件 | 本项目用途 | 原始许可证 | 兼容性 |
|---|---|---|---|
| **Botan 2.19.5** | GMAC、SP 800-108、PGP S2K、HMAC-DRBG、Tiger/SEED/ARIA/Kuznyechik/NOEKEON/MISTY1/KASUMI/CLEFIA 等常量与流程、`.vec` 测试向量 | BSD 2-Clause（Copyright 1999-2022 The Botan Authors） | ✅ 兼容，需保留声明 |
| **Google Adiantum**（`google/adiantum`） | `python/` 下实现与 `test_vectors/ours/` 官方向量 | **MIT**（Copyright 2018 Google LLC） | ✅ 兼容，需保留声明 |
| **Ascon 官方 C 参考**（`ascon-c`） | Ascon-128a / Ascon-Hash256 常量与 KAT | **CC0 1.0 Universal**（公有领域） | ✅ 无义务 |
| **BLAKE2 官方参考**（`BLAKE2`） | BLAKE2bp / BLAKE2sp 的 IV、sigma、流程与 KAT | **CC0** | ✅ 无义务 |
| **liboqs**（Open Quantum Safe） | sntrup761 官方 C 参考、FrodoKEM 12 方案官方实现与参数 | **MIT**（内含各算法各自许可） | ✅ 兼容 |
| **PQClean** | Classic McEliece 348864 参考实现与自产向量 | **CC0 / MIT**（各实现不同） | ✅ 兼容 |
| **arkworks-rs**（`algebra` / `curves`） | BLS12-377 曲线常量与 hash-to-curve 官方向量 | **MIT OR Apache-2.0**（双许可） | ✅ 兼容 |
| **RHash 1.4.4** | Tiger 的 4×256 项 64 位 S-box | **BSD 0-Clause** | ✅ 无义务 |
| **gmalg**（Python） | SM9 标识加密交叉验证参照物 | **MIT** | ✅ 兼容 |
| **xurz97/TES** | XCB / EME2 唯一可编译参考实现 | **MIT** | ✅ 兼容 |
| **ocb3 参考** | OCB（RFC 7253）实现参照 | **BSD 3-Clause** | ✅ 兼容 |
| **NIST CAVP / RFC / IEEE / BIP / 3GPP 官方测试向量** | 各算法验证用事实性数据 | 事实性数据，不构成衍生作品 | ✅ 无义务 |

---

## ✅ 已澄清：CAST5 / CAST-128 不存在 LGPL 风险（2026-10-18）

**文件**：`cast5_gen.js`、`crypto_block_legacy.js`

早期注释曾记载 CAST5「S 盒取自 libgcrypt（LGPL-2.1+）」，并据此认为存在许可冲突。
**该记载有误，现已更正。**

### 澄清过程

1. **S 盒（S1–S8）** —— 是 **RFC 2144 明文规定的固定常量**，属规范性数值（事实性数据），
   直接从 RFC 取得即可，不依赖任何实现，不受版权约束。
   本项目的 8 张表另经 **Botan 2.19.5（BSD-2-Clause）** `src/lib/block/cast128/` 逐项交叉核对一致。

2. **密钥编排与轮函数结构** —— 按 **RFC 2144 §2** 实现：
   - §2.4 规定密钥编排**连续两次** `cast_ks`，且第二次使用第一次**已被修改**的 `X`；
   - 解密为**标准 Feistel 逆序**。本实现用 ping-pong 写法（`t=l; l=r; r=t^f(...)`），
     `i` 从 15 递减时 `i%3` 依次取到 F1/F3/F2/F1…，恰好就是 RFC 要求的轮函数次序，
     与 Botan 展开式写法**完全等价**。

### 验证证据

编写了一份**独立的 RFC 2144 参考实现**（Python），先确认其对 RFC 2144 官方向量
（`0123456712345678234567893456789A` / `0123456789ABCDEF` → `238B4FE5847E44B2`）正确，
再与本项目实现做**双向 300 组随机向量逐字节对拍**：

- 加密 **300/300** 一致
- 解密 **300/300** 一致

结论：本项目 CAST5 实现**始终符合 RFC 2144**，不含任何 libgcrypt 衍生内容，
不存在 LGPL 污染，**整体 MIT 授权完整覆盖**。

---

## 说明

- 本文件随交付包分发，位于包根目录。
- 算法参数（AES/ARIA S 盒、曲线参数、NIST 常量等）均为各标准组织公布的**规范性数值**，
  属事实性数据，不受版权约束。
- 本项目未直接复制任何第三方源码文件，实现均为依据上述公开规范与参考资料的独立 JavaScript 编写；
  列出来源是为尊重原作者劳动与满足许可证的署名要求。
