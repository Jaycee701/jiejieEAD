# jiejieEAD · 加解密逻辑总览（可查 · 可试算）

> **版本**：v3.5（2026-09-16）　**配套**：工具内 Tab 11「加密逻辑总览」、
> 命令行 `crypto_logic_registry.py`
> **性质**：这是一份**查阅与比对用的索引**——遇到一段密文时，先来这里定位
> 「形态 → 算法 → 密钥来源 → 编码 → 完整性」，再决定用工具的哪个入口动手。

---

## 〇、怎么用这份文档（三条查阅路径）

| 你现在的处境 | 走哪条路 |
|---|---|
| 手上只有一段密文，不知道它是什么 | **第五章**「密文特征 → 逻辑反查表」按特征对号入座；或者直接贴进 Tab 10 / Tab 11 的「按特征匹配」 |
| 已经知道算法，卡在密钥从哪来 | **第二章 2.4 密钥来源层** + **第三章 18 个样本归纳**（每个样本就是一条"密钥怎么来"的实例） |
| 想确认工具能不能做某件事 | **附录 A**（全量清单，含每条的用途/场景/关系/状态）+ **第六章**「未支持清单」 |

> **一个铁律**：这套工具不预置任何目标的密钥。所有密钥都来自
> 「你粘贴的源码片段 / 你指定的目标目录 / 本地知识库里你已经学过的规则」。

---

## 一、核心模型：加解密逻辑 = 四层叠加

你给的《常见加密逻辑组合总结》里那句「三个独立维度拼出来的」是对的，
工具的实际实现把第三维拆成了两半，所以这里按**四层**来讲：

```
第 1 层  对谁加密        对称（SM4/AES/DES/3DES/RC4/RC5/RC6/Blowfish/CAST5/RC2/ChaCha20/Salsa20） 或 非对称（SM2/RSA）
                         └ 混合信封 = 两层各用一次（非对称包对称密钥）
第 2 层  密钥怎么来      硬编码常量 / 字面量 / 伪装常量切片 / 种子派生（KDF）/
                         非对称解封 / 密钥协商（工具不支持）
第 3 层  怎么编码压缩    base64 / base64url / hex / url / 双层 / 多级链 /
                         zlib / gzip / deflate（先压缩后加密最常见）
第 4 层  完整性怎么保证  无 / MAC（HMAC-SM3、HMAC-SHA256…）/ GCM tag / 签名（SM2/RSA）
```

**相互关系的三句话**：

1. 第 3 层在**解密之前**必须完全还原（编码倒序 + 解压），否则后面全错——
   工具把这一层做成「编码链」，并且会先剪掉解不开的链再铺组合；
2. 第 2 层决定密钥长度，密钥长度决定第 1 层用哪个算法
   （16B→AES-128/SM4、24B→AES-192/3DES、32B→AES-256）；
3. 第 4 层是**唯一的"确凿证据"来源**：mac 对上了就是解对了，打分只是辅助。

---

## 二、工具现有的加解密逻辑（按层归类）

> 完整清单见**附录 A**（96 条原子逻辑，由 `crypto_logic_registry.py --export-md` 自动导出）。
> 这里只讲每层的**职责、取舍和层间关系**，便于形成整体图景。

### 2.1 第 1 层：算法与模式（algo / mode / padding）

| 类别 | 工具支持 | 关键取舍 |
|---|---|---|
| 分组/流算法 | SM4、AES-128/192/256、DES、3DES、RC4、RC5-32/12/16、RC5-32/16/16、RC5-64/16/16、RC6-32/20/16、RC6-32/16/16、Blowfish、CAST5、RC2、ChaCha20、Salsa20 | 密钥长度定算法：16B→AES128/SM4；24B→AES192/3DES（注意 3DES 分组是 **8 字节**）；任意长度→RC4/Blowfish/RC2；**分组 8 字节的算法没有 GCM**；RC5/RC6 为自实现（已用公开向量验证，比原生库慢约两个数量级）；ChaCha20/Salsa20 是带 nonce 的流密码（RC4 则无 nonce） |
| 模式 | ECB、CBC、CFB、OFB、CTR、GCM、STREAM | ECB 无 IV；CBC 要 IV；CFB/OFB/CTR 无填充且密文长度=明文长度；GCM 尾部多 16 字节 tag 且支持 AAD |
| 填充 | PKCS7、Zero、None、ISO7816、ANSIX923 | 只有 ECB/CBC 用填充；老系统爱用 ZeroPadding；**填充维度必须和算法一起试**（样本 15） |

**层间关系**：`padding` 只对 ECB/CBC 有意义，工具会自动把流式模式的填充压成 none；
`mode` 决定 IV 的长度要求（AES/SM4=16B，DES/3DES=8B，GCM=12/16B）——**IV 长度给错直接报错**。

### 2.2 第 2 层：密钥来源（keyfmt / kdf / keysrc）

**先讲最容易踩的坑——密钥文本格式（keyfmt）**：

| 格式 | `"4A7F2C1E9B3D5A08"` 的含义 | 什么时候用 |
|---|---|---|
| HEX | 8 字节 | 密钥是纯十六进制串 |
| **UTF-8** | **16 字节** | **前端写 `var KEY="..."` 时几乎都是这个**（16 个可打印字符 = 16 字节） |
| Base64 | 解码后 11 字节 | 密钥以 Base64 存在构建产物里 |
| auto | 自动挑一个长度匹配的 | 不确定时先用 `--keyinfo` 看三种解释的字节数 |

**KDF（密钥派生）—— 8 个预设**：

| 预设 | 输出 | 典型场景 |
|---|---|---|
| `digest-sha256` / `digest-md5` / `digest-sm3` | 32/16/32 字节 | 密钥 = 摘要(种子)，常配 slice |
| `hmac-sha256` / `hmac-sm3` | 32 字节 | 带盐派生（盐也是硬编码常量） |
| `aes-cbc-then-sha256` | 32 字节 | 白盒前端两层派生 |
| **`aes-cbc-then-sha256-slice`** | **16 字节** | **银行 H5 最常见**：AES-CBC(种子)→SHA256→取[16:32] |
| `sm4-cbc-then-sm3` | 32 字节 | 纯国密链路 |

> 修复记录：`digest-*` 预设原本**没有 slice 步骤**，传 `slice_start/end` 会被静默忽略
> （标着取前 16 字节、实际拿 32 字节）。已在引擎层统一补齐——只要调用方要了区间
> 而预设里没人接，就自动追加一个 slice 步骤。

**材料来源（keysrc）—— 工具从哪把密钥挖出来**：

| 来源 | 识别方式 | 对应样本 |
|---|---|---|
| 伪装常量（data URI / 长 Base64） | 解码后是可打印文本、长度 32/64/67 | 01/02/10 |
| 命名密钥字面量（`AES_KEY`/`IV`/`NONCE`） | 按变量名抓，三种解释都产出 | 03~09/11/13~15 |
| 定长切片 | 32+16+16+3 或 32+32 的拼法 | 01/02 |
| 派生链识别 + 跨文件绑定 | A 文件定算法、B 文件给常量 | （Tab 5） |
| PEM 私钥 / 十六进制私钥 | `-----BEGIN ... PRIVATE KEY-----` 或 `SM2_PRIV="<64hex>"` | 17/18 |
| 本地知识库 | 以前解过的「密文特征 → 方案」 | （Tab 4/5） |
| 报文头部字段当种子 | head 解出的 wx、时间戳、deviceId | 01/02/12/16 |

### 2.3 第 3 层：编码与压缩（encoding / compress / chain）

**必须先说清的一个口径差异**（写文档时最容易踩）：

> **引擎与求解器的编码链方向正好相反。**
> - 引擎 `encode_chain / decode_chain`：列出的步骤 = **编码时施加的顺序**（解码自动倒序）；
>   样本 13 的 `hex(base64(ct))` 写成 `[base64, hex]`。
> - 求解器 `cipher_auto_solver._decode_ciphertext`：列出的是**解码时施加的顺序**；
>   同一个样本写成 `[hex, base64]`。
>
> 本登记表与 CLI `--chain` 统一按**引擎口径**（编码顺序）。

| 链 | 编码顺序 | 对应样本 |
|---|---|---|
| 单层 Base64 | base64 | 03/06/07/08/12/15/17/18 |
| 双层 Base64 | base64 → base64 | 09 |
| Base64→HEX（= `hex(base64(ct))`） | base64 → hex | 13 |
| Base64→URL（= `url(base64(ct))`） | base64 → url | 14 |
| 压缩 + 加密 | zlib/gzip → 对称加密 | 04（gzip）、13（zlib） |

压缩支持 zlib / gzip / deflate / **deflate-raw**（pako 的 deflate 是裸流，容易搞混），
解压时会先按魔数猜（`78 9C`=zlib、`1F 8B`=gzip），猜错自动轮询其它三种。

### 2.4 第 4 层：完整性与 mac（digest / hmac）

| 摘要/HMAC | 字节 | Base64 长度 | 备注 |
|---|---|---|---|
| MD5 / HMAC-MD5 | 16 | 24 | 弱，老系统 |
| SHA-1 / HMAC-SHA1 | 20 | 28 | 弱，老系统 |
| SHA-256 / HMAC-SHA256 | 32 | **44** | 现代；**与 HMAC-SM3 等长，分不出来** |
| SHA-512 / HMAC-SHA512 | 64 | 88 | 少见 |
| SM3 / HMAC-SM3 | 32 | **44** | 国密 |

> **mac 算法自适应**：44 字符（32 字节）的 mac 无法从长度区分 SM3 还是 SHA256，
> 工具按「长度 → 候选算法」的表逐个试（32B→SM3/SHA256、20B→SHA1、16B→MD5、64B→SHA512）。
> **mac 覆盖范围（scope）** 同样关键：常见是「被保护的字段 + cipher」或「解码前的密文文本」；
> 范围算错必然对不上——而**设计里漏签的字段就是注入点**。

### 2.5 非对称与混合信封（asym / envelope）

| 能力 | 关键点 |
|---|---|
| SM2 加解密 | C1C3C2（国标）/ C1C2C3（老实现）两种排序都要试；可带 ASN.1(DER)、prehashed |
| SM2 签名验签 | SM3withSM2 的 Z 值含公钥分量 → **只给私钥时验签必失败**，须先从私钥推公钥 |
| RSA 加解密 | PKCS#1 v1.5 / OAEP(sha1/sha256)；长文本自动分段（encryptLong2） |
| RSA 签名验签 | v1.5 / PSS，摘要 md5~sha512 |
| 密钥对生成 | `--keygen sm2` / `--keygen rsa:2048`（调试与自造样本用） |
| 混合信封 | 非对称包对称密钥 + 对称加密数据；**国内 App 最主流** |

> **两个必须记住的坑**：
> 1. **RSA PKCS#1 v1.5 解密没有完整性校验**——用错填充解错也不报错、返回垃圾字节。
>    所以信封解封结果必须是 **16/24/32 字节**（对称密钥长度），工具靠长度筛垃圾，
>    并把 OAEP 排在 v1.5 前面。
> 2. **GCM nonce 复用** = 认证密钥可恢复；**ECB / 固定 IV 的 CBC** = 可重放/字典。
>    工具负责把参数摆出来，利用与否由你判断。

### 2.6 报文框架识别（frame）——先认形状再选逻辑

| 形态 | 特征 | 说明 |
|---|---|---|
| 整段 HTTP | 有报文头 | 自动取 body |
| 裸 Base64 / Base64URL / HEX / URL | — | **纯 HEX 必须优先于 Base64 判**（否则解成乱码） |
| 种子前置 | 32hex + Base64 | 种子明文前置，配 `SHA256(种子)[0:16]` |
| JSON 混合信封 | `{...}`，含包裹密钥字段 + 密文字段 | 字段名自动识别（encKey/sked ↔ data/ed ↔ iv/nonce） |
| 混杂文本 | 密文与源码/日志粘在一起 | 先抽最长密文段（≥120 字符；找不到再放宽到 ≥44 字符并按「不可打印 + 分组对齐」过滤），再从整段挖常量 |

---

## 三、14 个样本的逻辑归纳（对照实验结论）

> 每个样本都是「四层叠加」的一条完整实例。工具的验证方式是：
> 只给 `cipher.txt` 与目标源码目录，让它自己挖材料、自己定配方、自己解，
> 并与 `expect.json` 的标准答案**逐字比对**。**14/14 全部解出。**

| # | 样本 | 第 1 层（算法·模式·填充） | 第 2 层（密钥来源） | 第 3 层（编码/压缩） | 第 4 层（完整性） |
|---|---|---|---|---|---|
| 03 | AES128-CBC | AES-128-CBC/PKCS7 | 命名字面量（UTF-8 解释） | Base64 | — |
| 04 | AES256+gzip | AES-256-CBC/PKCS7 | 命名字面量（UTF-8，32 字节） | **Base64URL**，**内层 gzip** | — |
| 05 | 3DES-CBC | 3DES-CBC/PKCS7（分组 8） | 命名字面量（HEX 解释，24 字节） | HEX | — |
| 06 | RC4 | RC4/STREAM/无填充 | 命名字面量（UTF-8） | Base64 | — |
| 07 | SM4-CTR | SM4-CTR/无填充 | 命名字面量 | Base64；**IV 前置 16 字节** | — |
| 08 | AES128-GCM | AES-128-GCM/无填充 | 命名字面量 | Base64；**nonce 前置 12 字节** | GCM tag + AAD |
| 09 | AES128-ECB | AES-128-ECB/PKCS7 | 命名字面量 | **双层 Base64** | — |
| 11 | SM4-ECB 裸 HEX | SM4-ECB/PKCS7 | 命名字面量（**Base64 解释**） | **HEX** | — |
| 12 | 种子前置 | SM4-ECB/PKCS7 | **种子前置** → `SHA256(种子)[0:16]` | Base64 | — |
| 13 | AES192+zlib+多级 | AES-192-CBC/PKCS7 | 命名字面量（24 字节） | **base64→hex 多级链**，内层 zlib | — |
| 14 | DES-CBC+URL | DES-CBC/PKCS7（分组 8） | 命名字面量（8 字节） | **base64→url** | — |
| 15 | SM4-ECB+Zero | SM4-ECB/**ZeroPadding** | 命名字面量 | Base64 | — |
| 17 | RSA 信封 | SM4-CBC/PKCS7 | **PEM 私钥** → RSA-OAEP/SHA-256 解封 | Base64 | — |
| 18 | SM2 信封 | SM4-CBC/PKCS7 | **十六进制私钥** → SM2 C1C3C2 解封 sked | Base64 | — |

**从这批样本里固化下来的两条经验**：

1. **纯 HEX 必须先于 Base64 判**——纯 hex 串同时满足 Base64 字符集，
   判错顺序就会把末尾 44 字符当 mac 切掉（样本 05/11 曾因此全军覆没）；
2. **明文打分必须按字符算**——UTF-8 汉字占 3 字节、全在 0x20~0x7E 之外，
   按字节算可打印率，一篇纯中文明文会被冤枉成乱码（样本 04/12）。

---

## 四、常见加解密逻辑组合（渗透视角 · 含工具对照）

> 本章把你给的《常见加密逻辑组合总结》与公开案例配方**收编进来**，
> 并逐条标注工具的支持情况：✅ 已支持 / ⚠️ 部分支持（需人工补一步） / ❌ 未支持。

### 4.1 对称加密 + 密钥来源（最核心的一维）

| 组合 | 工具 | 说明 |
|---|---|---|
| 硬编码固定 key | ✅ | `keysrc.literal`（三种解释都产出） |
| 固定 key + 随机 IV 前置 | ✅ | 自动试「密文前 8/12/16 字节是 IV」（样本 07/08） |
| 固定 key + 派生（MD5(盐+时间戳) 之类） | ✅ | `kdf.*` 预设 + 自定义链 |
| 随机会话 key + 非对称包 key（★ 国内 App 最常见） | ✅ | `envelope.*`（样本 17/18）；某银行 App 的封装形态 `base64(JSON)→AES-128-ECB(16位随机十进制key)→RSA-2048包key` 即此形态 |
| 密钥协商（ECDH / SM2 交换，一次一密） | ❌ | 见 `gap.key-exchange`：抓包只见公钥交换，须实现层支持 |

### 4.2 对称加密内部的组合

| 组合 | 工具 | 备注 |
|---|---|---|
| ECB 无 IV | ✅ | 国内占比极高 → 块重放/块替换/字典（利用需手工） |
| CBC + PKCS7 + 固定 IV | ✅ | 等价弱化版 ECB；padding oracle 工具不自动打 |
| CTR/CFB/OFB + 固定 nonce | ✅ | 密钥流固定 → 明文异或即得密文 |
| 加密 then MAC vs MAC then encrypt | ⚠️ | 工具能复现两种顺序的 mac 计算，但**不自动判断谁先谁后**——靠 scope 试 |
| 套娃编码 `enc→base64→urlencode→base64` | ✅ | `chain.*` 多级链（样本 09/13/14） |
| 压缩 + 加密（gzip/AES） | ✅ | `compress.*` + 自动魔数嗅探（样本 04/13）；CRIME/BREACH 属实现层 |

### 4.3 完整性与签名的组合

| 组合 | 工具 | 备注 |
|---|---|---|
| 参数排序→拼接 `&key=secret`→MD5/SHA1/HMAC→sign | ⚠️ | `--digest`/`--hmac` 可复现计算；**排序与拼接要手工拼串**；漏签字段=注入点 |
| 国密：SM3 摘要 + SM2 签名 | ✅ | `asym.sm2-sign`（SM3withSM2）；双证书分离属协议层 |
| 时间戳 + nonce + sign 三件套 | ⚠️ | 这是**验证**手段：改 timestamp / 重放 nonce，看服务端认不认（工具外用 Burp 做） |
| 只加密不签名 | ✅（识别） | 可构造任意密文提交 |
| 只签名不加密 | ✅（识别） | 可读但改不了 |
| 密文无完整性保护（翻转 1 bit 仍被接受） | ⚠️ | 工具能解出密文供你改，重放与验证在抓包工具里做 |

### 4.4 分场景的典型落地组合

| 场景 | 常见做法 | 工具 |
|---|---|---|
| 登录 | RSA 加密整个密码体 / MD5(密码) 加盐 / 挑战应答 / SM2 加密密码 + SM4 会话密钥 | ✅（SM2/RSA/AES/SM4 都齐） |
| 请求 | 整体 SM4-ECB + sign 头 / AES-CBC + 头里带 keyId·version（**老版本密钥可能没下线**） | ✅ |
| 响应 | 整体 SM4/AES 加密，App 内置解密材料（如某银行 App：响应 SM4-ECB，需 App 内 SM2 公钥）/ 仅敏感字段加密 | ✅ |
| 文件/大流量 | 分块 AES-CBC（❌ 分块流式）/ 预签名 URL（⚠️ 签名过期、路径穿越需人工看） | ⚠️ |
| **公开案例** | 拼多多 anti-token：RSA-1024 包 32B random_key + AES-256-CBC(iv=0) + JSON{key,data}；短签名 "2ag"+Base64，长签名 "2af"+Base64(AES(GZIP(TLV))) | ✅（信封）/ ❌ TLV 解析 |
| **公开案例** | Flutter 壳：请求体以 `.` 分隔，前段 ≈334B 是 RSA 包的 key | ⚠️ 自定义分隔符不自动切 |
| **公开案例** | RSA-OAEP + AES-GCM + HMAC-SHA256（密文拼接 时间戳+随机 Base64 再算 HMAC） | ✅ |
| **公开案例** | 企业 IM：SM2 公钥包 32B 会话密钥 + SM4(ECB/CBC) 业务体 + SM3/HMAC；**缺陷是 ParamsBuilder.java 硬编码 SM2 公钥、CacheTask.java 硬编码 SM4 key** | ✅ |
| **公开案例** | 豆瓣 `_sig`：AES/CBC/**NoPadding** 固定 IV `DOUBANFRODOAPPIV` + HMAC-SHA1（密钥由应用签名生成） | ✅（算法层）/ ⚠️（签名密钥来自签名动态生成） |
| **公开案例** | Soul：SM4 密钥不落 so，由 Java 层按 sessionId 经 `generateKey()` 动态生成 | ❌（见 `gap.native-kdf`，只能动态 Hook） |

### 4.5 识别要点与爆破优先级（收编自你的总结）

**最快的识别路径（看密文特征反推）** —— 已整理成**第五章的反查表**并实现进 Tab 11。

**爆破优先级（从高到低）**：

1. 搜硬编码 key（反编译 + 特征扫描）—— 工具的 `keysrc.*` 就是干这个的
2. ECB → 块重放 / 块替换 / 字典 —— 工具还原算法，利用靠手工
3. 固定 IV + CBC → 可预测 IV 构造
4. MAC 不校验内容 → 改密文绕过（实例：某银行 App 的 mac 头）
5. 无重放保护 → 直接重放交易包（实例：某银行 App）
6. 降级请求 / 老版本协议通道（实例：某系统降级通道下 MAC 密钥硬编码、
   内置 RSA 私钥可离线自签——**登录态仍不可伪造**）

**判断标准（一句话）**：只要"加密密钥"或"签名密钥"有一份在客户端，
这套组合就只剩混淆强度，不剩密码学强度。

### 4.6 静态检索与动态 Hook 清单（工具外动作，收编备查）

- **静态 grep**：`Cipher.getInstance("...")`、`ECB|DES|RC4|MD5|SHA-1`、
  `SecretKeySpec`、`IvParameterSpec`、`new Random()`、`SHA1PRNG`、`setSeed`、
  `ANDROID_ID`、`AndroidKeyStore`、`RSA/ECB/NoPadding`
- **Frida Hook 点**：`SecretKeySpec.$init`（抓硬编码 key）、`Cipher.init`（key/IV/算法/方向）、
  `Cipher.doFinal`（明文/密文）、`getIV/getAlgorithm`；
  同设备多次运行对比 key 是否变化 → 判定是否硬编码；记录 (key,iv) 对 → 判定 nonce 复用
- **密钥的"非硬编码"花样（静态提取会漏）**：native 拼接、多来源合成、
  分散存储/移位/异或/置换表、运行时解密、sessionId 经 KDF 派生（最强）
- **已知易漏的对抗形态**：`.so` 内 RegisterNatives、内嵌 LuaJIT VM、
  算法拆在 Java+native+VM 三层、主流量算法迭代快
- **工具链**：静态 jadx / Ghidra / MobSF / Blutter；动态 Frida；
  抓包 Burp / Charles / mitmproxy（国密 TLS 可用 Yakit）；闭环 = 真实密文回解出明文 JSON

---

## 五、密文特征 → 逻辑反查表（18 条）

> 这张表已实现进 Tab 11 的「按特征匹配」和 CLI `--match`：
> 贴一段密文 → 工具量出特征 → 按这张表给出"该优先试哪几条"。

| # | 密文特征 | 结论 | 优先试 |
|---|---|---|---|
| f01 | 长度是 16 的倍数 + Base64 | 分组密码 AES/SM4（也可能是 DES/3DES，分组 8） | base64 → aes128/sm4/aes256/pkcs7 |
| f02 | 解码后长度不是分组整数倍 | 流式（CTR/GCM/CFB/OFB/RC4）或加密后又编码 | ctr/gcm/rc4/chain |
| f03 | 密文长度 ≈ 明文长度 | 流式加密，或 ECB 无填充 | ctr/ofb/rc4/none |
| f04 | 请求里一长一短两个字段（短的约 344 字符） | 短的极可能是「包 key」（RSA-2048 密文 Base64 后约 344 字符） | envelope.rsa / envelope.json |
| f05 | 同明文两次密文相同 | ECB 或固定 IV 的 CBC → 可重放/字典 | ecb / frame / keysrc |
| f06 | 同明文两次密文不同、前 16 字节随机 | IV 前置 | cbc / ctr / gcm |
| f07 | 纯 HEX、长度 %32==0 | SM4/AES 密钥或密文；**必须先于 Base64 判** | hex / raw-hex |
| f08 | 含 `-` `_`，或长度 %4≠0 却无 `=` | Base64URL | base64url |
| f09 | 含 %XX 转义 | URL 编码，里面通常还套一层 | url / chain |
| f10 | 解码后开头 `78 9C` / `1F 8B` | zlib / gzip 压缩数据 | zlib / gzip / sniff |
| f12 | 整段 JSON、含两个长字符串字段 | 混合信封（一个包 key、一个密文） | envelope.* / keysrc.pem |
| f13 | 末尾 44 字符 Base64（=32 字节） | 报文 mac：HMAC-SM3 或 HMAC-SHA256（等长分不出） | hmac.auto |
| f14 | 末尾 mac 是 28 / 24 / 88 字符 | HMAC-SHA1 / HMAC-MD5 / HMAC-SHA512 | hmac.auto |
| f16 | 源码里 `data:image/...` 挂着长 Base64 | 伪装常量（解开是打包的多个参数） | keysrc.disguised / keysrc.slice |
| f17 | 源码里 `var KEY="<16 个可打印字符>"` | 16 字节 UTF-8 密钥（不是 8 字节 HEX） | keyfmt.utf8 / keyfmt.auto |
| f18 | Header 带 timestamp/nonce 但内容不变 | 大概率没真校验（可重放） | 用 Burp 验证 |
| f19 | 密文比明文长 1~16 字节 | 分组密码 + 填充（差值=填充字节数） | pkcs7 / zero |
| f20 | Base64 解码后全是不可打印字节且长度整齐 | 标准分组密文（不是编码套编码） | 直接进解密矩阵 |

---

## 六、工具暂不支持的逻辑（gap）与补法

| 缺口 | 现状 | 怎么补 |
|---|---|---|
| 白盒 SM4（自定义 S-box/查表） | ❌ | 需先把查表还原回标准 SM4（按目标单独写） |
| 自定义算法（SIMON/SPECK、魔改轮函数，如 TikTok X-Argus） | ❌ | 每个目标一套实现；工具只能帮你剥掉编码/压缩层 |
| 密钥协商（ECDH / SM2 交换） | ❌ | 最强的一类，只能打实现层（弱随机、复用） |
| 国密 TLS（GB/T 38636-2020） | ❌ | 传输层就换了国密栈，需 Yakit 一类支持国密的代理 |
| Native / so 内派生（sessionId 经 KDF） | ❌ | 静态分析失效，需 Frida 动态 Hook |
| 非标准编码（自定义 base 码表） | ❌ | 需已知明文对推测码表 |
| TLV / Protobuf 结构解析 | ❌ | 工具只剥编码/压缩层，不解析业务结构 |
| 超大文件分块流式 | ⚠️ | 当前文件模式上限 32MB、明文上限 4MB |

---

## 七、新模块：加密逻辑总览（Tab 11 / CLI）

### 7.1 GUI（Tab 11「加密逻辑总览」）

- **左侧分类树**：17 个分类（算法/模式/填充/密钥格式/派生/材料来源/摘要/HMAC/编码/
  压缩/编码链/非对称/信封/报文框架/组合配方/特征规则/未支持），带计数，可点选；
- **中间逻辑卡片**：每条显示名称、用途、适用场景、参数、与其他逻辑的关系、
  支持状态（✅/⚠️/❌）、对应样本、CLI 复现命令；顶部有**关键词搜索**；
- **右侧试算面板**：选中任一条逻辑 → 填密文/明文 + 密钥/IV/方向 → 「按此逻辑试算」，
  直接出结果（加密给 Base64+HEX，解密给明文/HEX，失败给可读原因）；
- **顶部反查区**：贴一段密文 → 「按特征匹配」→ 列出命中的特征规则与建议试解顺序，
  可一键交给一键解密流水线。

### 7.2 CLI（`crypto_logic_registry.py`）

```bash
# ① 全量清单（按分类 / 关键词筛选）
crypto_logic_registry.py --list
crypto_logic_registry.py --list --cat envelope
crypto_logic_registry.py --list --q 安全键盘 --json

# ② 密文特征规则表
crypto_logic_registry.py --features

# ③ 贴密文 → 按特征反推该试哪些逻辑
crypto_logic_registry.py --match --text "<密文或报文>" 
crypto_logic_registry.py --match --file 密文.txt --json

# ④ 按指定逻辑对密文/明文试算
crypto_logic_registry.py --apply algo.sm4 --text 明文 --key 00112233445566778899aabbccddeeff --op enc
crypto_logic_registry.py --apply algo.sm4 --text <Base64密文> --key ... --op dec
crypto_logic_registry.py --apply kdf.digest-sha256 --seed 5f2c... --slice 0:16
crypto_logic_registry.py --apply envelope.sm2 --text <cipher_hex> --private-key <hex> \
                          --wrapped-key <hex> --op dec
crypto_logic_registry.py --apply frame.json-envelope --text "<报文>"   # 只做形态识别

# ⑤ 导出本文档附录 A（与代码同源，改代码后重跑即可刷新）
crypto_logic_registry.py --export-md --out 加密逻辑清单.md

# ⑥ 自检（44 项：分类 / 清单 / 反查 / 执行 / 导出）
crypto_logic_registry.py --selftest
```

### 7.3 与其它入口的关系

```
Tab 1  加解密工作台      手工拼参数（最灵活）
Tab 4/5 文件/文件夹分析  从目标源码里挖材料、跨文件合成配方
Tab 10 一键解密          全自动：贴密文 → 分析 → 试解 → 明文+依据
Tab 11 加密逻辑总览      【本模块】先看有什么逻辑 → 按逻辑试算 / 按特征反查
CLI    cli_crypto.py    所有原子能力的命令行入口（每条逻辑都带复现命令）
       crypto_logic_registry.py  逻辑目录 + 试算 + 反查 + 导出
       cipher_auto_solver.py     一键解密流水线（Tab 11 的"组合配方"直接调它）
```

**一句话分工**：Tab 11 负责「**知道有什么**」，Tab 10 负责「**自动试出来**」，
Tab 1/4/5 负责「**手工精细控制**」。

---

## 八、速查：CLI 能力一览（与逻辑 ID 对应）

| 想做什么 | 命令 |
|---|---|
| 对称加解密 | `cli_crypto.py --alg sm4 --mode ecb --padding pkcs7 --op dec --key <hex> --text <b64>` |
| 密钥三种解释字节数 | `cli_crypto.py --keyinfo --key "4A7F2C1E9B3D5A08"` |
| 摘要 / HMAC | `cli_crypto.py --digest sm3 --text "..."` / `--hmac hmac-sm3 --key ... --text ...` |
| 密钥派生 | `cli_crypto.py --derive aes-cbc-then-sha256-slice --seed <种子> --derive-key ... --derive-iv ... --slice 16:32` |
| 非对称 | `cli_crypto.py --sm2 enc --public-key ... --text ...` / `--rsa dec --private-key ...` |
| 密钥对 | `cli_crypto.py --keygen sm2` / `--keygen rsa:2048` |
| 压缩 | `cli_crypto.py --zip enc --zip-algo gzip --text ...` |
| 编码链 | `cli_crypto.py --chain base64 --op dec --text ...` |
| 混合信封 | `cli_crypto.py --envelope enc --recipient sm2 --public-key ... --text ...` |
| 一键解密 | `cli_crypto.py --auto-solve --file 密文.txt --target-dir <目标目录>` |
| 能力矩阵 | `cli_crypto.py --spec` |
| 逻辑总览 | `crypto_logic_registry.py --list / --match / --apply / --export-md` |

---

> **最后重复一遍那条判断标准**：只要"加密密钥"或"签名密钥"有一份在客户端，
> 这套组合就只剩混淆强度，不剩密码学强度——区别只在于你要花多少时间，
> 把设备里的密码学还原成算法。这份文档 + 这套工具，就是把"花的时间"压到最短。

---

## 附录 A · 工具加解密逻辑全量清单（自动导出，勿手改）

> 由 `crypto_logic_registry.py --export-md` 生成；与工具实际能力同源，
> 改代码后重跑即可刷新。共 103 条原子逻辑 / 19 条组合配方 / 18 条特征规则（其中用户添加 0 条，已隐藏内置 0 条）。


### A.1 分组 / 流算法（17 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `algo.sm4` | SM4（国密分组） | 中国商用分组密码标准（GB/T 32907），分组 128 位、密钥固定 128 位。 | 金融 / 政务 / 国密 App / 小程序；国内 App 的默认选择，出现频率最高。 | mode.*、padding.*、chain.*、hmac.hmac-sm3、asym.sm2 | ✅ | — |
| `algo.aes128` | AES-128 | AES 分组密码，128 位密钥（16 字节）。 | 国际通用；老系统 / 原生 App / Node 默认分段最常见。 | mode.*、padding.*、chain.*、hmac.hmac-sha256 | ✅ | — |
| `algo.aes192` | AES-192 | AES 分组密码，192 位密钥（24 字节）。 | 较少见；遇到 24 字节密钥时优先怀疑它（3DES 也是 24 字节，两者要靠长度+模式区分）。 | algo.des3、mode.* | ⚠️ | — |
| `algo.aes256` | AES-256 | AES 分组密码，256 位密钥（32 字节）。 | 现代 App / 反爬 Header / 文件加密的常见选择。 | mode.*、padding.*、chain.* | ✅ | — |
| `algo.des` | DES | 老式分组密码，64 位分组 / 56 位有效密钥（8 字节）。 | 2010 年前后的老核心系统；现在只在兼容老接口时见到，属于「能解出来就行」的场景。 | algo.des3、mode.* | ✅ | — |
| `algo.des3` | 3DES（Triple DES） | DES 的三次迭代，密钥 24 字节（也兼容 16 字节两密钥写法），分组仍是 64 位。 | 银行老核心 / 收单系统的常见算法；注意 **分组是 8 字节**，IV 必须是 8 字节——用 16 字节 IV 会直接报错。 | algo.des、mode.cbc、keyfmt.* | ✅ | — |
| `algo.rc4` | RC4（流密码） | 流密码，密钥长度 5~256 字节皆可，无 IV、无填充。 | 老式「伪加密」与自定义 Header 签名（如毫秒时间戳 → RC4 → Base64）。 | mode.stream | ⚠️ | — |
| `algo.rc5` | RC5-32/12/16（自实现） | 参数化分组算法：32 位字、12 轮、16 字节密钥、**分组 8 字节**。字节序按 OpenSSL/BouncyCastle 惯例（字小端）。 | 老式客户端与教学实现；轮数/字长可变的变体也已单独登记。**无 GCM**（GCM 构造按 128 位分组实现）。 | algo.rc6、mode.cbc | ✅ | — |
| `algo.rc5_16` | RC5-32/16/16（自实现） | RC5-32 的 16 轮变体，其余同 RC5-32/12/16。 | 目标把轮数调到 16 时用。 | algo.rc5 | ✅ | — |
| `algo.rc5_64` | RC5-64/16/16（自实现） | 64 位字变体，**分组 16 字节**，因此可用 GCM。 | 少数产品用 64 位字 RC5；分组与 RC6 相同。 | algo.rc5、mode.gcm | ✅ | — |
| `algo.rc6` | RC6-32/20/16（自实现） | AES 竞赛的五个决赛算法之一：32 位字 ×4、20 轮、分组 16 字节，可选 GCM。 | 少数嵌入式/老系统；已用 BouncyCastle（源自 AES 提交的 RSA 参考实现）向量验证。 | algo.rc5、mode.gcm | ✅ | — |
| `algo.rc6_16` | RC6-32/16/16（自实现） | RC6 的 16 轮变体，分组仍为 16 字节。 | 轮数与标准不同的 RC6 变体。 | algo.rc6 | ✅ | — |
| `algo.blowfish` | Blowfish | 经典 16 轮 Feistel，**分组 8 字节**、密钥 4~56 字节可变长。 | 老产品与 OpenSSL 的 bf-* 系列；分组 8 字节故无 GCM。已用 Eric Young 标准向量验证。 | algo.cast5、mode.cbc | ✅ | — |
| `algo.cast5` | CAST5 / CAST-128 | 分组 8 字节，**密钥仅支持 5 / 8 / 16 字节**（其它长度底层直接拒绝）。 | OpenSSL 的 cast5-* 系列、部分 PGP 实现。已用 RFC 2144 向量验证。 | algo.blowfish | ✅ | — |
| `algo.rc2` | RC2 | 分组 8 字节，密钥 5~128 字节；**另有 effective key bits 参数**。 | **该参数不对是 RC2 解成乱码的头号原因**（RFC 2268 的测试向量用的是 63，底层默认 128）。CLI 用 --rc2-effective-bits 调整。已用 RFC 2268 向量验证。 | algo.des | ✅ | — |
| `algo.chacha20` | ChaCha20（流密码） | 流密码，**密钥必须 32 字节**，**必须给 nonce**（8 / 12 / 24 字节，12 字节为 RFC 7539 变体）。 | 现代 TLS / QUIC 场景；与 RC4 不同，它需要 nonce。已用 RFC 8439 向量验证。 | mode.stream、algo.salsa20 | ✅ | — |
| `algo.salsa20` | Salsa20（流密码） | 流密码，密钥 16 / 32 字节，**nonce 只能 8 字节**。 | ChaCha20 的前身；老库（如 libsodium 早期）常见。已用 eSTREAM 官方向量验证。 | mode.stream、algo.chacha20 | ✅ | — |

### A.2 工作模式（7 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `mode.ecb` | ECB（电码本） | 每块独立加密，无 IV。相同明文块 → 相同密文块。 | 国内 App 占比极高（实现最省事）。密码学上是不安全模式：可直接做块重放 / 块替换 / 字典攻击；也正是最容易利用的模式。 | algo.*、padding.* | ✅ | — |
| `mode.cbc` | CBC（密码分组链接） | 前一块密文参与下一块，需要 IV；IV 固定时等价于弱化版 ECB。 | 最常见的分组模式；有 IV 前置 / 固定 IV / 全零 IV 三种常见写法。 | mode.ecb、padding.*、frame.* | ✅ | — |
| `mode.cfb` | CFB（密文反馈） | 把分组密码当流密码用，需要 IV，无填充。 | 少见但存在；密文长度 = 明文长度是它的标志。 | mode.ofb、mode.ctr | ⚠️ | — |
| `mode.ofb` | OFB（输出反馈） | 密钥流由 IV 反复加密生成，需要 IV，无填充。 | 同上，常见于自定义协议。 | mode.cfb、mode.ctr | ⚠️ | — |
| `mode.ctr` | CTR（计数器） | 对计数器加密得到密钥流，需要 IV/nonce，无填充。密文长度 = 明文长度。 | 现代实现常用；**nonce 复用即灾难**（密钥流复用 → 明文异或即得）。 | mode.ofb、asym.* | ⚠️ | — |
| `mode.gcm` | GCM（认证加密 AEAD） | CTR 加密 + GHASH 认证，输出密文尾部多 16 字节 tag，可带 AAD。 | 现代 App / API 的默认模式；支持 AAD（如 appid=9988&v=1 这种固定串）。**nonce 复用会导致认证密钥被恢复。** | mode.ctr、hmac.* | ⚠️ | 08 |
| `mode.stream` | STREAM（天然流密码） | RC4 这类算法没有分组模式概念，等价于流式；无 IV、无填充。 | 配 algo.rc4 使用。 | algo.rc4 | ⚠️ | — |

### A.3 填充方式（5 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `padding.pkcs7` | PKCS#7 填充 | 补 n 个值为 n 的字节，解密后按最后一字节校验并剥除。最标准、最常见的写法。 | AES / SM4 / DES 的 ecb、cbc 默认填充；**PKCS#7 校验不过通常直接说明密钥或参数错**。 | mode.ecb、mode.cbc | ✅ | — |
| `padding.zero` | ZeroPadding（补零） | 补 0x00 到分组整数倍；解密后剥掉尾部零字节。 | 老系统 / CryptoJS 的 ZeroPadding。注意：明文本身以 0x00 结尾时会误剥。 | padding.pkcs7 | ✅ | 15 |
| `padding.none` | 无填充（NoPadding） | 不做填充，要求明文长度本来就对齐分组。 | 流式模式（CTR/GCM/CFB/OFB）必然是无填充；分组模式里见到它，说明调用方自己保证了对齐（常见于定长字段、二进制块）。 | mode.ctr、mode.gcm | ✅ | — |
| `padding.iso7816` | ISO/IEC 7816-4 填充 | 补 0x80 后跟若干 0x00。 | 智能卡 / 部分欧洲银行系统。国内少见。 | padding.pkcs7 | ⚠️ | — |
| `padding.ansix923` | ANSI X9.23 填充 | 补若干 0x00 后跟一个长度字节。 | 部分老式金融终端。国内少见。 | padding.pkcs7 | ⚠️ | — |

### A.4 密钥文本格式（4 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `keyfmt.hex` | HEX 解释 | 把 32 个字符当 16 字节。引擎默认格式。 | 密钥是「纯十六进制串」时。例如 SM4 密钥 `4A7F2C1E9B3D5A08C6B1D90E37F2A485`。 | keyfmt.utf8、keyfmt.base64 | ✅ | — |
| `keyfmt.utf8` | UTF-8 字面量解释（★ 最常被搞错） | 把这串字符本身当字节。16 个 ASCII 字符 = 16 字节。 | 真实前端写 `var KEY = "4A7F2C1E9B3D5A08";` 时，**它多半是 16 字节 UTF-8**而不是 8 字节 HEX——按 HEX 解会直接报「密钥长度不合法」。看到 16 个可打印字符就优先按 UTF-8 试。 | keyfmt.hex | ✅ | — |
| `keyfmt.base64` | Base64 解释 | 把串按 Base64 解成字节。 | 密钥以 Base64 形式写在构建产物里（如 `MDEyMzQ1Njc4OWFiY2RlZg==` → 16 字节密钥）。 | keyfmt.hex | ✅ | 11 |
| `keyfmt.auto` | auto 自动判定 | 按长度与字符集自动在 HEX / UTF-8 / Base64 之间选一个能用的。 | 不确定密钥写法时的第一选择；`--keyinfo` 会列出三种解释各自的字节数，哪个等于算法要求的长度就是它。 | keyfmt.hex、keyfmt.utf8、keyfmt.base64 | ✅ | — |

### A.5 密钥派生（KDF）（9 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `kdf.digest-sha256` | SHA256(种子) | 对种子直接做 SHA-256，得到 32 字节。 | 密钥 = 摘要(种子)。常配合取区间使用（如取前 16 字节当密钥）。 | kdf.slice、algo.sm4 | ✅ | 12 |
| `kdf.digest-md5` | MD5(种子) | 对种子做 MD5，得到 16 字节。 | 老系统的「密钥派生」经常就是 MD5(盐+时间戳)。 | kdf.digest-sha256、digest.md5 | ✅ | — |
| `kdf.digest-sm3` | SM3(种子) | 对种子做国密摘要，得到 32 字节。 | 国密体系里的密钥派生 / 摘要。 | digest.sm3、kdf.digest-sha256 | ✅ | — |
| `kdf.hmac-sha256` | HMAC-SHA256(派生密钥, 种子) | 用一把派生密钥对种子做 HMAC。 | 带盐的派生：派生密钥通常也是硬编码常量。 | hmac.hmac-sha256 | ✅ | — |
| `kdf.hmac-sm3` | HMAC-SM3(派生密钥, 种子) | 国密版 HMAC 派生。 | 国密 App 里的带盐派生。 | hmac.hmac-sm3 | ✅ | — |
| `kdf.aes-cbc-then-sha256` | AES-128-CBC(种子) → SHA256 | 先把种子当明文用 AES-128-CBC 加密（常量做 key/iv），再 SHA256。 | 白盒前端最常见的两层派生。 | kdf.aes-cbc-then-sha256-slice | ⚠️ | — |
| `kdf.aes-cbc-then-sha256-slice` | AES-128-CBC(种子) → SHA256 → 取区间（★ 白盒前端最常见） | 在上面那条的基础上再切一段（通常取中间 16 字节 [16:32]）。 | 移动端 H5 的 `master.substr(16,32)` 就是它。种子一般取自报文前置的随机数。 | kdf.aes-cbc-then-sha256、frame.seed-prefix | ✅ | 12 |
| `kdf.sm4-cbc-then-sm3` | SM4-CBC(种子) → SM3 | 国密版两层派生：SM4-CBC 加密种子后再 SM3。 | 纯国密链路。 | kdf.aes-cbc-then-sha256 | ✅ | — |
| `kdf.slice` | 取字节区间（slice） | 派生链的收尾步骤：从摘要结果里切出一段当密钥（如 [0:16] / [16:32]）。 | 决定密钥长度的一步。**注意：切片参数只有在预设声明了 slice 步骤时才生效**，工具已在引擎层统一补齐（见踩坑记录）。 | kdf.*、keyfmt.* | ✅ | — |

### A.6 密钥来源与材料挖掘（7 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `keysrc.disguised` | 伪装常量（data URI / 长 Base64） | 把密钥常量编码成看起来像图片或资源的 Base64 串挂在源码里。 | `var CONST = "data:image/png;base64,MTJjMTRhMjQ0Yjg0..."` —— 解开是 67 字符，前 32 位是标识、中间 16+16 是 AES 密钥与 IV。工具会自动解码并切片。 | keysrc.slice、kdf.aes-cbc-then-sha256-slice | ✅ | — |
| `keysrc.literal` | 命名密钥字面量（AES_KEY / IV / NONCE） | 按变量名抓源码里的密钥字面量，同一串按 HEX / UTF-8 / Base64 三种解释都产出。 | 真实前端最常见的写法；工具会把三种解释都当候选，由解密结果决定哪个对。 | keyfmt.* | ✅ | 03/04/05/06/07/08/09/11/13/14/15 |
| `keysrc.slice` | 定长切片（把长常量切给不同用途） | 一段长常量按固定偏移切开：32+16+16+3（标识 / AES key / IV / 后缀）。 | 国密前端把多个参数打包成一个常量；切片位置就是它的语义。 | keysrc.disguised、kdf.aes-cbc-then-sha256-slice | ✅ | — |
| `keysrc.chain` | 派生链识别 + 跨文件绑定常量 | 从源码里认出「A 文件定义算法、B 文件提供密钥」的链路，并把常量绑到链上。 | 多文件前端（framework + business 分包）的标准形态。 | kdf.*、keysrc.literal | ✅ | — |
| `keysrc.pem` | PEM 私钥（多行）与十六进制私钥 | 从材料里挖非对称私钥：多行 PEM 块，或 `SM2_PRIV = "<64 位十六进制>"` 这种字面量。 | 信封解封必需。实战中它通常在服务端代码 / 配置文件 / 运维泄漏的密钥文件里。 | asym.*、envelope.* | ✅ | 17/18 |
| `keysrc.kb` | 本地知识库命中 | 把解过一次的「密文特征 → 方案」存进本地知识库，下次同类密文直接命中。 | 同一目标反复测时的加速器；知识库里只存规则与哈希，不存明文密钥。 | frame.*、composite.* | ✅ | — |
| `keysrc.header` | 报文头部字段当种子 | 从报文自身取派生种子（如报文前置的随机数、时间戳、deviceId）。 | 一次一密派生的入口：种子在包里，常量在客户端 —— 两者一凑就能离线解。 | kdf.*、frame.seed-prefix | ✅ | 12 |

### A.7 摘要（5 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `digest.md5` | MD5 摘要 | 16 字节摘要。已不适合安全用途，但老系统到处都是。 | 复现老逻辑（`sign = MD5(排序参数 + &key=secret)`）。工具会标注弱算法告警。 | hmac.hmac-md5 | ✅ | — |
| `digest.sha1` | SHA-1 摘要 | 20 字节摘要。碰撞已被工程化。 | 同上，复现老签名逻辑。 | hmac.hmac-sha1 | ✅ | — |
| `digest.sha256` | SHA-256 摘要 | 32 字节摘要，现代默认。 | 多数新系统的 sign / 完整性校验。 | hmac.hmac-sha256、kdf.digest-sha256 | ✅ | — |
| `digest.sha512` | SHA-512 摘要 | 64 字节摘要。 | 少数现代实现；也用于 KDF 取 32 字节。 | digest.sha256 | ✅ | — |
| `digest.sm3` | SM3 摘要（国密） | 国密摘要标准 GB/T 32905-2016，输出 32 字节。 | 国密 App 的完整性 / 签名前置哈希（SM3withSM2 里的 SM3 就是它）。 | hmac.hmac-sm3、asym.sm2 | ✅ | — |

### A.8 HMAC / 完整性（7 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `hmac.hmac-md5` | HMAC-MD5 | 16 字节带密钥摘要。 | 老接口的报文 mac。 | hmac.hmac-sha1 | ✅ | — |
| `hmac.hmac-sha1` | HMAC-SHA1 | 20 字节带密钥摘要。 | TikTok X-Gorgon 一类 Header 签名；部分老 API。 | hmac.hmac-sha256 | ✅ | — |
| `hmac.hmac-sha256` | HMAC-SHA256 | 32 字节带密钥摘要，**Base64 后是 44 字符**（与 HMAC-SM3 长度完全相同）。 | 现代接口的 mac / sign；与 HMAC-SM3 只差算法，**长度上分不出来，必须两个都试**。 | hmac.hmac-sm3、hmac.auto | ✅ | — |
| `hmac.hmac-sha512` | HMAC-SHA512 | 64 字节带密钥摘要。 | 少见；遇到 88 字符 mac 时怀疑它。 | hmac.hmac-sha256 | ✅ | — |
| `hmac.hmac-sm3` | HMAC-SM3（国密） | 32 字节国密带密钥摘要，Base64 后 44 字符。 | 国密报文的 mac；银行 H5 的 `mac` 字段基本就是它。 | hmac.hmac-sha256、hmac.auto | ✅ | — |
| `hmac.auto` | mac 算法自适应（按长度推断） | 按 mac 的字节长度缩小候选范围再逐个试：32B→SM3/SHA256、20B→SHA1、16B→MD5、64B→SHA512。 | 一键解密里默认行为：不写死算法，对上了才判定为确凿证据。 | hmac.* | ✅ | — |
| `hmac.scope` | mac 覆盖范围（scope） | mac 到底算了哪些字节：常见是「被保护的字段 + cipher」「32hex + cipher_b64」或「解码前的密文文本」。 | **范围算错必然对不上**；设计里漏签的字段就是注入点。工具会按形态给默认范围并展示出来。 | frame.*、hmac.auto | ✅ | — |

### A.9 编码（5 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `encoding.base64` | Base64 | 3 字节 → 4 字符，可带 `=` 填充。**不是加密**，只是表示。 | 几乎所有接口的密文外层。 | encoding.base64url | ✅ | — |
| `encoding.base64url` | Base64URL | 把 `+` `/` 换成 `-` `_`，常去掉 `=`。 | URL / Cookie / JWT 场景；见到 `-` `_` 或长度 %4≠0 就优先怀疑。 | encoding.base64 | ✅ | 04 |
| `encoding.hex` | HEX（十六进制） | 1 字节 → 2 字符，大小写都可能。 | 老系统 / so 交互 / 二进制通道。**注意：纯 hex 串也满足 Base64 字符集**，先判 hex 再判 base64，否则会解成乱码。 | encoding.base64 | ✅ | 05/11/13 |
| `encoding.url` | URL 编码（%XX） | 把特殊字符转成 %XX。 | `encodeURIComponent(base64(密文))` 很常见；解开后还要再解一层 Base64。 | encoding.base64、chain.* | ✅ | 14 |
| `encoding.raw` | raw（原始二进制） | 不做任何编码，直接吃二进制字节。 | 文件模式专用（`--op dec --encoding raw`）。 | encoding.base64 | ⚠️ | — |

### A.10 压缩（5 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `compress.zlib` | zlib 压缩 | zlib 容器格式，魔数 `78 9C`（默认级别）。 | 加密前先压缩（响应侧常见）；历史上催生 CRIME / BREACH。 | compress.gzip、chain.* | ✅ | 13 |
| `compress.gzip` | gzip 压缩 | gzip 容器格式，魔数 `1F 8B`。 | 同上；pako.gzip 是前端最常见的实现。 | compress.zlib | ✅ | 04 |
| `compress.deflate` | deflate（带 zlib 头） | 与 zlib 基本同物，部分实现这么叫。 | pako.deflate 的默认输出。 | compress.zlib | ✅ | — |
| `compress.deflate-raw` | deflate-raw（裸 deflate） | 无 zlib 头的裸 deflate 流，**pako 的 deflate 默认就是裸流**。 | 把 deflate 与 deflate-raw 搞混是常见错误；工具解压失败会自动换算法重试。 | compress.deflate | ✅ | — |
| `compress.sniff` | 压缩魔数嗅探 + 自动回退 | 解密结果不是可读文本时，按魔数猜算法，猜错就轮询其它三种。 | 一键解密的后处理步骤：很多「解密失败」其实是解出了一段压缩数据。 | compress.* | ✅ | 04/13 |

### A.11 多级编码链（6 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `chain.base64` | 单层 Base64（最常见） | 密文 → Base64 一层。 | 绝大多数接口的外层。 | encoding.base64 | ✅ | 03/06/07/08/12/15/17/18 |
| `chain.base64-twice` | 双层 Base64 | Base64 之后再 Base64 一层（`base64 → base64`）。 | 故意套一层混淆，很常见。 | encoding.base64 | ✅ | 09 |
| `chain.base64-then-hex` | Base64 之后再 HEX（样本 13 的 hex(base64(ct))） | 先 Base64，再把整串转成十六进制（`base64 → hex`）；解码顺序相反：先解 HEX 拿回 Base64 文本，再解 Base64 拿回密文。 | 大字段先压缩、再加密、再套两层编码的写法。 | encoding.hex、encoding.base64、compress.* | ✅ | 13 |
| `chain.base64-then-url` | Base64 之后再 URL 编码（encodeURIComponent(base64(ct))） | 先 Base64，再做 URL 转义（`base64 → url`）；解码顺序相反。 | 老系统 / 表单提交场景。 | encoding.url、encoding.base64 | ✅ | 14 |
| `chain.hex-then-base64` | HEX 之后再 Base64 | 先 HEX 再 Base64（`hex → base64`）。少见。 | 部分自定义协议；矩阵里会试。 | encoding.hex | ⚠️ | — |
| `chain.order` | ★ 顺序即语义（两套口径必须分清） | 编码链的顺序本身就是信息，但**引擎与求解器的写法正好相反**： · 引擎 `encode_chain/decode_chain`（本表口径）：列出的是**编码时施加的顺序**，解码时引擎自动倒序还原。所以样本 13 的 hex(base64(ct)) 写成 `[base64, hex]`。 · 求解器 `cipher_auto_solver._decode_ciphertext`：列出的是**解码时施加的顺序**，同一个样本写成 `[hex, base64]`。 写错顺序必然解不开。本登记表统一按**引擎口径**（编码顺序），避免与 CLI / GUI 打架。 | 另外：解不开的编码链会被先剪掉，避免组合爆炸把正确配方挤出候选上限。 | chain.* | ✅ | — |

### A.12 非对称（SM2 / RSA）（6 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `asym.sm2` | SM2 加解密（国密椭圆曲线） | 国密椭圆曲线公钥算法；密文有 C1C3C2 / C1C2C3 两种拼接顺序。 | 国密 App 的密钥包裹 / 敏感字段加密；微信小程序算法套件。 | algo.sm4、digest.sm3、envelope.sm2 | ✅ | 18 |
| `asym.sm2-sign` | SM2 签名 / 验签（SM3withSM2） | 签名前先算 Z 值（含公钥分量）再 SM3，因此**只给私钥时验签会失败，必须能从私钥推出公钥**。 | sid(JWT, alg=SM3withSM2) 这类令牌。 | digest.sm3、asym.sm2 | ✅ | — |
| `asym.rsa` | RSA 加解密 | 公钥加密、私钥解密；支持 PKCS#1 v1.5 与 OAEP 两种填充，长文本自动分段（encryptLong2）。 | 国际体系里的密钥包裹 / 密码体加密。 | asym.rsa-sign、envelope.rsa | ✅ | 17 |
| `asym.rsa-sign` | RSA 签名 / 验签 | PKCS#1 v1.5 或 PSS，摘要 md5~sha512 可选。 | 接口 sign 字段 / 客户端完整性校验。 | digest.*、asym.rsa | ✅ | — |
| `asym.keygen` | 生成测试密钥对（SM2 / RSA） | 现场生成密钥对，用于自造密文验证链路。 | 调试 / 验证 / 写样本时用；**不是攻击手段**。 | asym.sm2、asym.rsa、envelope.* | ✅ | — |
| `asym.weak` | 非对称实现缺陷识别 | 教科书式 RSA（`RSA/ECB/NoPadding`）、PKCS#1 v1.5 密钥传输（Bleichenbacher / ROBOT）、GCM nonce 复用、私钥落在客户端。 | 这些是「能打」的点，不是工具自动判定的——工具负责把参数摆出来供你判断。 | asym.rsa、mode.gcm | ⚠️ | — |

### A.13 混合信封（4 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `envelope.sm2` | SM2 混合信封（SM2 包 SM4 密钥） | 随机生成对称密钥 → 对称加密数据 → 用 SM2 公钥包裹该密钥，两个字段一起传。 | **国内 App 最主流的写法**：`ed`（密文）+ `sked`（包裹密钥）两字段一起传。 | asym.sm2、algo.sm4、envelope.json | ✅ | 18 |
| `envelope.rsa` | RSA 混合信封（RSA 包 AES 密钥） | 同上，非对称那一步换成 RSA（OAEP 或 PKCS#1 v1.5）。 | 拼多多 anti-token 一类：RSA-1024 包 32 字节随机 key + AES-256-CBC(iv=0) 加密 JSON。 | asym.rsa、algo.aes256、envelope.json | ✅ | 17 |
| `envelope.json` | JSON 信封自动识别 | 整段 JSON 里认出「哪个字段是被包裹的密钥、哪个是密文、哪个是 IV」并自动解封。 | 字段名线索：密钥 `encKey`/`encryptedKey`/`wrappedKey`/`sked`/`key`；密文 `data`/`ed`/`cipher`/`ct`/`body`；IV `iv`/`nonce`。 | envelope.sm2、envelope.rsa、keysrc.pem | ✅ | 17/18 |
| `envelope.checks` | 解封结果校验（长度 16/24/32） | 解封出来的必须是**对称密钥长度**（16/24/32 字节），否则说明填充或算法不对。 | **这一步是必须的**：RSA PKCS#1 v1.5 解密没有完整性校验，用错填充解错也不报错、会返回一段垃圾字节——只能靠长度把它筛掉。工具还让 OAEP 排在 v1.5 前面。 | asym.rsa、envelope.rsa | ✅ | — |

### A.14 报文框架识别（8 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `frame.http` | 整段 HTTP 报文 | 输入带请求行/响应头时自动丢弃头部，只取 body。 | 从 Burp 直接复制粘贴的常见形态。 | frame.* | ✅ | 10 |
| `frame.raw-base64` | 裸 Base64 | 无报文框架，规整 Base64 串。 | 最朴素的情形。 | encoding.base64 | ✅ | 03/06/07/08/09/15 |
| `frame.raw-base64url` | 裸 Base64URL | 含 `-` `_` 或去掉填充的 Base64。 | URL / JWT 场景。 | encoding.base64url | ✅ | 04 |
| `frame.raw-hex` | 裸 HEX | 纯十六进制串，无框架。**必须优先于 Base64 判定**。 | 老系统 / 二进制通道。 | encoding.hex | ✅ | 05/11/13 |
| `frame.raw-url` | URL 编码密文 | 满屏 %XX，解开是 Base64/HEX 文本。 | 表单场景。 | encoding.url | ✅ | 14 |
| `frame.seed-prefix` | 种子前置 | 前 32 字符是本次请求的随机种子（明文前置），其后才是密文。 | 一次一密派生：种子随包传、常量在客户端。 | kdf.digest-sha256、kdf.slice | ✅ | 12 |
| `frame.json-envelope` | JSON 混合信封 | 整段 JSON，含包裹密钥字段 + 对称密文字段（+ IV 字段）。 | 与 envelope.json 同一件事，这里是形态侧的名字。 | envelope.json | ✅ | 17/18 |
| `frame.mixed-text` | 混杂文本（密文与源码粘在一起） | 输入里混着代码/日志时，先抽出最长的那段密文，同时从整段里挖常量。 | 从 jadx / IDE 复制时最常见。 | keysrc.* | ✅ | （自检覆盖） |

### A.15 端到端组合配方（19 条）

| # | 配方 | 报文形态 | 分层逻辑 | 说明 | 样本 |
|---|---|---|---|---|---|
| c03 | 固定密钥 + AES-128-CBC + Base64 | raw-base64 | ① 命名密钥字面量（按 UTF-8 解释）<br>② AES-128-CBC/PKCS7<br>③ Base64 解码 | 最基础的形态；注意密钥那 16 个字符是 UTF-8 不是 HEX。 | 03 |
| c04 | 压缩 + 加密 + Base64URL | raw-base64url | ① 先 gzip 压缩明文<br>② AES-256-CBC/PKCS7<br>③ Base64URL（去 =） | 解密后还要解压；解压失败会自动换算法重试。 | 04 |
| c05 | 老系统 3DES-CBC + HEX 编码 | raw-hex | ① HEX 字面量密钥 → 24 字节<br>② 3DES-CBC/PKCS7（分组 8 字节，IV 8 字节）<br>③ 密文 HEX 编码（大写） | 注意 3DES 分组是 8 字节，IV 给 16 字节会报错。 | 05 |
| c06 | RC4 流密码 + Base64 | raw-base64 | ① 任意长度密钥（UTF-8 字面量）<br>② RC4/STREAM/无填充<br>③ Base64 | 流密码：密文长度 = 明文长度，无 IV 无填充。 | 06 |
| c07 | SM4-CTR + IV 前置 | raw-base64 | ① 密文前 16 字节就是 IV<br>② SM4-CTR/无填充<br>③ Base64 | 「同明文两次密文不同、且前 16 字节随机」的典型。 | 07 |
| c08 | AES-128-GCM + AAD + nonce 前置 | raw-base64 | ① 密文前 12 字节是 nonce<br>② AES-128-GCM（尾部 16 字节 tag）<br>③ AAD = appid=9988&v=1<br>④ Base64 | GCM 必须给 AAD，否则 tag 校验不过。 | 08 |
| c09 | AES-128-ECB + 双层 Base64 | raw-base64 | ① 命名密钥字面量<br>② AES-128-ECB/PKCS7<br>③ 先解外层 Base64，再解内层 Base64 | 双层编码是常见的混淆手段。 | 09 |
| c10 | 整段 HTTP 报文（自动取 body） | http | ① 剥掉报文头只取 body<br>② 之后按 body 的实际形态继续判（同 c01 或裸编码路径） | 从 Burp 直接粘贴的形态。 | （通用） |
| c11 | SM4-ECB + 裸 HEX 密文 + Base64 密钥 | raw-hex | ① Base64 解码得到 16 字节密钥<br>② SM4-ECB/PKCS7<br>③ 密文 HEX 解码 | 「裸 HEX」必须先于 Base64 判定，否则会被解成乱码。 | 11 |
| c12 | 种子前置 + SHA256(种子) 取前 16 字节 → SM4-ECB | seed-prefix | ① 前 32 字符是种子<br>② SHA256(种子)[0:16] 当密钥<br>③ SM4-ECB/PKCS7 解其后 Base64 | 种子随包传、常量在客户端；解不开时优先怀疑常量取自别的版本。 | 12 |
| c13 | AES-192-CBC + zlib + 多级编码 hex(base64(密文)) | raw-hex | ① 先解 HEX 得到 Base64 文本<br>② 再解 Base64 得到密文<br>③ AES-192-CBC/PKCS7<br>④ 解密结果再 zlib 解压 | 编码链顺序即语义：解码必须倒着来。 | 13 |
| c14 | DES-CBC + URL 编码（encodeURIComponent(base64)） | raw-url | ① URL 解码拿回 Base64<br>② Base64 解码<br>③ DES-CBC/PKCS7（8 字节分组） | 满屏 %XX 时先想它。 | 14 |
| c15 | SM4-ECB + ZeroPadding | raw-base64 | ① 命名密钥字面量<br>② SM4-ECB/ZeroPadding（不是 PKCS7）<br>③ Base64 | 只试 PKCS7 会解不开——填充维度必须一起试。 | 15 |
| c17 | RSA-2048 混合信封（OAEP 包 SM4 密钥） | json-envelope | ① 从材料里挖 PEM 私钥<br>② RSA-OAEP/SHA-256 解封 encKey → 16 字节 SM4 密钥<br>③ SM4-CBC/PKCS7 解 data（IV 来自 iv 字段） | **解封结果必须是 16/24/32 字节**，否则是填充错（v1.5 解错不报错）。 | 17 |
| c18 | SM2 混合信封（ed / sked 两字段形态） | json-envelope | ① SM2 私钥（64 位十六进制字面量）<br>② SM2 C1C3C2 解封 sked → 16 字节密钥<br>③ SM4-CBC/PKCS7 解 ed（iv 来自 iv 字段） | 字段命名 sked/ed 是国密安全键盘的惯例。 | 18 |
| c19 | 参数排序 + &key=secret → MD5/SHA1/HMAC 签名（sign 字段） | （签名不在密文里，在 Header/参数里） | ① 参数按字典序排序<br>② 拼 `&key=<secret>`<br>③ MD5 / SHA1 / HMAC-SHA256<br>④ 比对 sign 字段 | **注意漏签字段**：签名通常不覆盖全部参数，没被签的字段就是注入点。 | — |
| c20 | 时间戳 + nonce + sign 三件套（判断有没有真校验） | Header / 参数 | ① 改 timestamp 重放<br>② 重放旧 nonce<br>③ 看服务端是否仍接受 | 这是**验证**手段而不是解密手段：接受即说明没真校验。 | — |
| c21 | Flutter 壳：请求体以「.」分隔（前段 RSA 密文 = key，后段 AES 密文） | （自定义分隔符） | ① 按 . 切分<br>② 前段 ≈ 256/334 字节 = RSA 加密的密钥<br>③ 后段用解出的密钥 AES 解密 | 工具当前不会自动按自定义分隔符切分，需要手工切两段分别处理。 | — |
| c22 | 「data=密文:IV」冒号拼 IV 的格式 | （自定义分隔符） | ① 按 : 切分<br>② 左半是密文、右半是 IV（或反过来）<br>③ 按该 IV 解 CBC/CTR | 工具会自动试「密文前 8/12/16 字节是 IV」，但不会自动按冒号切——需手工分段。 | — |

### A.16 密文特征 → 推荐（18 条）

| # | 密文特征 | 结论 | 优先试 | 怎么试 |
|---|---|---|---|---|
| f01 | 长度是 16 的倍数 + Base64 形态 | 分组密码：AES / SM4（也可能是 DES/3DES，分组 8） | encoding.base64、algo.aes128、algo.sm4、algo.aes256、padding.pkcs7 | 先按 16 字节分组解 Base64，再逐算法试；密钥长度决定具体是 AES-128/192/256 还是 SM4。 |
| f02 | 解码后长度不是分组的整数倍 | 流式加密（CTR/GCM/CFB/OFB/RC4），或加密后又套了编码 | mode.ctr、mode.gcm、algo.rc4、chain.* | 先排掉分组+填充的组合，优先试流式；不行再回头查编码链是否多解了一层。 |
| f03 | 密文长度 ≈ 明文长度 | 流式加密，或 ECB 无填充（定长字段） | mode.ctr、mode.ofb、algo.rc4、padding.none | 流式与「ECB/NoPadding」两种都试，看哪个出合法明文。 |
| f04 | 请求里一长一短两个字段（短的约 344 字符 Base64） | 短的那个极可能是「包 key」——RSA-2048 密文 Base64 后约 344 字符 | envelope.rsa、envelope.json、asym.rsa | 先认 JSON 信封；有私钥就解短的拿对称密钥，再用它解长的。 |
| f05 | 同明文两次抓包密文完全相同 | ECB，或固定 IV 的 CBC → 可直接重放 / 字典攻击 | mode.ecb、frame.*、keysrc.* | 确认模式后，块重放 / 块替换 / 字典都是可打的点（工具负责还原算法，利用靠你手工）。 |
| f06 | 同明文两次密文不同，且前 16 字节每次都变 | IV 前置（密文前 16 字节就是 IV） | mode.cbc、mode.ctr、mode.gcm | 工具会自动试「密文前 8/12/16 字节是 IV/nonce」。 |
| f07 | 纯 HEX、长度 %32 == 0 | SM4/AES 密钥或密文；**必须优先于 Base64 判定** | encoding.hex、frame.raw-hex | 纯 hex 也满足 Base64 字符集，先判 hex 再判 base64，否则解成乱码。 |
| f08 | 含 `-` 或 `_`，或长度 %4 ≠ 0 却没有 `=` | Base64URL（去填充变体） | encoding.base64url | 补回 `=` 填充后按标准 Base64 解码。 |
| f09 | 含 %XX 转义 | URL 编码，里面通常还套着一层 Base64/HEX | encoding.url、chain.url-then-base64 | 先 unquote 拿到文本，再按文本形态继续判。 |
| f10 | 解码后开头是 `78 9C` / `1F 8B` | zlib / gzip 压缩数据（说明密文解出来还要解压） | compress.zlib、compress.gzip、compress.sniff | 解密结果按压缩算法还原；魔数猜错会自动轮询其它算法。 |
| f12 | 整段 JSON，含两个长字符串字段 | 混合信封（一个是被包裹的密钥，一个是密文） | frame.json-envelope、envelope.sm2、envelope.rsa、keysrc.pem | 字段名自动识别；需要私钥才能解封。 |
| f13 | 末尾有 44 字符的 Base64（=32 字节） | 报文 mac：HMAC-SM3 或 HMAC-SHA256（两者等长，分不出来） | hmac.auto、hmac.hmac-sm3、hmac.hmac-sha256 | 按长度推断候选算法后逐个试；算出来一致就是硬证据。 |
| f14 | 末尾 mac 是 28 / 24 / 88 字符 | 分别是 HMAC-SHA1(20B) / HMAC-MD5(16B) / HMAC-SHA512(64B) | hmac.auto、hmac.hmac-sha1、hmac.hmac-md5 | 长度本身就是很强的线索，工具自动按表选候选。 |
| f16 | 源码里一串长 Base64 挂着 `data:image/...` 前缀 | 伪装常量（解开是打包的多个参数） | keysrc.disguised、keysrc.slice、kdf.aes-cbc-then-sha256-slice | 解 Base64 后按 32+16+16+3 或 32+32 切片，分别当标识/密钥/IV。 |
| f17 | 源码里 `var KEY = "<16 个可打印字符>"` | 16 字节 UTF-8 密钥（不是 8 字节 HEX） | keyfmt.utf8、keyfmt.auto | 先按 UTF-8 解释；报「密钥长度不合法」时用 --keyinfo 看三种解释的字节数。 |
| f18 | 每次请求 Header 带 timestamp / nonce 但内容不变 | 大概率没真校验（可重放） | composite.c20 | 改 timestamp、重放 nonce，看服务端认不认——这是验证，不是解密。 |
| f19 | 密文长度与明文长度差 1~16 字节 | 分组密码 + 填充（差值就是填充字节数） | padding.pkcs7、padding.zero | 差值 = 分组数×分组长度 - 明文长度，可反推填充方案。 |
| f20 | Base64 解码后全是不可打印字节且长度整齐 | 标准分组密文（不是编码套编码） | frame.raw-base64、algo.aes128、algo.sm4 | 直接进解密矩阵；密钥从材料里挖。 |

### A.17 未支持 / 需人工（8 条）

| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |
|---|---|---|---|---|---|---|
| `gap.whitebox-sm4` | 白盒 SM4（自定义 S-box / 查表实现） | 把 S-box 与轮函数合并成巨大的查表，静态看不出标准 SM4。 | 需要把查表还原回标准 SM4，或用 Hook 抓中间态。 | algo.sm4 | ❌ | — |
| `gap.custom-cipher` | 自定义算法（SIMON/SPECK、魔改轮函数） | TikTok X-Argus 里的 SIMON-128(72 轮)、自研 S-box 等。 | 每个目标一套实现，无法通用；工具只能帮你把编码/压缩那一层剥掉。 | chain.*、compress.* | ❌ | — |
| `gap.key-exchange` | 密钥协商（ECDH / SM2 密钥交换） | 双方协商出一次一密，抓包只看到公钥交换。 | **这类是最强的**：没有长期私钥基本打不动，只能打实现层（弱随机数、复用）。 | asym.sm2 | ❌ | — |
| `gap.tlcp` | 国密 TLS（GB/T 38636-2020） | 传输层就换了国密栈（SM2+SM3+SM4，握手 5 次强制校验）。 | 金融 App 常见；抓包需 Yakit 一类支持国密的代理，证书绑定另需绕过。 | algo.sm4、asym.sm2 | ❌ | — |
| `gap.native-kdf` | Native / so 内派生（Frida Hook 场景） | 密钥在 so 里由 sessionId / 设备特征动态派生，静态分析拿不到。 | Soul 那种 `generateKey()` 动态传入 native 的写法。 | keysrc.chain | ❌ | — |
| `gap.custom-baseN` | 非标准编码（自定义 base 表 / 私有码表） | 换掉 Base64 字母表或自造编码。 | 遇到时密文会「像 Base64 但解出来是乱码」。 | encoding.base64 | ❌ | — |
| `gap.tlv` | TLV / Protobuf 结构解析 | 拼多多长签名里的 TLV、TikTok 的 Protobuf。 | 工具目前只做到「把编码/压缩层剥掉」，不解析业务结构。 | compress.*、chain.* | ❌ | — |
| `gap.stream-large` | 超大文件分块流式加解密 | 分块 AES-CBC + 断点续传场景。 | 当前实现会整块读入内存（有 4MB 明文上限与命令行长度上限保护）。 | algo.aes256 | ⚠️ | — |
