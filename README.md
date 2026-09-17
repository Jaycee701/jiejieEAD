# jiejieEAD · 加解密分析工作台

**国密 & 对称密码渗透工具集** ｜ **17 种算法 × 6 种工作模式 × 5 种填充** ｜ **MITM 自动加解密** ｜ **SM2 / SM3 / TLCP 国密分析** ｜ **密文一键解密**

> 当前版本 **v2.0.0**（密码引擎 v4）｜ **11 个 GUI 页签** ｜ 内置 Python 3.11.9 ｜ 目标机**零环境依赖**，下载解压双击即用

[![Version](https://img.shields.io/badge/version-2.0.0-brightgreen)](#十版本历史)
[![Python](https://img.shields.io/badge/Python-3.11.9-blue)](https://www.python.org/)
[![Tauri](https://img.shields.io/badge/Tauri-v2-24C8DB)](https://tauri.app/)
[![Vue](https://img.shields.io/badge/Vue-3.5-42B883)](https://vuejs.org/)
[![Algorithms](https://img.shields.io/badge/Algorithms-17-success)](#51-算法17-种)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)](#22-系统要求)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> ### ⚠️ 免责声明（务必阅读）
> 本工具**仅限用于已获书面授权的安全测试、安全研究与密码应用合规审计**。
> 未授权对系统进行渗透、破解属于违法行为，使用者需自行承担全部法律责任。
> 本工具全流程**本地离线运算**，不会上传任何密钥、明文或密文。

---

## 目录

- [一、这是什么](#一这是什么)
- [二、快速开始](#二快速开始)
- [三、仓库内容](#三仓库内容)
- [四、功能一览（11 个页签）](#四功能一览11-个页签)
- [五、支持矩阵](#五支持矩阵)
- [六、命令行用法（CLI）](#六命令行用法cli)
- [七、文档导航](#七文档导航)
- [八、常见问题](#八常见问题)
- [九、安全与合规](#九安全与合规)
- [十、版本历史](#十版本历史)

---

## 一、这是什么

jiejieEAD 是面向 **红队护网、APP 渗透、国密密码测评（密评）** 场景的一体化密码工具集，
提供「**识别 → 复现 → 改包 → 批量分析**」的完整闭环，打包为 Windows 免安装目录交付。

| 痛点 | 本工具的解法 |
|---|---|
| **全密 Body 接口改包困难** —— APP 接口 Body 是 SM4/AES 密文，Burp 里一片乱码，每次改包要在 CyberChef 与 Burp 间反复复制粘贴 | **MITM 自动加解密**：代理层自动「解密 → 明文透传到 mitmweb → 人工改包 → 自动加密回注」，改包时看到的就是明文 JSON |
| **拿到密文不知道是什么算法** —— 模式、填充、密钥、IV 全靠猜 | **文件扫描分析 / 一键解密**：自动识别算法·模式·填充·密钥·IV，识别到什么就能在工作台原样复现什么 |
| **密钥是算出来的，不是直接给的** —— 种子 → 加密 → 摘要 → 取字节区间 | **摘要 / HMAC / 密钥派生** + **伪装常量与派生链识别**，直接给出可执行的复现命令 |
| **国密合规核查工具链太重** —— 要开 Wireshark + openssl + 自写脚本 | 一条命令完成 SM3 摘要、SM2 公钥 **9 维风险审计**、TLCP 国密流量解析 |
| **错误密钥导致假阳性** —— 部分国密库去填充不校验，密钥错也静默返回乱码 | 严格 PKCS#7 校验，**错误密钥必定报错**；无完整性校验的组合界面会主动提醒人工核对 |

### 1.1 适合谁用

- **渗透测试 / 红队**：APP 与 Web 接口 Body 加解密分析、Burp 联动改包
- **密评 / 密码合规审计**：SM2 公钥风险审计、SM3 摘要、TLCP 流量结构核查
- **安全开发 / 逆向**：拿到密文或加密代码片段，快速判定算法与密钥派生链
- **CTF / 密码学学习**：17 种算法全矩阵手动试算，逐步留痕

### 1.2 不适合什么

本工具**不内置**任何爆破、免杀、持久化、横向移动、漏洞利用功能，也**不做**流量重放攻击。
它只回答一个问题：**「这段密文是用什么加出来的，我该怎么复现它」**。

---

## 二、快速开始

### 2.1 获取程序

| 方式 | 命令 / 操作 | 适用 |
|---|---|---|
| **下载 ZIP**（推荐） | 右上角 **Code → Download ZIP** | 只要能用就行，不想装 Git |
| **浅克隆**（体积最小） | `git clone --depth 1 https://github.com/Jaycee701/jiejieEAD.git` | 想留更新通道又不想拉全部历史 |
| **完整克隆** | `git clone https://github.com/Jaycee701/jiejieEAD.git` | 需要历史记录 |

> **仓库约 125 MB / 4,400+ 个文件**，其中约 119 MB 是内置 Python 运行时（`resources/python-embed/`），
> 克隆或下载会比较慢，属正常现象。**只想要命令行引擎**的话，见 [2.5 我需要纯 CLI](#25-我需要纯-cli无-gui)。

### 2.2 系统要求

- **Windows 10 1809+ / Windows 11**（本仓库是 Windows 免安装发行版）
- **WebView2 运行时** —— Win11 已内置；Win10 若提示缺失，装一下微软官方的 Evergreen Runtime 即可
- **不需要**安装 Python，**不需要** `pip install` 任何依赖

### 2.3 运行

1. 解压到任意目录（路径**不要**含特殊字符）；
2. 双击 **`jiejieEAD.exe`**；
3. 首次启动会检查内置 Python 环境，约 **1~3 秒**，底部状态栏显示「依赖检查通过」即可开始用。

> ### ⚠️ 不要只单独拷贝 exe
> `resources/` 文件夹是程序的「内脏」（内置 Python 3.11.9 + 密码库 + mitmproxy + MCP SDK + 业务脚本）。
> 要移动到其它位置或 U 盘，必须把 **`jiejieEAD.exe` 和 `resources/` 整个文件夹一起拷走并保持同级**，
> 否则程序会提示找不到 Python。

### 2.4 验证安装（30 秒）

不想点界面的话，直接用内置解释器跑一次自检，**全部 PASS 即环境完好**：

```bat
cd resources\python
..\python-embed\python.exe cli_crypto.py --selftest
```

实测结尾输出：

```
 [9/9] 经典算法公开标准向量（RC5 / RC6 / Blowfish / CAST5 / RC2 / ChaCha20 / Salsa20）
       [ OK ] RC5-32/12/16 与 RFC 2040 测试向量逐字节一致
       [ OK ] RC6-32/20/16 与 BouncyCastle 测试向量 3/3 一致（加密+解密往返）
       ...
--------------------------------------------------------------------
[PASS] 密码引擎自检全部通过。
```

### 2.5 三条上手路径

不确定从哪开始？按你的目的选一条：

| 我想… | 从哪进 | 三步走 |
|---|---|---|
| **改全密 Body 接口** | Tab 2「MITM 自动加解密」 | 填白名单域名 → 启动代理 → 在 mitmweb 里改明文，回注自动加密 |
| **搞清一段密文是什么算法** | Tab 4「文件扫描分析」 | 丢文件/代码进去扫描 → 看识别结果 → 点「一键填入工作台」复现 |
| **只想要一条命令** | CLI | 见 [第六节](#六命令行用法cli)，`--selftest` → `--spec --json` → 干活 |

> 新手最省事的入口是 **Tab 4**：它会自动帮你把算法、模式、填充、密钥、IV 全部填好并跳到正确页签。

### 2.6 我需要纯 CLI（无 GUI）

密码引擎（`resources/python/`）是**零 GUI 依赖**的纯 Python 模块，可脱离 exe 跑在跳板机 / Linux 服务器上：

```bash
# 只取引擎源码（不需要下载 119 MB 运行时）
git clone --depth 1 --filter=blob:none --sparse https://github.com/Jaycee701/jiejieEAD.git
cd jiejieEAD && git sparse-checkout set resources/python

pip install -r resources/python/requirements.txt
python resources/python/cli_crypto.py --selftest
```

---

## 三、仓库内容

```
jiejieEAD/
├─ jiejieEAD.exe                     ← 桌面主程序（Tauri v2 + Vue3 + Element Plus，约 4.85 MB）
├─ resources/
│  ├─ python-embed/                  ← 内置 Python 3.11.9 运行时（约 119 MB，含全部密码依赖）
│  ├─ python/                        ← 密码引擎与业务脚本（15 个文件，纯 Python，可独立运行）
│  └─ tools/                         ← 密文样本生成与校验脚本
├─ 使用手册.md                        ← 完整使用手册（17 节，全部命令与输出均为实机跑通）
├─ 使用说明.txt                       ← 纯文本速查版（打印 / 离线查阅）
├─ jiejieEAD-加解密逻辑总览.md         ← 加解密与编码链路的设计说明
├─ LICENSE                           ← MIT License
└─ .gitignore                        ← 已排除密钥 / 证书 / 抓包文件 / 学习库
```

| 路径 | 说明 |
|---|---|
| `jiejieEAD.exe` | 桌面主程序（Tauri v2 + Vue3 + Element Plus，约 4.85 MB） |
| `resources/python-embed/` | 内置 Python 3.11.9 运行时（含全部密码依赖，约 119 MB） |
| `resources/python/` | 密码引擎与业务脚本（`crypto_core` / `cli_crypto` / `cipher_auto_solver` / `gm_crypto_analyzer` / `key_material_analyzer` / `file_crypto_scanner` / `folder_crypto_analyzer` / `mitm_crypto` / `ai_crypto_analyzer` / `crypto_mcp_server` 等） |
| `resources/tools/` | 密文样本生成与校验脚本（`make_cipher_samples.py` / `verify_cipher_samples.py`） |
| `使用手册.md` | **完整使用手册**（17 节，全部命令与输出均为实机跑通结果） |
| `使用说明.txt` | 纯文本速查版（打印/离线查阅用） |
| `jiejieEAD-加解密逻辑总览.md` | 加解密与编码链路的设计说明 |
| `LICENSE` | MIT License |

整体约 **125 MB / 4,400+ 个文件**，全部离线运行，无任何网络请求。

> ### ℹ️ 关于本仓库的性质
> 本仓库是 **免安装发行版（release）仓库**，不是源码工程 —— 因此**没有** `package.json`、`Cargo.toml`、`src/` 目录树，也不需要你 `npm install` / `cargo build`。
> 里面的 `resources/python/*.py` 是可读、可直接跑、可二次开发的**未混淆源码**；GUI 前端（Vue3 部分）以编译产物形式包含在 exe 内。

---

## 四、功能一览（11 个页签）

| # | 页签 | 能力 |
|---|---|---|
| 1 | **加解密工作台** | 17 算法 × 6 工作模式 × 5 填充，文本 / 文件加解密，密钥·IV·编码自动校验与随机生成 |
| 2 | **MITM 自动加解密** | mitmproxy 插件，**仅拦截白名单域名**，请求解密透传 → 改包 → 响应加密回注；GUI 一键启停并自动抓出带 token 的改包地址 |
| 3 | **国密密码分析** | SM3 摘要、SM2 公钥 9 维风险审计、TLCP 国密流量解析（pcap） |
| 4 | **文件扫描分析** | 丢文件进去自动识别文件类型 / 算法 / 模式 / 填充 / 密钥 / IV，支持钻包解析 ZIP·APK 内层，一键回填 |
| 5 | **文件夹整体分析** | 整个工程目录递归分析，产出**跨文件关系图**（import / 共享密钥 / 符号引用）与**数据流链路**，找出单文件看不见的全貌 |
| 6 | **AI 智能分析** | 粘贴代码或抓包片段直接判定算法 / 模式 / 填充 / 密钥；默认离线启发式（零网络），可选接在线 LLM |
| 7 | **MCP 接入** | 把加解密 / 文件扫描能力暴露为 MCP 工具，供 WorkBuddy / Claude Desktop 等 AI 客户端调用 |
| 8 | **摘要 / HMAC / 派生** | MD5 / SHA-1 / 256 / 512 / **SM3**、HMAC（含 **HMAC-SM3**）、8 个密钥派生预设，逐步留痕 |
| 9 | **非对称 / 压缩** | SM2、RSA 加解密与签名验签、混合信封、压缩与编码链 |
| 10 | **一键解密** | 贴一段密文自动穷举配方解出明文，附命中配方、判定依据与全部尝试记录 |
| 11 | **加密逻辑总览** | 加密逻辑知识库：分类检索 / 特征反查 / 按逻辑试算，一键套用回填 |

---

## 五、支持矩阵

### 5.1 算法（17 种）

| 族 | 算法 | `--alg` | 密钥长度 |
|---|---|---|---|
| 国密 | SM4 | `sm4` | 16 字节 |
| AES | AES-128 / 192 / 256 | `aes128` / `aes192` / `aes256` | 16 / 24 / 32 字节 |
| 传统分组 | DES / 3DES | `des` / `des3` | 8 / 24（或 16）字节 |
| 流密码 | RC4 / ChaCha20 / Salsa20 | `rc4` / `chacha20` / `salsa20` | 5–256 / 32 / 32 字节 |
| 经典分组 | RC5（3 变体）/ RC6（2 变体）/ Blowfish / CAST5 / RC2 | `rc5-32-12-16` 等 | 见 `--spec` |

> RC5 / RC6 为**自实现**（pycryptodome 与 cryptography 均未提供），已用 RFC 2040 与 BouncyCastle 公开向量逐字节验证；
> 纯 Python 实现比原生库慢约两个数量级，大文件会明显变慢。

### 5.2 模式与填充

| 模式 | 需要 IV | 需要填充 | 有完整性校验 |
|---|---|---|---|
| `ecb` | ❌ | ✅ | 仅取决于填充 |
| `cbc` | ✅ | ✅ | 仅取决于填充 |
| `cfb` / `ofb` / `ctr` | ✅ | ❌ 流式 | ❌ |
| `gcm` | ✅（12 字节） | ❌ | ✅ 认证标签 |

| 填充 | `--padding` | 有完整性校验 |
|---|---|---|
| PKCS#7 | `pkcs7` | ✅ |
| ISO/IEC 7816-4 | `iso7816` | ✅ |
| ANSI X9.23 | `ansix923` | ✅ |
| ZeroPadding | `zero` | ❌（错误密钥静默乱码，界面主动提醒） |
| NoPadding | `none` | ❌ |

### 5.3 附加能力（引擎 v3 / v4）

- **密钥材料**：`hex` / `utf8` / `base64` / `auto` 四种密钥格式；`--keyinfo` 一次看全（「密钥长度不合法」最常见的根因就是格式选错）
- **摘要 / HMAC**：MD5 / SHA-1 / SHA-256 / SHA-512 / SM3、HMAC（含 **HMAC-SM3**，与 BouncyCastle 逐字节一致）
- **派生预设**：`digest-*` / `hmac-*` / `aes-cbc-then-sha256` / `aes-cbc-then-sha256-slice` / `sm4-cbc-then-sm3` 等
- **非对称**：SM2（`c1c3c2` / `c1c2c3` / ASN.1）、RSA（PKCS#1 v1.5 / OAEP / PSS）、**混合信封**（公钥包对称密钥 + 对称加密数据）
- **压缩与编码链**：zlib / gzip / deflate / deflate-raw，与 base64 / base64url / hex / url 任意组合、顺序可控，解码自动反序

> **能力矩阵是唯一事实来源**：以上内容由 `cli_crypto.py --spec --json` 动态产出，
> GUI 下拉框、MITM 配置校验、文件扫描器镜像表三处都从同一个引擎读取 ——
> 不存在「界面里能选、命令行却跑不了」的情况。

---

## 六、命令行用法（CLI）

Python 引擎可脱离 GUI 独立运行，适合跳板机 / 服务器等无图形环境，也方便写脚本批处理。

```bat
cd resources\python
set PY=..\python-embed\python.exe

REM ① 自检（首次必跑）
%PY% cli_crypto.py --selftest

REM ② 查看引擎能力矩阵（算法 / 模式 / 填充 / 编码 / 哪些组合有完整性校验）
%PY% cli_crypto.py --spec --json

REM ③ SM4-CBC 加密 hello（输出 Base64）
%PY% cli_crypto.py --alg sm4 --op enc --mode cbc --padding pkcs7 ^
    --key 0123456789abcdeffedcba9876543210 ^
    --iv  00000000000000000000000000000000 ^
    --text "hello" --encoding base64
rem 实测输出：2wZpvYQeVFDsFlLs1CttYA==

REM ④ 国密分析
%PY% gm_crypto_analyzer.py sm3hash  --text "abc"
%PY% gm_crypto_analyzer.py sm2check --pubkey server_pub.pem
%PY% gm_crypto_analyzer.py tlcp     --pcap capture.pcap --port 443

REM ⑤ 密钥格式体检 + 派生（种子 → 加密 → 摘要 → 取中间 16 字节）
%PY% cli_crypto.py --keyinfo --key 4A7F2C1E9B3D5A08
%PY% cli_crypto.py --derive aes-cbc-then-sha256-slice --seed <伪装常量> ^
    --derive-key 4A7F2C1E9B3D5A08 --derive-key-format utf8 ^
    --derive-iv C6B1D90E37F2A485 --derive-iv-format utf8 --slice 16:32
```

`cli_crypto.py --selftest` 覆盖 9 组用例：国标向量、全长度区间、错误密钥检出、
与 pycryptodome 原生实现的字节级对照、HMAC-SM3 与 BouncyCastle 对照、
公开标准向量（RC5 / RC6 / Blowfish / CAST5 / RC2 / ChaCha20 / Salsa20）、混合信封端到端。

> 完整参数列表见 [`使用手册.md` 第十四节「命令速查」](使用手册.md)，含每个模块的实测输入输出。

---

## 七、文档导航

| 想了解 | 看这里 |
|---|---|
| 完整功能与每一步操作 | **[`使用手册.md`](使用手册.md)**（17 节，实机命令与输出） |
| 只想快速上手、纯文本速查 | [`使用说明.txt`](使用说明.txt) |
| 加解密与编码链路怎么设计的 | [`jiejieEAD-加解密逻辑总览.md`](jiejieEAD-加解密逻辑总览.md) |
| 许可协议 | [`LICENSE`](LICENSE) |

---

## 八、常见问题

<details>
<summary><b>Q1：提示「找不到 Python」/ 缺依赖怎么办？</b></summary>

几乎都是**只拷了 exe 没拷 `resources`**。把 `jiejieEAD.exe` 与 `resources/` 保持同级一起移动即可，
不需要在本机安装任何 Python 环境。
</details>

<details>
<summary><b>Q2：解密报「去填充失败」是什么意思？</b></summary>

绝大多数情况是**密钥或 IV 不对**，其次是密文被截断或篡改。
注意区分算法：SM4 密钥 16 字节，AES-256 密钥 32 字节，两者不能混用。

> 这正是本工具的一个设计优势：不少实现（包括 gmssl 原生 `crypt_cbc`）在密钥错误时会**静默返回乱码**，
> 让人误以为「解密成功但内容看不懂」；本工具会明确报错。

若选的是 `ECB/CBC + Zero/None` 或 `CFB/OFB/CTR/RC4` 这类**无完整性校验**的组合，
密钥错了不会报错，界面会提前用橙色提示条提醒你人工核对明文。
</details>

<details>
<summary><b>Q3：为什么 TLCP 流量不能直接解密？</b></summary>

TLCP（GB/T 38636 / GM/T 0024）使用基于 SM2 的 ECDHE 类密钥交换，具备**前向安全性**，
会话密钥从不在网络上传输。要解密必须持有**服务端私钥**或**会话主密钥（SSLKEYLOGFILE）**。

任何声称仅凭 pcap 就能解 TLCP 密文的工具都不可信。本工具做的是协议结构解析
（记录层 / 握手层 / 套件 / 证书），并在输出中明确标注这一边界。
</details>

<details>
<summary><b>Q4：mitmweb 打开提示需要 token？</b></summary>

mitmproxy 11+ 为 Web 界面加了 token 保护，必须带 `?token=...` 才能访问。
本工具的 GUI 已自动处理：启动代理后会从日志解析出完整地址，在面板中以蓝色提示条展示并提供「复制改包地址」。
纯 CLI 使用时，从终端输出里手动复制完整地址即可。
</details>

<details>
<summary><b>Q5：首次运行被 Windows SmartScreen / 杀软拦了？</b></summary>

`jiejieEAD.exe` **未做代码签名**（个人工具，无 EV 证书），因此 Windows 可能弹出
「Windows 已保护你的电脑」蓝色提示 —— 点「更多信息 → 仍要运行」即可。

部分杀软对 `mitmproxy` 相关组件会误报，属**代理抓包工具的通用误报**。
介意的话可以把整个目录加进白名单，或在虚拟机上跑。
</details>

<details>
<summary><b>Q6：支持 macOS / Linux 吗？</b></summary>

**CLI 部分完全支持** —— `resources/python/` 是纯 Python，无平台依赖，
装好 `requirements.txt` 后在 macOS / Linux 上可直接运行（见 [2.6](#26-我需要纯-cli无-gui)）。

**GUI 部分不支持**：本仓库提供的是 Windows 免安装发行版（含 Windows 版内嵌运行时与 exe）。
</details>

<details>
<summary><b>Q7：AI 智能分析会联网吗？会不会泄露我的密文？</b></summary>

**默认不联网**。AI 页签默认走**离线启发式规则**（纯本地正则 + 特征码匹配），零网络请求。

只有你手动打开「启用在线」并自行填入 Base URL / API Key 后，才会把**你主动粘贴的那段文本**
发送给你自己配置的模型服务。发布版**不含任何 LLM 密钥**。
</details>

<details>
<summary><b>Q8：MCP 接入怎么配？</b></summary>

见 [`使用手册.md` 第九节「MCP 接入」](使用手册.md)。核心是用 `mcp_setup.py` 生成客户端配置片段，
指向 `crypto_mcp_server.py`，然后把片段贴进 WorkBuddy / Claude Desktop 的 MCP 配置里。
接入后 AI 客户端就能调用本工具的加解密与文件扫描能力。
</details>

<details>
<summary><b>Q9：仓库里的源码能二次开发吗？</b></summary>

可以。`resources/python/*.py` **未混淆、可直接读**，MIT 协议允许修改与再分发（保留版权声明即可）。
但**不要**在交付目录里直接改完就重新打包 —— 组目录脚本会镜像覆盖 `resources/`，改动会丢。
建议 fork 或复制一份源码工程再改。
</details>

---

## 九、安全与合规

- **全流程离线**：代码中零网络请求，密钥 / 明文 / 密文不出本机；发布版不含任何 LLM 密钥，不配置在线模型即全程离线运行。
- **不手写底层算法**：全部调用成熟密码库（pycryptodome / gmssl 等），规避 S 盒、轮函数、密钥扩展等实现漏洞；自实现的 RC5/RC6 已用公开标准向量逐字节验证。
- **抗命令注入 / 路径穿越**：桥接层使用参数数组传参、脚本名白名单校验；外部跳转仅允许本机地址。
- **敏感文件不入库**：`.gitignore` 已排除 `*.key` / `*.pem` / `*.p12` / `*.pcap` / 学习库 `crypto_knowledge.json` 等，
  避免实战中接触的真实密钥与抓包文件被误传到公开仓库。
- **合规使用**：所有源码头部含免责声明，GUI 顶部常驻不可关闭的法律声明横幅；
  工具**不内置任何爆破、免杀、持久化、横向移动功能**。
- **授权要求**：仅限**已获书面授权**的安全测试与密码合规审计使用。在中华人民共和国境内开展测试，
  应遵守《网络安全法》《数据安全法》《个人信息保护法》及《商用密码管理条例》等相关法律法规。

---

## 十、版本历史

| 版本 | 主要变化 |
|---|---|
| **v2.0.0**（当前） | 密码引擎 **v4**：算法从 SM4-CBC / AES-256-CBC 扩展为 **17 算法 × 6 模式 × 5 填充**全矩阵；新增「文件夹整体分析」（跨文件关系图 + 数据流链路）、「加密逻辑总览」、「一键解密」；GUI 扩展至 11 个页签；文件扫描器识别到的组合**全部可在工作台 / MITM 复现** |
| v1.x | 初版：SM4-CBC / AES-256-CBC 加解密、MITM 自动加解密、国密分析基础能力 |

---

## License

MIT License — 详见 [LICENSE](LICENSE)

**使用本工具即表示您已阅读、理解并同意上述免责声明与法律声明。**

---

<sub>Bug / 缺陷 / 建议反馈：jiejieddd@qq.com ｜ From JieJie</sub>
