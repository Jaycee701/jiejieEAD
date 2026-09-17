#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 jiejieEAD | 模块四：文件密码扫描分析器
 文件：file_crypto_scanner.py
================================================================================

【免责声明】
    本工具仅用于拥有书面授权的安全测试、安全研究与密码应用合规审计。
    未授权对他人系统进行渗透、破解属于违法行为。使用者需自行承担因违规
    使用产生的一切法律责任。

【功能概述】「丢一个文件进去，自动分析出加密逻辑与密钥」
    一条流水线，五步产出：

      ① 分类识别   —— 按文件魔数 + 内容特征自动判定文件类型
                      （pcap / PEM 证书 / ZIP·APK·JAR / ELF / PE / JSON /
                        JS·TS 源码 / 配置文件 / 未知二进制 …）
      ② 算法识别   —— 识别 SM2/SM3/SM4、AES/DES/3DES/RC4、RSA、
                      MD5/SHA 系列，以及模式(CBC/ECB/GCM…)、填充(PKCS7…)、
                      编码(Base64/Hex)、JS 密码库(CryptoJS/sm-crypto/jsencrypt)
                      与国密 OID
      ③ 密钥提取   —— 四路并行提取硬编码密钥材料：
                      变量名上下文 / HEX·Base64 长度特征 / 二进制字符串常量池 /
                      PEM 块与 SM2 裸公钥；并做弱密钥识别
      ④ 逻辑总结   —— 归纳成一条「加密规则」，例如
                      「SM4-CBC + PKCS7 + 32 位 HEX 密钥 + Base64 输出」
      ⑤ 落地建议   —— 输出 apply 配置，可直接自动填入 GUI 的
                      「加解密工作台」与「MITM 自动加解密」配置

【设计原则】
    - 零第三方依赖：本模块只用 Python 标准库，离线可跑；
      pcap / SM2 深度解析按需惰性调用模块三（gm_crypto_analyzer.py）。
    - 不猜、不编：每条结论都带 evidence（命中片段 + 行号 / 偏移），
      置信度分 high / medium / low 三档，绝不给「看起来像」的假结果。
    - 大文件防护：默认只扫描前 32MB 文本内容，熵值按全量采样计算。

【使用示例】
    python file_crypto_scanner.py scan --file ./app.js
    python file_crypto_scanner.py scan --file ./app.js --json
    python file_crypto_scanner.py scan --file ./release.apk --deep
    python file_crypto_scanner.py --selftest
================================================================================
"""

from __future__ import annotations

import argparse
import base64
import binascii
import io
import json
import math
import os
import re
import struct
import sys
import zipfile
from collections import Counter
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
# 被 Tauri 以绝对路径调用时，脚本目录未必在 sys.path 首位（嵌入式 Python 的 _pth
# 不会自动把脚本目录加入 sys.path），必须显式插入，否则 `import crypto_core` /
# `import gm_crypto_analyzer` 等兄弟模块会报 ModuleNotFoundError。cli_crypto.py /
# crypto_mcp_server.py / ai_crypto_analyzer.py 也这样做。
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# 密钥材料分析（伪装 base64 常量解码 + AES/SHA 派生链识别）。
# 作为可选依赖：万一缺文件，扫描器仍要能正常工作，只是少一块结论。
try:
    import key_material_analyzer as kma  # noqa: E402
except Exception:  # noqa: BLE001
    kma = None

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_RUNTIME = 2

# ---- 进度上报（供 GUI 百分比进度条）----
# 只写 stderr —— 绝不能污染 stdout 上的 JSON 结果，否则前端解析会失败。
# 由 CLI 的 --progress 开关或环境变量 JIEJIEEAD_PROGRESS=1 打开。
_PROGRESS_ON = os.environ.get("JIEJIEEAD_PROGRESS", "") == "1"


def enable_progress() -> None:
    global _PROGRESS_ON
    _PROGRESS_ON = True


def _progress(pct: int, stage: str) -> None:
    """向前端播报进度：格式 `[PROGRESS] <百分比> <阶段文字>`。"""
    if _PROGRESS_ON:
        print("[PROGRESS] %d %s" % (pct, stage), file=sys.stderr, flush=True)

# 扫描上限：文本类分析最多读入 32MB，避免大二进制把内存吃满
DEFAULT_MAX_BYTES = 32 * 1024 * 1024
# 二进制字符串常量池最短长度
MIN_STRING_LEN = 6


# ============================================================================
# 一、文件类型知识表
# ============================================================================

# (魔数 bytes, 类型标识, 显示名, 大类)
MAGIC_TABLE: list[tuple[bytes, str, str, str]] = [
    (b"\x0a\x0d\x0d\x0a", "pcapng", "PCAP-NG 抓包文件", "capture"),
    (b"\xd4\xc3\xb2\xa1", "pcap", "PCAP 抓包文件 (小端)", "capture"),
    (b"\xa1\xb2\xc3\xd4", "pcap", "PCAP 抓包文件 (大端)", "capture"),
    (b"\x50\x4b\x03\x04", "zip", "ZIP 容器 (可能是 APK/JAR/DOCX/XLSX)", "archive"),
    (b"\x50\x4b\x05\x06", "zip", "ZIP 空容器", "archive"),
    (b"\x1f\x8b", "gzip", "GZIP 压缩流", "archive"),
    (b"\x37\x7a\xbc\xaf\x27\x1c", "7z", "7-Zip 压缩包", "archive"),
    (b"\x52\x61\x72\x21\x1a\x07", "rar", "RAR 压缩包", "archive"),
    (b"\x7f\x45\x4c\x46", "elf", "ELF 可执行/SO 库 (Linux/Android)", "executable"),
    (b"\x4d\x5a", "pe", "PE 可执行文件 / DLL (Windows)", "executable"),
    (b"\xca\xfe\xba\xbe", "java_class", "Java Class 字节码", "executable"),
    (b"\x64\x65\x78\x0a", "dex", "Android DEX 字节码", "executable"),
    (b"\x00\x61\x73\x6d", "wasm", "WebAssembly 模块", "executable"),
    (b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", "png", "PNG 图片", "media"),
    (b"\xff\xd8\xff", "jpeg", "JPEG 图片", "media"),
    (b"\x47\x49\x46\x38", "gif", "GIF 图片", "media"),
    (b"\x25\x50\x44\x46", "pdf", "PDF 文档", "document"),
    (b"SQLite format 3\x00", "sqlite", "SQLite 数据库", "document"),
    (b"\x53\x51\x4c\x69\x74\x65", "sqlite", "SQLite 数据库", "document"),
]

# 说明：文本类型判定逻辑已内联到 classify_file() 中按「强特征优先」的顺序执行
#（PEM → JSON → XML/HTML → JS 源码 → YAML），不再使用独立的特征表——
# 因为宽松的正则表会把 JS 里的「mode: CBC」误判成 YAML。

# JS / TS 源码特征关键字（命中 3 个以上即判定为源码）
JS_KEYWORDS = [
    "function ", "const ", "let ", "var ", "=>", "require(", "module.exports",
    "import ", "export ", "document.", "window.", "console.log", "prototype",
    "new Promise", "async ", "await ",
]

# 常见密码库标识（用于判断「这是加密逻辑」而不是「碰巧有 key 这个词」）
CRYPTO_LIB_HINTS = {
    "crypto-js": "CryptoJS (前端通用密码库)",
    "cryptojs": "CryptoJS (前端通用密码库)",
    "sm-crypto": "sm-crypto (JS 国密库)",
    "sm2.js": "sm2.js (JS 国密库)",
    "sm3.js": "sm3.js (JS 国密库)",
    "sm4.js": "sm4.js (JS 国密库)",
    "jsencrypt": "JSEncrypt (RSA 前端库)",
    "node-forge": "node-forge (JS 密码库)",
    "forge": "node-forge (JS 密码库)",
    "bjca": "BJCA 数字证书组件",
    "bouncycastle": "BouncyCastle (Java 密码库)",
    "pycryptodome": "PyCryptodome (Python 密码库)",
    "gmssl": "gmssl (Python 国密库)",
    "cryptography.hazmat": "cryptography (Python 密码库)",
    "tweetnacl": "TweetNaCl (JS 密码库)",
    "openSSL": "OpenSSL",
    "libcrypto": "OpenSSL libcrypto",
    "nanosvg": "",  # 占位，保持表结构
}


# ============================================================================
# 二、算法特征识别知识表
# ============================================================================
# 结构：(算法名, 分类, 正则, 权重, 说明)
#   权重 3 = 强特征（几乎可确定）  2 = 中   1 = 弱（辅助佐证）

ALGO_PATTERNS: list[tuple[str, str, str, int, str]] = [
    # ---------------- 国密 ----------------
    ("SM4", "国密", r"\bSM4\b|\bsm4\b|SM4[/_-]?(CBC|ECB|CTR)", 3, "国密分组密码 SM4"),
    ("SM4", "国密", r"sm4\.(encrypt|decrypt)\s*\(", 3, "sm-crypto 的 SM4 调用"),
    ("SM3", "国密", r"\bSM3\b|\bsm3\b|sm3\s*\(|sm3Hash|SM3withSM2", 3, "国密杂凑 SM3"),
    ("SM2", "国密", r"\bSM2\b|\bsm2\b|doEncrypt\s*\(|doSignature\s*\(|sm2Encrypt", 3, "国密非对称 SM2"),
    ("国密OID", "国密", r"1\.2\.156\.10197\.1\.(301|302|401|402)", 3, "国密标准 OID"),
    ("SM Series", "国密身份证", r"sm2p256v1|GM/T\s*0003|GB/T\s*3290[57]|GB/T\s*38636", 3, "国密标准编号引用"),
    # ---------------- 对称密码 ----------------
    ("AES", "对称", r"\bAES\b|AES[/_-]?(128|192|256)|AES[/_-]?(CBC|ECB|GCM|CTR)", 3, "对称密码 AES"),
    ("AES", "对称", r"CryptoJS\.AES|aes-?(128|192|256)-?(cbc|ecb|gcm|ctr)?|createCipheriv\s*\(\s*['\"]aes", 3, "AES 具体调用"),
    ("DES", "对称", r"\bDES\b|DES[/_-]?(CBC|ECB)|des-(cbc|ecb)|TripleDES|3DES|des-ede3", 3, "对称密码 DES/3DES（已不安全）"),
    ("RC4", "对称", r"\bRC4\b|\barc4\b|ARCFOUR", 3, "流密码 RC4（已不安全）"),
    ("Blowfish", "对称", r"Blowfish|bf-(cbc|ecb)", 2, "对称密码 Blowfish"),
    ("ChaCha20", "对称", r"ChaCha20|chacha20-poly1305", 2, "流密码 ChaCha20"),
    ("RC5", "对称", r"\bRC5\b|rc5-(32|64)|RC5[/_]?(32|64)", 2, "对称密码 RC5（参数化：字长/轮数）"),
    ("RC6", "对称", r"\bRC6\b|rc6-(32|64)|RC6[/_]?(32|64)", 2, "对称密码 RC6（AES 候选算法）"),
    ("CAST5", "对称", r"\bCAST5?\b|CAST-?128|cast5-(cbc|ecb)", 2, "对称密码 CAST-128 / CAST5"),
    ("RC2", "对称", r"\bRC2\b|ARC2|rc2-(cbc|ecb)", 2, "对称密码 RC2（注意 effective key bits 参数）"),
    ("Salsa20", "对称", r"Salsa20|salsa20-", 2, "流密码 Salsa20"),
    # ---------------- 非对称 ----------------
    ("RSA", "非对称", r"\bRSA\b|RSA[/_-]?(ECB|OAEP)|rsa-(2048|4096)|PKCS1Padding|OAEPWithSHA", 3, "非对称密码 RSA"),
    ("RSA", "非对称", r"JSEncrypt|publicEncrypt|privateDecrypt|createSign\s*\(\s*['\"]RSA", 3, "RSA 具体调用"),
    ("ECC", "非对称", r"\bECC\b|secp256r1|prime256v1|ECIES", 2, "椭圆曲线 ECC"),
    # ---------------- 摘要 ----------------
    ("MD5", "摘要", r"\bMD5\b|md5\s*\(|MD5withRSA|md5sum", 2, "摘要 MD5（碰撞已破，不宜用于完整性校验）"),
    ("SHA1", "摘要", r"\bSHA1\b|SHA-1\b|sha1\s*\(|SHA1withRSA", 2, "摘要 SHA-1（已不推荐）"),
    ("SHA256", "摘要", r"\bSHA256\b|SHA-256\b|sha256\s*\(|SHA256withRSA", 2, "摘要 SHA-256"),
    ("SHA512", "摘要", r"\bSHA512\b|SHA-512\b|sha512\s*\(", 2, "摘要 SHA-512"),
    ("HMAC", "摘要", r"\bHMAC\b|createHmac|HmacSHA", 2, "消息认证码 HMAC"),
    ("PBKDF2", "密钥派生", r"PBKDF2|pbkdf2_hmac|deriveBits", 2, "密钥派生 PBKDF2"),
    # ---------------- 模式 ----------------
    ("模式:CBC", "工作模式", r"[/_-]CBC|\bCBC\b|cbc", 1, "CBC 分组链接模式"),
    ("模式:ECB", "工作模式", r"[/_-]ECB|\bECB\b|ecb", 1, "ECB 模式（相同明文产生相同密文，不安全）"),
    ("模式:GCM", "工作模式", r"[/_-]GCM|\bGCM\b|gcm", 1, "GCM 认证加密模式"),
    ("模式:CTR", "工作模式", r"[/_-]CTR|\bCTR\b", 1, "CTR 计数器模式"),
    ("模式:CFB", "工作模式", r"[/_-]CFB|\bCFB\b", 1, "CFB 反馈模式"),
    ("模式:OFB", "工作模式", r"[/_-]OFB|\bOFB\b", 1, "OFB 反馈模式"),
    # ---------------- 填充 ----------------
    ("填充:PKCS7", "填充", r"PKCS5Padding|PKCS7Padding|Pkcs7|pkcs7|pkcs5|padding\s*[:=]\s*['\"]?pkcs5?['\"]?", 2, "PKCS#5/#7 填充"),
    ("填充:NoPadding", "填充", r"NoPadding|nopadding|padding\s*[:=]\s*['\"]?none['\"]?|padding\s*[:=]\s*['\"]?nopadding['\"]?", 2, "无填充（要求数据块对齐）"),
    ("填充:ZeroPadding", "填充", r"ZeroPadding|zeropadding|zero_padding|padding\s*[:=]\s*['\"]?zero['\"]?", 2, "零填充"),
    ("填充:ISO10126", "填充", r"ISO10126", 2, "ISO10126 填充"),
    # ---------------- 编码 ----------------
    ("编码:Base64", "编码", r"base64|Base64|btoa\s*\(|atob\s*\(|toString\(CryptoJS\.enc\.Base64\)", 1, "Base64 编码（密文常再套一层 Base64）"),
    ("编码:Hex", "编码", r"toString\(CryptoJS\.enc\.Hex\)|hexlify|\btoHex\b|bytesToHex|Buffer\.from\([^)]*['\"]hex['\"]\)", 2, "Hex 十六进制编码"),
    # ---------------- 库 / 框架 API ----------------
    ("API:Java Cipher", "实现方式", r"Cipher\.getInstance|SecretKeySpec|IvParameterSpec", 3, "Java/Android JCE 加密 API"),
    ("API:Node crypto", "实现方式", r"createCipheriv|createDecipheriv|createHash|createHmac", 3, "Node.js crypto 模块"),
    ("API:WebCrypto", "实现方式", r"crypto\.subtle|window\.crypto\.subtle|deriveKey\s*\(", 2, "浏览器 WebCrypto API"),
    ("API:Python", "实现方式", r"Crypto\.Cipher|from\s+cryptography|import\s+gmssl|from\s+Crypto", 3, "Python 密码库调用"),
    ("API:Android Keystore", "实现方式", r"AndroidKeyStore|KeyStore\.getInstance", 3, "Android 密钥库"),
]


# ============================================================================
# 三、密钥材料识别规则
# ============================================================================

# 变量名上下文提取：key/iv/secret 等命名 + 字符串字面量赋值
# 注意：第一段必须是「捕获组」——group(1)=变量名, group(2)=引号, group(3)=值
SECRET_NAME_RE = re.compile(
    r"(?i)\b("
    r"aes[_-]?key|sm4[_-]?key|sm2[_-]?key|des[_-]?key|"
    r"encrypt[_-]?key|decrypt[_-]?key|secret[_-]?key|sign[_-]?key|"
    r"access[_-]?key|app[_-]?key|app[_-]?secret|api[_-]?key|"
    r"private[_-]?key|public[_-]?key|client[_-]?secret|"
    r"aes[_-]?iv|sm4[_-]?iv|des[_-]?iv|encrypt[_-]?iv|init[_-]?vector|"
    r"key|secret|salt|password|passwd|pwd|iv|nonce|vector"
    r")\b\s*[:=]\s*(['\"])([^'\"]{4,512})\2"
)

# 裸 HEX 长度特征：SM4/128位=32，192位=48，256位=64，SM2 裸公钥=128(不含04)
HEX_TOKEN_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})(?![0-9a-fA-F])")
# SM2 裸公钥：04 + 128 位 HEX
SM2_PUB_RE = re.compile(r"(?<![0-9a-fA-F])04([0-9a-fA-F]{128})(?![0-9a-fA-F])")
# 裸 Base64：长度 22~44，可能是 16/24/32 字节密钥
B64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{22,44}={0,2})(?![A-Za-z0-9+/=])")
# PEM 块
PEM_BLOCK_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+?)-----(.*?)-----END \1-----", re.S)
# 域名（用于 MITM 白名单建议）
DOMAIN_RE = re.compile(r"https?://([a-zA-Z0-9][a-zA-Z0-9.\-]{2,80}\.[a-zA-Z]{2,12})")
# 常见的第三方/CDN 域名，不应当作被测目标
DOMAIN_BLOCKLIST = (
    "w3.org", "github.com", "googleapis.com", "gstatic.com", "jquery.com",
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "bootstrapcdn.com",
    "baidu.com", "aliyun.com", "tencent.com", "qq.com", "weixin.qq.com",
    "schema.org", "example.com", "localhost",
)

# 弱密钥指纹（值 -> 说明）
WEAK_KEY_FINGERPRINTS: dict[str, str] = {
    "00000000000000000000000000000000": "16 字节全 0（极弱）",
    "ffffffffffffffffffffffffffffffff": "16 字节全 F（极弱）",
    "0123456789abcdeffedcba9876543210": "国标示例密钥，非生产密钥",
    "0123456789abcdef0123456789abcdef": "顺序递增示例密钥",
    "1234567890123456": "简单数字序列（16 字节）",
    "12345678901234567890123456789012": "简单数字序列（32 字节）",
    "1234567890123456789012345678901234567890123456789012345678901234": "简单数字序列（64 位 HEX）",
    "abcdefghijklmnop": "连续字母表（16 字节）",
    "0000000000000000": "8 字节全 0",
    "password": "字面量密码",
    "123456": "弱口令",
}


# ============================================================================
# 四、基础工具
# ============================================================================

def shannon_entropy(data: bytes) -> float:
    """计算字节级 Shannon 熵（0~8）。越高越像加密/压缩/随机数据。"""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def entropy_verdict(entropy: float) -> str:
    """把熵值翻译成人话。"""
    if entropy >= 7.9:
        return "极高（几乎可确定为加密或压缩数据）"
    if entropy >= 7.2:
        return "偏高（疑似加密/压缩/随机数据）"
    if entropy >= 5.5:
        return "中等（可能是压缩文本或结构化二进制）"
    if entropy >= 3.0:
        return "偏低（像源码、配置或结构化文本）"
    return "很低（重复模式明显，如全 0 填充）"


def hex_preview(data: bytes, limit: int = 48) -> str:
    """生成十六进制预览。"""
    chunk = data[:limit]
    text = binascii.hexlify(chunk).decode("ascii")
    if len(data) > limit:
        text += "..."
    return text


def text_likeness(data: bytes) -> float:
    """
    判断「像文本」的程度（0~1）。

    【为什么不用简单的 ASCII 可打印率】
    中文、日文等 UTF-8 文本的每个字节都 >= 0x80，纯按字节统计可打印率会得到
    接近 0 的结果，把正常的中文源码/文档误判成二进制。这里改为「先解码成字符、
    再按字符」统计，并显式排除解码失败产生的替换字符 U+FFFD。
    """
    if not data:
        return 0.0
    sample = data[:65536]
    text = decode_text(sample)
    if not text:
        return 0.0

    good = 0
    for ch in text:
        if ch == "\ufffd":          # 解码失败产生的替换字符，视为不可读
            continue
        code = ord(ch)
        if ch in "\t\n\r" or 32 <= code < 127 or code >= 0xA0:
            good += 1
    return good / len(text)


def decode_text(data: bytes) -> str:
    """宽松解码为文本，保证不抛异常。"""
    for enc in ("utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def extract_strings(data: bytes, min_len: int = MIN_STRING_LEN, limit: int = 20000) -> list[tuple[int, str]]:
    """
    从二进制中提取可打印字符串常量（等效于 strings 命令）。

    同时提取 ASCII 与 UTF-16LE 两种编码，返回 (偏移, 字符串) 列表。
    这是从 so / dex / exe 里挖密钥的关键手段——密钥几乎总是以字符串常量存在。
    """
    results: list[tuple[int, str]] = []

    # ASCII 连续可打印串
    pattern_ascii = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for match in pattern_ascii.finditer(data):
        if len(results) >= limit:
            break
        results.append((match.start(), match.group().decode("ascii", errors="ignore")))

    # UTF-16LE（Java / Windows 常见）
    pattern_utf16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    for match in pattern_utf16.finditer(data):
        if len(results) >= limit:
            break
        try:
            text = match.group().decode("utf-16-le", errors="ignore")
        except Exception:
            continue
        results.append((match.start(), text))

    return results


def guess_cipher_from_keylen(byte_len: int) -> str:
    """按密钥字节长度反推可能的算法。"""
    mapping = {
        8: "DES（8 字节密钥）",
        16: "SM4 / AES-128 / DES-EDE2（16 字节密钥）",
        24: "AES-192 / 3DES（24 字节密钥）",
        32: "AES-256（32 字节密钥），也可能是 SM4 的 32 位 HEX 文本形式",
        64: "AES-256 的 HEX 文本形式（64 位 HEX = 32 字节）",
    }
    return mapping.get(byte_len, "未知长度 %d 字节" % byte_len)


# ============================================================================
# 五、步骤①：文件分类识别
# ============================================================================

def classify_file(data: bytes, path: str) -> dict[str, Any]:
    """
    按魔数 + 内容特征自动判定文件类型。

    返回：{type, display, category, confidence, evidence[], entropy, size}
    """
    size = len(data)
    entropy = shannon_entropy(data[:262144])
    evidence: list[str] = []

    # ---- 1) 魔数匹配（最强证据）----
    for magic, type_id, display, category in MAGIC_TABLE:
        if data.startswith(magic):
            evidence.append("魔数命中 %s" % binascii.hexlify(magic).decode("ascii"))
            # ZIP 容器进一步细分（APK / JAR / Office）
            if type_id == "zip":
                type_id, display, category = _refine_zip_type(data, path, evidence)
            return {
                "type": type_id,
                "display": display,
                "category": category,
                "confidence": "high",
                "evidence": evidence,
                "entropy": entropy,
                "size": size,
            }

    # ---- 2) 文本内容特征 ----
    ext = os.path.splitext(path)[1].lower()
    ratio = text_likeness(data)
    if ratio >= 0.90:
        text_head = decode_text(data[:65536])

        stripped = text_head.lstrip()

        def _text_result(tid: str, display: str, category: str, conf: str) -> dict[str, Any]:
            return {"type": tid, "display": display, "category": category,
                    "confidence": conf, "evidence": evidence,
                    "entropy": entropy, "size": size}

        # 判定顺序很关键：先强特征（PEM/JSON/XML），再源码，最后才做宽松的
        # 键值配置匹配 —— 否则 JS 里的「mode: CBC」这类写法会被误判成 YAML。

        # (a) PEM
        if re.search(r"-----BEGIN [A-Z0-9 ]+-----", text_head):
            evidence.append("命中 PEM 头 -----BEGIN-----")
            return _text_result("pem", "PEM 编码的密钥/证书文本", "text", "high")

        # (b) JSON：必须真正能被解析，避免把以 { 开头的 JS 误判成 JSON
        if stripped[:1] in ("{", "["):
            try:
                json.loads(stripped if len(stripped) < 200000 else text_head[:200000])
                evidence.append("内容可被 json 解析")
                return _text_result("json", "JSON 数据", "text", "high")
            except Exception:
                pass

        # (c) XML / HTML
        if re.match(r"^\s*(<\?xml|<!DOCTYPE\s+html|<html)", text_head, re.I):
            evidence.append("命中 XML/HTML 文档头")
            return _text_result("xml" if "<?xml" in text_head[:200] else "html",
                                "XML 文档" if "<?xml" in text_head[:200] else "HTML 页面",
                                "text", "high")

        # (d) JS / TS 源码
        hits = [kw for kw in JS_KEYWORDS if kw in text_head]
        if len(hits) >= 3:
            evidence.append("JS 关键字命中 %d 个：%s" % (len(hits), ", ".join(hits[:5])))
            if re.search(r"\b(interface\s+\w+|type\s+\w+\s*=|:\s*(string|number|boolean)\b)", text_head):
                return _text_result("js", "TypeScript 源码", "source", "high")
            return _text_result("js", "JavaScript 源码", "source", "high")

        # (e) YAML / 键值配置：要求 --- 分隔符或至少 3 行 key: value
        yaml_lines = re.findall(r"(?m)^\s*[A-Za-z_][\w.\-]*\s*:\s+\S", text_head)
        if re.search(r"(?m)^---\s*$", text_head) or len(yaml_lines) >= 3:
            evidence.append("键值配置特征命中 %d 行" % len(yaml_lines))
            return _text_result("yaml", "YAML / 键值配置", "text", "medium")

        # 扩展名兜底
        ext_map = {
            ".js": ("js", "JavaScript 源码", "source"), ".mjs": ("js", "JavaScript 源码", "source"),
            ".ts": ("js", "TypeScript 源码", "source"), ".vue": ("js", "Vue 单文件组件", "source"),
            ".json": ("json", "JSON 数据", "text"), ".xml": ("xml", "XML 文档", "text"),
            ".html": ("html", "HTML 页面", "text"), ".htm": ("html", "HTML 页面", "text"),
            ".py": ("py", "Python 源码", "source"), ".java": ("java", "Java 源码", "source"),
            ".kt": ("java", "Kotlin 源码", "source"), ".php": ("php", "PHP 源码", "source"),
            ".go": ("go", "Go 源码", "source"), ".sh": ("shell", "Shell 脚本", "source"),
            ".yml": ("yaml", "YAML 配置", "text"), ".yaml": ("yaml", "YAML 配置", "text"),
            ".ini": ("config", "INI 配置", "text"), ".conf": ("config", "配置文件", "text"),
            ".env": ("config", "环境变量文件", "text"), ".properties": ("config", "Java 配置", "text"),
            ".md": ("markdown", "Markdown 文档", "text"), ".txt": ("text", "纯文本", "text"),
            ".log": ("text", "日志文件", "text"), ".csv": ("text", "CSV 数据", "text"),
        }
        if ext in ext_map:
            t, d, c = ext_map[ext]
            evidence.append("扩展名兜底 %s" % ext)
            return {"type": t, "display": d, "category": c,
                    "confidence": "medium", "evidence": evidence,
                    "entropy": entropy, "size": size}

        # 纯文本但类型未知
        return {"type": "text", "display": "未知文本内容", "category": "text",
                "confidence": "low", "evidence": ["可读字符占比 %.0f%%" % (ratio * 100)],
                "entropy": entropy, "size": size}

    # ---- 3) 未知二进制 ----
    verdict = entropy_verdict(entropy)
    evidence.append("可读字符占比仅 %.0f%%" % (ratio * 100))
    evidence.append("熵值 %.4f —— %s" % (entropy, verdict))
    return {
        "type": "binary",
        "display": "未知二进制数据",
        "category": "binary",
        "confidence": "medium",
        "evidence": evidence,
        "entropy": entropy,
        "size": size,
    }


def _refine_zip_type(data: bytes, path: str, evidence: list[str]) -> tuple[str, str, str]:
    """ZIP 容器进一步细分（APK / JAR / Office / 普通 ZIP）。"""
    ext = os.path.splitext(path)[1].lower()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except Exception:
        evidence.append("ZIP 魔数命中，但目录读取失败（可能被截断）")
        return ("zip", "ZIP 压缩包", "archive")

    evidence.append("ZIP 内含 %d 个条目" % len(names))
    joined = "\n".join(names[:4000])

    if "AndroidManifest.xml" in names or "classes.dex" in names:
        evidence.append("命中 AndroidManifest.xml / classes.dex")
        return ("apk", "Android APK 安装包", "archive")
    if "META-INF/MANIFEST.MF" in names and any(n.endswith(".class") for n in names[:800]):
        evidence.append("命中 META-INF/MANIFEST.MF + *.class")
        return ("jar", "JAR 包", "archive")
    if "[Content_Types].xml" in names:
        evidence.append("命中 [Content_Types].xml")
        if any(n.startswith("word/") for n in names):
            return ("docx", "Word 文档 (DOCX)", "document")
        if any(n.startswith("xl/") for n in names):
            return ("xlsx", "Excel 工作簿 (XLSX)", "document")
        if any(n.startswith("ppt/") for n in names):
            return ("pptx", "PowerPoint 演示 (PPTX)", "document")
        return ("ooxml", "Office Open XML 文档", "document")
    if ext == ".apk":
        return ("apk", "Android APK 安装包", "archive")
    if ext in (".jar", ".war"):
        return ("jar", "JAR 包", "archive")
    return ("zip", "ZIP 压缩包", "archive")


# ============================================================================
# 六、步骤②：算法特征识别
# ============================================================================

def _line_of(text: str, index: int) -> int:
    """把字符偏移换算成行号（1 基）。"""
    return text.count("\n", 0, index) + 1


def _snippet(text: str, index: int, match_len: int, pad: int = 32) -> str:
    """截取命中片段上下文，压成单行便于展示。"""
    start = max(0, index - pad)
    end = min(len(text), index + match_len + pad)
    frag = text[start:end].replace("\n", " ").replace("\r", " ").strip()
    if start > 0:
        frag = "..." + frag
    if end < len(text):
        frag = frag + "..."
    return frag[:160]


def detect_algorithms(text: str, source_label: str = "内容") -> list[dict[str, Any]]:
    """
    识别文本中的密码算法特征。

    返回按权重降序排列的命中列表，同一算法只保留最强的一条证据。
    """
    found: dict[str, dict[str, Any]] = {}

    for algo, category, pattern, weight, note in ALGO_PATTERNS:
        try:
            # 统一用 IGNORECASE：源码里 SM4/sm4/Md5/md5 写法并存，
            # 大小写敏感会漏掉一半命中（例如 createHash('md5')）
            match = re.search(pattern, text, re.IGNORECASE)
        except re.error:
            continue
        if not match:
            continue

        entry = found.get(algo)
        if entry and entry["weight"] >= weight:
            continue

        found[algo] = {
            "algorithm": algo,
            "category": category,
            "weight": weight,
            "confidence": {3: "high", 2: "medium", 1: "low"}[weight],
            "note": note,
            "source": source_label,
            "line": _line_of(text, match.start()),
            "evidence": _snippet(text, match.start(), len(match.group(0))),
        }

    return sorted(found.values(), key=lambda x: (-x["weight"], x["algorithm"]))


def detect_crypto_libs(text: str) -> list[dict[str, str]]:
    """识别引用的密码库。"""
    lower = text.lower()
    hits: list[dict[str, str]] = []
    seen: set[str] = set()
    for token, display in CRYPTO_LIB_HINTS.items():
        if not display:
            continue
        if token.lower() in lower:
            key = display
            if key in seen:
                continue
            seen.add(key)
            hits.append({"token": token, "display": display})
    return hits


# ============================================================================
# 七、步骤③：密钥材料提取
# ============================================================================

def classify_secret_value(value: str) -> dict[str, Any]:
    """
    分析一个候选字符串，判断它像什么密钥材料。

    返回 {kind, bytes_len, hex_len, readable, weak}
    """
    raw = value.strip()
    info: dict[str, Any] = {
        "kind": "unknown", "bytes_len": 0, "hex_len": 0,
        "readable": False, "weak": None,
    }

    # 弱密钥指纹（先查，弱密钥优先级最高，避免被当成"正常密钥"）
    low = raw.lower()
    if low in WEAK_KEY_FINGERPRINTS:
        info["weak"] = WEAK_KEY_FINGERPRINTS[low]
    elif len(set(raw)) == 1 and len(raw) >= 8:
        info["weak"] = "全部 %d 个字符相同（极弱）" % len(raw)

    # 纯 HEX 文本
    if re.fullmatch(r"[0-9a-fA-F]+", raw) and len(raw) >= 16:
        info["kind"] = "hex_text"
        info["hex_len"] = len(raw)
        info["bytes_len"] = len(raw) // 2
        return info

    # Base64 文本
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", raw) and len(raw) >= 16:
        try:
            pad = "=" * (-len(raw) % 4)
            decoded = base64.b64decode(raw + pad, validate=True)
            info["kind"] = "base64_text"
            info["bytes_len"] = len(decoded)
            return info
        except Exception:
            pass

    # 可打印字符串（原文密钥 / 口令 / salt）
    if raw.isprintable() and len(raw) >= 6:
        info["kind"] = "literal_text"
        info["bytes_len"] = len(raw.encode("utf-8"))
        info["readable"] = True
        return info

    return info


def extract_secrets(text: str, binary_strings: list[tuple[int, str]] | None = None,
                    source_label: str = "内容") -> list[dict[str, Any]]:
    """
    四路并行提取密钥材料，去重后按置信度排序。

    路径：
      A. 变量名上下文（key/iv/secret... = "字面量"）
      B. 裸 HEX 长度特征（32/48/64/128 位）
      C. 裸 Base64 长度特征
      D. 二进制字符串常量池（针对 so/dex/exe）
    """
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(value: str, origin: str, confidence: str, evidence: str, line: int = 0) -> None:
        value = value.strip()
        if len(value) < 4 or value in seen:
            return
        seen.add(value)
        info = classify_secret_value(value)
        results.append({
            "value": value,
            "origin": origin,
            "confidence": confidence,
            "evidence": evidence[:180],
            "line": line,
            "kind": info["kind"],
            "bytes_len": info["bytes_len"],
            "hex_len": info["hex_len"],
            "weak": info["weak"],
            "guess": guess_cipher_from_keylen(info["bytes_len"]) if info["bytes_len"] else "",
        })

    # ---- A. 变量名上下文（置信度最高）----
    for match in SECRET_NAME_RE.finditer(text):
        name = match.group(1)
        value = match.group(3)
        add(value, "变量名上下文:%s" % name, "high",
            _snippet(text, match.start(), len(match.group(0))),
            _line_of(text, match.start()))

    # ---- B. 裸 HEX ----
    for match in HEX_TOKEN_RE.finditer(text):
        value = match.group(1)
        # 全同字符（如 0000...）归为弱密钥，仍然保留
        add(value, "HEX 长度特征", "medium",
            "长度 %d 位 HEX" % len(value), _line_of(text, match.start()))

    # ---- B2. SM2 裸公钥（04 开头 130 位）----
    for match in SM2_PUB_RE.finditer(text):
        value = "04" + match.group(1)
        if value not in seen:
            seen.add(value)
            results.append({
                "value": value,
                "origin": "SM2 裸公钥",
                "confidence": "high",
                "evidence": "04 + 128 位 HEX，符合 SM2 未压缩公钥格式",
                "line": _line_of(text, match.start()),
                "kind": "sm2_pubkey",
                "bytes_len": 65,
                "hex_len": 130,
                "weak": None,
                "guess": "SM2 公钥（可交给 sm2check 审计）",
            })

    # ---- C. 裸 Base64 ----
    for match in B64_TOKEN_RE.finditer(text):
        value = match.group(1)
        if len(value) < 20:
            continue
        # 排除 import/require 里的模块路径（如 plus/es/locale/lang/zh）：
        # '/' 本身是合法 Base64 字符，但真实密钥不会长成"纯路径"的样子
        # —— 无 '=' / '+' 填充、且完全由路径字符分段构成，判为路径而非密钥
        if ("/" in value and not any(c in value for c in "=+")
                and re.fullmatch(r"[A-Za-z0-9._@~-]+(?:/[A-Za-z0-9._@~-]+)+", value)):
            continue
        add(value, "Base64 长度特征", "low",
            "长度 %d 的 Base64 串" % len(value), _line_of(text, match.start()))

    # ---- D. 二进制字符串常量池 ----
    if binary_strings:
        for offset, s in binary_strings:
            # 只处理"像密钥"的常量，避免把整个字符串池倒出来
            if re.fullmatch(r"[0-9a-fA-F]{16,128}", s) or re.fullmatch(r"[A-Za-z0-9+/]{20,44}={0,2}", s):
                add(s, "二进制字符串池", "medium",
                    "文件偏移 0x%X" % offset)
            elif re.search(r"(?i)key|secret|salt|iv|password|nonce", s) and len(s) < 200:
                add(s, "二进制字符串池(含关键词)", "low",
                    "文件偏移 0x%X" % offset)

    # ---- PEM 块单独处理 ----
    for match in PEM_BLOCK_RE.finditer(text):
        label = match.group(1).strip()
        body = match.group(2)
        results.append({
            "value": ("-----BEGIN %s----- ... -----END %s-----" % (label, label)),
            "origin": "PEM 块",
            "confidence": "high",
            "evidence": "PEM 标签：%s（%d 字符正文）" % (label, len(body.strip())),
            "line": _line_of(text, match.start()),
            "kind": "pem_" + label.lower().replace(" ", "_"),
            "bytes_len": 0,
            "hex_len": 0,
            "weak": None,
            "guess": "PEM 材料，可交给 sm2check / openssl 进一步分析",
        })

    # ---- 排序：弱密钥优先暴露，其次按置信度 ----
    order = {"high": 0, "medium": 1, "low": 2}
    results.sort(key=lambda r: (0 if r["weak"] else 1, order.get(r["confidence"], 3), -r["bytes_len"]))
    return results


def extract_domains(text: str, limit: int = 40) -> list[str]:
    """从内容中提取候选目标域名（用于 MITM 白名单建议）。"""
    hits: list[str] = []
    for match in DOMAIN_RE.finditer(text):
        host = match.group(1).lower()
        if any(bad in host for bad in DOMAIN_BLOCKLIST):
            continue
        if host not in hits:
            hits.append(host)
        if len(hits) >= limit:
            break
    return hits


# ============================================================================
# 八、步骤④⑤：加密逻辑总结 + 落地建议
# ============================================================================

#: 加解密引擎（crypto_core.py / cli_crypto.py / mitm_crypto.py）实际支持的能力。
#: 本扫描器刻意保持「零第三方依赖」，所以不 import crypto_core，而是在这里镜像一份。
#: ★ 修改 crypto_core.ALGO_SPECS 时必须同步本表，否则会出现能力漂移
#:   （自检里有一项专门校验两者一致）。
ENGINE_MODES: dict[str, tuple[str, ...]] = {
    "sm4":    ("ecb", "cbc", "cfb", "ofb", "ctr", "gcm"),
    "aes128": ("ecb", "cbc", "cfb", "ofb", "ctr", "gcm"),
    "aes192": ("ecb", "cbc", "cfb", "ofb", "ctr", "gcm"),
    "aes256": ("ecb", "cbc", "cfb", "ofb", "ctr", "gcm"),
    "des":    ("ecb", "cbc", "cfb", "ofb", "ctr"),
    "des3":   ("ecb", "cbc", "cfb", "ofb", "ctr"),
    "rc4":    ("stream",),
    # v5 新增：分组 8 字节的算法没有 GCM（本模块 GCM 构造按 128 位分组实现）；
    # RC5-64 / RC6 是 16 字节分组，可用 GCM。
    "rc5":     ("ecb", "cbc", "cfb", "ofb", "ctr"),
    "rc5_16":  ("ecb", "cbc", "cfb", "ofb", "ctr"),
    "rc5_64":  ("ecb", "cbc", "cfb", "ofb", "ctr", "gcm"),
    "rc6":     ("ecb", "cbc", "cfb", "ofb", "ctr", "gcm"),
    "rc6_16":  ("ecb", "cbc", "cfb", "ofb", "ctr", "gcm"),
    "blowfish": ("ecb", "cbc", "cfb", "ofb", "ctr"),
    "cast5":   ("ecb", "cbc", "cfb", "ofb", "ctr"),
    "rc2":     ("ecb", "cbc", "cfb", "ofb", "ctr"),
    "chacha20": ("stream",),
    "salsa20": ("stream",),
}
ENGINE_PADDINGS = ("pkcs7", "zero", "none", "iso7816", "ansix923")
ENGINE_STREAM_MODES = ("cfb", "ofb", "ctr", "gcm", "stream")
ENGINE_BLOCK_MODES = ("ecb", "cbc")


def engine_has_integrity(mode: str, padding: str) -> bool:
    """
    镜像 crypto_core.has_integrity_check：该组合能否自动判定密钥错误。

    无法判定时（Zero/NoPadding、CFB/OFB/CTR/RC4），必须提醒使用者人工核对明文，
    不能把「解密没报错」当成「密钥正确」。
    """
    if mode == "gcm":
        return True
    if mode in ENGINE_STREAM_MODES:
        return False
    return padding in ("pkcs7", "iso7816", "ansix923")


def resolve_engine_alg(primary: str, key_bytes: int | None) -> tuple[str | None, str | None]:
    """
    把扫描器识别到的算法名映射为引擎算法 id。

    :return: (算法 id 或 None, 需要追加的告警或 None)
    """
    name = (primary or "").upper()
    if name == "SM4":
        return "sm4", None
    if name == "AES":
        if key_bytes == 16:
            return "aes128", None
        if key_bytes == 24:
            return "aes192", None
        if key_bytes == 32:
            return "aes256", None
        return "aes256", (
            "已识别为 AES 但未能确定密钥长度，配置暂按 AES-256 生成；"
            "请根据实际密钥长度把「算法」改为 AES-128 / AES-192 / AES-256。"
        )
    if name in ("DES3", "3DES", "TRIPLEDES"):
        return "des3", None
    if name == "DES":
        return "des", None
    if name == "RC4":
        return "rc4", None
    # ---- v5 新增的经典算法 ----
    if name == "RC5":
        # 轮数/字长决定具体变体；识别不出时给最常见的 32/12/16，并提示可改
        return "rc5", ("已识别为 RC5，默认按最通用的 RC5-32/12/16 填入；"
                       "若目标用的是 16 轮或 64 位字变体，请在「算法」里改为 "
                       "RC5-32/16/16 / RC5-64/16/16。")
    if name == "RC6":
        return "rc6", ("已识别为 RC6，默认按 RC6-32/20/16 填入；"
                       "若目标是 16 轮变体，请改为 RC6-32/16/16。")
    if name in ("BLOWFISH", "BF"):
        return "blowfish", None
    if name in ("CAST5", "CAST", "CAST128", "CAST-128"):
        return "cast5", None
    if name in ("RC2", "ARC2"):
        return "rc2", ("RC2 另有 effective key bits 参数（默认 128）；"
                       "若解出乱码，多半是它不对 —— 在命令行的 "
                       "--rc2-effective-bits 里试 40/56/63/128。")
    if name in ("CHACHA20", "CHACHA"):
        return "chacha20", None
    if name in ("SALSA20", "SALSA"):
        return "salsa20", None
    if name in ("SM2", "RSA"):
        return None, (
            f"主算法为 {name}，属非对称加密，不在「加解密工作台」的对称算法范围内；"
            + ("请改用「国密密码分析」页签的 SM2 公钥审计。" if name == "SM2"
               else "RSA 相关运算请使用专用工具（如 openssl）或对应模块。")
        )
    return None, None


def summarize_crypto_logic(algorithms: list[dict[str, Any]],
                           secrets: list[dict[str, Any]],
                           libs: list[dict[str, str]]) -> dict[str, Any]:
    """
    把零散的命中归纳成一条「加密规则」，并给出可自动填入的配置。
    """
    algo_names = [a["algorithm"] for a in algorithms]
    strong = [a for a in algorithms if a["weight"] >= 3]

    # ---- 主算法判定 ----
    primary = None
    for candidate in ("SM4", "AES", "DES", "RC4", "SM2", "RSA"):
        if candidate in algo_names:
            primary = candidate
            break

    # 判定是否存在"对称加密"相关证据：
    # 只有出现对称算法或其模式特征时，默认的 CBC/PKCS7/Base64 才有意义；
    # 否则一律给空串（而不是让默认值冒充"已识别"），避免误导使用者。
    sym_hit = any(n in algo_names for n in ("SM4", "AES", "DES", "RC4"))
    mode_hit = any(n.startswith("模式:") for n in algo_names)
    enc_hit = any(n.startswith("编码:") for n in algo_names)

    # ---- 模式 ----
    mode = "cbc" if (sym_hit or mode_hit) else ""
    if "模式:ECB" in algo_names:
        mode = "ecb"
    elif "模式:GCM" in algo_names:
        mode = "gcm"
    elif "模式:CTR" in algo_names:
        mode = "ctr"
    elif "模式:CBC" in algo_names:
        mode = "cbc"

    # ---- 填充 ----
    padding = "pkcs7" if (sym_hit or mode_hit) else ""
    if "填充:NoPadding" in algo_names:
        padding = "none"
    elif "填充:ZeroPadding" in algo_names:
        padding = "zero"

    # ---- 密文编码 ----
    encoding = "base64" if (sym_hit or enc_hit) else ""
    if "编码:Hex" in algo_names:
        encoding = "hex"

    # ---- 选密钥 / IV ----
    chosen_key = None
    chosen_iv = None
    for item in secrets:
        origin = item.get("origin", "")
        is_iv_like = ("iv" in origin.lower() or "vector" in origin.lower()
                      or "nonce" in origin.lower())
        if is_iv_like and chosen_iv is None:
            chosen_iv = item
        elif not is_iv_like and chosen_key is None and item.get("bytes_len"):
            chosen_key = item
    if chosen_key is None:
        for item in secrets:
            if item.get("bytes_len") in (16, 24, 32) and not item.get("weak"):
                chosen_key = item
                break
    if chosen_iv is None:
        for item in secrets:
            if item.get("bytes_len") == 16 and item is not chosen_key:
                chosen_iv = item
                break

    # ---- 生成规则文本 ----
    parts: list[str] = []
    if primary:
        alg_display = {"SM4": "SM4", "AES": "AES", "DES": "DES/3DES",
                       "RC4": "RC4", "SM2": "SM2", "RSA": "RSA"}.get(primary, primary)
        if mode:
            parts.append("%s-%s" % (alg_display, mode.upper()))
        else:
            parts.append(alg_display)
        if padding and padding != "none":
            parts.append(padding.upper())
    else:
        parts.append("未识别出明确的对称加密主算法")

    if chosen_key:
        parts.append("密钥来自「%s」" % chosen_key["origin"])
    if chosen_iv:
        parts.append("IV 来自「%s」" % chosen_iv["origin"])
    if encoding:
        parts.append("密文编码 %s" % encoding.upper())

    rule = " + ".join(parts)

    # ---- 生成 apply 建议 ----
    apply_crypto: dict[str, Any] = {}
    apply_mitm: dict[str, Any] = {}
    warnings: list[str] = []

    key_bytes = chosen_key.get("bytes_len") if chosen_key else None
    gui_alg, alg_note = resolve_engine_alg(primary, key_bytes)
    if alg_note:
        warnings.append(alg_note)

    if gui_alg:
        # 模式/填充归一化，使其落在引擎真实支持的范围内
        # 注意：即便没有干净提取到密钥（chosen_key 为空），只要识别到对称主算法
        # 就应当给出 alg/mode/padding/encoding，便于 GUI「一键回填」后再手动补密钥；
        # 旧逻辑用 `if gui_alg and chosen_key` 把关，导致 AES 等无干净密钥时配置整段为空。
        mode_out = (mode or "cbc").lower()
        pad_out = (padding or "pkcs7").lower()
        if gui_alg == "rc4":
            mode_out = "stream"
        if mode_out in ENGINE_STREAM_MODES:
            pad_out = "none"
        elif pad_out not in ENGINE_PADDINGS:
            pad_out = "pkcs7"

        supported = ENGINE_MODES.get(gui_alg, ())
        if mode_out not in supported:
            warnings.append(
                "检测到工作模式 %s，但 %s 在加解密工作台中不支持该模式（支持：%s）；"
                "已按 CBC 生成配置，复现该模式请自行在脚本中处理。"
                % (mode_out.upper(), gui_alg.upper(),
                   " / ".join(m.upper() for m in supported if m != "stream"))
            )
            mode_out = "cbc" if "cbc" in supported else supported[0]

        key_value = chosen_key["value"] if chosen_key else ""
        iv_value = chosen_iv["value"] if chosen_iv else ""

        apply_crypto = {
            "alg": gui_alg,
            "op": "dec",
            "mode": mode_out,
            "padding": pad_out,
            "key": key_value,
            "iv": iv_value,
            "encoding": encoding or "base64",
        }
        apply_mitm = {
            "alg": gui_alg,
            "mode": mode_out,
            "padding": pad_out,
            "key": key_value,
            "iv": iv_value,
            "bodyEncoding": "none" if encoding == "raw" else (encoding or "base64"),
        }

        if mode_out not in ENGINE_BLOCK_MODES and mode_out != "stream" and not iv_value:
            warnings.append(
                "未提取到 IV/nonce；%s 模式必须提供，请从上下文或抓包中补全。"
                % mode_out.upper()
            )
        if mode_out == "gcm" and iv_value and len(iv_value) // 2 not in (12, 16):
            warnings.append(
                "GCM 的 nonce 应为 12 字节（24 位 HEX）或 16 字节，"
                f"当前提取值折算 {len(iv_value) // 2} 字节，填入后请人工核对。"
            )

        # 无完整性校验的组合：明确提醒「不报错 ≠ 密钥正确」
        if not engine_has_integrity(mode_out, pad_out):
            warnings.append(
                "该组合（%s + %s）不含完整性校验：密钥错误时不会报错，只会解出乱码。"
                "复现时请人工判断明文是否符合业务预期。"
                % (mode_out.upper(), pad_out.upper())
            )

    return {
        "rule": rule,
        "primary_algorithm": primary,
        "mode": mode,
        "padding": padding,
        "encoding": encoding,
        "chosen_key": chosen_key,
        "chosen_iv": chosen_iv,
        "apply_crypto": apply_crypto,
        "apply_mitm": apply_mitm,
        "warnings": warnings,
        "strong_hit_count": len(strong),
        "libs": libs,
    }


def assess_risks(algorithms: list[dict[str, Any]],
                 secrets: list[dict[str, Any]],
                 ftype: dict[str, Any]) -> list[dict[str, str]]:
    """给出风险提示（分级：high / medium / low）。"""
    risks: list[dict[str, str]] = []
    names = [a["algorithm"] for a in algorithms]

    hardcoded = [s for s in secrets if s["confidence"] == "high" and s.get("bytes_len")]
    if hardcoded:
        risks.append({
            "level": "high",
            "title": "存在硬编码密钥材料",
            "detail": "提取到 %d 条高置信度密钥/IV，硬编码密钥一旦随客户端分发即等同于公开，"
                      "建议改为服务端下发或使用密钥库/白盒方案。" % len(hardcoded),
        })

    weak = [s for s in secrets if s.get("weak")]
    if weak:
        risks.append({
            "level": "high",
            "title": "存在弱密钥",
            "detail": "共 %d 条弱密钥，例如「%s」—— %s"
                      % (len(weak), weak[0]["value"][:40], weak[0]["weak"]),
        })

    if "模式:ECB" in names:
        risks.append({
            "level": "high",
            "title": "使用 ECB 工作模式",
            "detail": "ECB 下相同明文块产生相同密文块，会泄露数据模式，"
                      "可被块重排/字典攻击，应改用 CBC/GCM 并随机化 IV。",
        })
    if "MD5" in names:
        risks.append({
            "level": "medium",
            "title": "使用 MD5",
            "detail": "MD5 抗碰撞性已被攻破，不应再用于签名或完整性校验。",
        })
    if "SHA1" in names:
        risks.append({
            "level": "medium",
            "title": "使用 SHA-1",
            "detail": "SHA-1 已被实际碰撞，建议升级到 SHA-256 或 SM3。",
        })
    if "DES" in names or "RC4" in names:
        risks.append({
            "level": "high",
            "title": "使用已淘汰算法",
            "detail": "DES（56 位有效密钥）/ RC4 均可被暴力或统计攻击破解，"
                      "国内合规场景应使用 SM4。",
        })

    # 国密合规性
    has_gm = any(n in ("SM2", "SM3", "SM4") for n in names)
    has_intl = any(n in ("AES", "RSA", "DES", "RC4") for n in names)
    if has_gm and has_intl:
        risks.append({
            "level": "medium",
            "title": "国密与国际算法混用",
            "detail": "同时检测到国密与国际算法，部分行业测评要求全程国密，混用可能导致合规不通过。",
        })
    elif has_intl and not has_gm:
        risks.append({
            "level": "medium",
            "title": "未使用国密算法",
            "detail": "仅检测到国际算法；若系统属于等保/密评范围，需评估国密改造要求。",
        })

    if ftype.get("entropy", 0) >= 7.9 and ftype.get("category") == "binary":
        risks.append({
            "level": "low",
            "title": "高熵二进制",
            "detail": "该二进制熵值极高，可能整体加密、加壳或为压缩载荷，"
                      "字符串与特征扫描可能覆盖不全。",
        })

    return risks


# ============================================================================
# 九、扫描主流程
# ============================================================================

def _scan_text_blob(text: str, label: str, offset_note: str = "") -> dict[str, Any]:
    """对一段文本内容做算法识别 + 密钥提取 + 域名提取。"""
    return {
        "label": label,
        "algorithms": detect_algorithms(text, label),
        "secrets": extract_secrets(text, source_label=label),
        "domains": extract_domains(text),
        "offset_note": offset_note,
    }


def scan_file(path: str, deep: bool = False, max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, Any]:
    """
    扫描单个文件，返回完整分析结果（可直接 JSON 序列化）。

    deep=True 时会展开 ZIP 内部条目、并对二进制做更彻底的字符串挖掘。
    """
    if not os.path.isfile(path):
        raise RuntimeError("文件不存在或不是常规文件：%s" % path)

    _progress(3, "读取文件")
    with open(path, "rb") as fh:
        raw = fh.read()

    data = raw[:max_bytes] if len(raw) > max_bytes else raw
    truncated = len(raw) > len(data)

    _progress(15, "识别文件类型")
    ftype = classify_file(data, path)
    ftype["truncated"] = truncated
    ftype["scanned_bytes"] = len(data)

    contents: list[dict[str, Any]] = []
    inner_files: list[dict[str, Any]] = []

    _progress(30, "解析文本主体")
    text = decode_text(data)
    contents.append(_scan_text_blob(text, "文件主体"))

    # ---- ZIP / APK / JAR 深挖 ----
    if ftype["category"] == "archive" and ftype["type"] in ("apk", "jar", "zip", "ooxml"):
        _progress(45, "深挖压缩包内层")
        inner_files = _scan_archive_entries(data, path, deep)

    # ---- 二进制字符串常量池 ----
    binary_strings: list[tuple[int, str]] = []
    if ftype["category"] in ("binary", "executable", "archive"):
        _progress(60, "提取二进制字符串常量池")
        binary_strings = extract_strings(data)
        if binary_strings:
            pool_text = "\n".join(s for _, s in binary_strings)
            blob = {
                "label": "二进制字符串常量池",
                "algorithms": detect_algorithms(pool_text, "字符串池"),
                "secrets": extract_secrets(pool_text, binary_strings=binary_strings,
                                          source_label="字符串池"),
                "domains": extract_domains(pool_text),
                "offset_note": "共提取 %d 条字符串常量" % len(binary_strings),
            }
            contents.append(blob)

    # ---- 汇总去重 ----
    _progress(75, "汇总算法与密钥材料")
    algorithms = _merge_algorithms(contents, inner_files)
    secrets = _merge_secrets(contents, inner_files)
    domains = _merge_list(contents, inner_files, "domains")
    libs = detect_crypto_libs(text)

    _progress(88, "归纳加密逻辑与风险")
    logic = summarize_crypto_logic(algorithms, secrets, libs)
    risks = assess_risks(algorithms, secrets, ftype)

    # ---- 密钥材料：伪装常量解码 + 派生链识别 ----
    _progress(94, "分析伪装常量与密钥派生链")
    key_material = _analyze_key_material(path, ftype)

    # ---- 路由建议：告诉 GUI「这个文件该去哪个页签」 ----
    _progress(96, "生成回填建议")
    route = _decide_route(ftype, logic, path)

    _progress(100, "扫描完成")

    return {
        "status": "ok",
        "file": {
            "path": os.path.abspath(path),
            "name": os.path.basename(path),
            "size": len(raw),
            "scanned_size": len(data),
            "type": ftype["type"],
            "type_display": ftype["display"],
            "category": ftype["category"],
            "confidence": ftype["confidence"],
            "evidence": ftype["evidence"],
            "entropy": ftype["entropy"],
            "entropy_verdict": entropy_verdict(ftype["entropy"]),
            "hex_preview": hex_preview(data),
            "truncated": truncated,
        },
        "algorithms": algorithms,
        "secrets": secrets,
        "crypto_libs": libs,
        "domains": domains,
        "logic": logic,
        "risks": risks,
        "route": route,
        "inner_files": inner_files,
        "contents_scanned": [c["label"] for c in contents],
        # 伪装常量 + 派生链：很多目标的密钥"既不是明文常量，也不是配置项"，
        # 而是藏在伪装的 base64 串里、由 AES/SHA 派生出来。这一块专治这种情况。
        "key_material": key_material,
    }


def _analyze_key_material(path: str, ftype: dict[str, Any]) -> dict[str, Any]:
    """调用密钥材料分析器；失败不影响主流程（返回空结构 + 说明）。"""
    empty = {"origin": path, "disguised": [], "derive_chains": [], "inner": [], "notes": []}
    if kma is None:
        empty["notes"].append("未加载 key_material_analyzer.py，已跳过伪装常量 / 派生链分析")
        return empty
    try:
        res = kma.analyze_file(path)
        # 命中摘要，方便 GUI 一眼看到"这次到底有没有挖到东西"
        res["summary"] = {
            "disguised": len(res.get("disguised", [])),
            "derive_chains": len(res.get("derive_chains", [])),
            "candidate_keys": sum(
                1 for it in res.get("disguised", [])
                for s in it.get("slices", []) if s.get("candidate_key")),
            "bound_chains": sum(1 for c in res.get("derive_chains", [])
                                if c.get("bound_constants")),
        }
        return res
    except Exception as exc:  # noqa: BLE001
        empty["notes"].append(f"密钥材料分析异常：{type(exc).__name__}: {exc}")
        return empty


def _scan_archive_entries(data: bytes, path: str, deep: bool) -> list[dict[str, Any]]:
    """扫描压缩包内值得一看的条目（源码 / 配置 / so / dex）。"""
    interesting_suffix = (
        ".js", ".mjs", ".ts", ".vue", ".json", ".xml", ".properties",
        ".so", ".dex", ".jar", ".keystore", ".jks", ".pem", ".cer", ".crt",
        ".conf", ".ini", ".yaml", ".yml", ".env", ".html", ".txt",
    )
    results: list[dict[str, Any]] = []
    try:
        # 【注意】ZipFile 必须在整个扫描过程中保持打开。
        # 若写成 `with zipfile.ZipFile(...) as zf:` 只包住 infolist()，
        # 块一结束档案就被关闭，后面 zf.read() 会抛
        # "Attempt to read ZIP archive that was already closed"，
        # 被 except 吞掉后表现为「包内一个条目都扫不到」。
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        return [{"name": "(压缩包读取失败)", "error": str(exc)}]

    # 按体积从小到大排序，优先看小的配置/源码文件
    infos = zf.infolist()
    infos.sort(key=lambda i: i.file_size)

    scanned = 0
    for info in infos:
        if info.is_dir():
            continue
        name = info.filename
        if not name.lower().endswith(interesting_suffix):
            continue
        if info.file_size > 4 * 1024 * 1024:
            continue
        if scanned >= (80 if deep else 25):
            break
        try:
            payload = zf.read(info)
        except Exception:
            continue
        scanned += 1

        text = decode_text(payload)
        algos = detect_algorithms(text, name)
        secs = extract_secrets(text, source_label=name)
        if not algos and not secs:
            continue
        results.append({
            "name": name,
            "size": info.file_size,
            "algorithms": algos,
            "secrets": secs,
            "domains": extract_domains(text),
        })
    zf.close()
    return results


def _merge_algorithms(contents: list[dict[str, Any]],
                      inner_files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """合并算法命中，同一算法保留权重最高的一条，并聚合来源。"""
    best: dict[str, dict[str, Any]] = {}
    for blob in contents:
        for item in blob.get("algorithms", []):
            key = item["algorithm"]
            if key not in best or item["weight"] > best[key]["weight"]:
                merged = dict(item)
                merged["sources"] = [blob["label"]]
                best[key] = merged
            elif blob["label"] not in best[key].get("sources", []):
                best[key].setdefault("sources", []).append(blob["label"])

    for entry in inner_files:
        for item in entry.get("algorithms", []):
            key = item["algorithm"]
            src = "包内文件:%s" % entry["name"]
            if key not in best:
                merged = dict(item)
                merged["sources"] = [src]
                best[key] = merged
            elif src not in best[key].get("sources", []):
                best[key].setdefault("sources", []).append(src)

    return sorted(best.values(), key=lambda x: (-x["weight"], x["algorithm"]))


def _merge_secrets(contents: list[dict[str, Any]],
                   inner_files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """合并密钥候选，按值去重。"""
    seen: set[str] = set()
    merged: list[dict[str, Any]] = []

    def push(item: dict[str, Any], where: str = "") -> None:
        value = item.get("value", "")
        if value in seen:
            return
        seen.add(value)
        copy = dict(item)
        if where:
            copy["found_in"] = where
        merged.append(copy)

    for blob in contents:
        for item in blob.get("secrets", []):
            push(item, blob["label"])
    for entry in inner_files:
        for item in entry.get("secrets", []):
            push(item, "包内文件:%s" % entry["name"])

    # 弱密钥与高置信度置顶
    order = {"high": 0, "medium": 1, "low": 2}
    merged.sort(key=lambda r: (0 if r.get("weak") else 1,
                               order.get(r.get("confidence"), 3),
                               -(r.get("bytes_len") or 0)))
    return merged[:200]


def _merge_list(contents: list[dict[str, Any]],
                inner_files: list[dict[str, Any]], field: str) -> list[str]:
    """合并字符串列表字段并去重。"""
    out: list[str] = []
    for blob in contents:
        for item in blob.get(field, []):
            if item not in out:
                out.append(item)
    for entry in inner_files:
        for item in entry.get(field, []):
            if item not in out:
                out.append(item)
    return out


def _decide_route(ftype: dict[str, Any], logic: dict[str, Any], path: str) -> dict[str, str]:
    """决定该文件应当路由到哪个分析页签。"""
    if ftype["type"] in ("pcap", "pcapng"):
        return {
            "tab": "gm",
            "action": "tlcp",
            "reason": "识别为抓包文件，建议使用国密密码分析的 TLCP 流量解析",
            "hint": "--pcap \"%s\"" % path,
        }
    if ftype["type"] == "pem" or any(
        s.get("kind", "").startswith("pem_") or s.get("kind") == "sm2_pubkey"
        for s in (logic.get("chosen_key") and [logic["chosen_key"]] or [])
    ):
        return {
            "tab": "gm",
            "action": "sm2check",
            "reason": "识别为 PEM/公钥材料，建议使用 SM2 公钥风险审计",
            "hint": "--pubkey \"%s\"" % path,
        }
    if logic.get("primary_algorithm") in ("SM4", "AES"):
        return {
            "tab": "crypto",
            "action": "apply_crypto",
            "reason": "提取到对称加密密钥，可直接填入加解密工作台验证",
            "hint": "",
        }
    return {"tab": "", "action": "", "reason": "未识别出明确的加密逻辑", "hint": ""}


# ============================================================================
# 十、命令行
# ============================================================================

def render_report(result: dict[str, Any]) -> None:
    """把扫描结果渲染成中文可读报告。"""
    info = result["file"]
    line = "=" * 68

    print(line)
    print(" jiejieEAD | 文件密码扫描分析报告")
    print(line)
    print(" 文件        : %s" % info["name"])
    print(" 路径        : %s" % info["path"])
    print(" 大小        : %d 字节 (%.1f KB)" % (info["size"], info["size"] / 1024.0))
    if info["truncated"]:
        print("              (超过扫描上限，仅分析前 %d 字节)" % info["scanned_size"])
    print(" 识别类型    : %s  [%s, 置信度 %s]"
          % (info["type_display"], info["type"], info["confidence"]))
    for ev in info["evidence"]:
        print("               · %s" % ev)
    print(" 熵值        : %.4f —— %s" % (info["entropy"], info["entropy_verdict"]))
    print(" 头部 HEX    : %s" % info["hex_preview"])

    # ---- 算法 ----
    print("-" * 68)
    print(" ① 识别的密码算法 (%d 项)" % len(result["algorithms"]))
    if not result["algorithms"]:
        print("     (未识别到密码算法特征)")
    for a in result["algorithms"]:
        print("   [%s] %-14s %s" % ({"high": "高", "medium": "中", "low": "低"}[a["confidence"]],
                                    a["algorithm"], a["note"]))
        print("        证据: %s (第 %d 行)" % (a["evidence"], a["line"]))

    # ---- 库 ----
    # 始终输出本段，保持 ①②③… 编号连续（无命中时明确写"未识别"，而不是整段消失）
    print("-" * 68)
    print(" ② 引用的密码库")
    if not result["crypto_libs"]:
        print("     (未识别到已知密码库指纹)")
    for lib in result["crypto_libs"]:
        print("   · %s  (关键字: %s)" % (lib["display"], lib["token"]))

    # ---- 密钥 ----
    print("-" * 68)
    print(" ③ 提取的密钥材料 (%d 条)" % len(result["secrets"]))
    if not result["secrets"]:
        print("     (未提取到硬编码密钥)")
    for s in result["secrets"][:30]:
        flag = "  【弱密钥】" if s.get("weak") else ""
        print("   [%s] %s%s" % ({"high": "高", "medium": "中", "low": "低"}[s["confidence"]],
                                s["origin"], flag))
        shown = s["value"] if len(s["value"]) <= 72 else s["value"][:69] + "..."
        print("        值    : %s" % shown)
        if s.get("bytes_len"):
            print("        长度  : %d 字节 → %s" % (s["bytes_len"], s["guess"]))
        if s.get("weak"):
            print("        弱密钥: %s" % s["weak"])
        print("        证据  : %s" % s["evidence"])
    if len(result["secrets"]) > 30:
        print("   ... 其余 %d 条见 --json 输出" % (len(result["secrets"]) - 30))

    # ---- 逻辑总结 ----
    logic = result["logic"]
    print("-" * 68)
    print(" ④ 加密逻辑总结")
    print("   主算法  : %s" % (logic["primary_algorithm"] or "未识别"))
    print("   模式    : %s" % (logic["mode"].upper() if logic["mode"] else "未识别"))
    print("   填充    : %s" % (logic["padding"].upper() if logic["padding"] else "未识别"))
    print("   密文编码: %s" % (logic["encoding"].upper() if logic["encoding"] else "未识别"))
    print("   >>> 规则: %s" % logic["rule"])
    for w in logic["warnings"]:
        print("   [注意] %s" % w)

    # ---- 落地建议 ----
    if logic["apply_crypto"]:
        print("-" * 68)
        print(" ⑤ 可直接填入加解密工作台的配置")
        ac = logic["apply_crypto"]
        print("   --alg %s --op %s --mode %s --padding %s --key %s --iv %s --encoding %s"
              % (ac["alg"], ac["op"], ac.get("mode", "cbc"), ac.get("padding", "pkcs7"),
                 ac["key"], ac["iv"] or "(缺)", ac["encoding"]))
        if not engine_has_integrity(ac.get("mode", ""), ac.get("padding", "")):
            print("   [注意] 该组合不含完整性校验，解密不报错 ≠ 密钥正确，"
                  "请人工核对明文。")
    if result["domains"]:
        print("-" * 68)
        print(" ⑥ 建议的 MITM 白名单域名 (%d 个)" % len(result["domains"]))
        for d in result["domains"][:20]:
            print("   · %s" % d)

    # ---- 风险 ----
    if result["risks"]:
        print("-" * 68)
        print(" ⑦ 风险提示 (%d 项)" % len(result["risks"]))
        for r in result["risks"]:
            label = {"high": "高", "medium": "中", "low": "低"}[r["level"]]
            print("   [%s] %s" % (label, r["title"]))
            print("        %s" % r["detail"])

    # ---- 路由 ----
    route = result["route"]
    if route.get("tab"):
        print("-" * 68)
        print(" ⑧ 建议下一步: %s" % route["reason"])
        if route.get("hint"):
            print("   命令: %s" % route["hint"])

    if result["inner_files"]:
        print("-" * 68)
        print(" ⑨ 包内命中文件 (%d 个)" % len(result["inner_files"]))
        for entry in result["inner_files"][:15]:
            print("   · %s (%d 字节)：算法 %s，密钥 %d 条"
                  % (entry["name"], entry["size"],
                     "/".join(a["algorithm"] for a in entry["algorithms"]) or "无",
                     len(entry["secrets"])))

    print(line)


def cmd_scan(args: argparse.Namespace) -> int:
    """scan 子命令实现。"""
    if getattr(args, "progress", False):
        enable_progress()
    try:
        _progress(1, "启动扫描")
        result = scan_file(args.file, deep=args.deep, max_bytes=args.max_bytes)
    except RuntimeError as exc:
        if args.as_json:
            print(json.dumps({"status": "error", "message": str(exc)}, ensure_ascii=False))
        else:
            print("[错误] %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # noqa: BLE001
        if args.as_json:
            print(json.dumps({"status": "error",
                              "message": "%s: %s" % (type(exc).__name__, exc)},
                             ensure_ascii=False))
        else:
            print("[错误] %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return EXIT_RUNTIME

    if args.as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        render_report(result)
    return EXIT_OK


# ============================================================================
# 十一、自检
# ============================================================================

def build_selftest_samples(workdir: str) -> dict[str, str]:
    """生成用于自检的合成样本文件，返回 {标签: 路径}。"""
    os.makedirs(workdir, exist_ok=True)
    samples: dict[str, str] = {}

    # 1) 含硬编码 SM4 密钥与 IV 的 JS 样本（变量名上下文可被识别）
    js = """
    const CryptoJS = require('crypto-js');
    var aesKey = '0123456789abcdeffedcba9876543210';
    var aesIv  = 'fedcba98765432100123456789abcdef';
    function enc(data) {
      var encrypted = CryptoJS.SM4.encrypt(data, CryptoJS.enc.Hex.parse(aesKey), {
        iv: CryptoJS.enc.Hex.parse(aesIv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });
      return encrypted.toString(CryptoJS.enc.Base64);
    }
    function call() { return fetch('https://api.acmecorp-test.com/v1/login'); }
    """
    p = os.path.join(workdir, "sample_sm4.js")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(js)
    samples["js_sm4"] = p

    # 2) 含 AES-256 的 JS，且使用 ECB + 弱密钥
    js2 = """
    const crypto = require('crypto');
    const SECRET_KEY = '0000000000000000000000000000000000000000000000000000000000000000';
    function hash(x){ return crypto.createHash('md5').update(x).digest('hex'); }
    function t(){ return crypto.createCipheriv('aes-256-ecb', SECRET_KEY, null); }
    """
    p = os.path.join(workdir, "sample_aes_ecb.js")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(js2)
    samples["js_aes_ecb"] = p

    # 2b) 老系统常见组合：SM4 + ECB + ZeroPadding（无 IV、无完整性校验）
    #     这是「识别到什么就必须能复现什么」的关键回归样本。
    js2b = """
    // legacy h5 crypto: sm4-ecb + ZeroPadding
    var SM4_KEY = "0123456789abcdeffedcba9876543210";
    var mode = "ECB";
    var padding = "ZeroPadding";
    function enc(data){
      var c = sm4.encrypt(data, SM4_KEY, {mode:'ecb', padding:'ZeroPadding'});
      return c;  // 密文以 base64 返回
    }
    $.post("https://api.acmecorp-test.com/api/v2/secure/submit", {data: enc(payload)});
    """
    p = os.path.join(workdir, "sample_sm4_ecb_zero.js")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(js2b)
    samples["js_sm4_ecb_zero"] = p

    # 3) PEM 公钥样本
    pem = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE4jS3p1cKv1VQZ2gc9F1v2o2g3
OqVPZ0eQ3rR1sT2uV3wX4yZ5aB6cD7eF8gH9iJ0kL1mN2oP3qR4sT5uV6wX7y
Z8aB9cD0eF1gH2iJ3kL4mN5oP6qR7sT8uV9wX0yZ1aB2cD3eF4gH5iJ6kL7mN8o
-----END PUBLIC KEY-----
"""
    p = os.path.join(workdir, "sample_pub.pem")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(pem)
    samples["pem"] = p

    # 4) pcap 样本（经典 pcap 头 + 一条 TCP/TLS 记录）
    pcap_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    payload = bytes([0x16, 0x03, 0x01, 0x00, 0x2A]) + b"\x01\x00\x00\x26" + b"\x00" * 32
    frame = b"\x00" * 54 + payload
    packet = struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    p = os.path.join(workdir, "sample_tlcp.pcap")
    with open(p, "wb") as fh:
        fh.write(pcap_header + packet)
    samples["pcap"] = p

    # 5) 高熵二进制（模拟整体加密/加壳）
    p = os.path.join(workdir, "sample_encrypted.bin")
    with open(p, "wb") as fh:
        fh.write(os.urandom(8192))
    samples["binary"] = p

    # 6) 含加密代码的 ZIP（模拟发布包）
    p = os.path.join(workdir, "sample_pkg.zip")
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("dist/app.js", js)
        zf.writestr("config/app.properties",
                    "db.password=S3cr3tP@ssw0rd\nencrypt.key=abcdef0123456789abcdef0123456789\n")
    samples["zip"] = p

    # 7) 纯文本（无加密特征）
    p = os.path.join(workdir, "sample_plain.txt")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write("这是一份普通的说明文档，没有任何加密相关内容。\n")
    samples["plain"] = p

    return samples


def run_selftest() -> int:
    """自检：验证分类、算法识别、密钥提取三条主链路。"""
    import tempfile

    print("=" * 68)
    print(" jiejieEAD 自检：文件密码扫描分析器")
    print("=" * 68)

    workdir = os.path.join(tempfile.gettempdir(), "jiejieead_scanner_selftest")
    samples = build_selftest_samples(workdir)

    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print("   [ %s ] %s%s" % ("OK" if ok else "!!", name,
                                  ("  —— " + detail) if detail else ""))
        if not ok:
            failures.append(name)

    # ---- 1) 文件分类 ----
    print("\n [1/4] 文件类型自动分类")
    expect = {
        "js_sm4": "js", "js_aes_ecb": "js", "js_sm4_ecb_zero": "js", "pem": "pem",
        "pcap": "pcap", "binary": "binary", "zip": "zip", "plain": "text",
    }
    for tag, want in expect.items():
        res = scan_file(samples[tag])
        got = res["file"]["type"]
        check("分类 %-12s → %s" % (tag, got), got == want,
              "" if got == want else "期望 %s" % want)

    # ---- 2) 算法识别 ----
    print("\n [2/4] 算法特征识别")
    res_js = scan_file(samples["js_sm4"])
    names = [a["algorithm"] for a in res_js["algorithms"]]
    check("JS 样本识别出 SM4", "SM4" in names, "命中: %s" % ",".join(names))
    check("JS 样本识别出 CBC 模式", "模式:CBC" in names)
    check("JS 样本识别出 PKCS7 填充", "填充:PKCS7" in names)
    check("JS 样本识别出 Base64 编码", "编码:Base64" in names)
    check("JS 样本识别出 CryptoJS 库",
          any("CryptoJS" in l["display"] for l in res_js["crypto_libs"]))

    res_aes = scan_file(samples["js_aes_ecb"])
    names_aes = [a["algorithm"] for a in res_aes["algorithms"]]
    check("AES 样本识别出 AES", "AES" in names_aes)
    check("AES 样本识别出 ECB 模式", "模式:ECB" in names_aes)
    check("AES 样本识别出 MD5", "MD5" in names_aes)

    # ---- 3) 密钥提取 ----
    print("\n [3/4] 硬编码密钥提取")
    values = [s["value"] for s in res_js["secrets"]]
    check("提取到 SM4 密钥 0123456789abcdeffedcba9876543210",
          "0123456789abcdeffedcba9876543210" in values)
    check("提取到 IV fedcba98765432100123456789abcdef",
          "fedcba98765432100123456789abcdef" in values)

    res_weak = scan_file(samples["js_aes_ecb"])
    weak = [s for s in res_weak["secrets"] if s.get("weak")]
    check("弱密钥（64 位全 0）被标记", len(weak) > 0,
          "弱密钥 %d 条" % len(weak))

    # ---- 4) 逻辑总结与落地建议 ----
    print("\n [4/4] 加密逻辑总结与自动填充建议")
    logic = res_js["logic"]
    check("主算法判定为 SM4", logic["primary_algorithm"] == "SM4",
          "实际: %s" % logic["primary_algorithm"])
    check("模式判定为 cbc", logic["mode"] == "cbc")
    check("填充判定为 pkcs7", logic["padding"] == "pkcs7")
    check("编码判定为 base64", logic["encoding"] == "base64")
    apply_crypto = logic["apply_crypto"]
    check("生成可填入工作台的配置", bool(apply_crypto.get("key")),
          "alg=%s key=%s" % (apply_crypto.get("alg"), apply_crypto.get("key", "")[:16] + "..."))
    check("配置的密钥与提取值一致",
          apply_crypto.get("key") == "0123456789abcdeffedcba9876543210")
    check("IV 与提取值一致",
          apply_crypto.get("iv") == "fedcba98765432100123456789abcdef")

    # ---- 4b) 「识别到什么就能复现什么」的关键回归 ----
    # 历史缺口：扫描器能识别出 ECB/ZeroPadding，但生成的配置只有 CBC/PKCS7，
    # 导致「检测到了却跑不了」。这里锁定该组合必须原样带进可复现配置。
    res_ez = scan_file(samples["js_sm4_ecb_zero"])
    logic_ez = res_ez["logic"]
    check("ECB+Zero 样本主算法为 SM4", logic_ez["primary_algorithm"] == "SM4",
          "实际: %s" % logic_ez["primary_algorithm"])
    check("ECB+Zero 样本模式判定为 ecb", logic_ez["mode"] == "ecb",
          "实际: %s" % logic_ez["mode"])
    check("ECB+Zero 样本填充判定为 zero", logic_ez["padding"] == "zero",
          "实际: %s" % logic_ez["padding"])
    ac_ez = logic_ez["apply_crypto"]
    check("复现配置带上了 --mode ecb", ac_ez.get("mode") == "ecb",
          "alg=%s mode=%s padding=%s" % (ac_ez.get("alg"), ac_ez.get("mode"),
                                         ac_ez.get("padding")))
    check("复现配置带上了 --padding zero", ac_ez.get("padding") == "zero")
    check("复现配置的算法可被引擎接受",
          ENGINE_MODES.get(ac_ez.get("alg", ""), ()) and ac_ez.get("mode") in ENGINE_MODES[ac_ez["alg"]],
          "alg=%s" % ac_ez.get("alg"))
    check("ECB+Zero 被明确提示「无完整性校验」",
          any("不含完整性校验" in w for w in logic_ez["warnings"]),
          "warnings=%d 条" % len(logic_ez["warnings"]))

    check("域名建议提取到 api.acmecorp-test.com",
          "api.acmecorp-test.com" in res_js["domains"],
          "域名: %s" % ",".join(res_js["domains"]))

    check("pcap 样本路由到 tlcp",
          scan_file(samples["pcap"])["route"]["action"] == "tlcp")
    check("PEM 样本路由到 sm2check",
          scan_file(samples["pem"])["route"]["action"] == "sm2check")

    res_zip = scan_file(samples["zip"])
    check("ZIP 内命中文件被扫描", len(res_zip["inner_files"]) >= 1,
          "命中 %d 个" % len(res_zip["inner_files"]))

    res_bin = scan_file(samples["binary"])
    check("高熵二进制被正确判定", res_bin["file"]["entropy"] >= 7.0,
          "熵值 %.4f" % res_bin["file"]["entropy"])

    res_plain = scan_file(samples["plain"])
    check("无加密文本不产生误报密钥",
          all(not s.get("weak") for s in res_plain["secrets"]))

    # ---- 能力矩阵防漂移校验 ----
    # 本扫描器镜像了一份「加解密引擎能力表」（ENGINE_MODES），供生成可复现配置使用。
    # 一旦 crypto_core 的能力变化而这里没同步，扫描器就会生成引擎跑不通的配置。
    # 因此这里主动交叉比对；crypto_core 不可用时跳过（本模块本身零依赖）。
    try:
        import crypto_core as _cc  # noqa: PLC0415 - 自检内按需导入
    except ImportError:
        print("       [SKIP] 未找到 crypto_core.py，跳过能力矩阵一致性校验")
    else:
        drift: list[str] = []
        for aid, spec in _cc.ALGO_SPECS.items():
            mirror = ENGINE_MODES.get(aid)
            if mirror is None:
                drift.append(f"{aid} 在扫描器镜像表中缺失")
                continue
            if tuple(mirror) != tuple(spec.modes):
                drift.append(f"{aid}: 镜像 {mirror} != 引擎 {tuple(spec.modes)}")
        for aid in ENGINE_MODES:
            if aid not in _cc.ALGO_SPECS:
                drift.append(f"镜像表多出算法 {aid}")
        if tuple(ENGINE_PADDINGS) != tuple(_cc.padding_choices()):
            drift.append(f"填充集合不一致：{ENGINE_PADDINGS} != {tuple(_cc.padding_choices())}")
        if tuple(ENGINE_STREAM_MODES) != tuple(_cc.STREAM_LIKE_MODES):
            drift.append(
                f"流式模式集合不一致：{ENGINE_STREAM_MODES} != {tuple(_cc.STREAM_LIKE_MODES)}")

        # 完整性判定也要一致，否则会给出误导性的安全提示
        for m in ("ecb", "cbc", "cfb", "ofb", "ctr", "gcm", "stream"):
            for p in ENGINE_PADDINGS:
                if engine_has_integrity(m, p) != _cc.has_integrity_check(m, p):
                    drift.append(f"完整性判定不一致：{m}/{p}")

        # 生成配置里的算法 id 必须都能被引擎识别
        for aid in ENGINE_MODES:
            if aid not in _cc.ALGO_SPECS:
                drift.append(f"生成的算法 id 引擎不认识：{aid}")

        check("扫描器镜像表与 crypto_core 能力矩阵一致"
              + ("" if not drift else f"（差异：{'; '.join(drift[:4])}）"),
              not drift)

    print("-" * 68)
    if failures:
        print(" [FAIL] %d 项未通过：%s" % (len(failures), "; ".join(failures)))
        return EXIT_RUNTIME
    print(" [PASS] 全部测试通过，文件扫描分析器工作正常。")
    print("        自检样本目录：%s" % workdir)
    return EXIT_OK


# ============================================================================
# 十二、入口
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    """构建命令行解析器。"""
    parser = argparse.ArgumentParser(
        prog="file_crypto_scanner.py",
        description="jiejieEAD 模块四：文件密码扫描分析器"
                    "（自动分类 → 识别算法 → 提取密钥 → 总结加密逻辑）",
        epilog="注意：本工具仅用于已获书面授权的安全测试与密码应用合规审计。",
    )
    subparsers = parser.add_subparsers(dest="command")

    p_scan = subparsers.add_parser("scan", help="扫描一个文件并分析其加密逻辑与密钥")
    p_scan.add_argument("--file", required=True, help="待扫描文件路径")
    p_scan.add_argument("--deep", action="store_true",
                        help="深度模式：展开压缩包内更多条目、更彻底地挖掘二进制字符串")
    p_scan.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        dest="max_bytes",
                        help="文本分析最多读取的字节数，默认 %d" % DEFAULT_MAX_BYTES)
    p_scan.add_argument("--json", action="store_true", dest="as_json",
                        help="以 JSON 格式输出（供 GUI / 自动化消费）")
    p_scan.add_argument("--progress", action="store_true",
                        help="向 stderr 播报进度（[PROGRESS] 百分比 阶段），供 GUI 进度条使用")
    p_scan.set_defaults(func=cmd_scan)

    parser.add_argument("--selftest", action="store_true",
                        help="运行内置自检（无需其它参数）")
    return parser


def main(argv: list[str] | None = None) -> int:
    """程序主入口。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "selftest", False):
        return run_selftest()

    if not getattr(args, "command", None):
        parser.print_help()
        print("\n[提示] 请指定子命令：scan --file <文件路径>")
        return EXIT_USAGE

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[中断] 用户取消操作", file=sys.stderr)
        return EXIT_RUNTIME
    except RuntimeError as exc:
        print("[运行错误] %s" % exc, file=sys.stderr)
        return EXIT_RUNTIME
    except Exception as exc:  # noqa: BLE001
        print("[未知错误] %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return EXIT_RUNTIME


if __name__ == "__main__":
    sys.exit(main())
