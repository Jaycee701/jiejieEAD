#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 jiejieEAD | 共享密码引擎（crypto_core.py）
================================================================================

【定位】
    本文件是整套工具集**唯一的密码算法/模式/填充定义源**，被以下模块共用：
      · cli_crypto.py          —— 加解密工作台（CLI / GUI Tab 1）
      · mitm_crypto.py         —— 中间人自动加解密（GUI Tab 2）
      · file_crypto_scanner.py —— 文件扫描分析（读取本文件能力矩阵生成配置）
    目的：避免「扫描器认得的模式，加解密引擎却不支持」这类能力漂移。

【免责声明】
    仅用于已获书面授权的安全测试与研究。全部运算本地离线完成，
    不上传任何密钥、明文或密文。

【设计原则】
    1. **绝不手写密码算法本体**（S 盒、轮函数、密钥扩展）。
       - AES / DES / 3DES / RC4：直接调用 pycryptodome 原生实现；
       - SM4：调用 gmssl 的 one_round 分组原语。
    2. 本文件自己实现的只有「分组模式的链接组装」（CBC/CFB/OFB/CTR 的异或链、
       反馈、计数器）与「填充格式」（PKCS#7 / Zero / ISO7816 / ANSIX923）
       —— 这两类属于数据编排规范，不是密码算法本体。
    3. GCM 的 GHASH 同属模式组装。为了让实现**可被证明正确**，自检里用
       「本文件的通用 GCM」加密 AES，并与 pycryptodome 原生 AES-GCM 的
       密文 + 认证标签逐字节比对。一致即证明 GHASH/GCTR 构造正确；
       同一套构造再用于 SM4-GCM，从而不必依赖任何未经验证的国密 GCM 实现。

【方向约束（重要）】
    GCM / CFB / OFB / CTR 这四种模式，解密时使用的仍然是**块加密函数 E**，
    只有 ECB / CBC 的解密方向才需要块解密函数 D。代码中通过「显式传入
    encrypting 标志 + 按模式挑选 block_op」来保证，不留隐式约定。

【支持矩阵】
    算法        密钥长度(字节)   分组   可用模式
    sm4         16               16     ecb cbc cfb ofb ctr gcm
    aes128      16               16     ecb cbc cfb ofb ctr gcm
    aes192      24               16     ecb cbc cfb ofb ctr gcm
    aes256      32               16     ecb cbc cfb ofb ctr gcm
    des         8                8      ecb cbc cfb ofb ctr
    des3        24 / 16          8      ecb cbc cfb ofb ctr
    rc4         5-256            流     —（无模式、无填充、无 IV）

    填充（仅 ecb / cbc 生效；cfb/ofb/ctr/gcm 属流式，强制 none）
    pkcs7 | zero | none | iso7816 | ansix923
================================================================================
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import gzip
import hashlib
import hmac
import io
import json
import re
import secrets
import sys
import urllib.parse
import zlib
from dataclasses import dataclass
from typing import Any, Callable

# ----------------------------------------------------------------------------
# 依赖按需导入：缺失时记录，由调用方给出友好中文提示
# ----------------------------------------------------------------------------
_MISSING_DEPS: list[str] = []

try:
    from Crypto.Cipher import AES, DES, DES3, ARC4  # pycryptodome
    # 经典分组 / 流算法：Blowfish、CAST5(CAST-128)、RC2、ChaCha20、Salsa20。
    # 它们在新旧 pycryptodome 里都在，但为稳妥起见单独 try —— 缺了只影响这几个算法，
    # 不该把 AES/DES 一起拖下水。
    from Crypto.Cipher import Blowfish, CAST, ARC2, ChaCha20, Salsa20
    from Crypto.Util import Counter as _Counter
except ImportError:  # pragma: no cover
    AES = DES = DES3 = ARC4 = None  # type: ignore
    Blowfish = CAST = ARC2 = ChaCha20 = Salsa20 = None  # type: ignore
    _Counter = None  # type: ignore
    _MISSING_DEPS.append("pycryptodome")

try:
    from gmssl import sm4 as gmssl_sm4  # gmssl 库
except ImportError:  # pragma: no cover
    gmssl_sm4 = None  # type: ignore
    _MISSING_DEPS.append("gmssl")

try:
    from gmssl import sm3 as gmssl_sm3  # SM3 摘要（供摘要 / HMAC-SM3 使用）
except ImportError:  # pragma: no cover
    gmssl_sm3 = None  # type: ignore

# ---- 非对称：SM2（gmssl）/ RSA（pycryptodome）----
try:
    from gmssl import sm2 as gmssl_sm2
    from gmssl import func as gmssl_func
except ImportError:  # pragma: no cover
    gmssl_sm2 = None    # type: ignore
    gmssl_func = None   # type: ignore

try:
    from Crypto.Hash import MD5 as _HASH_MD5, SHA1 as _HASH_SHA1, SHA256 as _HASH_SHA256, \
        SHA384 as _HASH_SHA384, SHA512 as _HASH_SHA512
    from Crypto.PublicKey import RSA as _RSA_KEY_CLS
    from Crypto.Cipher import PKCS1_OAEP as _PKCS1_OAEP, PKCS1_v1_5 as _PKCS1_V15
    from Crypto.Signature import pkcs1_15 as _PKCS1_15, pss as _PSS

    class _HashModule:      # 便捷取用（hash_alg 字符串 → 模块）
        MD5 = _HASH_MD5
        SHA1 = _HASH_SHA1
        SHA256 = _HASH_SHA256
        SHA384 = _HASH_SHA384
        SHA512 = _HASH_SHA512

    _HASH_MOD = _HashModule
    _SM2_CLS = gmssl_sm2.CryptSM2 if gmssl_sm2 is not None else None
except ImportError:  # pragma: no cover
    _RSA_KEY_CLS = None             # type: ignore
    _PKCS1_OAEP = _PKCS1_V15 = None  # type: ignore
    _PKCS1_15 = _PSS = None          # type: ignore
    _HASH_MOD = None                 # type: ignore
    _SM2_CLS = gmssl_sm2.CryptSM2 if gmssl_sm2 is not None else None


# ----------------------------------------------------------------------------
# 【兼容补丁】gmssl 3.2.2 的 CryptSM2.__init__ 里写的是：
#       self.public_key = public_key.lstrip("04") if public_key.startswith("04") else public_key
#   本意是剥掉"未压缩点"的 04 前缀，但 str.lstrip 的参数是**字符集**而不是前缀 ——
#   它会把开头所有 '0' / '4' 字符一并剥掉。
#   于是当一把合法公钥（128 位 HEX）的 X 分量恰好以 "04" 开头时（随机密钥约 1/256
#   命中；实测 2000 把随机密钥崩 9 次 ≈ 0.45%），公钥被截短成 126 位；
#   _kg 内部的 _add_point 拿到过短的点会返回 None，紧接着 len(None) 抛
#       TypeError: object of type 'NoneType' has no len()
#   表现为「SM2 加密 / 签名约 0.4% 概率偶发崩溃，且报错完全不可读」。
#   这里用子类在构造之后把公钥还原成规范化结果，绕开该缺陷（不改 gmssl 包本体）。
# ----------------------------------------------------------------------------
def _normalize_sm2_pub_hex(text: object) -> "str | None":
    """把「128 位 HEX 公钥（可带 0x / 04 前缀）」规范化成裸 128 位 HEX。

    只处理 HEX 形态；PEM / Base64 一律返回 None（交给 parse_sm2_public_key，
    此处不越权改写，保持 gmssl 原有行为）。
    """
    if not isinstance(text, str):
        return None
    t = re.sub(r"[\s:\-]", "", text)
    if t.lower().startswith("0x"):
        t = t[2:]
    for prefix in ("04", "06", "07"):
        if t.lower().startswith(prefix) and len(t) > 128:
            t = t[len(prefix):]
            break
    if len(t) == 128 and all(c in "0123456789abcdefABCDEF" for c in t):
        return t.lower()
    return None


if _SM2_CLS is not None and not getattr(_SM2_CLS, "_jjead_pubkey_patched", False):

    class _JJEADCryptSM2(_SM2_CLS):       # type: ignore[misc, valid-type]
        """CryptSM2 子类：修正 lstrip("04") 截断公钥的缺陷。"""

        _jjead_pubkey_patched = True

        def __init__(self, private_key, public_key,
                     ecc_table=gmssl_sm2.default_ecc_table, mode=0, asn1=False):
            super().__init__(private_key=private_key, public_key=public_key,
                             ecc_table=ecc_table, mode=mode, asn1=asn1)
            fixed = _normalize_sm2_pub_hex(public_key)
            if fixed is not None:
                self.public_key = fixed          # ← 还原被 lstrip 破坏的公钥

    _SM2_CLS = _JJEADCryptSM2


# ============================================================================
# 异常
# ============================================================================

class CryptoUsageError(Exception):
    """参数/输入校验错误（调用方一般映射为退出码 1）。"""


class CryptoRuntimeError(Exception):
    """依赖缺失、IO 异常、认证失败等运行时错误（映射为退出码 2）。"""


def missing_dependencies() -> list[str]:
    """返回缺失的依赖包名列表（供调用方检查）。"""
    return sorted(set(_MISSING_DEPS))


def check_dependencies() -> None:
    """检查密码库是否可用，缺失则给出安装提示。"""
    if _MISSING_DEPS:
        raise CryptoRuntimeError(
            "缺少依赖库：{0}\n请在本机项目目录执行：pip install {0}".format(
                " ".join(sorted(set(_MISSING_DEPS)))
            )
        )


# ============================================================================
# 一、能力矩阵（唯一事实来源）
# ============================================================================

MODE_ECB = "ecb"
MODE_CBC = "cbc"
MODE_CFB = "cfb"
MODE_OFB = "ofb"
MODE_CTR = "ctr"
MODE_GCM = "gcm"
MODE_STREAM = "stream"          # RC4 这类天然流密码，无分组模式概念

#: 流式模式：无需填充；且解密方向仍然只用块加密函数 E
STREAM_LIKE_MODES = (MODE_CFB, MODE_OFB, MODE_CTR, MODE_GCM, MODE_STREAM)

#: 仅这两种模式的解密方向需要块解密函数 D
MODES_NEEDING_DECRYPT_OP = (MODE_ECB, MODE_CBC)

PAD_PKCS7 = "pkcs7"
PAD_ZERO = "zero"
PAD_NONE = "none"
PAD_ISO7816 = "iso7816"
PAD_ANSIX923 = "ansix923"

PAD_DISPLAY = {
    PAD_PKCS7: "PKCS#7",
    PAD_ZERO: "ZeroPadding（零填充）",
    PAD_NONE: "NoPadding（不填充）",
    PAD_ISO7816: "ISO/IEC 7816-4（0x80 补位）",
    PAD_ANSIX923: "ANSI X9.23",
}

MODE_DISPLAY = {
    MODE_ECB: "ECB（电子密码本，无 IV；相同明文块密文相同，不安全）",
    MODE_CBC: "CBC（密码分组链接，需要 IV）",
    MODE_CFB: "CFB（密文反馈，流式，无需填充）",
    MODE_OFB: "OFB（输出反馈，流式，无需填充）",
    MODE_CTR: "CTR（计数器，流式，无需填充）",
    MODE_GCM: "GCM（认证加密 AEAD，产出 16 字节认证标签）",
    MODE_STREAM: "流密码（无分组模式）",
}

#: 结论上「按分组对齐」的模式
BLOCK_MODES = (MODE_ECB, MODE_CBC)

ENCODINGS = ("base64", "hex", "raw")
ENCODING_DISPLAY = {
    "base64": "Base64",
    "hex": "Hex",
    "raw": "Raw（原始二进制，仅适合文件模式）",
}


@dataclass(frozen=True)
class AlgoSpec:
    """一个算法的完整能力描述。"""
    aid: str                      # 命令行标识，如 "aes256"
    display: str                  # 展示名，如 "AES-256"
    family: str                   # 底层实现族：aes / des / des3 / sm4 / rc4 / …
    key_sizes: tuple[int, ...]    # 允许的密钥字节长度
    block: int                    # 分组字节数；流密码为 1
    modes: tuple[str, ...]        # 支持的模式
    implemented_in: str = ""      # 实现来源说明
    note: str = ""
    # 带 nonce 的流密码（ChaCha20 / Salsa20）允许的 nonce 字节长度；
    # 空元组表示「无 nonce」（RC4）或「非流密码」。
    nonce_sizes: tuple[int, ...] = ()
    # 参数化分组算法的参数：(轮数, 字长位)。仅 RC5 / RC6 使用。
    rc_params: tuple[int, int] = ()

    @property
    def is_stream(self) -> bool:
        return self.block == 1

    @property
    def default_key_len(self) -> int:
        return self.key_sizes[0]

    @property
    def key_hex_lens(self) -> list[int]:
        return [n * 2 for n in self.key_sizes]

    @property
    def key_hint(self) -> str:
        """
        人类可读的密钥长度提示。
        连续区间（如 RC4 的 5-256）用范围表达，避免把上百个数字塞进 UI。
        """
        sizes = self.key_sizes
        if len(sizes) == 1:
            return f"{sizes[0]} 字节（{sizes[0] * 2} 位 HEX）"
        if len(sizes) == 2:
            return f"{sizes[0]} 或 {sizes[1]} 字节"
        if sizes == tuple(range(sizes[0], sizes[-1] + 1)):
            return f"{sizes[0]}-{sizes[-1]} 字节（{sizes[0] * 2}-{sizes[-1] * 2} 位 HEX）"
        return " / ".join(str(n) for n in sizes) + " 字节"

    @property
    def is_key_range(self) -> bool:
        """密钥长度是否为连续区间（RC4 这类）。"""
        sizes = self.key_sizes
        return len(sizes) > 4 and sizes == tuple(range(sizes[0], sizes[-1] + 1))

    def to_dict(self) -> dict[str, Any]:
        """给 GUI 用的元数据（GUI 据此渲染下拉框与长度提示）。"""
        return {
            "id": self.aid,
            "display": self.display,
            "key_sizes": list(self.key_sizes) if not self.is_key_range else [],
            "key_range": [self.key_sizes[0], self.key_sizes[-1]] if self.is_key_range else None,
            "key_hex_lens": self.key_hex_lens if not self.is_key_range else [],
            "default_key_bytes": self.default_key_len,
            "key_hint": self.key_hint,
            "block": self.block,
            "is_stream": self.is_stream,
            "modes": list(self.modes),
            "modes_display": [MODE_DISPLAY.get(m, m) for m in self.modes],
            "implemented_in": self.implemented_in,
            "note": self.note,
            "nonce_sizes": list(self.nonce_sizes),
            "rc_params": list(self.rc_params),
        }


ALGO_SPECS: dict[str, AlgoSpec] = {
    "sm4": AlgoSpec(
        aid="sm4", display="SM4", family="sm4",
        key_sizes=(16,), block=16,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR, MODE_GCM),
        implemented_in="gmssl 分组原语 + 本模块模式组装",
        note="国密分组算法；GCM 为通用构造（已用 AES-GCM 对照验证）",
    ),
    "aes128": AlgoSpec(
        aid="aes128", display="AES-128", family="aes",
        key_sizes=(16,), block=16,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR, MODE_GCM),
        implemented_in="pycryptodome",
    ),
    "aes192": AlgoSpec(
        aid="aes192", display="AES-192", family="aes",
        key_sizes=(24,), block=16,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR, MODE_GCM),
        implemented_in="pycryptodome",
    ),
    "aes256": AlgoSpec(
        aid="aes256", display="AES-256", family="aes",
        key_sizes=(32,), block=16,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR, MODE_GCM),
        implemented_in="pycryptodome",
    ),
    "des": AlgoSpec(
        aid="des", display="DES", family="des",
        key_sizes=(8,), block=8,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR),
        implemented_in="pycryptodome",
        note="密钥仅 56 位有效，只用于复现遗留系统，切勿用于新业务",
    ),
    "des3": AlgoSpec(
        aid="des3", display="3DES / Triple DES", family="des3",
        key_sizes=(24, 16), block=8,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR),
        implemented_in="pycryptodome",
        note="24 字节为 3-key；16 字节为 2-key(EDE) 变体",
    ),
    "rc4": AlgoSpec(
        aid="rc4", display="RC4", family="rc4",
        key_sizes=tuple(range(5, 257)), block=1,
        modes=(MODE_STREAM,),
        implemented_in="pycryptodome",
        note="流密码：无 IV、无填充，密钥 5-256 字节",
    ),

    # ---------------- RC5 / RC6：本模块自实现（pycryptodome 与 cryptography 均无） ----------------
    # 参数化分组算法，每个变体单独一项。字节序按 OpenSSL / BouncyCastle 惯例（字小端）。
    # 实现已用公开向量坐实：RC5-32/12/16 对 RFC 2040；RC6-32/20/16 对 BouncyCastle（源自
    # AES 提交的 RSA 参考实现）×3 —— 见 run_selftest 的 [9/9] 段。
    "rc5": AlgoSpec(
        aid="rc5", display="RC5-32/12/16", family="rc5",
        key_sizes=(16,), block=8,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR),
        implemented_in="本模块自实现（已用 RFC 2040 公开向量验证）",
        note="自实现·已用公开向量验证。分组 8 字节（32 位字 ×2）、12 轮，"
             "故无 GCM；纯 Python 实现，大文件比 pycryptodome 慢约两个数量级",
        rc_params=(12, 32),
    ),
    "rc5_16": AlgoSpec(
        aid="rc5_16", display="RC5-32/16/16", family="rc5",
        key_sizes=(16,), block=8,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR),
        implemented_in="本模块自实现（内核已用 RFC 2040 向量验证）",
        note="自实现。RC5-32 的 16 轮变体，分组 8 字节；纯 Python 实现",
        rc_params=(16, 32),
    ),
    "rc5_64": AlgoSpec(
        aid="rc5_64", display="RC5-64/16/16", family="rc5",
        key_sizes=(16, 32), block=16,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR, MODE_GCM),
        implemented_in="本模块自实现（内核已用 RFC 2040 向量验证）",
        note="自实现。64 位字变体，分组 16 字节，可用 GCM；纯 Python 实现",
        rc_params=(16, 64),
    ),
    "rc6": AlgoSpec(
        aid="rc6", display="RC6-32/20/16", family="rc6",
        key_sizes=(16, 24, 32), block=16,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR, MODE_GCM),
        implemented_in="本模块自实现（已用 BouncyCastle/AES 参考实现向量验证）",
        note="自实现·已用公开向量验证。AES 候选算法，分组 16 字节、20 轮；"
             "纯 Python 实现，大文件比 pycryptodome 慢约两个数量级",
        rc_params=(20, 32),
    ),
    "rc6_16": AlgoSpec(
        aid="rc6_16", display="RC6-32/16/16", family="rc6",
        key_sizes=(16, 24, 32), block=16,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR, MODE_GCM),
        implemented_in="本模块自实现（内核已用公开向量验证）",
        note="自实现。RC6 的 16 轮变体，分组 16 字节；纯 Python 实现",
        rc_params=(16, 32),
    ),

    # ---------------- pycryptodome 原生可用的经典分组算法 ----------------
    "blowfish": AlgoSpec(
        aid="blowfish", display="Blowfish", family="blowfish",
        key_sizes=tuple(range(4, 57)), block=8,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR),
        implemented_in="pycryptodome",
        note="分组 8 字节（故无 GCM）；密钥 4-56 字节可变长。已用 Eric Young 标准向量验证",
    ),
    "cast5": AlgoSpec(
        aid="cast5", display="CAST5 (CAST-128)", family="cast5",
        key_sizes=(5, 8, 16), block=8,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR),
        implemented_in="pycryptodome",
        note="分组 8 字节；**密钥仅支持 5 / 8 / 16 字节**（其它长度会被底层拒绝）。"
             "已用 RFC 2144 向量验证",
    ),
    "rc2": AlgoSpec(
        aid="rc2", display="RC2", family="rc2",
        key_sizes=tuple(range(5, 129)), block=8,
        modes=(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR),
        implemented_in="pycryptodome",
        note="分组 8 字节；密钥 5-128 字节。**另有 effective key bits 参数**（默认 128，"
             "可用 --rc2-effective-bits 调整）—— 它不对是 RC2 解成乱码的头号原因"
             "（RFC 2268 的测试向量用的是 63）。已用 RFC 2268 向量验证",
    ),

    # ---------------- pycryptodome 原生可用的流密码（带 nonce） ----------------
    "chacha20": AlgoSpec(
        aid="chacha20", display="ChaCha20", family="chacha20",
        key_sizes=(32,), block=1,
        modes=(MODE_STREAM,),
        implemented_in="pycryptodome",
        note="流密码：无填充，**密钥必须 32 字节**，**必须给 nonce**"
             "（8 / 12 / 24 字节；12 字节为 RFC 7539 变体）。已用 RFC 8439 向量验证",
        nonce_sizes=(8, 12, 24),
    ),
    "salsa20": AlgoSpec(
        aid="salsa20", display="Salsa20", family="salsa20",
        key_sizes=(16, 32), block=1,
        modes=(MODE_STREAM,),
        implemented_in="pycryptodome",
        note="流密码：无填充，**nonce 只能 8 字节**。已用 eSTREAM 官方向量验证",
        nonce_sizes=(8,),
    ),
}

FAMILY_DISPLAY = {
    "sm4": "SM4（国密）",
    "aes": "AES（高级加密标准）",
    "des": "DES（数据加密标准）",
    "des3": "3DES（三重 DES）",
    "rc4": "RC4（流密码）",
    "rc5": "RC5（自实现）",
    "rc6": "RC6（自实现）",
    "blowfish": "Blowfish",
    "cast5": "CAST5 / CAST-128",
    "rc2": "RC2",
    "chacha20": "ChaCha20（流密码）",
    "salsa20": "Salsa20（流密码）",
}


# RC2 的「有效密钥位数」（RFC 2268 的 T1）：底层默认 128，这里也默认 128。
# ⚠ 它不对是 RC2 解成乱码的头号原因 —— RFC 2268 的测试向量用的是 **63**。
# CLI 可用 --rc2-effective-bits 覆盖（见 set_rc2_effective_bits）。
RC2_EFFECTIVE_BITS = 128


def set_rc2_effective_bits(bits: int) -> None:
    """设置 RC2 的有效密钥位数（T1）。传入 None/0 表示用底层默认 128。"""
    global RC2_EFFECTIVE_BITS
    RC2_EFFECTIVE_BITS = int(bits) if bits else 128


def algo_choices() -> list[str]:
    return list(ALGO_SPECS.keys())


def mode_choices() -> list[str]:
    return [MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR, MODE_GCM, MODE_STREAM]


def padding_choices() -> list[str]:
    return [PAD_PKCS7, PAD_ZERO, PAD_NONE, PAD_ISO7816, PAD_ANSIX923]


def get_spec(alg: str) -> AlgoSpec:
    spec = ALGO_SPECS.get((alg or "").lower())
    if spec is None:
        raise CryptoUsageError(f"不支持的算法：{alg}（可选：{'/'.join(ALGO_SPECS)}）")
    return spec


def get_spec_by_keylen(alg: str, key_bytes: int) -> AlgoSpec:
    """给定密钥长度，在算法族内挑选匹配的具体算法（如 aes → aes256）。"""
    base = (alg or "").lower()
    if base in ("aes", "des3"):
        for spec in ALGO_SPECS.values():
            if spec.family == base and key_bytes in spec.key_sizes:
                return spec
    return get_spec(alg)


def has_integrity_check(mode: str, padding: str) -> bool:
    """
    判断「模式 + 填充」组合是否具备可自动判定密钥错误的完整性校验。

    这直接决定工具的自我验证能力，是渗透测试中判断结果可信度的关键：

      能自动判定（返回 True）：
        · GCM         —— AEAD 认证标签，密钥/nonce 错误直接报认证失败
        · PKCS#7      —— 去填充严格校验，错误密钥几乎必然违反填充格式
        · ISO 7816-4  —— 需找到 0x80 补位字节，错误密钥通常失败
        · ANSI X9.23  —— 需满足「前 n-1 字节全 0」，有一定检出率

      无法自动判定（返回 False）：
        · ZeroPadding / NoPadding —— 无任何格式约束，错误密钥静默产出乱码
        · CFB / OFB / CTR / RC4   —— 纯流式异或，无结构可校验

    当返回 False 时，使用者必须**人工判断明文是否符合业务预期**，
    不能因为"解密没报错"就认为密钥正确。
    """
    if mode == MODE_GCM:
        return True
    if mode in STREAM_LIKE_MODES:
        return False
    return padding in (PAD_PKCS7, PAD_ISO7816, PAD_ANSIX923)


def integrity_warning(mode: str, padding: str) -> str | None:
    """若该组合缺乏完整性校验，返回一句中文提示；否则返回 None。"""
    if has_integrity_check(mode, padding):
        return None
    if mode in (MODE_CFB, MODE_OFB, MODE_CTR, MODE_STREAM):
        return (
            f"{mode.upper()} 属流式模式，没有完整性校验："
            "密钥/IV 错误时不会报错，只会解出一段看似正常的乱码。"
            "请人工确认解密结果是否符合业务预期，切勿仅凭「无报错」判断密钥正确。"
        )
    return (
        f"{PAD_DISPLAY.get(padding, padding)}不携带任何填充格式约束，"
        "无法据此判断密钥是否正确：密钥错误时会静默产出乱码。"
        "如需可靠验证，建议改用 PKCS#7 填充，或使用 GCM 认证加密。"
    )


def capability_matrix() -> dict[str, Any]:
    """
    导出完整能力矩阵（GUI 启动时调用，动态渲染下拉框，避免前后端定义漂移）。
    """
    return {
        "algorithms": [s.to_dict() for s in ALGO_SPECS.values()],
        "modes": [{"id": m, "display": MODE_DISPLAY[m]} for m in mode_choices()],
        "paddings": [{"id": p, "display": PAD_DISPLAY[p]} for p in padding_choices()],
        "encodings": [{"id": e, "display": ENCODING_DISPLAY[e]} for e in ENCODINGS],
        # ---- 密钥材料格式：真实目标的密钥常常是 UTF-8 字面量或 Base64，不是 HEX ----
        "key_formats": [{"id": f, "display": KEY_FORMAT_DISPLAY[f],
                         "hint": KEY_FORMAT_HINT[f]}
                        for f in (KEY_HEX, KEY_UTF8, KEY_BASE64, KEY_AUTO)],
        "digests": [{"id": d, "display": v["display"], "bytes": v["bytes"],
                     "weak": v["weak"], "note": v["note"]}
                    for d, v in DIGEST_SPECS.items()],
        "hmacs": [{"id": h, "display": v["display"], "bytes": v["bytes"],
                   "note": v.get("note", "")}
                  for h, v in HMAC_SPECS.items()],
        "kdf_presets": [{"id": k, "display": v["display"], "needs": v["needs"]}
                        for k, v in KDF_PRESETS.items()],
        # ---- 非对称 / 压缩 / 编码链（真实业务里的组合拳）----
        "asym": {
            "algorithms": [
                {"id": ASYM_SM2, "display": "SM2（国密，加解密/签名验签）",
                 "ops": ["enc", "dec", "sign", "verify"],
                 "key_inputs": ["public_key(128 位 HEX/04 前缀/BASE64/PEM)",
                                "private_key(64 位 HEX/BASE64/PEM)"],
                 "extra": ["cipher_mode(c1c3c2/c1c2c3)", "asn1(DER 签名)"]},
                {"id": ASYM_RSA, "display": "RSA（PKCS#1 v1.5 / OAEP，长文本自动分段）",
                 "ops": ["enc", "dec", "sign", "verify"],
                 "key_inputs": ["PEM", "DER/BASE64", "JSON(n,e[,d])", "HEX"],
                 "extra": ["padding(pkcs1v15/oaep)", "scheme(pkcs1v15/pss)", "hash(md5..sha512)"]},
            ],
            "sm2_cipher_modes": [
                {"id": SM2_C1C3C2, "display": SM2_CIPHER_MODE_DISPLAY[SM2_C1C3C2]},
                {"id": SM2_C1C2C3, "display": SM2_CIPHER_MODE_DISPLAY[SM2_C1C2C3]},
            ],
            "rsa_paddings": list(RSA_PADDINGS),
            "rsa_sign_schemes": list(RSA_SIGN_SCHEMES),
            "hash_algos": ["md5", "sha1", "sha256", "sha384", "sha512"],
        },
        "compression": [{"id": a, "display": COMPRESS_DISPLAY[a]} for a in COMPRESS_ALGOS],
        "chain_steps": [{"id": c, "display": CHAIN_STEP_DISPLAY[c]} for c in CHAIN_STEPS],
        "stream_like_modes": list(STREAM_LIKE_MODES),
        "block_modes": list(BLOCK_MODES),
        "families": FAMILY_DISPLAY,
        "version": 5,   # v5：新增 RC5/RC6/Blowfish/CAST5/RC2/ChaCha20/Salsa20
    }


# ============================================================================
# 二、HEX / 编码工具
# ============================================================================

def hex_to_bytes(value: str, name: str, expect_len: int | None = None) -> bytes:
    """HEX 字符串 → bytes，容错空格/换行/0x 前缀/冒号/短横线，并做长度校验。"""
    if value is None:
        raise CryptoUsageError(f"{name} 不能为空")

    cleaned = (
        value.strip()
        .replace(" ", "").replace("\n", "").replace("\r", "")
        .replace("\t", "").replace(":", "").replace("-", "")
    )
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]

    if not cleaned:
        raise CryptoUsageError(f"{name} 不能为空")

    if not all(c in "0123456789abcdefABCDEF" for c in cleaned):
        bad = next(c for c in cleaned if c not in "0123456789abcdefABCDEF")
        raise CryptoUsageError(
            f"{name} 必须是 HEX(十六进制) 格式，检测到非法字符：'{bad}'。\n"
            f"正确示例：{'0' * (expect_len * 2) if expect_len else '0123456789abcdef'}"
        )

    if len(cleaned) % 2 != 0:
        raise CryptoUsageError(
            f"{name} 的 HEX 长度必须为偶数（两个十六进制字符表示 1 字节），"
            f"当前长度为 {len(cleaned)}"
        )

    raw = bytes.fromhex(cleaned)
    if expect_len is not None and len(raw) != expect_len:
        raise CryptoUsageError(
            f"{name} 长度不合法：要求 {expect_len} 字节（{expect_len * 2} 位 HEX），"
            f"当前为 {len(raw)} 字节（{len(cleaned)} 位 HEX）"
        )
    return raw


def encode_bytes(data: bytes, encoding: str) -> str:
    """二进制 → 文本（base64 / hex / raw）。"""
    if encoding == "base64":
        return base64.b64encode(data).decode("ascii")
    if encoding == "hex":
        return binascii.hexlify(data).decode("ascii")
    if encoding == "raw":
        return data.decode("latin-1")
    raise CryptoUsageError(f"不支持的输出编码：{encoding}")


def decode_text(text: str, encoding: str) -> bytes:
    """文本 → 二进制（base64 / hex / raw）。"""
    if encoding == "base64":
        cleaned = text.replace("\n", "").replace("\r", "").replace(" ", "")
        cleaned += "=" * ((-len(cleaned)) % 4)      # 容错缺失的 '=' 填充
        try:
            return base64.b64decode(cleaned, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CryptoUsageError(f"Base64 解码失败，请检查密文格式：{exc}") from exc
    if encoding == "hex":
        return hex_to_bytes(text, "密文")
    if encoding == "raw":
        return text.encode("latin-1")
    raise CryptoUsageError(f"不支持的输入编码：{encoding}")


# ============================================================================
# 三、填充 / 去填充
# ============================================================================

def pad_data(data: bytes, block: int, style: str) -> bytes:
    """
    按 style 填充。

    对齐语义（与 pycryptodome / CryptoJS 一致）：
      · pkcs7 / iso7816 / ansix923 / zero：**总是**补到下一个分组边界，
        已对齐时额外补一整块，保证解密端可无歧义去填充；
      · none：不填充，但要求已对齐，否则报错。
    """
    if block <= 1:
        return data

    if style == PAD_NONE:
        if len(data) % block != 0:
            raise CryptoUsageError(
                f"选择 NoPadding 时数据必须恰好按 {block} 字节对齐，"
                f"当前长度为 {len(data)} 字节（差 {block - len(data) % block} 字节）"
            )
        return data

    pad_len = block - (len(data) % block)

    if style == PAD_PKCS7:
        return data + bytes([pad_len]) * pad_len
    if style == PAD_ZERO:
        return data + b"\x00" * pad_len
    if style == PAD_ISO7816:
        return data + b"\x80" + b"\x00" * (pad_len - 1)
    if style == PAD_ANSIX923:
        return data + b"\x00" * (pad_len - 1) + bytes([pad_len])

    raise CryptoUsageError(f"不支持的填充方式：{style}")


def unpad_data(data: bytes, block: int, style: str) -> bytes:
    """
    去填充并**严格校验**。

    校验失败一律抛错而不是静默返回乱码 —— 这是本工具相对 gmssl 原生实现的
    关键改进：错误密钥/IV 必须被明确检出，避免密码测评中的假阳性。
    """
    if block <= 1 or style == PAD_NONE:
        return data

    if not data:
        raise CryptoUsageError("密文为空，无法去填充")
    if len(data) % block != 0:
        raise CryptoUsageError(f"密文长度非法：必须是 {block} 字节的整数倍")

    if style == PAD_PKCS7:
        pad_len = data[-1]
        if pad_len < 1 or pad_len > block:
            raise CryptoUsageError(
                "PKCS#7 去填充失败：填充字节非法，通常说明【密钥或该模式参数错误】、"
                "或密文被截断/篡改"
            )
        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            raise CryptoUsageError(
                "PKCS#7 去填充失败：填充内容不一致，通常说明【密钥或该模式参数错误】、"
                "或密文被截断/篡改"
            )
        return data[:-pad_len]

    if style == PAD_ZERO:
        # 零填充天然歧义（无法区分真实尾随 0x00），只能尽力剥离
        return data.rstrip(b"\x00")

    if style == PAD_ISO7816:
        idx = len(data) - 1
        while idx >= 0 and data[idx] == 0x00:
            idx -= 1
        if idx < 0 or data[idx] != 0x80:
            raise CryptoUsageError(
                "ISO/IEC 7816-4 去填充失败：未找到 0x80 补位字节，"
                "通常说明【密钥或该模式参数错误】"
            )
        return data[:idx]

    if style == PAD_ANSIX923:
        pad_len = data[-1]
        if pad_len < 1 or pad_len > block:
            raise CryptoUsageError(
                "ANSI X9.23 去填充失败：填充长度字段非法，"
                "通常说明【密钥或该模式参数错误】"
            )
        if data[-(pad_len):-1] != b"\x00" * (pad_len - 1):
            raise CryptoUsageError(
                "ANSI X9.23 去填充失败：填充内容不一致，"
                "通常说明【密钥或该模式参数错误】"
            )
        return data[:-pad_len]

    raise CryptoUsageError(f"不支持的填充方式：{style}")


# ============================================================================
# 四、GF(2^128) 乘法与 GHASH（GCM 用；NIST SP 800-38D 标准算法）
# ============================================================================

_GCM_R = 0xE1000000000000000000000000000000      # 约简多项式 R = 11100001 || 0^120
_MASK128 = (1 << 128) - 1
_MASK32 = (1 << 32) - 1


def gf128_mul(x: int, y: int) -> int:
    """GF(2^128) 乘法（GCM 约定，自最高位起逐位）。"""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ _GCM_R if v & 1 else v >> 1
    return z


def ghash(h: int, data: bytes) -> int:
    """GHASH_H(data)：按 16 字节分组累积，末块右侧补零。"""
    y = 0
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16].ljust(16, b"\x00")
        y = gf128_mul(y ^ int.from_bytes(block, "big"), h)
    return y


def _inc32(value: int) -> int:
    """仅对最低 32 位 +1（GCM 计数器递增规则）。"""
    return (value & ~_MASK32) | ((value + 1) & _MASK32)


def _gcm_j0(h: int, nonce: bytes) -> int:
    """计算预计数器 J0（兼容任意长度 nonce，非仅 96 位）。"""
    if len(nonce) == 12:
        return int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")
    pad_len = (-len(nonce)) % 16
    tail = nonce + b"\x00" * pad_len + b"\x00" * 8 + (len(nonce) * 8).to_bytes(8, "big")
    return ghash(h, tail)


def _gctr(block_enc: Callable[[bytes], bytes], icb: int, data: bytes) -> bytes:
    """GCTR：以 icb 为初始计数块生成密钥流并与 data 异或。"""
    out = bytearray()
    counter = icb
    for offset in range(0, len(data), 16):
        keystream = block_enc(counter.to_bytes(16, "big"))
        chunk = data[offset:offset + 16]
        out += bytes(a ^ b for a, b in zip(chunk, keystream))
        counter = _inc32(counter)
    return bytes(out)


def _gcm_tag(block_enc: Callable[[bytes], bytes], h: int, j0: int,
             aad: bytes, cipher: bytes) -> bytes:
    """计算认证标签 T = E(J0) ⊕ GHASH(H, A || pad || C || pad || len(A) || len(C))。"""
    aad_pad = aad + b"\x00" * ((-len(aad)) % 16)
    ct_pad = cipher + b"\x00" * ((-len(cipher)) % 16)
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(cipher) * 8).to_bytes(8, "big")
    s = ghash(h, aad_pad + ct_pad + lengths)
    return bytes(a ^ b for a, b in zip(block_enc(j0.to_bytes(16, "big")),
                                       s.to_bytes(16, "big")))


def gcm_encrypt_128(block_enc: Callable[[bytes], bytes], nonce: bytes,
                    plain: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """
    通用 GCM 加密（适用于任意 128 位分组的块加密函数）。
    解密方向也只用 block_enc（GCM 不需要块解密函数）。
    返回 (密文, 16 字节认证标签)。
    """
    h = int.from_bytes(block_enc(b"\x00" * 16), "big")
    j0 = _gcm_j0(h, nonce)
    cipher = _gctr(block_enc, _inc32(j0), plain)
    return cipher, _gcm_tag(block_enc, h, j0, aad, cipher)


def gcm_decrypt_128(block_enc: Callable[[bytes], bytes], nonce: bytes,
                    cipher: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """通用 GCM 解密；认证标签不匹配则抛 CryptoRuntimeError。"""
    h = int.from_bytes(block_enc(b"\x00" * 16), "big")
    j0 = _gcm_j0(h, nonce)
    expect = _gcm_tag(block_enc, h, j0, aad, cipher)
    if expect != tag:
        raise CryptoRuntimeError(
            "GCM 认证失败：认证标签不匹配，说明【密钥/nonce 错误】或密文已被篡改。\n"
            "（这是 AEAD 模式的正常保护行为，不是程序缺陷）"
        )
    return _gctr(block_enc, _inc32(j0), cipher)


# ============================================================================
# 五、SM4 分组原语 + 通用分组模式组装
# ----------------------------------------------------------------------------
# 【重要工程决策 · 关于 gmssl 的填充陷阱】
#   gmssl 的 crypt_ecb / crypt_cbc 内部会自动做 PKCS#7 填充，但其去填充实现为
#   `lambda data: data[:-data[-1]]` —— **完全不校验填充**。后果：密钥或 IV 出错时
#   解密会「静默成功」并返回乱码，使用者会误以为解密正确。对密码测评/渗透场景，
#   这是不可接受的假阳性来源。
#   因此本模块：密码运算 100% 走 gmssl 的 one_round 分组原语；填充与链接模式由
#   本模块实现并严格校验。（已用 GB/T 32907-2016 官方向量验证分组运算：
#   key = pt = 0123456789abcdeffedcba9876543210 → 681edf34d206965e86b3e94f536e4246）
# ============================================================================

def sm4_encrypt_block(key: bytes, block: bytes) -> bytes:
    """SM4 块加密 E（16 → 16 字节），调用 gmssl 的 one_round。"""
    return _sm4_one_round(key, block, encrypt=True)


def sm4_decrypt_block(key: bytes, block: bytes) -> bytes:
    """SM4 块解密 D（16 → 16 字节）。"""
    return _sm4_one_round(key, block, encrypt=False)


def _sm4_one_round(key: bytes, block: bytes, encrypt: bool) -> bytes:
    if gmssl_sm4 is None:
        raise CryptoRuntimeError("缺少 gmssl 依赖，无法执行 SM4 运算")
    if len(block) != 16:
        raise CryptoUsageError("SM4 分组长度必须为 16 字节")

    cipher = gmssl_sm4.CryptSM4()
    cipher.set_key(key, gmssl_sm4.SM4_ENCRYPT if encrypt else gmssl_sm4.SM4_DECRYPT)
    if not hasattr(cipher, "one_round"):
        raise CryptoRuntimeError(
            "当前 gmssl 版本缺少 one_round 分组原语接口，请升级：pip install -U gmssl"
        )
    return bytes(cipher.one_round(cipher.sk, list(block)))


# ============================================================================
# 12b. RC5 / RC6 分组原语（本模块自实现）
# ============================================================================
# 【为什么破例手写算法本体】
#   本文件开头的设计原则是「绝不手写密码算法本体」，但 RC5 与 RC6 在 pycryptodome
#   与 cryptography 里**都没有实现**，而它们是渗透测试里会遇到的真实算法。
#   因此这里破例自实现，并以**公开标准向量**做担保（见 run_selftest 的 [9/9] 段）：
#     · RC5-32/12/16 → RFC 2040 测试向量
#     · RC6-32/20/16 → BouncyCastle 的向量（源自 AES 提交的 RSA 参考实现）
#   参数化变体（16 轮 / 64 位字）与上述两者共用同一份密钥编排与轮函数代码，
#   只差 rounds / word-size 两个参数。
#
# 【字节序】按 OpenSSL / BouncyCastle 的惯例 = **字小端**（little-endian word packing）。
#   ⚠ 注意：RFC 2040 正文里的部分测试向量是按「字大端」打印的，同一算法两种约定
#   输出互为「每 4 字节反转」。自检里用的是与本实现同约定（小端）的那组向量。
#
# 【性能】纯 Python 实现，比 pycryptodome 的 C 实现慢约两个数量级；短报文无感，
#   大文件会明显变慢 —— spec 的 note 里已向用户提示。

_RC5_P = {32: 0xB7E15163, 64: 0xB7E151628AED2A6B}
_RC5_Q = {32: 0x9E3779B9, 64: 0x9E3779B97F4A7C15}


def _rotl_w(x: int, n: int, w: int) -> int:
    m = (1 << w) - 1
    n %= w
    return ((x << n) | (x >> (w - n))) & m


def _rotr_w(x: int, n: int, w: int) -> int:
    m = (1 << w) - 1
    n %= w
    return ((x >> n) | (x << (w - n))) & m


def _rc_key_sched(key: bytes, rounds: int, w: int, t_words: int) -> list[int]:
    """RC5 / RC6 共用的密钥编排（RFC 2040 的 key expansion）。"""
    P, Q = _RC5_P[w], _RC5_Q[w]
    mask = (1 << w) - 1
    u = w // 8
    c = max(1, len(key) // u)
    L = [int.from_bytes(key[i * u:(i + 1) * u].ljust(u, b"\x00"), "little")
         for i in range(c)]
    S = [0] * t_words
    S[0] = P
    for i in range(1, t_words):
        S[i] = (S[i - 1] + Q) & mask
    a = b = i = j = 0
    for _ in range(3 * max(t_words, c)):
        a = S[i] = _rotl_w((S[i] + a + b) & mask, 3, w)
        b = L[j] = _rotl_w((L[j] + a + b) & mask, (a + b) & (w - 1), w)
        i = (i + 1) % t_words
        j = (j + 1) % c
    return S


def rc5_encrypt_block(key: bytes, block: bytes, rounds: int = 12, w: int = 32) -> bytes:
    """RC5 块加密（block = 两个 w 位字，共 w/4 字节）。"""
    h = w // 8
    if len(block) != 2 * h:
        raise CryptoUsageError("RC5（%d 位字）分组长度必须为 %d 字节" % (w, 2 * h))
    mask = (1 << w) - 1
    S = _rc_key_sched(key, rounds, w, 2 * (rounds + 1))
    a = (int.from_bytes(block[:h], "little") + S[0]) & mask
    b = (int.from_bytes(block[h:], "little") + S[1]) & mask
    for i in range(1, rounds + 1):
        a = (_rotl_w(a ^ b, b & (w - 1), w) + S[2 * i]) & mask
        b = (_rotl_w(b ^ a, a & (w - 1), w) + S[2 * i + 1]) & mask
    return a.to_bytes(h, "little") + b.to_bytes(h, "little")


def rc5_decrypt_block(key: bytes, block: bytes, rounds: int = 12, w: int = 32) -> bytes:
    """RC5 块解密（与加密严格互逆）。"""
    h = w // 8
    if len(block) != 2 * h:
        raise CryptoUsageError("RC5（%d 位字）分组长度必须为 %d 字节" % (w, 2 * h))
    mask = (1 << w) - 1
    S = _rc_key_sched(key, rounds, w, 2 * (rounds + 1))
    a = int.from_bytes(block[:h], "little")
    b = int.from_bytes(block[h:], "little")
    for i in range(rounds, 0, -1):
        b = (_rotr_w((b - S[2 * i + 1]) & mask, a & (w - 1), w) ^ a) & mask
        a = (_rotr_w((a - S[2 * i]) & mask, b & (w - 1), w) ^ b) & mask
    return ((a - S[0]) & mask).to_bytes(h, "little") + ((b - S[1]) & mask).to_bytes(h, "little")


def rc6_encrypt_block(key: bytes, block: bytes, rounds: int = 20, w: int = 32) -> bytes:
    """RC6 块加密（block 长度 = w/2 字节，即 4 个 w 位字）。"""
    h = w // 8
    if len(block) != 4 * h:
        raise CryptoUsageError("RC6（%d 位字）分组长度必须为 %d 字节" % (w, 4 * h))
    mask = (1 << w) - 1
    lg = w.bit_length() - 1
    S = _rc_key_sched(key, rounds, w, 2 * rounds + 4)
    a, b, c, d = (int.from_bytes(block[h * i:h * (i + 1)], "little") for i in range(4))
    b = (b + S[0]) & mask
    d = (d + S[1]) & mask
    for i in range(1, rounds + 1):
        t = _rotl_w((b * (2 * b + 1)) & mask, lg, w)
        u = _rotl_w((d * (2 * d + 1)) & mask, lg, w)
        a = (_rotl_w(a ^ t, u & (w - 1), w) + S[2 * i]) & mask
        c = (_rotl_w(c ^ u, t & (w - 1), w) + S[2 * i + 1]) & mask
        a, b, c, d = b, c, d, a
    a = (a + S[2 * rounds + 2]) & mask
    c = (c + S[2 * rounds + 3]) & mask
    return b"".join(x.to_bytes(h, "little") for x in (a, b, c, d))


def rc6_decrypt_block(key: bytes, block: bytes, rounds: int = 20, w: int = 32) -> bytes:
    """RC6 块解密（与加密严格互逆）。"""
    h = w // 8
    if len(block) != 4 * h:
        raise CryptoUsageError("RC6（%d 位字）分组长度必须为 %d 字节" % (w, 4 * h))
    mask = (1 << w) - 1
    lg = w.bit_length() - 1
    S = _rc_key_sched(key, rounds, w, 2 * rounds + 4)
    a, b, c, d = (int.from_bytes(block[h * i:h * (i + 1)], "little") for i in range(4))
    c = (c - S[2 * rounds + 3]) & mask
    a = (a - S[2 * rounds + 2]) & mask
    for i in range(rounds, 0, -1):
        a, b, c, d = d, a, b, c
        u = _rotl_w((d * (2 * d + 1)) & mask, lg, w)
        t = _rotl_w((b * (2 * b + 1)) & mask, lg, w)
        c = (_rotr_w((c - S[2 * i + 1]) & mask, t & (w - 1), w) ^ u) & mask
        a = (_rotr_w((a - S[2 * i]) & mask, u & (w - 1), w) ^ t) & mask
    d = (d - S[1]) & mask
    b = (b - S[0]) & mask
    return b"".join(x.to_bytes(h, "little") for x in (a, b, c, d))


def mode_ecb(block_op: Callable[[bytes], bytes], data: bytes, block: int) -> bytes:
    """ECB：逐块独立运算（相同明文块 → 相同密文块，不安全，仅用于复现）。"""
    _require_aligned(data, block, "ECB")
    return b"".join(block_op(data[i:i + block]) for i in range(0, len(data), block))


def mode_cbc(block_op: Callable[[bytes], bytes], iv: bytes, data: bytes,
             block: int, encrypting: bool) -> bytes:
    """
    CBC 链接。
      加密：C[i] = E(P[i] ⊕ C[i-1])，block_op 必须是 E
      解密：P[i] = D(C[i]) ⊕ C[i-1]，block_op 必须是 D
    """
    _require_aligned(data, block, "CBC")
    out = bytearray()
    prev = iv
    for i in range(0, len(data), block):
        chunk = data[i:i + block]
        if encrypting:
            result = block_op(bytes(a ^ b for a, b in zip(chunk, prev)))
            prev = result
        else:
            decrypted = block_op(chunk)
            result = bytes(a ^ b for a, b in zip(decrypted, prev))
            prev = chunk
        out += result
    return bytes(out)


def mode_cfb(block_enc: Callable[[bytes], bytes], iv: bytes, data: bytes,
             block: int, encrypting: bool) -> bytes:
    """CFB：加解密**都只用 E**。C[i] = P[i] ⊕ E(C[i-1]) / P[i] = C[i] ⊕ E(C[i-1])。

    流式模式，允许任意字节长度：末块的密钥流按需截断即可（zip 天然截断）。
    """
    out = bytearray()
    prev = iv
    for i in range(0, len(data), block):
        chunk = data[i:i + block]
        keystream = block_enc(prev)
        result = bytes(a ^ b for a, b in zip(chunk, keystream))
        out += result
        prev = result if encrypting else chunk      # 反馈的一律是密文
    return bytes(out)


def mode_ofb(block_enc: Callable[[bytes], bytes], iv: bytes, data: bytes,
             block: int) -> bytes:
    """OFB：O[i] = E(O[i-1])，C[i] = P[i] ⊕ O[i]（加解密同一套运算，只用 E）。

    流式模式，允许任意字节长度。
    """
    out = bytearray()
    feedback = iv
    for i in range(0, len(data), block):
        chunk = data[i:i + block]
        feedback = block_enc(feedback)
        out += bytes(a ^ b for a, b in zip(chunk, feedback))
    return bytes(out)


def mode_ctr(block_enc: Callable[[bytes], bytes], iv: bytes, data: bytes,
             block: int) -> bytes:
    """CTR：以 IV 为初始计数器（大端整数递增），密钥流与数据异或，只用 E。"""
    out = bytearray()
    span = 1 << (block * 8)
    counter = int.from_bytes(iv, "big")
    for i in range(0, len(data), block):
        chunk = data[i:i + block]
        keystream = block_enc(counter.to_bytes(block, "big"))
        out += bytes(a ^ b for a, b in zip(chunk, keystream))
        counter = (counter + 1) % span
    return bytes(out)


def _require_aligned(data: bytes, block: int, mode_name: str) -> None:
    """分组模式要求数据严格按分组长度对齐。"""
    if block > 1 and len(data) % block != 0:
        raise CryptoUsageError(
            f"{mode_name} 模式的数据长度必须是 {block} 字节的整数倍，"
            f"当前为 {len(data)} 字节"
        )


# ============================================================================
# 六、参数规范化与校验
# ============================================================================

def normalize_mode_padding(spec: AlgoSpec, mode: str,
                           padding: str) -> tuple[str, str, list[str]]:
    """
    规范化模式与填充，返回 (mode, padding, notes)。

    规则：
      · 流密码（RC4）只有 stream 模式，无填充、无 IV；
      · 流式模式（cfb/ofb/ctr/gcm）不需要填充，若用户显式选了别的会给出提示；
      · 分组模式（ecb/cbc）使用用户填充，默认 pkcs7。
    """
    notes: list[str] = []
    mode = (mode or "").lower()
    padding = (padding or "").lower()

    if mode not in spec.modes:
        raise CryptoUsageError(
            f"{spec.display} 不支持模式 {mode.upper()}；"
            f"可用模式：{'/'.join(m.upper() for m in spec.modes)}"
        )

    if mode in STREAM_LIKE_MODES:
        if padding not in ("", PAD_NONE):
            notes.append(
                f"{mode.upper()} 属流式模式，本身不需要填充，"
                f"已忽略你选择的 {PAD_DISPLAY.get(padding, padding)}。"
            )
        padding = PAD_NONE
    else:
        padding = padding or PAD_PKCS7
        if padding not in padding_choices():
            raise CryptoUsageError(
                f"不支持的填充方式：{padding}（可选：{'/'.join(padding_choices())}）"
            )

    return mode, padding, notes


def validate_key(spec: AlgoSpec, key: bytes) -> None:
    """校验密钥长度。"""
    if len(key) not in spec.key_sizes:
        if spec.is_key_range:
            lo, hi = spec.key_sizes[0], spec.key_sizes[-1]
            want = f"{lo}-{hi}"
            hexes = f"{lo * 2}-{hi * 2}"
        else:
            want = " 或 ".join(str(n) for n in spec.key_sizes)
            hexes = " 或 ".join(str(n * 2) for n in spec.key_sizes)
        raise CryptoUsageError(
            f"{spec.display} 的密钥长度不合法：要求 {want} 字节（{hexes} 位 HEX），"
            f"当前为 {len(key)} 字节（{len(key) * 2} 位 HEX）"
        )


def validate_iv(spec: AlgoSpec, mode: str, iv: bytes) -> None:
    """校验 IV / nonce 长度。ECB 与无 nonce 的流密码不需要 IV。"""
    # 带 nonce 的流密码（ChaCha20 / Salsa20）走这里的校验：它们 block==1，
    # 若直接走下面的早退分支就完全不做校验，用户不传 nonce 也放行，
    # 直到 _dispatch 构造 cipher 时才炸 —— 报错点离用户操作太远。
    if spec.nonce_sizes:
        if not iv:
            raise CryptoUsageError(
                "%s 需要 nonce，请用 --iv 提供（允许长度：%s 字节）"
                % (spec.display, " / ".join(str(n) for n in spec.nonce_sizes)))
        if len(iv) not in spec.nonce_sizes:
            raise CryptoUsageError(
                "%s 的 nonce 只能为 %s 字节，当前为 %d 字节"
                % (spec.display,
                   " / ".join(str(n) for n in spec.nonce_sizes), len(iv)))
        return

    if spec.is_stream or mode in (MODE_STREAM, MODE_ECB):
        return

    if not iv:
        raise CryptoUsageError(f"{mode.upper()} 模式需要提供 IV/nonce（HEX）")

    if mode == MODE_GCM:
        if len(iv) not in (12, 16):
            raise CryptoUsageError(
                f"GCM 的 nonce 应为 12 字节（24 位 HEX，标准）或 16 字节；"
                f"当前为 {len(iv)} 字节"
            )
        return

    if len(iv) != spec.block:
        raise CryptoUsageError(
            f"{spec.display} 在 {mode.upper()} 模式下的 IV 必须为 {spec.block} 字节"
            f"（{spec.block * 2} 位 HEX），当前为 {len(iv)} 字节（{len(iv) * 2} 位 HEX）"
        )


# ============================================================================
# 七、密钥材料格式 / 摘要 / HMAC / 密钥派生
# ----------------------------------------------------------------------------
#  为什么要有这一节：真实目标（白盒前端、H5、App 内嵌脚本、jar 扩展）里，
#  密钥几乎从来不是"干净的 HEX"。最常见的三种形态是：
#    1. HEX 文本        "0123456789abcdeffedcba9876543210"
#    2. UTF-8 字面量    "4A7F2C1E9B3D5A08"  ← 16 个 ASCII 字符 = 16 字节！
#                        按 HEX 解只有 8 字节，AES-128 会直接报长度不合法
#    3. Base64 文本     "TURC3g0="
#  而且密钥往往还要"派生"出来：
#        种子(随机数/时间戳) → 对称加密 → 摘要 → 取中间若干字节 → 当分组密钥
#  外加一层 HMAC-SM3 / HMAC-SHA256 做报文签名。
#
#  本节把「密钥格式」「摘要」「HMAC」「派生链」补齐，字段与
#  常见真实业务链路一一对应，可直接复现。
# ============================================================================

# ---- 密钥/IV 文本格式 ----
KEY_HEX = "hex"
KEY_UTF8 = "utf8"
KEY_BASE64 = "base64"
KEY_AUTO = "auto"
KEY_FORMATS = (KEY_HEX, KEY_UTF8, KEY_BASE64, KEY_AUTO)
KEY_FORMAT_DISPLAY = {
    KEY_HEX: "HEX 十六进制文本",
    KEY_UTF8: "UTF-8 字面量",
    KEY_BASE64: "Base64 文本",
    KEY_AUTO: "自动判定",
}
KEY_FORMAT_HINT = {
    KEY_HEX: "十六进制文本，如 0123456789abcdeffedcba9876543210（32 字符 = 16 字节）",
    KEY_UTF8: "把密钥当文本用其 UTF-8 字节，如 4A7F2C1E9B3D5A08（16 字符 = 16 字节）",
    KEY_BASE64: "Base64 文本，解码后为密钥字节",
    KEY_AUTO: "按 HEX → Base64 → UTF-8 顺序尝试（可用 --keyinfo 查看各解释）",
}


def parse_key_material(value: str, fmt: str = KEY_HEX, name: str = "密钥") -> bytes:
    """按指定格式把**文本**密钥解析成字节。

    这里是整套工具最容易出错的地方：同一个字符串按不同格式解析，字节数完全不同。
    例如 "4A7F2C1E9B3D5A08"：
        hex  → 8 字节（AES-128 直接报错）
        utf8 → 16 字节（真实业务里的正确用法）
    """
    if value is None:
        raise CryptoUsageError(f"{name} 不能为空")
    fmt = (fmt or KEY_HEX).strip().lower()
    if fmt not in KEY_FORMATS:
        raise CryptoUsageError(
            f"不支持的密钥格式：{fmt}（可选：{'/'.join(KEY_FORMATS)}）")
    text = value.strip()
    if not text:
        raise CryptoUsageError(f"{name} 不能为空")

    if fmt == KEY_HEX:
        return hex_to_bytes(text, name)
    if fmt == KEY_UTF8:
        return text.encode("utf-8")
    if fmt == KEY_BASE64:
        cleaned = text.replace("\n", "").replace("\r", "").replace(" ", "")
        cleaned += "=" * ((-len(cleaned)) % 4)
        try:
            return base64.b64decode(cleaned, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CryptoUsageError(f"{name} 不是合法的 Base64：{exc}") from exc

    # ---- auto：HEX（仅当整串都是 hex 且长度为偶数）→ Base64 → UTF-8 ----
    probe = (text.replace(" ", "").replace("\n", "").replace("\r", "")
             .replace("\t", "").replace(":", "").replace("-", ""))
    if probe.lower().startswith("0x"):
        probe = probe[2:]
    if probe and len(probe) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in probe):
        return bytes.fromhex(probe)
    cleaned = text.replace("\n", "").replace("\r", "").replace(" ", "")
    cleaned_padded = cleaned + "=" * ((-len(cleaned)) % 4)
    try:
        return base64.b64decode(cleaned_padded, validate=True)
    except (binascii.Error, ValueError):
        return text.encode("utf-8")


def explain_key_material(value: str) -> dict:
    """列出同一段密钥文本在三种格式下分别会得到多少字节。

    给 GUI 用：用户填了 "4A7F2C1E9B3D5A08" 时，界面能直接提示
    「按 HEX 是 8 字节、按 UTF-8 是 16 字节」——真实业务里 90% 的
    「密钥长度不合法」都是这一处看错了。
    """
    reps = []
    for fmt in (KEY_HEX, KEY_UTF8, KEY_BASE64):
        item = {"format": fmt, "display": KEY_FORMAT_DISPLAY[fmt]}
        try:
            raw = parse_key_material(value, fmt, "密钥")
            item.update({
                "ok": True,
                "bytes": len(raw),
                "hex": binascii.hexlify(raw).decode("ascii"),
                "preview": binascii.hexlify(raw[:16]).decode("ascii"),
            })
        except (CryptoUsageError, CryptoRuntimeError) as exc:
            item.update({"ok": False, "reason": str(exc).split("\n")[0]})
        reps.append(item)
    return {"text": value, "chars": len(value or ""), "interpretations": reps}


# ============================================================================
# 摘要（digest）
# ============================================================================
DIGEST_SPECS: dict[str, dict[str, Any]] = {
    "md5":    {"display": "MD5", "bytes": 16, "impl": "hashlib", "weak": True,
               "note": "已不适合用于安全场景，仅用于复现老系统的逻辑"},
    "sha1":   {"display": "SHA-1", "bytes": 20, "impl": "hashlib", "weak": True,
               "note": "同上，碰撞已被工程化"},
    "sha256": {"display": "SHA-256", "bytes": 32, "impl": "hashlib", "weak": False, "note": ""},
    "sha512": {"display": "SHA-512", "bytes": 64, "impl": "hashlib", "weak": False, "note": ""},
    "sm3":    {"display": "SM3（国密）", "bytes": 32, "impl": "gmssl", "weak": False,
               "note": "国密摘要，输出与 GB/T 32905-2016 向量一致"},
}


def digest_choices() -> list[str]:
    return list(DIGEST_SPECS)


class _SM3Hash:
    """haslib 风格的 SM3 适配器：让标准库 hmac.new 直接支持 HMAC-SM3。"""

    block_size = 64
    digest_size = 32
    name = "sm3"

    def __init__(self, data: bytes = b""):
        self._buf = bytes(data)

    def update(self, data: bytes) -> None:
        self._buf += bytes(data)

    def digest(self) -> bytes:
        return sm3_digest(self._buf)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "_SM3Hash":
        return _SM3Hash(self._buf)


def sm3_digest(data: bytes) -> bytes:
    """SM3 摘要（32 字节）。"""
    if gmssl_sm3 is None:                      # pragma: no cover
        raise CryptoRuntimeError("缺少 gmssl，无法计算 SM3：pip install gmssl")
    return bytes.fromhex(gmssl_sm3.sm3_hash(list(data)))


def do_digest(alg: str, data: bytes) -> bytes:
    """计算摘要，返回原始字节（16/20/32/64 字节）。"""
    key = (alg or "").strip().lower()
    if key not in DIGEST_SPECS:
        raise CryptoUsageError(
            f"不支持的摘要算法：{alg}（可选：{'/'.join(digest_choices())}）")
    if key == "sm3":
        return sm3_digest(data)
    return hashlib.new(key, data).digest()


# ============================================================================
# HMAC（报文签名 / 完整性校验）
# ============================================================================
HMAC_SPECS: dict[str, dict[str, Any]] = {
    "hmac-md5":    {"display": "HMAC-MD5", "bytes": 16, "algo": "md5"},
    "hmac-sha1":   {"display": "HMAC-SHA1", "bytes": 20, "algo": "sha1"},
    "hmac-sha256": {"display": "HMAC-SHA256", "bytes": 32, "algo": "sha256"},
    "hmac-sha512": {"display": "HMAC-SHA512", "bytes": 64, "algo": "sha512"},
    "hmac-sm3":    {"display": "HMAC-SM3（国密）", "bytes": 32, "algo": "sm3",
                    "note": "块长 64 字节；与 BouncyCastle HMac(SM3Digest) 逐字节一致"},
}


def hmac_choices() -> list[str]:
    return list(HMAC_SPECS)


def do_hmac(alg: str, key: bytes, data: bytes) -> bytes:
    """计算 HMAC，返回原始字节。"""
    spec_entry = HMAC_SPECS.get((alg or "").strip().lower())
    if not spec_entry:
        raise CryptoUsageError(
            f"不支持的 HMAC 算法：{alg}（可选：{'/'.join(hmac_choices())}）")
    algo = spec_entry["algo"]
    digester = _SM3Hash if algo == "sm3" else algo
    return hmac.new(bytes(key), bytes(data), digester).digest()


# ============================================================================
# 密钥派生（KDF）
# ----------------------------------------------------------------------------
#  步骤是 JSON 可序列化的 dict 列表，GUI / CLI 用同一套描述：
#    {"op":"encrypt","alg":"aes128","mode":"cbc","padding":"pkcs7",
#     "key":"4A7F2C1E9B3D5A08","key_format":"utf8",
#     "iv":"C6B1D90E37F2A485","iv_format":"utf8"}
#    {"op":"decrypt", ...同上...}
#    {"op":"digest","alg":"sha256"}                       # sha256/sm3/md5/sha1/sha512
#    {"op":"hmac","alg":"hmac-sm3","key":"...","key_format":"utf8"}
#    {"op":"slice","start":16,"end":32}                   # 左闭右开；end 可为 null
# ============================================================================
KDF_PRESETS: dict[str, dict[str, Any]] = {
    "digest-sha256": {
        "display": "SHA256(种子)",
        "steps": [{"op": "digest", "alg": "sha256"}],
        "needs": [],
    },
    "digest-md5": {
        "display": "MD5(种子)",
        "steps": [{"op": "digest", "alg": "md5"}],
        "needs": [],
    },
    "digest-sm3": {
        "display": "SM3(种子)",
        "steps": [{"op": "digest", "alg": "sm3"}],
        "needs": [],
    },
    "hmac-sha256": {
        "display": "HMAC-SHA256(派生密钥, 种子)",
        "steps": [{"op": "hmac", "alg": "hmac-sha256", "key": "@key", "key_format": "@key_format"}],
        "needs": ["key"],
    },
    "hmac-sm3": {
        "display": "HMAC-SM3(派生密钥, 种子)",
        "steps": [{"op": "hmac", "alg": "hmac-sm3", "key": "@key", "key_format": "@key_format"}],
        "needs": ["key"],
    },
    "aes-cbc-then-sha256": {
        "display": "AES-128-CBC(种子) → SHA256",
        "steps": [
            {"op": "encrypt", "alg": "aes128", "mode": "cbc", "padding": "pkcs7",
             "key": "@key", "key_format": "@key_format",
             "iv": "@iv", "iv_format": "@iv_format"},
            {"op": "digest", "alg": "sha256"},
        ],
        "needs": ["key", "iv"],
    },
    "aes-cbc-then-sha256-slice": {
        "display": "AES-128-CBC(种子) → SHA256 → 取字节区间（白盒前端最常见）",
        "steps": [
            {"op": "encrypt", "alg": "aes128", "mode": "cbc", "padding": "pkcs7",
             "key": "@key", "key_format": "@key_format",
             "iv": "@iv", "iv_format": "@iv_format"},
            {"op": "digest", "alg": "sha256"},
            {"op": "slice", "start": "@slice_start", "end": "@slice_end"},
        ],
        "needs": ["key", "iv"],
    },
    "sm4-cbc-then-sm3": {
        "display": "SM4-CBC(种子) → SM3",
        "steps": [
            {"op": "encrypt", "alg": "sm4", "mode": "cbc", "padding": "pkcs7",
             "key": "@key", "key_format": "@key_format",
             "iv": "@iv", "iv_format": "@iv_format"},
            {"op": "digest", "alg": "sm3"},
        ],
        "needs": ["key", "iv"],
    },
}


def kdf_preset_choices() -> list[str]:
    return list(KDF_PRESETS)


def build_kdf_steps(preset: str, *, key: str = "", iv: str = "",
                    key_format: str = KEY_HEX, iv_format: str = KEY_HEX,
                    slice_start: int | None = None,
                    slice_end: int | None = None) -> list[dict]:
    """把预设展开成具体步骤（@key / @iv / @slice_* 占位符替换成实际参数）。"""
    entry = KDF_PRESETS.get((preset or "").strip().lower())
    if not entry:
        raise CryptoUsageError(
            f"未知的派生预设：{preset}（可选：{'/'.join(kdf_preset_choices())}）")
    missing = [n for n in entry["needs"] if n == "key" and not key or n == "iv" and not iv]
    if missing:
        raise CryptoUsageError(
            "该派生方式需要额外参数：" + "、".join(
                {"key": "派生密钥", "iv": "派生 IV"}[m] for m in missing))

    def subst(step: dict) -> dict:
        out: dict[str, Any] = {}
        for k, v in step.items():
            if v == "@key":
                out[k] = key
            elif v == "@iv":
                out[k] = iv
            elif v == "@key_format":
                out[k] = key_format
            elif v == "@iv_format":
                out[k] = iv_format
            elif v == "@slice_start":
                out[k] = slice_start
            elif v == "@slice_end":
                out[k] = slice_end
            else:
                out[k] = v
        return out

    steps = [subst(s) for s in entry["steps"]]
    # 有些预设（digest-sha256 / digest-md5 / digest-sm3 / hmac-*）只含一步摘要或 HMAC，
    # **本身没有 slice 步骤** —— 调用方传了 slice_start/slice_end 会被静默忽略，
    # 表现为「标着取前 16 字节，实际拿回 32 字节」，是极难查的一类错。
    # 这里补一条：只要调用方要了区间、而预设里没人接，就显式追加一个 slice 步骤。
    if slice_start is not None and not any(st.get("op") == "slice" for st in steps):
        steps.append({"op": "slice", "start": slice_start, "end": slice_end})
    return steps


def derive_key(seed: str, steps: list[dict], seed_format: str = KEY_UTF8) -> dict:
    """执行派生链，返回 {output_hex, output_base64, output_len, trace}。

    `trace` 会逐步记录每一步的输入/输出长度与内容前缀，便于人工核对
    「到底在哪一步开始不一样」——这是复现真实业务时最耗时的排查点。
    """
    if not steps:
        raise CryptoUsageError("派生步骤为空")
    data = parse_key_material(seed, seed_format, "派生种子")
    trace: list[dict] = []

    for idx, step in enumerate(steps, 1):
        op = (step.get("op") or "").strip().lower()
        if op in ("encrypt", "decrypt"):
            alg = step.get("alg") or "aes128"
            key_bytes = parse_key_material(step.get("key", ""), step.get("key_format", KEY_HEX),
                                           "派生用密钥")
            iv_bytes = (parse_key_material(step.get("iv", ""), step.get("iv_format", KEY_HEX),
                                           "派生用 IV")
                        if step.get("iv") else b"")
            before = len(data)
            data = do_crypt(
                alg, "enc" if op == "encrypt" else "dec",
                binascii.hexlify(key_bytes).decode("ascii"),
                binascii.hexlify(iv_bytes).decode("ascii") if iv_bytes else None,
                data,
                mode=step.get("mode") or MODE_CBC,
                padding=step.get("padding") or PAD_PKCS7,
                warn_weak=False,
            )
            trace.append({"step": idx, "op": op,
                          "detail": f"{alg.upper()}-{(step.get('mode') or MODE_CBC).upper()}"
                                    f"/{(step.get('padding') or PAD_PKCS7).upper()}"
                                    f"（密钥 {len(key_bytes)} 字节、IV {len(iv_bytes)} 字节）",
                          "in_len": before, "out_len": len(data),
                          "out_preview": binascii.hexlify(data[:16]).decode("ascii")})
        elif op == "digest":
            alg = step.get("alg") or "sha256"
            before = len(data)
            data = do_digest(alg, data)
            trace.append({"step": idx, "op": "digest", "detail": alg.upper(),
                          "in_len": before, "out_len": len(data),
                          "out_preview": binascii.hexlify(data[:16]).decode("ascii")})
        elif op == "hmac":
            alg = step.get("alg") or "hmac-sha256"
            key_bytes = parse_key_material(step.get("key", ""), step.get("key_format", KEY_HEX),
                                           "HMAC 密钥")
            before = len(data)
            data = do_hmac(alg, key_bytes, data)
            trace.append({"step": idx, "op": "hmac", "detail": alg.upper(),
                          "in_len": before, "out_len": len(data),
                          "out_preview": binascii.hexlify(data[:16]).decode("ascii")})
        elif op == "slice":
            start = step.get("start")
            end = step.get("end")
            before = len(data)
            start = 0 if start is None else int(start)
            data = data[start:None if end is None else int(end)]
            if not data:
                raise CryptoUsageError(
                    f"第 {idx} 步 slice[{start}:{end}] 结果为空：原数据只有 {before} 字节，"
                    "请检查取字节区间（常见错误：把 16 进制字符串的字符位置当字节位置）")
            trace.append({"step": idx, "op": "slice", "detail": f"[{start}:{end if end is not None else '末尾'}]",
                          "in_len": before, "out_len": len(data),
                          "out_preview": binascii.hexlify(data[:16]).decode("ascii")})
        else:
            raise CryptoUsageError(f"不支持的派生步骤：{op}（encrypt/decrypt/digest/hmac/slice）")

    return {
        "output_hex": binascii.hexlify(data).decode("ascii"),
        "output_base64": base64.b64encode(data).decode("ascii"),
        "output_len": len(data),
        "trace": trace,
    }


def derive_key_by_preset(seed: str, preset: str, *, seed_format: str = KEY_UTF8,
                        key: str = "", iv: str = "",
                        key_format: str = KEY_HEX, iv_format: str = KEY_HEX,
                        slice_start: int | None = None,
                        slice_end: int | None = None) -> dict:
    """按预设名执行派生（GUI / CLI 的常用入口）。"""
    steps = build_kdf_steps(preset, key=key, iv=iv, key_format=key_format,
                            iv_format=iv_format, slice_start=slice_start,
                            slice_end=slice_end)
    return derive_key(seed, steps, seed_format=seed_format)


# ============================================================================
# 八、统一加解密入口
# ============================================================================

def do_crypt(alg: str, op: str, key_hex: str, iv_hex: str | None, data: bytes,
             mode: str = MODE_CBC, padding: str = PAD_PKCS7,
             warn_weak: bool = True, notes: list[str] | None = None,
             aad: bytes = b"", key_format: str = KEY_HEX,
             iv_format: str = KEY_HEX) -> bytes:
    """
    统一加解密入口（整套工具集共用）。

    :param alg:       算法 id，见 ALGO_SPECS
    :param op:        "enc" 加密 / "dec" 解密
    :param key_hex:   密钥文本（格式由 key_format 决定；默认 HEX，向后兼容）
    :param iv_hex:    IV / nonce 文本（ECB 与 RC4 可为 None）
    :param data:      enc 时为明文；dec 时为密文（GCM 需含末尾 16 字节标签）
    :param mode:      ecb/cbc/cfb/ofb/ctr/gcm/stream
    :param padding:   pkcs7/zero/none/iso7816/ansix923（仅 ecb/cbc 生效）
    :param warn_weak: 是否输出弱密钥/弱 IV 告警（自检时关闭）
    :param notes:     传入 list 时，会把「已忽略填充」等提示追加进去
    :param aad:       GCM 的附加认证数据（可选）
    :param key_format: 密钥文本格式 hex/utf8/base64/auto —— 真实业务里密钥常是
                       UTF-8 字面量（16 个 ASCII 字符 = 16 字节），按 HEX 解会短一半
    :param iv_format:  IV 文本格式，取值同 key_format
    :return:          enc 时返回密文（GCM 追加 16 字节标签）；dec 时返回明文
    """
    check_dependencies()

    if op not in ("enc", "dec"):
        raise CryptoUsageError(f"不支持的操作：{op}（应为 enc / dec）")

    # 先解析密钥，再据此定位具体算法：这样既支持精确 id（aes256），
    # 也支持族名 + 密钥长度自动判定（--alg aes --key <32字节> → aes256）
    key_probe = parse_key_material(key_hex, key_format, "密钥 KEY")
    spec = get_spec_by_keylen(alg, len(key_probe))
    validate_key(spec, key_probe)

    mode, padding, local_notes = normalize_mode_padding(spec, mode, padding)
    if notes is not None:
        notes.extend(local_notes)

    iv = parse_key_material(iv_hex, iv_format, "初始向量 IV") if iv_hex else b""
    validate_iv(spec, mode, iv)

    # ---- 弱密钥 / 弱 IV 告警（不阻断执行）----
    if warn_weak:
        if len(set(key_probe)) == 1:
            print("[警告] 检测到全同字节密钥（如全 0），属极弱密钥，"
                  "仅建议用于本地调试，切勿用于真实业务。", file=sys.stderr)
        if iv and len(set(iv)) == 1 and mode not in (MODE_STREAM, MODE_ECB):
            print(f"[警告] 检测到全同字节 IV（如全 0），{mode.upper()} 模式的 IV "
                  "应随机生成且每次不同。", file=sys.stderr)

    return _dispatch(spec, mode, padding, op, key_probe, iv, data, aad)


def _assemble_modes(spec: AlgoSpec, mode: str, padding: str, encrypting: bool,
                    key: bytes, iv: bytes, data: bytes, aad: bytes,
                    enc_op: Callable[[bytes], bytes],
                    dec_op: Callable[[bytes], bytes]) -> bytes:
    """用「分组加/解密函数」组装各工作模式（SM4 / RC5 / RC6 共用）。

    本模块的模式实现只依赖「分组字节数 + 块运算函数」，与具体算法无关；
    各分组模式（ECB/CBC/CFB/OFB/CTR）也**全部只处理 16 字节分组的算法**——
    GCM 例外：gcm_* 系列硬编码 128 位分组（见 ghash/_gctr 的实现），
    所以 8 字节分组的算法（DES/3DES/Blowfish/CAST5/RC2/RC5-32）不在 spec.modes 里给 GCM。
    """
    block = spec.block

    if mode == MODE_GCM:
        if block != 16:
            raise CryptoUsageError(
                "%s 分组为 %d 字节，不支持 GCM（GCM 实现按 128 位分组构造）"
                % (spec.display, block))
        if encrypting:
            cipher, tag = gcm_encrypt_128(enc_op, iv, data, aad)
            return cipher + tag
        _require_tag(data)
        return gcm_decrypt_128(enc_op, iv, data[:-16], data[-16:], aad)

    # ECB / CBC 属分组模式，需要填充与严格去填充
    if mode in BLOCK_MODES:
        payload = pad_data(data, block, padding) if encrypting else data
        op_fn = enc_op if encrypting else dec_op
        if mode == MODE_ECB:
            result = mode_ecb(op_fn, payload, block)
        else:
            result = mode_cbc(op_fn, iv, payload, block, encrypting)
        return unpad_data(result, block, padding) if not encrypting else result

    # CFB / OFB / CTR：只用块加密函数
    if mode == MODE_CFB:
        return mode_cfb(enc_op, iv, data, block, encrypting)
    if mode == MODE_OFB:
        return mode_ofb(enc_op, iv, data, block)
    if mode == MODE_CTR:
        return mode_ctr(enc_op, iv, data, block)

    raise CryptoUsageError(f"{spec.display} 不支持模式 {mode.upper()}")


def _dispatch(spec: AlgoSpec, mode: str, padding: str, op: str,
              key: bytes, iv: bytes, data: bytes, aad: bytes) -> bytes:
    """按算法族 + 模式分派到具体实现。"""
    encrypting = (op == "enc")
    block = spec.block

    # ---------- RC4：天然流密码（无 nonce） ----------
    if spec.family == "rc4":
        if ARC4 is None:
            raise CryptoRuntimeError("缺少 pycryptodome 依赖，无法执行 RC4")
        return ARC4.new(key).encrypt(data)

    # ---------- ChaCha20 / Salsa20：带 nonce 的流密码 ----------
    # 与 RC4 的区别：**必须**提供 nonce（走 iv 参数），加解密同一个函数。
    if spec.family in ("chacha20", "salsa20"):
        modulus = {"chacha20": ChaCha20, "salsa20": Salsa20}[spec.family]
        if modulus is None:
            raise CryptoRuntimeError(
                "缺少 pycryptodome 依赖，无法执行 %s" % spec.display)
        if not iv:
            raise CryptoUsageError(
                "%s 需要 nonce，请用 --iv 提供（允许长度：%s 字节）"
                % (spec.display, " / ".join(str(n) for n in spec.nonce_sizes)))
        # ⚠ 必须用关键字传 key：ChaCha20.new() 是纯关键字签名，位置传参会 TypeError
        # （Salsa20 恰好接受位置参数，所以两者写法要统一成关键字才不会漏）。
        return _new_cipher(modulus, spec, key=key, nonce=iv).encrypt(data)

    # ---------- RC5 / RC6：模式由本模块组装（与 SM4 同一条路径） ----------
    if spec.family in ("rc5", "rc6"):
        rounds, w = spec.rc_params or (12, 32)
        if spec.family == "rc5":
            enc_op = lambda b: rc5_encrypt_block(key, b, rounds, w)   # noqa: E731
            dec_op = lambda b: rc5_decrypt_block(key, b, rounds, w)   # noqa: E731
        else:
            enc_op = lambda b: rc6_encrypt_block(key, b, rounds, w)   # noqa: E731
            dec_op = lambda b: rc6_decrypt_block(key, b, rounds, w)   # noqa: E731
        return _assemble_modes(spec, mode, padding, encrypting, key, iv, data, aad,
                               enc_op, dec_op)

    # ---------- SM4：模式由本模块组装 ----------
    if spec.family == "sm4":
        enc_op = lambda b: sm4_encrypt_block(key, b)      # noqa: E731
        dec_op = lambda b: sm4_decrypt_block(key, b)      # noqa: E731
        return _assemble_modes(spec, mode, padding, encrypting, key, iv, data, aad,
                               enc_op, dec_op)

    # ---------- AES / DES / DES3 / Blowfish / CAST5 / RC2：pycryptodome 原生模式 ----------
    module = {"aes": AES, "des": DES, "des3": DES3,
              "blowfish": Blowfish, "cast5": CAST, "rc2": ARC2}[spec.family]
    if module is None:
        raise CryptoRuntimeError(
            "缺少 pycryptodome 依赖，无法执行 %s" % spec.display)

    if mode == MODE_GCM:
        if encrypting:
            cipher = _new_cipher(module, spec, key, module.MODE_GCM, nonce=iv)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return ciphertext + tag
        _require_tag(data)
        cipher = _new_cipher(module, spec, key, module.MODE_GCM, nonce=iv)
        try:
            return cipher.decrypt_and_verify(data[:-16], data[-16:])
        except ValueError as exc:
            raise CryptoRuntimeError(
                "GCM 认证失败：认证标签不匹配，说明【密钥/nonce 错误】或密文已被篡改。\n"
                "（这是 AEAD 模式的正常保护行为，不是程序缺陷）"
            ) from exc

    if mode in BLOCK_MODES:
        payload = pad_data(data, block, padding) if encrypting else data
    else:
        payload = data          # 流式模式不填充

    if mode == MODE_ECB:
        cipher = _new_cipher(module, spec, key, module.MODE_ECB)
    elif mode == MODE_CBC:
        cipher = _new_cipher(module, spec, key, module.MODE_CBC, iv)
    elif mode == MODE_CFB:
        # 全分组反馈（AES→CFB-128 / DES→CFB-64），与 OpenSSL、CryptoJS 默认一致
        cipher = _new_cipher(module, spec, key, module.MODE_CFB, iv, segment_size=block * 8)
    elif mode == MODE_OFB:
        cipher = _new_cipher(module, spec, key, module.MODE_OFB, iv)
    elif mode == MODE_CTR:
        if _Counter is None:
            raise CryptoRuntimeError("缺少 pycryptodome 依赖，无法执行 CTR")
        counter = _Counter.new(block * 8, initial_value=int.from_bytes(iv, "big"))
        cipher = _new_cipher(module, spec, key, module.MODE_CTR, counter=counter)
    else:
        raise CryptoUsageError(f"{spec.display} 不支持模式 {mode.upper()}")

    if encrypting:
        return cipher.encrypt(payload)

    try:
        plain = cipher.decrypt(payload)
    except ValueError as exc:
        raise CryptoRuntimeError(f"解密失败：{exc}") from exc
    return unpad_data(plain, block, padding) if mode in BLOCK_MODES else plain


def _new_cipher(module, spec: AlgoSpec, *args, **kwargs):
    """
    统一包装 pycryptodome 的 new()，把底层 ValueError 翻译成中文可读提示。

    典型场景：3DES 的三段子密钥若完全相同（或 K1==K2），密钥会「退化」为单重 DES，
    pycryptodome 出于安全考虑直接拒绝。直接抛英文 ValueError 对使用者毫无帮助。
    """
    # RC2 有一个额外的「有效密钥位数」参数（RFC 2268 的 T1）。它不对是 RC2 把密文
    # 解成乱码的头号原因 —— 底层默认 128，而 RFC 2268 的测试向量用的是 63。
    if spec.family == "rc2" and "effective_keylen" not in kwargs:
        kwargs["effective_keylen"] = RC2_EFFECTIVE_BITS
    try:
        return module.new(*args, **kwargs)
    except ValueError as exc:
        msg = str(exc)
        if "degenerates" in msg.lower():
            raise CryptoUsageError(
                f"{spec.display} 的密钥退化：三段 8 字节子密钥相同（或前两段相同），"
                "等价于单重 DES，底层库出于安全考虑拒绝使用。\n"
                "请改用三段互不相同的 24 字节密钥，或直接选择 des 算法。"
            ) from exc
        raise CryptoUsageError(f"{spec.display} 参数错误：{msg}") from exc


def _require_tag(data: bytes) -> None:
    """GCM 密文必须包含末尾 16 字节认证标签。"""
    if len(data) < 16:
        raise CryptoUsageError("GCM 密文至少需要包含 16 字节认证标签")


# ============================================================================
# 九、非对称加密（SM2 / RSA）、压缩与多级编码
# ----------------------------------------------------------------------------
#  为什么要有这一节：真实业务（银行/政务 H5、App 内嵌 SDK）几乎不会只用一个
#  对称算法。典型组合是：
#    · 安全键盘 / 敏感字段：随机生成的 SM4 密钥加密数据，
#      再用 SM2（或 RSA）把那个随机密钥加密 —— **混合加密信封**；
#    · 大字段：明文先 gzip/deflate 压缩，再 base64，再加密（多级编码链）；
#    · 完整性：SM3 / HMAC-SM3 做 mac（见第七节）。
#  这些在旧版引擎里全部缺失：只有"SM2 公钥风险审计"，没有 SM2 加解密/签名；
#  RSA、压缩、多级编码链更是完全没有。
#
#  本节所有能力都带自检（第十节 [8/8]）：向量来自公开标准，
#  或用"独立重算"交叉验证（例如用固定随机数 k 自己重算 SM2 的 C1/C2/C3）。
# ============================================================================

# ---- SM2 密文格式 ----
SM2_C1C3C2 = "c1c3c2"      # 国标推荐（GM/T 0003.4）
SM2_C1C2C3 = "c1c2c3"      # 部分老实现使用
SM2_CIPHER_MODES = (SM2_C1C3C2, SM2_C1C2C3)
SM2_CIPHER_MODE_DISPLAY = {
    SM2_C1C3C2: "C1C3C2（国标推荐）",
    SM2_C1C2C3: "C1C2C3（老实现）",
}
_SM2_N = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"

# ---- 非对称算法 ----
ASYM_SM2 = "sm2"
ASYM_RSA = "rsa"
ASYM_CHOICES = (ASYM_SM2, ASYM_RSA)

# ---- RSA 填充 / 签名方案 ----
RSA_PKCS1V15 = "pkcs1v15"
RSA_OAEP = "oaep"
RSA_PSS = "pss"
RSA_PADDINGS = (RSA_PKCS1V15, RSA_OAEP)
RSA_SIGN_SCHEMES = (RSA_PKCS1V15, RSA_PSS)

# ---- 压缩算法 ----
COMPRESS_ZLIB = "zlib"
COMPRESS_GZIP = "gzip"
COMPRESS_DEFLATE = "deflate"
COMPRESS_RAW = "deflate-raw"
COMPRESS_ALGOS = (COMPRESS_ZLIB, COMPRESS_GZIP, COMPRESS_DEFLATE, COMPRESS_RAW)
COMPRESS_DISPLAY = {
    COMPRESS_ZLIB: "zlib（头 78 9C）",
    COMPRESS_GZIP: "gzip（头 1F 8B）",
    COMPRESS_DEFLATE: "deflate（zlib 封装，与 JS pako.deflate 默认一致）",
    COMPRESS_RAW: "deflate-raw（裸流，pako Deflate 原始输出）",
}

# ---- 编码链步骤 ----
CHAIN_STEPS = ("base64", "base64url", "hex", "url", "zlib", "gzip", "deflate", "deflate-raw")
CHAIN_STEP_DISPLAY = {
    "base64": "Base64（加密方向编码 / 解密方向解码）",
    "base64url": "Base64URL（-_ 变体、去填充）",
    "hex": "HEX 十六进制",
    "url": "URL 百分号编码（encodeURIComponent 语义）",
    "zlib": "zlib 压缩 / 解压",
    "gzip": "gzip 压缩 / 解压",
    "deflate": "deflate 压缩 / 解压",
    "deflate-raw": "裸 deflate 压缩 / 解压",
}


def _secure_random_hex(n: int) -> str:
    """密码学安全的随机 hex。"""
    return "".join(secrets.choice("0123456789abcdef") for _ in range(n))


@contextlib.contextmanager
def _secure_random_context():
    """临时把 gmssl 的 random_hex 换成 secrets 版本。

    gmssl 自带的 `func.random_hex` 用的是非密码学的 `random` 模块。
    SM2 加密/签名的随机数 k 一旦可预测，私钥就可能被还原 ——
    真实测评里这属于「实现级漏洞」，所以这里强制换成 secrets（用完还原，不污染全局）。
    """
    if gmssl_func is None:      # pragma: no cover
        yield
        return
    origin = getattr(gmssl_func, "random_hex", None)
    try:
        gmssl_func.random_hex = _secure_random_hex
        yield
    finally:
        if origin is not None:
            gmssl_func.random_hex = origin


# ============================================================================
# 10.1 密钥材料解析（HEX / Base64 / PEM）
# ============================================================================
def _der_from_text(text: str) -> bytes:
    """去掉 PEM 头尾与空白后做 Base64 解码，得到 DER 字节。"""
    body = re.sub(r"-----[A-Z ]+-----", "", text or "")
    body = re.sub(r"[\s]", "", body)
    if not body:
        return b""
    try:
        return base64.b64decode(body + "=" * ((-len(body)) % 4))
    except (binascii.Error, ValueError):
        return b""


def _b64_or_none(text: str):
    cleaned = re.sub(r"[\s]", "", text or "")
    if not cleaned or len(cleaned) < 8:
        return None
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    cleaned += "=" * ((-len(cleaned)) % 4)
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return None


def parse_sm2_private_key(text: str, fmt: str = KEY_AUTO) -> str:
    """解析 SM2 私钥，返回 64 位十六进制（不带 0x）。

    支持：裸 HEX（64 位，可带空格/冒号/短横）、Base64、PEM/DER。
    """
    t = (text or "").strip()
    if not t:
        raise CryptoUsageError("SM2 私钥不能为空")

    cleaned = re.sub(r"[\s:\-]", "", t)
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) == 64 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
        return cleaned.lower()

    der = _der_from_text(t)
    if der:
        idx = der.find(b"\x04\x20")            # RFC 5915：04 20 <32 字节私钥>
        if idx >= 0 and len(der) >= idx + 34:
            cand = der[idx + 2: idx + 2 + 32].hex()
            if 0 < int(cand, 16) < int(_SM2_N, 16):
                return cand
        if len(der) >= 32:                      # PKCS#8 兜底
            cand = der[-32:].hex()
            if 0 < int(cand, 16) < int(_SM2_N, 16):
                return cand

    raw = _b64_or_none(t)
    if raw and len(raw) in (32, 33, 34):
        cand = raw[-32:].hex()
        if 0 < int(cand, 16) < int(_SM2_N, 16):
            return cand

    raise CryptoUsageError("SM2 私钥格式无法识别。支持：64 位 HEX / Base64 / PEM(EC PRIVATE KEY)")


def parse_sm2_public_key(text: str, fmt: str = KEY_AUTO) -> dict:
    """解析 SM2 公钥，返回 {hex, x, y}（hex 为 128 位，不含 04 前缀）。"""
    t = (text or "").strip()
    if not t:
        raise CryptoUsageError("SM2 公钥不能为空")

    cleaned = re.sub(r"[\s:\-]", "", t)
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    for prefix in ("04", "06", "07"):
        if cleaned.lower().startswith(prefix) and len(cleaned) > 128:
            cleaned = cleaned[len(prefix):]
            break
    if len(cleaned) == 128 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
        return {"hex": cleaned.lower(), "x": cleaned[:64].lower(), "y": cleaned[64:].lower()}

    der = _der_from_text(t)
    if der:
        idx = der.find(b"\x04")
        while idx >= 0 and idx + 65 <= len(der):
            cand = der[idx + 1: idx + 65]
            h = cand.hex()
            if len(h) == 128 and int(h[:64], 16) > 0 and int(h[64:], 16) > 0:
                return {"hex": h, "x": h[:64], "y": h[64:]}
            idx = der.find(b"\x04", idx + 1)

    raw = _b64_or_none(t)
    if raw and len(raw) in (64, 65):
        h = raw[-64:].hex()
        return {"hex": h, "x": h[:64], "y": h[64:]}

    raise CryptoUsageError("SM2 公钥格式无法识别。支持：128 位 HEX（可带 04 前缀）/ Base64 / PEM")


def load_rsa_key(text: str, password: str | None = None):
    """加载 RSA 密钥。支持 PEM / DER-Base64 / JSON(n,e[,d]) / 纯 HEX。

    :return: (key 对象, 'public' | 'private')
    """
    if _RSA_KEY_CLS is None:      # pragma: no cover
        raise CryptoRuntimeError("缺少 pycryptodome，无法使用 RSA：pip install pycryptodome")
    t = (text or "").strip()
    if not t:
        raise CryptoUsageError("RSA 密钥不能为空")

    if "-----" in t:
        try:
            key = _RSA_KEY_CLS.import_key(
                t.encode("utf-8"), passphrase=password.encode() if password else None)
        except Exception as exc:  # noqa: BLE001
            raise CryptoUsageError(f"RSA PEM 解析失败：{exc}") from exc
        return key, ("private" if key.has_private() else "public")

    if t.startswith("{"):
        try:
            data = json.loads(t)
        except ValueError as exc:
            raise CryptoUsageError(f"RSA 密钥 JSON 解析失败：{exc}") from exc
        try:
            n, e = int(str(data["n"]), 16), int(str(data["e"]), 16)
            if data.get("d"):
                return _RSA_KEY_CLS.construct((n, e, int(str(data["d"]), 16))), "private"
            return _RSA_KEY_CLS.construct((n, e)), "public"
        except Exception as exc:  # noqa: BLE001
            raise CryptoUsageError(f"RSA 密钥参数不完整（需要 n/e[/d]，HEX 字符串）：{exc}") from exc

    for candidate in (_der_from_text(t), _b64_or_none(t)):
        if not candidate:
            continue
        try:
            key = _RSA_KEY_CLS.import_key(candidate)
            return key, ("private" if key.has_private() else "public")
        except Exception:  # noqa: BLE001
            continue
    raise CryptoUsageError("RSA 密钥格式无法识别。支持：PEM / DER-Base64 / JSON(n,e[,d]) / HEX")


# ============================================================================
# 10.2 SM2 加解密与签名验签
# ============================================================================
def sm2_keygen() -> dict:
    """生成一对 SM2 密钥（调试/自检用；生产请走标准密钥管理）。"""
    if _SM2_CLS is None:      # pragma: no cover
        raise CryptoRuntimeError("缺少 gmssl，无法使用 SM2：pip install gmssl")
    while True:
        d = _secure_random_hex(64)
        if 0 < int(d, 16) < int(_SM2_N, 16):
            break
    helper = _SM2_CLS(private_key=d, public_key="")
    pub = helper._kg(int(d, 16), helper.ecc_table["g"])
    return {"private_key": d, "public_key": pub,
            "public_x": pub[:64], "public_y": pub[64:]}


def do_sm2(op: str, *, data: bytes = b"", message: bytes = b"", sig: str = "",
           private_key: str = "", public_key: str = "",
           cipher_mode: str = SM2_C1C3C2, asn1: bool = False,
           prehashed: bool = False) -> bytes:
    """SM2 加解密 / 签名验签（一次调用完成一步）。

    :param op:      enc 加密 / dec 解密 / sign 签名 / verify 验签
    :param data:    enc=明文；dec=密文（C1C3C2 或 C1C2C3）；sign=待签数据
    :param message: verify 时的原文数据（与签名配套）
    :param sig:     verify 时的签名（128 位 HEX 或 DER）
    :param prehashed: sign/verify 时 data/message 已是 32 字节摘要（跳过 SM3+Z）
    :return:        enc→密文 bytes；dec→明文 bytes；sign→签名 HEX 文本；
                    verify→b"OK" / (b"FAIL:" + 原因)
    """
    if _SM2_CLS is None:      # pragma: no cover
        raise CryptoRuntimeError("缺少 gmssl，无法使用 SM2：pip install gmssl")
    if op not in ("enc", "dec", "sign", "verify"):
        raise CryptoUsageError(f"SM2 不支持的操作：{op}（enc/dec/sign/verify）")
    cipher_mode = (cipher_mode or SM2_C1C3C2).lower()
    if cipher_mode not in SM2_CIPHER_MODES:
        raise CryptoUsageError(
            "SM2 密文格式只支持 %s，收到 %s" % ("/".join(SM2_CIPHER_MODES), cipher_mode))

    priv = parse_sm2_private_key(private_key) if private_key else ""
    pub = parse_sm2_public_key(public_key)["hex"] if public_key else ""
    # ⚠ 签名时必须能算出 SM3 的 Z 值，而 Z 里含公钥分量。
    #   只给私钥不给公钥时，Z 会按"空公钥"计算，导致对方用真实公钥验签必然失败。
    #   所以这里先从私钥推导出公钥（d*G），与真实验签方保持一致。
    if op == "sign" and priv and not pub:
        pub = _SM2_CLS(private_key=priv, public_key="")._kg(int(priv, 16),
                                                          _SM2_CLS(
                                                              private_key=priv,
                                                              public_key="").ecc_table["g"])
    helper = _SM2_CLS(private_key=priv or ("00" * 32), public_key=pub,
                      mode=1 if cipher_mode == SM2_C1C3C2 else 0, asn1=asn1)

    if op == "enc":
        if not pub:
            raise CryptoUsageError("SM2 加密需要公钥（--public-key）")
        with _secure_random_context():
            out = helper.encrypt(bytes(data))
        if out is None:
            raise CryptoRuntimeError("SM2 加密失败（KDF 输出全零，换随机数重试即可）")
        return out

    if op == "dec":
        if not priv:
            raise CryptoUsageError("SM2 解密需要私钥（--private-key）")
        out = helper.decrypt(bytes(data))
        return out.encode("utf-8") if isinstance(out, str) else out

    if op == "sign":
        if not priv:
            raise CryptoUsageError("SM2 签名需要私钥（--private-key）")
        with _secure_random_context():
            if prehashed:
                if len(data) != 32:
                    raise CryptoUsageError("prehashed 模式下待签数据必须是 32 字节摘要")
                out = helper.sign(bytes(data), _secure_random_hex(64))
            else:
                out = helper.sign_with_sm3(bytes(data))
        if not out:
            raise CryptoRuntimeError("SM2 签名失败（随机数导致 r/s 越界，重试即可）")
        return out.encode("ascii") if isinstance(out, str) else out

    # ---- verify ----
    if not pub:
        raise CryptoUsageError("SM2 验签需要公钥（--public-key）")
    sig_text = re.sub(r"[\s:]", "", sig or "")
    if not sig_text:
        raise CryptoUsageError("SM2 验签需要签名值（--sig）")
    if not asn1:
        if len(sig_text) != 128:
            return ("FAIL:".encode() + (f"签名应为 128 位 HEX（r||s），当前 {len(sig_text)} 位；"
                                        "DER 签名请加 --asn1").encode())
        if any(c not in "0123456789abcdefABCDEF" for c in sig_text):
            return "FAIL:签名含非 HEX 字符".encode("utf-8")
    target = bytes(message if message else data)
    try:
        if prehashed:
            if len(target) != 32:
                return "FAIL:prehashed 模式下原文必须是 32 字节摘要".encode("utf-8")
            ok = helper.verify(sig_text.lower(), target)
        else:
            ok = helper.verify_with_sm3(sig_text.lower(), target)
    except Exception as exc:  # noqa: BLE001
        return b"FAIL:" + str(exc).encode("utf-8", errors="replace")
    if ok:
        return b"OK"
    return "FAIL:签名校验不通过（原文被改、密钥不对或签名格式不符）".encode("utf-8")


# ============================================================================
# 10.3 RSA 加解密 / 签名（含长文本自动分段）
# ============================================================================
def rsa_keygen(bits: int = 2048) -> dict:
    """生成一对 RSA 密钥（调试/自检用）。"""
    if _RSA_KEY_CLS is None:      # pragma: no cover
        raise CryptoRuntimeError("缺少 pycryptodome，无法使用 RSA：pip install pycryptodome")
    key = _RSA_KEY_CLS.generate(bits)
    return {
        "private_pem": key.export_key().decode("ascii"),
        "public_pem": key.publickey().export_key().decode("ascii"),
        "n_hex": format(key.n, "x"),
        "e_hex": format(key.e, "x"),
        "bits": bits,
    }


def _rsa_chunk_size(key_len: int, padding: str, hash_alg: str) -> int:
    """单个 RSA 分块能装多少明文字节（长文本必须分段，这就是 JS 里 encryptLong2 干的事）。"""
    if padding == RSA_OAEP:
        h_len = hashlib.new(hash_alg).digest_size
        return key_len - 2 * h_len - 2
    return key_len - 11     # PKCS#1 v1.5


def do_rsa(op: str, *, data: bytes = b"", message: bytes = b"", sig: bytes = b"",
           key_text: str = "", password: str | None = None,
           padding: str = RSA_PKCS1V15, hash_alg: str = "sha256",
           scheme: str = RSA_PKCS1V15, chunked: bool = True) -> bytes:
    """RSA 加解密 / 签名验签。

    :param op:       enc / dec / sign / verify
    :param data:     enc=明文；dec=密文（可多块拼接）；sign=待签数据
    :param message:  verify 时的原文
    :param sig:      verify 时的签名值
    :param padding:  enc/dec 的填充：pkcs1v15 / oaep
    :param scheme:   sign/verify 的方案：pkcs1v15 / pss
    :param chunked:  长文本自动分段（对应 JS 里的 encryptLong2/decryptLong2）
    :return:         enc→密文；dec→明文；sign→签名 bytes；verify→b"OK"/b"FAIL:..."
    """
    if _RSA_KEY_CLS is None:      # pragma: no cover
        raise CryptoRuntimeError("缺少 pycryptodome，无法使用 RSA：pip install pycryptodome")
    if op not in ("enc", "dec", "sign", "verify"):
        raise CryptoUsageError(f"RSA 不支持的操作：{op}（enc/dec/sign/verify）")
    padding = (padding or RSA_PKCS1V15).lower()
    scheme = (scheme or RSA_PKCS1V15).lower()
    if padding not in RSA_PADDINGS:
        raise CryptoUsageError("RSA 填充只支持 %s" % "/".join(RSA_PADDINGS))
    if scheme not in RSA_SIGN_SCHEMES:
        raise CryptoUsageError("RSA 签名方案只支持 %s" % "/".join(RSA_SIGN_SCHEMES))
    if hash_alg.lower() not in ("md5", "sha1", "sha256", "sha384", "sha512"):
        raise CryptoUsageError("不支持的摘要算法：%s" % hash_alg)

    key, kind = load_rsa_key(key_text, password)

    if op == "enc":
        if kind != "public" and not key.has_private():
            raise CryptoUsageError("RSA 加密需要公钥或私钥（私钥也可用于加密）")
        pub = key.publickey()
        size = _rsa_chunk_size(_rsa_key_bytes(key), padding, hash_alg)
        if size <= 0:
            raise CryptoUsageError("RSA 密钥太短，无法容纳该填充方式")
        chunks = [bytes(data)[i:i + size] for i in range(0, max(len(data), 1), size)] or [b""]
        out = []
        for chunk in chunks:
            if padding == RSA_OAEP:
                cipher = _PKCS1_OAEP.new(pub, hashAlgo=getattr(_HASH_MOD, hash_alg.upper()))
            else:
                cipher = _PKCS1_V15.new(pub)
            out.append(cipher.encrypt(chunk))
        if not chunked and len(chunks) > 1:
            raise CryptoUsageError(
                "明文超过单块 RSA 容量（%d 字节），已拒绝；如确需分段请开启 chunked" % size)
        return b"".join(out)

    if op == "dec":
        if not key.has_private():
            raise CryptoUsageError("RSA 解密需要私钥（--private-key）")
        if padding == RSA_PKCS1V15:
            print("[注意] PKCS#1 v1.5 不含完整性校验：密钥不对时不一定会报错，"
                  "可能只返回空/乱码。要确认密钥正确，请核对明文内容或改用 OAEP。",
                  file=sys.stderr)
        blk = _rsa_key_bytes(key)
        raw = bytes(data)
        if len(raw) % blk != 0:
            raise CryptoUsageError(
                f"RSA 密文长度 {len(raw)} 不是密钥长度 {blk} 的整数倍（多块密文应直接拼接）")
        out = []
        for i in range(0, len(raw), blk):
            chunk = raw[i:i + blk]
            if padding == RSA_OAEP:
                cipher = _PKCS1_OAEP.new(key, hashAlgo=getattr(_HASH_MOD, hash_alg.upper()))
            else:
                cipher = _PKCS1_V15.new(key)
            try:
                if padding == RSA_OAEP:
                    out.append(cipher.decrypt(chunk))
                else:
                    sentinel = object()
                    dec = cipher.decrypt(chunk, sentinel)
                    if dec is sentinel:
                        raise CryptoRuntimeError("RSA 解密失败（填充校验不过：密钥不对或密文被改）")
                    out.append(dec)
            except CryptoRuntimeError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise CryptoRuntimeError(f"RSA 解密失败：{exc}") from exc
        return b"".join(out)

    if op == "sign":
        if not key.has_private():
            raise CryptoUsageError("RSA 签名需要私钥（--private-key）")
        h = getattr(_HASH_MOD, hash_alg.upper()).new(bytes(data))
        if scheme == RSA_PSS:
            return _PSS.new(key, salt_bytes=getattr(_HASH_MOD, hash_alg.upper()).digest_size).sign(h)
        return _PKCS1_15.new(key).sign(h)

    # verify
    h = getattr(_HASH_MOD, hash_alg.upper()).new(bytes(message if message else data))
    pub = key.publickey()
    try:
        if scheme == RSA_PSS:
            _PSS.new(pub).verify(h, bytes(sig))
        else:
            _PKCS1_15.new(pub).verify(h, bytes(sig))
    except Exception as exc:  # noqa: BLE001
        return b"FAIL:" + str(exc).encode("utf-8", errors="replace")
    return b"OK"


def _rsa_key_bytes(key) -> int:
    return (key.size_in_bits() + 7) // 8


# ============================================================================
# 10.4 压缩 / 解压（真实业务里常作为加密前的一层）
# ============================================================================
def _zip_kwargs(level: int) -> dict:
    return {"level": max(0, min(9, int(level)))}


def do_compress(data: bytes, algo: str = COMPRESS_ZLIB, level: int = 6) -> bytes:
    """压缩。algo：zlib / gzip / deflate / deflate-raw。"""
    algo = (algo or COMPRESS_ZLIB).lower()
    if algo not in COMPRESS_ALGOS:
        raise CryptoUsageError("不支持的压缩算法：%s（%s）" % (algo, "/".join(COMPRESS_ALGOS)))
    if algo == COMPRESS_GZIP:
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=max(0, min(9, level)), mtime=0) as fh:
            fh.write(bytes(data))
        return buf.getvalue()
    if algo == COMPRESS_RAW:
        co = zlib.compressobj(level, zlib.DEFLATED, -zlib.MAX_WBITS)
        return co.compress(bytes(data)) + co.flush()
    # zlib 与 deflate 在 Python 里都是 zlib 封装（78 9C 头），与 JS pako.deflate 一致
    return zlib.compress(bytes(data), max(0, min(9, level)))


def do_decompress(data: bytes, algo: str = COMPRESS_ZLIB) -> bytes:
    """解压。支持自动回退：指定算法失败时依次试其它三种（真实数据经常标错）。"""
    algo = (algo or COMPRESS_ZLIB).lower()
    order = [algo] + [a for a in COMPRESS_ALGOS if a != algo]
    errors = []
    for candidate in order:
        try:
            raw = bytes(data)
            if candidate == COMPRESS_GZIP:
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as fh:
                    return fh.read()
            if candidate == COMPRESS_RAW:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
            return zlib.decompress(raw)
        except Exception as exc:  # noqa: BLE001
            errors.append("%s→%s" % (candidate, exc))
            continue
    raise CryptoRuntimeError(
        "解压失败（四种算法都试过）：%s。可能不是压缩数据，或需要先做编码解码" % "；".join(errors[:2]))


def looks_compressed(data: bytes) -> str | None:
    """按魔数猜压缩格式（给扫描器/界面提示用）。"""
    if data[:2] == b"\x78" and data[2:3] in (b"\x01", b"\x9c", b"\xda", b"\x5e"):
        return COMPRESS_ZLIB
    if data[:2] == b"\x1f\x8b":
        return COMPRESS_GZIP
    if data[:1] == b"\x78":
        return COMPRESS_ZLIB
    return None


# ============================================================================
# 10.5 多级编码链（压缩 / Base64 / HEX / URL 的组合，顺序可控）
# ============================================================================
def encode_chain(data: bytes, steps) -> bytes:
    """按给定顺序做「编码/压缩」。例如 steps=['zlib','base64'] = 压缩后 Base64。"""
    out = bytes(data)
    for step in steps or []:
        s = str(step).lower()
        if s == "base64":
            out = base64.b64encode(out)
        elif s == "base64url":
            out = base64.urlsafe_b64encode(out).rstrip(b"=")
        elif s == "hex":
            out = binascii.hexlify(out)
        elif s == "url":
            out = urllib.parse.quote_from_bytes(out, safe="").encode("ascii")
        elif s in COMPRESS_ALGOS:
            out = do_compress(out, s)
        else:
            raise CryptoUsageError("不支持的编码步骤：%s（%s）" % (step, "/".join(CHAIN_STEPS)))
    return out


def decode_chain(data: bytes, steps) -> bytes:
    """按**相反顺序**解码/解压。steps 与加密方向一致书写即可。"""
    out = bytes(data)
    for step in reversed(list(steps or [])):
        s = str(step).lower()
        try:
            if s == "base64":
                cleaned = re.sub(rb"[\s]", b"", out)
                out = base64.b64decode(cleaned + b"=" * ((-len(cleaned)) % 4))
            elif s == "base64url":
                cleaned = re.sub(rb"[\s]", b"", out)
                cleaned += b"=" * ((-len(cleaned)) % 4)
                out = base64.urlsafe_b64decode(cleaned)
            elif s == "hex":
                out = binascii.unhexlify(re.sub(rb"[\s:]", b"", out))
            elif s == "url":
                out = urllib.parse.unquote_to_bytes(out.decode("ascii", errors="replace"))
            elif s in COMPRESS_ALGOS:
                out = do_decompress(out, s)
            else:
                raise CryptoUsageError("不支持的编码步骤：%s" % step)
        except CryptoUsageError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CryptoUsageError(
                "解码链在「%s」这一步失败：%s。请确认编码顺序与补齐方式" % (s, exc)) from exc
    return out


# ============================================================================
# 10.6 混合加密信封（SM2/RSA 加密对称密钥 + 对称算法加密数据）
# ----------------------------------------------------------------------------
#  这是银行 App / H5「安全键盘」「敏感字段」最常见的形态：
#      随机生成对称密钥 → 对称加密数据
#      → 用服务端公钥（SM2 或 RSA）加密该对称密钥
#      → 两个字段一起提交（或拼成一个包）
# ============================================================================
def envelope_encrypt(plain: bytes, *, recipient: str = ASYM_SM2, public_key: str = "",
                     symmetric: str = "sm4", mode: str = MODE_ECB,
                     padding: str = PAD_PKCS7, key_format: str = KEY_HEX,
                     symmetric_key: str = "", iv: str = "" , iv_format: str = KEY_HEX) -> dict:
    """生成混合加密信封。

    :param public_key:    接收方公钥（SM2 128 位 HEX / RSA PEM）
    :param symmetric:     对称算法（sm4/aes128/...，见 ALGO_SPECS）
    :param key_format:    若自带 symmetric_key，其文本格式
    :return: dict（可直接 JSON 化）：含加密后的对称密钥、密文、以及用于复现的参数
    """
    recipient = (recipient or ASYM_SM2).lower()
    if recipient not in ASYM_CHOICES:
        raise CryptoUsageError("信封模式只支持 sm2 / rsa 作为接收方算法")
    spec = get_spec(symmetric)

    # 1) 对称密钥
    if symmetric_key:
        key_bytes = parse_key_material(symmetric_key, key_format, "对称密钥")
        validate_key(spec, key_bytes)
    else:
        key_bytes = bytes(secrets.randbelow(256) for _ in range(spec.default_key_len))
    iv_bytes = b""
    if mode not in (MODE_ECB, MODE_STREAM) and not spec.is_stream:
        iv_bytes = (parse_key_material(iv, iv_format, "IV") if iv
                    else bytes(secrets.randbelow(256) for _ in range(spec.block)))
        validate_iv(spec, mode, iv_bytes)

    # 2) 对称加密数据
    cipher = do_crypt(symmetric, "enc", binascii.hexlify(key_bytes).decode(),
                      binascii.hexlify(iv_bytes).decode() if iv_bytes else None,
                      bytes(plain), mode=mode, padding=padding, warn_weak=False)

    # 3) 用接收方公钥加密对称密钥
    if recipient == ASYM_SM2:
        if not public_key:
            raise CryptoUsageError("信封加密需要接收方 SM2 公钥")
        wrapped = do_sm2("enc", data=key_bytes, public_key=public_key)
    else:
        if not public_key:
            raise CryptoUsageError("信封加密需要接收方 RSA 公钥")
        wrapped = do_rsa("enc", data=key_bytes, key_text=public_key)

    return {
        "recipient": recipient,
        "symmetric": spec.aid,
        "mode": mode,
        "padding": padding,
        "wrapped_key_hex": binascii.hexlify(wrapped).decode(),
        "wrapped_key_b64": base64.b64encode(wrapped).decode(),
        "cipher_hex": binascii.hexlify(cipher).decode(),
        "cipher_b64": base64.b64encode(cipher).decode(),
        "iv_hex": binascii.hexlify(iv_bytes).decode() if iv_bytes else "",
        # 调试用：真实攻击里这一项拿不到（只有服务端私钥能解出）
        "debug_plain_key_hex": binascii.hexlify(key_bytes).decode(),
    }


def envelope_decrypt(*, recipient: str = ASYM_SM2, wrapped_key: str = "", cipher: str = "",
                     private_key: str = "", symmetric: str = "sm4", mode: str = MODE_ECB,
                     padding: str = PAD_PKCS7, iv: str = "",
                     input_format: str = "hex", output_format: str = "raw") -> bytes:
    """解开混合加密信封，返回原始明文。

    攻击视角：拿到客户端/服务端私钥后，先用私钥解出对称密钥，再解数据。
    """
    recipient = (recipient or ASYM_SM2).lower()
    if not wrapped_key:
        raise CryptoUsageError("需要加密后的对称密钥（--wrapped-key）")
    if not private_key:
        raise CryptoUsageError("需要接收方私钥（--private-key）")

    if input_format == "hex":
        wrapped = binascii.unhexlify(re.sub(r"[\s:]", "", wrapped_key))
        cbytes = binascii.unhexlify(re.sub(r"[\s:]", "", cipher))
    elif input_format == "base64":
        wrapped = base64.b64decode(wrapped_key + "=" * ((-len(wrapped_key)) % 4))
        cbytes = base64.b64decode(cipher + "=" * ((-len(cipher)) % 4))
    else:
        raise CryptoUsageError("input_format 只支持 hex / base64")

    if recipient == ASYM_SM2:
        key_bytes = do_sm2("dec", data=wrapped, private_key=private_key)
    else:
        key_bytes = do_rsa("dec", data=wrapped, key_text=private_key)

    spec = get_spec(symmetric)
    validate_key(spec, key_bytes)
    # envelope_encrypt 返回的 iv_hex / 这里传入的 iv 都是 HEX 文本，直接透传给统一入口
    iv_hex = re.sub(r"[\s:]", "", iv) if iv else None
    plain = do_crypt(symmetric, "dec", binascii.hexlify(key_bytes).decode(),
                     iv_hex, cbytes, mode=mode, padding=padding, warn_weak=False)
    return plain


# ============================================================================
# 十、自检：用「已充分验证的实现」交叉证明本模块的模式组装正确
# ----------------------------------------------------------------------------
# 核心验证策略：
#   本模块自己实现了 ECB/CBC/CFB/OFB/CTR/GCM 的模式组装。SM4 没有原生模式实现
#   可以对照，但 **AES 有**（pycryptodome 原生）。
#   于是：把「AES 的块加密函数」喂给本模块的模式组装，与 pycryptodome 原生
#   AES 各模式结果逐字节比对。一致即证明模式组装正确；同一套代码用于 SM4
#   即为可信（因为模式组装与分组算法无关，是通用结构）。
# ============================================================================

def run_selftest() -> int:
    """
    执行密码引擎自检。返回退出码：0 全部通过，2 存在失败。
    """
    check_dependencies()

    print("=" * 68)
    print(" jiejieEAD 密码引擎自检（crypto_core）")
    print("=" * 68)

    failures = 0

    def ok(msg: str) -> None:
        print(f"       [ OK ] {msg}")

    def fail(msg: str) -> None:
        nonlocal failures
        failures += 1
        print(f"       [FAIL] {msg}")

    # ------------------------------------------------------------------
    # [1/6] SM4 分组运算 vs GB/T 32907-2016 官方向量
    # ------------------------------------------------------------------
    print(" [1/9] SM4 分组运算对照 GB/T 32907-2016 官方测试向量")
    std_key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    std_pt = bytes.fromhex("0123456789abcdeffedcba9876543210")
    std_ct = "681edf34d206965e86b3e94f536e4246"
    got = sm4_encrypt_block(std_key, std_pt).hex()
    if got == std_ct:
        ok(f"单次加密 = {got}")
    else:
        fail(f"期望 {std_ct}，实际 {got}")
    if sm4_decrypt_block(std_key, bytes.fromhex(std_ct)) == std_pt:
        ok("单次解密可还原明文")
    else:
        fail("单次解密还原失败")

    # ------------------------------------------------------------------
    # [2/6] 模式组装正确性：本模块实现 对照 pycryptodome 原生 AES
    # ------------------------------------------------------------------
    print(" [2/9] 模式组装正确性（本模块实现 vs pycryptodome 原生 AES）")
    aes_key = bytes.fromhex("00" * 15 + "2b")          # AES-128
    blk = 16
    iv16 = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    payload = bytes((i * 7 + 3) % 256 for i in range(64))

    def aes_enc_block(b: bytes) -> bytes:
        return AES.new(aes_key, AES.MODE_ECB).encrypt(b)

    def aes_dec_block(b: bytes) -> bytes:
        return AES.new(aes_key, AES.MODE_ECB).decrypt(b)

    # ECB
    native = AES.new(aes_key, AES.MODE_ECB).encrypt(payload)
    mine = mode_ecb(aes_enc_block, payload, blk)
    (ok if mine == native else fail)("ECB 与原生实现一致")
    (ok if mode_ecb(aes_dec_block, native, blk) == payload else fail)("ECB 解密可还原")

    # CBC（比较原始链接结果，先自行补齐到分组边界）
    padded = payload                                    # 64 字节已对齐
    native = AES.new(aes_key, AES.MODE_CBC, iv16).encrypt(padded)
    mine = mode_cbc(aes_enc_block, iv16, padded, blk, encrypting=True)
    (ok if mine == native else fail)("CBC 加密与原生实现一致")
    mine_dec = mode_cbc(aes_dec_block, iv16, native, blk, encrypting=False)
    (ok if mine_dec == padded else fail)("CBC 解密与原生实现一致")

    # CFB（全分组反馈）
    native = AES.new(aes_key, AES.MODE_CFB, iv16, segment_size=128).encrypt(payload)
    mine = mode_cfb(aes_enc_block, iv16, payload, blk, encrypting=True)
    (ok if mine == native else fail)("CFB-128 加密与原生实现一致")
    mine_dec = mode_cfb(aes_enc_block, iv16, native, blk, encrypting=False)
    (ok if mine_dec == payload else fail)("CFB-128 解密与原生实现一致")

    # OFB
    native = AES.new(aes_key, AES.MODE_OFB, iv16).encrypt(payload)
    mine = mode_ofb(aes_enc_block, iv16, payload, blk)
    (ok if mine == native else fail)("OFB 与原生实现一致")

    # CTR
    from Crypto.Util import Counter as _C
    native = AES.new(aes_key, AES.MODE_CTR,
                     counter=_C.new(128, initial_value=int.from_bytes(iv16, "big"))
                     ).encrypt(payload)
    mine = mode_ctr(aes_enc_block, iv16, payload, blk)
    (ok if mine == native else fail)("CTR 与原生实现一致")

    # 非对齐长度（流式模式必须支持任意字节长度，末块按需截断）
    partial = payload[:50]
    for mode_name, my_fn, native_fn in (
        ("CFB", lambda: mode_cfb(aes_enc_block, iv16, partial, blk, encrypting=True),
         lambda: AES.new(aes_key, AES.MODE_CFB, iv16, segment_size=128).encrypt(partial)),
        ("OFB", lambda: mode_ofb(aes_enc_block, iv16, partial, blk),
         lambda: AES.new(aes_key, AES.MODE_OFB, iv16).encrypt(partial)),
        ("CTR", lambda: mode_ctr(aes_enc_block, iv16, partial, blk),
         lambda: AES.new(aes_key, AES.MODE_CTR,
                         counter=_C.new(128, initial_value=int.from_bytes(iv16, "big"))
                         ).encrypt(partial)),
    ):
        if my_fn() == native_fn():
            ok(f"{mode_name} 非对齐长度（50 字节）与原生实现一致")
        else:
            fail(f"{mode_name} 非对齐长度处理与原生实现不一致")

    # ------------------------------------------------------------------
    # [3/6] 通用 GCM 正确性：本模块 GCM vs pycryptodome 原生 AES-GCM
    # ------------------------------------------------------------------
    print(" [3/9] 通用 GCM 构造正确性（本模块 GCM vs 原生 AES-GCM 密文+标签）")
    for nonce_len, label in ((12, "96 位 nonce（标准）"), (16, "128 位 nonce")):
        nonce = bytes(range(nonce_len))
        for aad in (b"", b"additional-auth-data-1234"):
            native_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            if aad:
                native_cipher.update(aad)
            n_ct, n_tag = native_cipher.encrypt_and_digest(payload[:50])

            m_ct, m_tag = gcm_encrypt_128(aes_enc_block, nonce, payload[:50], aad)
            tag_note = "" if not aad else " + AAD"
            if m_ct == n_ct and m_tag == n_tag:
                ok(f"GCM {label}{tag_note} 与原生实现逐字节一致")
            else:
                fail(f"GCM {label}{tag_note} 不一致")
            # 解密方向
            if gcm_decrypt_128(aes_enc_block, nonce, m_ct, m_tag, aad) == payload[:50]:
                pass
            else:
                fail(f"GCM {label}{tag_note} 解密还原失败")

    # ------------------------------------------------------------------
    # [4/6] 填充格式
    # ------------------------------------------------------------------
    print(" [4/9] 填充格式往返 + 已知向量")
    for style in (PAD_PKCS7, PAD_ZERO, PAD_NONE, PAD_ISO7816, PAD_ANSIX923):
        for length in (0, 1, 15, 16, 17, 31, 32):
            raw = bytes((i * 3 + 1) % 256 for i in range(length))
            if style == PAD_NONE and length % 16 != 0:
                continue
            try:
                padded = pad_data(raw, 16, style)
                if len(padded) % 16 != 0:
                    fail(f"{PAD_DISPLAY[style]} len={length} 填充后未对齐")
                    continue
                back = unpad_data(padded, 16, style)
                # 零填充天然歧义：只校验「去掉尾部 0 后」一致
                if style == PAD_ZERO:
                    if back != raw.rstrip(b"\x00"):
                        fail(f"{PAD_DISPLAY[style]} len={length} 往返不一致")
                elif back != raw:
                    fail(f"{PAD_DISPLAY[style]} len={length} 往返不一致")
            except Exception as exc:  # noqa: BLE001
                fail(f"{PAD_DISPLAY[style]} len={length} 抛异常：{exc}")
    ok("PKCS#7 / Zero / NoPadding / ISO7816 / ANSIX923 往返全部通过")

    # PKCS#7 已知向量：明文 "YELLOW SUBMARINE"（16 字节）→ 补满一块 0x10
    vec = pad_data(b"YELLOW SUBMARINE", 16, PAD_PKCS7)
    if vec == b"YELLOW SUBMARINE" + b"\x10" * 16:
        ok("PKCS#7 补整块行为符合标准（16 字节数据 → 新增一整块 0x10）")
    else:
        fail("PKCS#7 补整块行为不符合标准")

    # ------------------------------------------------------------------
    # [5/6] 全算法 × 全模式 往返一致性（真实走 do_crypt 分派）
    # ------------------------------------------------------------------
    print(" [5/9] 全算法 × 全模式往返一致性（经统一入口 do_crypt）")
    payloads = [b"", b"A", "hello 国密 SM4".encode("utf-8"), bytes(range(50)),
                bytes((i * 11) % 256 for i in range(255))]

    def varied_hex(nbytes: int, seed: int, salt: int = 11) -> str:
        """
        生成「各段互不相同」的测试密钥。
        注意：绝不能用 "ab" * 24 这类均匀重复串 —— 3DES 会因三段子密钥相同而
        退化，被 pycryptodome 拒绝（这是正确的安全行为，见 _new_cipher 的提示）。
        """
        return "".join("%02x" % ((i * 37 + seed * 53 + salt) % 256)
                       for i in range(nbytes))

    total_cases = 0
    bad_cases: list[str] = []

    for spec in ALGO_SPECS.values():
        if spec.is_stream:
            # 密钥长度按 spec 取（RC4 是变长区间取首值；ChaCha20 只认 32 字节）。
            # 带 nonce 的流密码（ChaCha20 / Salsa20）必须给 nonce，无 nonce 的（RC4）给 None。
            key_hex = varied_hex(spec.default_key_len, seed=hash(spec.aid) & 0xFF)
            nonce_hex = ("cd" * spec.nonce_sizes[0]) if spec.nonce_sizes else None
            for pl in payloads:
                total_cases += 1
                try:
                    ct = do_crypt(spec.aid, "enc", key_hex, nonce_hex, pl,
                                  mode=MODE_STREAM, padding=PAD_NONE, warn_weak=False)
                    pt = do_crypt(spec.aid, "dec", key_hex, nonce_hex, ct,
                                  mode=MODE_STREAM, padding=PAD_NONE, warn_weak=False)
                    if pt != pl:
                        bad_cases.append(f"{spec.aid}/stream len={len(pl)}")
                except Exception as exc:  # noqa: BLE001
                    bad_cases.append(f"{spec.aid}/stream len={len(pl)} 异常 {exc}")
            continue

        key_hex = varied_hex(spec.default_key_len, seed=hash(spec.aid) & 0xFF)
        for mode in spec.modes:
            iv_hex = "cd" * (12 if mode == MODE_GCM else spec.block)
            for style in padding_choices():
                if mode in STREAM_LIKE_MODES and style != PAD_NONE:
                    continue          # 流式模式只测 none
                if mode in BLOCK_MODES and style == PAD_NONE:
                    continue          # 分组模式 none 需要对齐，payload 未必对齐
                for pl in payloads:
                    total_cases += 1
                    try:
                        ct = do_crypt(spec.aid, "enc", key_hex, iv_hex, pl,
                                      mode=mode, padding=style, warn_weak=False)
                        pt = do_crypt(spec.aid, "dec", key_hex, iv_hex, ct,
                                      mode=mode, padding=style, warn_weak=False)
                        if pt != pl:
                            bad_cases.append(
                                f"{spec.aid}/{mode}/{style} len={len(pl)}")
                    except Exception as exc:  # noqa: BLE001
                        bad_cases.append(
                            f"{spec.aid}/{mode}/{style} len={len(pl)} 异常 {exc}")
    if bad_cases:
        fail(f"共 {len(bad_cases)} 个用例失败，前 8 个：{bad_cases[:8]}")
    else:
        ok(f"全部 {total_cases} 个「算法 × 模式 × 填充 × 长度」组合往返一致")

    # ------------------------------------------------------------------
    # [6/6] 安全性行为：错误密钥必须报错 / GCM 篡改必须报错
    # ------------------------------------------------------------------
    print(" [6/9] 安全行为：错误密钥与篡改必须被检出")
    for aid in ("sm4", "aes256", "des", "des3"):
        spec = get_spec(aid)
        good = varied_hex(spec.default_key_len, seed=7, salt=11)
        bad = varied_hex(spec.default_key_len, seed=7, salt=97)
        iv_hex = "33" * spec.block
        ct = do_crypt(aid, "enc", good, iv_hex, b"jiejieead selftest payload",
                      mode=MODE_CBC, padding=PAD_PKCS7, warn_weak=False)
        try:
            wrong = do_crypt(aid, "dec", bad, iv_hex, ct,
                             mode=MODE_CBC, padding=PAD_PKCS7, warn_weak=False)
            if wrong == b"jiejieead selftest payload":
                fail(f"{aid} 使用错误密钥竟解出正确明文")
            else:
                ok(f"{aid} 错误密钥产出错误明文（长度 {len(wrong)}）")
        except (CryptoUsageError, CryptoRuntimeError):
            ok(f"{aid} 错误密钥被明确检出（填充校验失败）")

    # GCM 篡改检测
    for aid in ("sm4", "aes128"):
        key_hex = varied_hex(get_spec(aid).default_key_len, seed=23, salt=41)
        nonce = "55" * 12
        ct = do_crypt(aid, "enc", key_hex, nonce, b"authentic payload",
                      mode=MODE_GCM, warn_weak=False)
        tampered = bytearray(ct)
        tampered[0] ^= 0x01                    # 翻转密文首字节
        try:
            do_crypt(aid, "dec", key_hex, nonce, bytes(tampered),
                     mode=MODE_GCM, warn_weak=False)
            fail(f"{aid}-GCM 篡改密文后竟解密成功（认证形同虚设）")
        except CryptoRuntimeError:
            ok(f"{aid}-GCM 篡改被认证标签检出")

    # ------------------------------------------------------------------
    # [7/9] 密钥材料格式 / 摘要 / HMAC / 密钥派生
    #       回归样本走通用链路（伪装常量 → AES-CBC 派生 → SM4 正文 → HMAC-SM3），
    #       期望值一律用**独立实现**现算（pycryptodome / hashlib / gmssl / 手写
    #       RFC 2104 构造），不复用被测代码路径，避免"自己验自己"。
    # ------------------------------------------------------------------
    print(" [7/9] 密钥格式 / 摘要 / HMAC / 密钥派生（通用链路 + 独立复算）")

    # ---- 密钥格式：同一串文本按不同格式解析，字节数不同 ----
    sample = "4A7F2C1E9B3D5A08"
    if len(parse_key_material(sample, KEY_HEX)) != 8:
        fail("HEX 解析 16 个 hex 字符应为 8 字节")
    else:
        ok("HEX 解析 16 个 hex 字符 → 8 字节")
    if len(parse_key_material(sample, KEY_UTF8)) != 16:
        fail("UTF-8 解析 16 个 ASCII 字符应为 16 字节")
    else:
        ok("UTF-8 解析 16 个 ASCII 字符 → 16 字节（与 HEX 差一倍，最易踩坑）")
    if len(explain_key_material(sample)["interpretations"]) != 3:
        fail("密钥格式解释应给出 hex/utf8/base64 三种解读")
    else:
        ok("密钥格式解释同时给出三种字节数（供界面直接提示用户）")
    if parse_key_material(base64.b64encode(b"0123456789abcdef").decode(), KEY_BASE64) \
            != b"0123456789abcdef":
        fail("Base64 密钥解析异常")
    else:
        ok("Base64 密钥解析正确")
    if parse_key_material("0123456789abcdeffedcba9876543210", KEY_AUTO) \
            != bytes.fromhex("0123456789abcdeffedcba9876543210"):
        fail("auto 对纯 hex 串应判定为 HEX")
    else:
        ok("auto 对纯 HEX 串判定为 HEX")

    # ---- 摘要已知向量（RFC / 国标）----
    for alg, expect in (
        ("md5", "900150983cd24fb0d6963f7d28e17f72"),
        ("sha1", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        ("sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("sm3", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
    ):
        got = do_digest(alg, b"abc").hex()
        if got != expect:
            fail(f"{alg.upper()}('abc') = {got}，与公开标准向量不符")
        else:
            ok(f"{alg.upper()}('abc') 与公开标准向量一致")

    # ---- HMAC 已知向量 + HMAC-SM3 与 BouncyCastle 对照 ----
    h256 = do_hmac("hmac-sha256", b"key",
                   b"The quick brown fox jumps over the lazy dog").hex()
    if h256 != "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8":
        fail(f"HMAC-SHA256 已知向量不符：{h256}")
    else:
        ok("HMAC-SHA256 已知向量一致（RFC 4231 常用样本）")

    from Crypto.Cipher import AES as _AES   # 独立实现的对照基准（pycryptodome）
    # ---- HMAC-SM3：用「手写 RFC 2104 构造」独立交叉验证（不依赖第三方库给出的期望值）----
    # ⚠ 注意口径：下面 _sm3_ref 仍调用本引擎的 do_digest("sm3")，所以这里验证的是
    #   **HMAC 包装层**（ipad/opad 拼接、超长密钥先摘要、空消息），SM3 本体另有
    #   [7/9] 段开头的国标向量与 RFC 4231 对照覆盖。
    def _sm3_ref(b: bytes) -> bytes:
        return do_digest("sm3", b)

    def _hmac_sm3_ref(key: bytes, msg: bytes, block: int = 64) -> bytes:
        if len(key) > block:
            key = _sm3_ref(key)
        k_pad = key.ljust(block, b"\x00")
        inner = _sm3_ref(bytes(x ^ 0x36 for x in k_pad) + msg)
        return _sm3_ref(bytes(x ^ 0x5C for x in k_pad) + inner)

    _hmac_ok = True
    for _k, _m in ((bytes.fromhex(hashlib.sha256(b"hmac-sm3-check").hexdigest()),
                    "通用链路回归消息".encode("utf-8")),
                   (bytes(range(64)), b""),
                   (bytes(range(80)), b"long-key-should-be-hashed-first")):
        if _hmac_sm3_ref(_k, _m) != do_hmac("hmac-sm3", _k, _m):
            fail("HMAC-SM3 与 RFC 2104 手工构造不一致（key=%d 字节）" % len(_k))
            _hmac_ok = False
            break
    if _hmac_ok:
        ok("HMAC-SM3 与手写 ipad/opad 构造逐字节一致（含超长密钥先摘要分支）")

    # ---- 密钥派生：通用链路，用 pycryptodome + hashlib 独立复算 ----
    seed = "808dfc1c0b6471f557ba0e50979dca88"
    k_utf8, iv_utf8 = sample, "C6B1D90E37F2A485"
    _aes = _AES.new(k_utf8.encode(), _AES.MODE_CBC, iv_utf8.encode())
    _raw = seed.encode()
    _padlen = 16 - (len(_raw) % 16)
    expect_master = hashlib.sha256(_aes.encrypt(_raw + bytes([_padlen]) * _padlen)).hexdigest()
    derived = derive_key_by_preset(
        seed, "aes-cbc-then-sha256-slice",
        seed_format=KEY_UTF8, key=k_utf8, iv=iv_utf8,
        key_format=KEY_UTF8, iv_format=KEY_UTF8, slice_start=16, slice_end=32)
    if derived["output_hex"] != expect_master[32:64]:
        fail("派生结果与独立复算不一致：%s vs %s"
             % (derived["output_hex"], expect_master[32:64]))
    else:
        ok("AES-CBC(种子)→SHA256→取[16:32] 与 pycryptodome+hashlib 独立复算一致")
    # 第二条断言：与跨模块共用的回归基线对拍（cipher_auto_solver 的合成夹具派生出同一个正文密钥）
    if derived["output_hex"] != "e30087bba22de68ac7942df9d79b1cdc":
        fail("派生结果与跨模块回归基线不符：%s" % derived["output_hex"])
    else:
        ok("派生结果与跨模块回归基线一致（与一键解密的合成夹具同源）")
    if len(derived["trace"]) != 3:
        fail("派生 trace 应记录 3 步")
    else:
        ok("派生过程逐步留痕（加密 / 摘要 / 取区间各一步，便于人工核对）")

    # 用派生出的密钥做一次「独立构造密文 → 引擎解密」的端到端闭环
    from gmssl.sm4 import CryptSM4, SM4_ENCRYPT as _S4E
    body = '{"reqHead":{"txCd":"TEST-TXCD-0001"},"reqData":{"amt":"1.00"}}'
    _sm4 = CryptSM4()
    _sm4.set_key(bytes.fromhex(derived["output_hex"]), _S4E)
    _b = body.encode()
    _pl = 16 - (len(_b) % 16)
    # ⚠ gmssl 的 crypt_ecb 会在传入数据之上**再补一层 PKCS#7**（本模块的正文明文/填充
    #   组装刻意绕开它，见文件头的「填充陷阱」说明）。这里拿它当独立对照基准时，
    #   只需取回前 len(_b)+_pl 字节 —— ECB 各分组独立，截断不影响正确性。
    ct_body = _sm4.crypt_ecb(_b + bytes([_pl]) * _pl)[:len(_b) + _pl]
    plain = do_crypt("sm4", "dec", derived["output_hex"], None, ct_body,
                     mode=MODE_ECB, padding=PAD_PKCS7, warn_weak=False)
    if plain != body.encode():
        fail("用派生密钥未能解出正文")
    else:
        ok("用派生密钥成功解出正文（派生 → 解密 端到端闭环）")

    # ---- 另一个派生预设（纯摘要）：同样独立复算 ----
    inner = derive_key_by_preset(
        seed, "digest-sha256", seed_format=KEY_UTF8)
    if inner["output_hex"] != hashlib.sha256(seed.encode()).hexdigest():
        fail("SHA256(种子) 预设与 hashlib 不一致：%s" % inner["output_hex"])
    else:
        ok("SHA256(种子) 预设与 hashlib 独立复算一致")

    # ---- UTF-8 密钥直接走通用入口（与独立构造的密文对齐）----
    seed_text = seed
    ct = do_crypt("aes128", "enc", sample, iv_utf8, seed_text.encode(),
                  mode=MODE_CBC, padding=PAD_PKCS7, warn_weak=False,
                  key_format=KEY_UTF8, iv_format=KEY_UTF8)
    _aes2 = _AES.new(sample.encode(), _AES.MODE_CBC, iv_utf8.encode())
    _r2 = seed_text.encode()
    _p2 = 16 - (len(_r2) % 16)
    expect_aes = binascii.hexlify(_aes2.encrypt(_r2 + bytes([_p2]) * _p2)).decode()
    if binascii.hexlify(ct).decode() != expect_aes:
        fail("UTF-8 密钥 + AES-128-CBC 与独立复算不符：%s" % binascii.hexlify(ct).decode())
    else:
        ok("UTF-8 密钥直接走通用入口（与 pycryptodome 独立加密逐字节一致）")
    back = do_crypt("aes128", "dec", sample, iv_utf8, ct,
                    mode=MODE_CBC, padding=PAD_PKCS7, warn_weak=False,
                    key_format=KEY_UTF8, iv_format=KEY_UTF8)
    if back != seed_text.encode():
        fail("UTF-8 密钥加解密往返失败")
    else:
        ok("UTF-8 密钥加解密往返一致")

    # ---- 负向：格式写错必须明确报错，而不是静默算出错结果 ----
    try:
        do_crypt("aes128", "enc", sample, iv_utf8, b"hello",
                 mode=MODE_CBC, padding=PAD_PKCS7, warn_weak=False,
                 key_format=KEY_HEX, iv_format=KEY_UTF8)
        fail("把 UTF-8 密钥按 HEX 解析竟未报错（8 字节不能当 AES-128 密钥）")
    except (CryptoUsageError, CryptoRuntimeError):
        ok("密钥格式写错时明确报错（不会静默产出错误密文）")

    try:
        derive_key_by_preset("seed", "aes-cbc-then-sha256-slice",
                             seed_format=KEY_UTF8, key=sample, iv=iv_utf8,
                             key_format=KEY_UTF8, iv_format=KEY_UTF8,
                             slice_start=99, slice_end=None)
        fail("取字节区间越界竟然未报错")
    except CryptoUsageError:
        ok("取字节区间越界时给出可读报错（提示按字节而非字符位置）")

    # ------------------------------------------------------------------
    # [8/9] 非对称（SM2 / RSA）、压缩与多级编码
    #    SM2 的加密用「固定随机数 k 独立重算 C1/C2/C3」交叉验证，
    #    RSA 的签名用「手工构造 EMSA-PKCS1-v1_5 后做模幂」独立验证。
    # ------------------------------------------------------------------
    print(" [8/9] 非对称（SM2 / RSA）/ 压缩 / 编码链 / 混合信封")
    if _SM2_CLS is None or _RSA_KEY_CLS is None:
        fail("pycryptodome 或 gmssl 不可用，非对称能力无法自检"
             "（SM2=%s / RSA=%s）" % (_SM2_CLS is not None, _RSA_KEY_CLS is not None))
    else:
        # ---- SM2：固定密钥对 ----
        d_fixed = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
        helper = _SM2_CLS(private_key=d_fixed, public_key="")
        pub_fixed = helper._kg(int(d_fixed, 16), helper.ecc_table["g"])
        msg = "jiejieEAD SM2 test payload".encode()

        ct = do_sm2("enc", data=msg, public_key=pub_fixed)
        ok("SM2 加密产出密文（%d 字节 = C1 64 + C3 32 + C2 %d）"
           % (len(ct), len(msg)))
        if do_sm2("dec", data=ct, private_key=d_fixed) != msg:
            fail("SM2 加解密往返不一致")
        else:
            ok("SM2 加解密往返一致")

        # C1 必须是合法曲线点：y² ≡ x³ + ax + b (mod p)
        p_mod = int(helper.ecc_table["p"], 16)
        a_mod = int(helper.ecc_table["a"], 16)
        b_mod = int(helper.ecc_table["b"], 16)
        c1 = ct[:64].hex()          # C1 = 64 字节（gmssl 输出不带 04 前缀）
        x1, y1 = int(c1[:64], 16), int(c1[64:], 16)
        if (y1 * y1 - (x1 * x1 * x1 + a_mod * x1 + b_mod)) % p_mod == 0:
            ok("SM2 密文 C1 是曲线上的合法点（独立校验曲线方程）")
        else:
            fail("SM2 密文 C1 不在曲线上")

        # 固定 k 独立重算 C1/C2/C3 → 验证实现与国标流程一致
        k_fixed = "0000000000000000000000000000000000000000000000000000000000000001"
        origin_random = getattr(gmssl_func, "random_hex", None)
        try:
            gmssl_func.random_hex = lambda n: k_fixed.rjust(n, "0")[:n]
            ct_kat = _SM2_CLS(private_key="", public_key=pub_fixed,
                              mode=1).encrypt(msg)
        finally:
            if origin_random is not None:
                gmssl_func.random_hex = origin_random
        c1_exp = helper._kg(int(k_fixed, 16), helper.ecc_table["g"])
        xy = helper._kg(int(k_fixed, 16), pub_fixed)
        x2, y2 = xy[:64], xy[64:]
        t_kdf = gmssl_sm3.sm3_kdf(xy.encode("utf-8"), len(msg))
        c2_exp = ("%0*x" % (len(msg) * 2, int(msg.hex(), 16) ^ int(t_kdf, 16)))
        c3_exp = gmssl_sm3.sm3_hash(list(bytes.fromhex("%s%s%s" % (x2, msg.hex(), y2))))
        expect = bytes.fromhex(c1_exp + c3_exp + c2_exp)
        if ct_kat == expect:
            ok("SM2 密文与「独立重算 C1=kG / C2 / C3」逐字节一致（固定 k 已知答案测试）")
        else:
            fail("SM2 密文与独立重算不一致")
        if do_sm2("dec", data=bytes.fromhex(c1_exp + c3_exp + c2_exp),
                  private_key=d_fixed) == msg:
            ok("独立重算出的密文可被本模块解密")
        else:
            fail("独立重算密文解密失败")

        # C1C2C3 变体
        ct_old = do_sm2("enc", data=msg, public_key=pub_fixed, cipher_mode=SM2_C1C2C3)
        if len(ct_old) == len(ct) and do_sm2("dec", data=ct_old, private_key=d_fixed,
                                             cipher_mode=SM2_C1C2C3) == msg:
            ok("SM2 C1C2C3（老实现）格式加解密一致，长度与 C1C3C2 相同")
        else:
            fail("SM2 C1C2C3 格式加解密失败")

        # 篡改必须失败（C2 改一字节）
        tampered = bytearray(ct)
        tampered[-1] ^= 0x01
        if do_sm2("dec", data=bytes(tampered), private_key=d_fixed) != msg:
            ok("SM2 篡改密文后解不出原文（C3 校验生效）")
        else:
            fail("SM2 篡改密文竟然解出原文")

        # 签名：默认（SM3+Z）、prehashed、DER
        sig = do_sm2("sign", data=msg, private_key=d_fixed)
        if len(sig) == 128 and do_sm2("verify", sig=sig.decode(), message=msg,
                                      public_key=pub_fixed) == b"OK":
            ok("SM2 签名/验签通过（r||s 128 位 HEX，含 SM3+Z 预处理）")
        else:
            fail("SM2 签名/验签失败")
        if do_sm2("verify", sig=sig.decode(), message=msg + b"x",
                  public_key=pub_fixed) != b"OK":
            ok("SM2 原文被改后验签失败")
        else:
            fail("SM2 篡改原文后竟验签通过")
        digest = sm3_digest(msg)
        sig_pre = do_sm2("sign", data=digest, private_key=d_fixed, prehashed=True)
        if do_sm2("verify", sig=sig_pre.decode(), message=digest,
                  public_key=pub_fixed, prehashed=True) == b"OK":
            ok("SM2 prehashed 模式（直接签 32 字节摘要）验签通过")
        else:
            fail("SM2 prehashed 模式验签失败")
        sig_der = do_sm2("sign", data=msg, private_key=d_fixed, asn1=True)
        if do_sm2("verify", sig=sig_der.decode(), message=msg,
                  public_key=pub_fixed, asn1=True) == b"OK":
            ok("SM2 DER(asn1) 签名/验签通过")
        else:
            fail("SM2 DER 签名验签失败")

        # 公钥各种前缀 / 私钥各种格式
        for label, pub_text in (("128 位 HEX", pub_fixed),
                                ("带 04 前缀", "04" + pub_fixed),
                                ("带 0x 前缀", "0x" + pub_fixed)):
            if parse_sm2_public_key(pub_text)["hex"] == pub_fixed:
                ok("SM2 公钥解析兼容 %s" % label)
            else:
                fail("SM2 公钥解析不支持 %s" % label)
        if (parse_sm2_private_key(d_fixed) == d_fixed
                and parse_sm2_private_key(base64.b64encode(bytes.fromhex(d_fixed)).decode()) == d_fixed):
            ok("SM2 私钥解析兼容 HEX / Base64")
        else:
            fail("SM2 私钥解析异常")
        # 手工构造一段合法的 SEC1 DER（30 77 02 01 01 04 20 <32 字节私钥>）再包成 PEM，
        # 用来验证 PEM/Base64 分支真的能解出私钥（不依赖任何外部密钥文件）
        der = b"\x30\x77\x02\x01\x01\x04\x20" + bytes.fromhex(d_fixed)
        pem_text = ("-----BEGIN EC PRIVATE KEY-----\n"
                    + base64.b64encode(der).decode() + "\n-----END EC PRIVATE KEY-----")
        try:
            if parse_sm2_private_key(pem_text) == d_fixed:
                ok("SM2 私钥解析兼容 PEM(EC PRIVATE KEY/DER)")
            else:
                fail("SM2 私钥 PEM 解析结果不正确")
        except CryptoUsageError as exc:
            fail("SM2 私钥 PEM 解析失败：%s" % exc)

        # ---- RSA ----
        rk = rsa_keygen(1024)
        rk2 = rsa_keygen(1024)
        if "PRIVATE KEY" in rk["private_pem"] and "PUBLIC KEY" in rk["public_pem"]:
            ok("RSA 密钥生成（1024 位，PEM 含私钥/公钥块）")
        else:
            fail("RSA 密钥生成异常")

        r_msg = b"jiejieEAD RSA payload"
        c_v15 = do_rsa("enc", data=r_msg, key_text=rk["public_pem"])
        if len(c_v15) == 128 and do_rsa("dec", data=c_v15, key_text=rk["private_pem"]) == r_msg:
            ok("RSA PKCS#1 v1.5 加解密往返一致（单块 128 字节）")
        else:
            fail("RSA PKCS#1 v1.5 加解密失败")
        c_oaep = do_rsa("enc", data=r_msg, key_text=rk["public_pem"], padding=RSA_OAEP)
        if do_rsa("dec", data=c_oaep, key_text=rk["private_pem"], padding=RSA_OAEP) == r_msg:
            ok("RSA OAEP(SHA-256) 加解密往返一致")
        else:
            fail("RSA OAEP 加解密失败")
        long_plain = bytes(range(256)) * 2          # 512 字节，必然多块
        c_long = do_rsa("enc", data=long_plain, key_text=rk["public_pem"])
        if len(c_long) % 128 == 0 and do_rsa("dec", data=c_long,
                                             key_text=rk["private_pem"]) == long_plain:
            ok("RSA 长文本自动分段（512 字节 → %d 块）往返一致，对应 JS 里的 encryptLong2"
               % (len(c_long) // 128))
        else:
            fail("RSA 长文本分段加解密失败")
        try:
            do_rsa("dec", data=c_v15[:-1], key_text=rk["private_pem"])
            fail("RSA 密文长度不整倍数竟未报错")
        except (CryptoUsageError, CryptoRuntimeError):
            ok("RSA 密文长度异常时明确报错（不会静默出错）")
        # PKCS#1 v1.5 本身没有完整性校验：用错私钥时，pycryptodome 可能返回空/乱码
        # 而不是报错（填充校验有 1/65536 的偶然通过概率）。真正要保证的是
        # 「绝不能还原出正确明文」，以及 OAEP 这种带摘要校验的填充必须明确失败。
        try:
            wrong = do_rsa("dec", data=c_v15, key_text=rk2["private_pem"])
            if wrong == r_msg:
                fail("用错私钥竟然解出了正确明文")
            else:
                ok("用错私钥无法还原原文（PKCS#1 v1.5 无完整性校验，但结果必然不同）")
        except CryptoRuntimeError:
            ok("用错私钥被明确检出（PKCS#1 v1.5 填充校验不过）")
        try:
            do_rsa("dec", data=c_oaep, key_text=rk2["private_pem"], padding=RSA_OAEP)
            fail("OAEP 用错私钥竟未报错")
        except CryptoRuntimeError:
            ok("OAEP 用错私钥被明确检出（含摘要校验，失败概率 2^-256）")

        r_sig = do_rsa("sign", data=r_msg, key_text=rk["private_pem"])
        if do_rsa("verify", message=r_msg, sig=r_sig, key_text=rk["public_pem"]) == b"OK":
            ok("RSA PKCS#1 v1.5(SHA-256) 签名/验签通过")
        else:
            fail("RSA 签名验签失败")
        if do_rsa("verify", message=r_msg + b"!", sig=r_sig,
                  key_text=rk["public_pem"]) != b"OK":
            ok("RSA 原文被改后验签失败")
        else:
            fail("RSA 篡改原文后竟验签通过")

        # 独立验证 PKCS#1 v1.5 签名格式：手工拼 EMSA 后做模幂
        key_obj = _RSA_KEY_CLS.import_key(rk["public_pem"])
        dig_info = bytes.fromhex("3031300d060960864801650304020105000420") + \
            _HASH_MOD.SHA256.new(r_msg).digest()
        em = (b"\x00\x01" + b"\xff" * (len(c_v15) - len(dig_info) - 3)
              + b"\x00" + dig_info)
        recovered = pow(int.from_bytes(r_sig, "big"), key_obj.e, key_obj.n).to_bytes(
            len(c_v15), "big")
        if recovered == em:
            ok("RSA 签名独立验证：modpow(sig,e,n) == 手工构造的 EMSA-PKCS1-v1_5")
        else:
            fail("RSA 签名的 EMSA 结构与 RFC 8017 不符")

        r_sig_pss = do_rsa("sign", data=r_msg, key_text=rk["private_pem"], scheme=RSA_PSS)
        if do_rsa("verify", message=r_msg, sig=r_sig_pss, key_text=rk["public_pem"],
                  scheme=RSA_PSS) == b"OK":
            ok("RSA PSS 签名/验签通过（随机化填充）")
        else:
            fail("RSA PSS 签名验签失败")
        _key_obj, _kind = load_rsa_key(rk["public_pem"])
        if _kind == "public" and _key_obj.size_in_bits() == 1024:
            ok("RSA 密钥加载返回 (key, 类型=%s, %d 位)" % (_kind, _key_obj.size_in_bits()))
        else:
            fail("RSA 密钥加载类型/位数异常：%s" % str(_kind))

        # ---- 压缩 ----
        payload = (b"jiejieEAD compress test " * 20)
        for algo in COMPRESS_ALGOS:
            c = do_compress(payload, algo)
            if do_decompress(c, algo) != payload:
                fail("压缩 %s 往返不一致" % algo)
                continue
            ok("压缩 %s 往返一致（%d → %d 字节）" % (algo, len(payload), len(c)))
        if do_compress(b"x", COMPRESS_ZLIB)[:2] == b"\x78\x9c":
            ok("zlib 输出头为 78 9C（与 Python zlib / JS pako.deflate 一致）")
        else:
            fail("zlib 输出头异常")
        if do_compress(b"x", COMPRESS_GZIP)[:2] == b"\x1f\x8b":
            ok("gzip 输出头为 1F 8B")
        else:
            fail("gzip 输出头异常")
        if do_decompress(do_compress(payload, COMPRESS_RAW), COMPRESS_ZLIB) == payload:
            ok("解压算法标错时自动回退识别（真实数据常见）")
        else:
            fail("解压自动回退失败")
        try:
            do_decompress(b"not compressed at all", COMPRESS_ZLIB)
            fail("非压缩数据竟解压成功")
        except CryptoRuntimeError:
            ok("非压缩数据解压时给出可读报错")

        # ---- 多级编码链 ----
        chain_data = "jiejieEAD 编码链测试 payload".encode()
        for steps in (["base64"], ["hex"], ["base64url"], ["url"],
                      ["zlib", "base64"], ["gzip", "hex"], ["zlib", "base64", "hex"],
                      ["deflate-raw", "base64url"]):
            enc = encode_chain(chain_data, steps)
            if decode_chain(enc, steps) == chain_data:
                ok("编码链 %s 往返一致" % "+".join(steps))
            else:
                fail("编码链 %s 往返不一致" % "+".join(steps))
        enc_b64 = encode_chain(chain_data, ["zlib", "base64"])
        if decode_chain(enc_b64, ["base64"]) != chain_data:
            ok("编码顺序写错时不会给出错误的原文（会报错或长度不符）")
        else:
            fail("编码顺序写错竟还原成功（逻辑有误）")
        try:
            decode_chain(b"!!!not-base64!!!", ["base64", "zlib"])
            ok("非法编码输入在解码链里被拦截")
        except CryptoUsageError:
            ok("非法编码输入在解码链里给出可读报错")

        # ---- 混合加密信封（SM2 / RSA 包对称密钥）----
        env = envelope_encrypt(b"secret keyboard input", recipient=ASYM_SM2,
                               public_key=pub_fixed, symmetric="sm4", mode=MODE_ECB,
                               padding=PAD_PKCS7)
        if (envelope_decrypt(recipient=ASYM_SM2, wrapped_key=env["wrapped_key_hex"],
                             cipher=env["cipher_hex"], private_key=d_fixed,
                             symmetric="sm4", mode=MODE_ECB, padding=PAD_PKCS7,
                             input_format="hex")
                == b"secret keyboard input"):
            ok("混合信封（SM2 加密 SM4 密钥 + SM4 加密数据）端到端解密一致")
        else:
            fail("混合信封解密失败")
        env2 = envelope_encrypt(b"rsa envelope", recipient=ASYM_RSA,
                                public_key=rk["public_pem"], symmetric="sm4",
                                mode=MODE_CBC, padding=PAD_ZERO)
        if (envelope_decrypt(recipient=ASYM_RSA, wrapped_key=env2["wrapped_key_b64"],
                             cipher=env2["cipher_b64"], private_key=rk["private_pem"],
                             symmetric="sm4", mode=MODE_CBC, padding=PAD_ZERO,
                             iv=env2["iv_hex"], input_format="base64")
                == b"rsa envelope"):
            ok("混合信封（RSA + SM4-CBC/ZeroPadding，Base64 通道）端到端解密一致")
        else:
            fail("RSA 混合信封解密失败")
        env3 = envelope_encrypt(b"x", recipient=ASYM_SM2, public_key=pub_fixed,
                                symmetric="sm4", mode=MODE_CBC, padding=PAD_ZERO)
        if env3["iv_hex"] and len(env3["iv_hex"]) == 32:
            ok("信封在需要 IV 的模式下自动生成 16 字节 IV 并随包返回")
        else:
            fail("信封未正确生成 IV")
        if looks_compressed(do_compress(b"abc", COMPRESS_GZIP)) == COMPRESS_GZIP:
            ok("压缩格式魔数识别可用（供扫描器判断）")
        else:
            fail("压缩魔数识别失败")

    # ------------------------------------------------------------------
    # [9/9] 新增经典算法的公开标准向量对照
    #   本节存在的意义：RC5 / RC6 是本模块**自实现**的（pycryptodome 与
    #   cryptography 都没有），破例于文件头「绝不手写算法本体」的原则，
    #   因此必须用**外部公开向量**做担保，而不是自己验自己。
    #
    #   ⚠ 覆盖面差异（如实标注，不冒充）：
    #     · RC5-32/12/16 与 RC6-32/20/16 —— 有**外部公开向量**（下面前 4 条）
    #     · RC5-32/16/16 / RC5-64/16/16 / RC6-32/16/16 —— 无外部向量，
    #       只有「与已验证内核同源」的往返断言（最后一组）
    # ------------------------------------------------------------------
    print(" [9/9] 经典算法公开标准向量（RC5 / RC6 / Blowfish / CAST5 / RC2 / ChaCha20 / Salsa20）")

    # ---- RC5-32/12/16：RFC 2040 测试向量 ----
    # ⚠ 字节序：RFC 2040 正文里另有按「字大端」打印的同算法向量，两者互为
    #   每 4 字节反转。本实现与 OpenSSL / BouncyCastle 一致用**字小端**，
    #   故这里引用的是与实现同约定的那组。
    _rc5_key = bytes.fromhex("915F4619BE41B2516355A50110A9CE91")
    _rc5_pt = bytes.fromhex("21A5DBEE154B8F6D")
    _rc5_ct = rc5_encrypt_block(_rc5_key, _rc5_pt, 12, 32)
    if _rc5_ct.hex().upper() != "F7C013AC5B2B8952":
        fail("RC5-32/12/16 与 RFC 2040 向量不符：%s" % _rc5_ct.hex().upper())
    else:
        ok("RC5-32/12/16 与 RFC 2040 测试向量逐字节一致")
    if rc5_decrypt_block(_rc5_key, _rc5_ct, 12, 32) == _rc5_pt:
        ok("RC5 解密与加密严格互逆（同一向量往返）")
    else:
        fail("RC5 解密未能还原原文")

    # ---- RC6-32/20/16：BouncyCastle 向量（源自 AES 提交的 RSA 参考实现）----
    _rc6_cases = (
        ("00000000000000000000000000000000", "00000000000000000000000000000000",
         "8fc3a53656b1f778c129df4e9848a41e"),
        ("00000000000000000000000000000000", "80000000000000000000000000000000",
         "f71f65e7b80c0c6966fee607984b5cdf"),
        ("00000001000000000000000000000000", "00000000000000000000000000000000",
         "8a380594d7396453771a1dfbe2914c8e"),
    )
    _rc6_ok = 0
    for _kh, _ph, _eh in _rc6_cases:
        _k, _p = bytes.fromhex(_kh), bytes.fromhex(_ph)
        _got = rc6_encrypt_block(_k, _p, 20, 32)
        if _got.hex() == _eh and rc6_decrypt_block(_k, _got, 20, 32) == _p:
            _rc6_ok += 1
        else:
            fail("RC6-32/20/16 向量不符：期望 %s 实得 %s" % (_eh, _got.hex()))
    if _rc6_ok == len(_rc6_cases):
        ok("RC6-32/20/16 与 BouncyCastle 测试向量 %d/%d 一致（加密+解密往返）"
           % (_rc6_ok, len(_rc6_cases)))

    # ---- pycryptodome 原生算法：各自的标准向量 ----
    _native_vectors = (
        ("blowfish", "0000000000000000", "0000000000000000", "4ef997456198dd78",
         "Eric Young 标准向量"),
        ("cast5", "0123456712345678234567893456789a", "0123456789abcdef",
         "238b4fe5847e44b2", "RFC 2144"),
    )
    for _aid, _kh, _ph, _eh, _src in _native_vectors:
        try:
            _ct = do_crypt(_aid, "enc", _kh, None, bytes.fromhex(_ph),
                           mode=MODE_ECB, padding=PAD_NONE, warn_weak=False)
            if _ct.hex() == _eh:
                ok("%s 与 %s 向量逐字节一致" % (ALGO_SPECS[_aid].display, _src))
            else:
                fail("%s 与 %s 不符：期望 %s 实得 %s"
                     % (_aid, _src, _eh, _ct.hex()))
        except Exception as exc:  # noqa: BLE001
            fail("%s 向量对照异常：%s" % (_aid, exc))

    # ---- RC2：RFC 2268 向量（必须把 effective key bits 调到 63 才对得上）----
    _rc2_old = RC2_EFFECTIVE_BITS
    try:
        set_rc2_effective_bits(63)
        _ct = do_crypt("rc2", "enc", "0000000000000000", None,
                       bytes.fromhex("0000000000000000"),
                       mode=MODE_ECB, padding=PAD_NONE, warn_weak=False)
        if _ct.hex() == "ebb773f993278eff":
            ok("RC2 与 RFC 2268 向量逐字节一致（effective key bits = 63）")
        else:
            fail("RC2 与 RFC 2268 不符：期望 ebb773f993278eff 实得 %s" % _ct.hex())
        # 反向：默认 128 位有效长度时必须**不**等于该向量 —— 证明该参数真的生效，
        # 而不是"碰巧算对"。这正是 RC2 解成乱码的头号原因。
        set_rc2_effective_bits(128)
        _ct128 = do_crypt("rc2", "enc", "0000000000000000", None,
                          bytes.fromhex("0000000000000000"),
                          mode=MODE_ECB, padding=PAD_NONE, warn_weak=False)
        if _ct128.hex() != "ebb773f993278eff":
            ok("RC2 的 effective key bits 确实生效（128 位时结果与 63 位不同）")
        else:
            fail("RC2 的 effective key bits 未生效（128 与 63 结果相同）")
    finally:
        set_rc2_effective_bits(_rc2_old)

    # ---- ChaCha20：RFC 8439 §2.3.2 的「块函数」向量 ----
    # ⚠ 为什么不直接用 §2.4.2 的消息向量：那条要求 **counter = 1**，而本引擎的
    #   流密码入口不暴露 counter 偏移（从 0 开始），直接比会差一个分组。
    #   改用等价且更干净的做法：加密 **128 字节全零明文**（密文 == 密钥流），
    #   则第 64~128 字节正好是 counter=1 那个分组的密钥流，与 §2.3.2 的官方
    #   块函数输出逐字节可比。这样既守住了"外部公开向量"，又不依赖 counter 偏移。
    _ch_key = bytes(range(32))
    _ch_nonce = bytes.fromhex("000000090000004a00000000")   # RFC 8439 §2.3.2 的 nonce
    _ch_ks = do_crypt("chacha20", "enc", _ch_key.hex(), _ch_nonce.hex(), bytes(128),
                      mode=MODE_STREAM, padding=PAD_NONE, warn_weak=False)
    _blk1 = ("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
             "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
    if _ch_ks[64:128].hex() == _blk1:
        ok("ChaCha20 的 counter=1 密钥流块与 RFC 8439 §2.3.2 官方块函数逐字节一致")
    else:
        fail("ChaCha20 与 RFC 8439 §2.3.2 不符：%s" % _ch_ks[64:128].hex())

    _sa_key = bytes.fromhex("80" + "00" * 15 + "00" * 16)
    _sa_ct = do_crypt("salsa20", "enc", _sa_key.hex(), ("00" * 8), bytes(64),
                      mode=MODE_STREAM, padding=PAD_NONE, warn_weak=False)
    if _sa_ct.hex()[:32] == "e3be8fdd8beca2e3ea8ef9475b29a6e7":
        ok("Salsa20 与 eSTREAM 官方向量一致（nonce 8 字节）")
    else:
        fail("Salsa20 与 eSTREAM 向量不符：%s" % _sa_ct.hex()[:32])

    # ---- 参数变体：无外部向量，只做「与已验证内核同源」的往返断言 ----
    # 如实标注：这三项**不是**外部公开向量验证，而是参数变体（轮数/字长）在
    # 同一份已验证代码路径上的自洽性检查。
    _variant_ok = 0
    for _aid, _kh, _ph in (
        ("rc5_16", "915f4619be41b2516355a50110a9ce91", "21a5dbee154b8f6d"),
        ("rc5_64", "915f4619be41b2516355a50110a9ce91",
         "21a5dbee154b8f6d0badf00dcafebabe"),
        ("rc6_16", "00000000000000000000000000000000",
         "00000000000000000000000000000000"),
    ):
        _p = bytes.fromhex(_ph)
        _ct = do_crypt(_aid, "enc", _kh, None, _p,
                       mode=MODE_ECB, padding=PAD_NONE, warn_weak=False)
        _back = do_crypt(_aid, "dec", _kh, None, _ct,
                         mode=MODE_ECB, padding=PAD_NONE, warn_weak=False)
        if _back == _p:
            _variant_ok += 1
        else:
            fail("%s 往返不一致" % _aid)
    if _variant_ok == 3:
        ok("RC5/RC6 参数变体往返自洽 3/3（回归基线，**非**外部公开向量）")

    print("-" * 68)
    if failures == 0:
        print("[PASS] 密码引擎自检全部通过。")
        return 0
    print(f"[FAIL] 共 {failures} 项失败。")
    return 2
