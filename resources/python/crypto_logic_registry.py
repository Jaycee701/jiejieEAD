#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jiejieEAD | 加密逻辑登记表（加解密逻辑总览 · 可查 · 可试算）
================================================================================

解决的问题：这套工具里的加解密能力散在十来个模块里（引擎、CLI、自动求解器、
材料分析器、知识库、MITM……），用的时候要"想起它在哪"。本模块把**全部逻辑**
集中登记到一处，做到：

  ① 一眼可见 —— 分类清单 + 每条逻辑的「用途 / 适用场景 / 参数 / 与其他逻辑的关系」；
  ② 清晰可查 —— 支持按分类、按关键词筛选；支持"贴一段密文 → 按特征反推该试哪些逻辑"；
  ③ 可试算   —— 支持直接对密文/明文按指定逻辑执行加解密（不用切到别的 Tab 拼参数）；
  ④ 可导出   —— `--export-md` 导出一份文档章节，保证文档与代码同步、不会写歪。

三段式数据：

  LOGICS       原子逻辑：算法 / 模式 / 填充 / 密钥格式 / 派生 / 摘要 / HMAC / 编码 /
               压缩 / 编码链 / 非对称 / 信封 / 报文框架 / 材料来源
  COMPOSITES   组合配方：端到端可执行的"一整套逻辑"（对应 18 个样本 + 常见组合）
  FEATURE_RULES 密文特征规则：看到什么特征 → 优先试哪些逻辑（反查表）

用法：
  python crypto_logic_registry.py --list                     # 全部逻辑
  python crypto_logic_registry.py --list --cat algo          # 只看法定算法
  python crypto_logic_registry.py --list --q 国密 --json
  python crypto_logic_registry.py --features                 # 密文特征规则表
  python crypto_logic_registry.py --match --text "<密文>"     # 反向匹配：该试哪些逻辑
  python crypto_logic_registry.py --apply algo.sm4 --text "明文" --key 00112233... --op enc
  python crypto_logic_registry.py --export-md --out <文件>
  python crypto_logic_registry.py --selftest

设计原则（与工具其它部分一致）：
  · 只登记**工具真的能做到**的事；做不到的单列 `gap` 分类，并写清缺什么；
  · 每条逻辑都带 CLI 复现命令，看到结论就能手工跑一遍；
  · 本模块不预置任何目标的密钥，只描述"逻辑形状"，密钥永远由使用者提供。
"""
from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import crypto_core as cc  # noqa: E402

# ============================================================================
# 分类
# ============================================================================
CATEGORIES: list[tuple[str, str, str]] = [
    ("algo",      "分组 / 流算法",   "对谁加密的第一层：选哪个算法"),
    ("mode",      "工作模式",        "同一个算法怎么用；模式选错密文必错"),
    ("padding",   "填充方式",        "分组模式的收尾规则；老系统爱用 ZeroPadding"),
    ("keyfmt",    "密钥文本格式",    "同一串字符按 HEX / UTF-8 / Base64 解释，字节数完全不同"),
    ("kdf",       "密钥派生（KDF）", "密钥不是常量而是算出来的（白盒前端最常见）"),
    ("keysrc",    "密钥来源与材料挖掘", "密钥藏在哪儿：伪装常量 / 字面量 / 切片 / 派生链 / 私钥"),
    ("digest",    "摘要",            "不加密，只做一次性哈希"),
    ("hmac",      "HMAC / 完整性",   "带密钥的摘要，通常当报文 mac / sign 用"),
    ("encoding",  "编码",            "base64 / hex / url … 不是加密，但必须在解密前还原"),
    ("compress",  "压缩",            "加密前先压缩很常见；解错顺序一定还原不出明文"),
    ("chain",     "多级编码链",      "套娃编码：顺序即语义，解码要倒着来"),
    ("asym",      "非对称（SM2 / RSA）", "公钥加密 + 私钥解密，或签名验签"),
    ("envelope",  "混合信封",        "非对称包对称密钥 + 对称加密数据（国内 App 最主流）"),
    ("frame",     "报文框架识别",    "先认形状：HTTP / 裸编码 / URL / 种子前置 / JSON 信封"),
    ("composite", "端到端组合配方",  "把上面几层串成一条完整链路（就是 18 个样本的逻辑）"),
    ("feature",   "密文特征 → 推荐", "反查表：看到这个特征，优先试哪几条"),
    ("gap",       "未支持 / 需人工",	"工具目前做不到的，写清缺什么、该怎么补"),
    ("user",      "用户添加",        "你从分析结果里沉淀下来的逻辑（可编辑、可删除，落盘在 crypto_logic_user.json）"),
]

CATEGORY_DISPLAY = {cid: name for cid, name, _ in CATEGORIES}
CATEGORY_HINT = {cid: hint for cid, _, hint in CATEGORIES}

# 支持状态
S = "supported"      # 工具完整支持
P = "partial"        # 部分支持 / 有条件
N = "unsupported"    # 未支持


def _L(lid, cat, name, purpose, scene, params=None, rel=None, status=S,
       cli="", sample="", exec_kind=""):
    """登记一条逻辑。"""
    return {
        "id": lid, "cat": cat, "name": name,
        "purpose": purpose, "scene": scene,
        "params": params or {}, "rel": rel or [],
        "status": status, "cli": cli, "sample": sample, "exec_kind": exec_kind,
    }


# ============================================================================
# 一、原子逻辑
# ============================================================================
LOGICS: list[dict] = [

    # ---------------- algo ----------------
    _L("algo.sm4", "algo", "SM4（国密分组）",
       "中国商用分组密码标准（GB/T 32907），分组 128 位、密钥固定 128 位。",
       "金融 / 政务 / 国密 App / 小程序；国内 App 的默认选择，出现频率最高。",
       {"key_bits": [128], "block_bits": 128,
        "modes": ["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"]},
       ["mode.*", "padding.*", "chain.*", "hmac.hmac-sm3", "asym.sm2"]),
    _L("algo.aes128", "algo", "AES-128",
       "AES 分组密码，128 位密钥（16 字节）。",
       "国际通用；老系统 / 原生 App / Node 默认分段最常见。",
       {"key_bits": [128], "block_bits": 128,
        "modes": ["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"]},
       ["mode.*", "padding.*", "chain.*", "hmac.hmac-sha256"]),
    _L("algo.aes192", "algo", "AES-192",
       "AES 分组密码，192 位密钥（24 字节）。",
       "较少见；遇到 24 字节密钥时优先怀疑它（3DES 也是 24 字节，两者要靠长度+模式区分）。",
       {"key_bits": [192], "block_bits": 128,
        "modes": ["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"]},
       ["algo.des3", "mode.*"], P),
    _L("algo.aes256", "algo", "AES-256",
       "AES 分组密码，256 位密钥（32 字节）。",
       "现代 App / 反爬 Header / 文件加密的常见选择。",
       {"key_bits": [256], "block_bits": 128,
        "modes": ["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"]},
       ["mode.*", "padding.*", "chain.*"]),
    _L("algo.des", "algo", "DES",
       "老式分组密码，64 位分组 / 56 位有效密钥（8 字节）。",
       "2010 年前后的老核心系统；现在只在兼容老接口时见到，属于「能解出来就行」的场景。",
       {"key_bits": [64], "block_bits": 64, "modes": ["ecb", "cbc", "cfb", "ofb", "ctr"]},
       ["algo.des3", "mode.*"]),
    _L("algo.des3", "algo", "3DES（Triple DES）",
       "DES 的三次迭代，密钥 24 字节（也兼容 16 字节两密钥写法），分组仍是 64 位。",
       "银行老核心 / 收单系统的常见算法；注意 **分组是 8 字节**，"
       "IV 必须是 8 字节——用 16 字节 IV 会直接报错。",
       {"key_bits": [192, 128], "block_bits": 64,
        "modes": ["ecb", "cbc", "cfb", "ofb", "ctr"]},
       ["algo.des", "mode.cbc", "keyfmt.*"]),
    _L("algo.rc4", "algo", "RC4（流密码）",
       "流密码，密钥长度 5~256 字节皆可，无 IV、无填充。",
       "老式「伪加密」与自定义 Header 签名（如毫秒时间戳 → RC4 → Base64）。",
       {"key_bits": [40, 2048], "block_bits": 1, "modes": ["stream"]},
       ["mode.stream"], P),

    # ---- v5 新增的经典算法（RC5/RC6 为自实现，已用公开向量验证）----
    _L("algo.rc5", "algo", "RC5-32/12/16（自实现）",
       "参数化分组算法：32 位字、12 轮、16 字节密钥、**分组 8 字节**。"
       "字节序按 OpenSSL/BouncyCastle 惯例（字小端）。",
       "老式客户端与教学实现；轮数/字长可变的变体也已单独登记。"
       "**无 GCM**（GCM 构造按 128 位分组实现）。",
       {"key_bits": [128], "block_bits": 64, "rounds": 12, "word": 32,
        "modes": ["ecb", "cbc", "cfb", "ofb", "ctr"]},
       ["algo.rc6", "mode.cbc"], S),
    _L("algo.rc5_16", "algo", "RC5-32/16/16（自实现）",
       "RC5-32 的 16 轮变体，其余同 RC5-32/12/16。",
       "目标把轮数调到 16 时用。",
       {"key_bits": [128], "block_bits": 64, "rounds": 16, "word": 32},
       ["algo.rc5"], S),
    _L("algo.rc5_64", "algo", "RC5-64/16/16（自实现）",
       "64 位字变体，**分组 16 字节**，因此可用 GCM。",
       "少数产品用 64 位字 RC5；分组与 RC6 相同。",
       {"key_bits": [128, 256], "block_bits": 128, "rounds": 16, "word": 64,
        "modes": ["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"]},
       ["algo.rc5", "mode.gcm"], S),
    _L("algo.rc6", "algo", "RC6-32/20/16（自实现）",
       "AES 竞赛的五个决赛算法之一：32 位字 ×4、20 轮、分组 16 字节，可选 GCM。",
       "少数嵌入式/老系统；已用 BouncyCastle（源自 AES 提交的 RSA 参考实现）向量验证。",
       {"key_bits": [128, 192, 256], "block_bits": 128, "rounds": 20, "word": 32,
        "modes": ["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"]},
       ["algo.rc5", "mode.gcm"], S),
    _L("algo.rc6_16", "algo", "RC6-32/16/16（自实现）",
       "RC6 的 16 轮变体，分组仍为 16 字节。",
       "轮数与标准不同的 RC6 变体。",
       {"key_bits": [128, 192, 256], "block_bits": 128, "rounds": 16, "word": 32},
       ["algo.rc6"], S),
    _L("algo.blowfish", "algo", "Blowfish",
       "经典 16 轮 Feistel，**分组 8 字节**、密钥 4~56 字节可变长。",
       "老产品与 OpenSSL 的 bf-* 系列；分组 8 字节故无 GCM。"
       "已用 Eric Young 标准向量验证。",
       {"key_bits": [32, 448], "block_bits": 64,
        "modes": ["ecb", "cbc", "cfb", "ofb", "ctr"]},
       ["algo.cast5", "mode.cbc"], S),
    _L("algo.cast5", "algo", "CAST5 / CAST-128",
       "分组 8 字节，**密钥仅支持 5 / 8 / 16 字节**（其它长度底层直接拒绝）。",
       "OpenSSL 的 cast5-* 系列、部分 PGP 实现。已用 RFC 2144 向量验证。",
       {"key_bits": [40, 64, 128], "block_bits": 64, "note": "密钥长度受限"},
       ["algo.blowfish"], S),
    _L("algo.rc2", "algo", "RC2",
       "分组 8 字节，密钥 5~128 字节；**另有 effective key bits 参数**。",
       "**该参数不对是 RC2 解成乱码的头号原因**（RFC 2268 的测试向量用的是 63，"
       "底层默认 128）。CLI 用 --rc2-effective-bits 调整。已用 RFC 2268 向量验证。",
       {"key_bits": [40, 1024], "block_bits": 64, "effective_key_bits": [40, 56, 63, 128]},
       ["algo.des"], S),
    _L("algo.chacha20", "algo", "ChaCha20（流密码）",
       "流密码，**密钥必须 32 字节**，**必须给 nonce**（8 / 12 / 24 字节，"
       "12 字节为 RFC 7539 变体）。",
       "现代 TLS / QUIC 场景；与 RC4 不同，它需要 nonce。已用 RFC 8439 向量验证。",
       {"key_bits": [256], "block_bits": 1, "nonce_bytes": [8, 12, 24],
        "modes": ["stream"]},
       ["mode.stream", "algo.salsa20"], S),
    _L("algo.salsa20", "algo", "Salsa20（流密码）",
       "流密码，密钥 16 / 32 字节，**nonce 只能 8 字节**。",
       "ChaCha20 的前身；老库（如 libsodium 早期）常见。已用 eSTREAM 官方向量验证。",
       {"key_bits": [128, 256], "block_bits": 1, "nonce_bytes": [8],
        "modes": ["stream"]},
       ["mode.stream", "algo.chacha20"], S),

    # ---------------- mode ----------------
    _L("mode.ecb", "mode", "ECB（电码本）",
       "每块独立加密，无 IV。相同明文块 → 相同密文块。",
       "国内 App 占比极高（实现最省事）。密码学上是不安全模式："
       "可直接做块重放 / 块替换 / 字典攻击；也正是最容易利用的模式。",
       {"iv": "不需要", "block_align": True}, ["algo.*", "padding.*"]),
    _L("mode.cbc", "mode", "CBC（密码分组链接）",
       "前一块密文参与下一块，需要 IV；IV 固定时等价于弱化版 ECB。",
       "最常见的分组模式；有 IV 前置 / 固定 IV / 全零 IV 三种常见写法。",
       {"iv": "8/16 字节", "block_align": True},
       ["mode.ecb", "padding.*", "frame.*"]),
    _L("mode.cfb", "mode", "CFB（密文反馈）",
       "把分组密码当流密码用，需要 IV，无填充。",
       "少见但存在；密文长度 = 明文长度是它的标志。",
       {"iv": "8/16 字节", "block_align": False}, ["mode.ofb", "mode.ctr"], P),
    _L("mode.ofb", "mode", "OFB（输出反馈）",
       "密钥流由 IV 反复加密生成，需要 IV，无填充。",
       "同上，常见于自定义协议。",
       {"iv": "8/16 字节", "block_align": False}, ["mode.cfb", "mode.ctr"], P),
    _L("mode.ctr", "mode", "CTR（计数器）",
       "对计数器加密得到密钥流，需要 IV/nonce，无填充。密文长度 = 明文长度。",
       "现代实现常用；**nonce 复用即灾难**（密钥流复用 → 明文异或即得）。",
       {"iv": "16 字节（前 12 常作 nonce）", "block_align": False},
       ["mode.ofb", "asym.*"], P),
    _L("mode.gcm", "mode", "GCM（认证加密 AEAD）",
       "CTR 加密 + GHASH 认证，输出密文尾部多 16 字节 tag，可带 AAD。",
       "现代 App / API 的默认模式；支持 AAD（如 appid=9988&v=1 这种固定串）。"
       "**nonce 复用会导致认证密钥被恢复。**",
       {"iv": "12 或 16 字节", "tag": "16 字节（附在密文尾部）", "aad": "可选"},
       ["mode.ctr", "hmac.*"], P, sample="08"),
    _L("mode.stream", "mode", "STREAM（天然流密码）",
       "RC4 这类算法没有分组模式概念，等价于流式；无 IV、无填充。",
       "配 algo.rc4 使用。",
       {"iv": "不需要", "padding": "none"}, ["algo.rc4"], P),

    # ---------------- padding ----------------
    _L("padding.pkcs7", "padding", "PKCS#7 填充",
       "补 n 个值为 n 的字节，解密后按最后一字节校验并剥除。最标准、最常见的写法。",
       "AES / SM4 / DES 的 ecb、cbc 默认填充；**PKCS#7 校验不过通常直接说明密钥或参数错**。",
       {"applies_to": ["ecb", "cbc"]}, ["mode.ecb", "mode.cbc"]),
    _L("padding.zero", "padding", "ZeroPadding（补零）",
       "补 0x00 到分组整数倍；解密后剥掉尾部零字节。",
       "老系统 / CryptoJS 的 ZeroPadding。注意：明文本身以 0x00 结尾时会误剥。",
       {"applies_to": ["ecb", "cbc"]}, ["padding.pkcs7"], S, sample="15"),
    _L("padding.none", "padding", "无填充（NoPadding）",
       "不做填充，要求明文长度本来就对齐分组。",
       "流式模式（CTR/GCM/CFB/OFB）必然是无填充；分组模式里见到它，"
       "说明调用方自己保证了对齐（常见于定长字段、二进制块）。",
       {"applies_to": ["ecb", "cbc", "所有模式"]}, ["mode.ctr", "mode.gcm"]),
    _L("padding.iso7816", "padding", "ISO/IEC 7816-4 填充",
       "补 0x80 后跟若干 0x00。",
       "智能卡 / 部分欧洲银行系统。国内少见。",
       {"applies_to": ["ecb", "cbc"]}, ["padding.pkcs7"], P),
    _L("padding.ansix923", "padding", "ANSI X9.23 填充",
       "补若干 0x00 后跟一个长度字节。",
       "部分老式金融终端。国内少见。",
       {"applies_to": ["ecb", "cbc"]}, ["padding.pkcs7"], P),

    # ---------------- keyfmt ----------------
    _L("keyfmt.hex", "keyfmt", "HEX 解释",
       "把 32 个字符当 16 字节。引擎默认格式。",
       "密钥是「纯十六进制串」时。例如 SM4 密钥 `4A7F2C1E9B3D5A08C6B1D90E37F2A485`。",
       {"example": "4A7F2C1E9B3D5A08 -> 8 字节"}, ["keyfmt.utf8", "keyfmt.base64"]),
    _L("keyfmt.utf8", "keyfmt", "UTF-8 字面量解释（★ 最常被搞错）",
       "把这串字符本身当字节。16 个 ASCII 字符 = 16 字节。",
       "真实前端写 `var KEY = \"4A7F2C1E9B3D5A08\";` 时，**它多半是 16 字节 UTF-8**"
       "而不是 8 字节 HEX——按 HEX 解会直接报「密钥长度不合法」。"
       "看到 16 个可打印字符就优先按 UTF-8 试。",
       {"example": "4A7F2C1E9B3D5A08 -> 16 字节"}, ["keyfmt.hex"]),
    _L("keyfmt.base64", "keyfmt", "Base64 解释",
       "把串按 Base64 解成字节。",
       "密钥以 Base64 形式写在构建产物里（如 `MDEyMzQ1Njc4OWFiY2RlZg==` → 16 字节密钥）。",
       {"example": "MDEyMzQ1Njc4OWFiY2RlZg== -> 16 字节"}, ["keyfmt.hex"], S, sample="11"),
    _L("keyfmt.auto", "keyfmt", "auto 自动判定",
       "按长度与字符集自动在 HEX / UTF-8 / Base64 之间选一个能用的。",
       "不确定密钥写法时的第一选择；`--keyinfo` 会列出三种解释各自的字节数，"
       "哪个等于算法要求的长度就是它。",
       {}, ["keyfmt.hex", "keyfmt.utf8", "keyfmt.base64"]),

    # ---------------- kdf ----------------
    _L("kdf.digest-sha256", "kdf", "SHA256(种子)",
       "对种子直接做 SHA-256，得到 32 字节。",
       "密钥 = 摘要(种子)。常配合取区间使用（如取前 16 字节当密钥）。",
       {"output": 32, "needs": []}, ["kdf.slice", "algo.sm4"], S, sample="12"),
    _L("kdf.digest-md5", "kdf", "MD5(种子)",
       "对种子做 MD5，得到 16 字节。",
       "老系统的「密钥派生」经常就是 MD5(盐+时间戳)。",
       {"output": 16, "needs": []}, ["kdf.digest-sha256", "digest.md5"]),
    _L("kdf.digest-sm3", "kdf", "SM3(种子)",
       "对种子做国密摘要，得到 32 字节。",
       "国密体系里的密钥派生 / 摘要。",
       {"output": 32, "needs": []}, ["digest.sm3", "kdf.digest-sha256"]),
    _L("kdf.hmac-sha256", "kdf", "HMAC-SHA256(派生密钥, 种子)",
       "用一把派生密钥对种子做 HMAC。",
       "带盐的派生：派生密钥通常也是硬编码常量。",
       {"output": 32, "needs": ["key"]}, ["hmac.hmac-sha256"]),
    _L("kdf.hmac-sm3", "kdf", "HMAC-SM3(派生密钥, 种子)",
       "国密版 HMAC 派生。",
       "国密 App 里的带盐派生。",
       {"output": 32, "needs": ["key"]}, ["hmac.hmac-sm3"]),
    _L("kdf.aes-cbc-then-sha256", "kdf", "AES-128-CBC(种子) → SHA256",
       "先把种子当明文用 AES-128-CBC 加密（常量做 key/iv），再 SHA256。",
       "白盒前端最常见的两层派生。",
       {"output": 32, "needs": ["key", "iv"]}, ["kdf.aes-cbc-then-sha256-slice"], P),
    _L("kdf.aes-cbc-then-sha256-slice", "kdf",
       "AES-128-CBC(种子) → SHA256 → 取区间（★ 白盒前端最常见）",
       "在上面那条的基础上再切一段（通常取中间 16 字节 [16:32]）。",
       "移动端 H5 的 `master.substr(16,32)` 就是它。种子一般取自报文前置的随机数。",
       {"output": 16, "needs": ["key", "iv"], "slice": "[16:32]"},
       ["kdf.aes-cbc-then-sha256", "frame.seed-prefix"], S, sample="12"),
    _L("kdf.sm4-cbc-then-sm3", "kdf", "SM4-CBC(种子) → SM3",
       "国密版两层派生：SM4-CBC 加密种子后再 SM3。",
       "纯国密链路。",
       {"output": 32, "needs": ["key", "iv"]}, ["kdf.aes-cbc-then-sha256"]),
    _L("kdf.slice", "kdf", "取字节区间（slice）",
       "派生链的收尾步骤：从摘要结果里切出一段当密钥（如 [0:16] / [16:32]）。",
       "决定密钥长度的一步。**注意：切片参数只有在预设声明了 slice 步骤时才生效**，"
       "工具已在引擎层统一补齐（见踩坑记录）。",
       {"语法": "start:end（左闭右开，end 可为空）"},
       ["kdf.*", "keyfmt.*"]),

    # ---------------- keysrc ----------------
    _L("keysrc.disguised", "keysrc", "伪装常量（data URI / 长 Base64）",
       "把密钥常量编码成看起来像图片或资源的 Base64 串挂在源码里。",
       "`var CONST = \"data:image/png;base64,MTJjMTRhMjQ0Yjg0...\"` —— 解开是 67 字符，"
       "前 32 位是标识、中间 16+16 是 AES 密钥与 IV。工具会自动解码并切片。",
       {"判据": "base64 解码后是可打印文本且长度是 32/64/67 等" + "定长"},
       ["keysrc.slice", "kdf.aes-cbc-then-sha256-slice"], S),
    _L("keysrc.literal", "keysrc", "命名密钥字面量（AES_KEY / IV / NONCE）",
       "按变量名抓源码里的密钥字面量，同一串按 HEX / UTF-8 / Base64 三种解释都产出。",
       "真实前端最常见的写法；工具会把三种解释都当候选，由解密结果决定哪个对。",
       {"变量名线索": "key / aeskey / sm4key / secret / iv / nonce / aad / seed"},
       ["keyfmt.*"], S, sample="03/04/05/06/07/08/09/11/13/14/15"),
    _L("keysrc.slice", "keysrc", "定长切片（把长常量切给不同用途）",
       "一段长常量按固定偏移切开：32+16+16+3（标识 / AES key / IV / 后缀）。",
       "国密前端把多个参数打包成一个常量；切片位置就是它的语义。",
       {"常见切法": ["32+16+16+3", "32+32"]},
       ["keysrc.disguised", "kdf.aes-cbc-then-sha256-slice"], S),
    _L("keysrc.chain", "keysrc", "派生链识别 + 跨文件绑定常量",
       "从源码里认出「A 文件定义算法、B 文件提供密钥」的链路，并把常量绑到链上。",
       "多文件前端（framework + business 分包）的标准形态。",
       {"来源": "folder_crypto_analyzer 的跨文件配方合成"},
       ["kdf.*", "keysrc.literal"], S),
    _L("keysrc.pem", "keysrc", "PEM 私钥（多行）与十六进制私钥",
       "从材料里挖非对称私钥：多行 PEM 块，或 `SM2_PRIV = \"<64 位十六进制>\"` 这种字面量。",
       "信封解封必需。实战中它通常在服务端代码 / 配置文件 / 运维泄漏的密钥文件里。",
       {"识别": "-----BEGIN ... PRIVATE KEY----- 或 priv/private 命名 + 16/24/32/48/64 字节"},
       ["asym.*", "envelope.*"], S, sample="17/18"),
    _L("keysrc.kb", "keysrc", "本地知识库命中",
       "把解过一次的「密文特征 → 方案」存进本地知识库，下次同类密文直接命中。",
       "同一目标反复测时的加速器；知识库里只存规则与哈希，不存明文密钥。",
       {"文件": "crypto_knowledge.json"}, ["frame.*", "composite.*"], S),
    _L("keysrc.header", "keysrc", "报文头部字段当种子",
       "从报文自身取派生种子（如报文前置的随机数、时间戳、deviceId）。",
       "一次一密派生的入口：种子在包里，常量在客户端 —— 两者一凑就能离线解。",
       {"实例": "报文前置 32 位 HEX 种子、时间戳、deviceId"},
       ["kdf.*", "frame.seed-prefix"], S, sample="12"),

    # ---------------- digest ----------------
    _L("digest.md5", "digest", "MD5 摘要",
       "16 字节摘要。已不适合安全用途，但老系统到处都是。",
       "复现老逻辑（`sign = MD5(排序参数 + &key=secret)`）。工具会标注弱算法告警。",
       {"output": 16, "weak": True}, ["hmac.hmac-md5"], S),
    _L("digest.sha1", "digest", "SHA-1 摘要",
       "20 字节摘要。碰撞已被工程化。",
       "同上，复现老签名逻辑。",
       {"output": 20, "weak": True}, ["hmac.hmac-sha1"], S),
    _L("digest.sha256", "digest", "SHA-256 摘要",
       "32 字节摘要，现代默认。",
       "多数新系统的 sign / 完整性校验。",
       {"output": 32, "weak": False}, ["hmac.hmac-sha256", "kdf.digest-sha256"], S),
    _L("digest.sha512", "digest", "SHA-512 摘要",
       "64 字节摘要。",
       "少数现代实现；也用于 KDF 取 32 字节。",
       {"output": 64, "weak": False}, ["digest.sha256"], S),
    _L("digest.sm3", "digest", "SM3 摘要（国密）",
       "国密摘要标准 GB/T 32905-2016，输出 32 字节。",
       "国密 App 的完整性 / 签名前置哈希（SM3withSM2 里的 SM3 就是它）。",
       {"output": 32, "weak": False}, ["hmac.hmac-sm3", "asym.sm2"], S),

    # ---------------- hmac ----------------
    _L("hmac.hmac-md5", "hmac", "HMAC-MD5",
       "16 字节带密钥摘要。",
       "老接口的报文 mac。",
       {"output": 16, "b64_len": 24}, ["hmac.hmac-sha1"], S),
    _L("hmac.hmac-sha1", "hmac", "HMAC-SHA1",
       "20 字节带密钥摘要。",
       "TikTok X-Gorgon 一类 Header 签名；部分老 API。",
       {"output": 20, "b64_len": 28}, ["hmac.hmac-sha256"], S),
    _L("hmac.hmac-sha256", "hmac", "HMAC-SHA256",
       "32 字节带密钥摘要，**Base64 后是 44 字符**（与 HMAC-SM3 长度完全相同）。",
       "现代接口的 mac / sign；与 HMAC-SM3 只差算法，**长度上分不出来，必须两个都试**。",
       {"output": 32, "b64_len": 44}, ["hmac.hmac-sm3", "hmac.auto"], S),
    _L("hmac.hmac-sha512", "hmac", "HMAC-SHA512",
       "64 字节带密钥摘要。",
       "少见；遇到 88 字符 mac 时怀疑它。",
       {"output": 64, "b64_len": 88}, ["hmac.hmac-sha256"]),
    _L("hmac.hmac-sm3", "hmac", "HMAC-SM3（国密）",
       "32 字节国密带密钥摘要，Base64 后 44 字符。",
       "国密报文的 mac；银行 H5 的 `mac` 字段基本就是它。",
       {"output": 32, "b64_len": 44}, ["hmac.hmac-sha256", "hmac.auto"], S),
    _L("hmac.auto", "hmac", "mac 算法自适应（按长度推断）",
       "按 mac 的字节长度缩小候选范围再逐个试：32B→SM3/SHA256、20B→SHA1、16B→MD5、64B→SHA512。",
       "一键解密里默认行为：不写死算法，对上了才判定为确凿证据。",
       {"长度表": {"44 字符": ["hmac-sm3", "hmac-sha256"], "28": ["hmac-sha1"],
                   "24": ["hmac-md5"], "88": ["hmac-sha512"]}},
       ["hmac.*"], S),
    _L("hmac.scope", "hmac", "mac 覆盖范围（scope）",
       "mac 到底算了哪些字节：常见是「被保护的字段 + cipher」「32hex + cipher_b64」"
       "或「解码前的密文文本」。",
       "**范围算错必然对不上**；设计里漏签的字段就是注入点。工具会按形态给默认范围并展示出来。",
       {"默认": {"seed-prefix": "32hex 种子 + cipher_b64",
                 "其它": "密文（解码前文本）"}},
       ["frame.*", "hmac.auto"], S),

    # ---------------- encoding ----------------
    _L("encoding.base64", "encoding", "Base64",
       "3 字节 → 4 字符，可带 `=` 填充。**不是加密**，只是表示。",
       "几乎所有接口的密文外层。",
       {"判据": "字符集 [A-Za-z0-9+/=] 且长度 %4==0"}, ["encoding.base64url"]),
    _L("encoding.base64url", "encoding", "Base64URL",
       "把 `+` `/` 换成 `-` `_`，常去掉 `=`。",
       "URL / Cookie / JWT 场景；见到 `-` `_` 或长度 %4≠0 就优先怀疑。",
       {"判据": "含 -_ 或（不以 = 结尾且长度 %4 ∈ {2,3}）"}, ["encoding.base64"], S, sample="04"),
    _L("encoding.hex", "encoding", "HEX（十六进制）",
       "1 字节 → 2 字符，大小写都可能。",
       "老系统 / so 交互 / 二进制通道。**注意：纯 hex 串也满足 Base64 字符集**，"
       "先判 hex 再判 base64，否则会解成乱码。",
       {"判据": "长度偶数且全部 [0-9a-fA-F]"}, ["encoding.base64"], S, sample="05/11/13"),
    _L("encoding.url", "encoding", "URL 编码（%XX）",
       "把特殊字符转成 %XX。",
       "`encodeURIComponent(base64(密文))` 很常见；解开后还要再解一层 Base64。",
       {"判据": "出现 %[0-9A-Fa-f]{2}"}, ["encoding.base64", "chain.*"], S, sample="14"),
    _L("encoding.raw", "encoding", "raw（原始二进制）",
       "不做任何编码，直接吃二进制字节。",
       "文件模式专用（`--op dec --encoding raw`）。",
       {}, ["encoding.base64"], P),

    # ---------------- compress ----------------
    _L("compress.zlib", "compress", "zlib 压缩",
       "zlib 容器格式，魔数 `78 9C`（默认级别）。",
       "加密前先压缩（响应侧常见）；历史上催生 CRIME / BREACH。",
       {"magic": "789C"}, ["compress.gzip", "chain.*"], S, sample="13"),
    _L("compress.gzip", "compress", "gzip 压缩",
       "gzip 容器格式，魔数 `1F 8B`。",
       "同上；pako.gzip 是前端最常见的实现。",
       {"magic": "1F8B"}, ["compress.zlib"], S, sample="04"),
    _L("compress.deflate", "compress", "deflate（带 zlib 头）",
       "与 zlib 基本同物，部分实现这么叫。",
       "pako.deflate 的默认输出。",
       {}, ["compress.zlib"]),
    _L("compress.deflate-raw", "compress", "deflate-raw（裸 deflate）",
       "无 zlib 头的裸 deflate 流，**pako 的 deflate 默认就是裸流**。",
       "把 deflate 与 deflate-raw 搞混是常见错误；工具解压失败会自动换算法重试。",
       {}, ["compress.deflate"], S),
    _L("compress.sniff", "compress", "压缩魔数嗅探 + 自动回退",
       "解密结果不是可读文本时，按魔数猜算法，猜错就轮询其它三种。",
       "一键解密的后处理步骤：很多「解密失败」其实是解出了一段压缩数据。",
       {"实现": "crypto_core.looks_compressed"}, ["compress.*"], S, sample="04/13"),

    # ---------------- chain ----------------
    _L("chain.base64", "chain", "单层 Base64（最常见）",
       "密文 → Base64 一层。",
       "绝大多数接口的外层。",
       {"链": ["base64"]}, ["encoding.base64"], S, sample="03/06/07/08/12/15/17/18"),
    _L("chain.base64-twice", "chain", "双层 Base64",
       "Base64 之后再 Base64 一层（`base64 → base64`）。",
       "故意套一层混淆，很常见。",
       {"链": ["base64", "base64"]}, ["encoding.base64"], S, sample="09"),
    _L("chain.base64-then-hex", "chain", "Base64 之后再 HEX（样本 13 的 hex(base64(ct))）",
       "先 Base64，再把整串转成十六进制（`base64 → hex`）；"
       "解码顺序相反：先解 HEX 拿回 Base64 文本，再解 Base64 拿回密文。",
       "大字段先压缩、再加密、再套两层编码的写法。",
       {"链": ["base64", "hex"], "解码序": ["hex", "base64"]},
       ["encoding.hex", "encoding.base64", "compress.*"], S, sample="13"),
    _L("chain.base64-then-url", "chain",
       "Base64 之后再 URL 编码（encodeURIComponent(base64(ct))）",
       "先 Base64，再做 URL 转义（`base64 → url`）；解码顺序相反。",
       "老系统 / 表单提交场景。",
       {"链": ["base64", "url"], "解码序": ["url", "base64"]},
       ["encoding.url", "encoding.base64"], S, sample="14"),
    _L("chain.hex-then-base64", "chain", "HEX 之后再 Base64",
       "先 HEX 再 Base64（`hex → base64`）。少见。",
       "部分自定义协议；矩阵里会试。",
       {"链": ["hex", "base64"], "解码序": ["base64", "hex"]}, ["encoding.hex"], P),
    _L("chain.order", "chain", "★ 顺序即语义（两套口径必须分清）",
       "编码链的顺序本身就是信息，但**引擎与求解器的写法正好相反**：\n"
       "· 引擎 `encode_chain/decode_chain`（本表口径）：列出的是**编码时施加的顺序**，"
       "解码时引擎自动倒序还原。所以样本 13 的 hex(base64(ct)) 写成 `[base64, hex]`。\n"
       "· 求解器 `cipher_auto_solver._decode_ciphertext`：列出的是**解码时施加的顺序**，"
       "同一个样本写成 `[hex, base64]`。\n"
       "写错顺序必然解不开。本登记表统一按**引擎口径**（编码顺序），避免与 CLI / GUI 打架。",
       "另外：解不开的编码链会被先剪掉，避免组合爆炸把正确配方挤出候选上限。",
       {"引擎口径": "编码顺序", "求解器口径": "解码顺序"},
       ["chain.*"], S),

    # ---------------- asym ----------------
    _L("asym.sm2", "asym", "SM2 加解密（国密椭圆曲线）",
       "国密椭圆曲线公钥算法；密文有 C1C3C2 / C1C2C3 两种拼接顺序。",
       "国密 App 的密钥包裹 / 敏感字段加密；微信小程序算法套件。",
       {"椭圆曲线": "sm2p256v1", "密文结构": "C1(65) + C3(32) + C2(明文长) = 113 字节（16 字节明文时）",
        "C1 排序": ["c1c3c2（国标推荐）", "c1c2c3（部分老实现）"],
        "可选": ["asn1(DER)", "prehashed", "不带 04 前缀的 C1"]},
       ["algo.sm4", "digest.sm3", "envelope.sm2"], S, sample="18"),
    _L("asym.sm2-sign", "asym", "SM2 签名 / 验签（SM3withSM2）",
       "签名前先算 Z 值（含公钥分量）再 SM3，因此**只给私钥时验签会失败，必须能从私钥推出公钥**。",
       "sid(JWT, alg=SM3withSM2) 这类令牌。",
       {"摘要": "SM3", "注意": "Z 值含公钥分量"}, ["digest.sm3", "asym.sm2"], S),
    _L("asym.rsa", "asym", "RSA 加解密",
       "公钥加密、私钥解密；支持 PKCS#1 v1.5 与 OAEP 两种填充，长文本自动分段（encryptLong2）。",
       "国际体系里的密钥包裹 / 密码体加密。",
       {"密钥长度": "1024 / 2048 / 3072 / 4096",
        "填充": ["pkcs1v15", "oaep(sha1/sha256)"],
        "长文本": "自动分段（RSA 单块上限 = 模长 - 填充开销）"},
       ["asym.rsa-sign", "envelope.rsa"], S, sample="17"),
    _L("asym.rsa-sign", "asym", "RSA 签名 / 验签",
       "PKCS#1 v1.5 或 PSS，摘要 md5~sha512 可选。",
       "接口 sign 字段 / 客户端完整性校验。",
       {"方案": ["pkcs1v15", "pss"], "摘要": ["md5", "sha1", "sha256", "sha512"]},
       ["digest.*", "asym.rsa"], S),
    _L("asym.keygen", "asym", "生成测试密钥对（SM2 / RSA）",
       "现场生成密钥对，用于自造密文验证链路。",
       "调试 / 验证 / 写样本时用；**不是攻击手段**。",
       {"命令": "cli_crypto.py --keygen sm2 / --keygen rsa:2048"},
       ["asym.sm2", "asym.rsa", "envelope.*"], S),
    _L("asym.weak", "asym", "非对称实现缺陷识别",
       "教科书式 RSA（`RSA/ECB/NoPadding`）、PKCS#1 v1.5 密钥传输（Bleichenbacher / ROBOT）、"
       "GCM nonce 复用、私钥落在客户端。",
       "这些是「能打」的点，不是工具自动判定的——工具负责把参数摆出来供你判断。",
       {"参考": ["Bleichenbacher(1998)", "ROBOT(2017)", "F-12 密文无完整性"]},
       ["asym.rsa", "mode.gcm"], P),

    # ---------------- envelope ----------------
    _L("envelope.sm2", "envelope", "SM2 混合信封（SM2 包 SM4 密钥）",
       "随机生成对称密钥 → 对称加密数据 → 用 SM2 公钥包裹该密钥，两个字段一起传。",
       "**国内 App 最主流的写法**：`ed`（密文）+ `sked`（包裹密钥）两字段一起传。",
       {"字段": ["ed / sked（安全键盘）", "encKey / data", "key / data"],
        "解封": ["SM2 C1C3C2", "SM2 C1C2C3"]},
       ["asym.sm2", "algo.sm4", "envelope.json"], S, sample="18"),
    _L("envelope.rsa", "envelope", "RSA 混合信封（RSA 包 AES 密钥）",
       "同上，非对称那一步换成 RSA（OAEP 或 PKCS#1 v1.5）。",
       "拼多多 anti-token 一类：RSA-1024 包 32 字节随机 key + AES-256-CBC(iv=0) 加密 JSON。",
       {"字段": ["key / data", "encKey / data"],
        "解封": ["RSA-OAEP/sha256", "RSA-OAEP/sha1", "RSA-PKCS1v1.5"]},
       ["asym.rsa", "algo.aes256", "envelope.json"], S, sample="17"),
    _L("envelope.json", "envelope", "JSON 信封自动识别",
       "整段 JSON 里认出「哪个字段是被包裹的密钥、哪个是密文、哪个是 IV」并自动解封。",
       "字段名线索：密钥 `encKey`/`encryptedKey`/`wrappedKey`/`sked`/`key`；"
       "密文 `data`/`ed`/`cipher`/`ct`/`body`；IV `iv`/`nonce`。",
       {"顺序": "先用私钥解封包裹密钥 → 再用它解正文"},
       ["envelope.sm2", "envelope.rsa", "keysrc.pem"], S, sample="17/18"),
    _L("envelope.checks", "envelope", "解封结果校验（长度 16/24/32）",
       "解封出来的必须是**对称密钥长度**（16/24/32 字节），否则说明填充或算法不对。",
       "**这一步是必须的**：RSA PKCS#1 v1.5 解密没有完整性校验，用错填充解错也不报错、"
       "会返回一段垃圾字节——只能靠长度把它筛掉。工具还让 OAEP 排在 v1.5 前面。",
       {"阈值": [16, 24, 32]}, ["asym.rsa", "envelope.rsa"], S),

    # ---------------- frame ----------------
    _L("frame.http", "frame", "整段 HTTP 报文",
       "输入带请求行/响应头时自动丢弃头部，只取 body。",
       "从 Burp 直接复制粘贴的常见形态。",
       {}, ["frame.*"], S, sample="10"),
    _L("frame.raw-base64", "frame", "裸 Base64", "无报文框架，规整 Base64 串。",
       "最朴素的情形。", {}, ["encoding.base64"], S, sample="03/06/07/08/09/15"),
    _L("frame.raw-base64url", "frame", "裸 Base64URL",
       "含 `-` `_` 或去掉填充的 Base64。",
       "URL / JWT 场景。", {}, ["encoding.base64url"], S, sample="04"),
    _L("frame.raw-hex", "frame", "裸 HEX",
       "纯十六进制串，无框架。**必须优先于 Base64 判定**。",
       "老系统 / 二进制通道。", {}, ["encoding.hex"], S, sample="05/11/13"),
    _L("frame.raw-url", "frame", "URL 编码密文",
       "满屏 %XX，解开是 Base64/HEX 文本。",
       "表单场景。", {}, ["encoding.url"], S, sample="14"),
    _L("frame.seed-prefix", "frame", "种子前置",
       "前 32 字符是本次请求的随机种子（明文前置），其后才是密文。",
       "一次一密派生：种子随包传、常量在客户端。",
       {"派生": "常配 SHA256(种子)[0:16]"}, ["kdf.digest-sha256", "kdf.slice"], S, sample="12"),
    _L("frame.json-envelope", "frame", "JSON 混合信封",
       "整段 JSON，含包裹密钥字段 + 对称密文字段（+ IV 字段）。",
       "与 envelope.json 同一件事，这里是形态侧的名字。",
       {}, ["envelope.json"], S, sample="17/18"),
    _L("frame.mixed-text", "frame", "混杂文本（密文与源码粘在一起）",
       "输入里混着代码/日志时，先抽出最长的那段密文，同时从整段里挖常量。",
       "从 jadx / IDE 复制时最常见。",
       {"实现": "先抽 [A-Za-z0-9+/=_-]{120,} 的最长串"}, ["keysrc.*"], S, sample="（自检覆盖）"),

    # ---------------- gap ----------------
    _L("gap.whitebox-sm4", "gap", "白盒 SM4（自定义 S-box / 查表实现）",
       "把 S-box 与轮函数合并成巨大的查表，静态看不出标准 SM4。",
       "需要把查表还原回标准 SM4，或用 Hook 抓中间态。",
       {"缺什么": "查表 → 标准 S-box 的还原器（需先定位表结构）"},
       ["algo.sm4"], N),
    _L("gap.custom-cipher", "gap", "自定义算法（SIMON/SPECK、魔改轮函数）",
       "TikTok X-Argus 里的 SIMON-128(72 轮)、自研 S-box 等。",
       "每个目标一套实现，无法通用；工具只能帮你把编码/压缩那一层剥掉。",
       {"缺什么": "通用自定义轮函数引擎（不现实，按目标单独写）"},
       ["chain.*", "compress.*"], N),
    _L("gap.key-exchange", "gap", "密钥协商（ECDH / SM2 密钥交换）",
       "双方协商出一次一密，抓包只看到公钥交换。",
       "**这类是最强的**：没有长期私钥基本打不动，只能打实现层（弱随机数、复用）。",
       {"缺什么": "协商过程还原（需实现侧支持）"}, ["asym.sm2"], N),
    _L("gap.tlcp", "gap", "国密 TLS（GB/T 38636-2020）",
       "传输层就换了国密栈（SM2+SM3+SM4，握手 5 次强制校验）。",
       "金融 App 常见；抓包需 Yakit 一类支持国密的代理，证书绑定另需绕过。",
       {"缺什么": "国密 TLS 终结点（工具只在应用层工作）"}, ["algo.sm4", "asym.sm2"], N),
    _L("gap.native-kdf", "gap", "Native / so 内派生（Frida Hook 场景）",
       "密钥在 so 里由 sessionId / 设备特征动态派生，静态分析拿不到。",
       "Soul 那种 `generateKey()` 动态传入 native 的写法。",
       {"缺什么": "动态 Hook 能力（工具是离线静态分析）"},
       ["keysrc.chain"], N),
    _L("gap.custom-baseN", "gap", "非标准编码（自定义 base 表 / 私有码表）",
       "换掉 Base64 字母表或自造编码。",
       "遇到时密文会「像 Base64 但解出来是乱码」。",
       {"缺什么": "码表推测（需要已知明文对）"}, ["encoding.base64"], N),
    _L("gap.tlv", "gap", "TLV / Protobuf 结构解析",
       "拼多多长签名里的 TLV、TikTok 的 Protobuf。",
       "工具目前只做到「把编码/压缩层剥掉」，不解析业务结构。",
       {"缺什么": "按目标提供 schema"}, ["compress.*", "chain.*"], N),
    _L("gap.stream-large", "gap", "超大文件分块流式加解密",
       "分块 AES-CBC + 断点续传场景。",
       "当前实现会整块读入内存（有 4MB 明文上限与命令行长度上限保护）。",
       {"缺什么": "分块流式处理（当前文件模式上限 32MB）"}, ["algo.aes256"], P),
]

# ============================================================================
# 二、端到端组合配方（对应 18 个样本 + 常见组合）
# ============================================================================
def _C(cid, name, frame, layers, note, sample="", exec_hint=""):
    return {"id": cid, "name": name, "frame": frame, "layers": layers,
            "note": note, "sample": sample, "exec_hint": exec_hint}


COMPOSITES: list[dict] = [
    _C("c03", "固定密钥 + AES-128-CBC + Base64",
       "raw-base64",
       ["命名密钥字面量（按 UTF-8 解释）", "AES-128-CBC/PKCS7", "Base64 解码"],
       "最基础的形态；注意密钥那 16 个字符是 UTF-8 不是 HEX。", "03"),
    _C("c04", "压缩 + 加密 + Base64URL",
       "raw-base64url",
       ["先 gzip 压缩明文", "AES-256-CBC/PKCS7", "Base64URL（去 =）"],
       "解密后还要解压；解压失败会自动换算法重试。", "04"),
    _C("c05", "老系统 3DES-CBC + HEX 编码",
       "raw-hex",
       ["HEX 字面量密钥 → 24 字节", "3DES-CBC/PKCS7（分组 8 字节，IV 8 字节）",
        "密文 HEX 编码（大写）"],
       "注意 3DES 分组是 8 字节，IV 给 16 字节会报错。", "05"),
    _C("c06", "RC4 流密码 + Base64",
       "raw-base64",
       ["任意长度密钥（UTF-8 字面量）", "RC4/STREAM/无填充", "Base64"],
       "流密码：密文长度 = 明文长度，无 IV 无填充。", "06"),
    _C("c07", "SM4-CTR + IV 前置",
       "raw-base64",
       ["密文前 16 字节就是 IV", "SM4-CTR/无填充", "Base64"],
       "「同明文两次密文不同、且前 16 字节随机」的典型。", "07"),
    _C("c08", "AES-128-GCM + AAD + nonce 前置",
       "raw-base64",
       ["密文前 12 字节是 nonce", "AES-128-GCM（尾部 16 字节 tag）",
        "AAD = appid=9988&v=1", "Base64"],
       "GCM 必须给 AAD，否则 tag 校验不过。", "08"),
    _C("c09", "AES-128-ECB + 双层 Base64",
       "raw-base64",
       ["命名密钥字面量", "AES-128-ECB/PKCS7", "先解外层 Base64，再解内层 Base64"],
       "双层编码是常见的混淆手段。", "09"),
    _C("c10", "整段 HTTP 报文（自动取 body）",
       "http",
       ["剥掉报文头只取 body", "之后按 body 的实际形态继续判（同 c01 或裸编码路径）"],
       "从 Burp 直接粘贴的形态。", "（通用）"),
    _C("c11", "SM4-ECB + 裸 HEX 密文 + Base64 密钥",
       "raw-hex",
       ["Base64 解码得到 16 字节密钥", "SM4-ECB/PKCS7", "密文 HEX 解码"],
       "「裸 HEX」必须先于 Base64 判定，否则会被解成乱码。", "11"),
    _C("c12", "种子前置 + SHA256(种子) 取前 16 字节 → SM4-ECB",
       "seed-prefix",
       ["前 32 字符是种子", "SHA256(种子)[0:16] 当密钥", "SM4-ECB/PKCS7 解其后 Base64"],
       "种子随包传、常量在客户端；解不开时优先怀疑常量取自别的版本。", "12"),
    _C("c13", "AES-192-CBC + zlib + 多级编码 hex(base64(密文))",
       "raw-hex",
       ["先解 HEX 得到 Base64 文本", "再解 Base64 得到密文", "AES-192-CBC/PKCS7",
        "解密结果再 zlib 解压"],
       "编码链顺序即语义：解码必须倒着来。", "13"),
    _C("c14", "DES-CBC + URL 编码（encodeURIComponent(base64)）",
       "raw-url",
       ["URL 解码拿回 Base64", "Base64 解码", "DES-CBC/PKCS7（8 字节分组）"],
       "满屏 %XX 时先想它。", "14"),
    _C("c15", "SM4-ECB + ZeroPadding",
       "raw-base64",
       ["命名密钥字面量", "SM4-ECB/ZeroPadding（不是 PKCS7）", "Base64"],
       "只试 PKCS7 会解不开——填充维度必须一起试。", "15"),
    _C("c17", "RSA-2048 混合信封（OAEP 包 SM4 密钥）",
       "json-envelope",
       ["从材料里挖 PEM 私钥", "RSA-OAEP/SHA-256 解封 encKey → 16 字节 SM4 密钥",
        "SM4-CBC/PKCS7 解 data（IV 来自 iv 字段）"],
       "**解封结果必须是 16/24/32 字节**，否则是填充错（v1.5 解错不报错）。", "17"),
    _C("c18", "SM2 混合信封（ed / sked 两字段形态）",
       "json-envelope",
       ["SM2 私钥（64 位十六进制字面量）", "SM2 C1C3C2 解封 sked → 16 字节密钥",
        "SM4-CBC/PKCS7 解 ed（iv 来自 iv 字段）"],
       "字段命名 sked/ed 是国密安全键盘的惯例。", "18"),
    _C("c19", "参数排序 + &key=secret → MD5/SHA1/HMAC 签名（sign 字段）",
       "（签名不在密文里，在 Header/参数里）",
       ["参数按字典序排序", "拼 `&key=<secret>`", "MD5 / SHA1 / HMAC-SHA256", "比对 sign 字段"],
       "**注意漏签字段**：签名通常不覆盖全部参数，没被签的字段就是注入点。",
       "", "用 --hmac / --digest 复现"),
    _C("c20", "时间戳 + nonce + sign 三件套（判断有没有真校验）",
       "Header / 参数",
       ["改 timestamp 重放", "重放旧 nonce", "看服务端是否仍接受"],
       "这是**验证**手段而不是解密手段：接受即说明没真校验。", "", "配合 Burp 重放"),
    _C("c21", "Flutter 壳：请求体以「.」分隔（前段 RSA 密文 = key，后段 AES 密文）",
       "（自定义分隔符）",
       ["按 . 切分", "前段 ≈ 256/334 字节 = RSA 加密的密钥", "后段用解出的密钥 AES 解密"],
       "工具当前不会自动按自定义分隔符切分，需要手工切两段分别处理。",
       "", "见 gap 分类"),
    _C("c22", "「data=密文:IV」冒号拼 IV 的格式",
       "（自定义分隔符）",
       ["按 : 切分", "左半是密文、右半是 IV（或反过来）", "按该 IV 解 CBC/CTR"],
       "工具会自动试「密文前 8/12/16 字节是 IV」，但不会自动按冒号切——需手工分段。",
       "", "见 gap 分类"),
]

# ============================================================================
# 三、密文特征规则（反查表）
# ============================================================================
FEATURE_RULES: list[dict] = [
    {"id": "f01", "feature": "长度是 16 的倍数 + Base64 形态",
     "conclusion": "分组密码：AES / SM4（也可能是 DES/3DES，分组 8）",
     "try": ["encoding.base64", "algo.aes128", "algo.sm4", "algo.aes256", "padding.pkcs7"],
     "how": "先按 16 字节分组解 Base64，再逐算法试；密钥长度决定具体是 AES-128/192/256 还是 SM4。"},
    {"id": "f02", "feature": "解码后长度不是分组的整数倍",
     "conclusion": "流式加密（CTR/GCM/CFB/OFB/RC4），或加密后又套了编码",
     "try": ["mode.ctr", "mode.gcm", "algo.rc4", "chain.*"],
     "how": "先排掉分组+填充的组合，优先试流式；不行再回头查编码链是否多解了一层。"},
    {"id": "f03", "feature": "密文长度 ≈ 明文长度",
     "conclusion": "流式加密，或 ECB 无填充（定长字段）",
     "try": ["mode.ctr", "mode.ofb", "algo.rc4", "padding.none"],
     "how": "流式与「ECB/NoPadding」两种都试，看哪个出合法明文。"},
    {"id": "f04", "feature": "请求里一长一短两个字段（短的约 344 字符 Base64）",
     "conclusion": "短的那个极可能是「包 key」——RSA-2048 密文 Base64 后约 344 字符",
     "try": ["envelope.rsa", "envelope.json", "asym.rsa"],
     "how": "先认 JSON 信封；有私钥就解短的拿对称密钥，再用它解长的。"},
    {"id": "f05", "feature": "同明文两次抓包密文完全相同",
     "conclusion": "ECB，或固定 IV 的 CBC → 可直接重放 / 字典攻击",
     "try": ["mode.ecb", "frame.*", "keysrc.*"],
     "how": "确认模式后，块重放 / 块替换 / 字典都是可打的点（工具负责还原算法，利用靠你手工）。"},
    {"id": "f06", "feature": "同明文两次密文不同，且前 16 字节每次都变",
     "conclusion": "IV 前置（密文前 16 字节就是 IV）",
     "try": ["mode.cbc", "mode.ctr", "mode.gcm"],
     "how": "工具会自动试「密文前 8/12/16 字节是 IV/nonce」。"},
    {"id": "f07", "feature": "纯 HEX、长度 %32 == 0",
     "conclusion": "SM4/AES 密钥或密文；**必须优先于 Base64 判定**",
     "try": ["encoding.hex", "frame.raw-hex"],
     "how": "纯 hex 也满足 Base64 字符集，先判 hex 再判 base64，否则解成乱码。"},
    {"id": "f08", "feature": "含 `-` 或 `_`，或长度 %4 ≠ 0 却没有 `=`",
     "conclusion": "Base64URL（去填充变体）",
     "try": ["encoding.base64url"],
     "how": "补回 `=` 填充后按标准 Base64 解码。"},
    {"id": "f09", "feature": "含 %XX 转义",
     "conclusion": "URL 编码，里面通常还套着一层 Base64/HEX",
     "try": ["encoding.url", "chain.url-then-base64"],
     "how": "先 unquote 拿到文本，再按文本形态继续判。"},
    {"id": "f10", "feature": "解码后开头是 `78 9C` / `1F 8B`",
     "conclusion": "zlib / gzip 压缩数据（说明密文解出来还要解压）",
     "try": ["compress.zlib", "compress.gzip", "compress.sniff"],
     "how": "解密结果按压缩算法还原；魔数猜错会自动轮询其它算法。"},
    {"id": "f12", "feature": "整段 JSON，含两个长字符串字段",
     "conclusion": "混合信封（一个是被包裹的密钥，一个是密文）",
     "try": ["frame.json-envelope", "envelope.sm2", "envelope.rsa", "keysrc.pem"],
     "how": "字段名自动识别；需要私钥才能解封。"},
    {"id": "f13", "feature": "末尾有 44 字符的 Base64（=32 字节）",
     "conclusion": "报文 mac：HMAC-SM3 或 HMAC-SHA256（两者等长，分不出来）",
     "try": ["hmac.auto", "hmac.hmac-sm3", "hmac.hmac-sha256"],
     "how": "按长度推断候选算法后逐个试；算出来一致就是硬证据。"},
    {"id": "f14", "feature": "末尾 mac 是 28 / 24 / 88 字符",
     "conclusion": "分别是 HMAC-SHA1(20B) / HMAC-MD5(16B) / HMAC-SHA512(64B)",
     "try": ["hmac.auto", "hmac.hmac-sha1", "hmac.hmac-md5"],
     "how": "长度本身就是很强的线索，工具自动按表选候选。"},
    {"id": "f16", "feature": "源码里一串长 Base64 挂着 `data:image/...` 前缀",
     "conclusion": "伪装常量（解开是打包的多个参数）",
     "try": ["keysrc.disguised", "keysrc.slice", "kdf.aes-cbc-then-sha256-slice"],
     "how": "解 Base64 后按 32+16+16+3 或 32+32 切片，分别当标识/密钥/IV。"},
    {"id": "f17", "feature": "源码里 `var KEY = \"<16 个可打印字符>\"`",
     "conclusion": "16 字节 UTF-8 密钥（不是 8 字节 HEX）",
     "try": ["keyfmt.utf8", "keyfmt.auto"],
     "how": "先按 UTF-8 解释；报「密钥长度不合法」时用 --keyinfo 看三种解释的字节数。"},
    {"id": "f18", "feature": "每次请求 Header 带 timestamp / nonce 但内容不变",
     "conclusion": "大概率没真校验（可重放）",
     "try": ["composite.c20"],
     "how": "改 timestamp、重放 nonce，看服务端认不认——这是验证，不是解密。"},
    {"id": "f19", "feature": "密文长度与明文长度差 1~16 字节",
     "conclusion": "分组密码 + 填充（差值就是填充字节数）",
     "try": ["padding.pkcs7", "padding.zero"],
     "how": "差值 = 分组数×分组长度 - 明文长度，可反推填充方案。"},
    {"id": "f20", "feature": "Base64 解码后全是不可打印字节且长度整齐",
     "conclusion": "标准分组密文（不是编码套编码）",
     "try": ["frame.raw-base64", "algo.aes128", "algo.sm4"],
     "how": "直接进解密矩阵；密钥从材料里挖。"},
]


# ============================================================================
# 三·五、用户自建逻辑：新增 / 删除 / 恢复（JSON 持久化）
# ----------------------------------------------------------------------------
# 为什么要"删除标记"而不是真删：内置逻辑写在代码里，删不掉；但用户可能就是不想要
# 某条（比如团队约定不用 RC4），所以删除内置条目 = 记一条 hidden 标记，
# 列表里不再出现、但可以一键恢复，数据永远可回溯。
# 存储位置与本地知识库同一套约定：环境变量 > 脚本目录（可写）> %LOCALAPPDATA%。
# ============================================================================
STORE_FILENAME = "crypto_logic_user.json"


def _is_writable_dir(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".jiejieead_write_probe")
        with open(probe, "a", encoding="utf-8"):
            pass
        os.remove(probe)
        return True
    except Exception:  # noqa: BLE001
        return False


def user_store_path() -> str:
    env = os.environ.get("JIEJIE_LOGIC_STORE")
    if env:
        return env
    if _is_writable_dir(HERE):
        return os.path.join(HERE, STORE_FILENAME)
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or HERE
    return os.path.join(base, "jiejieEAD", STORE_FILENAME)


def _empty_store() -> dict:
    return {"version": 1, "added": [], "hidden": [], "updated_at": ""}


def load_store(path: str | None = None) -> dict:
    p = path or user_store_path()
    if not os.path.isfile(p):
        return _empty_store()
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return _empty_store()
    out = _empty_store()
    if isinstance(data, dict):
        out["added"] = [x for x in (data.get("added") or []) if isinstance(x, dict) and x.get("id")]
        out["hidden"] = [str(x) for x in (data.get("hidden") or []) if x]
        out["updated_at"] = str(data.get("updated_at") or "")
    return out


def save_store(store: dict, path: str | None = None) -> str:
    """原子写：先写 .tmp 再 os.replace，避免半截文件（与知识库/配方同一纪律）。"""
    p = path or user_store_path()
    os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
    store["updated_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(store, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, p)
    return p


BUILTIN_IDS = {x["id"] for x in LOGICS} | {x["id"] for x in COMPOSITES} | \
    {x["id"] for x in FEATURE_RULES}


def normalize_user_item(raw: dict) -> dict:
    """把用户提交的条目规整成与内置逻辑同构的结构（缺字段给默认值）。"""
    if not isinstance(raw, dict):
        raise cc.CryptoUsageError("逻辑条目必须是 JSON 对象")
    lid = str(raw.get("id") or "").strip()
    name = str(raw.get("name") or "").strip()
    if not name:
        raise cc.CryptoUsageError("必须提供名称（name）")
    cat = str(raw.get("cat") or "user").strip().lower()
    if cat not in CATEGORY_DISPLAY:
        cat = "user"
    if not lid:
        # 用名称生成稳定 ID（同名重复添加会被后面判重拦下）
        slug = re.sub(r"[^\w\u4e00-\u9fff]+", "-", name.lower()).strip("-")[:40]
        lid = "user." + (slug or hashlib.md5(name.encode("utf-8")).hexdigest()[:8])
    if not lid.startswith("user."):
        # 用户条目统一带 user. 前缀，避免与内置 ID 撞车
        lid = "user." + lid
    return {
        "id": lid, "cat": cat, "name": name,
        "purpose": str(raw.get("purpose") or raw.get("note") or "（用户添加，未填写用途）"),
        "scene": str(raw.get("scene") or "（用户添加，未填写适用场景）"),
        "params": raw.get("params") if isinstance(raw.get("params"), dict) else {},
        "rel": raw.get("rel") if isinstance(raw.get("rel"), list) else [],
        "status": str(raw.get("status") or "supported"),
        "cli": str(raw.get("cli") or ""),
        "sample": str(raw.get("sample") or ""),
        "exec_kind": str(raw.get("exec_kind") or ""),
        "origin": "user",
        "source": str(raw.get("source") or ""),
        "created_at": str(raw.get("created_at") or
                          datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    }


def add_user_logic(raw: dict, path: str | None = None) -> dict:
    """新增一条用户逻辑（同名或同 ID 已存在则报错，不覆盖）。"""
    item = normalize_user_item(raw)
    store = load_store(path)
    if any(x.get("id") == item["id"] for x in store["added"]):
        raise cc.CryptoUsageError("该逻辑已存在：%s（如需修改请先删除再添加）" % item["id"])
    if item["id"] in BUILTIN_IDS:
        raise cc.CryptoUsageError("ID 与内置逻辑冲突：%s" % item["id"])
    store["added"].append(item)
    p = save_store(store, path)
    return {"ok": True, "item": item, "store": p,
            "added_total": len(store["added"]), "hidden_total": len(store["hidden"])}


def remove_logic(logic_id: str, path: str | None = None) -> dict:
    """删除一条逻辑：用户自建的真删；内置的记 hidden 标记（可恢复）。"""
    lid = str(logic_id or "").strip()
    if not lid:
        raise cc.CryptoUsageError("必须提供要删除的逻辑 ID")
    store = load_store(path)
    before = len(store["added"])
    store["added"] = [x for x in store["added"] if x.get("id") != lid]
    if len(store["added"]) != before:
        p = save_store(store, path)
        return {"ok": True, "kind": "user", "id": lid, "store": p}
    if lid in BUILTIN_IDS:
        if lid not in store["hidden"]:
            store["hidden"].append(lid)
        p = save_store(store, path)
        return {"ok": True, "kind": "builtin-hidden", "id": lid, "store": p}
    raise cc.CryptoUsageError("找不到该逻辑：%s" % lid)


def restore_logic(logic_id: str, path: str | None = None) -> dict:
    """恢复被隐藏的内置逻辑。"""
    lid = str(logic_id or "").strip()
    store = load_store(path)
    if lid not in store["hidden"]:
        raise cc.CryptoUsageError("该逻辑没有被隐藏：%s" % lid)
    store["hidden"] = [x for x in store["hidden"] if x != lid]
    p = save_store(store, path)
    return {"ok": True, "id": lid, "store": p}


def user_entries() -> dict:
    """返回用户存储的现状：新增了哪些、隐藏了哪些内置。"""
    store = load_store()
    hidden = [x for x in store["hidden"] if x in BUILTIN_IDS]
    hidden_detail = []
    for lid in hidden:
        it = _find(lid)
        hidden_detail.append({"id": lid, "name": (it or {}).get("name", lid)})
    return {"store": user_store_path(), "added": store["added"],
            "hidden": hidden_detail, "updated_at": store.get("updated_at", "")}


# ============================================================================
# 四、能力盘点
# ============================================================================
def stats() -> dict:
    merged = _merged_logics()
    comps = _merged_composites()
    store = load_store()
    cats: dict[str, int] = {}
    for it in merged:
        cats[it["cat"]] = cats.get(it["cat"], 0) + 1
    return {
        "logic_total": len(merged),
        "user_added": len(store["added"]),
        "builtin_hidden": len([x for x in store["hidden"] if x in BUILTIN_IDS]),
        "composite_total": len(comps),
        "feature_total": len(FEATURE_RULES),
        "per_category": cats,
        "supported": sum(1 for x in merged if x["status"] == S),
        "partial": sum(1 for x in merged if x["status"] == P),
        "unsupported": sum(1 for x in merged if x["status"] == N),
    }


def catalog() -> dict:
    merged = _merged_logics()
    comps = _merged_composites()
    return {
        "categories": [{"id": c, "name": n, "hint": h,
                        "count": sum(1 for x in merged if x["cat"] == c)
                                 + (len(comps) if c == "composite" else 0)
                                 + (len(FEATURE_RULES) if c == "feature" else 0)
                                 + (sum(1 for x in merged
                                        if x.get("origin") == "user") if c == "user" else 0)}
                       for c, n, h in CATEGORIES],
        "logics": merged,
        "composites": comps,
        "features": FEATURE_RULES,
        "stats": stats(),
        "status_display": {S: "已支持", P: "部分支持", N: "未支持"},
        "user": user_entries(),
    }


def _merged_logics() -> list[dict]:
    """内置逻辑 + 用户新增，剔除被隐藏的（用户条目统一打 origin=user）。"""
    store = load_store()
    hidden = set(store["hidden"])
    out: list[dict] = []
    for x in LOGICS:
        if x["id"] in hidden:
            continue
        out.append(dict(x, origin="builtin"))
    # 用户条目按分类插入到列表末尾（同分类内保持添加顺序）
    # 注意：cat=composite 的用户条目由 _merged_composites() 负责，这里跳过，
    # 否则同一条会在 items() 里出现两次（实测踩过）。
    for x in store["added"]:
        if x["id"] in hidden or x.get("cat") == "composite":
            continue
        out.append(dict(x, origin="user"))
    return out


def _merged_composites() -> list[dict]:
    store = load_store()
    hidden = set(store["hidden"])
    out = [dict(x, origin="builtin") for x in COMPOSITES if x["id"] not in hidden]
    for x in store["added"]:
        if x.get("cat") == "composite" and x["id"] not in hidden:
            out.append(dict(x, origin="user"))
    return out


def _all_items() -> list[dict]:
    """总览的完整条目集（含用户自建），顺序：原子逻辑 → 组合配方 → 特征规则。"""
    logics = _merged_logics()
    comps = _merged_composites()
    # 用户条目里 cat=composite 的已进 comps，这里把非 composite 的用户条目也并入 logics
    user_extra = [x for x in logics if x.get("origin") == "user"]
    base = [x for x in logics if x.get("origin") != "user"]
    return base + comps + user_extra + list(FEATURE_RULES)


def items(cat: str = "", q: str = "") -> list[dict]:
    """按分类 / 关键词筛选（logics + composites + features 一起返回）。"""
    out: list[dict] = []
    user_added = load_store()["added"]
    if not cat or cat == "composite":
        for u in user_added:
            if u.get("cat") == "composite":
                out.append(dict(u, cat="composite",
                                params=u.get("params") or {},
                                cli=u.get("cli") or "",
                                exec_kind=u.get("exec_kind") or "user",
                                rel=u.get("rel") or []))
        out.extend([dict(x, cat="composite", purpose=x["note"],
                         scene=x["frame"], params={"分层": x["layers"]},
                         cli=("cipher_auto_solver.py --file <密文> --target-dir <目标目录>"
                              if x.get("sample") else ""),
                         status=S, rel=["frame.*"], exec_kind="composite", sample=x.get("sample", ""))
                    for x in COMPOSITES])
    if not cat or cat == "feature":
        out.extend([dict(x, cat="feature", name=x["feature"], purpose=x["conclusion"],
                         scene="识别阶段：先判形态再选逻辑", params={"优先试": x["try"]},
                         cli="crypto_logic_registry.py --match --text <密文>", status=S,
                         rel=x["try"], exec_kind="feature", sample="")
                    for x in FEATURE_RULES])
    if not cat or cat not in ("composite", "feature"):
        out.extend([x for x in _merged_logics() if not cat or x["cat"] == cat])
    if q:
        ql = q.lower()
        def hit(x):
            blob = json.dumps(x, ensure_ascii=False).lower()
            return ql in blob
        out = [x for x in out if hit(x)]
    return out


# ============================================================================
# 五、密文特征分析 + 反向匹配
# ============================================================================
def analyze_features(text: str) -> dict:
    """从一段密文里量化出可判定的特征（不猜算法，只测事实）。"""
    raw = (text or "").strip()
    flat = re.sub(r"\s", "", raw)
    f: dict = {"raw_len": len(raw), "flat_len": len(flat), "facts": [], "notes": []}

    def mark(name, value, desc):
        f[name] = value
        f["facts"].append({"name": name, "value": value, "desc": desc})

    mark("is_json", raw.startswith("{") and raw.endswith("}"),
         "整段 JSON（可能是混合信封）")
    mark("has_hash_prefix", "#" in raw, "含 `#`（可能是自定义报文框架前缀）")
    mark("has_http", "\n\n" in raw or "\r\n\r\n" in raw, "像整段 HTTP 报文")
    mark("has_url_escape", bool(re.search(r"%[0-9A-Fa-f]{2}", flat)), "含 %XX URL 转义")
    mark("has_b64url_char", bool(re.search(r"[-_]", flat)), "含 `-` 或 `_`（Base64URL 特征）")
    pure_hex = (len(flat) >= 32 and len(flat) % 2 == 0
                and bool(re.fullmatch(r"[0-9a-fA-F]+", flat)))
    mark("pure_hex", pure_hex, "整体是纯十六进制串")
    mark("hex32_prefix", bool(re.fullmatch(r"[0-9a-fA-F]{32}", flat[:32] or "")),
         "以 32 位 hex 开头（候选种子 / 种子前置）")
    mark("mod4", len(flat) % 4, "长度 %4（≠0 且无以 = 结尾 → 去填充 Base64）")
    mark("ends_with_pad", flat.endswith("="), "以 `=` 结尾（标准 Base64 填充）")

    # 解码后的字节数（按最可能的编码试）
    dec, enc = None, ""
    if pure_hex:
        try:
            dec, enc = bytes.fromhex(flat), "hex"
        except ValueError:
            pass
    if dec is None:
        dec = _b64(flat)
        if dec is not None:
            enc = "base64"
    if dec is not None:
        mark("decoded_len", len(dec), "按 %s 解码后的字节数" % enc)
        mark("decoded_mod16", len(dec) % 16, "解码后长度 %16（0 → 可能是分组密码）")
        mark("decoded_mod8", len(dec) % 8, "解码后长度 %8（0 → 可能是 DES/3DES）")
        mark("decoded_printable", _printable_ratio(dec) >= 0.9,
             "解码后基本可打印（→ 里面还套着一层编码）")
        magic = cc.looks_compressed(dec)
        mark("decoded_compression", magic or "", "解码后像压缩数据（魔数嗅探）")
    # tail 44 字符像 mac 吗
    if len(flat) >= 44:
        tail = flat[-44:]
        if re.fullmatch(r"[A-Za-z0-9+/=]{44}", tail):
            try:
                n = len(base64.b64decode(tail + "=" * ((-len(tail)) % 4), validate=True))
                mark("tail44_bytes", n, "末尾 44 字符 Base64 解出 %d 字节（32 → 像 mac）" % n)
            except (binascii.Error, ValueError):
                pass
    return f


def _b64(t: str) -> bytes | None:
    s = re.sub(r"\s", "", t or "").replace("-", "+").replace("_", "/")
    s += "=" * ((-len(s)) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return ok / len(data)


def match_features(text: str) -> dict:
    """贴一段密文 → 按特征反推该优先试哪些逻辑。"""
    f = analyze_features(text)
    hits: list[dict] = []

    def on(rule_id, cond, extra=""):
        if cond:
            r = next(x for x in FEATURE_RULES if x["id"] == rule_id)
            hits.append({"rule": rule_id, "feature": r["feature"],
                         "conclusion": r["conclusion"], "try": r["try"],
                         "how": r["how"], "extra": extra})

    on("f01", f.get("decoded_mod16") == 0 and not f.get("decoded_printable"))
    on("f02", f.get("decoded_mod16") not in (None, 0) or f.get("decoded_printable"))
    on("f07", f.get("pure_hex"))
    on("f08", f.get("has_b64url_char") or (f.get("mod4") in (2, 3) and not f.get("ends_with_pad")))
    on("f09", f.get("has_url_escape"))
    on("f10", bool(f.get("decoded_compression")),
       "嗅探到：%s" % f.get("decoded_compression", ""))
    on("f12", f.get("is_json"))
    on("f13", f.get("tail44_bytes") == 32)
    on("f16", "data:image" in text or "base64," in text)
    on("f17", bool(re.search(r'(key|KEY|Key)\s*[:=]\s*["\'][ -~]{16}["\']', text)))
    on("f19", f.get("decoded_mod16") == 0)

    # 去重 + 给出建议执行顺序
    seen, uniq = set(), []
    for h in hits:
        if h["rule"] in seen:
            continue
        seen.add(h["rule"])
        uniq.append(h)
    plan = []
    for h in uniq:
        for t in h["try"]:
            if t not in plan:
                plan.append(t)
    return {"features": f, "matched": uniq,
            "suggested_order": plan,
            "next_step": ("直接用一键解密跑一遍（它会按上面顺序自动试）"
                          if uniq else "特征不典型，建议直接贴给一键解密，并补充目标源码目录")}


# ============================================================================
# 六、执行（按指定逻辑试算）
# ============================================================================
def _find(item_id: str) -> dict | None:
    for x in LOGICS:
        if x["id"] == item_id:
            return x
    for x in COMPOSITES:
        if x["id"] == item_id:
            return x
    return None


def apply_logic(item_id: str, *, text: str = "", op: str = "dec", key: str = "",
                key_format: str = cc.KEY_HEX, iv: str = "", iv_format: str = cc.KEY_HEX,
                alg: str = "", mode: str = "", padding: str = "",
                aad: str = "", chain: str = "", algo: str = "",
                public_key: str = "", private_key: str = "",
                wrapped_key: str = "", recipient: str = "sm2",
                seed: str = "", seed_format: str = cc.KEY_UTF8,
                derive_key: str = "", derive_iv: str = "",
                slice_range: str = "", oneline: bool = True) -> dict:
    """按某条逻辑对 text 执行操作（能算就算，算不了就说清缺什么）。"""
    item = _find(item_id)
    name = item["name"] if item else item_id
    out: dict = {"id": item_id, "name": name, "op": op, "ok": False,
                 "result": "", "result_hex": "", "trace": [], "error": ""}
    data = text.encode("utf-8")

    try:
        cc.check_dependencies()
        iid = item_id

        # ---- 组合配方 / 报文框架 / 特征：交给一键解密流水线 ----
        # 注意：这里**不能**写 iid.startswith("c") —— 那会把 chain.* / compress.*
        # 也当成组合配方（c01…）送进自动流水线，静默走错分支（实测踩过）。
        is_composite_like = (item is None
                             or bool(item and item.get("cat") in ("composite", "feature"))
                             or iid.startswith("frame."))
        if is_composite_like:
            if iid.startswith("frame."):
                # 这些只做形态分析
                try:
                    import cipher_auto_solver as cas
                    if iid.startswith("frame."):
                        frames = cas.detect_frames(text)
                        out.update({"ok": True, "result": json.dumps(
                            [{"kind": x["kind"], "label": x["label"]} for x in frames],
                            ensure_ascii=False), "trace": ["形态识别（不涉及密钥）"]})
                        return out
                except Exception:  # noqa: BLE001
                    pass
            try:
                import cipher_auto_solver as cas
                res = cas.auto_solve(text)
                out["trace"].append("一键解密流水线：形态 → 材料 → 配方 → 试解 → 打分")
                if res.get("status") == "ok":
                    best = res.get("best") or {}
                    out.update({"ok": True, "result": best.get("plain", ""),
                                "result_hex": "", "confidence": best.get("confidence")})
                else:
                    out["error"] = res.get("summary", "未解出")
                return out
            except Exception as exc:  # noqa: BLE001
                out["error"] = "需要一键解密模块：%s" % exc
                return out

        # ---- 摘要 ----
        if iid.startswith("digest."):
            raw = cc.do_digest(iid.split(".", 1)[1], data)
            out.update({"ok": True, "result": raw.hex(), "result_hex": raw.hex()})
            return out

        # ---- HMAC ----
        if iid.startswith("hmac.") and iid not in ("hmac.auto", "hmac.scope"):
            algo_id = iid.split(".", 1)[1]
            if not key:
                out["error"] = "HMAC 需要 --key"
                return out
            kb = cc.parse_key_material(key, key_format)
            raw = cc.do_hmac(algo_id, kb, data)
            out.update({"ok": True, "result": _b64_or_hex(raw), "result_hex": raw.hex()})
            out["trace"].append("HMAC 输出 %d 字节，Base64 后 %d 字符"
                                % (len(raw), len(_b64_or_hex(raw))))
            return out

        # ---- 编码 / 多级链 ----
        if iid.startswith("encoding.") or iid.startswith("chain."):
            steps = [s for s in (chain or "").split(",") if s] or _chain_steps(iid)
            if not steps:
                out["error"] = "请用 --chain 指定编码步骤，如 --chain base64 或 --chain hex,base64"
                return out
            if op == "enc":
                res = cc.encode_chain(data, steps)
            else:
                # 这里**不要**先调用 _input_bytes 再 decode_chain —— 那就是解了两遍
                # （求解器那边踩过同一个「双重解码」的坑：先解一次 + 链里再解一次）
                res = cc.decode_chain((text or "").encode("utf-8"), steps)
            out.update({"ok": True, "result": _safe_text(res), "result_hex": res.hex()})
            out["trace"].append("编码链 %s（%s）" % ("+".join(steps), "编码" if op == "enc" else "解码"))
            return out

        # ---- 压缩 ----
        if iid.startswith("compress."):
            a = algo or (iid.split(".", 1)[1] if "." in iid else "zlib")
            if a not in cc.COMPRESS_ALGOS:
                a = "zlib"
            if op == "enc":
                res = cc.do_compress(data, a)
            else:
                res = cc.do_decompress(_input_bytes(text, iid), a)
            out.update({"ok": True, "result": _safe_text(res), "result_hex": res.hex()})
            out["trace"].append("%s %s 完成，输出 %d 字节" % (a, "压缩" if op == "enc" else "解压", len(res)))
            return out

        # ---- 派生 ----
        if iid.startswith("kdf."):
            preset = iid.split(".", 1)[1]
            if preset == "slice":
                out["error"] = "slice 是派生链的一步，请配合 --derive 使用，如 --derive digest-sha256 --slice 0:16"
                return out
            if not seed:
                out["error"] = "派生需要 --seed（种子）"
                return out
            s0, s1 = _parse_slice(slice_range)
            steps = cc.build_kdf_steps(preset, key=derive_key, iv=derive_iv,
                                       key_format=cc.KEY_UTF8, iv_format=cc.KEY_UTF8,
                                       slice_start=s0, slice_end=s1)
            r = cc.derive_key(seed, steps, seed_format)
            out.update({"ok": True, "result": r["output_hex"], "result_hex": r["output_hex"],
                        "trace": ["%s → %d 字节" % (preset, r["output_len"])]
                                 + [("%s %s → %d 字节 %s…" % (st.get("op"),
                                                              st.get("detail", ""),
                                                              st.get("out_len", 0),
                                                              (st.get("out_preview") or "")[:16]))
                                    for st in (r.get("trace") or [])]})
            return out

        # ---- 非对称 ----
        if iid == "asym.keygen":
            a = (algo or "sm2").to_dict() if False else (algo or "sm2")
            if a.startswith("rsa"):
                bits = int(a.split(":")[1]) if ":" in a else 2048
                out.update({"ok": True, "result": json.dumps(cc.rsa_keygen(bits),
                                                             ensure_ascii=False)})
            else:
                out.update({"ok": True, "result": json.dumps(cc.sm2_keygen(),
                                                             ensure_ascii=False)})
            return out
        if iid in ("asym.sm2", "asym.sm2-sign", "asym.rsa", "asym.rsa-sign"):
            return _apply_asym(iid, out, text, op, key, public_key, private_key,
                               wrapped_key, mode, algo)
        if iid.startswith("envelope."):
            if uid := None:  # noqa: F841
                pass
            return _apply_envelope(iid, out, text, op, public_key, private_key,
                                   wrapped_key, recipient, alg, mode, padding, iv)

        # ---- 对称加解密（含 algo.* / mode.* / padding.* 都归到这条路）----
        alg_id = alg or _default_alg(iid)
        m = mode or _default_mode(iid)
        p = padding or _default_padding(iid, m)
        if not alg_id:
            out["error"] = "这条逻辑需要 --alg 指定算法（如 --alg sm4）"
            return out
        spec = cc.get_spec(alg_id)
        if m == "stream" and not spec.is_stream:
            m = spec.modes[0]
        if not spec.is_stream and m == "stream":
            m = "cbc"
        if not key:
            out["error"] = "加解密需要 --key（密钥文本），可用 --key-format 指定解释方式"
            return out
        if not iv and m not in (cc.MODE_ECB,) and not spec.is_stream and m != cc.MODE_GCM:
            out["trace"].append("未提供 IV → 该模式需要 IV，先按全零试（老接口确实这么写）")
            iv = "00" * spec.block
        res = cc.do_crypt(alg_id, op, key, (iv or None),
                          _input_bytes(text, iid, alg_id, key_format, m) if op == "dec" else data,
                          mode=m, padding=p, aad=aad.encode("utf-8"),
                          key_format=key_format, iv_format=iv_format, warn_weak=False)
        # 加密方向一律给 Base64（与 CLI 默认 --encoding base64 一致）并附 HEX。
        # 否则二进制密文会被 _safe_text 转成 HEX 显示，用户再把它贴回来当 Base64 解就错位了。
        out.update({"ok": True, "result_hex": res.hex(),
                    "result": (base64.b64encode(res).decode("ascii") if op == "enc"
                               else _safe_text(res))})
        out["trace"].append("%s/%s/%s %s完成，输出 %d 字节"
                            % (alg_id.upper(), m.upper(), p.upper(),
                               "加密" if op == "enc" else "解密", len(res)))
        return out
    except Exception as exc:  # noqa: BLE001
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
        return out


def _apply_asym(iid, out, text, op, key, public_key, private_key, wrapped_key, mode, algo):
    try:
        if "rsa" in iid:
            if op == "enc":
                r = cc.do_rsa("enc", data=text.encode("utf-8"), key_text=public_key or key,
                              padding=(cc.RSA_OAEP if (mode == "oaep") else cc.RSA_PKCS1V15))
            elif op == "sign":
                r = cc.do_rsa("sign", message=text.encode("utf-8"), key_text=private_key or key,
                              scheme=(cc.RSA_PSS if mode == "pss" else cc.RSA_PKCS1V15))
            elif op == "verify":
                ok = cc.do_rsa("verify", message=text.encode("utf-8"),
                               sig=bytes.fromhex(wrapped_key), key_text=public_key or key)
                out.update({"ok": True, "result": "验签通过" if ok else "验签失败"})
                return out
            else:
                r = cc.do_rsa("dec", data=_input_bytes(text, iid), key_text=private_key or key,
                              padding=(cc.RSA_OAEP if (mode == "oaep") else cc.RSA_PKCS1V15))
            out.update({"ok": True, "result": _safe_text(r) if not isinstance(r, bytes) or
                        len(r) < 4096 else "", "result_hex": r.hex() if isinstance(r, bytes) else ""})
            out["trace"].append("RSA %s 完成（%s）" % (op, mode or "pkcs1v15"))
            return out
        cm = cc.SM2_C1C2C3 if mode == "c1c2c3" else cc.SM2_C1C3C2
        if op == "enc":
            r = cc.do_sm2("enc", data=text.encode("utf-8"), public_key=public_key or key,
                          cipher_mode=cm)
            out.update({"ok": True, "result": r.hex(), "result_hex": r.hex()})
        elif op == "sign":
            r = cc.do_sm2("sign", message=text.encode("utf-8"),
                          private_key=private_key or key, cipher_mode=cm)
            out.update({"ok": True, "result": r if isinstance(r, str) else r.hex()})
        elif op == "verify":
            ok = cc.do_sm2("verify", message=text.encode("utf-8"), sig=wrapped_key,
                           public_key=public_key or key)
            out.update({"ok": True, "result": "验签通过" if ok else "验签失败"})
        else:
            r = cc.do_sm2("dec", data=_input_bytes(text, iid), private_key=private_key or key,
                          cipher_mode=cm)
            out.update({"ok": True, "result": _safe_text(r), "result_hex": r.hex()})
        out["trace"].append("SM2 %s 完成（%s）" % (op, cm))
        return out
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
        return out


def _apply_envelope(iid, out, text, op, public_key, private_key, wrapped_key,
                    recipient, alg, mode, padding, iv):
    try:
        if iid == "envelope.checks":
            out["error"] = "这是「解封结果校验」规则本身，不是可执行操作；它在信封解密流程内自动生效"
            return out
        if op == "enc":
            r = cc.envelope_encrypt(text.encode("utf-8"), recipient=recipient,
                                    public_key=public_key,
                                    symmetric=alg or "sm4",
                                    mode=mode or cc.MODE_ECB,
                                    padding=padding or cc.PAD_PKCS7)
            out.update({"ok": True, "result": json.dumps(r, ensure_ascii=False),
                        "result_hex": r.get("cipher_hex", ""),
                        "trace": ["信封生成：%s 包裹 %s 密钥；返回里含 wrapped_key_hex 与 cipher_hex"
                                  % (recipient.upper(), str(r.get("symmetric", "")).upper())]})
            return out
        r = cc.envelope_decrypt(recipient=recipient, wrapped_key=wrapped_key,
                                cipher=text, private_key=private_key,
                                symmetric=alg or "sm4", mode=mode or cc.MODE_ECB,
                                padding=padding or cc.PAD_PKCS7,
                                input_format=("base64" if _looks_b64(text) else "hex"))
        out.update({"ok": True, "result": _safe_text(r), "result_hex": r.hex()})
        out["trace"].append("信封解开：%s 私钥解封包裹密钥 → 还原明文" % recipient.upper())
        return out
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
        return out


def _chain_steps(iid: str) -> list[str]:
    """返回**编码顺序**的步骤（与 crypto_core.encode_chain 的口径一致）。"""
    return {
        "chain.base64": ["base64"],
        "chain.base64-twice": ["base64", "base64"],
        "chain.base64-then-hex": ["base64", "hex"],
        "chain.base64-then-url": ["base64", "url"],
        "chain.hex-then-base64": ["hex", "base64"],
        "encoding.base64": ["base64"],
        "encoding.base64url": ["base64url"],
        "encoding.hex": ["hex"],
        "encoding.url": ["url"],
        "encoding.raw": [],
    }.get(iid, [])


def _input_bytes(text: str, iid: str, alg: str = "", key_format: str = "",
                 mode: str = "") -> bytes:
    """解密方向的输入：把密文文本变成字节。

    注意顺序：**纯 HEX 必须先于 Base64 判** —— 纯 hex 串也满足 Base64 字符集，
    先按 Base64 解会得到一堆垃圾（求解器那边踩过同一个坑）。
    """
    t = re.sub(r"\s", "", text or "")
    if t and len(t) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", t):
        return bytes.fromhex(t)
    b = _b64(t)
    if b is not None and t and re.fullmatch(r"[A-Za-z0-9+/=_-]+", t):
        return b
    return (text or "").encode("utf-8")


def _default_alg(iid: str) -> str:
    return iid.split(".", 1)[1] if iid.startswith("algo.") else ""


def _default_mode(iid: str) -> str:
    """默认模式：mode.* 取自身；algo.* 按算法给合理默认（流密码给 stream，其余 cbc）。"""
    if iid.startswith("mode."):
        return iid.split(".", 1)[1]
    if iid.startswith("algo."):
        alg = iid.split(".", 1)[1]
        try:
            return "stream" if cc.get_spec(alg).is_stream else cc.MODE_CBC
        except Exception:  # noqa: BLE001
            return cc.MODE_CBC
    return ""


def _default_padding(iid: str, mode: str) -> str:
    if iid.startswith("padding."):
        return iid.split(".", 1)[1]
    return cc.PAD_NONE if mode in cc.STREAM_LIKE_MODES else cc.PAD_PKCS7


def _parse_slice(s: str) -> tuple[int | None, int | None]:
    if not s or ":" not in s:
        return None, None
    a, b = s.split(":", 1)
    return (int(a) if a.strip() else None, int(b) if b.strip() else None)


def _looks_b64(text: str) -> bool:
    t = re.sub(r"\s", "", text or "")
    return (len(t) >= 16 and bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", t))
            and not re.fullmatch(r"[0-9a-fA-F]+", t))


def _b64_or_hex(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _safe_text(data: bytes) -> str:
    try:
        t = data.decode("utf-8")
        return t if all(c.isprintable() or c in "\r\n\t" for c in t) else data.hex()
    except UnicodeDecodeError:
        return data.hex()


# ============================================================================
# 七、导出 Markdown
# ============================================================================
def export_markdown() -> str:
    L: list[str] = []
    st = stats()
    L.append("## 附录 A · 工具加解密逻辑全量清单（自动导出，勿手改）\n")
    L.append("> 由 `crypto_logic_registry.py --export-md` 生成；与工具实际能力同源，")
    L.append("> 改代码后重跑即可刷新。共 %d 条原子逻辑 / %d 条组合配方 / %d 条特征规则"
             "（其中用户添加 %d 条，已隐藏内置 %d 条）。\n"
             % (st["logic_total"], st["composite_total"], st["feature_total"],
                st.get("user_added", 0), st.get("builtin_hidden", 0)))
    for cid, cname, chint in CATEGORIES:
        if cid == "user":
            urows = load_store()["added"]
            if not urows:
                continue
            L.append("\n### A.%d %s（%d 条 · 用户添加）\n"
                     % (CATEGORIES.index((cid, cname, chint)) + 1, cname, len(urows)))
            L.append("| 逻辑 ID | 名称 | 用途 | 来源 | 添加时间 |")
            L.append("|---|---|---|---|---|")
            for x in urows:
                L.append("| `%s` | %s | %s | %s | %s |"
                         % (x["id"], x["name"], str(x.get("purpose", "")).replace("\n", " "),
                            x.get("source") or "手工添加", x.get("created_at", "")))
            continue
        rows = [x for x in _merged_logics() if x["cat"] == cid]
        if cid == "composite":
            L.append("\n### A.%d %s（%d 条）\n" % (CATEGORIES.index((cid, cname, chint)) + 1,
                                                  cname, len(COMPOSITES)))
            L.append("| # | 配方 | 报文形态 | 分层逻辑 | 说明 | 样本 |")
            L.append("|---|---|---|---|---|---|")
            for x in COMPOSITES:
                L.append("| %s | %s | %s | %s | %s | %s |"
                         % (x["id"], x["name"], x["frame"],
                            "<br>".join("① ② ③ ④ ⑤ ⑥ ⑦ ⑧ ⑨ ⑩".split()[i].strip() + " "
                                        + s for i, s in enumerate(x["layers"])),
                            x["note"], x["sample"] or "—"))
            continue
        if cid == "feature":
            L.append("\n### A.%d %s（%d 条）\n" % (CATEGORIES.index((cid, cname, chint)) + 1,
                                                  cname, len(FEATURE_RULES)))
            L.append("| # | 密文特征 | 结论 | 优先试 | 怎么试 |")
            L.append("|---|---|---|---|---|")
            for x in FEATURE_RULES:
                L.append("| %s | %s | %s | %s | %s |"
                         % (x["id"], x["feature"], x["conclusion"],
                            "、".join(x["try"]), x["how"]))
            continue
        if not rows:
            continue
        L.append("\n### A.%d %s（%d 条）\n" % (CATEGORIES.index((cid, cname, chint)) + 1,
                                              cname, len(rows)))
        L.append("| 逻辑 ID | 名称 | 用途 | 适用场景 | 与其他逻辑的关系 | 状态 | 样本 |")
        L.append("|---|---|---|---|---|---|---|")
        for x in rows:
            L.append("| `%s` | %s | %s | %s | %s | %s | %s |"
                     % (x["id"], x["name"], x["purpose"].replace("\n", " "),
                        x["scene"].replace("\n", " "),
                        "、".join(x["rel"]) or "—",
                        {"supported": "✅", "partial": "⚠️", "unsupported": "❌"}[x["status"]],
                        x["sample"] or "—"))
    return "\n".join(L) + "\n"


# ============================================================================
# 八、自检
# ============================================================================
def _selftest() -> int:
    ok_n = fail = 0

    def check(name, cond, extra=""):
        nonlocal ok_n, fail
        if cond:
            ok_n += 1
            print("   [ OK ] %s" % name)
        else:
            fail += 1
            print("   [ !! ] %s %s" % (name, extra))

    print("=" * 78)
    print(" 加密逻辑登记表 自检")
    print("=" * 78)
    cat = catalog()
    check("分类数 = %d" % len(CATEGORIES), len(cat["categories"]) == len(CATEGORIES))
    check("逻辑条目 > 60（实际 %d）" % cat["stats"]["logic_total"],
          cat["stats"]["logic_total"] > 60)
    empty_cats = [c["id"] for c in cat["categories"] if c["count"] == 0]
    # `user` 是用户自建分类，默认可以是空的，不算缺项
    check("每个分类都有条目（gap 也算，user 除外）",
          [x for x in empty_cats if x != "user"] == [], str(empty_cats))
    check("存在「用户添加」分类（供自定义逻辑归位）",
          "user" in [c["id"] for c in cat["categories"]])
    check("所有逻辑 ID 唯一",
          len({x["id"] for x in LOGICS}) == len(LOGICS))
    check("每条逻辑都有用途与适用场景",
          all(x["purpose"] and x["scene"] for x in LOGICS))
    check("内置组合配方定义 19 条（实际 %d）" % len(COMPOSITES), len(COMPOSITES) == 19)
    check("生效的组合配方数 = 内置 - 已隐藏 + 用户新增",
          cat["stats"]["composite_total"] == len(COMPOSITES)
          - sum(1 for x in load_store()["hidden"] if x in {c["id"] for c in COMPOSITES})
          + sum(1 for x in load_store()["added"] if x.get("cat") == "composite"),
          cat["stats"]["composite_total"])
    check("特征规则定义 18 条（实际 %d）" % len(FEATURE_RULES), len(FEATURE_RULES) == 18)
    check("每条特征规则都给了解读与试法",
          all(x["conclusion"] and x["try"] and x["how"] for x in FEATURE_RULES))

    # 筛选
    only_algo = items("algo")
    check("按分类筛选可用（algo 定义 17 条，生效 %d 条）" % len(only_algo),
          len([x for x in LOGICS if x["cat"] == "algo"]) == 17
          and all(x["cat"] == "algo" for x in only_algo))
    check("关键词筛选可用（SM4）",
          any("sm4" in x["id"] for x in items(q="SM4")))
    check("关键词筛选命中中文说明",
          any(x["id"] == "envelope.sm2" for x in items(q="安全键盘")))

    # 特征分析 + 匹配（用「定长常量 + 密文 + mac」的合成报文）
    sample = ("REQ#" + base64.b64encode(
        b"12c14a244b84be04c60933da198be3dd4a7f2c1e9b3d5a08c6b1d90e37f2a485007").decode()
        + base64.b64encode(b"x" * 48).decode() + base64.b64encode(b"m" * 32).decode())
    f = analyze_features(sample)
    check("特征分析识别出 `#` 框架", f.get("has_hash_prefix") is True)
    check("特征分析识别出末尾 44 字符 mac（32 字节）", f.get("tail44_bytes") == 32,
          str(f.get("tail44_bytes")))
    m = match_features(sample)
    check("反向匹配给出了候选规则", len(m["matched"]) >= 1, str(len(m["matched"])))
    check("反向匹配给出建议顺序", len(m["suggested_order"]) >= 1)

    hex_only = bytes.fromhex("00112233445566778899001122334455" * 8).hex().upper()
    fh = analyze_features(hex_only)
    check("纯 HEX 被识别", fh.get("pure_hex") is True and fh.get("decoded_mod16") == 0)
    check("纯 HEX 匹配到 f07", any(h["rule"] == "f07" for h in match_features(hex_only)["matched"]))

    zl = base64.b64encode(cc.do_compress(b'{"a":1}', "zlib")).decode()
    fz = analyze_features(zl)
    check("压缩魔数嗅探在特征里体现（zlib）", fz.get("decoded_compression") == "zlib",
          str(fz.get("decoded_compression")))

    # 执行：对称
    enc = apply_logic("algo.sm4", text="hello 汇总", op="enc",
                      key="00112233445566778899aabbccddeeff")
    check("按 algo.sm4 加密可执行", enc["ok"], enc.get("error"))
    dec = apply_logic("algo.sm4", text=enc["result"], op="dec",
                      key="00112233445566778899aabbccddeeff")
    check("按 algo.sm4 解密还原一致",
          dec["ok"] and dec["result"] == "hello 汇总", dec.get("error") or dec.get("result"))

    # 执行：摘要 / HMAC
    dg = apply_logic("digest.sm3", text="abc")
    check("SM3 摘要 = 标准向量",
          dg["ok"] and dg["result"] == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
          dg.get("result"))
    hm = apply_logic("hmac.hmac-sm3", text="abc", key="6b6579", key_format=cc.KEY_HEX)
    check("HMAC-SM3 可执行且输出 44 字符 Base64", hm["ok"] and len(hm["result"]) == 44,
          hm.get("result"))

    # 执行：派生
    kd = apply_logic("kdf.digest-sha256", seed="5f2c1a9b8e7d6c5b4a39281706f5e4d3",
                     slice_range="0:16")
    check("派生 SHA256(seed)[0:16] 恰好 16 字节（slice 生效）",
          kd["ok"] and len(kd["result_hex"]) == 32, kd.get("result_hex"))
    kd2 = apply_logic("kdf.digest-sha256", seed="x")
    check("派生不带 slice 给全 32 字节", kd2["ok"] and len(kd2["result_hex"]) == 64)

    # 执行：编码链 / 压缩
    ce = apply_logic("chain.base64-then-hex", text="hello", op="enc")
    cd = apply_logic("chain.base64-then-hex", text=ce["result"], op="dec")
    check("多级编码链加解密往返一致", cd["ok"] and cd["result"] == "hello",
          cd.get("error") or cd.get("result"))
    cp = apply_logic("compress.gzip", text="hello" * 20, op="enc")
    dp = apply_logic("compress.gzip", text=cp["result_hex"], op="dec", algo="gzip")
    check("gzip 压缩可执行", cp["ok"], cp.get("error"))
    check("按 hex 通道解压回原文（压缩任一路径可复核）",
          dp["ok"] and "hello" in dp["result"], dp.get("error") or dp.get("result")[:40])

    # 执行：非对称信封（SM2 端到端）
    kp = cc.sm2_keygen()
    ev = apply_logic("envelope.sm2", text='{"a":1}', op="enc", recipient="sm2",
                     public_key=kp["public_key"], alg="sm4", mode="ecb")
    check("SM2 信封加密可执行", ev["ok"], ev.get("error"))
    if ev["ok"]:
        pkg = json.loads(ev["result"])
        dv = apply_logic("envelope.sm2", text=pkg.get("cipher_hex", ""), op="dec",
                         recipient="sm2", private_key=kp["private_key"],
                         wrapped_key=pkg.get("wrapped_key_hex", ""))
        check("SM2 信封解密还原一致", dv["ok"] and dv["result"] == '{"a":1}',
              dv.get("error") or dv.get("result"))

    # 缺参数要给人话
    miss = apply_logic("algo.sm4", text="x", op="dec")
    check("缺密钥时给可读提示而不是抛异常",
          miss["ok"] is False and "需要 --key" in miss["error"], miss.get("error"))

    # ---- 15. 用户自建逻辑：新增 / 去重 / 删除（内置隐藏）/ 恢复 / 持久化 ----
    import tempfile
    tmp_store = os.path.join(tempfile.mkdtemp(prefix="jiejie_logic_"), "user.json")
    _prev_store = os.environ.get("JIEJIE_LOGIC_STORE")
    os.environ["JIEJIE_LOGIC_STORE"] = tmp_store      # 自检隔离，不污染真实存储
    try:
        before_total = stats()["logic_total"]
        r_add = add_user_logic({"name": "自检用自定义逻辑", "cat": "composite",
                                "purpose": "自检", "scene": "自检",
                                "params": {"算法": "SM4", "模式": "ECB"}})
        check("新增用户逻辑成功且落盘", r_add["ok"] and os.path.isfile(tmp_store),
              r_add.get("store"))
        hit = items(q="自检用自定义逻辑")
        check("新增后立刻出现在清单里，且只出现一次",
              len(hit) == 1 and hit[0]["origin"] == "user",
              "%d 条: %s" % (len(hit), [x["id"] for x in hit]))
        check("用户条目计入组合配方数",
              stats()["composite_total"] == 20, stats()["composite_total"])
        try:
            add_user_logic({"name": "自检用自定义逻辑", "cat": "composite"})
            check("重复添加被拦下", False, "竟然成功了")
        except cc.CryptoUsageError:
            check("重复添加被拦下", True)
        r_rm = remove_logic("algo.rc4")
        check("删除内置 → 记为隐藏", r_rm["kind"] == "builtin-hidden", r_rm.get("kind"))
        check("隐藏后不再出现在清单里",
              not any(x["id"] == "algo.rc4" for x in items(q="RC4")))
        remove_logic(r_add["item"]["id"])
        check("删除用户条目 → 彻底移除",
              not any(x["id"] == r_add["item"]["id"] for x in load_store()["added"]))
        restore_logic("algo.rc4")
        check("恢复内置 → 重新出现在清单里",
              any(x["id"] == "algo.rc4" for x in items(q="RC4")))
        check("落盘文件是合法 JSON 且含 added/hidden",
              set(load_store().keys()) >= {"added", "hidden"})
        # 重开一次（重新读盘）验证持久化
        add_user_logic({"name": "自检持久化验证", "cat": "gap"})
        reloaded = load_store()
        check("重新读盘后条目仍在（真持久化）",
              any(x["name"] == "自检持久化验证" for x in reloaded["added"]))
        check("统计里能看到用户添加数",
              stats()["user_added"] >= 1, stats()["user_added"])
    finally:
        if _prev_store is None:
            os.environ.pop("JIEJIE_LOGIC_STORE", None)
        else:
            os.environ["JIEJIE_LOGIC_STORE"] = _prev_store
        try:
            os.remove(tmp_store)
        except OSError:
            pass

    # 导出
    md = export_markdown()
    check("Markdown 导出包含全部三段（原子/组合/特征）",
          "附录 A" in md and "端到端组合配方" in md and "密文特征" in md)
    # 导出的是"生效视图"（内置 - 隐藏 + 用户新增），所以按同一口径比对
    expect_ids = [x["id"] for x in _merged_logics()]
    missing = [x for x in expect_ids if ("`%s`" % x) not in md]
    check("Markdown 导出覆盖全部生效逻辑（%d 条，每条都带 ID 单元格）" % len(expect_ids),
          not missing, str(missing[:5]))

    print("-" * 78)
    if fail:
        print(" [FAIL] %d 项未通过。" % fail)
        return 2
    print(" [PASS] 加密逻辑登记表自检全部通过（%d 项：分类 / 清单 / 反查 / 执行 / 导出）。" % ok_n)
    return 0


# ============================================================================
# 九、CLI
# ============================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="crypto_logic_registry.py",
        description="工具加解密逻辑总览：清单 / 反查 / 试算 / 导出",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n"
               "  crypto_logic_registry.py --list --cat envelope\n"
               "  crypto_logic_registry.py --match --text \"REQ#...\"\n"
               "  crypto_logic_registry.py --apply algo.sm4 --text 明文 --key <hex> --op enc\n"
               "  crypto_logic_registry.py --export-md --out 逻辑清单.md\n")
    p.add_argument("--list", action="store_true", help="列出全部逻辑")
    p.add_argument("--cat", help="按分类筛选：%s" % "/".join(c[0] for c in CATEGORIES))
    p.add_argument("--q", help="关键词筛选（会搜用途/场景/参数等全部字段）")
    p.add_argument("--features", action="store_true", help="只列密文特征规则表")
    p.add_argument("--stats", action="store_true", help="只输出统计")
    p.add_argument("--match", action="store_true", help="贴密文 → 按特征反推该试哪些逻辑")
    p.add_argument("--apply", metavar="逻辑ID", help="按指定逻辑对密文/明文执行操作")
    p.add_argument("--op", default="dec", choices=["enc", "dec", "sign", "verify"],
                   help="操作方向，默认 dec")
    p.add_argument("--text", help="密文或明文")
    p.add_argument("--file", help="从文件读入 --text")
    p.add_argument("--key", help="密钥文本（格式见 --key-format）")
    p.add_argument("--key-format", default=cc.KEY_HEX,
                   choices=list(cc.KEY_FORMATS), help="密钥解释方式，默认 hex")
    p.add_argument("--iv", help="IV / nonce")
    p.add_argument("--iv-format", default=cc.KEY_HEX, choices=list(cc.KEY_FORMATS))
    p.add_argument("--alg", help="算法（当逻辑本身没绑定时用，如 --alg sm4）")
    p.add_argument("--mode", help="模式（如 cbc / oaep / pss / c1c2c3）")
    p.add_argument("--padding", help="填充")
    p.add_argument("--aad", help="GCM AAD")
    p.add_argument("--chain", help="编码链步骤，逗号分隔，如 hex,base64")
    p.add_argument("--algo", help="压缩算法 / 密钥对类型（zlib / gzip / sm2 / rsa:2048）")
    p.add_argument("--public-key", help="公钥（SM2 hex / RSA PEM）")
    p.add_argument("--private-key", help="私钥")
    p.add_argument("--wrapped-key", help="信封里的包裹密钥（解密时）/ 签名字节（verify 时）")
    p.add_argument("--recipient", default="sm2", choices=["sm2", "rsa"])
    p.add_argument("--seed", help="派生种子")
    p.add_argument("--seed-format", default=cc.KEY_UTF8, choices=list(cc.KEY_FORMATS))
    p.add_argument("--derive-key", help="派生步骤里用的密钥")
    p.add_argument("--derive-iv", help="派生步骤里用的 IV")
    p.add_argument("--slice", dest="slice_range", help="派生取区间，如 0:16 / 16:32")
    p.add_argument("--export-md", action="store_true", help="导出 Markdown 逻辑清单")
    p.add_argument("--user-add", action="store_true",
                   help="新增一条用户逻辑（配合 --logic-json，或 --text 传 JSON）")
    p.add_argument("--logic-json", help="逻辑条目的 JSON（--user-add 用）")
    p.add_argument("--user-remove", metavar="逻辑ID",
                   help="删除一条逻辑：用户自建的真删；内置的记为隐藏（可恢复）")
    p.add_argument("--user-restore", metavar="逻辑ID", help="恢复被隐藏的内置逻辑")
    p.add_argument("--user-list", action="store_true", help="查看用户添加 / 隐藏的现状")
    p.add_argument("--store", help="用户逻辑存储文件路径（默认脚本目录下 crypto_logic_user.json）")
    p.add_argument("--out", help="导出路径（不指定则打印到终端）")
    p.add_argument("--json", action="store_true", help="以 JSON 输出")
    p.add_argument("--selftest", action="store_true", help="运行自检")
    return p


def _brief(x: dict) -> str:
    flag = {"supported": "✅", "partial": "⚠️", "unsupported": "❌"}.get(x["status"], "  ")
    line = "%s %-24s %s" % (flag, x["id"], x["name"])
    return line


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.selftest:
        return _selftest()
    text = args.text
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print("读取文件失败：%s" % exc, file=sys.stderr)
            return 2

    # ---- 用户自建逻辑：新增 / 删除 / 恢复 / 查看（都要落盘持久化）----
    if args.store:
        os.environ["JIEJIE_LOGIC_STORE"] = args.store
    try:
        if args.user_add:
            raw = args.logic_json or text or "{}"
            res = add_user_logic(json.loads(raw))
            if args.json:
                print(json.dumps(res, ensure_ascii=False))
            else:
                print("已添加：[%s] %s（存储：%s，当前用户条目 %d 条）"
                      % (res["item"]["id"], res["item"]["name"], res["store"],
                         res["added_total"]))
            return 0
        if args.user_remove:
            res = remove_logic(args.user_remove)
            if args.json:
                print(json.dumps(res, ensure_ascii=False))
            else:
                print("已删除：%s（%s，存储：%s）"
                      % (res["id"], "用户条目已彻底移除" if res["kind"] == "user"
                         else "内置条目已隐藏，可用 --user-restore 恢复", res["store"]))
            return 0
        if args.user_restore:
            res = restore_logic(args.user_restore)
            if args.json:
                print(json.dumps(res, ensure_ascii=False))
            else:
                print("已恢复内置逻辑：%s（存储：%s）" % (res["id"], res["store"]))
            return 0
        if args.user_list:
            data = user_entries()
            if args.json:
                print(json.dumps(data, ensure_ascii=False))
            else:
                print("用户逻辑存储：%s" % data["store"])
                print("新增条目：%d 条" % len(data["added"]))
                for x in data["added"]:
                    print("  + [%s] %s（来源：%s）"
                          % (x["id"], x["name"], x.get("source") or "手工"))
                print("已隐藏的内置条目：%d 条" % len(data["hidden"]))
                for x in data["hidden"]:
                    print("  - [%s] %s" % (x["id"], x["name"]))
            return 0
    except cc.CryptoUsageError as exc:
        print("[错误] %s" % exc, file=sys.stderr)
        return 1
    except ValueError as exc:
        print("[错误] JSON 解析失败：%s" % exc, file=sys.stderr)
        return 1

    if args.stats:
        print(json.dumps(stats(), ensure_ascii=False, indent=2))
        return 0

    if args.features:
        rows = FEATURE_RULES
        if args.json:
            print(json.dumps(rows, ensure_ascii=False))
            return 0
        for r in rows:
            print("%s  %s" % (r["id"], r["feature"]))
            print("      → %s" % r["conclusion"])
            print("      优先试：%s" % "、".join(r["try"]))
        return 0

    if args.match:
        if not text:
            print("--match 需要 --text 或 --file 提供密文", file=sys.stderr)
            return 1
        res = match_features(text)
        if args.json:
            print(json.dumps(res, ensure_ascii=False))
            return 0
        print("=" * 78)
        print(" 密文特征反查")
        print("=" * 78)
        print(" 量出的特征：")
        for fact in res["features"].get("facts", []):
            print("   · %-22s %s" % (fact["name"] + " = " + str(fact["value"]), fact["desc"]))
        print("-" * 78)
        if not res["matched"]:
            print(" 没有命中已知特征规则。")
        for h in res["matched"]:
            print(" [%s] %s" % (h["rule"], h["feature"]))
            print("      → %s" % h["conclusion"])
            print("      → %s" % h["how"])
        print("-" * 78)
        print(" 建议试解顺序：%s" % " → ".join(res["suggested_order"]) or "（无）")
        print(" 下一步：%s" % res["next_step"])
        return 0

    if args.apply:
        res = apply_logic(
            args.apply, text=text or "", op=args.op, key=args.key or "",
            key_format=args.key_format, iv=args.iv or "", iv_format=args.iv_format,
            alg=args.alg or "", mode=args.mode or "", padding=args.padding or "",
            aad=args.aad or "", chain=args.chain or "", algo=args.algo or "",
            public_key=args.public_key or "", private_key=args.private_key or "",
            wrapped_key=args.wrapped_key or "", recipient=args.recipient,
            seed=args.seed or "", seed_format=args.seed_format,
            derive_key=args.derive_key or "", derive_iv=args.derive_iv or "",
            slice_range=args.slice_range or "")
        if args.json:
            print(json.dumps(res, ensure_ascii=False))
        else:
            print("=" * 78)
            print(" %s（%s）" % (res["name"], res["op"]))
            print("=" * 78)
            for t in res["trace"]:
                print(" · %s" % t)
            if res["ok"]:
                print("-" * 78)
                print(res["result"])
                if res.get("result_hex") and res["result_hex"] != res["result"]:
                    print("-" * 78)
                    print("HEX: %s" % res["result_hex"])
            else:
                print("[失败] %s" % res["error"])
        return 0 if res["ok"] else 1

    if args.export_md:
        md = export_markdown()
        if args.out:
            with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(md)
            print("已导出：%s（%d 字符）" % (args.out, len(md)))
        else:
            print(md)
        return 0

    # 默认 / --list
    rows = items(args.cat or "", args.q or "")
    if args.json:
        print(json.dumps({"stats": stats(), "items": rows}, ensure_ascii=False))
        return 0
    print("=" * 78)
    print(" jiejieEAD 加解密逻辑总览")
    print("=" * 78)
    st = stats()
    print(" 原子逻辑 %d 条（已支持 %d / 部分支持 %d / 未支持 %d）·组合配方 %d 条 ·特征规则 %d 条"
          % (st["logic_total"], st["supported"], st["partial"], st["unsupported"],
             st["composite_total"], st["feature_total"]))
    print("-" * 78)
    cur = ""
    for x in rows:
        if x["cat"] != cur:
            cur = x["cat"]
            print("\n【%s】%s" % (CATEGORY_DISPLAY.get(cur, cur), CATEGORY_HINT.get(cur, "")))
        print("  " + _brief(x))
        print("      用途：%s" % x["purpose"].replace("\n", " ")[:96])
        print("      场景：%s" % x["scene"].replace("\n", " ")[:96])
        if x["rel"]:
            print("      关联：%s" % "、".join(x["rel"]))
    print("\n" + "-" * 78)
    print(" 提示：--match 贴密文反查 / --apply <逻辑ID> 试算 / --export-md 导出清单")
    return 0


if __name__ == "__main__":
    sys.exit(main())
