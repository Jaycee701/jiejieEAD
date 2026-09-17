#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jiejieEAD | 密钥材料分析（伪装常量解码 + 派生链识别）
================================================================================

补的是这一类真实目标的「前两步」：

  1. **伪装 base64 常量的自动解码**
     密钥常量很少老老实实写成 `KEY = "0123456789abcdef"`。更常见的写法是：
         · 伪装成图片/字体：`data:image/png;base64,MDEyMzQ1...`（解码出来根本不是 PNG）
         · 伪装成普通编码串：`var pubKey = "MTJjMTRhMjQ0Yjg0..."`（其实是 ASCII 文本）
         · 伪装成十六进制：32~64 位长 hex 串（解码后是文本）
         · 套两层的：base64 里还是 base64
     本模块把这些串**找出来、解开、判断是不是伪装、并按定长切成候选密钥/IV/种子**。

  2. **AES/SHA 派生链识别**
     密钥不是常量，而是算出来的：
         `master = SHA256(AES-CBC(seed, 常量A, 常量B))`；`正文密钥 = master[16:32]`
     本模块在 JS / Java / Python / Go / PHP 等代码里识别
         「对称加密 → 摘要 → 取字节区间」这条链，
     并把识别结果**翻译成 jiejieEAD Tab 8 可直接执行的派生配方**（--derive 命令）。

设计要点：
  · 纯静态、零网络、零第三方依赖（只用标准库）；
  · 代码与二进制一视同仁：`.class` / `.dex` / 无扩展名二进制先抽可打印串再分析
    （Java class 常量池里的字符串就是这么出来的）；
  · 所有结论都带 `evidence`（命中位置与原文片段），不做黑箱判断；
  · 误报控制：真 PNG 的 data URI 不会被当成"伪装"，纯随机 base64 不会当成文本。

用法：
  python key_material_analyzer.py --text "data:image/png;base64,MDEyMzQ1..."
  python key_material_analyzer.py --file  path/to/Config.class
  python key_material_analyzer.py --dir   path/to/project --deep
  python key_material_analyzer.py --file  x.jar --json
  python key_material_analyzer.py --selftest
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
import os
import re
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# ============================================================================
# 一、常量与阈值
# ============================================================================
MIN_B64_RUN = 24          # 短于这个长度的 base64 串不当作"常量"（噪声太多）
MIN_HEX_RUN = 32          # 长 hex 串的最低长度
MIN_STRING_RUN = 12       # 二进制里抽取可打印串的最低长度
# 真实代码里长常量常被换行或字符串拼接拆开（"AAA" +\n"BBB"），
# 片段之间只允许出现空白 / 引号 / 加号，才认定为"同一段常量被拆行"
MERGE_GAP_RE = re.compile(r'^[\s"\'+]*$')
MERGE_MAX_GAP = 40        # 片段之间允许的最大间隔（含缩进换行），间隔内容仍须是空白/引号/加号
PROSE_EXT = {".md", ".txt", ".rst", ".log"}   # 散文类文件：只找常量，不做派生链识别
MAX_CHAINS_PER_FILE = 5   # 单文件最多报几条链，避免刷屏
PRINTABLE_THRESHOLD = 0.90   # 解码后判定为"文本"的可打印比例
MAX_DECODE_BYTES = 64 * 1024  # 单个候选项最多解码这么多字节（防炸）

# 真文件魔数：用来判断"声明的类型"和"实际内容"是否对得上
MAGIC = {
    "png": (b"\x89PNG\r\n\x1a\n", b"\x89PNG"),
    "jpeg": (b"\xff\xd8\xff",),
    "jpg": (b"\xff\xd8\xff",),
    "gif": (b"GIF87a", b"GIF89a"),
    "webp": (b"RIFF",),
    "bmp": (b"BM",),
    "ico": (b"\x00\x00\x01\x00",),
    "svg": (b"<svg", b"<?xml", b"<SVG"),
    "pdf": (b"%PDF",),
    "woff": (b"wOFF",),
    "woff2": (b"wOF2",),
    "ttf": (b"\x00\x01\x00\x00", b"true"),
    "otf": (b"OTTO",),
    "zip": (b"PK\x03\x04", b"PK\x05\x06"),
    "gzip": (b"\x1f\x8b",),
    "mp4": (b"\x00\x00\x00",),
}

# 声明这类 MIME 时若内容对不上，几乎可以断定是"拿类型做伪装"
IMAGE_MIMES = ("image/", "font/", "application/font", "audio/", "video/", "application/pdf")

# 跳过的目录（与其它扫描器保持一致）
SKIP_DIRS = {
    "__pycache__", ".git", "node_modules", ".venv", "venv", "dist", "build",
    "target", ".idea", ".vscode", "Pods", ".mypy_cache", ".pytest_cache",
}
# 可直接按文本读的扩展名
TEXT_EXT = {
    ".js", ".mjs", ".cjs", ".ts", ".vue", ".jsx", ".tsx", ".html", ".htm", ".css",
    ".py", ".java", ".kt", ".go", ".php", ".rb", ".cs", ".c", ".h", ".cpp",
    ".json", ".xml", ".yaml", ".yml", ".ini", ".conf", ".cfg", ".properties",
    ".txt", ".md", ".sh", ".bat", ".ps1", ".gradle", ".smali",
}
# 需要先抽可打印串再分析的二进制/字节码
BINARY_EXT = {
    ".class", ".jar", ".dex", ".apk", ".aar", ".so", ".dll", ".exe", ".bin",
    ".dat", ".pak", ".node", ".wasm", ".pyc", ".zip",
}
# 深挖超时/体积保护
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_DEEP_FILES = 4000


# ============================================================================
# 二、基础工具
# ============================================================================
def printable_ratio(data: bytes) -> float:
    """可打印字符（含 \r\n\t）占比，用于判断解码结果是不是"文本"。"""
    if not data:
        return 0.0
    good = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return good / len(data)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def looks_hex(text: str) -> bool:
    t = text.strip()
    return bool(t) and len(t) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in t)


def b64_decode_tolerant(text: str) -> bytes | None:
    """容错 Base64 解码（补 '='、忽略空白与 URL-safe 变体）。"""
    cleaned = re.sub(r"[\s]", "", text or "")
    if not cleaned:
        return None
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    cleaned += "=" * ((-len(cleaned)) % 4)
    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", cleaned):
        return None
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return None


def decode_any(text: str) -> tuple[bytes | None, str]:
    """把一段文本当 base64 或 hex 解开，返回 (bytes, 方式)。"""
    raw = b64_decode_tolerant(text)
    if raw:
        return raw, "base64"
    if looks_hex(text):
        try:
            return bytes.fromhex(text.strip()), "hex"
        except ValueError:
            return None, ""
    return None, ""


def magic_ok(mime: str, data: bytes) -> bool | None:
    """声明的 MIME 与解码内容是否匹配。返回 None 表示无法判断。"""
    if not mime:
        return None
    key = mime.split("/")[-1].lower()
    key = key.split("+")[0].split(";")[0].strip()
    if key in ("x-icon", "vnd.microsoft.icon"):
        key = "ico"
    magics = MAGIC.get(key)
    if not magics:
        return None
    return any(data.startswith(m) for m in magics)


# ============================================================================
# 三、伪装 base64 常量：发现 + 解码 + 切片
# ============================================================================
# 注意：base64 段**不能**用 \s，否则会贪婪地跨行吞掉紧随其后的另一个 base64 串，
# 导致解码失败、整个 data URI 命中被丢弃（实测踩过这个坑）。
DATA_URI_RE = re.compile(
    r"data:(?P<mime>[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+)?"
    r"(?P<params>(?:;[A-Za-z0-9\-=.]+)*);base64,(?P<b64>[A-Za-z0-9+/=]{16,})"
)
# 裸 base64：前后不能紧邻 base64 字符，避免从长串中间截断
BARE_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")
HEX_RUN_RE = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{32,})(?![0-9A-Fa-f])")


def _candidate_from_bytes(raw: bytes, origin_kind: str, extra: dict) -> dict:
    """把一段解码结果整理成候选常量描述（含切片建议与是否像文本）。"""
    ratio = printable_ratio(raw)
    item = {
        "origin": origin_kind,
        "decoded_len": len(raw),
        "printable_ratio": round(ratio, 3),
        "entropy": round(shannon_entropy(raw[:4096]), 2),
        "is_text": ratio >= PRINTABLE_THRESHOLD,
        "decoded_hex": binascii.hexlify(raw[:64]).decode(),
        "decoded_text": None,
        "slices": [],
        "notes": [],
    }
    item.update(extra)

    if item["is_text"]:
        text = raw.decode("utf-8", errors="replace")
        item["decoded_text"] = text[:4000]
        # 二次编码：解码结果本身又是一个 base64/hex 串
        stripped = text.strip()
        if 16 <= len(stripped) <= 4096:
            inner, way = decode_any(stripped)
            if inner and printable_ratio(inner) >= PRINTABLE_THRESHOLD:
                item["nested"] = {
                    "way": way,
                    "decoded_len": len(inner),
                    "decoded_text": inner.decode("utf-8", errors="replace")[:2000],
                }
                item["notes"].append(
                    f"解码结果本身还是 {way}，已自动剥第二层（内层 {len(inner)} 字节文本）")
        # 高位可打印但熵很低 → 可能是 padding/填充噪音
        if len(set(raw)) <= 4 and len(raw) > 32:
            item["notes"].append("解码结果字符种类极少，可能是填充或占位数据，建议人工确认")
    else:
        item["notes"].append("解码结果不是文本（二进制），按原始字节看待")

    item["slices"] = suggest_slices(item["decoded_text"] or "")
    return item


def find_disguised_base64(text: str, origin: str = "") -> list[dict]:
    """在文本里找伪装 / 裸 base64 / 长 hex 常量，并给出解码与切片建议。"""
    found: list[dict] = []
    covered: list[tuple[int, int]] = []

    # ---- 1) data URI（最常见也最容易被当成图片跳过）----
    for m in DATA_URI_RE.finditer(text):
        mime = (m.group("mime") or "").strip()
        payload = m.group("b64")
        raw = b64_decode_tolerant(payload)
        if raw is None:
            continue
        covered.append((m.start(), m.end()))
        ok = magic_ok(mime, raw)
        disguised = (ok is False) or (ok is None and any(mime.startswith(p) for p in IMAGE_MIMES))
        item = _candidate_from_bytes(raw, "data-uri", {
            "_payload": payload.strip(), "_text": text,
            "span": [m.start(), m.end()],
            "disguise": "data-uri",
            "declared_mime": mime,
            "encoded_len": len(payload.strip()),
            "magic_ok": ok,
            "is_disguised": bool(disguised),
            "evidence": text[max(0, m.start() - 24): m.start() + 60].replace("\n", "\\n"),
        })
        if disguised:
            item["notes"].insert(
                0, f"⚠ 声明为 {mime or '未知 MIME'} 但内容不是该类型 —— 典型的「伪装常量」，"
                   f"解码后是 {len(raw)} 字节{'文本' if item['is_text'] else '二进制'}")
        found.append(item)

    # ---- 2) 裸 base64 串 ----
    for m in BARE_B64_RE.finditer(text):
        if any(s <= m.start() < e for s, e in covered):
            continue
        payload = m.group(1)
        raw = b64_decode_tolerant(payload)
        if raw is None or not raw:
            continue
        if printable_ratio(raw) < PRINTABLE_THRESHOLD:
            continue          # 纯二进制的裸 base64 误报率高，交给 data URI 路径
        covered.append((m.start(), m.end()))
        item = _candidate_from_bytes(raw, "bare-base64", {
            "_payload": payload.strip(), "_text": text,
            "span": [m.start(), m.end()],
            "disguise": "bare-base64",
            "declared_mime": "",
            "encoded_len": len(payload),
            "magic_ok": None,
            "is_disguised": True,
            "evidence": text[max(0, m.start() - 24): m.start() + 60].replace("\n", "\\n"),
        })
        item["notes"].insert(
            0, f"看起来是普通编码串，解码后是 {len(raw)} 字节可读文本 —— 常被当作「公钥/密钥常量」")
        found.append(item)

    # ---- 3) 长 hex 串 ----
    for m in HEX_RUN_RE.finditer(text):
        if any(s <= m.start() < e for s, e in covered):
            continue
        run = m.group(1)
        if run.lower().startswith(("0x",)):
            continue
        if len(run) % 2:
            run = run[:-1]          # 奇数长度的 hex 串无法按字节解码，去掉末位
        if len(run) < MIN_HEX_RUN:
            continue
        try:
            raw = bytes.fromhex(run)
        except ValueError:
            continue
        if printable_ratio(raw) < PRINTABLE_THRESHOLD:
            continue
        item = _candidate_from_bytes(raw, "hex-run", {
            "span": [m.start(), m.end()],
            "disguise": "hex-run",
            "declared_mime": "",
            "encoded_len": len(run),
            "magic_ok": None,
            "is_disguised": True,
            "evidence": text[max(0, m.start() - 24): m.start() + 60].replace("\n", "\\n"),
        })
        item["notes"].insert(0, f"长 HEX 串（{len(run)} 字符）解码后是 {len(raw)} 字节可读文本")
        found.append(item)

    return _merge_and_filter(found)


def _merge_and_filter(items: list[dict]) -> list[dict]:
    """把被换行 / '+' 拼接拆开的 base64 片段合回去，并去掉低价值重复项。

    真实代码里 92 个字符的常量经常写成：
        "MTJjMTRh...Q0QT" +
        "dGMkMxR...Nw=="
    不合并的话会得到两段都解不出完整文本的"半截常量"，反而误导人。
    """
    if not items:
        return items
    # ---- 1) 合并：按 span 排序，间隔仅含空白/引号/加号时拼起来重解 ----
    ordered = sorted(items, key=lambda x: x["span"][0])
    merged: list[dict] = []
    i = 0
    while i < len(ordered):
        cur = ordered[i]
        payload = cur.get("_payload") or ""
        span = list(cur["span"])
        j = i + 1
        fragment_count = 1
        while j < len(ordered):
            nxt = ordered[j]
            gap = (cur.get("_text") or "")[span[1]:nxt["span"][0]]
            if (nxt["span"][0] >= span[1] and len(gap) <= MERGE_MAX_GAP
                    and MERGE_GAP_RE.match(gap or "")):
                payload += nxt.get("_payload") or ""
                span[1] = nxt["span"][1]
                fragment_count += 1
                j += 1
                continue
            break
        if fragment_count > 1:
            raw = b64_decode_tolerant(payload)
            if raw and printable_ratio(raw) >= PRINTABLE_THRESHOLD:
                new_item = _candidate_from_bytes(raw, cur["origin"], {
                    "span": span,
                    "disguise": cur["disguise"],
                    "declared_mime": cur.get("declared_mime", ""),
                    "encoded_len": len(payload),
                    "magic_ok": cur.get("magic_ok"),
                    "is_disguised": True,
                    "evidence": (cur.get("_text") or "")[span[0]:min(span[1], span[0] + 80)],
                })
                new_item["notes"].insert(0, f"常量在原文里被换行/拼接拆成 {fragment_count} 段，已自动合并后解码")
                merged.append(new_item)
                i = j
                continue
        merged.append(cur)
        i += 1

    # ---- 2) 去重 + 过滤：同一解出文本只留置信度最高的一条 ----
    best: dict[tuple, dict] = {}
    for it in merged:
        text = it.get("decoded_text") or ""
        key = (text[:120], it.get("disguise"))
        if not text and it.get("decoded_len", 0) < 12:
            continue          # 太短且非文本，价值低
        prev = best.get(key)
        if prev is None or _item_score(it) > _item_score(prev):
            best[key] = it
    out = sorted(best.values(), key=lambda x: (-_item_score(x), x["span"][0]))
    for it in out:
        it.pop("_payload", None)
        it.pop("_text", None)
    return out


def _item_score(item: dict) -> int:
    """常量价值打分：解出文本 + 有切片建议 + 是伪装 的排在前面。"""
    score = 0
    if item.get("is_text"):
        score += 2
    if item.get("slices"):
        score += 3
    if item.get("is_disguised"):
        score += 1
    if item.get("nested"):
        score += 1
    score += min(item.get("decoded_len", 0) // 16, 5)
    return score


def suggest_slices(decoded_text: str) -> list[dict]:
    """按常见「种子 + 密钥 + IV + 后缀」拼法给出定长切片建议。

    真实常量串往往是把几样东西拼在一个字符串里，再靠 substring(a,b) 取用。
    对 67 字符这种典型长度，直接给出 32 / 16 / 16 / 3 的切法。
    """
    if not decoded_text:
        return []
    t = decoded_text
    n = len(t)
    out: list[dict] = []

    def add(start, end, role, reason):
        piece = t[start:end]
        if not piece:
            return
        out.append({
            "range": [start, end],
            "len": len(piece),
            "value": piece,
            "is_hex": looks_hex(piece),
            "role": role,
            "reason": reason,
            "candidate_key": len(piece) in (16, 24, 32),
        })

    if n == 67 and t[64:].isdigit():
        add(0, 32, "32hex 前缀（常见：业务号 / 种子 / wx）", "长度 67 = 32+16+16+3 的典型拼法")
        add(32, 48, "疑似 AES/SM4 密钥（16 字节）", "紧跟前缀之后的 16 字符")
        add(48, 64, "疑似 IV（16 字节）", "再往后 16 字符")
        add(64, 67, "固定后缀", "末尾三位数字，常为业务标识（如 001）")
    elif n == 64:
        add(0, 32, "32hex 前缀", "64 字符常为 32+16+16 或 32+32")
        add(32, 48, "疑似密钥（16 字节）", "")
        add(48, 64, "疑似 IV（16 字节）", "")
    elif n == 48:
        add(0, 32, "32hex 前缀", "")
        add(32, 48, "疑似密钥（16 字节）", "48 字符常为 32+16")
        add(0, 16, "疑似密钥（16 字节）", "也可能是 16+16+16 三段")
        add(16, 32, "疑似密钥/IV（16 字节）", "")
        add(32, 48, "疑似密钥/IV（16 字节）", "")
    elif n == 32:
        add(0, 16, "疑似密钥（16 字节）", "32 字符常为 16+16")
        add(16, 32, "疑似 IV（16 字节）", "")
    elif n == 16:
        add(0, 16, "疑似密钥或 IV（16 字节）", "整串就是一个 16 字节密钥材料")

    # 通用兜底：整体是长 hex 时，每 16 字节切一段
    if not out and looks_hex(t) and n >= 32:
        for i in range(0, n, 32):
            add(i, min(i + 32, n), f"第 {i // 32 + 1} 段（16 字节）", "整体为 hex，按 16 字节切分")
    return out


# ============================================================================
# 四、AES/SHA 派生链识别
# ============================================================================
DIGEST_MARKERS = [
    # 允许后缀：Sm3Util / SHA256Digest / md5Hex / sha256sum 都要能命中
    (r"\bsha-?256\w*", "sha256"),
    (r"\bsha-?512\w*", "sha512"),
    (r"\bsha-?1\w*", "sha1"),
    (r"\bmd5\w*", "md5"),
    (r"\bsm3\w*", "sm3"),
]
CIPHER_MARKERS = [
    (r"AES/CBC/[A-Za-z]+|CBC/PKCS5Padding|PKCS5Padding|PKCS7Padding", ("aes", "cbc")),
    (r"AES/ECB/[A-Za-z]+", ("aes", "ecb")),
    (r"aes-128-cbc|aes-192-cbc|aes-256-cbc|aes128|aes256|AES-128|AES-256", ("aes", "cbc")),
    (r"sm4-ecb|sm4\.ecb|SM4/ECB", ("sm4", "ecb")),
    (r"sm4-cbc|sm4\.cbc|SM4/CBC|SM4Cipher|CryptSM4|Sm4Util", ("sm4", "cbc")),
    (r"CryptoJS\.AES|CryptoJS\.SM4|Cipher\.getInstance|CipherFactory|"
     r"aesEncrypt|aesDecrypt|encryptByAES|decryptByAES|encryptData|sm4Encrypt", (None, None)),
]
SLICE_RE = re.compile(
    r"(?:\.substring\s*\(\s*(\d+)\s*(?:,\s*(\d+)\s*)?\)"
    r"|\.slice\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)"
    r"|copyOfRange\s*\(\s*[^,]+,\s*(\d+)\s*,\s*(\d+)\s*\)"
    r"|\.substr\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)"
    r"|\[\s*(\d+)\s*:\s*(\d+)\s*\])"
)
WINDOW = 600          # 判定"同一条链"的字符窗口


def _hits(text: str, markers) -> list[dict]:
    out = []
    for pat, tag in markers:
        for m in re.finditer(pat, text, re.I):
            out.append({"tag": tag, "span": (m.start(), m.end()), "text": m.group(0)})
    return sorted(out, key=lambda x: x["span"][0])


def find_derive_chains(text: str, origin: str = "") -> list[dict]:
    """在源码里识别「对称加密 → 摘要 → 取字节区间」派生链。

    只做"形态识别 + 证据留痕"，不做完整数据流分析：
    真实项目里变量名千变万化，能定位到"这一段在用派生"就已经足够人工接手。
    """
    chains: list[dict] = []
    digests = _hits(text, DIGEST_MARKERS)
    ciphers = _hits(text, CIPHER_MARKERS)
    if not digests:
        return chains

    for d in digests:
        near_ciphers = [c for c in ciphers if 0 < d["span"][0] - c["span"][0] <= WINDOW
                        or 0 < c["span"][0] - d["span"][0] <= 120]
        if not near_ciphers:
            continue
        c = max(near_ciphers, key=lambda x: x["span"][0])
        # 摘要之后的取字节区间（同一窗口内）
        slices = [s for s in SLICE_RE.finditer(text)
                  if 0 <= s.start() - d["span"][1] <= WINDOW]
        steps: list[dict] = []

        alg, mode = c["tag"] if isinstance(c["tag"], tuple) else (None, None)
        if not alg:
            seg = text[max(0, c["span"][0] - 60): c["span"][1] + 60].lower()
            if "sm4" in seg:
                alg, mode = "sm4", ("ecb" if "ecb" in seg else "cbc")
            elif "aes" in seg:
                alg, mode = "aes", ("ecb" if "ecb" in seg else "cbc")

        steps.append({
            "op": "encrypt",
            "alg": alg or "aes",
            "mode": mode or "cbc",
            "padding": "pkcs7",
            "detail": f"{ (alg or 'aes').upper() }-{(mode or 'cbc').upper()} 加密种子",
            "evidence": text[max(0, c["span"][0] - 40): c["span"][1] + 40].replace("\n", " ").strip(),
        })
        digest_tag = d["tag"] if isinstance(d["tag"], str) else "sha256"
        steps.append({
            "op": "digest",
            "alg": digest_tag,
            "detail": f"{digest_tag.upper()} 摘要（对上一段密文）",
            "evidence": text[max(0, d["span"][0] - 40): d["span"][1] + 40].replace("\n", " ").strip(),
        })
        if slices:
            s = slices[0]
            nums = [int(g) for g in s.groups() if g is not None]
            if len(nums) >= 2:
                start, end = nums[0], nums[1]
                steps.append({
                    "op": "slice",
                    "start": start,
                    "end": end,
                    "detail": f"取字节区间 [{start}:{end}]"
                              + ("（丢弃前 16 字节，取中段当密钥 —— 极常见的写法）"
                                 if start == 16 and end == 32 else ""),
                    "evidence": s.group(0),
                })

        confidence = 0.45
        tags = {_ for _ in [steps[0]["alg"]]}
        if slices:
            confidence += 0.2
        if any(k in text for k in ("substring", "slice", "copyOfRange")):
            confidence += 0.05
        if digest_tag == "sha256" and steps[0]["alg"] == "aes":
            confidence += 0.1

        preset = _preset_for(steps)
        chains.append({
            "origin": origin,
            "steps": steps,
            "confidence": round(min(confidence, 0.95), 2),
            "suggest_preset": preset,
            "suggest_cmd": _command_for(steps, preset),
            "evidence": [s["evidence"] for s in steps if s.get("evidence")][:3],
            "tags": sorted(tags),
        })
    # 去重（同一处可能被多个摘要标记命中）
    uniq: dict[tuple, dict] = {}
    for ch in chains:
        key = (ch["steps"][0]["evidence"][:60], ch["suggest_preset"])
        if key not in uniq or ch["confidence"] > uniq[key]["confidence"]:
            uniq[key] = ch
    return list(uniq.values())


def _preset_for(steps: list[dict]) -> str:
    """把识别出的链映射成 jiejieEAD Tab 8 的派生预设名。"""
    alg = (steps[0].get("alg") or "aes").lower()
    mode = (steps[0].get("mode") or "cbc").lower()
    digest = next((s.get("alg") for s in steps if s["op"] == "digest"), "sha256")
    has_slice = any(s["op"] == "slice" for s in steps)
    if alg == "aes" and mode == "cbc" and digest == "sha256":
        return "aes-cbc-then-sha256-slice" if has_slice else "aes-cbc-then-sha256"
    if alg == "sm4" and digest == "sm3":
        return "sm4-cbc-then-sm3"
    if steps[0]["op"] == "hmac":
        return f"hmac-{digest}"
    return f"digest-{digest}"


def _command_for(steps: list[dict], preset: str) -> str:
    """生成可直接执行的派生命令（占位符留给人工替换）。"""
    slice_step = next((s for s in steps if s["op"] == "slice"), None)
    cmd = ["cli_crypto.py", "--derive", preset, "--seed", "<种子，如报文里的 wx>"]
    if any(s["op"] in ("encrypt", "decrypt") for s in steps):
        cmd += ["--derive-key", "<加密常量A>", "--derive-key-format", "utf8",
                "--derive-iv", "<加密常量B>", "--derive-iv-format", "utf8"]
    if slice_step:
        cmd += ["--slice", f"{slice_step.get('start')}:{slice_step.get('end')}"]
    return " ".join(cmd)


def chain_from_cooccurrence(strings: list[str], origin: str = "") -> list[dict]:
    """二进制/字节码场景：只能靠"同一文件里同时出现"来推断派生链。

    .class / .dex 里没有可读的顺序信息，但常量池会同时留下
    `SHA-256`、`AES/CBC/PKCS5Padding`、伪装常量这些字符串。
    三者同现，基本可以判定该文件在做"派生出密钥"这件事。
    """
    blob = "\n".join(strings)
    digest_hit = next((tag for pat, tag in DIGEST_MARKERS if re.search(pat, blob, re.I)), None)
    cipher_hit = next(((pat, tag) for pat, tag in CIPHER_MARKERS if re.search(pat, blob, re.I)), None)
    if not (digest_hit and cipher_hit):
        return []
    alg, mode = cipher_hit[1]
    if not alg:
        seg = blob.lower()
        alg = "sm4" if "sm4" in seg else ("aes" if "aes" in seg else "aes")
        mode = "ecb" if "ecb" in seg.lower() else "cbc"
    steps = [
        {"op": "encrypt", "alg": alg, "mode": mode, "padding": "pkcs7",
         "detail": f"字节码中同时出现 {alg.upper()}/{mode.upper()} 与 {digest_hit.upper()} 标记",
         "evidence": f"{alg.upper()} + {digest_hit.upper()} 同现"},
        {"op": "digest", "alg": digest_hit,
         "detail": f"{digest_hit.upper()} 摘要",
         "evidence": "常量池标记"},
    ]
    preset = _preset_for(steps)
    return [{
        "origin": origin,
        "steps": steps,
        "confidence": 0.3,
        "suggest_preset": preset,
        "suggest_cmd": _command_for(steps, preset),
        "evidence": ["仅凭字节码常量池共现推断，具体顺序需人工确认（建议反编译核实）"],
        "tags": [digest_hit],
        "binary_hint": True,
    }]


# ============================================================================
# 五、文本 / 二进制 / 目录 分析入口
# ============================================================================
def extract_printable_strings(data: bytes, min_len: int = MIN_STRING_RUN) -> list[str]:
    """从二进制里抽可打印串（等价于 strings 命令，但纯 Python）。"""
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if 0x20 <= b <= 0x7E:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="replace"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="replace"))
    return out


def analyze_text(text: str, origin: str = "", from_binary: bool = False,
                 prose: bool = False) -> dict:
    disguised = find_disguised_base64(text, origin)
    # 散文（README / 说明文档）里满是"SM4、AES、SHA256"这类词，
    # 做链路识别只会刷屏；这类文件只用来找常量。
    chains = [] if prose else find_derive_chains(text, origin)[:MAX_CHAINS_PER_FILE]
    if from_binary:
        # 共现判定要用短门槛（SHA-256 只有 7 个字符），否则标记会被抽串步骤丢掉
        strings = extract_printable_strings(text.encode("utf-8", errors="ignore"), min_len=6)
        chains += chain_from_cooccurrence(strings, origin)
    return {
        "origin": origin,
        "disguised": disguised,
        "derive_chains": chains,
        "from_binary": from_binary,
    }


def is_probably_binary(path: str, head: bytes) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in BINARY_EXT:
        return True
    if b"\x00" in head:
        return True
    return False


def analyze_file(path: str) -> dict:
    """分析单个文件（源码 / 二进制 / zip 都支持）。"""
    ext = os.path.splitext(path)[1].lower()
    prose = ext in PROSE_EXT
    result = {"origin": path, "kind": "file", "disguised": [], "derive_chains": [],
              "inner": [], "notes": []}
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        result["notes"].append(f"读取失败：{exc}")
        return result

    # ---- zip / jar / apk：逐个条目分析（二进制条目先抽串）----
    if ext in (".zip", ".jar", ".apk", ".aar", ".whl"):
        try:
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > MAX_TEXT_BYTES:
                        continue
                    raw = zf.read(info)
                    inner_ext = os.path.splitext(info.filename)[1].lower()
                    label = f"{os.path.basename(path)}::{info.filename}"
                    if inner_ext in TEXT_EXT or not is_probably_binary(info.filename, raw[:4096]):
                        sub = analyze_text(raw.decode("utf-8", errors="replace"), label,
                                           prose=inner_ext in PROSE_EXT)
                    else:
                        strings = extract_printable_strings(raw, min_len=6)
                        sub = analyze_text("\n".join(strings), label, from_binary=True)
                    if sub["disguised"] or sub["derive_chains"]:
                        result["inner"].append(sub)
        except zipfile.BadZipFile as exc:
            result["notes"].append(f"不是合法 zip：{exc}")
        return result

    if size > MAX_TEXT_BYTES and ext not in BINARY_EXT:
        result["notes"].append(f"文件过大（{size} 字节），已跳过")
        return result

    with open(path, "rb") as fh:
        raw = fh.read(MAX_TEXT_BYTES if not is_probably_binary(path, b"") else 32 * 1024 * 1024)

    if is_probably_binary(path, raw[:4096]):
        # 抽串门槛用 6：常量有自己的长度门槛（base64≥24 / hex≥32），
        # 但 SHA-256、AES 这类**标记**只有 5~7 个字符，门槛太高会漏掉
        strings = extract_printable_strings(raw, min_len=6)
        result["kind"] = "binary"
        result["notes"].append(f"按二进制处理，抽出 {len(strings)} 条可打印串（含 class 常量池）")
        sub = analyze_text("\n".join(strings), path, from_binary=True)
        result["disguised"] = sub["disguised"]
        result["derive_chains"] = sub["derive_chains"]
    else:
        sub = analyze_text(raw.decode("utf-8", errors="replace"), path, prose=prose)
        result["disguised"] = sub["disguised"]
        result["derive_chains"] = sub["derive_chains"]
    if prose and not result["derive_chains"]:
        result["notes"].append("散文类文件不做派生链识别（避免 PRD/README 里的术语造成误报）")

    # ---- 把"解出来的密钥材料"和"派生链"绑定起来 ----
    bind_constants_to_chains(result)
    return result


def bind_constants_to_chains(result: dict) -> None:
    """若同一文件里既有伪装常量、又有派生链，尝试把切出来的常量填进配方占位符。

    这是本模块最有价值的一步：`SHA256(AES-CBC(seed, A, B))[16:32]` 里的 A、B
    往往就藏在同一个文件那条 67 字符的常量串里（32+16+16+3 切法）。
    """
    slices: list[dict] = []
    for item in result.get("disguised", []):
        for s in item.get("slices", []):
            s = dict(s)
            s["_source"] = item.get("origin", "")
            slices.append(s)
    if not slices:
        return
    key_like = [s for s in slices if s.get("candidate_key") and s["role"].find("密钥") >= 0]
    iv_like = [s for s in slices if s.get("candidate_key") and s["role"].find("IV") >= 0]
    for chain in result.get("derive_chains", []):
        if not any(s["op"] in ("encrypt", "decrypt") for s in chain["steps"]):
            continue
        filled = []
        if key_like:
            chain.setdefault("bound_constants", {})["derive_key"] = key_like[0]["value"]
            chain["bound_constants"]["derive_key_format"] = "utf8"
            filled.append(f"派生密钥 ← 常量切片[{key_like[0]['range'][0]}:{key_like[0]['range'][1]}]")
        if iv_like:
            chain.setdefault("bound_constants", {})["derive_iv"] = iv_like[0]["value"]
            chain["bound_constants"]["derive_iv_format"] = "utf8"
            filled.append(f"派生 IV ← 常量切片[{iv_like[0]['range'][0]}:{iv_like[0]['range'][1]}]")
        if filled:
            chain["confidence"] = min(0.95, chain["confidence"] + 0.25)
            chain["bound_note"] = "；".join(filled) + "（同文件内的常量自动绑定）"
            chain["suggest_cmd"] = _command_from_binding(chain)


def _command_from_binding(chain: dict) -> str:
    b = chain.get("bound_constants") or {}
    cmd = ["cli_crypto.py", "--derive", chain["suggest_preset"],
           "--seed", "<种子，如报文里的 wx>"]
    if b.get("derive_key"):
        cmd += ["--derive-key", b["derive_key"], "--derive-key-format", b.get("derive_key_format", "utf8")]
    if b.get("derive_iv"):
        cmd += ["--derive-iv", b["derive_iv"], "--derive-iv-format", b.get("derive_iv_format", "utf8")]
    sl = next((s for s in chain["steps"] if s["op"] == "slice"), None)
    if sl:
        cmd += ["--slice", f"{sl.get('start')}:{sl.get('end')}"]
    return " ".join(cmd)


def analyze_dir(root: str, deep: bool = False) -> dict:
    out = {"origin": root, "kind": "dir", "files": [], "disguised": [], "derive_chains": [],
           "notes": [], "scanned": 0}
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if count >= MAX_DEEP_FILES:
                out["notes"].append(f"文件数超过 {MAX_DEEP_FILES}，已截断")
                return out
            path = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            if ext and ext not in TEXT_EXT and ext not in BINARY_EXT:
                if not deep:
                    continue
            count += 1
            res = analyze_file(path)
            out["scanned"] += 1
            if res["disguised"] or res["derive_chains"] or res["inner"]:
                out["files"].append(res)
                out["disguised"].extend(res["disguised"])
                out["derive_chains"].extend(res["derive_chains"])
                for sub in res["inner"]:
                    out["disguised"].extend(sub["disguised"])
                    out["derive_chains"].extend(sub["derive_chains"])
    return out


# ============================================================================
# 六、自检
# ============================================================================
def _selftest() -> int:
    print("=" * 78)
    print(" 密钥材料分析自检（伪装常量解码 + 派生链识别）")
    print("=" * 78)
    fails = 0

    def check(name, cond, extra=""):
        nonlocal fails
        if cond:
            print(f"   [ OK ] {name}")
        else:
            print(f"   [ !! ] {name}" + (f"\n          {extra}" if extra else ""))
            fails += 1

    # ---- 1. 伪装 data URI（合成常量，与任何真实目标无关）----
    real_uri = ("data:image/png;base64,MTJjMTRhMjQ0Yjg0YmUwNGM2MDkzM2RhMTk4YmUzZGQ0QT"
                "dGMkMxRTlCM0Q1QTA4QzZCMUQ5MEUzN0YyQTQ4NTAwNw==")
    hits = find_disguised_base64(real_uri)
    check("真伪装常量被识别为 data URI", len(hits) == 1 and hits[0]["disguise"] == "data-uri")
    h = hits[0] if hits else {}
    check("判定为伪装（声明 PNG 但不是 PNG）", h.get("is_disguised") is True)
    check("解码出 67 字符文本", h.get("decoded_len") == 67 and h.get("is_text"))
    check("解码内容与标准答案一致",
          h.get("decoded_text") == "12c14a244b84be04c60933da198be3dd4A7F2C1E9B3D5A08C6B1D90E37F2A485007",
          h.get("decoded_text"))
    slices = {tuple(s["range"]): s for s in h.get("slices", [])}
    check("按 32/16/16/3 给出切片建议", set(slices) == {(0, 32), (32, 48), (48, 64), (64, 67)})
    check("切片[32:48] 被标为疑似密钥",
          slices.get((32, 48), {}).get("value") == "4A7F2C1E9B3D5A08"
          and slices[(32, 48)]["candidate_key"] is True)
    check("切片[48:64] 被标为疑似 IV", slices.get((48, 64), {}).get("value") == "C6B1D90E37F2A485")
    check("切片[64:67] 被标为固定后缀", slices.get((64, 67), {}).get("value") == "007")

    # ---- 2. 真 PNG 不误报 ----
    real_png = ("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
                "AAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==")
    p = find_disguised_base64(real_png)
    check("真 PNG data URI 不被判为伪装", len(p) == 1 and p[0]["is_disguised"] is False,
          str(p[0].get("magic_ok")) if p else "无命中")

    # ---- 3. 裸 base64 文本常量 ----
    bare = "var pubKey = 'MDEyMzQ1Njc4OWFiY2RlZmZlZGNiYTk4NzY1NDMyMTA=';"
    b = find_disguised_base64(bare)
    check("裸 base64 常量被识别", any(x["disguise"] == "bare-base64" for x in b))
    check("解码出 32 字符文本",
          any((x.get("decoded_text") or "").startswith("0123456789abcdef") for x in b))

    # ---- 4. 两层 base64 ----
    inner = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
    outer = base64.b64encode(inner.encode()).decode()
    n = find_disguised_base64(f"K = '{outer}'")
    check("双层 base64 被自动剥第二层",
          any(x.get("nested", {}).get("decoded_text", "").startswith("0123456789abcdef") for x in n))

    # ---- 5. 长 hex 文本常量 ----
    hx = binascii.hexlify(b"4A7F2C1E9B3D5A08C6B1D90E37F2A485").decode()
    hh = find_disguised_base64(f"const K = '{hx}'")
    check("长 HEX 文本常量被识别", any(x["disguise"] == "hex-run" for x in hh))
    check("HEX 解码出 32 字符文本",
          any((x.get("decoded_text") or "") == "4A7F2C1E9B3D5A08C6B1D90E37F2A485" for x in hh))

    # ---- 6. 派生链：JS 顺序写法（真实前端的常见形态）----
    js = """
    var wx = getWx();
    var master = aesEncrypt(wx, '4A7F2C1E9B3D5A08', 'C6B1D90E37F2A485', {mode:'cbc'});
    master = CryptoJS.SHA256(master);
    var bodyKey = master.substring(16, 32);
    """
    chains = find_derive_chains(js)
    check("JS 顺序写法识别出派生链", len(chains) >= 1)
    c0 = chains[0] if chains else {}
    ops = [s["op"] for s in c0.get("steps", [])]
    check("链路包含 加密 → 摘要 → 取区间", ops == ["encrypt", "digest", "slice"], str(ops))
    check("映射到预设 aes-cbc-then-sha256-slice",
          c0.get("suggest_preset") == "aes-cbc-then-sha256-slice", c0.get("suggest_preset"))
    check("识别出取 [16:32]", any(s.get("start") == 16 and s.get("end") == 32
                              for s in c0.get("steps", [])))
    check("生成的命令含 --derive 与 --slice",
          "--derive aes-cbc-then-sha256-slice" in c0.get("suggest_cmd", "")
          and "--slice 16:32" in c0.get("suggest_cmd", ""), c0.get("suggest_cmd"))

    # ---- 7. 派生链：Java 嵌套 + copyOfRange ----
    java = """
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    byte[] m = MessageDigest.getInstance("SHA-256").digest(c.doFinal(seed));
    byte[] key = Arrays.copyOfRange(m, 16, 32);
    """
    jc = find_derive_chains(java)
    check("Java 写法（getInstance/copyOfRange）识别出派生链", len(jc) >= 1)
    check("Java 链同样映射到 -slice 预设",
          any(x["suggest_preset"] == "aes-cbc-then-sha256-slice" for x in jc))

    # ---- 8. 派生链：SM4 + SM3 变体 ----
    sm = "byte[] m = Sm3Util.hash(Sm4Util.encrypt(seed, key, iv));"
    sc = find_derive_chains(sm)
    check("SM4+SM3 变体识别出链路", len(sc) >= 1)
    check("变体映射到 sm4-cbc-then-sm3 预设",
          any(x["suggest_preset"] == "sm4-cbc-then-sm3" for x in sc),
          str([x["suggest_preset"] for x in sc]))

    # ---- 9. 无派生链的普通代码不误报 ----
    plain = "function md5(s){ return hex(s); } var x = md5('abc');"
    check("纯摘要（无加密）不报派生链", find_derive_chains(plain) == [])

    # ---- 10. 二进制：class 常量池 ----
    cls = (b"\xca\xfe\xba\xbe\x00\x00\x00\x34" +
           b"\x12data:image/png;base64,MTJjMTRhMjQ0Yjg0YmUwNGM2MDkzM2RhMTk4YmUzZGQ0QT"
           b"dGMkMxRTlCM0Q1QTA4QzZCMUQ5MEUzN0YyQTQ4NTAwNw==" +
           b"\x00\x01SHA-256\x00\x01AES/CBC/PKCS5Padding")
    # 真实路径里二进制抽串门槛是 6（见 analyze_file），自检保持一致
    strings = extract_printable_strings(cls, min_len=6)
    check("二进制里抽出 class 常量池字符串",
          any("data:image" in s for s in strings) and any(s == "SHA-256" for s in strings))
    bin_res = analyze_text("\n".join(strings), "Config.class", from_binary=True)
    check("二进制场景仍能解出伪装常量", len(bin_res["disguised"]) == 1)
    check("二进制场景给出派生链线索（常量池共现）",
          any(c.get("binary_hint") for c in bin_res["derive_chains"]),
          str([c.get("confidence") for c in bin_res["derive_chains"]]))

    # ---- 11. 常量与派生链自动绑定 ----
    both = {
        "disguised": [{"origin": "Config.class", "slices": [
            {"range": [32, 48], "len": 16, "value": "4A7F2C1E9B3D5A08", "candidate_key": True,
             "role": "疑似 AES/SM4 密钥（16 字节）", "is_hex": False, "reason": "", "value_": ""},
            {"range": [48, 64], "len": 16, "value": "C6B1D90E37F2A485", "candidate_key": True,
             "role": "疑似 IV（16 字节）", "is_hex": False, "reason": "", "value_": ""},
        ]}],
        "derive_chains": [{"steps": [{"op": "encrypt", "alg": "aes", "mode": "cbc"},
                                     {"op": "digest", "alg": "sha256"},
                                     {"op": "slice", "start": 16, "end": 32}],
                           "confidence": 0.3, "suggest_preset": "aes-cbc-then-sha256-slice",
                           "suggest_cmd": ""}],
    }
    bind_constants_to_chains(both)
    ch = both["derive_chains"][0]
    check("常量被自动绑定为派生密钥", (ch.get("bound_constants") or {}).get("derive_key") == "4A7F2C1E9B3D5A08")
    check("常量被自动绑定为派生 IV", (ch.get("bound_constants") or {}).get("derive_iv") == "C6B1D90E37F2A485")
    check("绑定后置信度提升", ch["confidence"] > 0.3)
    check("绑定后的命令已填入真实常量",
          "4A7F2C1E9B3D5A08" in ch["suggest_cmd"] and "C6B1D90E37F2A485" in ch["suggest_cmd"],
          ch["suggest_cmd"])

    print("-" * 78)
    if fails:
        print(f" [FAIL] {fails} 项未通过。")
        return 2
    print(" [PASS] 密钥材料分析自检全部通过（伪装常量 / 切片 / 派生链 / 二进制 / 自动绑定）。")
    return 0


# ============================================================================
# 七、CLI
# ============================================================================
def _emit(result: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, ensure_ascii=False))
        return

    def show_disguised(items, indent="  "):
        for i, it in enumerate(items, 1):
            tag = "伪装" if it.get("is_disguised") else "明文"
            print(f"{indent}[{i}] {tag} · {it.get('disguise')}"
                  f" · 声明 {it.get('declared_mime') or '-'}"
                  f" · 解出 {it.get('decoded_len')} 字节"
                  f"（可打印 {it.get('printable_ratio')}）")
            if it.get("decoded_text"):
                print(f"{indent}    文本：{it['decoded_text'][:90]}")
            if it.get("nested"):
                print(f"{indent}    二次解码（{it['nested']['way']}）："
                      f"{it['nested']['decoded_text'][:70]}")
            for s in it.get("slices", []):
                mark = "★密钥" if s.get("candidate_key") else "     "
                print(f"{indent}    {mark} [{s['range'][0]}:{s['range'][1]}] "
                      f"{s['len']:>2}字符 {s['value']}   {s['role']}")
            for n in it.get("notes", [])[:2]:
                print(f"{indent}    · {n}")

    def show_chains(chains, indent="  "):
        for i, ch in enumerate(chains, 1):
            print(f"{indent}[{i}] 置信度 {ch['confidence']} · 预设 {ch['suggest_preset']}"
                  + ("（字节码共现推断）" if ch.get("binary_hint") else ""))
            for st in ch["steps"]:
                print(f"{indent}    → {st['op']:<8} {st.get('detail', '')}")
            if ch.get("bound_note"):
                print(f"{indent}    ✔ {ch['bound_note']}")
            print(f"{indent}    复现命令：{ch['suggest_cmd']}")
            for ev in ch.get("evidence", [])[:2]:
                print(f"{indent}    证据：{ev[:110]}")

    print("=" * 78)
    print(" 密钥材料分析（伪装常量解码 + 派生链识别）")
    print("=" * 78)
    print(f" 目标：{result.get('origin')}")
    if result.get("kind") == "dir":
        print(f" 扫描文件数：{result.get('scanned')}")
    for n in result.get("notes", []):
        print(f" 说明：{n}")
    print("-" * 78)
    if result.get("disguised"):
        print(f" ■ 疑似密钥材料常量 {len(result['disguised'])} 处：")
        show_disguised(result["disguised"])
    chains_all = result.get("derive_chains") or []
    if chains_all:
        print(f" ■ 疑似密钥派生链 {len(chains_all)} 处：")
        show_chains(sorted(chains_all, key=lambda c: -c["confidence"])[:8])
        if len(chains_all) > 8:
            print(f"  （另有 {len(chains_all) - 8} 条未显示，用 --json 看全量）")
    if result.get("files"):
        print(" ■ 命中文件明细：")
        for f in result["files"]:
            print(f"  · {f['origin']}"
                  f"（常量 {len(f['disguised'])} / 派生链 {len(f['derive_chains'])}"
                  f"{' / 内层命中 ' + str(len(f['inner'])) if f.get('inner') else ''}）")
    if not (result.get("disguised") or result.get("derive_chains")):
        print(" 未发现伪装常量或派生链。可尝试：加 --deep 扩大文件类型范围，"
              "或对该文件用 Tab 4 文件扫描分析看算法特征。")
    print("-" * 78)
    print("提示：识别结果可直接投喂给 jiejieEAD：")
    print("  · Tab 8「摘要 / HMAC / 密钥派生」→ 选对应预设，填入上面的常量即可复算密钥")
    print("  · 或直接执行上面给出的 cli_crypto.py --derive 命令")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="key_material_analyzer.py",
        description="密钥材料分析：伪装 base64 常量解码 + AES/SHA 派生链识别",
    )
    p.add_argument("--text", help="直接分析一段文本")
    p.add_argument("--file", help="分析单个文件（源码 / class / jar / apk 均可）")
    p.add_argument("--dir", help="分析整个目录")
    p.add_argument("--deep", action="store_true", help="目录模式下连未知扩展名文件也扫")
    p.add_argument("--json", action="store_true", help="以 JSON 输出")
    p.add_argument("--selftest", action="store_true", help="运行自检")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.selftest:
        return _selftest()
    if args.text is not None:
        _emit(analyze_text(args.text, "<--text>"), args.json)
        return 0
    if args.file:
        _emit(analyze_file(args.file), args.json)
        return 0
    if args.dir:
        _emit(analyze_dir(args.dir, deep=args.deep), args.json)
        return 0
    build_parser().print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
