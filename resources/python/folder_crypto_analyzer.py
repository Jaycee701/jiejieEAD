#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件夹整体分析模块（多文件 + 跨文件串联逻辑 + 整体总结）。

为什么要单独一个模块：
  单文件分析只能回答「这个文件用了什么加密方案」；
  但真实项目里，**密钥定义在 A 文件、加解密实现在 B 文件、发请求在 C 文件**，
  只看单个文件永远是碎片。本模块把一整个文件夹当成一个系统来分析：

  1) 遍历筛选：递归扫描目录，剔除 node_modules/.git/dist 等噪声
  2) 逐文件摘要：复用 file_crypto_scanner 做离线判定（类型/算法/密钥/库/熵）
  3) 跨文件关系：import 依赖边 / 共享密钥边 / 符号引用边
  4) 链路重建：按「取钥 → 初始化 → 加解密 → 编码 → 传输/签名」的语义角色，
     把一个密钥从定义到使用再到外发的路径串起来
  5) 整体证据包 → 在线 LLM → 整体总结（体系 / 数据流 / 密钥管理 / 风险）
     在线不可用时用规则兜底总结，绝不静默失败
  6) **解密配方反推**：把整体分析出的「加密逻辑」反过来写成可执行的「解密逻辑」
     （alg/mode/padding + HEX key/iv + 密文编码链），并支持直接粘贴密文解密
     （自动尝试 Base64 / Hex / 双重 Base64 等输入形态，按明文特征打分选最优）

用法：
  python folder_crypto_analyzer.py --dir ./project --json
  python folder_crypto_analyzer.py --dir ./project --json --progress [--deep]
  python folder_crypto_analyzer.py --dir ./project --max-files 300 --no-llm
  python folder_crypto_analyzer.py --decrypt-text "<密文>"        # 用上次分析出的配方解密
  python folder_crypto_analyzer.py --decrypt-file ./cipher.txt --json
  python folder_crypto_analyzer.py --selftest
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
import tempfile
import time
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
# 被 Tauri 以绝对路径调用时，脚本目录未必在 sys.path 首位（嵌入式 Python 的 _pth
# 不会自动把脚本目录加入 sys.path），必须显式插入，否则兄弟模块 import 会失败。
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import file_crypto_scanner as fcs  # noqa: E402
import ai_crypto_analyzer as aica  # noqa: E402
import crypto_core as cc  # noqa: E402

# 密钥材料分析（伪装 base64 常量 / AES-SHA 派生链）。可选依赖，缺失只少一块结论。
try:
    import key_material_analyzer as kma  # noqa: E402
except Exception:  # noqa: BLE001
    kma = None


# ============================================================================
# 参数与常量
# ============================================================================
DEFAULT_MAX_FILES = 200
DEFAULT_MAX_FILE_MB = 4
# 归档类文件单独给一个更宽的上限（内部条目会逐个按体积过滤，不会真的全量读）
_MAX_KDF_PLANS = 3   # 派生配方最多报几套（其余用 --json 看全量）
ARCHIVE_MAX_MB = 64
ARCHIVE_EXT = {".jar", ".war", ".aar", ".apk", ".zip", ".whl", ".egg"}
DEFAULT_FOLDER_EVIDENCE_CHARS = 24000
_MAX_TEXT_BYTES = 2 * 1024 * 1024      # 单文件参与 import/符号分析时最多读 2MB
_MAX_TEXT_KEEP = 60                    # 最多为多少个文件保留文本做符号引用检测
_MAX_SNIPPET = 240                     # 每条角色证据的片段长度
_MAX_SNIPPETS_PER_FILE = 4
_MAX_EDGES = 400
_MAX_CHAINS = 40

# ---- 解密配方（把「加密逻辑」反推成「能直接跑的解密逻辑」）----
_MAX_PLANS = 12                        # 最多输出几套解密方案
_MAX_DECRYPT_INPUT = 4 * 1024 * 1024   # 密文文件上限（4MB）
# 命令行/输入框传参的实际上限：Windows CreateProcess 命令行约 32K 字符，
# 超了会被截断（而且是悄悄截断，解出来是错的）——所以这里必须显式挡住并引导走文件。
_MAX_TEXT_ARG = 30000
PLAINS_MIN_SCORE = 0.55                # 明文判定阈值（低于此分不算解出明文）


# 自检用例共用的密钥/IV（16 字节 → AES-128，专门用来验证「按密钥长度纠正位宽」）
_SELFTEST_KEY = "0432C4AE2C1F1981195F9904466A39C9"
_SELFTEST_IV = "000102030405060708090A0B0C0D0E0F"


def plans_path() -> str:
    """解密配方的落盘位置。

    为什么落盘：分析一次要遍历整个目录（可能几十秒），而用户会**反复粘贴不同密文**
    来解密。把配方缓存成文件后，`--decrypt-text` 就只需读文件，不必重新分析。
    """
    env = os.environ.get("JIEJIEEAD_PLANS_PATH")
    if env:
        return env
    return os.path.join(tempfile.gettempdir(), "jiejieead_folder_plans.json")


def _save_plans(plans: list[dict[str, Any]], path: str | None = None) -> str:
    """把配方**原子写**到磁盘（.tmp → os.replace），返回实际路径。

    写失败不算致命：只是后续 --decrypt-text 需要重新分析，不该让整个分析失败。
    """
    target = path or plans_path()
    try:
        tmp = target + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "plans": plans}, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, target)
        return target
    except OSError:
        return ""


def _load_plans(path: str | None = None) -> tuple[list[dict[str, Any]], str]:
    """读回落盘的配方。返回 (plans, 错误信息)。"""
    target = path or plans_path()
    if not os.path.isfile(target):
        return [], ("没有找到解密配方：%s\n"
                    "请先对目标目录跑一次整体分析（--dir <目录>），配方会自动落盘后复用。" % target)
    try:
        with open(target, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        return [], "配方文件损坏或不可读：%s（%s）" % (target, exc)
    plans = doc.get("plans") if isinstance(doc, dict) else None
    if not isinstance(plans, list):
        return [], "配方文件格式不正确：%s" % target
    return plans, ""

# 噪声目录：这些目录里的文件几乎不可能是业务加密逻辑（第三方库/构建产物/缓存）
EXCLUDE_DIRS = {
    "node_modules", ".git", ".svn", ".hg", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", "out", "target",
    ".next", ".nuxt", ".output", "coverage", ".nyc_output", ".idea", ".vscode",
    ".vs", "vendor", "bower_components", ".gradle", "pods", ".terraform",
    "venv", ".venv", "env", ".tox", "site-packages", ".cache", "tmp",
    ".parcel-cache", ".turbo", ".dart_tool", "obj", "bin", "Debug", "Release",
}

# 与密码学高度相关的后缀（决定优先级与是否纳入）
HIGH_EXT = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte",
    ".java", ".kt", ".kts", ".smali", ".dex", ".class", ".jar", ".aar", ".apk",
    ".so", ".dll", ".dylib", ".py", ".rb", ".php", ".go", ".rs", ".cs", ".c",
    ".cpp", ".cc", ".h", ".swift", ".m", ".mm", ".lua", ".pl", ".sh", ".ps1",
    ".json", ".xml", ".properties", ".yml", ".yaml", ".ini", ".conf", ".cfg",
    ".gradle", ".pro", ".env", ".pem", ".key", ".crt", ".cer", ".p12", ".pfx",
    ".sql", ".db", ".sqlite", ".plist", ".manifest", ".txt", ".har",
}
LOW_EXT = {
    ".html", ".htm", ".css", ".scss", ".less", ".md", ".rst", ".map",
    ".svg", ".gitignore", ".editorconfig", ".lock",
}
# 明确无关的（图片/音视频/字体/办公文档/压缩包内的纯资源）
NOISE_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tiff",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".ogg", ".mkv", ".webm",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".psd", ".ai", ".sketch", ".fig",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
    ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".zip.001",
    ".exe", ".msi", ".apk.1", ".DS_Store",
}

# 角色识别：语义化「这一步在干什么」
ROLE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("key_source", r"(?i)(?:secret|app_?key|appkey|api_?key|encrypt_?key|aes_?key|"
                   r"sm4_?key|des_?key|private_?key|public_?key|passphrase|salt|"
                   r"getKey|getSecret|fetchKey|loadKey|deriveKey|kdf|pbkdf2|"
                   r"keystore|keyStore|密钥)"),
    ("cipher_init", r"(?i)(?:Cipher\.getInstance|createCipheriv|createDecipheriv|"
                    r"AES\.(?:encrypt|decrypt)|sm4\.(?:encrypt|decrypt)|"
                    r"DES\.(?:encrypt|decrypt)|TripleDES|RC4|CipherInit|"
                    r"SecureRandom|IvParameterSpec|GCMParameterSpec)"),
    ("transform", r"(?i)(?:\.doFinal|\.update\(|\bencrypt\b|\bdecrypt\b|"
                  r"\.cipher\(|ciphertext|plaintext)"),
    ("encode", r"(?i)(?:\.toString\(|base64|btoa|atob|toBase64|encodeBase64|"
               r"decodeBase64|bytesToHex|hexEncode|\.toHex|Base64\.)"),
    ("sign", r"(?i)(?:\bhmac\b|signature|\bsign\(|md5|sha1|sha256|sha512|"
             r"signWith|MessageDigest)"),
    ("transport", r"(?i)(?:axios|fetch\(|XMLHttpRequest|\$\.ajax|requests\.(?:post|get)|"
                  r"okhttp|HttpURLConnection|volley|WebSocket|\.post\(|\.get\(|"
                  r"sendBeacon|http\.request)"),
)
ROLE_ORDER = {"key_source": 1, "cipher_init": 2, "transform": 3,
              "encode": 4, "sign": 5, "transport": 6}
ROLE_DISPLAY = {
    "key_source": "取密钥 / 派生密钥",
    "cipher_init": "初始化密码器",
    "transform": "加解密运算",
    "encode": "编码（Base64/HEX）",
    "sign": "签名 / 摘要",
    "transport": "传输 / 外发",
}

_CAMEL_BOUNDARY = re.compile(r"[^A-Za-z0-9]+")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


# ============================================================================
# 小工具
# ============================================================================
def _step_enabled() -> bool:
    return os.environ.get("JIEJIEEAD_PROGRESS", "") == "1"


def _mk_step(on_step):
    """统一进度回调：把百分比缩放到 5~90 区间（留给在线 LLM 阶段 90~100）。"""
    def step(pct: int, text: str) -> None:
        if not on_step:
            return
        scaled = 5 + int(max(0, min(100, pct)) * 0.85)
        on_step(scaled, text)
    return step


def _norm_key(value: str) -> str:
    """把密钥字面量归一化，便于跨文件比对（HEX 统一大写，其余去空白）。"""
    v = (value or "").strip().strip("'\"`")
    if not v:
        return ""
    if _HEX_RE.match(v) and len(v) >= 8:
        return v.upper()
    return _CAMEL_BOUNDARY.sub("", v)


def _rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except Exception:  # noqa: BLE001
        return os.path.basename(path)


def _read_text_for_analysis(path: str) -> str:
    """读取文件用于 import / 符号分析：文本直接用，二进制走字符串常量池。"""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(_MAX_TEXT_BYTES)
    except Exception:  # noqa: BLE001
        return ""
    if not raw:
        return ""
    try:
        likeness = fcs.text_likeness(raw)
    except Exception:  # noqa: BLE001
        likeness = 0.0
    if likeness >= 0.6:
        return fcs.decode_text(raw)
    try:
        strings = fcs.extract_strings(raw, limit=6000)
    except Exception:  # noqa: BLE001
        return ""
    return "\n".join(s for _, s in strings)


def _snippet_at(text: str, index: int, length: int = _MAX_SNIPPET) -> str:
    start = max(0, index - 60)
    end = min(len(text), index + length)
    return re.sub(r"\s+", " ", text[start:end]).strip()


# ============================================================================
# 1) 遍历与筛选
# ============================================================================
def walk_folder(root: str, *, max_files: int = DEFAULT_MAX_FILES,
                max_file_mb: float = DEFAULT_MAX_FILE_MB,
                exclude_dirs: set[str] | None = None,
                on_step=None) -> dict[str, Any]:
    """递归遍历目录，挑选「值得分析」的文件并按优先级排序。"""
    step = _mk_step(on_step)
    step(2, "遍历目录并筛选文件")

    if not os.path.isdir(root):
        raise RuntimeError("不是有效目录：%s" % root)

    exclude = {d.lower() for d in (exclude_dirs or EXCLUDE_DIRS)}
    max_bytes = int(max_file_mb * 1024 * 1024)

    total_files = 0
    total_bytes = 0
    picked: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    ext_counter: dict[str, int] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        # 原地裁剪目录列表：既省时间，也让 os.walk 不再下探
        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in exclude and not d.startswith(".")
        ]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if not os.path.isfile(full):
                continue
            total_files += 1
            ext = os.path.splitext(fn)[1].lower()
            ext_counter[ext or "(无后缀)"] = ext_counter.get(ext or "(无后缀)", 0) + 1

            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            total_bytes += size

            if ext in NOISE_EXT:
                skipped.append({"path": _rel(root, full), "reason": "非代码资源（图片/音视频/字体/文档）"})
                continue
            if size == 0:
                skipped.append({"path": _rel(root, full), "reason": "空文件"})
                continue
            # 归档类（jar/apk/zip/aar）按**内部可读条目**处理，不能拿整包体积一刀切：
            # 一个 6MB 的 jar 里真正有价值的 class/常量池可能只有几百 KB。
            # 实测踩过：银行 H5 的 6.2MB jar 被 4MB 上限直接跳过，等于放走了整个目标。
            limit = max_bytes
            if ext in ARCHIVE_EXT:
                limit = max(max_bytes, int(ARCHIVE_MAX_MB * 1024 * 1024))
            if size > limit:
                skipped.append({
                    "path": _rel(root, full),
                    "reason": "超过单文件上限 %.1f MB（当前 %.1f MB）" % (limit / 1048576.0,
                                                                        size / 1048576.0),
                })
                continue

            if ext in HIGH_EXT:
                priority = 0
            elif ext in LOW_EXT:
                priority = 2
            else:
                priority = 1  # 未知后缀：可能是无后缀的密钥/配置，给中等优先级
            picked.append({"path": full, "rel": _rel(root, full),
                           "size": size, "ext": ext, "priority": priority})

    # 优先级升序、同优先级按体积降序（大文件信息多，先看）
    picked.sort(key=lambda x: (x["priority"], -x["size"]))
    kept = picked[:max_files]
    dropped = picked[max_files:]

    step(10, "命中 %d 个候选文件（共 %d 个）" % (len(kept), total_files))

    return {
        "root": os.path.abspath(root),
        "total_files": total_files,
        "total_bytes": total_bytes,
        "candidate_files": len(picked),
        "scanned_files": len(kept),
        "files": kept,
        "skipped": skipped[:200],
        "skipped_count": len(skipped),
        "dropped_by_limit": [{"path": d["rel"], "size": d["size"]} for d in dropped[:100]],
        "dropped_count": len(dropped),
        "ext_histogram": dict(sorted(ext_counter.items(), key=lambda kv: -kv[1])[:30]),
        "truncated": bool(dropped),
    }


# ============================================================================
# 2) 逐文件摘要
# ============================================================================
_PARSE_HINT_PATTERNS = (
    ("hex", re.compile(r"enc\.Hex\.parse|from_hex|bytes\.fromhex|Codec\.Hex|hex2bytes|"
                       r"binascii\.unhexlify", re.I)),
    ("utf8", re.compile(r"enc\.Utf8\.parse|from_utf8|TextEncoder|NewEncoder\(\)\.Encode|"
                        r"\.encode\(['\"]utf-?8['\"]\)", re.I)),
    ("base64", re.compile(r"enc\.Base64\.parse|b64decode|FromBase64String|atob\(", re.I)),
)


def _key_parse_hint(text: str) -> str:
    """从源码里看出「密钥字面量是按哪种编码解析成字节的」。

    同一串 '1a2b3c…' 按 Hex 解析是 16 字节密钥，按 UTF-8 解析是 32 字节文本，
    长度不同 → 算法位宽也不一样。所以这是反推解密配方时不可省的一步。
    """
    for hint, pat in _PARSE_HINT_PATTERNS:
        if pat.search(text):
            return hint
    return ""


def _cipher_from_scan(scan: dict[str, Any]) -> dict[str, Any]:
    """把 file_crypto_scanner 的 logic 压成「解密配方原料」。

    只保留能直接驱动解密引擎的字段（HEX 的 key/iv 是 crypto_core 的入参形态），
    外加「人话出处」（例如「AES_KEY 变量」）用于给用户解释这条配方从哪来。
    """
    logic = scan.get("logic") or {}
    apply_crypto = logic.get("apply_crypto") or {}
    chosen_key = logic.get("chosen_key") or {}
    chosen_iv = logic.get("chosen_iv") or {}
    # ★ 不能因为「没有算法」就整条丢掉：纯密钥文件（export const AES_KEY = '…'）
    #   本来就没有算法上下文，但它的密钥恰恰是解密配方的另一半，丢了就拼不起来。
    if (not apply_crypto and not logic.get("primary_algorithm")
            and not chosen_key and not chosen_iv):
        return {}
    return {
        "primary_algorithm": logic.get("primary_algorithm") or "",
        "mode": logic.get("mode") or "",
        "padding": logic.get("padding") or "",
        "encoding": logic.get("encoding") or "",
        "rule": logic.get("rule") or "",
        "alg": apply_crypto.get("alg") or "",
        "engine_mode": apply_crypto.get("mode") or "",
        "engine_padding": apply_crypto.get("padding") or "",
        "key_hex": apply_crypto.get("key") or "",
        "iv_hex": apply_crypto.get("iv") or "",
        "engine_encoding": apply_crypto.get("encoding") or "",
        "key_origin": chosen_key.get("origin") or "",
        "key_bytes": chosen_key.get("bytes_len"),
        "key_value": chosen_key.get("value") or "",
        "key_confidence": chosen_key.get("confidence") or "",
        "iv_origin": chosen_iv.get("origin") or "",
        "iv_value": chosen_iv.get("value") or "",
        "warnings": list(logic.get("warnings") or []),
    }


def analyze_one_file(root: str, entry: dict[str, Any], *, deep: bool = False,
                     keep_text: bool = False) -> dict[str, Any]:
    """对单个文件做离线摘要，产出「图节点」所需的一切信息。

    keep_text=True 时把文本留在 node["_text"]（供后续跨文件「符号引用」检测复用），
    调用方用完必须 pop 掉，避免把大段源码带进最终 JSON。
    """
    path = entry["path"]
    rel = entry["rel"]
    node: dict[str, Any] = {
        "id": rel, "label": os.path.basename(rel), "path": rel,
        "size": entry["size"], "ext": entry["ext"],
        "type": "", "type_display": "", "category": "",
        "algos": [], "libs": [], "domains": [],
        "secrets": [], "keys": [], "symbols": [], "symbol_refs": [],
        "imports": [], "roles": [], "hits": False, "score": 0,
        "cipher": {},          # ★ 单文件判定出的「加密逻辑」（解密配方的原料）
        "error": "",
    }
    try:
        scan = fcs.scan_file(path, deep=deep)
    except Exception as exc:  # noqa: BLE001 —— 单文件失败不能拖垮整体分析
        node["error"] = str(exc)
        return node

    finfo = scan.get("file", {}) or {}
    node["type"] = finfo.get("type", "")
    node["type_display"] = finfo.get("type_display", "")
    node["category"] = finfo.get("category", "")
    node["entropy"] = finfo.get("entropy")
    node["algos"] = [a.get("algorithm", "") for a in (scan.get("algorithms") or []) if a.get("algorithm")]
    node["libs"] = [l.get("display", "") for l in (scan.get("crypto_libs") or []) if l.get("display")]
    node["domains"] = (scan.get("domains") or [])[:8]

    # ---- 密钥材料（跨文件共享密钥边的基础）----
    for s in (scan.get("secrets") or [])[:60]:
        val = str(s.get("value") or "").strip()
        if not val:
            continue
        bytes_len = s.get("bytes_len")
        # 只有「够长 + 像密钥」的才参与跨文件比对，避免把 'GET' 之类当共享密钥
        interesting = bool(bytes_len) and int(bytes_len) >= 8
        node["secrets"].append({
            "value": val[:120],
            "kind": s.get("guess") or s.get("kind", ""),
            "bytes_len": bytes_len,
            "confidence": s.get("confidence", ""),
            "source": s.get("source", ""),
        })
        if interesting:
            node["keys"].append(_norm_key(val))

    # ---- 加密逻辑（解密配方的原料：alg/mode/padding + HEX key/iv）----
    node["cipher"] = _cipher_from_scan(scan)

    # ---- 文本级：imports / 符号 / 角色证据 ----
    text = _read_text_for_analysis(path)
    if text:
        node["imports"] = _extract_imports(text)
        node["symbols"] = _extract_symbol_defs(text)
        node["roles"] = _extract_roles(text)
        # 密钥字面量的「解析语义」：CryptoJS.enc.Hex.parse / Utf8.parse / Base64.parse
        # 决定同一串字符到底是 16 字节密钥还是一串普通文本 —— 反推解密配方时必须知道
        node["cipher"]["parse_hint"] = _key_parse_hint(text)
        if keep_text:
            node["_text"] = text

    # ---- 相关度打分：用于排序与「重点文件」标记 ----
    score = 0
    score += 12 * len(node["secrets"])
    score += 8 * len(node["algos"])
    score += 6 * len(node["libs"])
    score += 4 * len(node["symbols"])
    score += 3 * len({r["role"] for r in node["roles"]})
    score += 2 * len(node["imports"])
    node["score"] = score
    node["hits"] = bool(node["algos"] or node["secrets"] or node["libs"]
                        or node["symbols"] or node["roles"])
    return node


_MAX_SYMBOL_NAMES = 300


def _unique_definers(nodes: list[dict[str, Any]]) -> dict[str, str]:
    """
    只保留「在目录内只有一个文件定义」的符号。

    若同一个名字被多个文件各自定义（真实项目里常见：AES_KEY 在 config 与某个
    client 里各写一遍），就无法判断谁是「定义方」。此时取「先遍历到的那个」
    会产生方向随机、语义错误的边，所以干脆不给它建符号引用边
    ——这种重复定义本身已由「共享密钥边」覆盖。
    """
    def_files: dict[str, set[str]] = {}
    for n in nodes:
        for name in n.get("symbols") or []:
            def_files.setdefault(name, set()).add(n["id"])
    return {name: next(iter(files)) for name, files in def_files.items() if len(files) == 1}


def attach_symbol_refs(nodes: list[dict[str, Any]]) -> None:
    """
    跨文件「符号引用」检测：A 定义、B 引用。

    真实项目的串联方式是 **config 定义 AES_KEY，cipher/sign 引用它**，
    而不是多个文件各自重复定义同一个名字。只比对「定义」会漏掉整条主链，
    所以这里先把「唯一定义方」的密码学符号名收集起来（限量），
    再逐文件看它在谁的文本里以标识符形式出现 → 形成「定义方 → 使用方」边。

    正则两侧加负向断言：
      · 左边排除字母/数字/_/$ —— 避免匹配到 `myAES_KEY` 这类更长标识符的一部分；
      · 左边再排除 `/` 与 `\\` —— 避免把 import 路径 `'../utils/cipher.js'` 里的
        `cipher` 误当成「引用了 cipher 这个符号」（真实踩过的假阳性）。
    """
    defs = _unique_definers(nodes)
    names = list(defs.keys())[:_MAX_SYMBOL_NAMES]
    if not names:
        return
    rxs = [(name, re.compile(r"(?<![A-Za-z0-9_$/\\])%s(?![A-Za-z0-9_$])" % re.escape(name)))
           for name in names]
    for n in nodes:
        text = n.get("_text") or ""
        if not text:
            continue
        refs: list[str] = []
        for name, rx in rxs:
            if defs.get(name) == n["id"]:
                continue               # 定义文件自身不算「引用」
            if rx.search(text):
                refs.append(name)
        n["symbol_refs"] = refs


# ---------------------------------------------------------------------------
# import / 符号 / 角色 抽取
# ---------------------------------------------------------------------------
_IMPORT_PATTERNS = (
    re.compile(r"""\bimport\s+(?:[\w*{},\s$]+\s+from\s+)?['"]([^'"]+)['"]"""),
    re.compile(r"""\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""\bfrom\s+([\w.]+)\s+import\b"""),
    re.compile(r"""\bimport\s+([\w.]+)\s*;"""),
    re.compile(r"""#include\s*[<"]([^">]+)[">]"""),
    re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]"""),
    re.compile(r"""\bnew\s+Worker\s*\(\s*['"]([^'"]+)['"]"""),
)


def _extract_imports(text: str, limit: int = 60) -> list[str]:
    found: list[str] = []
    for pat in _IMPORT_PATTERNS:
        for m in pat.finditer(text):
            spec = (m.group(1) or "").strip()
            if not spec or spec.startswith(("http://", "https://", "//", "data:")):
                continue
            if spec not in found:
                found.append(spec)
            if len(found) >= limit:
                return found
    return found


_SYMBOL_DEF_PATTERNS = (
    re.compile(r"""\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*="""),
    re.compile(r"""\bfunction\s+([A-Za-z_$][\w$]*)\s*\("""),
    re.compile(r"""\bclass\s+([A-Za-z_$][\w$]*)\b"""),
    re.compile(r"""\bdef\s+([A-Za-z_][\w]*)\s*\("""),
    re.compile(r"""\b(?:public|private|protected|static|final|\s)+[A-Za-z_][\w<>\[\]]*\s+([A-Za-z_][\w]*)\s*="""),
    re.compile(r"""#define\s+([A-Za-z_][\w]*)"""),
    re.compile(r"""(?:^|[,\{\s])\"([A-Za-z_][\w]*)\"\s*:"""),
)
# 只有「名字本身暗示密码学」的定义才值得做跨文件符号边，否则噪声太大
_SYMBOL_HINT = re.compile(
    r"(?i)(?:key|iv|secret|salt|cipher|encrypt|decrypt|sm2|sm3|sm4|aes|des|rc4|"
    r"rsa|hmac|sign|token|passwd|password|credential|nonce)"
)


def _extract_symbol_defs(text: str, limit: int = 60) -> list[str]:
    out: list[str] = []
    for pat in _SYMBOL_DEF_PATTERNS:
        for m in pat.finditer(text):
            name = m.group(1)
            if not _SYMBOL_HINT.search(name):
                continue
            if len(name) < 4:
                continue
            if name not in out:
                out.append(name)
            if len(out) >= limit:
                return out
    return out


def _extract_roles(text: str, limit: int = _MAX_SNIPPETS_PER_FILE * 3) -> list[dict[str, Any]]:
    """
    找出「这一步在干什么」的证据片段（按角色分类，保留出现顺序）。

    去重规则：**只有位置真正重叠才算重复**（例如 `CryptoJS.AES.encrypt(` 同时命中
    cipher_init 与 transform）。早期版本用「40 字符内只留一个」，会把
    `btoa(body); return axios.post(...)` 这种紧挨着的两种不同角色误杀，
    导致「传输」角色整条链路丢失。
    """
    hits: list[dict[str, Any]] = []
    seen_spans: list[tuple[int, int]] = []
    for role, pat in ROLE_PATTERNS:
        try:
            rx = re.compile(pat)
        except re.error:
            continue
        for m in rx.finditer(text):
            start, end = m.span()
            if any(not (end <= s or start >= e) for s, e in seen_spans):
                continue  # 与已记录的位置真正重叠 → 同一处，跳过
            seen_spans.append((start, end))
            line_no = text.count("\n", 0, start) + 1
            hits.append({
                "role": role,
                "role_display": ROLE_DISPLAY.get(role, role),
                "line": line_no,
                "match": m.group(0)[:40],
                "snippet": _snippet_at(text, start),
            })
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break
    hits.sort(key=lambda h: (h["line"], ROLE_ORDER.get(h["role"], 9)))
    return hits[:_MAX_SNIPPETS_PER_FILE * 2]


# ============================================================================
# 3) 跨文件关系图
# ============================================================================
def _resolve_import(spec: str, from_rel: str, by_basename: dict[str, list[str]]) -> str | None:
    """把 import 说明符尽量解析成目录内的某个文件（解析不到就返回 None）。"""
    s = spec.strip()
    if not s:
        return None
    # 相对路径：../x/y、./y
    if s.startswith("."):
        base_dir = os.path.dirname(from_rel)
        cand = os.path.normpath(os.path.join(base_dir, s)).replace("\\", "/")
    else:
        cand = s.replace("\\", "/")

    cands = [cand]
    for suf in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".json",
                ".py", ".java", ".kt", ".dart", ".go", "/index.js", "/index.ts"):
        cands.append(cand + suf)
    for c in cands:
        if c in by_basename.get("__all__", []):
            return c
    # 退一步：只在同目录里按文件名匹配（避免 "com.a.b.C" 这类点号路径误伤）
    base = os.path.basename(cand)
    for suffix in ("", ".js", ".ts", ".vue", ".json", ".py", ".java"):
        for hit in by_basename.get(base + suffix, []):
            return hit
    # 点号分隔的模块名（Java/Python）：取最后一段按 basename 匹配
    if "." in base:
        last = base.split(".")[-1]
        for suffix in ("", ".js", ".ts", ".py", ".java", ".kt"):
            for hit in by_basename.get(last + suffix, []):
                return hit
    return None


def _is_external(spec: str) -> bool:
    """裸模块名（npm/maven 包）视为外部依赖，不做文件级边。"""
    if spec.startswith(".") or spec.startswith("/") or spec.startswith("\\"):
        return False
    # 形如 com.foo.Bar / java.util.List 的包名也视为外部
    return True


def build_graph(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    """构建跨文件关系图：节点=文件，边=import / 共享密钥 / 符号引用。"""
    by_id = {n["id"]: n for n in nodes}
    by_basename: dict[str, list[str]] = {"__all__": sorted(by_id.keys())}
    for n in nodes:
        by_basename.setdefault(n["label"], []).append(n["id"])

    edges: list[dict[str, Any]] = []
    edge_seen: set[tuple[str, str, str]] = set()

    def add_edge(src: str, dst: str, kind: str, label: str) -> None:
        if src == dst or src not in by_id or dst not in by_id:
            return
        key = (src, dst, kind)
        if key in edge_seen:
            return
        edge_seen.add(key)
        edges.append({"from": src, "to": dst, "type": kind, "label": label})

    # ---- (a) import 依赖边 ----
    external_imports: dict[str, int] = {}
    for n in nodes:
        for spec in n.get("imports") or []:
            if _is_external(spec):
                external_imports[spec] = external_imports.get(spec, 0) + 1
                continue
            target = _resolve_import(spec, n["id"], by_basename)
            if target:
                add_edge(n["id"], target, "import", "import %s" % spec)

    # ---- (b) 共享密钥边：同一个密钥值出现在多个文件 ----
    key_owners: dict[str, list[str]] = {}
    for n in nodes:
        for k in set(n.get("keys") or []):
            key_owners.setdefault(k, []).append(n["id"])
    shared_keys: list[dict[str, Any]] = []
    for k, owners in key_owners.items():
        if len(owners) < 2:
            continue
        owners_sorted = sorted(owners)
        shared_keys.append({"key": k[:48], "files": owners_sorted, "count": len(owners_sorted)})
        # 星型连边：第一个定义为源，其余连过去，避免 O(n^2) 边爆炸
        for other in owners_sorted[1:]:
            add_edge(owners_sorted[0], other, "shared_key", "共享密钥 %s…" % k[:16])

    # ---- (c) 符号引用边：A 定义、B 引用（名字须暗示密码学）----
    # 语义是「定义方 → 使用方」，不是「多个文件各自定义同名」。
    # 真实项目里 AES_KEY 只在 config 定义一次、在 cipher/sign 里被引用，
    # 若只比对定义会整条主链丢失；若同一个名字有多个定义方则放弃建边
    # （避免「谁先遍历到谁是定义方」这种方向随机的假边）。
    def_index = _unique_definers(nodes)
    for n in nodes:
        for name in n.get("symbol_refs") or []:
            src = def_index.get(name)
            if src and src != n["id"]:
                add_edge(src, n["id"], "symbol", "引用符号 %s" % name)

    # ---- (d) 同库边（弱）：仅在关系稀薄时补充，帮助看出「同一套体系」----
    lib_owners: dict[str, list[str]] = {}
    for n in nodes:
        for lib in n.get("libs") or []:
            lib_owners.setdefault(lib, []).append(n["id"])
    if len(edges) < 12:
        for lib, owners in lib_owners.items():
            if len(owners) < 2 or len(owners) > 12:
                continue
            owners_sorted = sorted(owners)
            for other in owners_sorted[1:]:
                add_edge(owners_sorted[0], other, "same_lib", "同用密码库 %s" % lib)

    edges.sort(key=lambda e: ({"import": 0, "shared_key": 1, "symbol": 2, "same_lib": 3}.get(e["type"], 9),
                              e["from"], e["to"]))
    if len(edges) > _MAX_EDGES:
        edges = edges[:_MAX_EDGES]

    # 只保留参与关系的节点 + 高相关度节点，避免图上全是孤立噪声点
    linked = {e["from"] for e in edges} | {e["to"] for e in edges}
    graph_nodes = []
    for n in nodes:
        if n["id"] in linked or n["hits"]:
            graph_nodes.append({
                "id": n["id"], "label": n["label"], "size": n["size"],
                "type_display": n["type_display"], "algos": n["algos"],
                "libs": n["libs"], "score": n["score"], "hits": n["hits"],
                "secrets": len(n["secrets"]), "roles": sorted({r["role"] for r in n.get("roles") or []}),
                "linked": n["id"] in linked, "error": n.get("error", ""),
            })

    return {
        "nodes": graph_nodes,
        "edges": edges,
        "shared_keys": sorted(shared_keys, key=lambda x: -x["count"])[:30],
        "external_imports": [{"spec": k, "count": v}
                             for k, v in sorted(external_imports.items(), key=lambda kv: -kv[1])[:40]],
        "stats": {
            "nodes": len(graph_nodes),
            "edges": len(edges),
            "import_edges": sum(1 for e in edges if e["type"] == "import"),
            "shared_key_edges": sum(1 for e in edges if e["type"] == "shared_key"),
            "symbol_edges": sum(1 for e in edges if e["type"] == "symbol"),
            "same_lib_edges": sum(1 for e in edges if e["type"] == "same_lib"),
        },
    }


# ============================================================================
# 4) 链路重建：一个密钥从「定义」到「使用」到「外发」的路径
# ============================================================================
def build_chains(nodes: list[dict[str, Any]], graph: dict[str, Any]) -> dict[str, Any]:
    """
    产出两类东西：
      · chains —— 「密钥追溯链」：某个密钥/符号出现在哪些文件、各承担什么角色
      · flow   —— 「全局数据流」：把全项目的角色证据按语义顺序排成一条线
    """
    by_id = {n["id"]: n for n in nodes}
    chains: list[dict[str, Any]] = []

    # ---- chains：按共享密钥 + 符号，追溯它跨越了哪些文件 ----
    for sk in graph.get("shared_keys") or []:
        steps = []
        for fid in sk["files"]:
            n = by_id.get(fid)
            if not n:
                continue
            roles = sorted({r["role"] for r in (n.get("roles") or [])},
                           key=lambda r: ROLE_ORDER.get(r, 9))
            steps.append({
                "file": fid,
                "roles": roles,
                "role_display": " → ".join(ROLE_DISPLAY.get(r, r) for r in roles) or "（未见明显密码学角色）",
                "evidence": (n.get("roles") or [{}])[0].get("snippet", "") if n.get("roles") else "",
            })
        if steps:
            chains.append({
                "kind": "key",
                "name": "密钥 %s…" % sk["key"][:20],
                "files": sk["files"],
                "steps": steps,
                "note": "该密钥材料同时出现在 %d 个文件，说明存在跨文件共享" % sk["count"],
            })

    # ---- chains：按「符号定义 vs 引用」看模块间调用 ----
    symbol_edges = [e for e in (graph.get("edges") or []) if e["type"] == "symbol"]
    for e in symbol_edges[:12]:
        src, dst = by_id.get(e["from"]), by_id.get(e["to"])
        if not src or not dst:
            continue
        name = e["label"].replace("引用符号 ", "")
        chains.append({
            "kind": "symbol",
            "name": "符号 %s" % name,
            "files": [src["id"], dst["id"]],
            "steps": [
                {"file": src["id"], "roles": [r["role"] for r in (src.get("roles") or [])],
                 "role_display": "定义方",
                 "evidence": "定义 `%s`（%s）" % (name, src["type_display"])},
                {"file": dst["id"], "roles": [r["role"] for r in (dst.get("roles") or [])],
                 "role_display": "使用方",
                 "evidence": "引用 `%s`" % name},
            ],
            "note": "跨文件符号引用：定义与使用分离",
        })

    # ---- flow：全局数据流（把各文件的角色证据按语义顺序拼成一条线）----
    flow: list[dict[str, Any]] = []
    for n in nodes:
        for r in n.get("roles") or []:
            flow.append({
                "role": r["role"],
                "role_display": r.get("role_display", ""),
                "file": n["id"],
                "line": r.get("line"),
                "match": r.get("match", ""),
                "snippet": r.get("snippet", ""),
            })
    # 先按角色语义排序，再按文件+行号，得到一条尽量符合真实时序的流程
    flow.sort(key=lambda s: (ROLE_ORDER.get(s["role"], 9), s["file"], s.get("line") or 0))
    flow = flow[:120]

    # 合并成「阶段」视图：每个角色一档，档内列出涉及的文件
    stages: list[dict[str, Any]] = []
    for role in sorted(ROLE_ORDER, key=lambda r: ROLE_ORDER[r]):
        items = [f for f in flow if f["role"] == role]
        if not items:
            continue
        files: list[str] = []
        for it in items:
            if it["file"] not in files:
                files.append(it["file"])
        stages.append({
            "role": role,
            "role_display": ROLE_DISPLAY.get(role, role),
            "files": files,
            "samples": items[:_MAX_SNIPPETS_PER_FILE],
            "count": len(items),
        })

    return {
        "chains": chains[:_MAX_CHAINS],
        "flow": flow,
        "stages": stages,
        "dominant_path": " → ".join(s["role_display"] for s in stages) if stages else "",
    }


# ============================================================================
# 4b) 解密配方：把「加密逻辑」反过来写成「能直接跑的解密逻辑」
# ============================================================================
_ALG_DISPLAY = {
    "sm4": "SM4", "aes128": "AES-128", "aes192": "AES-192", "aes256": "AES-256",
    "des": "DES", "des3": "3DES", "rc4": "RC4",
    "rc5": "RC5-32/12/16", "rc5_16": "RC5-32/16/16", "rc5_64": "RC5-64/16/16",
    "rc6": "RC6-32/20/16", "rc6_16": "RC6-32/16/16",
    "blowfish": "Blowfish", "cast5": "CAST5", "rc2": "RC2",
    "chacha20": "ChaCha20", "salsa20": "Salsa20",
}
_ENC_DISPLAY = {"base64": "Base64", "hex": "十六进制(Hex)", "raw": "原始二进制"}

# 明文里常见的业务字段名：命中说明「这确实解出业务数据了」而不是碰巧乱码可打印
_PLAIN_KW_RE = re.compile(
    r'"(?:id|name|code|msg|message|data|token|access_token|refresh_token|order|orderId|'
    r'userId|user_id|phone|mobile|status|success|result|error|timestamp|sign|amount|price)"'
    r"|'(?:id|name|code|msg|data|token|sign)'"
    r"|\b(?:id|code|msg|token|phone|order|amount)=\S",
    re.I,
)


def _alg_display(alg: str) -> str:
    return _ALG_DISPLAY.get((alg or "").lower(), (alg or "?").upper())


def _enc_display(enc: str) -> str:
    return _ENC_DISPLAY.get((enc or "").lower(), (enc or "?").upper())


def _looks_like_plaintext(data: bytes) -> tuple[bool, float, str]:
    """给「解密结果」打分：判断这堆字节到底是不是可读明文。

    这是自动解密的关键——错误密钥在 CBC/ECB 下**不会报错**，只会解出乱码，
    所以必须靠「明文长什么样」来排序与判定，否则会把乱码当成功结果给用户。
    """
    if not data:
        return False, 0.0, "解密结果为空"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        # 二进制可允许少量非 UTF-8，但整体判为「非文本」
        return False, 0.12, "不是合法 UTF-8 文本（可能是二进制或密钥不匹配）"

    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    ratio = printable / max(1, len(text))
    if ratio < 0.80:
        return False, 0.15, "可打印字符仅 %.0f%%，疑似密钥/IV 不匹配" % (ratio * 100)

    score = 0.0
    reasons: list[str] = []
    if ratio >= 0.99:
        score += 0.5
        reasons.append("全部可打印")
    elif ratio >= 0.95:
        score += 0.40
        reasons.append("可打印 %.0f%%" % (ratio * 100))
    else:
        score += 0.25
        reasons.append("可打印 %.0f%%" % (ratio * 100))

    stripped = text.strip()
    head = stripped[:1]
    if head in ("{", "["):
        score += 0.28
        reasons.append("JSON 结构")
    elif head == "<":
        score += 0.18
        reasons.append("XML/HTML 结构")
    elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", stripped):
        score += 0.18
        reasons.append("表单/查询串结构")

    if _PLAIN_KW_RE.search(stripped):
        score += 0.22
        reasons.append("命中业务字段名")

    if len(stripped) >= 8:
        score += 0.05
    if "\ufffd" in text:          # 替换字符 → 明显是解码失败的乱码
        score -= 0.25
        reasons.append("含替换字符(U+FFFD)")

    return score >= PLAINS_MIN_SCORE, max(0.0, min(score, 1.0)), "、".join(reasons) or "普通文本"


def _decode_layer(text: str, kind: str) -> bytes | None:
    """把一层编码还原成字节；还原不了返回 None（不抛异常）。"""
    s = "".join(text.split())
    if not s:
        return None
    if kind == "base64":
        s2 = s.replace("-", "+").replace("_", "/")
        pad = (-len(s2)) % 4
        try:
            return base64.b64decode(s2 + "=" * pad, validate=False)
        except (binascii.Error, ValueError):
            return None
    if kind == "hex":
        s2 = s[:-1] if s.startswith(("0x", "0X")) else s
        if len(s2) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s2):
            return None
        try:
            return binascii.unhexlify(s2)
        except (binascii.Error, ValueError):
            return None
    if kind == "raw":
        return text.encode("utf-8", errors="surrogateescape")
    return None


def _decode_chain(text: str, chain: list[str]) -> bytes | None:
    """按 chain 逐层解码：如 ["base64","base64"] = 先解一层再解一层。"""
    data = text
    for i, kind in enumerate(chain):
        layer = _decode_layer(data, kind)
        if layer is None:
            return None
        if i < len(chain) - 1:
            # 中间层必须是文本，否则没法继续按编码解（例如 base64 解出的是二进制）
            try:
                data = layer.decode("ascii")
            except UnicodeDecodeError:
                return None
        else:
            return layer
    return None


def _input_chains(preferred: str, prefer_hex: bool = False) -> list[list[str]]:
    """候选「输入解码链」，把配方里识别到的编码提到最前。

    prefer_hex：密文来自**二进制文件**（已被转成 HEX 字符串），
    此时只有 hex 解码能还原原始字节，必须放在第一位。
    """
    order: list[list[str]] = []
    pref = (preferred or "").lower()

    def push(chain: list[str]) -> None:
        if chain not in order:
            order.append(chain)

    if prefer_hex:
        push(["hex"])
    if pref in ("base64", "hex", "raw"):
        push([pref])
        if pref == "base64":
            push(["base64", "base64"])        # btoa(base64密文) —— 双重 Base64 很常见
        if pref == "hex":
            push(["hex", "hex"])
    push(["base64"])
    push(["hex"])
    push(["base64", "base64"])
    push(["raw"])
    return order


def _collect_cipher_evidence(nodes: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """把「单文件判定出的加密逻辑」按 (alg,mode,padding,key,iv,encoding) 归拢。"""
    bucket: dict[str, dict[str, Any]] = {}
    for n in nodes:
        c = n.get("cipher") or {}
        alg = (c.get("alg") or "").lower()
        key_hex = (c.get("key_hex") or "").strip().lower()
        if not alg:
            continue
        mode = (c.get("engine_mode") or c.get("mode") or "cbc").lower()
        pad = (c.get("engine_padding") or c.get("padding") or "pkcs7").lower()
        iv_hex = (c.get("iv_hex") or "").strip().lower()
        enc = (c.get("engine_encoding") or c.get("encoding") or "base64").lower()
        sig = "|".join([alg, mode, pad, key_hex, iv_hex, enc])

        item = bucket.setdefault(sig, {
            "alg": alg, "mode": mode, "padding": pad, "key_hex": key_hex, "iv_hex": iv_hex,
            "encoding": enc, "files": [], "evidence": [], "rules": [], "warnings": [],
            "key_origin": "", "iv_origin": "", "key_bytes": None, "key_confidence": "",
            "primary_algorithm": c.get("primary_algorithm") or "",
            "role_roles": [],
        })
        if n["id"] not in item["files"]:
            item["files"].append(n["id"])
        if c.get("key_origin") and not item["key_origin"]:
            item["key_origin"] = c["key_origin"]
        if c.get("iv_origin") and not item["iv_origin"]:
            item["iv_origin"] = c["iv_origin"]
        if c.get("key_bytes") and not item["key_bytes"]:
            item["key_bytes"] = c["key_bytes"]
        if c.get("key_confidence") and not item["key_confidence"]:
            item["key_confidence"] = c["key_confidence"]
        if c.get("rule") and c["rule"] not in item["rules"]:
            item["rules"].append(c["rule"])
        for w in c.get("warnings") or []:
            if w not in item["warnings"]:
                item["warnings"].append(w)
        # 取该文件里最能说明「这一步在干什么」的证据片段
        for r in (n.get("roles") or [])[:_MAX_SNIPPETS_PER_FILE]:
            if r["role"] not in item["role_roles"]:
                item["role_roles"].append(r["role"])
            ev = {"file": n["id"], "line": r.get("line"), "role": r["role"],
                  "role_display": r.get("role_display", ""), "snippet": r.get("snippet", "")[:200]}
            if ev not in item["evidence"] and len(item["evidence"]) < 12:
                item["evidence"].append(ev)
    return bucket


def _logic_texts(item: dict[str, Any]) -> tuple[list[str], list[str], str]:
    """生成「加密逻辑 / 解密逻辑」两条人类可读的步骤链（解密 = 加密的逆序）。"""
    alg = _alg_display(item["alg"])
    mode = (item["mode"] or "cbc").upper()
    pad = (item["padding"] or "pkcs7").upper()
    enc = _enc_display(item["encoding"])
    key_short = (item["key_hex"] or "")[:16] + ("…" if len(item["key_hex"] or "") > 16 else "")
    iv_short = (item["iv_hex"] or "")[:16] + ("…" if len(item["iv_hex"] or "") > 16 else "")
    key_src = item["key_origin"] or ("文件内硬编码" if item["key_hex"] else "未识别到密钥")
    is_stream = item["mode"] in ("stream",)
    is_ecb = item["mode"] == "ecb"
    if item["iv_hex"]:
        iv_src = item["iv_origin"] or "文件内硬编码"
    elif not is_stream and not is_ecb:
        # 分组模式没 IV 是**解不出来**的，必须说实话，不能含糊成「无需 IV」
        iv_src = "未提取到（%s 必需 IV，需人工补全）" % (item["mode"] or "cbc").upper()
    else:
        iv_src = "无（ECB/RC4 无需 IV）"

    enc_steps = [
        "① 取密钥：%s%s"
        % (key_src, ("（%d 字节）" % item["key_bytes"]) if item.get("key_bytes") else ""),
    ]
    if not is_stream and not is_ecb:
        enc_steps.append("② 取 IV/nonce：%s" % iv_src)
    crypter = "②" if (is_stream or is_ecb) else "③"
    if is_stream:
        enc_steps.append("%s 用 %s 流式加密明文（无需填充）" % (crypter, alg))
    else:
        enc_steps.append("%s 明文用 %s-%s + %s 填充加密" % (crypter, alg, mode, pad))
    enc_steps.append("%s 密文以 %s 编码成字符串" % ("③" if (is_stream or is_ecb) else "④", enc))
    enc_steps.append("%s 随请求/落盘外发" % ("④" if (is_stream or is_ecb) else "⑤"))

    # ---- 解密 = 把上面整条链倒过来 ----
    dec_steps = [
        "① 拿到密文字符串，按 %s **解码**成密文字节" % enc,
    ]
    if item["encoding"] == "base64":
        dec_steps.append("   ⚠ 若密文是二次编码（如 btoa 包裹 Base64），本工具会自动先剥一层")
    crypter_d = "②" if (is_stream or is_ecb) else "③"
    if not is_stream and not is_ecb:
        dec_steps.append("② 用同一 IV：%s" % iv_src)
    if is_stream:
        dec_steps.append("%s 用同一密钥 %s 做 %s 流式解密" % (crypter_d, key_short, alg))
    else:
        dec_steps.append("%s 用同一密钥 %s 做 %s-%s 解密，并去掉 %s 填充"
                         % (crypter_d, key_short, alg, mode, pad))
    dec_steps.append("%s 得到的字节按 UTF-8 解码 → 明文"
                     % ("③" if (is_stream or is_ecb) else "④"))
    if item["encoding"] == "raw":
        dec_steps.append("   ⚠ 配方标注为原始二进制：密文请用 --decrypt-file 传文件，别复制粘贴")

    return enc_steps, dec_steps, ("%s-%s / %s / %s" % (alg, mode, pad, enc) if not is_stream
                                 else "%s / %s" % (alg, enc))


def _plan_cli(item: dict[str, Any]) -> str:
    """给用户一条可以直接复制的命令行。"""
    parts = [
        "python cli_crypto.py --op dec",
        "--alg %s" % (item["alg"] or "aes256"),
        "--mode %s" % (item["mode"] or "cbc"),
        "--padding %s" % (item["padding"] or "pkcs7"),
        "--key %s" % (item["key_hex"] or "<HEX密钥>"),
    ]
    if item["iv_hex"]:
        parts.append("--iv %s" % item["iv_hex"])
    parts.append("--encoding %s" % (item["encoding"] or "base64"))
    parts.append('--text "<把你复制的密文粘到这里>"')
    return " ".join(parts)


def _cipher_material(nodes: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """收集「携带密钥材料」的文件：file_id → 材料（含解析语义 hint）。

    注意这些文件往往**没有算法上下文**（例如只写 `export const AES_KEY = '…'`），
    所以扫描器给不出 apply_crypto，密钥只能留在 chosen_key 里 —— 必须单独收一遍。
    """
    mats: dict[str, dict[str, Any]] = {}
    for n in nodes:
        c = n.get("cipher") or {}
        key_hex = (c.get("key_hex") or "").strip()
        key_value = (c.get("key_value") or "").strip()
        if not key_hex and not key_value:
            continue
        mats[n["id"]] = {
            "file": n["id"],
            "key_hex": key_hex,
            "iv_hex": (c.get("iv_hex") or "").strip(),
            "key_value": key_value,
            "iv_value": (c.get("iv_value") or "").strip(),
            "key_origin": c.get("key_origin") or "",
            "iv_origin": c.get("iv_origin") or "",
            "key_bytes": c.get("key_bytes"),
            "key_confidence": c.get("key_confidence") or "",
            "parse_hint": c.get("parse_hint") or "",
        }
    return mats


def _to_hex_candidates(value: str, hint: str) -> list[tuple[str, str, str]]:
    """把密钥/IV 的原始写法转成若干 (HEX, 解析方式, 说明) 候选，按可能性排序。"""
    v = (value or "").strip().strip("'\"")
    if not v:
        return []
    cands: list[tuple[str, str, str]] = []
    if len(v) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", v):
        cands.append((v.lower(), "hex", "按十六进制字符串解析"))
    cands.append((v.encode("utf-8").hex(), "utf8", "按 UTF-8 文本解析"))
    try:
        raw = base64.b64decode(v + "=" * ((-len(v)) % 4), validate=False)
        if raw:
            cands.append((raw.hex(), "base64", "按 Base64 解析"))
    except (binascii.Error, ValueError):
        pass

    order = ["hex", "utf8", "base64"]
    h = (hint or "").lower()
    if h in order:
        order = [h] + [k for k in order if k != h]
    cands.sort(key=lambda c: order.index(c[1]))
    seen: set[str] = set()
    out: list[tuple[str, str, str]] = []
    for c in cands:
        if c[0] not in seen:
            seen.add(c[0])
            out.append(c)
    return out


def _want_iv(mode: str) -> bool:
    return (mode or "").lower() not in ("ecb", "stream", "")


def _resolve_material(family: str, fallback_alg: str, mode: str,
                      mat: dict[str, Any]) -> dict[str, Any]:
    """把一份密钥材料解析成引擎可用的 (alg, key_hex, iv_hex)。

    关键：算法位宽必须**按密钥真实长度重算**。
    扫描器只看算法名时会默认 aes256；一旦跨文件拿到 16 字节密钥，
    真正的算法是 AES-128 —— 不重算就会拿 32 字节去解 16 字节的密钥，必然失败。
    """
    key_hex, key_how = "", ""
    alg = fallback_alg or "aes256"
    cands: list[tuple[str, str, str]] = []
    if mat.get("key_hex"):
        cands.append((mat["key_hex"].lower(), "hex", "扫描器已按算法上下文解析"))
    cands += _to_hex_candidates(mat.get("key_value", ""), mat.get("parse_hint", ""))

    for hx, _kind, how in cands:
        if not hx:
            continue
        try:
            spec = cc.get_spec_by_keylen(family or alg, len(hx) // 2)
            cc.validate_key(spec, bytes.fromhex(hx))
            alg, key_hex, key_how = spec.aid, hx, how
            break
        except Exception:  # noqa: BLE001 —— 长度对不上就试下一个候选
            continue
    if not key_hex and cands:
        key_hex, key_how = cands[0][0], cands[0][2]

    block = 16
    try:
        block = cc.get_spec(alg).block
    except Exception:  # noqa: BLE001
        pass
    ok_lens = {block, 12, 16}

    iv_hex, iv_how = "", ""
    if mat.get("iv_hex"):
        iv_hex, iv_how = mat["iv_hex"].lower(), "扫描器已按算法上下文解析"
    elif mat.get("iv_value"):
        ic = _to_hex_candidates(mat["iv_value"], mat.get("parse_hint", ""))
        for hx, _kind, how in ic:
            if len(hx) // 2 in ok_lens:
                iv_hex, iv_how = hx, how
                break
        if not iv_hex and ic:
            iv_hex, iv_how = ic[0][0], ic[0][2]

    return {"alg": alg, "key_hex": key_hex, "key_how": key_how,
            "iv_hex": iv_hex, "iv_how": iv_how}


def _linked_material_files(nodes: list[dict[str, Any]], graph: dict[str, Any],
                           material_ids: set[str]) -> dict[str, list[str]]:
    """从每个文件出发，列出它能拿到的「密钥材料文件」候选。

    优先走关系图的 import / 符号引用边（`A → B` 表示 A 依赖 B，密钥常在 B）；
    如果整个项目只有一份密钥材料，则所有文件都可以兜底引用它
    （避免 import 解析失败时整条配方作废——本项目实测过这种漏配）。
    """
    adj: dict[str, list[str]] = {}
    for e in graph.get("edges") or []:
        if e["type"] in ("import", "symbol"):
            adj.setdefault(e["from"], []).append(e["to"])

    out: dict[str, list[str]] = {}
    for n in nodes:
        fid = n["id"]
        found: list[str] = []
        if fid in material_ids:
            found.append(fid)
        for to in adj.get(fid, []):
            if to in material_ids and to not in found:
                found.append(to)
        if not found and len(material_ids) == 1:
            only = next(iter(material_ids))
            if only != fid:
                found.append(only)
        out[fid] = found
    return out


def _analyze_key_material(folder_path: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """分析整目录的伪装常量与派生链，并把结果转成配方。

    这里做的是**跨文件绑定**——本例（银行 H5 报文 jar）里：
      · `Config.class` 里藏着 67 字符伪装常量（32+16+16+3 切法 → 密钥 + IV）
      · `Crypto.class` 里同时出现 AES/CBC 与 SHA-256 常量池标记（派生链线索）
    单看任一文件都拼不出配方，合起来才能给出「种子 → AES-CBC(常量A,常量B) → SHA256 → [16:32]」。
    """
    empty: dict[str, Any] = {"origin": folder_path, "kind": "dir", "files": [],
                             "disguised": [], "derive_chains": [], "notes": [],
                             "summary": {"disguised": 0, "derive_chains": 0,
                                         "candidate_keys": 0, "bound_chains": 0}}
    if kma is None:
        empty["notes"].append("未加载 key_material_analyzer.py，已跳过伪装常量 / 派生链分析")
        return empty, []
    try:
        km = kma.analyze_dir(folder_path)
    except Exception as exc:  # noqa: BLE001
        empty["notes"].append(f"密钥材料分析异常：{type(exc).__name__}: {exc}")
        return empty, []

    # ---- 跨文件绑定：把别处解出来的候选密钥/IV 填进还没有常量的派生链 ----
    key_like: list[dict] = []
    iv_like: list[dict] = []
    for it in km.get("disguised", []):
        for sl in it.get("slices", []):
            if not sl.get("candidate_key"):
                continue
            item = dict(sl)
            item["origin"] = it.get("origin", "")
            if "IV" in (sl.get("role") or ""):
                iv_like.append(item)
            else:
                key_like.append(item)
    # 排序：角色明确写着"密钥"的排最前，"32hex 前缀（业务号/种子）"排最后 ——
    # 否则 32 位业务号会被误当成密钥绑进配方（实测踩过）。
    def _role_rank(item: dict) -> tuple[int, int]:
        role = item.get("role") or ""
        if "前缀" in role:
            return (3, -item.get("len", 0))
        if "密钥" in role:
            return (0, -item.get("len", 0))
        return (2, -item.get("len", 0))

    key_like.sort(key=_role_rank)
    iv_like.sort(key=lambda x: 0 if "IV" in (x.get("role") or "") else 1)
    for ch in km.get("derive_chains", []):
        if not any(s["op"] in ("encrypt", "decrypt") for s in ch["steps"]):
            continue
        bound = ch.setdefault("bound_constants", {})
        notes = []
        if "derive_key" not in bound and key_like:
            bound["derive_key"] = key_like[0]["value"]
            bound["derive_key_format"] = "utf8"
            notes.append("派生密钥 ← 跨文件常量切片%s（来自 %s）"
                         % (key_like[0]["range"], os.path.basename(str(key_like[0]["origin"]))))
        if "derive_iv" not in bound and iv_like:
            bound["derive_iv"] = iv_like[0]["value"]
            bound["derive_iv_format"] = "utf8"
            notes.append("派生 IV ← 跨文件常量切片%s（来自 %s）"
                         % (iv_like[0]["range"], os.path.basename(str(iv_like[0]["origin"]))))
        if notes:
            ch["confidence"] = min(0.95, ch["confidence"] + 0.2)
            ch["bound_note"] = "；".join(notes)
            ch["suggest_cmd"] = kma._command_from_binding(ch)

    km["summary"] = {
        "disguised": len(km.get("disguised", [])),
        "derive_chains": len(km.get("derive_chains", [])),
        "candidate_keys": sum(1 for s in key_like + iv_like),
        "bound_chains": sum(1 for c in km.get("derive_chains", []) if c.get("bound_constants")),
    }
    return km, _kdf_plans(km)


def _kdf_plans(km: dict[str, Any]) -> list[dict[str, Any]]:
    """把派生链转成与现有配方同构的 plan，供 GUI 统一渲染 / 一键执行。"""
    out: list[dict[str, Any]] = []
    for ch in km.get("derive_chains", []) or []:
        steps = ch.get("steps") or []
        enc = next((s for s in steps if s["op"] in ("encrypt", "decrypt")), None)
        if not enc:
            continue
        bound = ch.get("bound_constants") or {}
        slices = next((s for s in steps if s["op"] == "slice"), None)
        digest = next((s for s in steps if s["op"] == "digest"), None)
        alg_disp = "%s-%s" % (str(enc.get("alg", "aes")).upper(), str(enc.get("mode", "cbc")).upper())
        label = "派生密钥 · %s(种子)→%s%s" % (
            alg_disp,
            str((digest or {}).get("alg", "sha256")).upper(),
            "→取[%s:%s]" % (slices.get("start"), slices.get("end")) if slices else "")
        enc_steps = ["① 取种子（报文里的 wx / 时间戳 / 设备号等运行时值）",
                     "② %s 用常量 A / 常量 B 加密种子" % alg_disp]
        if digest:
            enc_steps.append("③ 对密文做 %s 摘要" % str(digest["alg"]).upper())
        if slices:
            enc_steps.append("④ 取字节区间 [%s:%s] 得到正文密钥" % (slices.get("start"), slices.get("end")))
        dec_steps = ["① 用同样方式派生出密钥（见上）",
                     "② 用该密钥按对应算法解密正文"]
        out.append({
            "label": label,
            # alg 留空：这不是分组算法，避免 GUI 按算法下拉去匹配
            "alg": "", "alg_display": "密钥派生（KDF）",
            "mode": "", "padding": "", "encoding": "hex",
            "key_hex": bound.get("derive_key", ""),
            "iv_hex": bound.get("derive_iv", ""),
            "key_bytes": len(bound.get("derive_key", "")) if bound.get("derive_key") else 0,
            "key_origin": bound.get("derive_key") and "伪装常量切片（UTF-8 字面量）" or "尚未确定",
            "iv_origin": bound.get("derive_iv") and "伪装常量切片（UTF-8 字面量）" or "尚未确定",
            # 「可执行」= 常量齐了、命令能直接跑（种子仍需人工填）
            "executable": bool(bound.get("derive_key") and bound.get("derive_iv")),
            "missing_iv": not bound.get("derive_iv"),
            "has_integrity": False,
            "encryption_logic": enc_steps,
            "decryption_logic": dec_steps,
            "files": [str(ch.get("origin", ""))],
            "evidence": (ch.get("evidence") or [])[:6],
            "rules": ["key_material_derive"],
            "warnings": (["⚠ 种子需要人工确定（通常是报文里每次变化的随机值），填进命令即可复算出密钥"]
                         + (["⚠ 该链路来自字节码常量池共现推断，顺序需反编译核实"]
                            if ch.get("binary_hint") else [])),
            "cli": ch.get("suggest_cmd", ""),
            "confidence": ch.get("confidence", 0.3),
            "confidence_reason": "密钥材料分析：" + (ch.get("bound_note") or "仅形态识别"),
            # 让 GUI 能一键把参数填进 Tab 8 的派生面板（形成闭环）
            "is_derive": True,
            "derive_preset": ch.get("suggest_preset", ""),
            "derive_key": bound.get("derive_key", ""),
            "derive_key_format": bound.get("derive_key_format", "utf8"),
            "derive_iv": bound.get("derive_iv", ""),
            "derive_iv_format": bound.get("derive_iv_format", "utf8"),
            "slice": ("%s:%s" % (slices.get("start"), slices.get("end"))) if slices else "",
        })
    # 同一套派生方案（算法/摘要/区间/常量完全相同）只留置信度最高的一条
    dedup: dict[str, dict[str, Any]] = {}
    for p in out:
        sig = "|".join([p["label"], p["key_hex"], p["iv_hex"], p["cli"]])
        if sig not in dedup or p["confidence"] > dedup[sig]["confidence"]:
            dedup[sig] = p
    ranked = sorted(dedup.values(), key=lambda x: -x["confidence"])
    return ranked[:_MAX_KDF_PLANS]


def build_decrypt_plans(nodes: list[dict[str, Any]], graph: dict[str, Any],
                        chains: dict[str, Any]) -> list[dict[str, Any]]:
    """把整体分析出的「加密逻辑」反推成若干套**可执行解密方案**。

    核心是**跨文件合并**，这正是文件夹分析存在的意义：
      · 有的文件只有算法与模式（`CryptoJS.AES.encrypt(..., {mode:CBC})`）
      · 有的文件只有密钥字面量（`export const AES_KEY = '…'`）
    单看任一文件都做不出可执行的解密配方，必须按 import / 符号引用把它们拼起来。
    合并后还要**按真实密钥长度重算算法位宽**（16 字节 → AES-128，而不是默认的 AES-256）。
    """
    bucket = _collect_cipher_evidence(nodes)
    mats = _cipher_material(nodes)
    linked = _linked_material_files(nodes, graph, set(mats))
    plans: list[dict[str, Any]] = []

    for item in bucket.values():
        family = (item["primary_algorithm"] or "").lower()

        # ---- 组装「算法侧 + 密钥侧」的候选组合 ----
        combos: list[dict[str, Any]] = []
        if item["key_hex"]:
            # 同文件自洽：算法和密钥都拿到了
            combos.append({"mat": None, "self": True})
        else:
            seen_files: set[str] = set()
            for f in item["files"]:
                for mf in linked.get(f, []):
                    if mf in seen_files:
                        continue
                    seen_files.add(mf)
                    combos.append({"mat": mats[mf], "self": False})
        if not combos:
            combos.append({"mat": None, "self": False})     # 缺密钥也出一条，方便人工补

        for combo in combos:
            mat = combo["mat"]
            merged = dict(item)
            reasons: list[str] = []
            conf = 0.30
            extra_files: list[str] = []
            extra_evidence: list[dict[str, Any]] = []

            if combo["self"]:
                merged["key_hex"] = item["key_hex"]
                merged["iv_hex"] = item["iv_hex"]
                merged["key_bytes"] = len(item["key_hex"]) // 2
                conf += 0.30
                reasons.append("同文件内算法与密钥自洽（%d 字节密钥）" % merged["key_bytes"])
                if item["key_confidence"] == "high":
                    conf += 0.10
                    reasons.append("密钥提取置信度高")

                # 「密钥在同一个文件、IV 在另一个文件」同样常见：缺 IV 时再去引用的文件里补
                if _want_iv(merged["mode"]) and not merged["iv_hex"]:
                    for f in item["files"]:
                        for mf in linked.get(f, []):
                            m = mats.get(mf)
                            if not m or mf in item["files"]:
                                continue
                            r_iv = _resolve_material(family, merged["alg"], merged["mode"], m)
                            if not r_iv["iv_hex"]:
                                continue
                            merged["iv_hex"] = r_iv["iv_hex"]
                            merged["iv_origin"] = m["iv_origin"] or ("%s 中的 IV 字面量" % mf)
                            extra_files.append(mf)
                            extra_evidence.append({
                                "file": mf, "line": None, "role": "key_source",
                                "role_display": "取 IV",
                                "snippet": "IV 字面量（%s）：%s"
                                           % (r_iv["iv_how"], (m["iv_value"] or m["iv_hex"])[:60]),
                            })
                            reasons.append("IV 从 %s 补齐（原文件只定义了密钥）" % mf)
                            break
                        if merged["iv_hex"]:
                            break
            elif mat is not None:
                r = _resolve_material(family, item["alg"], item["mode"], mat)
                merged["alg"] = r["alg"]
                merged["key_hex"] = r["key_hex"]
                merged["iv_hex"] = r["iv_hex"]
                merged["key_bytes"] = len(r["key_hex"]) // 2
                merged["key_origin"] = mat["key_origin"] or ("%s 中的密钥字面量" % mat["file"])
                merged["iv_origin"] = mat["iv_origin"] or ("%s 中的 IV 字面量" % mat["file"])
                extra_files = [mat["file"]]
                if r["key_hex"]:
                    conf += 0.34
                    reasons.append("跨文件合并出 %d 字节密钥（%s）" % (merged["key_bytes"], r["key_how"]))
                    if r["iv_hex"]:
                        reasons.append("IV 来自 %s（%s）" % (mat["file"], r["iv_how"]))
                    elif _want_iv(merged["mode"]):
                        reasons.append("⚠ 未取到 IV，而 %s 必需 IV" % merged["mode"].upper())
                else:
                    reasons.append("找到了密钥材料但长度不合法，已原样给出供人工核对")
                extra_evidence.append({
                    "file": mat["file"], "line": None, "role": "key_source",
                    "role_display": "取密钥",
                    "snippet": "密钥字面量（%s）：%s" % (
                        r["key_how"] or mat["key_confidence"] or "待人工确认",
                        (mat["key_value"] or mat["key_hex"])[:60]),
                })
                if mat["file"] not in item["files"]:
                    reasons.append("算法来自 %s、密钥来自 %s（跨文件拼接）"
                                   % ("、".join(item["files"][:2]), mat["file"]))
            else:
                reasons.append("未找到配套密钥材料（算法已识别，密钥需人工补全）")

            if len(item["files"]) >= 2:
                conf += 0.10
                reasons.append("%d 个文件互证同一算法/模式" % len(item["files"]))
            if item["role_roles"]:
                conf += 0.06
                reasons.append("角色链完整（%s）" % "→".join(
                    ROLE_DISPLAY.get(r, r) for r in sorted(
                        item["role_roles"], key=lambda r: ROLE_ORDER.get(r, 9))))
            if item["primary_algorithm"]:
                conf += 0.04

            needs_iv = _want_iv(merged["mode"])
            missing_iv = bool(needs_iv and not merged["iv_hex"])
            if missing_iv:
                conf -= 0.15
                reasons.append("⚠ 未取到 IV，而 %s 模式必须提供（否则解不出来）"
                               % (merged["mode"] or "cbc").upper())

            enc_steps, dec_steps, label = _logic_texts(merged)
            all_files = list(item["files"])
            for f in extra_files:
                if f not in all_files:
                    all_files.append(f)

            plans.append({
                "label": label,
                "alg": merged["alg"],
                "alg_display": _alg_display(merged["alg"]),
                "mode": merged["mode"],
                "padding": merged["padding"],
                "encoding": merged["encoding"],
                "key_hex": merged["key_hex"],
                "iv_hex": merged["iv_hex"],
                "key_bytes": merged["key_bytes"] or 0,
                "key_origin": merged["key_origin"],
                "iv_origin": merged["iv_origin"],
                # ★ 「可执行」必须把 IV 也算进去：CBC/CFB/OFB/CTR/GCM 没有 IV 根本解不出来，
                #   只看「有没有密钥」会给出一个点了必然失败的按钮（实测踩过）。
                "executable": bool(merged["key_hex"] and merged["alg"] and not missing_iv),
                "missing_iv": missing_iv,
                "has_integrity": bool(merged["alg"]
                                      and cc.has_integrity_check(merged["mode"], merged["padding"])),
                "encryption_logic": enc_steps,
                "decryption_logic": dec_steps,
                "files": all_files,
                "evidence": (item["evidence"] + extra_evidence)[:14],
                "rules": item["rules"],
                "warnings": list(item["warnings"]),
                "cli": _plan_cli(merged),
                "confidence": round(min(conf, 0.98), 2),
                "confidence_reason": "；".join(reasons),
            })

    # 同一套配方可能被多个文件重复产出，按「算法+密钥+IV+编码」再收敛一次
    dedup: dict[str, dict[str, Any]] = {}
    for p in plans:
        sig = "|".join([p["alg"], p["mode"], p["padding"], p["key_hex"], p["iv_hex"], p["encoding"]])
        old = dedup.get(sig)
        if old is None or p["confidence"] > old["confidence"]:
            dedup[sig] = p
    plans = list(dedup.values())

    plans.sort(key=lambda p: (0 if p["executable"] else 1, -p["confidence"]))
    return plans[:_MAX_PLANS]


def offline_decrypt_logic_text(plans: list[dict[str, Any]]) -> list[str]:
    """不依赖 LLM：用规则把「整体解密逻辑」写成一段可直接读的说明。"""
    if not plans:
        return ["未从目录中提取到任何可执行的对称加密配方，无法给出解密逻辑。"
                "（常见原因：加密在服务端、密钥运行时下发、或加密库被压缩/加壳）"]
    out: list[str] = []
    exe = [p for p in plans if p["executable"]]
    if not exe:
        out.append("检出 %d 套加密方案，但都没能提取到密钥，暂时无法自动解密。" % len(plans))
        for p in plans[:3]:
            out.append("· %s（出现在 %s）—— 需人工补密钥" % (p["label"], "、".join(p["files"][:3])))
        return out

    out.append("整体解密思路：密文先用「与加密相反的编码」还原成字节，"
               "再用同一把密钥与同一组算法/模式/填充解回来，最后按 UTF-8 得到明文。")
    for i, p in enumerate(exe[:5], 1):
        out.append("方案 %d：%s" % (i, p["label"]))
        out.append("　密钥：%s（%s）" % (p["key_hex"][:24] + "…" if p["key_hex"] else "缺",
                                        p["key_origin"] or "文件内硬编码"))
        if p["iv_hex"]:
            out.append("　IV：%s（%s）" % (p["iv_hex"][:24] + "…", p["iv_origin"] or "文件内硬编码"))
        out.append("　解密步骤：" + " → ".join(
            re.sub(r"^[①②③④⑤⑥]\s*", "", s).strip() for s in p["decryption_logic"][:4]))
        out.append("　可用文件：" + "、".join(p["files"][:4]))
        if not p["has_integrity"]:
            out.append("　⚠ 该组合无完整性校验：密钥不对不会报错，只会解出乱码，"
                       "所以要看解出来的内容是否符合业务预期。")
    if len(exe) > 5:
        out.append("（另有 %d 套方案，见下方解密配方列表）" % (len(exe) - 5))
    return out


def _read_cipher_input(text_arg: str | None, file_arg: str | None) -> tuple[str, str]:
    """读取待解密的密文。返回 (密文文本, 来源说明)。"""
    if file_arg:
        path = os.path.abspath(file_arg)
        if not os.path.isfile(path):
            raise ValueError("密文文件不存在：%s" % path)
        size = os.path.getsize(path)
        if size > _MAX_DECRYPT_INPUT:
            raise ValueError("密文文件过大（%.1f MB，上限 %d MB）"
                             % (size / 1048576.0, _MAX_DECRYPT_INPUT // 1048576))
        with open(path, "rb") as fh:
            raw = fh.read()
        try:
            return raw.decode("utf-8"), "文件 %s" % path
        except UnicodeDecodeError:
            # ★ 二进制密文（.bin / 抓包导出的原始 body）绝不能 errors="replace" 硬解，
            #   那会把每个非 UTF-8 字节换成 U+FFFD，密文就废了。
            #   转成 HEX 字符串：后续 "hex" 解码链能精确还原成原始字节。
            return raw.hex(), "文件 %s（二进制，按原始字节处理）" % path
    if text_arg is not None:
        if len(text_arg) > _MAX_TEXT_ARG:
            raise ValueError(
                "密文过长（%d 字符，命令行/输入框上限 %d 字符）。\n"
                "本机命令行长度有限，超长会被系统悄悄截断、导致解密结果错误。\n"
                "请把密文保存成文件，改用：--decrypt-file <文件路径>"
                % (len(text_arg), _MAX_TEXT_ARG))
        return text_arg, "命令行/输入框"
    # 兜底：从 stdin 读（管道用法：type cipher.txt | python ... --decrypt-text -）
    data = sys.stdin.read()
    return data, "标准输入"


def decrypt_ciphertext(ciphertext: str, plans: list[dict[str, Any]],
                       plan_id: str = "auto", on_step=None,
                       prefer_hex: bool = False) -> dict[str, Any]:
    """用配方解密：自动尝试「多方案 × 多输入编码链」，按明文特征选最优。

    为什么必须自动尝试：
      · 用户只知道「复制一段密文」，并不知道它有没有被二次编码；
      · CBC/ECB 解错密钥**不报错**，只会出乱码 —— 必须靠打分而不是异常来判定。
    """
    step = _mk_step(on_step)
    text = (ciphertext or "").strip()
    if not text:
        return {"ok": False, "message": "没有收到任何密文内容。", "attempts": []}

    candidates = [p for p in plans if p.get("executable")]
    if plan_id and plan_id != "auto":
        picked = [p for p in plans if p.get("label") == plan_id or p.get("id") == plan_id]
        if not picked:
            return {"ok": False, "message": "找不到指定的方案：%s" % plan_id, "attempts": []}
        candidates = picked
    if not candidates:
        return {"ok": False, "attempts": [],
                "message": "没有可执行的解密配方（缺少密钥）。请先在文件夹整体分析里确认密钥，"
                           "或手动补全 --key / --iv 后重试。"}

    attempts: list[dict[str, Any]] = []
    total = max(1, len(candidates))
    for i, plan in enumerate(candidates, 1):
        chains = _input_chains(plan.get("encoding") or "base64", prefer_hex=prefer_hex)
        for chain in chains:
            label = "→".join(chain)
            step(10 + 70.0 * (i - 1) / total,
                 "尝试方案 %d/%d（%s）· 输入编码 %s" % (i, total, plan["label"], label))
            data = _decode_chain(text, chain)
            if data is None:
                attempts.append({"plan": plan["label"], "input_chain": label,
                                 "ok": False, "reason": "按该编码解不开（不是这种编码）"})
                continue
            try:
                plain = cc.do_crypt(
                    plan["alg"], "dec", plan["key_hex"],
                    plan["iv_hex"] or None, data,
                    mode=plan["mode"], padding=plan["padding"], warn_weak=False,
                )
            except Exception as exc:  # noqa: BLE001 —— 单次尝试失败不能中断整体
                attempts.append({"plan": plan["label"], "input_chain": label, "ok": False,
                                 "reason": "%s" % exc})
                continue
            ok, score, reason = _looks_like_plaintext(plain)
            attempts.append({
                "plan": plan["label"], "input_chain": label, "ok": ok,
                "score": round(score, 2), "reason": reason,
                "plaintext": plain.decode("utf-8", errors="replace") if ok else plain[:120].decode("utf-8", errors="replace"),
                "bytes": len(plain),
            })
            if score >= 0.90:      # 已经足够确定，不必继续烧时间
                break
        if any(a.get("score", 0) >= 0.90 for a in attempts):
            break

    step(100, "解密尝试完成（共 %d 次）" % len(attempts))
    good = [a for a in attempts if a.get("ok")]
    good.sort(key=lambda a: -a.get("score", 0))
    if good:
        best = good[0]
        return {
            "ok": True,
            "plaintext": best["plaintext"],
            "plan": best["plan"],
            "input_chain": best["input_chain"],
            "score": best["score"],
            "reason": best["reason"],
            "bytes": best["bytes"],
            "alternatives": good[1:4],
            "attempts": attempts,
            "message": "解密成功（方案：%s；输入编码：%s）" % (best["plan"], best["input_chain"]),
        }

    hint = ("所有方案都没解出可读明文。可能原因：\n"
            "  ① 密文经过本工具没识别到的编码（如自定义字符集/压缩后再加密）\n"
            "  ② 这套密文用的密钥/IV 不在目录里（服务端下发或运行时拼装）\n"
            "  ③ 该接口本身就是不加密的（部分接口明文返回）\n"
            "  ④ 密文被截断或复制时丢了字符\n"
            "建议：确认密文完整；或用 --show-evidence 看证据包里的候选密钥是否选对。")
    return {"ok": False, "attempts": attempts, "message": hint}


# ============================================================================
# 5) 整体证据包
# ============================================================================
def build_folder_evidence(folder: dict[str, Any], nodes: list[dict[str, Any]],
                          graph: dict[str, Any], chains: dict[str, Any],
                          plans: list[dict[str, Any]] | None = None,
                          budget_chars: int = DEFAULT_FOLDER_EVIDENCE_CHARS) -> str:
    """把整个文件夹压缩成一份「LLM 可消费的整体证据包」。"""
    out: list[str] = []

    # ---- A. 范围 ----
    out.append("【分析范围】")
    out.append("目录：%s" % folder["root"])
    out.append("文件总数：%d（扫描分析 %d 个，按相关度排序取前 %d；超限丢弃 %d 个）"
               % (folder["total_files"], folder["scanned_files"],
                  folder["scanned_files"], folder.get("dropped_count", 0)))
    out.append("总体积：%.1f KB" % (folder.get("total_bytes", 0) / 1024.0))
    hits = [n for n in nodes if n["hits"]]
    out.append("与密码学相关的文件：%d 个" % len(hits))
    if folder.get("ext_histogram"):
        top = list(folder["ext_histogram"].items())[:12]
        out.append("文件类型分布：" + "、".join("%s×%d" % (e, c) for e, c in top))
    out.append("")

    # ---- B. 关系图（这是「整体」的核心）----
    st = graph.get("stats", {})
    out.append("【跨文件关系图】")
    out.append("节点 %d 个、边 %d 条（import %d / 共享密钥 %d / 符号引用 %d / 同库 %d）"
               % (st.get("nodes", 0), st.get("edges", 0), st.get("import_edges", 0),
                  st.get("shared_key_edges", 0), st.get("symbol_edges", 0),
                  st.get("same_lib_edges", 0)))
    if graph.get("edges"):
        out.append("关系明细（文件 → 文件 : 关系）：")
        for e in graph["edges"][:60]:
            out.append("  - %s → %s : %s" % (e["from"], e["to"], e["label"]))
    else:
        out.append("（未检出跨文件引用关系——可能是各文件独立实现，或文件间通过后端/运行时弱耦合）")
    if graph.get("shared_keys"):
        out.append("共享密钥材料：")
        for sk in graph["shared_keys"][:12]:
            out.append("  - %s…  出现在 %d 个文件：%s"
                       % (sk["key"][:40], sk["count"], "、".join(sk["files"][:6])))
    if graph.get("external_imports"):
        out.append("外部依赖（未在目录内解析到实现）："
                   + "、".join("%s×%d" % (i["spec"], i["count"])
                               for i in graph["external_imports"][:15]))
    out.append("")

    # ---- C. 数据流链路 ----
    out.append("【跨文件数据流链路】")
    if chains.get("dominant_path"):
        out.append("整体语义路径：" + chains["dominant_path"])
    for s in chains.get("stages") or []:
        out.append("· %s（%d 处）：涉及 %s"
                   % (s["role_display"], s["count"],
                      "、".join(s["files"][:8]) + ("…" if len(s["files"]) > 8 else "")))
        for sm in s["samples"][:2]:
            out.append("    - [%s:%s] %s" % (sm["file"], sm.get("line", "?"), sm.get("snippet", "")[:150]))
    out.append("")

    # ---- C2. 可执行解密配方（本地规则反推，让 LLM 有据可依、不要凭空编密钥）----
    if plans:
        out.append("【可执行解密配方（本地从加密逻辑反推，密钥为逐字提取的原文）】")
        for i, p in enumerate(plans[:6], 1):
            out.append("· 配方%d：%s  置信度 %.2f" % (i, p["label"], p["confidence"]))
            out.append("    - 算法/模式/填充：%s / %s / %s；密文编码：%s"
                       % (p["alg"], p["mode"], p["padding"], p["encoding"]))
            if p["key_hex"]:
                out.append("    - 密钥（HEX）：%s（%d 字节，来源：%s）"
                           % (p["key_hex"], p["key_bytes"], p["key_origin"] or "文件内硬编码"))
            else:
                out.append("    - 密钥：未提取到")
            if p["iv_hex"]:
                out.append("    - IV（HEX）：%s（来源：%s）"
                           % (p["iv_hex"], p["iv_origin"] or "文件内硬编码"))
            out.append("    - 涉及文件：" + "、".join(p["files"][:5]))
            out.append("    - 加密侧：" + "；".join(p["encryption_logic"]))
            out.append("    - 解密侧（逆序即可复现）：" + "；".join(
                re.sub(r"^[①②③④⑤⑥]\s*", "", s).strip() for s in p["decryption_logic"]))
        out.append("")

    # ---- D. 重点文件明细（按相关度取前 N，受预算约束）----
    out.append("【重点文件明细（按相关度排序）】")
    used = sum(len(x) + 1 for x in out)
    for n in sorted(nodes, key=lambda x: -x["score"]):
        if used > budget_chars:
            out.append("…（预算用尽，其余 %d 个文件已省略；可通过提高 --evidence-chars 放宽）"
                       % max(0, len(hits) - len([x for x in out if x.startswith("###")])))
            break
        if not n["hits"] and n["score"] == 0:
            continue
        block: list[str] = []
        block.append("### %s  [%s, %.1f KB, 相关度 %d]" % (n["id"], n["type_display"] or "未知",
                                                         n["size"] / 1024.0, n["score"]))
        if n.get("error"):
            block.append("  ! 分析失败：%s" % n["error"])
        if n["algos"]:
            block.append("  算法特征：" + "、".join(n["algos"][:10]))
        if n["libs"]:
            block.append("  密码库：" + "、".join(n["libs"][:8]))
        if n["imports"]:
            block.append("  import：" + "、".join(n["imports"][:10]))
        if n["secrets"]:
            block.append("  密钥材料：")
            for s in n["secrets"][:12]:
                block.append("    - [%s] %s（%s%s）"
                             % (s.get("confidence", "?"), s["value"][:60], s.get("kind", ""),
                                (" · %d 字节" % s["bytes_len"]) if s.get("bytes_len") else ""))
        if n["symbols"]:
            block.append("  密码学相关符号：" + "、".join(n["symbols"][:12]))
        if n["roles"]:
            block.append("  角色证据：")
            for r in n["roles"][:_MAX_SNIPPETS_PER_FILE]:
                block.append("    - [%s · L%s] %s" % (r["role_display"], r.get("line"), r["snippet"][:180]))
        text = "\n".join(block)
        out.append(text)
        used += len(text) + 1

    # ---- E. 未能扫描的文件（让模型知道证据边界）----
    if folder.get("skipped"):
        out.append("")
        out.append("【未纳入分析的文件（节选）】")
        for s in folder["skipped"][:12]:
            out.append("  - %s：%s" % (s["path"], s["reason"]))

    return "\n".join(out)


# ============================================================================
# 6) 整体总结（在线 LLM / 离线兜底）
# ============================================================================
FOLDER_SYSTEM_PROMPT = """你是一名资深应用安全 / 密码学逆向分析师。用户给你的是**一个项目目录的「整体证据包」**，
里面包含：① 分析范围与文件类型分布 ② 跨文件关系图（import / 共享密钥 / 符号引用）
③ 跨文件数据流链路（取钥→初始化→加解密→编码→传输 的语义阶段）
④ **可执行解密配方**（本地规则已从加密逻辑反推出 alg/mode/padding + 逐字提取的 HEX 密钥/IV）
⑤ 按相关度排序的重点文件明细（算法特征 / 密码库 / import / 密钥材料 / 角色证据片段）。

你的任务是**站在整个项目的高度**做整体分析，而不是逐文件复述。只输出一段 JSON：

{
  "system_overview": "整体加密体系的一段话总结：这个项目整体上用什么加密方案、用在什么环节、为什么这么做",
  "data_flow": ["按时间顺序的数据流步骤，每步说明『在哪个文件做什么』，例如：config.js 定义 AES 密钥 → crypto.js 用 CBC/PKCS7 加密 → api.js Base64 后经 axios 发出"],
  "key_management": "密钥管理评价：密钥从哪来、是否跨文件共享/硬编码、是否有派生、是否随请求下发",
  "cross_file_logic": ["跨文件串联逻辑的关键结论，例如：A 与 B 共享同一密钥说明是同一条业务链；C 只做编码不做加密"],
  "algorithms": [{"alg": "aes256", "mode": "cbc", "padding": "pkcs7", "where": "文件或模块", "usage": "用途"}],
  "decrypt_logic": ["把上面这套加密逻辑反过来写成『拿到密文之后怎么一步步解回明文』的操作说明，逐条列出，例如：① 密文按 Base64 解码得到字节 ② 用同一密钥（HEX: xxx）与同一 IV 做 AES-128-CBC 解密并去掉 PKCS7 填充 ③ 得到的字节按 UTF-8 解码即为明文 ④ 若业务侧还做过二次 Base64（如 btoa），需先剥一层再解密"],
  "risks": ["整体性风险（跨文件才能看出的问题优先，例如密钥多处共享导致一处泄露全线失守、前后端同源密钥、仅前端加密后端不校验）"],
  "confidence": 0.0~1.0,
  "warnings": ["证据不足或不确定的点"]
}

约束：
- 只输出 JSON，不要 markdown 代码块，不要额外解释。
- 如果证据包里的关系图信息稀薄（例如只有单文件有密码学证据），要如实说明「未发现明显的跨文件串联」，不要编造调用链。
- 结论必须能对应到证据包里的文件名或片段；证据不足就降低 confidence。
- alg/mode/padding 取自：aes128/aes192/aes256/sm4/des/des3/rc4，ecb/cbc/cfb/ofb/ctr/gcm，
  pkcs7/zero/none/iso7816/ansix923。
- **decrypt_logic 里的密钥/IV 必须逐字复制证据包【可执行解密配方】里的 HEX 值，绝对不要自己推算或编造**；
  配方里没有密钥就写「密钥未提取到，需人工补全」，不要猜。
- decrypt_logic 要写成「用户拿去就能照着操作」的步骤，而不是复述加密方案的名字。"""

FOLDER_USER_TEMPLATE = """请对下面这个项目的整体证据包做「整体分析 + 整体总结」。

<<<证据包开始>>>
%s
<<<证据包结束>>>"""


def folder_summary_online(evidence: str, cfg, step=None, pct: int = 92) -> dict[str, Any]:
    """把整体证据包交给在线 LLM，产出整体总结。"""
    parsed = aica.llm_json(FOLDER_SYSTEM_PROMPT, FOLDER_USER_TEMPLATE % evidence,
                           cfg, step=step, pct=pct, label="整体总结")
    return {
        "source": "online",
        "model": cfg.model,
        "system_overview": parsed.get("system_overview") or "",
        "data_flow": parsed.get("data_flow") or [],
        "key_management": parsed.get("key_management") or "",
        "cross_file_logic": parsed.get("cross_file_logic") or [],
        "algorithms": parsed.get("algorithms") or [],
        "decrypt_logic": parsed.get("decrypt_logic") or [],
        "risks": parsed.get("risks") or [],
        "confidence": float(parsed.get("confidence", 0.8) or 0.8),
        "warnings": parsed.get("warnings") or [],
        "note": "在线 LLM（%s）基于整体证据包判定" % cfg.model,
    }


def folder_summary_offline(folder: dict[str, Any], nodes: list[dict[str, Any]],
                           graph: dict[str, Any], chains: dict[str, Any],
                           plans: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """离线兜底：完全用规则把整体结论拼出来（零网络、零依赖）。"""
    hits = [n for n in nodes if n["hits"]]
    alg_counter: dict[str, int] = {}
    lib_counter: dict[str, int] = {}
    for n in hits:
        for a in n["algos"]:
            alg_counter[a] = alg_counter.get(a, 0) + 1
        for l in n["libs"]:
            lib_counter[l] = lib_counter.get(l, 0) + 1
    top_algs = sorted(alg_counter.items(), key=lambda kv: -kv[1])[:6]
    top_libs = sorted(lib_counter.items(), key=lambda kv: -kv[1])[:5]

    overview = ("共扫描 %d 个文件，其中 %d 个含密码学特征；"
                % (folder["scanned_files"], len(hits)))
    if top_algs:
        overview += "出现最多的算法特征为 " + "、".join("%s(×%d)" % (a, c) for a, c in top_algs) + "；"
    if top_libs:
        overview += "主要依赖密码库 " + "、".join(l for l, _ in top_libs) + "；"
    if graph["stats"]["shared_key_edges"] or graph["stats"]["symbol_edges"]:
        overview += "检出跨文件串联关系（共享密钥 %d 条 / 符号引用 %d 条）。" % (
            graph["stats"]["shared_key_edges"], graph["stats"]["symbol_edges"])
    else:
        overview += "未检出明显的跨文件引用关系。"

    data_flow = []
    for s in chains.get("stages") or []:
        data_flow.append("%s：%s" % (s["role_display"], "、".join(s["files"][:5])))

    key_management = "（离线规则）"
    if graph.get("shared_keys"):
        key_management = ("检出 %d 组跨文件共享的密钥材料，例如 %s… 同时出现在 %s；"
                          "说明这些文件属于同一条业务链，但也意味着任一文件泄露即全线失守。"
                          % (len(graph["shared_keys"]), graph["shared_keys"][0]["key"][:24],
                             "、".join(graph["shared_keys"][0]["files"][:4])))
    else:
        hard = [n for n in hits if n["secrets"]]
        key_management = ("未检出跨文件共享密钥；但有 %d 个文件含硬编码密钥材料，"
                          "建议逐个人工确认来源与分发方式。" % len(hard))

    cross_logic = []
    for e in (graph.get("edges") or [])[:12]:
        cross_logic.append("%s → %s：%s" % (e["from"], e["to"], e["label"]))
    if not cross_logic:
        cross_logic.append("未检出跨文件引用/共享关系，各文件可能是独立实现。")

    risks = []
    if graph.get("shared_keys"):
        risks.append("同一密钥材料跨 %d 个文件共享：一处泄露全线失守，且轮换需多处同步修改。"
                     % len(graph["shared_keys"]))
    if any("前端" in (n.get("type_display") or "") or n["ext"] in (".js", ".ts", ".vue", ".html")
           for n in hits):
        risks.append("存在前端（客户端）文件参与加密：密钥必然下发到客户端，等同公开，不能作为服务端信任边界。")
    sec_files = [n for n in hits if n["secrets"]]
    if sec_files:
        risks.append("%d 个文件硬编码了密钥材料（如 %s），建议改为环境变量/密钥管理服务。"
                     % (len(sec_files), "、".join(n["label"] for n in sec_files[:4])))
    if not risks:
        risks.append("未从规则层面检出明显整体性风险，建议结合人工复核。")

    return {
        "source": "offline-folder",
        "model": "",
        "system_overview": overview,
        "data_flow": data_flow,
        "key_management": key_management,
        "cross_file_logic": cross_logic,
        "algorithms": [{"alg": a, "where": "多处", "usage": "规则统计"} for a, _ in top_algs],
        "decrypt_logic": offline_decrypt_logic_text(plans or []),
        "risks": risks,
        "confidence": 0.55,
        "warnings": ["本次为离线规则总结（未调用在线 LLM），结论粒度较粗，建议启用在线 LLM 获取整体推断。"],
        "note": "离线规则整体总结",
    }


# ============================================================================
# 7) 主流程
# ============================================================================
def analyze_folder(root: str, cfg=None, *, deep: bool = False,
                   max_files: int = DEFAULT_MAX_FILES,
                   max_file_mb: float = DEFAULT_MAX_FILE_MB,
                   evidence_chars: int = DEFAULT_FOLDER_EVIDENCE_CHARS,
                   use_llm: bool = True,
                   plans_out: str | None = None,
                   on_step=None) -> dict[str, Any]:
    """文件夹整体分析主流程。"""
    t0 = time.time()
    step = _mk_step(on_step)

    # ---- 1) 遍历 ----
    folder = walk_folder(root, max_files=max_files, max_file_mb=max_file_mb, on_step=on_step)
    if folder["scanned_files"] == 0:
        return {
            "status": "empty", "mode": "folder", "folder": folder,
            "files": [], "graph": {"nodes": [], "edges": [], "shared_keys": [],
                                   "external_imports": [], "stats": {}},
            "chains": {"chains": [], "flow": [], "stages": [], "dominant_path": ""},
            "decrypt_plans": [], "plans_path": "",
            "summary": None,
            "warnings": ["目录内没有可分析的文件（全部为空、超限或被排除）。"],
        }

    # ---- 2) 逐文件摘要 ----
    # 只对排在前面的文件保留文本（供跨文件符号引用检测），避免把几百份源码全留在内存里
    nodes: list[dict[str, Any]] = []
    total = len(folder["files"])
    for i, entry in enumerate(folder["files"], 1):
        step(int(10 + 60.0 * i / total), "分析文件 %d/%d：%s" % (i, total, entry["rel"]))
        nodes.append(analyze_one_file(root, entry, deep=deep, keep_text=(i <= _MAX_TEXT_KEEP)))

    # ---- 2b) 跨文件「符号引用」检测（必须在构图之前完成）----
    step(72, "检测跨文件符号引用")
    attach_symbol_refs(nodes)
    # 用完即弃：大段源码绝不进最终 JSON
    for n in nodes:
        n.pop("_text", None)

    # ---- 3) 关系图 + 链路 ----
    step(78, "构建跨文件关系图")
    graph = build_graph(nodes)
    step(84, "重建跨文件数据流链路")
    chains = build_chains(nodes, graph)

    # ---- 3b) 解密配方：把加密逻辑反推成可执行的解密逻辑 ----
    step(86, "反推可执行解密配方")
    plans = build_decrypt_plans(nodes, graph, chains)

    # ---- 3.5) 密钥材料：伪装常量解码 + 派生链识别（跨文件绑定）----
    step(87, "分析伪装常量与密钥派生链")
    key_material, kdf_plans = _analyze_key_material(folder.get("root") or root)
    plans = plans + kdf_plans
    written = _save_plans(plans, plans_out)

    # ---- 4) 整体证据包 ----
    step(88, "组装整体证据包")
    evidence = build_folder_evidence(folder, nodes, graph, chains,
                                     plans=plans, budget_chars=evidence_chars)

    # ---- 5) 整体总结 ----
    summary = None
    warnings: list[str] = []
    source = "offline-folder"
    if use_llm and cfg is not None and getattr(cfg, "is_usable", lambda: False)():
        try:
            step(90, "调用在线 LLM 做整体总结（模型：%s）" % cfg.model)
            summary = folder_summary_online(evidence, cfg, step=on_step, pct=92)
            source = "online"
        except Exception as exc:  # noqa: BLE001
            kind = getattr(exc, "kind", "unknown")
            warnings.append("在线整体总结失败（%s），已降级为离线规则总结：%s" % (kind, exc))
            warnings.append("排查建议：%s" % aica._remediation(kind))
            summary = folder_summary_offline(folder, nodes, graph, chains, plans)
            source = "offline-fallback"
    else:
        step(92, "未启用在线 LLM，使用离线规则做整体总结")
        summary = folder_summary_offline(folder, nodes, graph, chains, plans)
        source = "offline-folder"

    # 在线 LLM 没给解密逻辑（或整段失败）时，用本地规则文本兜底，保证这个板块永远有内容
    if not (summary or {}).get("decrypt_logic"):
        summary["decrypt_logic"] = offline_decrypt_logic_text(plans)

    step(100, "整体分析完成")

    hit_nodes = [n for n in nodes if n["hits"]]
    return {
        "status": "ok",
        "mode": "folder",
        "source": source,
        "folder": folder,
        "files": [{
            "id": n["id"], "label": n["label"], "size": n["size"], "ext": n["ext"],
            "type_display": n["type_display"], "category": n["category"],
            "algos": n["algos"], "libs": n["libs"], "domains": n["domains"],
            "secrets": n["secrets"][:12], "symbols": n["symbols"][:12],
            "imports": n["imports"][:12], "roles": n["roles"][:6],
            "score": n["score"], "hits": n["hits"], "error": n.get("error", ""),
        } for n in sorted(nodes, key=lambda x: -x["score"])],
        "graph": graph,
        "chains": chains,
        "key_material": key_material,
        "decrypt_plans": plans,
        "plans_path": written or plans_path(),
        "evidence_preview": evidence[:1500],
        "evidence_chars": len(evidence),
        "summary": summary,
        "stats": {
            "scanned_files": folder["scanned_files"],
            "crypto_files": len(hit_nodes),
            "total_files_in_dir": folder["total_files"],
            "edges": graph["stats"].get("edges", 0),
            "shared_keys": len(graph.get("shared_keys") or []),
            "chains": len(chains.get("chains") or []),
            "decrypt_plans": len(plans),
            "executable_plans": sum(1 for p in plans if p["executable"]),
            "disguised_constants": len(key_material.get("disguised") or []),
            "derive_chains": len(key_material.get("derive_chains") or []),
            "elapsed_sec": round(time.time() - t0, 2),
        },
        "warnings": warnings,
    }


# ============================================================================
# 8) CLI
# ============================================================================
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="文件夹整体分析（多文件 + 跨文件串联逻辑 + 整体总结）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--dir", help="要整体分析的目录")
    p.add_argument("--deep", action="store_true", help="对压缩包内层做深挖（更慢更全）")
    p.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES,
                   help="最多分析多少个文件（按相关度排序取前 N，默认 %d）" % DEFAULT_MAX_FILES)
    p.add_argument("--max-file-mb", type=float, default=DEFAULT_MAX_FILE_MB,
                   help="单文件体积上限 MB（默认 %.1f）" % DEFAULT_MAX_FILE_MB)
    p.add_argument("--evidence-chars", type=int, default=DEFAULT_FOLDER_EVIDENCE_CHARS,
                   help="整体证据包字符预算（默认 %d）" % DEFAULT_FOLDER_EVIDENCE_CHARS)
    p.add_argument("--plans-out", help="把解密配方写到此文件（默认写临时目录，供后续 --decrypt 复用）")
    p.add_argument("--no-llm", action="store_true", help="只用离线规则做整体总结，不调用在线 LLM")
    p.add_argument("--show-evidence", action="store_true",
                   help="把整体证据包完整打印到 stderr（排查用）")
    p.add_argument("--show-plans", action="store_true",
                   help="分析完只打印解密配方（加密逻辑→解密逻辑），便于快速取用")

    # ---- 解密模式：用上次分析出的配方直接解密密文（无需重新遍历目录）----
    dp = p.add_argument_group("解密（用整体分析出的配方直接解密）")
    dp.add_argument("--decrypt-text", nargs="?", const="-",
                    help="要解密的密文；不带值则从标准输入读（管道用法）")
    dp.add_argument("--decrypt-file", help="从文件读取密文（二进制/大密文用这个）")
    dp.add_argument("--plans", help="解密配方文件路径（默认读 --plans-out / 临时目录里的那份）")
    dp.add_argument("--plan", default="auto",
                    help="只用指定方案（默认 auto：自动尝试全部可执行方案）")

    p.add_argument("--json", action="store_true", help="以 JSON 输出")
    p.add_argument("--progress", action="store_true",
                   help="向 stderr 播报进度（[PROGRESS] 百分比 步骤），供 GUI 进度条")
    p.add_argument("--selftest", action="store_true", help="运行自检")
    return p


def _print_human(r: dict[str, Any]) -> None:
    folder = r.get("folder", {})
    print("=== 文件夹整体分析 ===")
    print("目录：%s" % folder.get("root"))
    print("文件：总 %d / 扫描 %d / 含密码学特征 %d"
          % (folder.get("total_files", 0), folder.get("scanned_files", 0),
             r.get("stats", {}).get("crypto_files", 0)))
    g = r.get("graph", {}).get("stats", {})
    print("关系图：节点 %d · 边 %d（import %d / 共享密钥 %d / 符号 %d）"
          % (g.get("nodes", 0), g.get("edges", 0), g.get("import_edges", 0),
             g.get("shared_key_edges", 0), g.get("symbol_edges", 0)))
    print("\n--- 跨文件关系 ---")
    for e in (r.get("graph", {}).get("edges") or [])[:20]:
        print("  %s → %s : %s" % (e["from"], e["to"], e["label"]))
    ch = r.get("chains", {})
    print("\n--- 数据流语义路径 ---")
    print("  " + (ch.get("dominant_path") or "（未检出）"))
    for s in ch.get("stages") or []:
        print("  · %s：%s" % (s["role_display"], "、".join(s["files"][:6])))
    sm = r.get("summary") or {}
    print("\n--- 整体总结（%s）---" % sm.get("source", "?"))
    print("体系：%s" % sm.get("system_overview", ""))
    if sm.get("data_flow"):
        print("数据流：")
        for i, d in enumerate(sm["data_flow"], 1):
            print("  %d) %s" % (i, d))
    if sm.get("key_management"):
        print("密钥管理：%s" % sm["key_management"])
    if sm.get("cross_file_logic"):
        print("跨文件逻辑：")
        for c in sm["cross_file_logic"]:
            print("  - %s" % c)
    if sm.get("decrypt_logic"):
        print("\n--- 解密逻辑（按加密逻辑反推）---")
        for line in sm["decrypt_logic"]:
            print("  %s" % line)
    plans = r.get("decrypt_plans") or []
    if plans:
        print()
        _print_plans(plans, out=sys.stdout, show_cli=False)
    if sm.get("risks"):
        print("\n整体风险：")
        for c in sm["risks"]:
            print("  ⚠ %s" % c)
    print("\n耗时 %.2fs · 证据包 %d 字符" % (r.get("stats", {}).get("elapsed_sec", 0),
                                          r.get("evidence_chars", 0)))


def _print_plans(plans: list[dict[str, Any]], out=None, show_cli: bool = True) -> None:
    """打印解密配方：加密逻辑 ↔ 解密逻辑 对照。"""
    out = out or sys.stdout
    if not plans:
        print("（未提取到可执行的解密配方）", file=out)
        return
    print("=== 可执行解密配方（共 %d 套，%d 套可直接解密）==="
          % (len(plans), sum(1 for p in plans if p["executable"])), file=out)
    for i, p in enumerate(plans, 1):
        print("\n[%d] %s   置信度 %.2f%s"
              % (i, p["label"], p["confidence"],
                 "" if p["executable"] else "  ⚠ 缺密钥，无法自动解密"), file=out)
        print("    依据：%s" % p["confidence_reason"], file=out)
        if p["key_hex"]:
            print("    密钥（HEX，%d 字节）：%s" % (p["key_bytes"], p["key_hex"]), file=out)
            print("      来源：%s" % (p["key_origin"] or "文件内硬编码"), file=out)
        if p["iv_hex"]:
            print("    IV（HEX）：%s    来源：%s"
                  % (p["iv_hex"], p["iv_origin"] or "文件内硬编码"), file=out)
        print("    涉及文件：%s" % "、".join(p["files"][:6]), file=out)
        print("    加密逻辑：", file=out)
        for s in p["encryption_logic"]:
            print("      %s" % s, file=out)
        print("    解密逻辑（逆序）：", file=out)
        for s in p["decryption_logic"]:
            print("      %s" % s, file=out)
        if not p["has_integrity"]:
            print("    ⚠ 该组合无完整性校验：密钥不对不会报错、只会出乱码，务必看内容是否符合业务预期",
                  file=out)
        if show_cli:
            print("    手动复现：%s" % p["cli"], file=out)
    print("\n提示：直接跑 `--decrypt-text \"<你复制的密文>\"`（可配 --plan 指定某套方案）即可解密。",
          file=out)


def _cmd_decrypt(args) -> int:
    """解密模式：读配方 → 解密用户粘贴的密文。"""
    plans, err = _load_plans(args.plans)
    if err:
        print("[错误] %s" % err, file=sys.stderr)
        return 2

    try:
        ciphertext, where = _read_cipher_input(args.decrypt_text, args.decrypt_file)
    except (ValueError, OSError) as exc:
        print("[错误] 读取密文失败：%s" % exc, file=sys.stderr)
        return 2

    print("[信息] 待解密内容来自 %s，共 %d 字符；配方 %d 套（可执行 %d 套）"
          % (where, len(ciphertext.strip()), len(plans),
             sum(1 for p in plans if p.get("executable"))), file=sys.stderr)

    res = decrypt_ciphertext(ciphertext, plans, plan_id=args.plan,
                             on_step=lambda pct, text: aica._step(pct, text),
                             prefer_hex=("二进制" in where))

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    if res.get("ok"):
        print("=== 解密成功 ===")
        print("方案：%s    输入编码：%s    明文判定：%s（%.2f）"
              % (res["plan"], res["input_chain"], res["reason"], res["score"]))
        print("--- 明文（%d 字节）---" % res["bytes"])
        print(res["plaintext"])
        if res.get("alternatives"):
            print("\n--- 其它也解出明文的尝试 ---", file=sys.stderr)
            for a in res["alternatives"]:
                print("  %s / %s：%s" % (a["plan"], a["input_chain"], a["plaintext"][:80]),
                      file=sys.stderr)
        return 0

    print("=== 未能解出明文 ===", file=sys.stderr)
    print(res.get("message", ""), file=sys.stderr)
    if res.get("attempts"):
        print("\n--- 尝试记录（最多 20 条）---", file=sys.stderr)
        for a in res["attempts"][:20]:
            print("  [%s] %s · %s → %s"
                  % ("OK" if a.get("ok") else "--", a.get("plan"), a.get("input_chain"),
                     a.get("reason")), file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.progress:
        os.environ["JIEJIEEAD_PROGRESS"] = "1"
        aica.enable_progress()

    if args.selftest:
        return _selftest()

    # ---- 解密模式：只读配方 + 密文，不遍历目录（秒回）----
    if args.decrypt_text is not None or args.decrypt_file:
        return _cmd_decrypt(args)

    if not args.dir:
        print("[错误] 请用 --dir 指定要整体分析的目录（或用 --decrypt-text 解密密文）")
        return 2
    if not os.path.isdir(args.dir):
        print("[错误] 目录不存在：%s" % args.dir)
        return 2

    cfg = None if args.no_llm else aica.load_config()
    use_llm = bool(cfg is not None and cfg.is_usable())

    def on_step(pct, text):
        aica._step(pct, text)

    if args.show_evidence:
        # 只构建证据包，不调用 LLM（排查用）
        folder = walk_folder(args.dir, max_files=args.max_files,
                             max_file_mb=args.max_file_mb)
        nodes = [analyze_one_file(args.dir, e, deep=args.deep) for e in folder["files"]]
        graph = build_graph(nodes)
        chains = build_chains(nodes, graph)
        plans = build_decrypt_plans(nodes, graph, chains)
        # ★ 注意用关键字传参：第 5 个位置参数已经从 budget_chars 变成 plans，
        #   位置传参会把 evidence_chars 当成 plans（签名变更是最容易埋雷的地方）
        ev = build_folder_evidence(folder, nodes, graph, chains,
                                   plans=plans, budget_chars=args.evidence_chars)
        print(ev, file=sys.stderr)
        return 0

    try:
        result = analyze_folder(
            args.dir, cfg, deep=args.deep, max_files=args.max_files,
            max_file_mb=args.max_file_mb, evidence_chars=args.evidence_chars,
            use_llm=use_llm, on_step=on_step, plans_out=args.plans_out,
        )
    except Exception as exc:  # noqa: BLE001
        print("[错误] 整体分析失败：%s" % exc, file=sys.stderr)
        return 1

    if args.show_plans:
        _print_plans(result.get("decrypt_plans") or [], out=sys.stdout, show_cli=True)
        print("\n配方已写入：%s" % result.get("plans_path", ""))
        return 0

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        _print_human(result)
    return 0


# ============================================================================
# 9) 自检
# ============================================================================
def _build_selftest_tree(workdir: str) -> str:
    """构造一个「密钥定义 / 加解密 / 传输」三层分离的多文件项目。"""
    root = os.path.join(workdir, "proj")
    os.makedirs(os.path.join(root, "src", "crypto"), exist_ok=True)
    os.makedirs(os.path.join(root, "src", "api"), exist_ok=True)
    os.makedirs(os.path.join(root, "node_modules", "left-pad"), exist_ok=True)
    os.makedirs(os.path.join(root, "dist"), exist_ok=True)

    KEY, IV = _SELFTEST_KEY, _SELFTEST_IV

    # 1) 密钥定义层
    with open(os.path.join(root, "src", "config.js"), "w", encoding="utf-8") as fh:
        fh.write(
            "// 密钥与 IV 集中定义\n"
            "var AES_KEY = '%s';\n"
            "var AES_IV = '%s';\n"
            "export function getCryptoKey() { return AES_KEY; }\n"
            "export { AES_KEY, AES_IV };\n" % (KEY, IV)
        )
    # 2) 加解密层（import 配置、用密钥做 CBC/PKCS7）
    with open(os.path.join(root, "src", "crypto", "aes.js"), "w", encoding="utf-8") as fh:
        fh.write(
            "import { AES_KEY, AES_IV } from '../config.js';\n"
            "import CryptoJS from 'crypto-js';\n"
            "export function encryptData(data) {\n"
            "  var key = CryptoJS.enc.Hex.parse(AES_KEY);\n"
            "  var iv = CryptoJS.enc.Hex.parse(AES_IV);\n"
            "  return CryptoJS.AES.encrypt(data, key, { iv: iv, mode: CryptoJS.mode.CBC,"
            " padding: CryptoJS.pad.Pkcs7 }).toString();\n"
            "}\n"
            "export function decryptData(cipher) {\n"
            "  var key = CryptoJS.enc.Hex.parse(AES_KEY);\n"
            "  return CryptoJS.AES.decrypt(cipher, key, { iv: CryptoJS.enc.Hex.parse(AES_IV),"
            " mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);\n"
            "}\n"
        )
    # 3) 传输层（复用同一密钥，Base64 后外发）
    with open(os.path.join(root, "src", "api", "client.js"), "w", encoding="utf-8") as fh:
        fh.write(
            "import { encryptData } from '../crypto/aes.js';\n"
            "import axios from 'axios';\n"
            "var AES_KEY = '%s';\n"
            "export function submit(payload) {\n"
            "  var body = encryptData(JSON.stringify(payload));\n"
            "  var b64 = btoa(body);\n"
            "  return axios.post('https://api.example.com/v1/submit', { data: b64 });\n"
            "}\n" % KEY
        )
    # 4) 噪声：node_modules 与 dist 必须被排除
    with open(os.path.join(root, "node_modules", "left-pad", "index.js"), "w", encoding="utf-8") as fh:
        fh.write("module.exports = function pad(s,n){return String(s).padStart(n,'0');};\n")
    with open(os.path.join(root, "dist", "bundle.js"), "w", encoding="utf-8") as fh:
        fh.write("var AES_KEY='DEADBEEFDEADBEEFDEADBEEFDEADBEEF';\n")
    # 5) 图片噪声
    with open(os.path.join(root, "logo.png"), "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200)
    return root


def _selftest() -> int:
    import shutil
    import tempfile

    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, bool(ok), detail))

    KEY, IV = _SELFTEST_KEY, _SELFTEST_IV
    tmp = tempfile.mkdtemp(prefix="csfoldertest_")
    old_kb = os.environ.get("JIEJIEEAD_KB_PATH")
    old_plans = os.environ.get("JIEJIEEAD_PLANS_PATH")
    try:
        # 自检期间彻底隔离知识库（与 ai_crypto_analyzer 自检同样的纪律）
        os.environ["JIEJIEEAD_KB_PATH"] = os.path.join(tmp, "kb-dummy.json")
        # 配方文件同样隔离：否则自检会把真实用户的配方缓存覆盖掉
        os.environ["JIEJIEEAD_PLANS_PATH"] = os.path.join(tmp, "plans-selftest.json")
        root = _build_selftest_tree(tmp)

        print("=" * 64)
        print(" jiejieEAD 文件夹整体分析 · 自检")
        print("=" * 64)
        print("[1] 遍历与筛选")
        folder = walk_folder(root)
        check("递归找到全部候选文件（3 个源码 + 1 张图片）",
              folder["scanned_files"] == 3 and folder["total_files"] >= 4,
              "scanned=%d total=%d" % (folder["scanned_files"], folder["total_files"]))
        rels = [f["rel"] for f in folder["files"]]
        check("node_modules 被排除", not any("node_modules" in r for r in rels),
              "rels=%s" % rels)
        check("dist 被排除", not any(r.startswith("dist/") for r in rels))
        check("图片等噪声被跳过",
              any("logo.png" in s["path"] for s in folder["skipped"]),
              "skipped=%d" % folder["skipped_count"])
        check("关键源码文件全部纳入",
              all(any(r.endswith(x) for r in rels)
                  for x in ("src/config.js", "src/crypto/aes.js", "src/api/client.js")))

        print("[2] 逐文件摘要")
        nodes = [analyze_one_file(root, e, keep_text=True) for e in folder["files"]]
        attach_symbol_refs(nodes)
        by_id = {n["id"]: n for n in nodes}
        cfg_node = by_id.get("src/config.js")
        check("config.js 提取到密钥材料", cfg_node is not None and len(cfg_node["secrets"]) >= 2,
              "secrets=%d" % (len(cfg_node["secrets"]) if cfg_node else -1))
        check("config.js 提取到密码学符号（AES_KEY/AES_IV）",
              cfg_node is not None and any(s in cfg_node["symbols"] for s in ("AES_KEY", "AES_IV")),
              "symbols=%s" % (cfg_node["symbols"] if cfg_node else []))
        check("config.js 识别出角色（取密钥）",
              cfg_node is not None and any(r["role"] == "key_source" for r in cfg_node["roles"]))
        aes_node = by_id.get("src/crypto/aes.js")
        check("aes.js 识别出算法特征（AES/CBC/PKCS7）",
              aes_node is not None and any("AES" in a for a in aes_node["algos"]),
              "algos=%s" % (aes_node["algos"] if aes_node else []))
        check("aes.js 提取到 import（含 ../config.js 与 crypto-js）",
              aes_node is not None and any("config" in i for i in aes_node["imports"])
              and any("crypto-js" in i for i in aes_node["imports"]),
              "imports=%s" % (aes_node["imports"] if aes_node else []))
        check("aes.js 识别出密码库 CryptoJS",
              aes_node is not None and any("CryptoJS" in l or "crypto-js" in l.lower()
                                           for l in aes_node["libs"]),
              "libs=%s" % (aes_node["libs"] if aes_node else []))
        check("aes.js 检出「引用」了别处唯一定义的符号 AES_IV",
              aes_node is not None and "AES_IV" in (aes_node.get("symbol_refs") or []),
              "refs=%s" % (aes_node.get("symbol_refs") if aes_node else []))
        check("AES_KEY 因在 config 与 client 各定义一次而不参与符号边（避免方向随机）",
              "AES_KEY" not in (aes_node.get("symbol_refs") or []))
        cli_node = by_id.get("src/api/client.js")
        check("client.js 识别出传输角色（axios.post）",
              cli_node is not None and any(r["role"] == "transport" for r in cli_node["roles"]),
              "roles=%s" % ([r["role"] for r in cli_node["roles"]] if cli_node else []))
        check("client.js 识别出编码角色（btoa）",
              cli_node is not None and any(r["role"] == "encode" for r in cli_node["roles"]))
        check("相关度排序：密码学文件排在前面",
              nodes and nodes[0]["score"] > 0
              and sorted(nodes, key=lambda x: -x["score"])[0]["hits"])
        # 模拟 analyze_folder 的收尾：符号检测完必须清掉源码
        for _n in nodes:
            _n.pop("_text", None)
        check("文本用完后被清理（不把源码留在节点里）",
              all("_text" not in n for n in nodes))

        print("[3] 跨文件关系图")
        graph = build_graph(nodes)
        etypes = [e["type"] for e in graph["edges"]]
        pairs = {(e["from"], e["to"], e["type"]) for e in graph["edges"]}
        check("检出 import 边 aes.js → config.js",
              ("src/crypto/aes.js", "src/config.js", "import") in pairs,
              "edges=%s" % sorted(pairs))
        check("检出 import 边 client.js → aes.js",
              ("src/api/client.js", "src/crypto/aes.js", "import") in pairs)
        check("检出共享密钥边（config.js 与 client.js 同 KEY）",
              any(e["type"] == "shared_key"
                  for e in graph["edges"]
                  if {e["from"], e["to"]} == {"src/config.js", "src/api/client.js"}),
              "shared_keys=%s" % [k["files"] for k in graph["shared_keys"]])
        check("检出「定义方 → 使用方」符号边（config.js → aes.js）",
              ("src/config.js", "src/crypto/aes.js", "symbol") in pairs,
              "symbol_edges=%s" % sorted(p for p in pairs if p[2] == "symbol"))
        check("符号边方向正确：定义文件在 from，引用文件在 to",
              all(e["from"] != e["to"] for e in graph["edges"] if e["type"] == "symbol"))
        check("只有定义方能作为符号边起点（引用方不冒充定义方）",
              ("src/crypto/aes.js", "src/config.js", "symbol") not in pairs
              and ("src/api/client.js", "src/config.js", "symbol") not in pairs,
              "symbol_edges=%s" % sorted(p for p in pairs if p[2] == "symbol"))
        check("同名多文件重复定义时不产生方向随机的假符号边"
              "（AES_KEY 在 config 与 client 各定义一次）",
              ("src/config.js", "src/api/client.js", "symbol") not in pairs
              and ("src/api/client.js", "src/config.js", "symbol") not in pairs)
        check("仍能检出唯一「函数级」符号边 aes.js → client.js（encryptData）",
              ("src/crypto/aes.js", "src/api/client.js", "symbol") in pairs)
        check("import 路径里的文件名不被误判为符号引用（'../config.js' 里的 config）",
              not any(e["type"] == "symbol" and e["label"] == "引用符号 config"
                      for e in graph["edges"]))
        check("node_modules / dist 的文件不出现在图里",
              not any("node_modules" in n["id"] or n["id"].startswith("dist/")
                      for n in graph["nodes"]))
        check("外部依赖被单独归类（crypto-js / axios）",
              any(i["spec"] in ("crypto-js", "axios") for i in graph["external_imports"]),
              "ext=%s" % graph["external_imports"])

        print("[4] 跨文件数据流链路")
        chains = build_chains(nodes, graph)
        check("dominant_path 覆盖取钥→初始化→传输",
              all(k in chains["dominant_path"] for k in ("取密钥", "初始化", "传输")),
              "path=%s" % chains["dominant_path"])
        check("阶段视图含 key_source / cipher_init / transport",
              {"key_source", "cipher_init", "transport"} <= {s["role"] for s in chains["stages"]},
              "stages=%s" % [s["role"] for s in chains["stages"]])
        check("密钥追溯链跨 ≥2 个文件",
              any(c["kind"] == "key" and len(c["files"]) >= 2 for c in chains["chains"]),
              "chains=%d" % len(chains["chains"]))
        check("符号链给出「定义方 / 使用方」",
              any(c["kind"] == "symbol" and len(c["steps"]) == 2 for c in chains["chains"]))

        print("[5] 整体证据包")
        ev = build_folder_evidence(folder, nodes, graph, chains)
        check("证据包含分析范围", "【分析范围】" in ev)
        check("证据包含跨文件关系图", "【跨文件关系图】" in ev)
        check("证据包含数据流链路", "【跨文件数据流链路】" in ev)
        check("证据包含重点文件明细", "【重点文件明细" in ev)
        check("证据包含跨文件边（而非只堆文件）",
              "→" in ev and any("import" in line or "共享密钥" in line
                                for line in ev.splitlines()))
        check("证据不含 node_modules 噪声",
              "node_modules" not in ev.replace("（已排除）", ""))
        check("证据包受字符预算约束（未超预算 20%）",
              len(ev) <= DEFAULT_FOLDER_EVIDENCE_CHARS * 1.2,
              "len=%d" % len(ev))

        print("[6] 离线兜底整体总结")
        summ = folder_summary_offline(folder, nodes, graph, chains)
        check("离线总结给出整体体系描述", bool(summ["system_overview"]))
        check("离线总结给出数据流", len(summ["data_flow"]) >= 2,
              "flow=%d" % len(summ["data_flow"]))
        check("离线总结点出跨文件共享密钥风险",
              any("跨" in r and "共享" in r for r in summ["risks"]),
              "risks=%s" % summ["risks"])
        check("离线总结指出前端加密不可信",
              any("前端" in r or "客户端" in r for r in summ["risks"]))
        check("离线总结标注 source=offline-folder", summ["source"] == "offline-folder")

        print("[7] 端到端（不联网）")
        res = analyze_folder(root, cfg=None, use_llm=False)
        check("端到端 status=ok", res["status"] == "ok")
        check("端到端 source=offline-folder", res["source"] == "offline-folder")
        check("端到端统计到 ≥3 个密码学文件", res["stats"]["crypto_files"] >= 3,
              "crypto_files=%d" % res["stats"]["crypto_files"])
        check("端到端关系图有边", res["stats"]["edges"] >= 3,
              "edges=%d" % res["stats"]["edges"])
        check("端到端含整体总结", bool(res["summary"] and res["summary"]["system_overview"]))
        check("端到端含证据包预览", bool(res["evidence_preview"]))
        check("端到端无异常告警", not res["warnings"], "warnings=%s" % res["warnings"])

        print("[8] 稳健性：异常输入")
        empty = os.path.join(tmp, "empty")
        os.makedirs(empty, exist_ok=True)
        r_empty = analyze_folder(empty, cfg=None, use_llm=False)
        check("空目录 → status=empty 且不崩溃", r_empty["status"] == "empty")
        try:
            analyze_folder(os.path.join(tmp, "no-such-dir"), cfg=None, use_llm=False)
            check("不存在的目录 → 抛错", False)
        except Exception as exc:  # noqa: BLE001
            check("不存在的目录 → 抛错并提示", "不是有效目录" in str(exc), str(exc)[:60])

        # 单文件：所有密码学证据集中在一个文件（无跨文件关系）也不该崩
        single = os.path.join(tmp, "single")
        os.makedirs(single, exist_ok=True)
        with open(os.path.join(single, "only.js"), "w", encoding="utf-8") as fh:
            fh.write("var SM4_KEY='0123456789abcdeffedcba9876543210';\n"
                     "function e(d){return sm4.encrypt(d,SM4_KEY,{mode:'ecb',padding:'Pkcs7'});}\n")
        r_single = analyze_folder(single, cfg=None, use_llm=False)
        check("单文件目录：无跨文件边也能出结论",
              r_single["status"] == "ok" and r_single["summary"]["system_overview"])
        check("单文件目录：离线总结如实说明无跨文件串联",
              any("未检出" in c for c in r_single["summary"]["cross_file_logic"]),
              "logic=%s" % r_single["summary"]["cross_file_logic"])

        # ------------------------------------------------------------------
        print("[9] 解密配方（加密逻辑 → 解密逻辑，跨文件合并）")
        plans = build_decrypt_plans(nodes, graph, chains)
        check("至少产出一套解密配方", len(plans) >= 1, "plans=%d" % len(plans))
        exe = [p for p in plans if p["executable"]]
        check("存在「可直接执行」的配方（密钥已拼齐）", bool(exe),
              "executable=%d / %d" % (len(exe), len(plans)))
        if exe:
            p0 = exe[0]
            joined = [p for p in exe
                      if any("aes.js" in f for f in p["files"])
                      and any("config.js" in f for f in p["files"])]
            check("跨文件合并：算法来自 aes.js、密钥/IV 来自 config.js",
                  bool(joined), "files=%s" % [p["files"] for p in exe])
            if joined:
                p0 = joined[0]
            check("缺 IV 的方案被标为不可执行（不能给用户一个必然失败的按钮）",
                  not any(p["executable"] and p.get("missing_iv") for p in plans)
                  and not any(p["executable"] for p in plans if p["mode"] == "cbc"
                              and not p["iv_hex"]),
                  "plans=%s" % [(p["alg"], p["mode"], bool(p["iv_hex"]), p["executable"]) for p in plans])
            check("按真实密钥长度纠正算法位宽（16 字节 → AES-128，而非默认 AES-256）",
                  p0["alg"] == "aes128" and p0["key_bytes"] == 16,
                  "alg=%s key_bytes=%d" % (p0["alg"], p0["key_bytes"]))
            check("密钥按源码语义解析为 HEX（enc.Hex.parse）",
                  p0["key_hex"] == KEY.lower(), "key=%s" % p0["key_hex"])
            check("IV 也跨文件取到", p0["iv_hex"] == IV.lower(), "iv=%s" % p0["iv_hex"])
            check("模式/填充/编码与源码一致（cbc/pkcs7/base64）",
                  (p0["mode"], p0["padding"], p0["encoding"]) == ("cbc", "pkcs7", "base64"),
                  "%s/%s/%s" % (p0["mode"], p0["padding"], p0["encoding"]))
            check("加密逻辑与解密逻辑都是有序步骤链",
                  len(p0["encryption_logic"]) >= 3 and len(p0["decryption_logic"]) >= 3,
                  "enc=%d dec=%d" % (len(p0["encryption_logic"]), len(p0["decryption_logic"])))
            check("解密逻辑是加密逻辑的逆序（先解码、再解密、最后 UTF-8）",
                  "解码" in p0["decryption_logic"][0]
                  and any("解密" in s for s in p0["decryption_logic"])
                  and any("UTF-8" in s for s in p0["decryption_logic"]),
                  "%s" % p0["decryption_logic"])
            check("提示了双重编码的可能（client.js 里就是 btoa 包裹 Base64）",
                  any("二次编码" in s for s in p0["decryption_logic"]))
            check("给出可直接复制的复现命令（含真实 key/iv）",
                  "--op dec" in p0["cli"] and p0["key_hex"] in p0["cli"] and p0["iv_hex"] in p0["cli"])
            check("离线也能给出解密逻辑文本（不依赖 LLM）",
                  any("解密" in s for s in offline_decrypt_logic_text(plans)))

        print("[10] 配方落盘 / 回读")
        wrote = _save_plans(plans)
        check("配方写入磁盘成功", bool(wrote) and os.path.isfile(wrote), "path=%s" % wrote)
        back, err = _load_plans()
        check("配方可回读且内容一致",
              not err and len(back) == len(plans)
              and [p["label"] for p in back] == [p["label"] for p in plans],
              "err=%s back=%d" % (err, len(back)))
        _, err_missing = _load_plans(os.path.join(tmp, "no-such-plans.json"))
        check("配方缺失时给出可操作的提示（而不是崩掉）",
              "请先对目标目录跑一次整体分析" in err_missing, err_missing[:60])

        # ------------------------------------------------------------------
        if cc.missing_dependencies():
            print("   [跳过] 未安装 gmssl/pycryptodome，跳过真实解密用例")
        else:
            print("[11] 粘贴密文 → 解密（真实跑密码引擎）")
            plain = '{"orderId":"TEST-ORDER-0001","phone":"TEST-PHONE-0001","amount":"128.00"}'
            raw = cc.do_crypt("aes128", "enc", KEY, IV, plain.encode("utf-8"),
                              mode="cbc", padding="pkcs7", warn_weak=False)
            b64 = base64.b64encode(raw).decode()
            double_b64 = base64.b64encode(b64.encode()).decode()

            r1 = decrypt_ciphertext(b64, plans)
            check("单层 Base64 密文 → 解出明文", r1["ok"] and r1["plaintext"] == plain,
                  "ok=%s chain=%s" % (r1.get("ok"), r1.get("input_chain")))
            check("明文判定命中业务字段（不是靠碰巧可打印）",
                  r1["ok"] and "命中业务字段名" in r1["reason"], r1.get("reason", ""))

            r2 = decrypt_ciphertext(double_b64, plans)
            check("双层 Base64（btoa 包裹）→ 自动剥一层后解出明文",
                  r2["ok"] and r2["plaintext"] == plain and r2["input_chain"] == "base64→base64",
                  "ok=%s chain=%s" % (r2.get("ok"), r2.get("input_chain")))

            wrong = cc.do_crypt("aes128", "enc", "ff" * 16, IV, plain.encode("utf-8"),
                                mode="cbc", padding="pkcs7", warn_weak=False)
            r3 = decrypt_ciphertext(base64.b64encode(wrong).decode(), plans)
            check("换一把密钥的密文 → 判定为失败（不把乱码当成功）", not r3["ok"])
            check("失败时保留每次尝试的原因，便于对症排查",
                  len(r3["attempts"]) >= 1 and any(a.get("reason") for a in r3["attempts"]),
                  "attempts=%d" % len(r3["attempts"]))
            check("失败时给出人话排查建议（而非只报异常）",
                  "密钥" in r3["message"] and "建议" in r3["message"])

            r4 = decrypt_ciphertext("", plans)
            check("空密文 → 明确提示而不是崩", not r4["ok"] and "没有收到" in r4["message"])
            r5 = decrypt_ciphertext(b64, [p for p in plans if not p["executable"]] or
                                    [dict(plans[0], executable=False, key_hex="")])
            check("没有可执行配方时提示「缺密钥」而不是静默失败",
                  not r5["ok"] and ("缺" in r5["message"] or "没有可执行" in r5["message"]),
                  r5.get("message", "")[:60])

            r6 = decrypt_ciphertext(b64, plans, plan_id="不存在的方案")
            check("指定不存在的方案 → 明确报错", not r6["ok"] and "找不到" in r6["message"])

            r7 = decrypt_ciphertext("这不是任何已知编码！！", plans)
            check("非编码输入 → 失败但列出尝试记录（不崩）", not r7["ok"])

            # 命令行传参有长度上限，超了会被系统静默截断 → 必须显式挡住
            try:
                _read_cipher_input("A" * (_MAX_TEXT_ARG + 10), None)
                check("超长密文（走命令行传参）被显式拦住并引导用 --decrypt-file", False)
            except ValueError as exc:
                check("超长密文（走命令行传参）被显式拦住并引导用 --decrypt-file",
                      "--decrypt-file" in str(exc), str(exc)[:60])
            # 同样的密文走「文件」通道应当被允许（上限 4MB）
            big = os.path.join(tmp, "big-cipher.txt")
            with open(big, "w", encoding="utf-8") as fh:
                fh.write("A" * (_MAX_TEXT_ARG + 10))
            try:
                _txt, where = _read_cipher_input(None, big)
                check("长密文改用文件通道可正常读取", where.startswith("文件"), where)
            except ValueError as exc:  # noqa: BLE001
                check("长密文改用文件通道可正常读取", False, str(exc)[:60])

            # 文本密文文件（--decrypt-file）要能直接解密
            f_b64 = os.path.join(tmp, "cipher-b64.txt")
            with open(f_b64, "w", encoding="utf-8") as fh:
                fh.write(b64)
            t_file, w_file = _read_cipher_input(None, f_b64)
            r_file = decrypt_ciphertext(t_file, plans, prefer_hex=("二进制" in w_file))
            check("文本密文文件（--decrypt-file）可解密出明文",
                  r_file["ok"] and r_file["plaintext"] == plain,
                  "ok=%s chain=%s" % (r_file.get("ok"), r_file.get("input_chain")))

            # 二进制密文文件：绝不能被 utf-8 errors="replace" 破坏（那会把密文废掉）
            blob = b"\xff\xfe\x80\x81PK\x03\x04\x00"
            bin_file = os.path.join(tmp, "raw.bin")
            with open(bin_file, "wb") as fh:
                fh.write(blob)
            t_bin, w_bin = _read_cipher_input(None, bin_file)
            check("二进制密文文件按原始字节处理（HEX 无损还原，不被 U+FFFD 污染）",
                  "二进制" in w_bin and bytes.fromhex(t_bin) == blob, w_bin)

            f_raw = os.path.join(tmp, "cipher-raw.bin")
            with open(f_raw, "wb") as fh:
                fh.write(raw)
            t_raw, w_raw = _read_cipher_input(None, f_raw)
            r_raw = decrypt_ciphertext(t_raw, plans, prefer_hex=("二进制" in w_raw))
            check("二进制密文文件可解密出明文（原生字节直达密码引擎）",
                  r_raw["ok"] and r_raw["plaintext"] == plain,
                  "ok=%s chain=%s where=%s" % (r_raw.get("ok"), r_raw.get("input_chain"), w_raw))

            # 端到端：analyze_folder 产出的配方，必须能直接解密（回归：配方—解密器接口）
            r8 = decrypt_ciphertext(b64, res["decrypt_plans"])
            check("端到端产物可解密（analyze_folder → decrypt_ciphertext 接口一致）",
                  r8["ok"] and r8["plaintext"] == plain)
            check("端到端返回值带配方与落盘路径",
                  bool(res.get("decrypt_plans")) and bool(res.get("plans_path")))
            check("端到端 summary 带解密逻辑",
                  bool(res["summary"].get("decrypt_logic")),
                  "%s" % (res["summary"].get("decrypt_logic") or [])[:1])
    finally:
        if old_kb is None:
            os.environ.pop("JIEJIEEAD_KB_PATH", None)
        else:
            os.environ["JIEJIEEAD_KB_PATH"] = old_kb
        if old_plans is None:
            os.environ.pop("JIEJIEEAD_PLANS_PATH", None)
        else:
            os.environ["JIEJIEEAD_PLANS_PATH"] = old_plans
        shutil.rmtree(tmp, ignore_errors=True)

    print("=" * 64)
    failed = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        if ok:
            print("   [ OK ] %s%s" % (name, ("  —— " + detail) if detail else ""))
        else:
            print("   [FAIL] %s%s" % (name, ("  —— " + detail) if detail else ""))
    print("-" * 64)
    if failed:
        print(" [FAIL] %d 项未通过。" % len(failed))
        return 2
    print(" [PASS] 文件夹整体分析自检全部通过（遍历/关系图/链路/证据包/总结均正常）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
