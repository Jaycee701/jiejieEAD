#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 智能密码分析模块（在线为主 + 离线兜底）。

职责：
  给定一个代码 / 抓包 / 配置片段，判断它用了哪套对称密码方案
  （算法 / 工作模式 / 填充 / 密钥 / IV / 编码），输出结构化结果，
  供 GUI「AI 分析」页签一键回填到加解密工作台或 MITM。

两种分析来源：
  1) 在线 LLM（OpenAI 兼容接口）：base_url + api_key + model，
     兼容 OpenAI / Claude(经 OpenRouter 等) / 本地 Ollama。
  2) 离线启发式：复用 file_crypto_scanner 的静态规则，零网络、零额外依赖。

融合策略：配置了在线端点就先走 LLM；LLM 调用失败（网络/鉴权/解析）时
自动降级到离线规则，并在结果里标记 source=offline-fallback，绝不静默失败。

设计约束：
  - 仅依赖 Python 标准库（urllib）调用 LLM，避免给嵌入式运行环境增加依赖。
  - 离线分析复用现有扫描器，保证「AI 离线」与「文件扫描」结论一致。
  - 输出 JSON 字段与工作台/MITM 配置字段对齐，GUI 可直接回填。

用法：
  python ai_crypto_analyzer.py --config-save base_url=... api_key=... model=... enabled=true
  python ai_crypto_analyzer.py --config-show
  python ai_crypto_analyzer.py --test-llm [--json]      # 连通性测试（诊断超时/鉴权/限流）
  python ai_crypto_analyzer.py --analyze --text "..." [--json]
  python ai_crypto_analyzer.py --analyze --file xxx.js [--json]
  python ai_crypto_analyzer.py --selftest
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
# 被 Tauri 以绝对路径调用时，脚本目录未必在 sys.path 首位（嵌入式 Python 的 _pth
# 不会自动把脚本目录加入 sys.path），必须显式插入，否则 `import file_crypto_scanner`
# 等兄弟模块会报 ModuleNotFoundError。cli_crypto.py / crypto_mcp_server.py 也这样做。
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# 密码逻辑知识库（自动学习 / 命中复用）。不可用时降级为「不查库、不学习」，
# 绝不允许知识库拖垮主分析流程。
try:
    import crypto_knowledge as kb_mod
except Exception:  # noqa: BLE001
    kb_mod = None

# ---- 进度 / 过程上报（供 GUI 进度条与「分析过程」日志）----
# 只写 stderr —— 不能污染 stdout 上的 JSON。
_PROGRESS_ON = os.environ.get("JIEJIEEAD_PROGRESS", "") == "1"


def enable_progress() -> None:
    global _PROGRESS_ON
    _PROGRESS_ON = True


def _step(pct: int, text: str) -> None:
    if _PROGRESS_ON:
        print("[PROGRESS] %d %s" % (pct, text), file=sys.stderr, flush=True)


# 与 crypto_core 保持一致的可选取值（LLM 输出需收敛到这些枚举，否则判为不可信）
KNOWN_ALG = {"sm4", "aes128", "aes192", "aes256", "des", "des3", "rc4",
             "rc5", "rc5_16", "rc5_64", "rc6", "rc6_16",
             "blowfish", "cast5", "rc2", "chacha20", "salsa20"}
KNOWN_MODE = {"ecb", "cbc", "cfb", "ofb", "ctr", "gcm", "stream"}
KNOWN_PADDING = {"pkcs7", "zero", "none", "iso7816", "ansix923"}
KNOWN_ENCODING = {"base64", "hex", "raw"}


# ============================================================================
# 配置
# ============================================================================
@dataclass
class AIConfig:
    base_url: str = ""
    api_key: str = ""
    model: str = "gpt-4o-mini"
    # 读超时（模型出字总时长上限）。推理模型（如 deepseek-v4-flash）会先生成
    # 大量 reasoning token，30s 经常不够 —— 这是「read operation timed out」的根因，
    # 因此默认放大到 120s。
    timeout: int = 120
    # 建连超时（DNS + TCP + TLS）。短一点，网络不通时可快速失败并给出明确提示。
    connect_timeout: int = 15
    # 瞬时失败（超时/连接中断/429/5xx）自动重试次数（不含首次），指数退避。
    max_retries: int = 2
    enabled: bool = False

    def is_usable(self) -> bool:
        return self.enabled and bool(self.base_url) and bool(self.api_key)


def config_path() -> str:
    # 默认与脚本同目录；可用环境变量覆盖（便于打包后放到可写目录）
    return os.environ.get(
        "JIEJIEEAD_AI_CONFIG",
        os.path.join(HERE, "ai_config.json"),
    )


def load_config(path: str | None = None) -> AIConfig:
    path = path or config_path()
    if not os.path.isfile(path):
        return AIConfig()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        return AIConfig(
            base_url=str(raw.get("base_url", "")),
            api_key=str(raw.get("api_key", "")),
            model=str(raw.get("model", "gpt-4o-mini")),
            timeout=int(raw.get("timeout", 120) or 120),
            connect_timeout=int(raw.get("connect_timeout", 15) or 15),
            max_retries=int(raw.get("max_retries", 2) or 0),
            enabled=bool(raw.get("enabled", False)),
        )
    except Exception:
        return AIConfig()


def save_config(cfg: AIConfig, path: str | None = None) -> str:
    path = path or config_path()
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(asdict(cfg), fh, ensure_ascii=False, indent=2)
    return path


# ============================================================================
# 工具：把 LLM / 离线结论收敛到可信枚举
# ============================================================================
def _coerce(value, allowed, default=None):
    if not isinstance(value, str):
        return default
    v = value.strip().lower()
    return v if v in allowed else default


def _normalize_result(r: dict[str, Any]) -> dict[str, Any]:
    """保证输出字段齐全、枚举合法。"""
    r["alg"] = _coerce(r.get("alg"), KNOWN_ALG, None)
    r["mode"] = _coerce(r.get("mode"), KNOWN_MODE, None)
    r["padding"] = _coerce(r.get("padding"), KNOWN_PADDING, None)
    r["encoding"] = _coerce(r.get("encoding"), KNOWN_ENCODING, "base64")
    r.setdefault("key", None)
    r.setdefault("iv", None)
    r.setdefault("hints", [])
    r.setdefault("warnings", [])
    r.setdefault("confidence", 0.0)
    if r["key"] in ("", "null", "None"):
        r["key"] = None
    if r["iv"] in ("", "null", "None"):
        r["iv"] = None
    return r


# ============================================================================
# 离线启发式（复用文件扫描器）
# ============================================================================
def offline_analyze(text: str) -> dict[str, Any]:
    import file_crypto_scanner as fcs  # 延迟导入，避免无依赖时硬失败

    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".txt", prefix="ai_offline_")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        res = fcs.scan_file(tmp)
    finally:
        if tmp and os.path.isfile(tmp):
            os.remove(tmp)

    logic = res.get("logic", {}) or {}
    ac = logic.get("apply_crypto") or {}
    alg = ac.get("alg")
    rule = logic.get("rule", "")
    warnings = list(logic.get("warnings", []) or [])

    # 离线规则的置信度：识别出主算法给 0.6，否则 0.0
    confidence = 0.6 if alg else 0.0
    if alg and ac.get("mode") and ac.get("mode") not in ("cbc",):
        confidence = 0.62  # 识别到非默认模式，价值更高

    hints = []
    for a in res.get("algorithms", []) or []:
        hints.append("%s（%s，%s）" % (a.get("algorithm", "?"), a.get("level", ""), a.get("evidence", "")[:80]))

    return _normalize_result({
        "status": "ok",
        "source": "offline",
        "alg": alg,
        "mode": ac.get("mode"),
        "padding": ac.get("padding"),
        "key": ac.get("key") or None,
        "iv": ac.get("iv") or None,
        "encoding": ac.get("encoding") or "base64",
        "confidence": confidence,
        "hints": hints,
        "warnings": warnings,
        "note": rule,
    })


# ============================================================================
# 文件级分析：把「一个文件」压缩成「高信号证据包」，再交给 LLM
#   —— 直接把整份文件（可达 32MB、二进制乱码）塞给 LLM 是不行的：
#      上下文会爆、噪声会淹没信号，模型只能瞎猜或直接超时报错。
#   —— 因此这里先做「离线证据抽取 → 相关度排序 → 预算装箱」，
#      必要时把证据切成多个片段分别问 LLM，最后按置信度投票合并。
# ============================================================================

# 抽取「值得送进 LLM 的代码窗口」时关注的密码学关键词。
# 与 file_crypto_scanner.ALGO_PATTERNS 互补：那边认「算法名」，这边认「调用结构与密钥变量名」。
CRYPTO_FOCUS_KW = (
    # 算法名
    "sm4", "sms4", "sm3", "sm2", "aes", "des3", "tripledes", "rc4", "blowfish", "chacha",
    "rc5", "rc6", "cast5", "cast128", "cast-128", "rc2", "arc2", "salsa20", "salsa",
    # 工作模式 / 填充
    "ecb", "cbc", "cfb", "ofb", "ctr", "gcm", "pkcs7", "pkcs5", "zeropadding",
    "iso10126", "ansix923", "nopadding", "paddingmode",
    # 调用点
    "encrypt", "decrypt", "cipher", "ciphertext", "createsign", "hmac", "digest", "dofinal",
    # 密钥 / 向量 / 签名盐
    "secretkey", "secret_key", "aeskey", "aes_key", "sm4key", "sm4_key", "deskey",
    "ivparameter", "ivspec", "keygenerator", "keyspec", "nonce",
    "appkey", "app_key", "appsecret", "app_secret", "signkey", "sign_key", "static_key",
    # 编解码
    "base64", "btoa", "atob", "hexlify", "unhexlify", "frombase64", "tobase64",
    # 常见密码库
    "gmssl", "crypto-js", "cryptojs", "node-forge", "sjcl", "javax.crypto",
    "bouncycastle", "pycryptodome", "hazmat", "cryptography",
)

# 单个证据窗口半径（字符）：以命中点为中心前后各取这么多
_WINDOW_PAD = 300
# 交付给 LLM 的单个片段字符预算
DEFAULT_CONTEXT_CHARS = 14000
# 最多切成几个片段分别送 LLM（每个片段一次调用）
DEFAULT_MAX_CHUNKS = 3
# 证据抽取阶段最多读取的字节数（避免大文件把内存与时间吃满）
_EVIDENCE_MAX_BYTES = 8 * 1024 * 1024
# 单个文件最多保留的证据窗口数
_MAX_WINDOWS = 120


def _snap_to_lines(text: str, start: int, end: int) -> tuple[int, int]:
    """把窗口边界吸附到换行处，避免把一行代码劈成两半。"""
    nl = text.rfind("\n", 0, start)
    if nl != -1 and start - nl <= 200:
        start = nl + 1
    nl2 = text.find("\n", end)
    if nl2 != -1 and nl2 - end <= 200:
        end = nl2
    return max(0, start), min(len(text), end)


def _extract_code_windows(text: str, limit: int = _MAX_WINDOWS) -> list[dict[str, Any]]:
    """
    围绕密码学关键词抽取「代码窗口」，按相关度降序返回。

    这是文件级分析的核心：**不要把整份文件给 LLM，而是把最相关的片段给它。**

    返回 [{"start", "end", "line", "score", "kws", "excerpt"}]
    """
    if not text:
        return []

    low = text.lower()
    spans: list[tuple[int, int, set[str]]] = []
    for kw in CRYPTO_FOCUS_KW:
        start = 0
        while True:
            idx = low.find(kw, start)
            if idx < 0:
                break
            spans.append((
                max(0, idx - _WINDOW_PAD),
                min(len(text), idx + len(kw) + _WINDOW_PAD),
                {kw},
            ))
            start = idx + len(kw)
            if len(spans) > 6000:  # 超大文件保护：命中太多就没必要继续扫
                break
        if len(spans) > 6000:
            break

    if not spans:
        return []

    # 按起点排序后合并重叠窗口，关键词取并集
    spans.sort(key=lambda s: (s[0], s[1]))
    merged: list[list[Any]] = []
    for s, e, kws in spans:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
            merged[-1][2] |= kws
        else:
            merged.append([s, e, set(kws)])

    out: list[dict[str, Any]] = []
    for s, e, kws in merged:
        s2, e2 = _snap_to_lines(text, s, e)
        excerpt = text[s2:e2].strip()
        if not excerpt:
            continue
        # 相关度 = 命中的不同关键词数量为主 + 结构性加分项
        score = len(kws) * 10
        blob = excerpt.lower()
        for bonus_kw, bonus in (
            ("encrypt", 8), ("decrypt", 8), ("key", 6), ("base64", 5),
            ("padding", 5), ("iv", 4), ("mode", 3),
        ):
            if bonus_kw in blob:
                score += bonus
        out.append({
            "start": s2,
            "end": e2,
            "line": text.count("\n", 0, s2) + 1,
            "score": score,
            "kws": sorted(kws),
            "excerpt": excerpt,
        })

    out.sort(key=lambda w: (-w["score"], w["start"]))
    return out[:limit]


def _pack_windows(windows: list[dict[str, Any]],
                  budget_chars: int) -> list[list[dict[str, Any]]]:
    """把窗口按相关度顺序装箱成若干片段，每片渲染后不超过 budget_chars。"""
    chunks: list[list[dict[str, Any]]] = []
    cur: list[dict[str, Any]] = []
    used = 0
    for w in windows:
        cost = len(w["excerpt"]) + 140  # 预留小标题开销
        if cur and used + cost > budget_chars:
            chunks.append(cur)
            cur, used = [], 0
        cur.append(w)
        used += cost
    if cur:
        chunks.append(cur)
    return chunks


# 压缩包内值得抽取证据的条目后缀（与 file_crypto_scanner._scan_archive_entries 对齐）
_ARCHIVE_INTERESTING = (
    ".js", ".mjs", ".ts", ".vue", ".json", ".xml", ".properties",
    ".so", ".dex", ".jar", ".keystore", ".jks", ".pem", ".cer", ".crt",
    ".conf", ".ini", ".yaml", ".yml", ".env", ".html", ".txt",
)
# 需要按「字符串常量池」方式读取的二进制条目
_ARCHIVE_BINARY_EXT = (".so", ".dex", ".jar", ".keystore", ".jks", ".cer", ".crt")
# 单个包内条目最多处理的字节数
_ARCHIVE_ENTRY_MAX = 2 * 1024 * 1024
# 包内条目合计最多处理的字节数（预算控制）
_ARCHIVE_TOTAL_MAX = 6 * 1024 * 1024


def _archive_text_blob(path: str, deep: bool = False) -> tuple[str, list[str]]:
    """
    把压缩包（APK / JAR / ZIP / OOXML）内值得分析的条目内容拼成一段**带条目标签的文本**。

    为什么必须这么做（真实踩过的坑）：
      压缩包主体是 Deflate 字节流，直接在整包上抽「密码学关键词窗口」等于在乱码里找
      关键词 —— 实测一条都命中不到（windows=0），LLM 只能看到「这是个压缩包」，
      结论置信度掉到 0.1。而真正的证据（assets/app.js 的 AES 调用、classes.dex 里的
      SM4 字符串）全在**包内条目**里。

    返回 (text_blob, 已纳入的条目标签列表)
    """
    import zipfile
    import file_crypto_scanner as fcs

    labels: list[str] = []
    parts: list[str] = []
    total = 0
    try:
        # 【注意】ZipFile 必须在整个读取过程中保持打开：
        # 若写成 `with zipfile.ZipFile(...) as zf:` 只包住 infolist()，
        # 块结束后档案被关闭，后续 zf.read() 会抛「archive already closed」。
        zf = zipfile.ZipFile(path)
    except Exception:  # noqa: BLE001 —— 不是合法压缩包就当作无条目
        return "", []

    try:
        infos = zf.infolist()
        infos.sort(key=lambda i: i.file_size)  # 先看小的配置/源码，再看大的二进制
        scanned = 0
        for info in infos:
            if info.is_dir():
                continue
            name = info.filename
            lower = name.lower()
            if not lower.endswith(_ARCHIVE_INTERESTING):
                continue
            if info.file_size > _ARCHIVE_ENTRY_MAX:
                continue
            if scanned >= (80 if deep else 30):
                break
            if total >= _ARCHIVE_TOTAL_MAX:
                break
            try:
                payload = zf.read(info)
            except Exception:  # noqa: BLE001
                continue
            scanned += 1
            total += len(payload)
            labels.append(name)
            parts.append("///// 包内条目：%s（%d 字节）/////" % (name, info.file_size))
            if lower.endswith(_ARCHIVE_BINARY_EXT):
                # 二进制条目（dex / so）：只取可打印字符串常量，避免乱码淹没信号
                try:
                    parts.append("\n".join(s for _, s in fcs.extract_strings(payload)))
                except Exception:  # noqa: BLE001
                    parts.append(payload.decode("utf-8", errors="replace"))
            else:
                parts.append(payload.decode("utf-8", errors="replace"))
    finally:
        try:
            zf.close()
        except Exception:  # noqa: BLE001
            pass
    return "\n".join(parts), labels


def _is_archive_like(finfo: dict[str, Any], raw: bytes) -> bool:
    """是否应按「压缩包」处理：离线分类为 archive，或字节头是 PK / dex。"""
    if str(finfo.get("category", "")) == "archive":
        return True
    if raw[:2] == b"PK":
        return True
    if raw[:4] == b"dex\n":
        return True
    return False


def build_file_context(path: str, *, deep: bool = False,
                       budget_chars: int = DEFAULT_CONTEXT_CHARS,
                       max_chunks: int = DEFAULT_MAX_CHUNKS,
                       on_step=None) -> dict[str, Any]:
    """
    把一个文件压缩成 LLM 可消费的「高信号证据包」。

    产物：
      meta   —— 文件概况（类型/大小/熵/头部 HEX/离线命中）
      chunks —— 证据片段列表，每段是一段结构化文本（≤ budget_chars）
      stats  —— 统计信息（窗口数/密钥数/文件形态/是否被截断）
    """
    import file_crypto_scanner as fcs

    def step(pct: int, text: str) -> None:
        if on_step:
            on_step(pct, text)

    # ---- 1) 复用离线扫描器：类型判定 + 算法/密钥/逻辑提取（零额外成本，纯本地）----
    step(25, "读取文件并分类")
    scan = fcs.scan_file(path, deep=deep)

    finfo = scan.get("file", {}) or {}
    logic = scan.get("logic", {}) or {}
    algos = scan.get("algorithms", []) or []
    secrets = scan.get("secrets", []) or []
    libs = scan.get("crypto_libs", []) or []
    inner = scan.get("inner_files", []) or []
    domains = scan.get("domains", []) or []

    size = int(finfo.get("size", 0) or 0)
    name = finfo.get("name") or os.path.basename(path)

    # ---- 2) 组装「永远随片段一起送达」的概况头（保证每片自足）----
    head = [
        "【文件概况】",
        "文件名：%s" % name,
        "识别类型：%s（置信度 %s）" % (finfo.get("type_display", "未知"), finfo.get("confidence", "低")),
        "大小：%.1f KB · 熵值 %s（%s）" % (size / 1024.0, finfo.get("entropy", "?"),
                                          finfo.get("entropy_verdict", "未知")),
        "头部 HEX：%s" % (finfo.get("hex_preview", "") or "（无）"),
    ]
    if algos:
        head.append("离线规则命中算法：" + "、".join(
            "%s(权%d)" % (a.get("algorithm"), a.get("weight", 1)) for a in algos[:12]))
    if libs:
        head.append("引用的密码库：" + "、".join(l.get("display", "") for l in libs[:12]))
    if logic.get("rule"):
        head.append("离线规则推断：%s" % logic.get("rule"))
    if domains:
        head.append("出现域名：" + "、".join(domains[:8]))
    head_text = "\n".join(head)

    # ---- 3) 候选密钥材料（最硬的证据，直接结构化给 LLM）----
    sec = ["【离线扫描提取到的候选密钥材料】"]
    if secrets:
        for s in secrets[:40]:
            sec.append("- [%s] %s  ← %s%s%s" % (
                {"high": "高", "medium": "中", "low": "低"}.get(s.get("confidence"), "?"),
                s.get("value", ""),
                s.get("guess") or s.get("kind", ""),
                (" · %d 字节" % s["bytes_len"]) if s.get("bytes_len") else "",
                (" ｜ " + str(s.get("evidence", ""))[:90]) if s.get("evidence") else "",
            ))
    else:
        sec.append("（未提取到硬编码密钥材料）")
    if inner:
        sec.append("【包内命中文件】")
        for f in inner[:15]:
            sec.append("- %s：算法 %s，密钥 %d 条" % (
                f.get("name"),
                "/".join(a.get("algorithm", "") for a in (f.get("algorithms") or [])) or "无",
                len(f.get("secrets") or []),
            ))
    secrets_text = "\n".join(sec)

    # ---- 4) 抽取证据窗口：三种来源按优先级选择 ----
    #   ① 压缩包（APK/JAR/ZIP）→ 包内条目文本（整包是 Deflate 流，抽不到关键词）
    #   ② 二进制             → 字符串常量池
    #   ③ 文本               → 源码本身
    step(40, "抽取密码学相关证据")
    try:
        with open(path, "rb") as fh:
            raw = fh.read(_EVIDENCE_MAX_BYTES)
    except OSError:
        raw = b""

    source_label = "文件文本"
    evidence_mode = "text"
    entry_labels: list[str] = []

    if _is_archive_like(finfo, raw):
        entry_text, entry_labels = _archive_text_blob(path, deep=deep)
        if entry_text:
            windows = _extract_code_windows(entry_text)
            evidence_mode = "archive"
            shown = "、".join(os.path.basename(x) for x in entry_labels[:6])
            source_label = "包内条目（%d 个：%s%s）" % (
                len(entry_labels), shown, "…" if len(entry_labels) > 6 else "")
        else:
            windows = []
    elif raw and fcs.text_likeness(raw) < 0.55:
        # 二进制 / 可执行文件：字符串常量池里才有可读证据
        pool = "\n".join(s for _, s in fcs.extract_strings(raw))
        windows = _extract_code_windows(pool)
        evidence_mode = "binary"
        source_label = "二进制字符串常量池"
    else:
        windows = _extract_code_windows(fcs.decode_text(raw) if raw else "")

    all_windows = windows
    packed = _pack_windows(windows, budget_chars)
    truncated = len(packed) > max_chunks
    packed = packed[:max_chunks]

    # ---- 5) 渲染片段文本 ----
    step(55, "组装 LLM 证据包")
    # 容器类文件要额外提醒模型：「容器本身不加密」不是结论，要看包内代码
    mode_note = {
        "archive": "（说明：本文件是压缩包/安装包，条目内容才是待分析的证据；"
                   "ZIP/DEX 等容器结构本身未加密属正常现象，不构成「无密码方案」的理由）",
        "binary": "（说明：本文件是二进制/可执行文件，证据取自字符串常量池，可能不完整）",
    }.get(evidence_mode, "")

    chunks: list[str] = []
    multi = len(packed) > 1
    for ki, group in enumerate(packed, 1):
        parts = [head_text, secrets_text]
        parts.append("【密码学相关证据（来源：%s）】%s" % (source_label, mode_note))
        if multi:
            parts[-1] = "【密码学相关证据 · 第 %d/%d 组（来源：%s）】%s" % (
                ki, len(packed), source_label, mode_note)
        for wi, w in enumerate(group, 1):
            parts.append("--- 证据 %d（第 %d 行；命中关键词：%s）---" % (
                wi, w["line"], ", ".join(w["kws"][:8])))
            parts.append(w["excerpt"])
        chunks.append("\n".join(parts))

    if not chunks:
        hint = "\n【密码学相关证据】\n（未在文件中找到任何密码学相关代码/字符串证据）"
        if evidence_mode == "archive":
            hint = ("\n【密码学相关证据】\n"
                    "（已展开压缩包内 %d 个条目，但其中未发现密码学相关代码/字符串证据）"
                    % len(entry_labels))
        chunks = [head_text + "\n" + secrets_text + hint]

    stats = {
        "file": name,
        "size": size,
        "type": finfo.get("type_display", ""),
        "mode": evidence_mode,  # text | binary | archive
        "source": source_label,
        "entries": list(entry_labels[:20]),
        "windows": len(all_windows),
        "windows_used": sum(len(g) for g in packed),
        "chunks": len(chunks),
        "chunks_total": len(_pack_windows(windows, budget_chars)) if windows else len(chunks),
        "chunk_chars": [len(c) for c in chunks],
        "evidence_chars": sum(len(c) for c in chunks),
        "algos": [a.get("algorithm") for a in algos],
        "secrets": len(secrets),
        "truncated": truncated,
        "deep": bool(deep),
    }
    return {"meta": finfo, "chunks": chunks, "stats": stats}


def _weighted_vote(parts: list[dict[str, Any]], field: str) -> tuple[Any, list[str]]:
    """按「置信度 + 固定票底」给某字段投票，返回 (胜出值, 候选顺序)。"""
    tally: dict[str, float] = {}
    for p in parts:
        v = p.get(field)
        if not v:
            continue
        tally[str(v)] = tally.get(str(v), 0.0) + float(p.get("confidence") or 0.0) + 0.05
    if not tally:
        return None, []
    ranked = sorted(tally.items(), key=lambda kv: -kv[1])
    return ranked[0][0], [k for k, _ in ranked]


def _merge_chunk_results(parts: list[dict[str, Any]], *, chunks_total: int,
                         used: int) -> dict[str, Any]:
    """把多个片段的在线结论按置信度投票合并成一条文件级结论。"""
    ok = [p for p in parts if p.get("status") == "ok"]
    if not ok:
        detail = "; ".join(str((p.get("warnings") or ["未知错误"])[0]) for p in parts)
        raise RuntimeError("所有片段的在线分析都失败了：%s" % detail)

    # 失败片段的原因必须保留下来（曾经因为只取成功片段的 warnings 而丢掉）
    failed = [i for i, p in enumerate(parts, 1) if p.get("status") != "ok"]
    fail_warnings = [
        "证据片段 %d 在线分析失败：%s" % (i, (parts[i - 1].get("warnings") or ["未知错误"])[0])
        for i in failed
    ]

    extra_warnings: list[str] = list(fail_warnings)
    if used < chunks_total:
        extra_warnings.append(
            "文件较大，仅分析了相关度最高的 %d 个片段（共 %d 个），结论基于最高信号部分"
            % (used, chunks_total))
    if failed:
        extra_warnings.append(
            "本次为**部分片段结论**（%d/%d 段成功），可能遗漏其余代码中的方案信息"
            % (len(ok), len(parts)))

    if len(ok) == 1:
        r = dict(ok[0])
        r["hints"] = list(r.get("hints") or [])
        # 关键：把失败片段的原因也带上，而不是只保留成功片段自己的 warnings
        r["warnings"] = list(r.get("warnings") or []) + extra_warnings
        tag = "（仅 %d/%d 个片段成功）" % (len(ok), len(parts)) if failed else "（单片段判定）"
        r["note"] = (r.get("note") or "").rstrip("。") + tag
        return _normalize_result(r)

    winners: dict[str, Any] = {}
    disagreements: list[str] = []
    for field in ("alg", "mode", "padding", "encoding"):
        best, order = _weighted_vote(ok, field)
        winners[field] = best
        if len(order) > 1:
            disagreements.append("%s 候选 %s" % (field, "/".join(order)))

    # 一致度：胜出算法的得票占总票比例
    tally: dict[str, float] = {}
    for p in ok:
        v = p.get("alg")
        if v:
            tally[str(v)] = tally.get(str(v), 0.0) + float(p.get("confidence") or 0.0) + 0.05
    ranked = sorted(tally.values(), reverse=True)
    agreement = (ranked[0] / sum(ranked)) if ranked and sum(ranked) else 0.0

    max_conf = max(float(p.get("confidence") or 0.0) for p in ok)
    confidence = round(max_conf * (0.6 + 0.4 * agreement), 3)

    # 密钥/IV：优先取「与胜出算法一致且置信度最高」的那一片，保证 alg 与 key 自洽
    pick = None
    for p in sorted(ok, key=lambda x: -(x.get("confidence") or 0.0)):
        if p.get("alg") == winners["alg"] and (p.get("key") or p.get("iv")):
            pick = p
            break
    if pick is None:
        pick = max(ok, key=lambda x: (1 if x.get("key") else 0, float(x.get("confidence") or 0.0)))

    hints: list[str] = []
    for i, p in enumerate(parts, 1):
        for h in (p.get("hints") or [])[:4]:
            hints.append("[片段 %d] %s" % (i, h))

    warnings = [w for p in ok for w in (p.get("warnings") or [])]
    if disagreements:
        warnings.append("不同片段的结论存在分歧，已按置信度投票取多数：" + "；".join(disagreements))
    warnings += extra_warnings

    return _normalize_result({
        "status": "ok",
        "source": "online",
        "alg": winners["alg"],
        "mode": winners["mode"],
        "padding": winners["padding"],
        "key": pick.get("key"),
        "iv": pick.get("iv"),
        "encoding": winners["encoding"] or "base64",
        "confidence": confidence,
        "hints": hints[:24],
        "warnings": warnings,
        "note": "在线 LLM 基于文件证据包分 %d 段分析后投票合并（%d/%d 段成功，一致度 %.0f%%）"
                % (len(ok), len(ok), len(parts), agreement * 100),
    })


def _online_analyze_chunks(chunks: list[str], cfg: AIConfig,
                           step=None, retries: int | None = None) -> dict[str, Any]:
    """
    把多个证据片段分别送 LLM，再投票合并成一条文件级结论。

    重试已下沉到网络层（`online_analyze` 内部按 `cfg.max_retries` 指数退避），
    这里只需保证「单片彻底失败不放弃整份文件」，并把失败原因记录下来。
    """
    total = len(chunks)
    parts: list[dict[str, Any]] = []
    for i, ch in enumerate(chunks, 1):
        last_exc = None
        if step:
            step(70, "调用在线 LLM 分析证据片段 %d/%d（模型：%s）" % (i, total, cfg.model))
        try:
            parts.append(online_analyze("", cfg, file_ctx={"evidence": ch},
                                        step=step, pct=70))
            last_exc = None
        except Exception as exc:  # noqa: BLE001 —— 单片失败不放弃整份文件
            last_exc = exc
        if last_exc is not None:
            parts.append({
                "status": "error", "source": "online", "alg": None,
                "confidence": 0.0, "warnings": ["片段 %d 调用失败：%s" % (i, last_exc)],
            })
    if step:
        step(85, "合并 %d 个片段的结论" % total)
    return _merge_chunk_results(parts, chunks_total=total, used=total)


# ============================================================================
# 在线 LLM（OpenAI 兼容接口，标准库 http.client）
# ============================================================================
SYSTEM_PROMPT = """你是一名资深密码学/逆向工程分析师。用户会贴出一段代码、抓包文本或配置片段，
你需要判断它使用了哪套「对称密码方案」，并只输出一段 JSON（不要解释、不要 markdown 代码块）。

JSON 字段（全部可选，判断不出就填 null 或省略）：
{
  "alg":      "sm4" | "aes128" | "aes192" | "aes256" | "des" | "des3" | "rc4"
              | "rc5" | "rc5_16" | "rc5_64" | "rc6" | "rc6_16"
              | "blowfish" | "cast5" | "rc2" | "chacha20" | "salsa20",
  "mode":     "ecb" | "cbc" | "cfb" | "ofb" | "ctr" | "gcm",
  "padding":  "pkcs7" | "zero" | "none" | "iso7816" | "ansix923",
  "key":      "密钥的 HEX 字符串（如 0123...），找不到填 null",
  "iv":       "IV/nonce 的 HEX 字符串，ECB 或流密码填 null",
  "encoding": "base64" | "hex" | "raw",
  "confidence": 0.0~1.0 的数值，表示你对整体判断的把握,
  "hints":    ["一条条你认为支持该结论的证据，中文"],
  "warnings": ["风险提示，例如：密钥硬编码在客户端、使用了不安全的 ECB 模式"]
}

约束：
- alg/mode/padding/encoding 必须严格取自上述枚举，不要自创。
- 只输出 JSON，不要任何额外文字。"""


FILE_SYSTEM_PROMPT = """你是一名资深密码学/逆向工程分析师。用户给的**不是一个代码片段，而是一个文件的「证据包」**：
里面依次包含 ① 文件概况（识别类型 / 大小 / 熵值 / 头部 HEX / 离线规则已命中的算法 / 引用到的密码库）
② 离线扫描已提取到的候选密钥材料（含字节长度与来源代码）
③ 按相关度排序的密码学相关证据。证据带来源标注，例如
   `///// 包内条目：assets/app.js /////` 表示下面这段来自压缩包（APK/JAR/ZIP）里的这个条目。

请据此判断**这个文件里实现/使用的对称密码方案**，并只输出一段 JSON（不要解释、不要 markdown 代码块）。

⚠ 首要澄清（最容易答错的地方）：
- 你要回答的是「文件里的代码/配置**用了什么对称密码方案**」，
  **不是**「这个文件本身是不是被加密的密文」。
- 因此：**压缩包（APK/JAR/ZIP）、可执行文件、前端 bundle 本身几乎总是未加密的**，
  这是正常且预期的。看到 `PK\\x03\\x04`、`dex\\n`、目录名、Deflate 特征，**都不能**作为
  「没有加密方案」的理由 —— 你必须继续去读证据里的**代码与配置内容**。
- 包内条目的代码（如 `assets/app.js`、`res/raw/config.json`）才是判断依据。请以代码级证据为准：
  `encrypt/decrypt/cipher` 调用、`mode/padding` 选项、`key/iv/secret` 变量与字面量、算法库引用。

JSON 字段（全部可选，判断不出就填 null 或省略）：
{
  "alg":      "sm4" | "aes128" | "aes192" | "aes256" | "des" | "des3" | "rc4"
              | "rc5" | "rc5_16" | "rc5_64" | "rc6" | "rc6_16"
              | "blowfish" | "cast5" | "rc2" | "chacha20" | "salsa20",
  "mode":     "ecb" | "cbc" | "cfb" | "ofb" | "ctr" | "gcm",
  "padding":  "pkcs7" | "zero" | "none" | "iso7816" | "ansix923",
  "key":      "密钥的 HEX 字符串（如 0123...），找不到填 null",
  "iv":       "IV/nonce 的 HEX 字符串，ECB 或流密码填 null",
  "encoding": "base64" | "hex" | "raw",
  "confidence": 0.0~1.0 的数值，表示你对整体判断的把握,
  "hints":    ["一条条你认为支持该结论的证据，中文，尽量引用证据包中的原文片段"],
  "warnings": ["风险提示，例如：密钥硬编码在客户端、使用了不安全的 ECB 模式"]
}

重要约束：
- 证据包是**抽取片段而非完整文件**：只能依据给出的证据下结论，不要脑补文件里不存在的内容。
- 若证据显示存在多套方案（例如同时有签名和加密），alg/mode/padding 填**最主要/最外层**那一套，其余写进 hints。
- key/iv 必须**逐字复制**证据中出现的字面量，不要自行推导、补齐或猜测；证据里没有就填 null。
- 密钥是 base64 或明文字符串时，先判断其字节长度：16 字节→AES-128/SM4，24 字节→AES-192，32 字节→AES-256。
  能明确换算成 HEX 就填 HEX，填不进去就在 hints 里注明原始形式。
- 证据不足以判定时，把 confidence 调到 0.4 以下，并在 warnings 里说明「还缺什么证据」。
  **但「文件是压缩包/可执行文件」不属于证据不足** —— 那只是容器，请继续看包内代码。
- alg/mode/padding/encoding 必须严格取自上述枚举，不要自创。
- 只输出 JSON，不要任何额外文字。"""


FILE_USER_TEMPLATE = """请分析下面这个文件的证据包，判断它使用的对称密码方案。

<<<证据包开始>>>
%s
<<<证据包结束>>>"""


def _endpoint_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    if base.endswith("/v1"):
        return base + "/chat/completions"
    return base + "/v1/chat/completions"


# ----------------------------------------------------------------------------
# 在线请求网络层
#
# 关键设计（针对「The read operation timed out」）：
#   1) 建连超时与读超时分离。urllib 的 timeout 同时管建连和读，一旦服务端
#      因为推理模型思考过久迟迟不吐字，就会在 30s 报 read timeout 而误判为
#      「网络故障」。这里用 http.client 手动分层：建连 15s 快速失败，
#      建连成功后把 socket 超时改为读超时（默认 120s）。
#   2) 瞬时错误自动重试（超时/连接重置/429/5xx），指数退避 1.5s→4s→8s，
#      因为这些都是幂等的「读取型」失败，重试即可恢复。
#   3) 所有失败都归类成可读中文，区分「超时 / 不可达 / 鉴权 / 限流 / 余额 /
#      服务端 / 输出解析」，让降级原因一眼可辨、可对症下药。
# ----------------------------------------------------------------------------
_RETRY_BACKOFF = (1.5, 4.0, 8.0, 12.0)


class LLMError(RuntimeError):
    """在线 LLM 调用失败，带可重试标记与错误类别。"""

    def __init__(self, message: str, retryable: bool = False, kind: str = "error"):
        super().__init__(message)
        self.retryable = retryable
        self.kind = kind


def _split_endpoint(url: str) -> tuple[str, str, int | None, str]:
    """把 URL 拆成 scheme/host/port/path（path 含 query）。"""
    u = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return (u.scheme or "https"), (u.hostname or ""), u.port, path


def _classify_http_status(code: int, detail: str) -> LLMError:
    """HTTP 状态码 → 可读原因 + 是否可重试。"""
    detail = (detail or "").strip().replace("\n", " ")[:200]
    if code == 401:
        return LLMError("鉴权失败（HTTP 401）：API Key 无效或已过期", False, "auth")
    if code == 403:
        return LLMError("无权限（HTTP 403）：该 Key 无权访问模型或接口。%s" % detail, False, "auth")
    if code == 402:
        return LLMError("余额/额度不足（HTTP 402）。%s" % detail, False, "billing")
    if code == 404:
        return LLMError("接口或模型不存在（HTTP 404）：请检查 Base URL 与模型名。%s" % detail,
                        False, "notfound")
    if code == 422:
        return LLMError("请求被拒（HTTP 422）：参数不合法或模型不支持该格式。%s" % detail,
                        False, "invalid")
    if code == 429:
        return LLMError("触发限流（HTTP 429）：请求过于频繁，稍后重试。%s" % detail, True, "ratelimit")
    if 500 <= code < 600:
        return LLMError("服务端错误（HTTP %d）：上游网关/模型异常。%s" % (code, detail), True, "server")
    return LLMError("LLM 接口返回 HTTP %d：%s" % (code, detail), False, "http")


def _classify_connect_error(exc: BaseException, connect_timeout: int, host: str, port) -> LLMError:
    where = "%s:%s" % (host, port or ("443" if port is None else port))
    if isinstance(exc, socket.gaierror):
        return LLMError("域名解析失败：无法解析 %s（检查网络/DNS/代理）" % host, False, "dns")
    if isinstance(exc, ssl.SSLCertVerificationError):
        return LLMError("TLS 证书校验失败：%s（可能存在中间人代理或自签证书）" % exc, False, "tls")
    if isinstance(exc, ssl.SSLError):
        return LLMError("TLS 握手失败：%s" % exc, False, "tls")
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return LLMError("建连超时（%ss）：无法连接到 %s（网络不通/被墙/代理未配）"
                        % (connect_timeout, where), True, "connect-timeout")
    if isinstance(exc, ConnectionRefusedError):
        return LLMError("连接被拒绝：%s 无服务监听（本地 Ollama/代理没起来？）" % where, True, "refused")
    if isinstance(exc, OSError):
        return LLMError("建连失败：%s（%s）" % (exc, where), True, "connect")
    return LLMError("建连异常：%s" % exc, True, "connect")


def _classify_transfer_error(exc: BaseException, read_timeout: int) -> LLMError:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return LLMError(
            "读超时（%ss）：已连上服务端但模型迟迟不返回。推理模型思考耗时波动大，"
            "可在「AI 配置 → 超时」调大（当前 %ss）或改用非推理模型" % (read_timeout, read_timeout),
            True, "timeout")
    if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
        return LLMError("连接被重置：%s（上游过早断开，可重试）" % exc, True, "reset")
    if isinstance(exc, http.client.IncompleteRead):
        return LLMError("响应被截断：%s（可重试）" % exc, True, "incomplete")
    if isinstance(exc, http.client.HTTPException):
        return LLMError("HTTP 协议异常：%s（可重试）" % exc, True, "httpexc")
    if isinstance(exc, ssl.SSLError):
        return LLMError("TLS 传输异常：%s" % exc, True, "tls")
    return LLMError("调用 LLM 失败：%s" % exc, True, "unknown")


def _remediation(kind: str) -> str:
    """按错误类别给出可操作建议。"""
    return {
        "timeout": "服务端已连上但返回慢：到「AI 配置」把超时调大到 180~300 秒，"
                   "或改用非推理模型（推理模型思考耗时波动大）",
        "connect-timeout": "连不上接口：检查网络/代理/防火墙，确认 Base URL 可从本机访问",
        "dns": "域名解析失败：检查 DNS 或把 Base URL 换成 IP/正确域名",
        "refused": "端口无服务：本地 Ollama/代理是否已启动，端口是否正确",
        "reset": "上游过早断开：稍后重试；若持续出现多为代理不稳定",
        "auth": "鉴权失败：检查 API Key 是否有效/过期、是否带了多余空格或前缀",
        "billing": "余额不足：请到模型服务商后台充值",
        "notfound": "接口或模型不存在：核对 Base URL 是否需带 /v1，模型名是否拼错",
        "invalid": "请求被拒：模型可能不支持 response_format=json_object，可换模型",
        "ratelimit": "触发限流：降低频率，稍后再试",
        "server": "上游服务异常：稍后重试；若持续出现可换模型或服务商",
        "tls": "TLS 问题：可能是代理/自签证书，检查 HTTPS_PROXY 或改用 http 端点",
        "parse": "模型输出无法解析成 JSON：可换用更听话的模型",
        "config": "配置缺失：到「AI 配置」补齐 Base URL / API Key / 模型名",
    }.get(kind, "先用「测试连接」定位；再按提示检查配置与网络")


def _http_post_json(url: str, body_bytes: bytes, headers: dict[str, str],
                    connect_timeout: int, read_timeout: int) -> str:
    """POST JSON，返回响应体文本。建连与读分别使用不同超时。"""
    scheme, host, port, path = _split_endpoint(url)
    if not host:
        raise LLMError("Base URL 非法：无法解析主机名（当前 %r）" % url, False, "url")
    if scheme not in ("http", "https"):
        raise LLMError("Base URL 协议不支持：仅支持 http/https（当前 %s）" % scheme, False, "url")

    if scheme == "https":
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            host, port or 443, timeout=connect_timeout)
    else:
        conn = http.client.HTTPConnection(host, port or 80, timeout=connect_timeout)
    try:
        # 1) 建连：短超时，快速暴露「网络不通」
        try:
            conn.connect()
        except Exception as exc:  # noqa: BLE001
            raise _classify_connect_error(exc, connect_timeout, host, port)
        # 2) 建连成功 → 切到长读超时
        try:
            if conn.sock is not None:
                conn.sock.settimeout(read_timeout)
        except Exception:  # noqa: BLE001
            pass
        # 3) 发送 + 读取
        try:
            conn.request("POST", path, body=body_bytes, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            status = resp.status
        except LLMError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _classify_transfer_error(exc, read_timeout)
        text = raw.decode("utf-8", errors="replace")
        if status >= 400:
            raise _classify_http_status(status, text)
        return text
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


class _Heartbeat:
    """长等待期间每 interval 秒经 step 播报一次进度，避免 GUI 看似卡死。"""

    def __init__(self, step, pct: int, label: str = "", interval: float = 5.0):
        self.step = step
        self.pct = pct
        self.label = label
        self.interval = interval
        self._stop = threading.Event()
        self._t: threading.Thread | None = None
        self._t0 = 0.0

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            waited = time.time() - self._t0
            try:
                self.step(self.pct, "等待模型响应…已 %.0fs%s（推理模型思考较慢属正常）"
                          % (waited, (" · " + self.label) if self.label else ""))
            except Exception:  # noqa: BLE001
                return

    def __enter__(self):
        if self.step:
            self._t0 = time.time()
            self._t = threading.Thread(target=self._run, daemon=True)
            self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._t:
            self._t.join(timeout=0.2)
        return False


def _post_with_retry(url: str, body_bytes: bytes, headers: dict[str, str],
                     cfg: AIConfig, step=None, pct: int = 70,
                     label: str = "") -> str:
    """
    带指数退避重试的 POST。仅对 retryable 的瞬时错误重试。

    另有**总预算封顶**（默认 ≈ 2×读超时 + 10s）：若每次读超时都重试，
    最坏情况会把 GUI 拖到十几分钟，因此耗完预算就不再重试、直接把最后一次
    的失败原因抛出去（前端照常降级为离线规则）。
    """
    attempts = max(1, int(getattr(cfg, "max_retries", 0) or 0) + 1)
    read_to = float(getattr(cfg, "timeout", 120) or 120)
    budget = read_to * 2.0 + 10.0
    t_start = time.time()
    last: LLMError | None = None
    for i in range(attempts):
        if i > 0:
            if time.time() - t_start >= budget:
                if step:
                    step(pct, "已耗时 %.0fs，超出总预算 %.0fs，不再重试"
                         % (time.time() - t_start, budget))
                break
            delay = _RETRY_BACKOFF[min(i - 1, len(_RETRY_BACKOFF) - 1)]
            if step:
                step(pct, "第 %d/%d 次重试（%.1fs 后）：上一次 %s"
                     % (i, attempts - 1, delay, last))
            time.sleep(delay)
        try:
            with _Heartbeat(step, pct, label):
                return _http_post_json(url, body_bytes, headers,
                                       cfg.connect_timeout, cfg.timeout)
        except LLMError as exc:
            last = exc
            if not exc.retryable:
                raise
            if i == attempts - 1:
                raise
            if step:
                step(pct, "调用失败（%s），准备重试" % exc.kind)
    raise last if last is not None else LLMError("未知错误", False, "unknown")


def test_llm(cfg: AIConfig, step=None) -> dict[str, Any]:
    """最小请求探活：验证 Base URL / Key / 模型是否真的可用，返回延迟与错误分类。"""
    if not cfg.base_url:
        return {"ok": False, "kind": "config", "error": "未配置 Base URL", "latency": None}
    if not cfg.api_key:
        return {"ok": False, "kind": "config", "error": "未配置 API Key", "latency": None}
    url = _endpoint_url(cfg.base_url)
    payload = {
        "model": cfg.model,
        "messages": [{"role": "user", "content": "ping，仅回复 OK"}],
        "temperature": 0.0,
        "max_tokens": 64,
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
        "Authorization": "Bearer " + cfg.api_key,
        "Content-Length": str(len(body)),
        "User-Agent": "jiejieEAD/1.0 (+llm-probe)",
    }
    t0 = time.time()
    try:
        raw = _post_with_retry(url, body, headers, cfg, step=step, pct=5, label="连通性测试")
    except LLMError as exc:
        return {"ok": False, "kind": exc.kind, "error": str(exc),
                "latency": round(time.time() - t0, 2), "url": url, "model": cfg.model}
    dt = round(time.time() - t0, 2)
    try:
        data = json.loads(raw)
        msg = data["choices"][0]["message"]
        content = msg.get("content") or ""
        reasoning = msg.get("reasoning_content") or ""
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "kind": "parse", "error": "响应结构异常：%s" % exc,
                "latency": dt, "url": url, "model": cfg.model}
    note = ""
    if not str(content).strip() and reasoning:
        note = "（该模型为推理模型：content 为空但 reasoning_content 非空，建议调大超时/换非推理模型）"
    return {"ok": True, "kind": "ok", "error": "", "latency": dt,
            "url": url, "model": cfg.model, "reply": str(content).strip()[:120], "note": note}


def llm_json(system_prompt: str, user_content: str, cfg: AIConfig,
             step=None, pct: int = 70, label: str = "") -> dict[str, Any]:
    """
    通用在线调用：把 (system, user) 发给 OpenAI 兼容接口，返回解析后的 JSON 对象。

    单文件分析 / 文件夹整体分析都复用这里，避免重复实现网络层与解析容错。
    """
    url = _endpoint_url(cfg.base_url)
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.0,
        "response_format": {"type": "json_object"},
    }
    body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
        "Authorization": "Bearer " + cfg.api_key,
        "Content-Length": str(len(body_bytes)),
        "User-Agent": "jiejieEAD/1.0 (+ai-crypto-analyzer)",
    }
    body = _post_with_retry(url, body_bytes, headers, cfg, step=step, pct=pct, label=label)

    # 解析 choices[0].message.content 中的 JSON
    try:
        data = json.loads(body)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("LLM 响应不是合法 JSON：%s（前 200 字：%s）"
                           % (exc, body[:200].replace("\n", " ")))
    if isinstance(data, dict) and data.get("error"):
        err = data["error"]
        msg = err.get("message") if isinstance(err, dict) else str(err)
        raise RuntimeError("LLM 返回错误对象：%s" % (str(msg)[:200]))
    try:
        choice = data["choices"][0]
        content = choice["message"]["content"]
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("LLM 响应结构异常：%s（前 200 字：%s）"
                           % (exc, body[:200].replace("\n", " ")))

    # 推理模型可能把内容留在 reasoning_content、或 content 为空
    if not content or not str(content).strip():
        reasoning = ""
        try:
            reasoning = choice["message"].get("reasoning_content") or ""
        except Exception:  # noqa: BLE001
            reasoning = ""
        fin = choice.get("finish_reason", "")
        raise RuntimeError(
            "LLM 返回内容为空（finish_reason=%s%s）：模型把预算全花在推理上，"
            "未产出结论。可换用非推理模型，或调大 max_tokens"
            % (fin, "，仅有 reasoning_content" if reasoning else ""))

    content = str(content).strip()
    if content.startswith("```"):
        # 去掉可能的 ```json ... ``` 包裹
        content = content.strip("`")
        if content.lower().startswith("json"):
            content = content[4:]
        content = content.strip()

    # 容错：模型偶尔会在 JSON 外层夹带说明文字，截取第一个 { 到最后一个 }
    if not content.startswith("{"):
        lo, hi = content.find("{"), content.rfind("}")
        if lo >= 0 and hi > lo:
            content = content[lo:hi + 1]

    try:
        parsed = json.loads(content)  # 解析失败会向上抛出，触发降级
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("模型输出无法解析为 JSON：%s（前 200 字：%s）"
                           % (exc, content[:200].replace("\n", " ")))
    if not isinstance(parsed, dict):
        raise RuntimeError("模型输出的 JSON 不是对象：%r" % (parsed,))
    return parsed


def online_analyze(text: str, cfg: AIConfig,
                   file_ctx: dict[str, Any] | None = None,
                   step=None, pct: int = 70) -> dict[str, Any]:
    """
    调用在线 LLM 做**单文件/单片段**的密码方案分析。

    - 文本模式：直接把 text 作为片段送给模型（粘贴代码/抓包场景）。
    - 文件模式：传 file_ctx={"evidence": "..."}，使用文件级提示词，
      让模型基于「证据包」而不是整份文件做判断。

    网络层（超时分层 / 重试 / 心跳）统一在 `llm_json` 里实现。
    """
    if file_ctx and file_ctx.get("evidence"):
        system_prompt = FILE_SYSTEM_PROMPT
        user_content = FILE_USER_TEMPLATE % file_ctx["evidence"]
        note_suffix = "基于文件证据包判定"
    else:
        system_prompt = SYSTEM_PROMPT
        user_content = "请分析以下片段使用的对称密码方案：\n\n" + text
        note_suffix = "判定结果"

    parsed = llm_json(system_prompt, user_content, cfg, step=step, pct=pct)

    result = {
        "status": "ok",
        "source": "online",
        "alg": parsed.get("alg"),
        "mode": parsed.get("mode"),
        "padding": parsed.get("padding"),
        "key": parsed.get("key"),
        "iv": parsed.get("iv"),
        "encoding": parsed.get("encoding") or "base64",
        "confidence": float(parsed.get("confidence", 0.8) or 0.8),
        "hints": parsed.get("hints", []) or [],
        "warnings": parsed.get("warnings", []) or [],
        "note": "在线 LLM（%s）%s" % (cfg.model, note_suffix),
    }
    return _normalize_result(result)


# ============================================================================
# 知识库融合：命中复用 / 自动学习 / 方案旁证
# ============================================================================
def _learned_result(entry: dict[str, Any]) -> dict[str, Any]:
    """把知识库条目还原成标准分析结果（source=learned）。"""
    hits = int(entry.get("hits", 0)) + 1  # 本次即为第 hits 次复用
    scheme = entry.get("scheme_sig", "")
    return _normalize_result({
        "status": "ok",
        "source": "learned",
        "alg": entry.get("alg"),
        "mode": entry.get("mode"),
        "padding": entry.get("padding"),
        "key": entry.get("key"),
        "iv": entry.get("iv"),
        "encoding": entry.get("encoding"),
        "confidence": 1.0,
        "hints": ["命中本地知识库：该逻辑此前已确认并入库（复用第 %d 次）" % hits],
        "warnings": [],
        "note": "命中已学习规则（%s），直接复用历史结论" % scheme,
        "learned_scheme": scheme,
        "learned_hits": hits,
        "learned_at": entry.get("updated_at", ""),
    })


def _annotate_scheme(res: dict[str, Any], use_kb: bool) -> dict[str, Any]:
    """方案级旁证：内容未精确命中，但同方案在库中出现过 → 追加一条提示。"""
    if not use_kb or kb_mod is None:
        return res
    try:
        sch = kb_mod.lookup_scheme(res)
    except Exception:  # noqa: BLE001
        sch = None
    if sch and int(sch.get("count", 0)) > 0:
        try:
            sig = kb_mod.scheme_sig(res)
        except Exception:  # noqa: BLE001
            sig = "?"
        res["hints"] = list(res.get("hints", [])) + [
            "该方案（%s）在本地知识库中已出现 %d 次，可作旁证参考" % (sig, int(sch["count"]))
        ]
        res["scheme_seen"] = int(sch["count"])
    return res


def _auto_learn(text: str, res: dict[str, Any], enabled: bool) -> None:
    """在线高置信结果自动入库（离线启发式置信不足，不自动入库）。"""
    if not enabled or kb_mod is None:
        return
    try:
        if res.get("alg") and float(res.get("confidence") or 0.0) >= 0.8:
            kb_mod.learn(text, res, source="online")
    except Exception:  # noqa: BLE001
        pass


# ============================================================================
# 融合入口
# ============================================================================
def analyze(text: str, cfg: AIConfig | None = None,
            use_kb: bool = True, learn_online: bool = True,
            file_path: str | None = None,
            file_ctx: dict[str, Any] | None = None,
            deep: bool = False,
            context_chars: int = DEFAULT_CONTEXT_CHARS,
            max_chunks: int = DEFAULT_MAX_CHUNKS) -> dict[str, Any]:
    """
    融合入口。

    - 文本模式（file_path/file_ctx 均为空）：把 text 当片段分析。
    - **文件模式**（给 file_path 或 file_ctx）：先把文件压缩成「高信号证据包」，
      再让 LLM 基于证据包做文件级判断；证据太多会自动分片 + 投票合并。
    """
    cfg = cfg or load_config()

    _step(5, "校验输入")
    # 1) 先查知识库：内容精确命中 → 直接复用历史结论（含密钥/IV）
    if use_kb and kb_mod is not None:
        _step(15, "查询本地知识库")
        try:
            hit = kb_mod.lookup(text)
            if hit.get("kind") == "exact" and hit.get("entry"):
                try:
                    kb_mod.bump_hit(hit["entry"]["content_sig"])
                except Exception:  # noqa: BLE001
                    pass
                _step(100, "命中知识库，直接复用历史结论")
                return _learned_result(hit["entry"])
        except Exception:  # noqa: BLE001 —— 查库异常不影响正常分析
            pass

    # 1.5) 文件模式：构建证据包（纯本地、零网络，复用离线扫描器的抽取能力）
    file_stats: dict[str, Any] | None = None
    if file_ctx is None and file_path:
        try:
            file_ctx = build_file_context(
                file_path, deep=deep,
                budget_chars=context_chars, max_chunks=max_chunks,
                on_step=_step,
            )
            file_stats = file_ctx.get("stats") or {}
            _step(60, "证据包就绪：%d 处证据 · %d 个片段 · 约 %d 字符" % (
                file_stats.get("windows_used", 0),
                file_stats.get("chunks", 0),
                file_stats.get("evidence_chars", 0)))
        except Exception as exc:  # noqa: BLE001 —— 证据抽取失败就退回纯文本模式
            _step(60, "证据包构建失败，退回整文件模式")
            file_ctx = None
            text = text or ""

    # 2) 在线 LLM 优先
    _step(65, "检测在线 LLM 配置")
    if cfg.is_usable():
        try:
            chunks = list((file_ctx or {}).get("chunks") or [])
            if len(chunks) > 1:
                res = _online_analyze_chunks(chunks, cfg, step=_step)
            elif chunks:
                # ⚠ 这里必须传 {"evidence": <片段文本>}，不能把整个 file_ctx 直接丢过去：
                # online_analyze 只认 file_ctx["evidence"]，传错结构会静默退回「文本片段」模式，
                # 于是把整份文件的乱码塞给模型 —— 二进制/APK 会因此always返回「未发现加密方案」。
                _step(70, "调用在线 LLM（文件证据包，模型：%s）" % cfg.model)
                res = online_analyze(text, cfg, file_ctx={"evidence": chunks[0]},
                                     step=_step, pct=70)
            else:
                _step(70, "调用在线 LLM（模型：%s）" % cfg.model)
                res = online_analyze(text, cfg, step=_step, pct=70)
            if file_stats:
                res["file_stats"] = file_stats
                res.setdefault("hints", [])
                res["hints"] = list(res["hints"]) + [
                    "文件级证据包：共 %d 处密码学相关证据（%d 个片段、约 %d 字符）送入在线 LLM"
                    % (file_stats.get("windows_used", 0), file_stats.get("chunks", 0),
                       file_stats.get("evidence_chars", 0))
                ]
            _step(85, "解析模型响应")
            # use_kb=False（即 CLI 的 --no-learn）语义是「既不查库也不自动学习」，
            # 因此这里必须一起关掉自动学习，否则 --no-learn 仍会往知识库写入。
            _auto_learn(text, res, learn_online and use_kb)
            _step(100, "分析完成")
            return _annotate_scheme(res, use_kb)
        except Exception as exc:  # noqa: BLE001
            # 在线失败 → 降级离线，并保留原因（按类别给出可操作建议）
            kind = getattr(exc, "kind", "unknown")
            _step(88, "在线调用失败（%s），降级为离线启发式" % kind)
            offline = offline_analyze(text)
            offline["source"] = "offline-fallback"
            if file_stats:
                offline["file_stats"] = file_stats
            offline["warnings"] = list(offline.get("warnings", [])) + [
                "在线 LLM 调用失败，已降级为离线启发式：%s" % exc,
                "排查建议：%s" % _remediation(kind),
            ]
            offline["llm_error_kind"] = kind
            _step(100, "分析完成（离线兜底）")
            return _annotate_scheme(offline, use_kb)

    # 3) 离线启发式
    _step(70, "未配置在线 LLM，走离线启发式规则")
    res = offline_analyze(text)
    if file_stats:
        res["file_stats"] = file_stats
    _step(100, "分析完成（离线规则）")
    return _annotate_scheme(res, use_kb)


# ============================================================================
# CLI
# ============================================================================
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="AI 智能密码分析（在线为主 + 离线兜底）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--config-save", nargs="*", metavar="key=value",
                   help="保存 AI 配置，如 base_url=... api_key=... model=... enabled=true")
    p.add_argument("--config-show", action="store_true", help="打印当前 AI 配置（隐藏密钥）")
    p.add_argument("--test-llm", action="store_true",
                   help="向已配置的在线 LLM 发一个最小请求做「连通性测试」，报告延迟/模型/错误分类")
    p.add_argument("--analyze", action="store_true", help="分析输入的代码/文本/文件")
    p.add_argument("--text", help="待分析文本")
    p.add_argument("--file", help="待分析文件路径（文件级分析：先抽证据包再交 LLM）")
    p.add_argument("--deep", action="store_true",
                   help="文件级分析时深挖压缩包内层（APK/JAR/ZIP），更慢但更全")
    p.add_argument("--context-chars", type=int, default=DEFAULT_CONTEXT_CHARS,
                   help="每个证据片段的字符预算（默认 %d）" % DEFAULT_CONTEXT_CHARS)
    p.add_argument("--max-chunks", type=int, default=DEFAULT_MAX_CHUNKS,
                   help="证据过多时最多切成几个片段分别送 LLM（默认 %d）" % DEFAULT_MAX_CHUNKS)
    p.add_argument("--show-context", action="store_true",
                   help="只打印将要交给 LLM 的文件证据包，不调用 LLM（排查用）")
    p.add_argument("--json", action="store_true", help="以 JSON 输出分析结果")
    p.add_argument("--learn", action="store_true",
                   help="把本次分析结果写入本地知识库（自动学习，下次同逻辑直接命中）")
    p.add_argument("--as-json", dest="as_json",
                   help="与 --learn 搭配：直接指定要入库的结果 JSON（人工校正）")
    p.add_argument("--no-learn", action="store_true",
                   help="本次分析既不查库也不自动学习（强制走启发式/LLM）")
    p.add_argument("--kb-stats", action="store_true", help="打印本地知识库统计")
    p.add_argument("--kb-list", action="store_true", help="列出本地知识库条目")
    p.add_argument("--kb-clear", action="store_true", help="清空本地知识库")
    p.add_argument("--kb-path", action="store_true", help="打印知识库文件路径")
    p.add_argument("--selftest", action="store_true", help="运行自检")
    p.add_argument("--progress", action="store_true",
                   help="向 stderr 播报进度/过程（[PROGRESS] 百分比 步骤），供 GUI 进度条与过程日志")
    return p


def _read_input(args) -> tuple[str | None, str | None, int]:
    """
    按 --file / --text / 管道读取待分析内容。

    返回 (text, file_path, exit_code)：
      · file_path 非空表示走「文件级分析」（证据包模式）；
      · text 始终是该内容的全文，用于知识库签名与离线兜底。
    """
    if args.file:
        if not os.path.isfile(args.file):
            print("[错误] 文件不存在：%s" % args.file)
            return None, None, 2
        # 与 file_crypto_scanner 的 DEFAULT_MAX_BYTES 对齐：最多读入前 32MB
        _MAX_ANALYZE_BYTES = 32 * 1024 * 1024
        with open(args.file, "rb") as fh:
            raw = fh.read(_MAX_ANALYZE_BYTES)
        return raw.decode("utf-8", errors="replace"), args.file, 0
    if args.text is not None:
        return args.text, None, 0
    if not sys.stdin.isatty():
        return sys.stdin.read(), None, 0
    print("[错误] 请用 --text / --file 指定待分析内容")
    return None, None, 2


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if getattr(args, "progress", False):
        enable_progress()

    if args.config_show:
        cfg = load_config()
        shown = asdict(cfg)
        if shown["api_key"]:
            shown["api_key"] = shown["api_key"][:4] + "****" + shown["api_key"][-2:]
        print(json.dumps(shown, ensure_ascii=False, indent=2))
        return 0

    if args.test_llm:
        cfg = load_config()
        step = _step if getattr(args, "progress", False) else None
        if step:
            step(5, "向 %s 发送最小测试请求（模型：%s，超时 %ss，重试 %d）"
                 % (cfg.base_url or "（未配置）", cfg.model, cfg.timeout, cfg.max_retries))
        info = test_llm(cfg, step=step)
        info["config"] = {
            "enabled": cfg.enabled,
            "base_url": cfg.base_url,
            "model": cfg.model,
            "timeout": cfg.timeout,
            "connect_timeout": cfg.connect_timeout,
            "max_retries": cfg.max_retries,
            "api_key_set": bool(cfg.api_key),
        }
        info["remediation"] = "" if info["ok"] else _remediation(info.get("kind", "unknown"))
        if args.json:
            print(json.dumps(info, ensure_ascii=False, indent=2))
        else:
            if info["ok"]:
                print("[OK] 在线 LLM 可用 ✅")
                print("  接口      : %s" % info.get("url"))
                print("  模型      : %s" % info.get("model"))
                print("  往返延迟  : %ss" % info.get("latency"))
                print("  模型回复  : %s" % (info.get("reply") or "(空)"))
                if info.get("note"):
                    print("  提示      : %s" % info["note"])
            else:
                print("[失败] 在线 LLM 不可用 ❌")
                print("  类别      : %s" % info.get("kind"))
                print("  原因      : %s" % info.get("error"))
                if info.get("latency") is not None:
                    print("  已耗时    : %ss" % info.get("latency"))
                print("  建议      : %s" % info.get("remediation"))
        if step:
            step(100, "连通性测试完成")
        return 0 if info["ok"] else 3

    if args.config_save is not None:
        cfg = load_config()
        for item in args.config_save:
            if "=" not in item:
                print("[参数错误] --config-save 需 key=value 形式：%s" % item)
                return 2
            k, v = item.split("=", 1)
            k = k.strip().lower()
            if k == "base_url":
                cfg.base_url = v.strip()
            elif k == "api_key":
                cfg.api_key = v.strip()
            elif k == "model":
                cfg.model = v.strip()
            elif k == "enabled":
                cfg.enabled = v.strip().lower() in ("1", "true", "yes", "y", "on")
            elif k == "timeout":
                try:
                    cfg.timeout = max(5, int(v))
                except ValueError:
                    print("[参数错误] timeout 需为整数（秒）")
                    return 2
            elif k == "connect_timeout":
                try:
                    cfg.connect_timeout = max(2, int(v))
                except ValueError:
                    print("[参数错误] connect_timeout 需为整数（秒）")
                    return 2
            elif k == "max_retries":
                try:
                    cfg.max_retries = max(0, int(v))
                except ValueError:
                    print("[参数错误] max_retries 需为整数")
                    return 2
            else:
                print("[参数错误] 未知配置项：%s" % k)
                return 2
        path = save_config(cfg)
        print("[OK] 配置已保存到 %s（enabled=%s）" % (path, cfg.enabled))
        return 0

    if args.selftest:
        return _selftest()

    # ---- 知识库管理命令 ----
    if args.kb_path:
        print(kb_mod.kb_path() if kb_mod else "[错误] 知识库模块不可用")
        return 0

    if args.kb_stats:
        if kb_mod is None:
            print("[错误] 知识库模块不可用")
            return 2
        st = kb_mod.stats()
        if args.json:
            print(json.dumps(st, ensure_ascii=False, indent=2))
        else:
            print("本地密码逻辑知识库")
            print("  规则条目 : %d" % st["entries"])
            print("  方案种类 : %d" % st["schemes"])
            print("  累计命中 : %d 次" % st["total_hits"])
            print("  文件路径 : %s" % st["path"])
        return 0

    if args.kb_list:
        if kb_mod is None:
            print("[错误] 知识库模块不可用")
            return 2
        rows = kb_mod.list_entries()
        if args.json:
            print(json.dumps(rows, ensure_ascii=False, indent=2))
        else:
            if not rows:
                print("(知识库为空)")
            for e in rows:
                print("[%s] alg=%s mode=%s padding=%s key=%s hits=%d"
                      % (e.get("source", "?"), e.get("alg"), e.get("mode"),
                         e.get("padding"), (e.get("key") or "终")[:24], int(e.get("hits", 0))))
                print("     %s" % e.get("input_preview", "")[:100])
        return 0

    if args.kb_clear:
        if kb_mod is None:
            print("[错误] 知识库模块不可用")
            return 2
        p = kb_mod.clear()
        print("[OK] 知识库已清空：%s" % p)
        return 0

    # ---- 学习：把「本次分析」或「人工校正结果」写入知识库 ----
    if args.learn:
        if kb_mod is None:
            print("[错误] 知识库模块不可用，无法学习")
            return 2
        text, fpath, err = _read_input(args)
        if err:
            return err
        if args.as_json:
            try:
                result = _normalize_result(json.loads(args.as_json))
            except Exception as exc:  # noqa: BLE001
                print("[参数错误] --as-json 不是合法 JSON：%s" % exc)
                return 2
        else:
            try:
                result = analyze(text, load_config(), use_kb=not args.no_learn, learn_online=False,
                                 file_path=fpath, deep=args.deep,
                                 context_chars=args.context_chars, max_chunks=args.max_chunks)
            except Exception as exc:  # noqa: BLE001
                print("[错误] 分析失败，无法学习：%s" % exc)
                return 2
        entry = kb_mod.learn(text, result, source="manual")
        print("[OK] 已学习并入库：alg=%s mode=%s padding=%s key=%s"
              % (entry.get("alg"), entry.get("mode"), entry.get("padding"),
                 (entry.get("key") or "（无）")[:32]))
        print("     内容签名 %s · 方案 %s" % (entry["content_sig"], entry["scheme_sig"]))
        print("     知识库路径 %s" % kb_mod.kb_path())
        return 0

    if args.analyze:
        text, fpath, err = _read_input(args)
        if err:
            return err

        # --show-context：只打印证据包（排查「AI 到底看到了什么」）
        if args.show_context:
            if not fpath:
                print("[参数错误] --show-context 只对 --file 有效")
                return 2
            try:
                ctx = build_file_context(fpath, deep=args.deep,
                                         budget_chars=args.context_chars,
                                         max_chunks=args.max_chunks)
            except Exception as exc:  # noqa: BLE001
                print("[错误] 构建证据包失败：%s" % exc)
                return 2
            stats = ctx["stats"]
            print("=== 证据包统计 ===")
            print(json.dumps(stats, ensure_ascii=False, indent=2))
            for i, ch in enumerate(ctx["chunks"], 1):
                print("\n=== 片段 %d/%d（%d 字符）===" % (i, len(ctx["chunks"]), len(ch)))
                print(ch)
            return 0

        try:
            result = analyze(text, load_config(), use_kb=not args.no_learn,
                             file_path=fpath, deep=args.deep,
                             context_chars=args.context_chars, max_chunks=args.max_chunks)
        except Exception as exc:  # noqa: BLE001
            print("[错误] 分析失败：%s" % exc)
            return 2
        if args.json:
            print(json.dumps(result, ensure_ascii=False))
        else:
            _print_human(result)
        return 0

    _build_parser().print_help()
    return 0


def _print_human(r: dict[str, Any]) -> None:
    print("=" * 64)
    print(" AI 智能密码分析结果  (来源: %s)" % r.get("source"))
    print("=" * 64)
    print("  算法    : %s" % (r.get("alg") or "（未识别）"))
    print("  模式    : %s" % (r.get("mode") or "（未识别）"))
    print("  填充    : %s" % (r.get("padding") or "（未识别）"))
    print("  编码    : %s" % (r.get("encoding") or "base64"))
    print("  密钥    : %s" % (r.get("key") or "（未提取到）"))
    print("  IV      : %s" % (r.get("iv") or "（不需要/未提取到）"))
    print("  置信度  : %.2f" % float(r.get("confidence", 0.0)))
    if r.get("note"):
        print("  说明    : %s" % r["note"])
    for h in r.get("hints", []) or []:
        print("   · 证据: %s" % h)
    for w in r.get("warnings", []) or []:
        print("   [!] 提示: %s" % w)


def _selftest() -> int:
    print("=" * 64)
    print(" jiejieEAD AI 分析自检")
    print("=" * 64)
    failures: list[str] = []

    def check(name, ok, detail=""):
        print("   [ %s ] %s%s" % ("OK" if ok else "!!", name,
                                  ("  —— " + detail) if detail else ""))
        if not ok:
            failures.append(name)

    # 1) 离线规则：能识别 SM4-ECB-Zero 样本
    sample = (
        "var SM4_KEY = \"0123456789abcdeffedcba9876543210\";\n"
        "var c = sm4.encrypt(data, SM4_KEY, {mode:'ecb', padding:'ZeroPadding'});\n"
    )
    try:
        r = offline_analyze(sample)
        check("离线规则识别 SM4", r["alg"] == "sm4", "alg=%s" % r["alg"])
        check("离线规则识别 ECB 模式", r["mode"] == "ecb", "mode=%s" % r["mode"])
        check("离线规则识别 ZERO 填充", r["padding"] == "zero", "padding=%s" % r["padding"])
        check("离线规则提取密钥", r["key"] == "0123456789abcdeffedcba9876543210")
    except Exception as exc:  # noqa: BLE001
        check("离线规则分析不抛异常", False, str(exc))

    # 2) 离线规则：纯文本不误报
    r2 = offline_analyze("function main(){ return 1+1; }")
    check("纯文本不产生算法误报", r2["alg"] in (None, ""), "alg=%s" % r2["alg"])

    # 3) 融合入口：无在线配置时走离线
    cfg_off = AIConfig(enabled=False)
    r3 = analyze(sample, cfg_off)
    check("未启用在线时走离线", r3["source"] == "offline", "source=%s" % r3["source"])

    # 4) 在线失败降级：构造一个不可用配置，必须降级且 source=offline-fallback
    cfg_bad = AIConfig(enabled=True, base_url="http://127.0.0.1:9/nope",
                       api_key="x", model="m", timeout=2)
    r4 = analyze(sample, cfg_bad)
    check("在线失败降级为离线兜底", r4["source"] == "offline-fallback",
          "source=%s" % r4["source"])
    check("降级后仍能识别算法", r4["alg"] == "sm4", "alg=%s" % r4["alg"])

    # 5) 枚举收敛：非法值被丢弃
    bad = _normalize_result({"alg": "BOGUS", "mode": "weird", "encoding": "b64x"})
    check("非法枚举被归一化为 null/默认", bad["alg"] is None and bad["mode"] is None
          and bad["encoding"] == "base64")

    # 6) 知识库回路：学习 → 命中（用临时库，避免污染真实数据）
    if kb_mod is None:
        check("知识库模块可用", False, "crypto_knowledge 导入失败")
    else:
        import tempfile as _tf
        _fd, _tmp = _tf.mkstemp(suffix=".json", prefix="ai_kb_selftest_")
        os.close(_fd)
        os.remove(_tmp)
        _old = os.environ.get("JIEJIEEAD_KB_PATH")
        os.environ["JIEJIEEAD_KB_PATH"] = _tmp
        try:
            kb_mod.learn(sample, offline_analyze(sample), source="manual")
            check("学习后库中有 1 条", kb_mod.stats()["entries"] == 1)
            r_hit = analyze(sample, cfg_off)  # 同内容再分析，应命中知识库
            check("同逻辑再次分析命中知识库", r_hit["source"] == "learned",
                  "source=%s" % r_hit["source"])
            check("命中结果复用密钥", r_hit["key"] == "0123456789abcdeffedcba9876543210")
            # 变体（不同排版/大小写）也应命中同一签名
            variant = sample.replace(" ", "").replace("sm4", "SM4")
            r_var = analyze(variant, cfg_off)
            check("排版/大小写变体仍命中", r_var["source"] == "learned",
                  "source=%s" % r_var["source"])
            # --no-learn 时必须绕过知识库
            r_off = analyze(sample, cfg_off, use_kb=False)
            check("use_kb=False 时绕过知识库", r_off["source"] == "offline",
                  "source=%s" % r_off["source"])
            check("知识库命中计数已累加", kb_mod.stats()["total_hits"] >= 1)
        finally:
            if _old is None:
                os.environ.pop("JIEJIEEAD_KB_PATH", None)
            else:
                os.environ["JIEJIEEAD_KB_PATH"] = _old
            for _p in (_tmp, _tmp + ".tmp"):
                if os.path.isfile(_p):
                    os.remove(_p)

    # 7) 文件级分析：文件 → 证据包 → （离线/在线）文件级结论
    # 【重要】本段会调用 analyze()，可能触发自动学习写入知识库。
    # 必须把知识库指向临时文件，否则每次跑自检都会污染用户真实知识库（真实踩过的坑）。
    _fd2, _tmpdir_file = tempfile.mkstemp(suffix=".js", prefix="ai_file_selftest_")
    os.close(_fd2)
    _fd2b, _tmpkb7 = tempfile.mkstemp(suffix=".json", prefix="ai_kb_selftest7_")
    os.close(_fd2b)
    os.remove(_tmpkb7)
    _old_kb7 = os.environ.get("JIEJIEEAD_KB_PATH")
    os.environ["JIEJIEEAD_KB_PATH"] = _tmpkb7
    try:
        # 造一个「大文件」：真正关心的加密逻辑 + 大量无关代码，验证证据抽取能否命中
        filler = "\n".join("function util%d(a,b){ return a*%d + b; }" % (i, i)
                           for i in range(120))
        # 多段彼此分散的加密逻辑：既验证「埋得深也能挖出来」，也验证「多处证据能被切分装箱」
        regions = []
        for i in range(10):
            regions.append(
                "// ---- 业务模块 {0} 的加解密 ----\n"
                "var iv{0} = '{1:032x}';\n"
                "var appKey{0} = 'app-secret-{0}-0123456789abcdef';\n"
                "function send{0}(payload){{\n"
                "  return CryptoJS.AES.encrypt(JSON.stringify(payload), appKey{0},\n"
                "    {{ mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7, iv: iv{0} }});\n"
                "}}\n".format(i, i)
            )
        body = (
            filler + "\n"
            "// ===== 核心加密逻辑（埋在大量无关代码之后）=====\n"
            "function enc(data){\n"
            "  var SM4_KEY = '0123456789abcdeffedcba9876543210';\n"
            "  return sm4.encrypt(data, SM4_KEY, {mode:'cbc', padding:'Pkcs7', iv:'00112233445566778899aabbccddeeff'});\n"
            "}\n"
            # 每段加密逻辑之间夹大量无关代码，确保它们在文件里彼此远离，
            # 从而形成多个独立证据窗口（而不是被上下文合并成一个）
            + "\n".join(r + filler + "\n" for r in regions)
            + filler + "\n"
        )
        with open(_tmpdir_file, "w", encoding="utf-8") as fh:
            fh.write(body)

        ctx = build_file_context(_tmpdir_file)
        st = ctx["stats"]
        check("文件证据包：抽取到多段证据窗口", st["windows"] >= 5, "windows=%d" % st["windows"])
        check("文件证据包：判定为文本型", st["mode"] == "text", "mode=%s" % st["mode"])
        check("文件证据包：命中埋藏的 SM4 逻辑",
              any("SM4_KEY" in c or "sm4.encrypt" in c for c in ctx["chunks"]),
              "chunks=%d" % st["chunks"])
        check("文件证据包：命中密钥字面量",
              any("0123456789abcdeffedcba9876543210" in c for c in ctx["chunks"]))
        check("文件证据包：每个片段不超过预算",
              all(len(c) <= DEFAULT_CONTEXT_CHARS + 2000 for c in ctx["chunks"]),
              "max=%d" % max(st["chunk_chars"]))

        # 相关度排序：包含密钥/加密调用的窗口必须排在前面
        wins = _extract_code_windows(body)
        check("证据窗口按相关度排序", wins[0]["score"] > wins[-1]["score"],
              "top=%d last=%d 窗口数=%d" % (wins[0]["score"], wins[-1]["score"], len(wins)))
        check("最相关窗口排在最前（含密钥/加密调用）",
              "encrypt" in wins[0]["excerpt"].lower() or "key" in wins[0]["excerpt"].lower(),
              "kw=%s" % ",".join(wins[0]["kws"][:5]))

        # 小预算强制分片 + 投票合并
        packed = _pack_windows(wins, 900)
        check("小预算下证据被切成多片", len(packed) > 1, "chunks=%d" % len(packed))
        merged = _merge_chunk_results([
            {"status": "ok", "alg": "sm4", "mode": "cbc", "padding": "pkcs7",
             "key": "0123456789abcdeffedcba9876543210", "confidence": 0.9, "hints": ["a"]},
            {"status": "ok", "alg": "sm4", "mode": "cbc", "padding": "pkcs7",
             "key": None, "confidence": 0.8, "hints": ["b"]},
            {"status": "ok", "alg": "aes256", "mode": "ecb", "padding": "zero",
             "key": None, "confidence": 0.3, "hints": ["c"]},
        ], chunks_total=3, used=3)
        check("分片结论投票取多数（alg=sm4）", merged["alg"] == "sm4",
              "alg=%s conf=%s" % (merged["alg"], merged["confidence"]))
        check("投票合并后密钥来自最可信且同方案的分片",
              merged["key"] == "0123456789abcdeffedcba9876543210")
        check("存在分歧时给出告警",
              any("分歧" in w for w in merged["warnings"]),
              "warnings=%d" % len(merged["warnings"]))

        # 部分片段失败：失败原因必须保留，且结论要标明是降级结果
        merged_partial = _merge_chunk_results([
            {"status": "ok", "alg": "aes256", "mode": "cbc", "padding": "pkcs7",
             "key": "ff" * 32, "confidence": 0.7, "hints": ["x"]},
            {"status": "error", "source": "online", "alg": None, "confidence": 0.0,
             "warnings": ["片段 2 调用失败：HTTP 500"]},
        ], chunks_total=2, used=2)
        check("部分片段失败时保留失败原因",
              any("片段 2 调用失败" in w for w in merged_partial["warnings"]),
              "warnings=%d" % len(merged_partial["warnings"]))
        check("部分片段失败时标注为降级结论",
              "仅 1/2" in (merged_partial.get("note") or ""),
              "note=%s" % merged_partial.get("note"))
        check("部分片段失败时不丢失成功片段的结论",
              merged_partial["alg"] == "aes256" and merged_partial["key"] == "ff" * 32)

        # 文件级 analyze：无在线配置 → 离线，但必须仍然给出 alg
        r_file = analyze(body, cfg_off, file_path=_tmpdir_file, learn_online=False)
        check("文件级分析（离线）识别出 SM4", r_file["alg"] == "sm4", "alg=%s" % r_file["alg"])
        check("文件级分析带上证据包统计",
              bool(r_file.get("file_stats")),
              "stats=%s" % ("有" if r_file.get("file_stats") else "无"))

        # 二进制文件：不能崩，且应走字符串常量池路径
        _fd3, _tmpbin = tempfile.mkstemp(suffix=".bin", prefix="ai_bin_selftest_")
        os.close(_fd3)
        with open(_tmpbin, "wb") as fh:
            fh.write(bytes(range(256)) * 64 + b"aes_key=00112233445566778899aabbccddeeff")
        try:
            ctx_bin = build_file_context(_tmpbin)
            check("二进制文件证据包不崩溃", ctx_bin["stats"]["chunks"] >= 1)
            check("二进制文件走字符串常量池路径",
                  ctx_bin["stats"]["mode"] in ("binary", "text"),
                  "mode=%s" % ctx_bin["stats"]["mode"])
        finally:
            for _p in (_tmpbin,):
                if os.path.isfile(_p):
                    os.remove(_p)

        # 压缩包（APK 场景）：证据必须来自「包内条目」，而不是整包 Deflate 字节流
        import zipfile as _zf
        _fd4, _tmpzip = tempfile.mkstemp(suffix=".apk", prefix="ai_zip_selftest_")
        os.close(_fd4)
        with _zf.ZipFile(_tmpzip, "w", _zf.ZIP_DEFLATED) as _z:
            _z.writestr("assets/app.js",
                        "var K='aBcDeFgHiJkLmNoPqRsTuVwXyZ012345';\n"
                        "var IV='112233445566778899aabbccddeeff00';\n"
                        "function f(d){ return CryptoJS.AES.encrypt(d, K, "
                        "{iv: IV, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7}); }\n")
            _z.writestr("classes.dex",
                        b"dex\n035\x00" + bytes(range(256)) * 8 +
                        b"Lcom/example/Helper;sm4_encrypt_sm4_key_0123456789abcdeffedcba9876543210")
            _z.writestr("res/raw/config.json", '{"cipher":"AES/CBC/PKCS5Padding"}')
        try:
            ctx_zip = build_file_context(_tmpzip, deep=True)
            stz = ctx_zip["stats"]
            check("压缩包证据来自包内条目", stz["mode"] == "archive", "mode=%s" % stz["mode"])
            check("压缩包证据窗口不为 0（关键：整包抽关键词是抽不到的）",
                  stz["windows"] > 0, "windows=%d" % stz["windows"])
            check("压缩包条目已展开并记录",
                  len(stz.get("entries") or []) >= 3,
                  "entries=%d" % len(stz.get("entries") or []))
            check("证据文本包含包内 AES 调用",
                  any("CryptoJS.AES.encrypt" in c for c in ctx_zip["chunks"]))
            check("二进制条目走字符串常量池（含 dex 里的 SM4 串）",
                  any("sm4_encrypt" in c or "sm4" in c.lower() for c in ctx_zip["chunks"]),
                  "hints=%s" % ",".join(stz.get("algos") or []))

            # ---- 回归：文件模式下「真正送给 LLM 的内容」必须是证据包，不能是整份文件 ----
            # 曾经的真实 bug：analyze() 把整个 file_ctx 传给 online_analyze()，
            # 而后者只认 file_ctx["evidence"] → 静默退回文本分支 → 把整份文件的
            # errors="replace" 乱码发给模型 → 二进制/APK 永远得到「未发现加密方案」。
            captured: dict[str, Any] = {}
            _orig_online = online_analyze

            def _fake_online(_text, _cfg, file_ctx=None, step=None, pct=70):  # noqa: ANN001
                captured["text"] = _text
                captured["evidence"] = (file_ctx or {}).get("evidence") or ""
                if step:
                    step(pct, "（自检桩）调用在线 LLM")
                return _normalize_result({
                    "status": "ok", "source": "online", "alg": "sm4",
                    "confidence": 0.9, "hints": [], "warnings": [],
                })

            globals()["online_analyze"] = _fake_online
            try:
                cfg_fake = AIConfig(enabled=True, base_url="http://127.0.0.1:1/v1",
                                    api_key="k", model="m")
                _before_kb = kb_mod.stats()["entries"] if kb_mod is not None else 0
                analyze(body, cfg_fake, use_kb=False, file_path=_tmpdir_file)
                if kb_mod is not None:
                    check("use_kb=False（--no-learn）不会写入知识库",
                          kb_mod.stats()["entries"] == _before_kb,
                          "entries %d -> %d" % (_before_kb, kb_mod.stats()["entries"]))
                ev_text = captured.get("evidence") or ""
                check("文本文件：送给 LLM 的是证据包而非整份文件",
                      bool(ev_text) and "SM4_KEY" in ev_text,
                      "evidence=%d 字符" % len(ev_text))
                check("文本文件：证据包远小于整份文件（窗口抽取生效）",
                      bool(ev_text) and len(ev_text) < len(body) * 0.4,
                      "evidence=%d 字符 / 文件=%d 字符" % (len(ev_text), len(body)))

                analyze(b"PK\x03\x04 fake", cfg_fake, use_kb=False, file_path=_tmpzip)
                ev_zip = captured.get("evidence") or ""
                check("压缩包：送给 LLM 的是包内条目证据而非整包乱码",
                      "CryptoJS.AES.encrypt" in ev_zip,
                      "evidence=%d 字符" % len(ev_zip))
                check("压缩包：证据包不含 ZIP 本地文件头乱码",
                      "PK\x03\x04" not in ev_zip)
            finally:
                globals()["online_analyze"] = _orig_online
        finally:
            if os.path.isfile(_tmpzip):
                os.remove(_tmpzip)
    finally:
        # 恢复知识库路径并清理临时文件，确保自检对用户真实数据零副作用
        if _old_kb7 is None:
            os.environ.pop("JIEJIEEAD_KB_PATH", None)
        else:
            os.environ["JIEJIEEAD_KB_PATH"] = _old_kb7
        for _p in (_tmpdir_file, _tmpkb7, _tmpkb7 + ".tmp"):
            if os.path.isfile(_p):
                os.remove(_p)

    # ---- 8) 在线网络层：超时分层 / 重试 / 错误分类（不碰真实网络，全用桩） ----
    print("[8] 在线网络层（超时分层 / 重试 / 错误分类）")

    # 8.1 URL 拆分
    sch, host, port, path = _split_endpoint("https://api.deepseek.com/v1/chat/completions")
    check("URL 拆分正确（https 默认端口/路径）",
          (sch, host, port, path) == ("https", "api.deepseek.com", None, "/v1/chat/completions"),
          "%s %s %s %s" % (sch, host, port, path))
    sch2, host2, _, path2 = _split_endpoint("http://127.0.0.1:11434/v1/chat/completions")
    check("URL 拆分保留显式端口", (host2, path2) == ("127.0.0.1", "/v1/chat/completions"),
          "%s %s" % (host2, path2))

    # 8.2 endpoint 拼接
    check("endpoint：裸域名补 /v1/chat/completions",
          _endpoint_url("https://a.com") == "https://a.com/v1/chat/completions")
    check("endpoint：已带 /v1 不重复追加",
          _endpoint_url("https://a.com/v1") == "https://a.com/v1/chat/completions")
    check("endpoint：已带完整路径则原样返回",
          _endpoint_url("https://a.com/v1/chat/completions") == "https://a.com/v1/chat/completions")

    # 8.3 HTTP 状态码分类（可重试性必须正确，否则要么白等要么不重试）
    for code, exp_kind, exp_retry in ((401, "auth", False), (402, "billing", False),
                                      (403, "auth", False), (404, "notfound", False),
                                      (422, "invalid", False), (429, "ratelimit", True),
                                      (500, "server", True), (503, "server", True)):
        e = _classify_http_status(code, "detail")
        check("HTTP %d → %s（retry=%s）" % (code, exp_kind, exp_retry),
              e.kind == exp_kind and e.retryable == exp_retry, "%s/%s" % (e.kind, e.retryable))

    # 8.4 读超时被识别为「可重试的 timeout」而非笼统失败
    e_to = _classify_transfer_error(socket.timeout("timed out"), 120)
    check("读超时 → kind=timeout 且可重试", e_to.kind == "timeout" and e_to.retryable,
          "%s/%s" % (e_to.kind, e_to.retryable))
    check("读超时提示里带上当前超时秒数（便于用户调大）", "120" in str(e_to))

    # 8.5 连接阶段错误分类
    e_dns = _classify_connect_error(socket.gaierror("nope"), 15, "bad.host", None)
    check("域名解析失败 → kind=dns 且不可重试", e_dns.kind == "dns" and not e_dns.retryable)
    e_ref = _classify_connect_error(ConnectionRefusedError("refused"), 15, "127.0.0.1", 11434)
    check("连接被拒 → kind=refused 且可重试", e_ref.kind == "refused" and e_ref.retryable)
    e_ct = _classify_connect_error(socket.timeout("t"), 15, "a.com", None)
    check("建连超时 → kind=connect-timeout 且可重试",
          e_ct.kind == "connect-timeout" and e_ct.retryable)

    # 8.6 重试次数：可重试错误按 max_retries 重试；不可重试错误立即抛出
    _real_post = globals().get("_http_post_json")
    try:
        cfg_r = AIConfig(enabled=True, base_url="http://x/v1", api_key="k",
                         model="m", timeout=5, connect_timeout=2, max_retries=2)
        n_retry = {"n": 0}

        def _always_timeout(*_a, **_k):  # noqa: ANN001
            n_retry["n"] += 1
            raise LLMError("读超时（5s）", True, "timeout")

        globals()["_http_post_json"] = _always_timeout
        _raised = None
        try:
            online_analyze("x", cfg_r)
        except Exception as exc:  # noqa: BLE001
            _raised = exc
        check("可重试错误：共调用 1+max_retries 次后抛出", n_retry["n"] == 3,
              "调用 %d 次（期望 3）" % n_retry["n"])
        check("重试耗尽后抛出原始可读原因", _raised is not None and "读超时" in str(_raised))

        n_auth = {"n": 0}

        def _always_auth(*_a, **_k):  # noqa: ANN001
            n_auth["n"] += 1
            raise LLMError("鉴权失败（HTTP 401）", False, "auth")

        globals()["_http_post_json"] = _always_auth
        try:
            online_analyze("x", cfg_r)
        except Exception:  # noqa: BLE001
            pass
        check("不可重试错误（401）：只调用 1 次，不浪费重试", n_auth["n"] == 1,
              "调用 %d 次（期望 1）" % n_auth["n"])

        # 8.7 首次失败、第二次成功 → 重试确实救回来了
        n_flaky = {"n": 0}

        def _flaky(*_a, **_k):  # noqa: ANN001
            n_flaky["n"] += 1
            if n_flaky["n"] < 3:
                raise LLMError("读超时（5s）", True, "timeout")
            return json.dumps({"choices": [{"message": {"content": '{"alg":"sm4","mode":"cbc"}'}}]})

        globals()["_http_post_json"] = _flaky
        got = online_analyze("x", cfg_r)
        check("瞬时失败后重试可恢复（第 3 次成功）", n_flaky["n"] == 3 and got.get("alg") == "sm4",
              "调用 %d 次 alg=%s" % (n_flaky["n"], got.get("alg")))

        # 8.8 长等待心跳（避免 GUI 看似卡死）
        _hb_events: list[str] = []
        _saved_sleep = time.sleep

        def _hb_stub(*_a, **_k):  # noqa: ANN001
            _saved_sleep(0.35)  # 换取一次心跳（把 interval 调小后）
            return json.dumps({"choices": [{"message": {"content": '{"alg":"des"}'}}]})

        globals()["_http_post_json"] = _hb_stub
        _orig_hb_interval = _Heartbeat.__init__

        def _fast_hb(self, step, pct, label="", interval=5.0):  # noqa: ANN001
            _orig_hb_interval(self, step, pct, label, 0.1)

        _Heartbeat.__init__ = _fast_hb
        try:
            online_analyze("x", cfg_r, step=lambda p, t: _hb_events.append(t))
        finally:
            _Heartbeat.__init__ = _orig_hb_interval
        check("长等待期间播报心跳（含已等待秒数）",
              any("等待模型响应" in t for t in _hb_events),
              "心跳 %d 条" % len([t for t in _hb_events if "等待模型响应" in t]))

        # 8.9 模型返回空 content（推理模型把预算花在 reasoning 上）→ 明确报错而非崩
        globals()["_http_post_json"] = lambda *_a, **_k: json.dumps(
            {"choices": [{"message": {"content": "", "reasoning_content": "想了很久"},
                          "finish_reason": "length"}]})
        _empty_err = None
        try:
            online_analyze("x", cfg_r)
        except Exception as exc:  # noqa: BLE001
            _empty_err = str(exc)
        check("空 content 时给出可读报错（提示推理模型/预算）",
              bool(_empty_err) and "推理" in _empty_err and "finish_reason=length" in _empty_err,
              (_empty_err or "")[:70])

        # 8.10 模型夹带解释文字时，能截取 JSON 主体
        globals()["_http_post_json"] = lambda *_a, **_k: json.dumps(
            {"choices": [{"message": {"content":
                          '好的，结论如下：\n{"alg":"aes256","mode":"gcm"}\n以上。'}}]})
        got2 = online_analyze("x", cfg_r)
        check("模型输出夹带说明文字时能提取 JSON 主体", got2.get("alg") == "aes256",
              "alg=%s" % got2.get("alg"))

        # 8.11 适配推理模型的响应（content 正常时 reasoning_content 不影响）
        globals()["_http_post_json"] = lambda *_a, **_k: json.dumps(
            {"choices": [{"message": {"content": '{"alg":"sm4"}',
                                      "reasoning_content": "思考中"}}]})
        got3 = online_analyze("x", cfg_r)
        check("带 reasoning_content 的正常响应可解析", got3.get("alg") == "sm4")
    finally:
        if _real_post is not None:
            globals()["_http_post_json"] = _real_post

    # 8.12 test_llm 的配置缺失分支（不发真实请求）
    r_nocfg = test_llm(AIConfig(enabled=True, base_url="", api_key=""))
    check("test_llm：缺 Base URL → kind=config",
          r_nocfg["ok"] is False and r_nocfg["kind"] == "config")
    r_nokey = test_llm(AIConfig(enabled=True, base_url="https://a.com", api_key=""))
    check("test_llm：缺 API Key → kind=config 且提示补 Key",
          r_nokey["ok"] is False and "API Key" in r_nokey["error"])

    # 8.13 每个错误类别都有排查建议（否则用户拿到错误也不知道怎么办）
    _all_kinds = ["timeout", "connect-timeout", "dns", "refused", "reset", "auth",
                  "billing", "notfound", "invalid", "ratelimit", "server", "tls",
                  "parse", "config", "unknown-kind"]
    _missing = [k for k in _all_kinds if not _remediation(k)]
    check("所有错误类别都有排查建议", not _missing, "缺失=%s" % _missing)

    print("-" * 64)
    if failures:
        print(" [FAIL] %d 项未通过。" % len(failures))
        return 2
    print(" [PASS] AI 分析自检全部通过（离线规则 + 在线降级均正常）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
