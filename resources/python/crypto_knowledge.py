#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 jiejieEAD | 密码逻辑知识库（自动学习 / 命中复用）
 文件：crypto_knowledge.py
================================================================================

【解决的痛点】
    同一个项目/同一套前端库的加密逻辑，往往在多个文件、多轮测试里反复出现。
    每次都要重新分析一遍纯属浪费。本模块把「已确认正确的分析结论」沉淀成本地
    知识库，下次遇到**同一段逻辑**时直接命中，秒出 alg/mode/padding/key/iv，
    既快又保证历次结论一致。

【两级签名（关键设计）】
    1) content_sig（内容签名，精确命中）
       把输入文本做归一化（去 JS 注释、抹掉所有空白、转小写）后取 SHA-256 前 32 位。
       作用：同一段代码换个缩进/换行/大小写，仍能命中；不同代码不会误命中。
       —— 精确命中时可直接复用**完整结论（含密钥/IV）**。
    2) scheme_sig（方案签名，方案级提示）
       `alg|mode|padding|encoding`，例如 `sm4|ecb|zero|base64`。
       作用：内容不完全相同、但方案一致的场景，用于给分析结果加一条
       「该方案历史出现过 N 次」的旁证，而**不**直接套用旧密钥（避免张冠李戴）。

【可信度来源】
    - manual  ：用户在 GUI 点「学习此规则」或 CLI --learn，视为人工确认；
    - apply   ：用户点「一键填入工作台/MITM」，视为接受该结论；
    - online  ：在线 LLM 高置信（>=0.8）结果自动入库。
    离线启发式结果**不**自动入库（置信度不足），需人工确认。

【设计约束】
    - 零第三方依赖，仅标准库；
    - 写入原子化（先写 .tmp 再 os.replace），避免半截文件损坏知识库；
    - 路径优先脚本同目录（免安装版可写）；若不可写（如装在 Program Files），
      自动回退到 %LOCALAPPDATA%\\jiejieEAD\\，可用环境变量
      JIEJIEEAD_KB_PATH 强制指定。

【CLI 速览】（由 ai_crypto_analyzer.py 暴露）
    python ai_crypto_analyzer.py --learn --text "..." [--as-json '{...}']
    python ai_crypto_analyzer.py --kb-stats [--json]
    python ai_crypto_analyzer.py --kb-list [--json]
    python ai_crypto_analyzer.py --kb-clear
    python crypto_knowledge.py --selftest
================================================================================
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
# 被 Tauri 以绝对路径调用时，脚本目录未必在 sys.path 首位（嵌入式 Python 的 _pth
# 不会自动把脚本目录加入 sys.path），必须显式插入。与其它模块保持一致。
if HERE not in sys.path:
    sys.path.insert(0, HERE)

KB_VERSION = 1
KB_FILENAME = "crypto_knowledge.json"

# 归一化用正则
_RE_JS_BLOCK = re.compile(r"/\*.*?\*/", re.S)
_RE_JS_LINE = re.compile(r"//[^\n]*")
_RE_WS = re.compile(r"\s+")


# ============================================================================
# 路径解析
# ============================================================================
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


def kb_path() -> str:
    """知识库文件路径：环境变量 > 脚本目录（可写）> %LOCALAPPDATA%。"""
    env = os.environ.get("JIEJIEEAD_KB_PATH")
    if env:
        return env
    if _is_writable_dir(HERE):
        return os.path.join(HERE, KB_FILENAME)
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or tempfile.gettempdir()
    return os.path.join(base, "jiejieEAD", KB_FILENAME)


# ============================================================================
# 签名
# ============================================================================
def normalize_text(text: str) -> str:
    """去掉 JS 注释与全部空白并转小写，得到「排版无关」的归一化文本。"""
    t = text or ""
    t = _RE_JS_BLOCK.sub("", t)
    t = _RE_JS_LINE.sub("", t)
    t = _RE_WS.sub("", t)
    return t.lower()


def content_sig(text: str) -> str:
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()[:32]


def scheme_sig(result: dict[str, Any]) -> str:
    a = (result.get("alg") or "?").lower()
    m = (result.get("mode") or "?").lower()
    p = (result.get("padding") or "?").lower()
    e = (result.get("encoding") or "?").lower()
    return "%s|%s|%s|%s" % (a, m, p, e)


def _preview(text: str, limit: int = 160) -> str:
    return _RE_WS.sub(" ", (text or "").strip())[:limit]


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ============================================================================
# 读写
# ============================================================================
def empty_kb() -> dict[str, Any]:
    return {"version": KB_VERSION, "entries": {}, "schemes": {}}


def load_kb(path: str | None = None) -> dict[str, Any]:
    path = path or kb_path()
    if not os.path.isfile(path):
        return empty_kb()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            kb = json.load(fh)
        if not isinstance(kb, dict) or not isinstance(kb.get("entries"), dict):
            return empty_kb()
        kb.setdefault("version", KB_VERSION)
        kb.setdefault("schemes", {})
        return kb
    except Exception:  # noqa: BLE001 —— 损坏时按空库处理，绝不因知识库拖垮主流程
        return empty_kb()


def save_kb(kb: dict[str, Any], path: str | None = None) -> str:
    path = path or kb_path()
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(kb, fh, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return path


# ============================================================================
# 查询 / 学习
# ============================================================================
def lookup(text: str, kb: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    查库。返回：
      {"kind": "exact", "entry": {...}}   内容精确命中（可复用完整结论）
      {"kind": "scheme", "scheme": {...}} 仅方案层面有历史记录（旁证）
      {"kind": None, "entry": None}
    """
    kb = kb if kb is not None else load_kb()
    sig = content_sig(text)
    entry = kb["entries"].get(sig)
    if entry:
        return {"kind": "exact", "entry": entry, "scheme": None}
    return {"kind": None, "entry": None, "scheme": None}


def lookup_scheme(result: dict[str, Any], kb: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """按方案签名（alg|mode|padding|encoding）查历史出现记录。"""
    kb = kb if kb is not None else load_kb()
    return kb.get("schemes", {}).get(scheme_sig(result))


def learn(text: str, result: dict[str, Any], kb: dict[str, Any] | None = None,
          source: str = "manual", persist: bool = True, path: str | None = None) -> dict[str, Any]:
    """把一条确认结果写入知识库（同一内容重复学习则更新并保留命中计数）。"""
    kb = kb if kb is not None else load_kb(path)
    sig = content_sig(text)
    ssig = scheme_sig(result)
    now = _now()
    prev = kb["entries"].get(sig)

    entry = {
        "content_sig": sig,
        "scheme_sig": ssig,
        "alg": result.get("alg"),
        "mode": result.get("mode"),
        "padding": result.get("padding"),
        "key": result.get("key"),
        "iv": result.get("iv"),
        "encoding": result.get("encoding"),
        "confidence": float(result.get("confidence") or 1.0),
        "note": result.get("note", "") or "",
        "source": source,
        "input_len": len(text or ""),
        "input_preview": _preview(text),
        "hits": (prev.get("hits", 0) if prev else 0),
        "created_at": (prev.get("created_at") if prev else now),
        "updated_at": now,
    }
    kb["entries"][sig] = entry

    # 方案级统计
    count = sum(1 for x in kb["entries"].values() if x.get("scheme_sig") == ssig)
    kb.setdefault("schemes", {})[ssig] = {
        "count": count,
        "rule": result.get("note", "") or "",
        "alg": result.get("alg"),
        "mode": result.get("mode"),
        "padding": result.get("padding"),
        "encoding": result.get("encoding"),
        "updated_at": now,
    }

    if persist:
        save_kb(kb, path)
    return entry


def bump_hit(sig: str, kb: dict[str, Any] | None = None, path: str | None = None) -> dict[str, Any] | None:
    """命中计数 +1（用于统计「这条规则被复用了几次」）。"""
    kb = kb if kb is not None else load_kb(path)
    entry = kb["entries"].get(sig)
    if not entry:
        return None
    entry["hits"] = int(entry.get("hits", 0)) + 1
    entry["last_hit_at"] = _now()
    save_kb(kb, path)
    return entry


def stats(kb: dict[str, Any] | None = None) -> dict[str, Any]:
    kb = kb if kb is not None else load_kb()
    entries = kb.get("entries", {})
    total_hits = sum(int(e.get("hits", 0)) for e in entries.values())
    return {
        "path": kb_path(),
        "entries": len(entries),
        "schemes": len(kb.get("schemes", {})),
        "total_hits": total_hits,
        "version": kb.get("version", KB_VERSION),
    }


def list_entries(kb: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    kb = kb if kb is not None else load_kb()
    rows = list(kb.get("entries", {}).values())
    rows.sort(key=lambda e: e.get("updated_at", ""), reverse=True)
    return rows


def remove(sig: str, kb: dict[str, Any] | None = None, path: str | None = None) -> bool:
    kb = kb if kb is not None else load_kb(path)
    entry = kb.get("entries", {}).pop(sig, None)
    if entry:
        ssig = entry.get("scheme_sig")
        cnt = sum(1 for x in kb["entries"].values() if x.get("scheme_sig") == ssig)
        if cnt:
            kb.get("schemes", {}).get(ssig, {})["count"] = cnt
        else:
            kb.get("schemes", {}).pop(ssig, None)
        save_kb(kb, path)
        return True
    return False


def clear(kb: dict[str, Any] | None = None, path: str | None = None) -> str:
    return save_kb(empty_kb(), path)


# ============================================================================
# CLI（独立自检；日常入口在 ai_crypto_analyzer.py）
# ============================================================================
def _selftest() -> int:
    print("=" * 64)
    print(" jiejieEAD 密码逻辑知识库 自检")
    print("=" * 64)
    failures: list[str] = []

    def check(name, ok, detail=""):
        print("   [ %s ] %s%s" % ("OK" if ok else "!!", name, ("  —— " + detail) if detail else ""))
        if not ok:
            failures.append(name)

    # 用临时文件做隔离自检，绝不污染真实知识库
    fd, tmp = tempfile.mkstemp(suffix=".json", prefix="kb_selftest_")
    os.close(fd)
    os.remove(tmp)
    try:
        sample = ("var SM4_KEY = '0123456789abcdeffedcba9876543210';\n"
                  "var c = sm4.encrypt(data, SM4_KEY, {mode:'ecb', padding:'zero'});")
        # 同一逻辑、不同排版，必须算出同一签名
        sample_reflow = ("var   SM4_KEY='0123456789ABCDEFfedcba9876543210';  // key\n"
                         "var c=sm4.encrypt( data, SM4_KEY,\n"
                         "   { mode : 'ecb', padding : 'zero' } );")
        sig_a = content_sig(sample)
        sig_b = content_sig(sample_reflow)
        check("排版/大小写不同 → 内容签名一致", sig_a == sig_b)

        result = {"alg": "sm4", "mode": "ecb", "padding": "zero", "encoding": "base64",
                  "key": "0123456789abcdeffedcba9876543210", "iv": None,
                  "confidence": 1.0, "note": "SM4-ECB + ZERO"}

        kb = load_kb(tmp)
        check("空库初始为 0 条", len(kb["entries"]) == 0)

        learn(sample, result, kb=kb, path=tmp)
        check("学习后入库 1 条", len(kb["entries"]) == 1)

        # 重新从磁盘读，验证持久化
        kb2 = load_kb(tmp)
        hit = lookup(sample_reflow, kb=kb2)   # 用变体文本查同一签名
        check("命中已学习规则（精确）", hit["kind"] == "exact" and hit["entry"] is not None)
        check("命中结果复用密钥", bool(hit["entry"]) and hit["entry"]["key"] == result["key"])

        sch = lookup_scheme(result, kb=kb2)
        check("方案签名可查（sm4|ecb|zero|base64）",
              bool(sch) and scheme_sig(result) == "sm4|ecb|zero|base64")

        # 命中计数
        bump_hit(content_sig(sample), kb=kb2, path=tmp)
        kb3 = load_kb(tmp)
        check("命中计数可累加", kb3["entries"][content_sig(sample)]["hits"] == 1)

        st = stats(kb3)
        check("统计条目数正确", st["entries"] == 1)

        # 删除
        check("删除条目成功", remove(content_sig(sample), kb=kb3, path=tmp))
        check("删除后库为空", len(load_kb(tmp)["entries"]) == 0)
    finally:
        for p in (tmp, tmp + ".tmp"):
            if os.path.isfile(p):
                os.remove(p)

    print("-" * 64)
    if failures:
        print(" [FAIL] %d 项未通过。" % len(failures))
        return 2
    print(" [PASS] 知识库自检全部通过（签名稳定性 + 学习/命中/计数/删除）。")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="jiejieEAD 密码逻辑知识库")
    p.add_argument("--selftest", action="store_true", help="运行自检（使用临时库，不污染真实数据）")
    p.add_argument("--path", action="store_true", help="打印当前知识库文件路径")
    p.add_argument("--stats", action="store_true", help="打印统计信息")
    args = p.parse_args(argv)

    if args.selftest:
        return _selftest()
    if args.path:
        print(kb_path())
        return 0
    if args.stats:
        print(json.dumps(stats(), ensure_ascii=False, indent=2))
        return 0
    p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
