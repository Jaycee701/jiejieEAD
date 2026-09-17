#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用 jiejieEAD 的一键解密（cipher_auto_solver）逐个跑「密文样本集」，并生成分析报告。

对每个样本：
    1. 读 cipher.txt 与 expect.json（标准答案）
    2. 调 auto_solve(密文, target_dir=样本目录)  —— 工具自己从 app.js 里挖材料
    3. 比对明文是否一致，记录工具给出的「解密逻辑 / 密文特征判定 / 依据 / 尝试次数」
    4. 汇总成 Markdown 报告

用法：
    python verify_cipher_samples.py --dir <样本集目录> [--report <报告路径>] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PY_DIR = os.path.normpath(os.path.join(HERE, "..", "python"))
for p in (PY_DIR, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import cipher_auto_solver as cas  # noqa: E402


def run_one(sample_dir: str) -> dict:
    name = os.path.basename(sample_dir)
    cipher_path = os.path.join(sample_dir, "cipher.txt")
    expect_path = os.path.join(sample_dir, "expect.json")
    with open(cipher_path, "r", encoding="utf-8") as fh:
        cipher = fh.read().strip()
    expect = {}
    if os.path.isfile(expect_path):
        with open(expect_path, "r", encoding="utf-8") as fh:
            expect = json.load(fh)

    t0 = time.time()
    res = cas.auto_solve(cipher, target_dir=sample_dir)
    dt = time.time() - t0

    plain = ((res.get("best") or {}).get("plain") or "")
    want = expect.get("plain", "")
    ok = res.get("status") == "ok" and plain.strip() == want.strip()
    return {
        "name": name,
        "status": res.get("status"),
        "ok": ok,
        "elapsed": round(dt, 2),
        "frame_label": (res.get("frame") or {}).get("label"),
        "frame_kind": (res.get("frame") or {}).get("kind"),
        "attempts": len(res.get("attempts") or []),
        "mac": (res.get("best") or {}).get("mac") or {"checked": False},
        "recipe": (res.get("best") or {}).get("recipe_name"),
        "key_hex": (res.get("best") or {}).get("key_hex"),
        "confidence": (res.get("best") or {}).get("confidence"),
        "decrypt_logic": res.get("decrypt_logic") or [],
        "evidence": (res.get("best") or {}).get("evidence") or [],
        "summary": res.get("summary"),
        "plain": plain,
        "expect": expect,
        "materials": res.get("materials") or {},
        "feature": _read_readme_field(sample_dir, "**密文特征**"),
        "idea": _read_readme_field(sample_dir, "**分析思路**"),
        "failed_attempts": [a for a in (res.get("attempts") or []) if not a.get("ok")][:3],
    }


def _read_readme_field(sample_dir: str, key: str) -> str:
    path = os.path.join(sample_dir, "README.md")
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip().startswith(key):
                    return line.split(key, 1)[1].strip(" *：:").strip()
    except OSError:
        pass
    return ""


def collect(root: str) -> list[dict]:
    dirs = sorted(d for d in os.listdir(root)
                  if os.path.isdir(os.path.join(root, d))
                  and os.path.isfile(os.path.join(root, d, "cipher.txt")))
    return [run_one(os.path.join(root, d)) for d in dirs]


def build_report(root: str, results: list[dict]) -> str:
    ok_n = sum(1 for r in results if r["ok"])
    lines: list[str] = []
    lines.append("# 密文样本集 · 分析与解密报告\n")
    lines.append("> 生成方式：用 jiejieEAD 的**一键解密**（`cipher_auto_solver.auto_solve`）逐个跑；"
                 "工具只拿到 `cipher.txt` 与样本目录（内含 `app.js` 目标源码片段，"
                 "信封样本还含 `server.js` 服务端解密片段），密钥材料全靠它自己从材料里挖。\n")
    lines.append("**样本目录**：`%s`\n" % os.path.abspath(root))
    lines.append("**总览**：共 %d 个样本，一键解密成功 **%d** 个（%.0f%%）。\n"
                 % (len(results), ok_n, 100.0 * ok_n / max(len(results), 1)))
    lines.append("\n## 一、覆盖矩阵\n")
    lines.append("| # | 样本 | 密文形态 | 算法/模式/填充 | 编码 | 密钥来源 | 结果 | 耗时 |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in results:
        e = r["expect"]
        if e.get("asym"):
            src = "非对称信封解封"
        elif e.get("seed"):
            src = "种子派生"
        elif e.get("key_hex") or e.get("key_b64") or e.get("key_bytes") or e.get("key_note"):
            src = "源码字面量"
        else:
            src = "—"
        alg = "/".join(x for x in [str(e.get("alg", "")).upper(),
                                   str(e.get("mode", "")).upper(),
                                   str(e.get("padding", "")).upper()] if x)
        if e.get("asym"):
            alg += "（%s 包裹密钥）" % e["asym"]
        enc = e.get("encoding", "")
        if e.get("encoding_chain"):
            enc = "+".join(e["encoding_chain"])
        if e.get("inner_compression"):
            enc += "（先 %s 压缩）" % e["inner_compression"]
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %ss |"
                     % (r["name"][:2], r["name"][3:], r["frame_kind"] or "—", alg, enc, src,
                        "✅ 成功" if r["ok"] else "❌ 未成功", r["elapsed"]))
    lines.append("")
    # ---- 覆盖度汇总：按算法 / 编码 / 形态 / 填充 / 非对称 分别统计 ----
    def _bucket(pick):
        b: dict[str, list[str]] = {}
        for r in results:
            k = pick(r["expect"])
            if not k:
                continue
            b.setdefault(k, []).append(r["name"][:2])
        return b

    def _fmt(b):
        return " · ".join("%s（%s）" % (k, "/".join(v)) for k, v in sorted(b.items()))

    def _enc_of(e):
        enc = e.get("encoding") or ""
        if e.get("encoding_chain"):
            enc = "+".join(e["encoding_chain"])
        if e.get("inner_compression"):
            enc += " + %s 压缩" % e["inner_compression"]
        return enc

    lines.append("\n### 1.1 覆盖度汇总\n")
    lines.append("| 维度 | 覆盖情况 |")
    lines.append("|---|---|")
    lines.append("| 分组算法 | %s |" % _fmt(_bucket(lambda e: str(e.get("alg", "")).upper())))
    lines.append("| 工作模式 | %s |" % _fmt(_bucket(lambda e: str(e.get("mode", "")).upper())))
    lines.append("| 填充方式 | %s |" % _fmt(_bucket(lambda e: str(e.get("padding", "")).upper())))
    lines.append("| 编码 / 压缩 | %s |" % _fmt(_bucket(_enc_of)))
    lines.append("| 报文形态 | %s |" % _fmt(_bucket(lambda e: e.get("framing", ""))))
    lines.append("| 非对称（信封） | %s |"
                 % (_fmt(_bucket(lambda e: e.get("asym", ""))) or "本批样本未覆盖"))
    lines.append("| mac 校验方式 | %s |"
                 % (_fmt(_bucket(lambda e: e.get("mac_algo", ""))) or "本批样本未覆盖"))
    lines.append("")

    lines.append("\n## 二、逐样本明细\n")
    for r in results:
        e = r["expect"]
        lines.append("### %s\n" % r["name"])
        lines.append("**① 密文特征**：%s\n" % (r["feature"] or "—"))
        if e:
            var = []
            if e.get("key_hex"):
                var.append("`key = %s`" % e["key_hex"])
            if e.get("key_b64"):
                var.append("`key(base64) = %s`" % e["key_b64"])
            if e.get("key_bytes"):
                var.append("`key = %d 字节`" % e["key_bytes"])
            if e.get("iv_hex"):
                var.append("`iv = %s`" % e["iv_hex"])
            if e.get("seed"):
                var.append("`seed = %s`" % e["seed"])
            if e.get("aad"):
                var.append("`aad = %s`" % e["aad"])
            if e.get("key_note"):
                var.append("派生：%s" % e["key_note"])
            if var:
                lines.append("**② 密钥/参数**：%s\n" % "；".join(var))
        lines.append("**③ 分析思路**：%s\n" % (r["idea"] or "—"))
        lines.append("**④ 工具实际执行的分析与解密过程**：\n")
        lines.append("```")
        lines.append("形态识别：%s" % r["frame_label"])
        if r["materials"].get("sources"):
            lines.append("材料来源：%s" % "；".join(r["materials"]["sources"]))
        for l in r["decrypt_logic"]:
            lines.append(l)
        lines.append("```")
        lines.append("**⑤ 结果**：%s\n" % ("✅ 解密成功" if r["ok"] else "❌ 未成功"))
        if r["ok"]:
            mac = r["mac"]
            if mac.get("checked"):
                lines.append("- mac 校验：**%s**（%s，覆盖 %s）"
                             % ("通过" if mac.get("ok") else "不通过", mac.get("algo"), mac.get("scope")))
            lines.append("- 可信度：%s；尝试方案数：%d" % (r["confidence"], r["attempts"]))
            lines.append("- 复算密钥：`%s`" % r.get("key_hex"))
            show = r["plain"] if len(r["plain"]) <= 300 else r["plain"][:300] + "…"
            lines.append("\n明文：\n\n```\n%s\n```\n" % show)
        else:
            lines.append("- 工具结论：%s" % r["summary"])
            for a in r["failed_attempts"]:
                lines.append("  - 尝试 %s → %s" % (a["recipe"], a["reason"][:80]))
            lines.append("")
        lines.append("---\n")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="校验密文样本集并生成报告")
    ap.add_argument("--dir", required=True, help="样本集目录")
    ap.add_argument("--report", help="报告输出路径（默认写到样本目录下）")
    ap.add_argument("--json", action="store_true", help="只输出 JSON 摘要")
    a = ap.parse_args(argv)
    root = os.path.abspath(a.dir)
    results = collect(root)
    if a.json:
        print(json.dumps([{k: v for k, v in r.items() if k not in ("decrypt_logic",)}
                          for r in results], ensure_ascii=False, indent=2))
        return 0
    for r in results:
        print("%s %-44s %s  %5.2fs  %d 套方案"
              % ("✅" if r["ok"] else "❌", r["name"], r["status"], r["elapsed"], r["attempts"]))
    ok_n = sum(1 for r in results if r["ok"])
    print("-" * 78)
    print("成功 %d / %d" % (ok_n, len(results)))
    report = build_report(root, results)
    out = a.report or os.path.join(root, "密文样本集-分析与解密报告.md")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(report)
    print("报告已写入：%s" % out)
    return 0 if ok_n == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
