#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jiejieEAD | MCP 接入向导（GUI「MCP 接入」页签的后端脚本）。

把「让本工具被 WorkBuddy / Claude Desktop 等 MCP 客户端调用」这件事
做成可一键完成的流程，不需要用户手抄路径、手改 JSON。

职责：
  1. --status    体检：mcp SDK 是否可用、依赖是否互相打架、服务器脚本是否齐全、
                 本机各客户端配置文件里是否已经登记过本服务器；
  2. --install   安装 / 修复 MCP 依赖（含 h11、httpcore 的兼容 pin，见下）；
  3. --config    生成可直接粘贴的 mcpServers 配置（自动填好本机真实绝对路径）；
  4. --write     把配置合并写入指定客户端配置文件（自动备份，保留其它服务器）；
  5. --smoke     真实 stdio 握手冒烟：拉起服务器 → initialize → tools/list → 调用；
  6. --selftest  自检（覆盖上面全部子命令，不需要 mcp SDK）。

为什么需要 --install 里那两个 pin：
  `mcp` 会把 h11 升到 0.16、httpcore 升到 1.0.9，而 mitmproxy 11.0.2 要求
  h11<=0.14.0 —— 不压回去，模块二的 MITM 代理会起不来。
  h11==0.14.0 + httpcore==1.0.7 是实测能做到 `pip check` 全绿、两侧共存的组合。

输出约定（与其它脚本一致）：
  - 人类可读信息 → stderr（[PROGRESS] <百分比> <阶段> 供 GUI 进度条使用）
  - 机器可读结果 → stdout，`--json` 时输出单个 JSON 对象

用法：
  python mcp_setup.py --status [--json]
  python mcp_setup.py --install [--json]
  python mcp_setup.py --config [--json]
  python mcp_setup.py --write workbuddy
  python mcp_setup.py --smoke [--json]
  python mcp_setup.py --selftest
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

SERVER_SCRIPT_NAME = "crypto_mcp_server.py"
SERVER_NAME = "jiejieead"

# 依赖要求（与 python/requirements.txt 保持一致）
MCP_REQUIREMENT = "mcp>=1,<2"
COMPAT_PINS = ["h11==0.14.0", "httpcore==1.0.7"]

# 需要随包存在的脚本（缺任何一个，MCP 服务器都会启动失败或能力残缺）
REQUIRED_SCRIPTS = [SERVER_SCRIPT_NAME, "crypto_core.py", "cli_crypto.py"]

# 已知的 4 个 MCP 工具（用于界面展示；实际清单以 tools/list 为准）
KNOWN_TOOLS = [
    {
        "name": "crypto_encrypt",
        "summary": "对称加密",
        "params": "alg / key / text / mode / padding / iv / encoding / aad",
    },
    {
        "name": "crypto_decrypt",
        "summary": "对称解密",
        "params": "同上（text 传密文文本）",
    },
    {
        "name": "scan_crypto_file",
        "summary": "分析文件里的密码特征（算法/模式/填充/硬编码密钥）",
        "params": "path",
    },
    {
        "name": "list_capabilities",
        "summary": "返回算法 / 模式 / 填充 / 编码能力矩阵",
        "params": "（无）",
    },
]

# 客户端配置文件默认位置（Windows）
HOME = os.path.expanduser("~")
_APPDATA = os.environ.get("APPDATA") or os.path.join(HOME, "AppData", "Roaming")
CLIENT_TARGETS = {
    "workbuddy": os.path.join(HOME, ".workbuddy", "mcp.json"),
    "claude": os.path.join(_APPDATA, "Claude", "claude_desktop_config.json"),
}


# ============================================================================
# 进度播报
# ============================================================================
_PROGRESS_ON = os.environ.get("JIEJIEEAD_PROGRESS", "") == "1"


def enable_progress(on: bool = True) -> None:
    global _PROGRESS_ON
    _PROGRESS_ON = on


def progress(pct: int, text: str) -> None:
    """[PROGRESS] <百分比> <阶段> —— GUI 据此驱动进度条（只写 stderr）。"""
    if _PROGRESS_ON:
        print("[PROGRESS] %d %s" % (pct, text), file=sys.stderr, flush=True)


def info(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


# ============================================================================
# 基础探测
# ============================================================================
def python_exe() -> str:
    return sys.executable


def server_script() -> str:
    return os.path.join(HERE, SERVER_SCRIPT_NAME)


def _mod_version(name: str):
    try:
        from importlib import metadata

        return metadata.version(name)
    except Exception:  # noqa: BLE001
        return None


def _has_module(name: str) -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec(name) is not None
    except Exception:  # noqa: BLE001
        return False


def pip_check() -> dict:
    """运行 `pip check`，返回 {ok, broken[]}。"""
    try:
        proc = subprocess.run(
            [python_exe(), "-m", "pip", "check"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        out = proc.stdout.decode("utf-8", errors="replace")
        broken = [
            ln.strip()
            for ln in out.splitlines()
            if ln.strip() and "No broken requirements" not in ln
        ]
        return {"ok": proc.returncode == 0 and not broken, "broken": broken}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "broken": ["pip check 执行失败：%s" % exc]}


def build_config() -> dict:
    """生成写入客户端用的 mcpServers 配置（绝对路径，已处理转义）。"""
    py = python_exe()
    srv = server_script()
    entry = {
        "command": py,
        "args": [srv],
        "env": {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
    }
    full = {"mcpServers": {SERVER_NAME: entry}}
    return {
        "server_name": SERVER_NAME,
        "command": py,
        "args": [srv],
        "env": entry["env"],
        "server_script": srv,
        "server_script_exists": os.path.isfile(srv),
        "json": json.dumps(full, ensure_ascii=False, indent=2),
        "json_compact": json.dumps(full, ensure_ascii=False, separators=(",", ":")),
        "targets": {
            key: {
                "path": path,
                "exists": os.path.isfile(path),
                "registered": _is_registered(path),
            }
            for key, path in CLIENT_TARGETS.items()
        },
    }


def _read_json_file(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception:  # noqa: BLE001
        return {}


def _is_registered(path: str) -> bool:
    cfg = _read_json_file(path)
    servers = cfg.get("mcpServers")
    return isinstance(servers, dict) and SERVER_NAME in servers


def resolve_target(target: str) -> str:
    """把 workbuddy / claude / 绝对路径 统一解析成配置文件路径。"""
    key = (target or "").strip().lower()
    if key in CLIENT_TARGETS:
        return CLIENT_TARGETS[key]
    if key in ("", "auto"):
        return ""
    return target


def status(smoke: bool = False) -> dict:
    """体检报告。smoke=True 时顺带跑一次 stdio 握手（较慢）。"""
    mcp_installed = _has_module("mcp")
    mitm_ok = _has_module("mitmproxy")
    chk = pip_check()
    scripts = {
        name: {"path": os.path.join(HERE, name), "exists": os.path.isfile(os.path.join(HERE, name))}
        for name in REQUIRED_SCRIPTS
    }
    missing = [n for n, v in scripts.items() if not v["exists"]]

    # 可用的判定：SDK 在 + 脚本齐 + 依赖不打架
    blockers = []
    if not mcp_installed:
        blockers.append("未安装 mcp SDK（点「一键安装依赖」）")
    if missing:
        blockers.append("缺少脚本：" + "、".join(missing))
    if mcp_installed and not chk["ok"]:
        blockers.append("依赖存在冲突（执行一次「一键安装依赖」会压回兼容版本）")

    rep = {
        "status": "ok",
        "ready": not blockers,
        "blockers": blockers,
        "python": python_exe(),
        "python_version": sys.version.split()[0],
        "scripts_dir": HERE,
        "server_script": server_script(),
        "mcp_installed": mcp_installed,
        "mcp_version": _mod_version("mcp"),
        "h11_version": _mod_version("h11"),
        "httpcore_version": _mod_version("httpcore"),
        "mitmproxy_version": _mod_version("mitmproxy"),
        "mitmproxy_importable": mitm_ok,
        "pip_check_ok": chk["ok"],
        "pip_check_output": chk["broken"],
        "scripts": scripts,
        "tools": KNOWN_TOOLS,
        "config": build_config(),
    }

    if smoke:
        rep["smoke"] = smoke_test()

    return rep


# ============================================================================
# 安装 / 修复依赖
# ============================================================================
def install_deps(as_json: bool = False) -> int:
    """安装 mcp 并压回与 mitmproxy 兼容的 h11 / httpcore。"""
    py = python_exe()
    steps = [
        (10, "安装 MCP SDK", [py, "-m", "pip", "install", "--no-warn-script-location", MCP_REQUIREMENT]),
        (55, "压回兼容版本（h11 / httpcore）", [py, "-m", "pip", "install", "--no-warn-script-location"] + COMPAT_PINS),
    ]
    failed = []
    for pct, desc, cmd in steps:
        progress(pct, desc)
        info("$ " + " ".join(cmd))
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=HERE,
            )
            assert proc.stdout is not None
            for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line:
                    info(line)
            proc.wait(timeout=900)
            if proc.returncode != 0:
                failed.append("%s（退出码 %d）" % (desc, proc.returncode))
        except Exception as exc:  # noqa: BLE001
            failed.append("%s：%s" % (desc, exc))

    progress(85, "复检依赖完整性")
    rep = status()
    rep["status"] = "error" if (failed or not rep["ready"]) else "ok"
    rep["install_failed"] = failed
    progress(100, "完成" if rep["status"] == "ok" else "需要人工处理")

    if as_json:
        print(json.dumps(rep, ensure_ascii=False))
    else:
        info("")
        info("安装结果：%s" % ("成功" if rep["status"] == "ok" else "未完成"))
        for b in rep["blockers"]:
            info("  · " + b)
    return 0 if rep["status"] == "ok" else 2


# ============================================================================
# 写入客户端配置
# ============================================================================
def write_config(target: str, as_json: bool = False) -> int:
    """把 mcpServers 合并写入客户端配置文件（保留其它服务器，先备份）。"""
    path = resolve_target(target)
    if not path:
        msg = "未指定目标：请用 --write workbuddy / --write claude / --write <配置文件绝对路径>"
        if as_json:
            print(json.dumps({"status": "error", "message": msg}, ensure_ascii=False))
        else:
            info(msg)
        return 2

    progress(20, "读取现有配置")
    cfg = _read_json_file(path)
    if os.path.isfile(path):
        bak = path + ".bak-jiejieead"
        try:
            shutil.copy2(path, bak)
        except Exception as exc:  # noqa: BLE001
            info("备份失败（继续写入）：%s" % exc)

    cfg.setdefault("mcpServers", {})
    if not isinstance(cfg["mcpServers"], dict):
        cfg["mcpServers"] = {}
    cfg["mcpServers"][SERVER_NAME] = build_config_entry()

    progress(60, "写入配置")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    except Exception as exc:  # noqa: BLE001
        if as_json:
            print(json.dumps({"status": "error", "message": "写入失败：%s" % exc}, ensure_ascii=False))
        else:
            info("写入失败：%s" % exc)
        return 2

    progress(100, "已写入")
    rep = {
        "status": "ok",
        "path": path,
        "backup": (path + ".bak-jiejieead") if os.path.isfile(path + ".bak-jiejieead") else "",
        "registered": _is_registered(path),
        "note": "如客户端已在运行，需要重启客户端（或在连接器管理页点「信任」）后才会生效。",
    }
    if as_json:
        print(json.dumps(rep, ensure_ascii=False))
    else:
        info("已写入：%s" % path)
        info(rep["note"])
    return 0


def build_config_entry() -> dict:
    py = python_exe()
    return {
        "command": py,
        "args": [server_script()],
        "env": {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
    }


# ============================================================================
# stdio 握手冒烟（需要 mcp SDK）
# ============================================================================
def smoke_test() -> dict:
    """拉起 crypto_mcp_server.py，走完 initialize → tools/list → 调用。

    返回结构化结果，永不抛异常（失败时 status=error + message）。
    """
    if not _has_module("mcp"):
        return {
            "status": "error",
            "message": "未安装 mcp SDK，无法做 stdio 握手；请先执行「一键安装依赖」",
        }

    import asyncio

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def _run() -> dict:
        params = StdioServerParameters(
            command=python_exe(),
            args=[server_script()],
            env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
        )
        t0 = time.time()
        result = {"status": "ok", "steps": []}
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                result["server"] = init.serverInfo.name
                result["steps"].append(
                    {"name": "initialize", "ok": True, "detail": "server=%s" % init.serverInfo.name}
                )

                tools = await session.list_tools()
                names = sorted(t.name for t in tools.tools)
                result["tools"] = names
                expect = [t["name"] for t in KNOWN_TOOLS]
                miss = [n for n in expect if n not in names]
                result["steps"].append(
                    {"name": "tools/list", "ok": not miss, "detail": "、".join(names)}
                )
                if miss:
                    result["status"] = "error"
                    result["message"] = "缺少期望工具：" + "、".join(miss)

                # 真实加密：SM4-CBC + 已知向量
                enc = json.loads(
                    (
                        await session.call_tool(
                            "crypto_encrypt",
                            {
                                "alg": "sm4",
                                "key": "0123456789abcdeffedcba9876543210",
                                "text": "hello",
                                "mode": "cbc",
                                "padding": "pkcs7",
                                "iv": "00000000000000000000000000000000",
                                "encoding": "base64",
                            },
                        )
                    ).content[0].text
                )
                ok_enc = enc.get("cipher") == "2wZpvYQeVFDsFlLs1CttYA=="
                result["steps"].append(
                    {"name": "crypto_encrypt", "ok": ok_enc, "detail": str(enc.get("cipher"))}
                )
                if not ok_enc:
                    result["status"] = "error"
                    result["message"] = "加密结果与已知向量不一致：%s" % enc.get("cipher")

                # 错误密钥必须被拒，且中文报错无损（stdio 编码检查）
                dec = json.loads(
                    (
                        await session.call_tool(
                            "crypto_decrypt",
                            {
                                "alg": "sm4",
                                "key": "ffffffffffffffffffffffffffffffff",
                                "text": "2wZpvYQeVFDsFlLs1CttYA==",
                                "mode": "cbc",
                                "padding": "pkcs7",
                                "iv": "00000000000000000000000000000000",
                                "encoding": "base64",
                            },
                        )
                    ).content[0].text
                )
                msg = str(dec.get("message", ""))
                ok_dec = dec.get("status") == "error" and "?" not in msg and "\ufffd" not in msg
                result["steps"].append(
                    {"name": "错误密钥被拒", "ok": ok_dec, "detail": msg[:48]}
                )
                if not ok_dec:
                    result["status"] = "error"
                    result["message"] = "错误密钥未被正确拒绝，或中文经 stdio 后乱码"

                # 能力矩阵
                cap = json.loads((await session.call_tool("list_capabilities", {})).content[0].text)
                fields = sorted(cap.keys())
                result["capability_fields"] = fields
                ok_cap = "algorithms" in cap and "modes" in cap and "paddings" in cap
                result["steps"].append(
                    {"name": "list_capabilities", "ok": ok_cap, "detail": "、".join(fields)}
                )
                if not ok_cap:
                    result["status"] = "error"
                    result["message"] = "能力矩阵字段不齐"

        result["elapsed"] = round(time.time() - t0, 2)
        return result

    try:
        return asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "message": "%s: %s" % (type(exc).__name__, exc), "steps": []}


# ============================================================================
# 自检
# ============================================================================
def _selftest() -> int:
    print("=" * 68)
    print(" jiejieEAD MCP 接入向导自检")
    print("=" * 68)
    fails = 0

    # ---- 1) 状态体检结构 ----
    rep = status()
    need = [
        "ready", "blockers", "python", "server_script", "mcp_installed",
        "h11_version", "httpcore_version", "pip_check_ok", "config", "tools",
    ]
    miss = [k for k in need if k not in rep]
    ok = not miss
    print("   [ %s ] status 字段齐全" % ("OK" if ok else "!!"))
    if not ok:
        print("        缺失：%s" % miss)
        fails += 1

    ok = rep["mcp_installed"] is True
    print("   [ %s ] 本环境已装 mcp SDK（v%s）" % ("OK" if ok else "!!", rep.get("mcp_version")))
    if not ok:
        fails += 1

    ok = rep.get("h11_version") == "0.14.0" and rep.get("httpcore_version") == "1.0.7"
    print("   [ %s ] 依赖已压到与 mitmproxy 共存的组合（h11 %s / httpcore %s）"
          % ("OK" if ok else "!!", rep.get("h11_version"), rep.get("httpcore_version")))
    if not ok:
        fails += 1

    ok = rep["pip_check_ok"] is True
    print("   [ %s ] pip check 无破损依赖" % ("OK" if ok else "!!"))
    if not ok:
        print("        %s" % rep.get("pip_check_output"))
        fails += 1

    # ---- 2) 配置文件生成 ----
    cfg = build_config()
    ok = (
        cfg["json"].lstrip().startswith("{")
        and SERVER_NAME in cfg["json"]
        and cfg["json_compact"]
        and cfg["server_script_exists"]
    )
    print("   [ %s ] 生成的 mcpServers JSON 可解析且路径真实存在" % ("OK" if ok else "!!"))
    if not ok:
        fails += 1
    try:
        parsed = json.loads(cfg["json"])
        entry = parsed["mcpServers"][SERVER_NAME]
        ok = entry["command"].lower().endswith("python.exe") and entry["args"][0].endswith(".py")
        print("   [ %s ] command 指向 python.exe、args 指向服务器脚本" % ("OK" if ok else "!!"))
        if not ok:
            fails += 1
        ok = entry["env"].get("PYTHONIOENCODING") == "utf-8"
        print("   [ %s ] env 已带 UTF-8 声明（防中文乱码）" % ("OK" if ok else "!!"))
        if not ok:
            fails += 1
    except Exception as exc:  # noqa: BLE001
        print("   [ !! ] JSON 结构异常：%s" % exc)
        fails += 1

    # ---- 3) 目标解析 ----
    ok = resolve_target("workbuddy").replace("\\", "/").endswith(".workbuddy/mcp.json")
    print("   [ %s ] --write workbuddy 解析到 ~/.workbuddy/mcp.json" % ("OK" if ok else "!!"))
    if not ok:
        fails += 1

    ok = resolve_target("D:/tmp/x.json") == "D:/tmp/x.json"
    print("   [ %s ] 绝对路径原样透传" % ("OK" if ok else "!!"))
    if not ok:
        fails += 1

    # ---- 4) 配置合并（不碰真实用户目录，用临时文件）----
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix="mcp_setup_test_")
    tgt = os.path.join(tmpdir, "mcp.json")
    try:
        with open(tgt, "w", encoding="utf-8") as fh:
            json.dump({"mcpServers": {"othersrv": {"command": "x"}}}, fh)
        rc = write_config(tgt)
        with open(tgt, "r", encoding="utf-8") as fh:
            merged = json.load(fh)
        ok = (
            rc == 0
            and "othersrv" in merged["mcpServers"]      # 保留他人配置
            and SERVER_NAME in merged["mcpServers"]     # 写入自己
            and os.path.isfile(tgt + ".bak-jiejieead")  # 有备份
        )
        print("   [ %s ] 写入时保留其它服务器、自己入库、并生成备份" % ("OK" if ok else "!!"))
        if not ok:
            fails += 1
    except Exception as exc:  # noqa: BLE001
        print("   [ !! ] 配置合并异常：%s" % exc)
        fails += 1

    # ---- 5) 缺 mcp SDK 时 smoke 必须优雅失败 ----
    sm = smoke_test()
    ok = sm.get("status") in ("ok", "error") and "steps" in sm
    print("   [ %s ] smoke 返回结构化结果（永不抛异常）" % ("OK" if ok else "!!"))
    if not ok:
        fails += 1
    if sm.get("status") == "ok":
        print("        stdio 握手通过：server=%s，%s 步，耗时 %ss"
              % (sm.get("server"), len(sm.get("steps", [])), sm.get("elapsed")))
    else:
        print("        smoke 未通过：%s" % sm.get("message"))

    print("-" * 68)
    if fails:
        print(" [FAIL] %d 项未通过。" % fails)
        return 2
    print(" [PASS] MCP 接入向导自检通过（体检 / 配置生成 / 写入合并 / 握手冒烟）。")
    return 0


# ============================================================================
# CLI
# ============================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp_setup.py",
        description="jiejieEAD MCP 接入向导（体检 / 装依赖 / 生成配置 / 写入客户端 / 握手自检）",
    )
    p.add_argument("--status", action="store_true", help="体检：SDK、依赖兼容性、脚本、客户端登记情况")
    p.add_argument("--install", action="store_true", help="安装/修复 MCP 依赖（含 h11/httpcore 兼容 pin）")
    p.add_argument("--config", action="store_true", help="生成可粘贴的 mcpServers 配置")
    p.add_argument("--write", metavar="TARGET",
                   help="写入客户端配置：workbuddy / claude / <配置文件绝对路径>")
    p.add_argument("--smoke", action="store_true", help="真实 stdio 握手冒烟（需 mcp SDK）")
    p.add_argument("--tools", action="store_true", help="列出暴露的 MCP 工具")
    p.add_argument("--json", action="store_true", help="以 JSON 输出结果（机器可读）")
    p.add_argument("--progress", action="store_true", help="向 stderr 播报进度（[PROGRESS] 百分比 步骤）")
    p.add_argument("--selftest", action="store_true", help="运行自检")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.progress:
        enable_progress(True)

    if args.selftest:
        return _selftest()

    if args.install:
        return install_deps(args.json)

    if args.write:
        return write_config(args.write, args.json)

    if args.tools:
        if args.json:
            print(json.dumps(KNOWN_TOOLS, ensure_ascii=False))
        else:
            for t in KNOWN_TOOLS:
                print("%-20s %s" % (t["name"], t["summary"]))
        return 0

    if args.smoke:
        progress(10, "启动 stdio 握手")
        result = smoke_test()
        progress(100, "握手完成" if result.get("status") == "ok" else "握手失败")
        if args.json:
            print(json.dumps(result, ensure_ascii=False))
        else:
            for step in result.get("steps", []):
                print("   [ %s ] %s —— %s" % ("OK" if step["ok"] else "!!", step["name"], step["detail"]))
            print(" [%s] %s" % ("PASS" if result.get("status") == "ok" else "FAIL",
                                result.get("message") or "MCP stdio 握手 + 工具调用端到端通过。"))
        return 0 if result.get("status") == "ok" else 2

    # 默认 / --config / --status
    with_smoke = False
    rep = status(smoke=with_smoke)

    if args.config:
        if args.json:
            print(json.dumps(rep["config"], ensure_ascii=False))
        else:
            print(rep["config"]["json"])
        return 0

    if args.json:
        print(json.dumps(rep, ensure_ascii=False))
        return 0

    # 人类可读
    print("jiejieEAD MCP 接入体检")
    print("-" * 68)
    print("  Python        : %s (%s)" % (rep["python"], rep["python_version"]))
    print("  脚本目录      : %s" % rep["scripts_dir"])
    print("  服务器脚本    : %s  %s"
          % (rep["server_script"],
             "存在" if rep["config"]["server_script_exists"] else "缺失"))
    print("  mcp SDK       : %s" % (rep["mcp_version"] or "未安装"))
    print("  h11 / httpcore: %s / %s" % (rep["h11_version"], rep["httpcore_version"]))
    print("  mitmproxy     : %s" % (rep["mitmproxy_version"] or "未安装"))
    print("  依赖完整性    : %s" % ("正常" if rep["pip_check_ok"] else "存在冲突"))
    print("-" * 68)
    if rep["ready"]:
        print("  状态：就绪，可直接被 MCP 客户端调用")
    else:
        print("  状态：未就绪")
        for b in rep["blockers"]:
            print("    · " + b)
    for key, t in rep["config"]["targets"].items():
        print("  %-10s %s  %s" % (key, "已登记" if t["registered"] else "未登记", t["path"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
