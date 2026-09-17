#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jiejieEAD MCP 服务器（stdio 传输，独立运行）。

把本工具的密码能力（加解密 / 文件扫描 / 能力矩阵）暴露为 MCP 工具，
供 WorkBuddy / Claude Desktop / 任意 MCP 客户端以「模型上下文协议」方式调用。

依赖（随包安装，见 requirements.txt）：
    pip install "mcp>=1,<2"
    pip install "h11==0.14.0" "httpcore==1.0.7"

    ⚠️ 第二行别省：mcp 会把 h11 升到 0.16、httpcore 升到 1.0.9，而 mitmproxy 11.0.2
    要求 h11<=0.14.0，pip 会报 dependency conflicts，模块二 MITM 会起不来。
    压成 h11 0.14.0 + httpcore 1.0.7 后 `pip check` 全绿，mcp 与 mitmproxy 两侧均可运行。

图形化入口：
    GUI「MCP 接入」页签（后端 mcp_setup.py）可一键体检 / 装依赖 / 生成并写入
    客户端配置 / 跑真实 stdio 握手，不需要手抄路径改 JSON。

典型接入（Claude Desktop / WorkBuddy 的 mcpServers 配置）：
    {
      "mcpServers": {
        "jiejieead": {
          "command": "C:\\\\path\\\\to\\\\python.exe",
          "args": ["C:\\\\path\\\\to\\\\jiejieEAD\\\\python\\\\crypto_mcp_server.py"],
          "env": { "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1" }
        }
      }
    }

说明：
  - 服务器通过 stdio 与客户端通信，不需要任何端口；
  - 所有密码运算复用 crypto_core.py，与 GUI / CLI 同源，结果一致；
  - scan_crypto_file 复用 file_crypto_scanner.py（静态分析，离线）；
  - 返回的 JSON 含中文（如「PKCS#7 去填充失败…」），故建议声明 UTF-8 环境变量。

用法：
  python crypto_mcp_server.py            # 以 MCP stdio 服务器启动
  python crypto_mcp_server.py --selftest # 自检底层能力（无需 mcp SDK）
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import crypto_core as cc  # noqa: E402


# ============================================================================
# 业务逻辑（与 MCP 解耦，便于 --selftest 直接复用）
# ============================================================================
def _do(op: str, alg: str, key: str, text: str, mode: str, padding: str,
        iv: str, encoding: str, aad: str) -> dict:
    """统一入口：调用密码引擎（返回 bytes），按 encoding 编解码为文本。

    返回 dict：{payload: <编码后的密文或明文文本>, integrity_checked: bool}
    """
    kw = dict(
        alg=alg,
        op=op,
        key_hex=key,
        iv_hex=iv or None,
        mode=mode or "cbc",
        padding=padding or "pkcs7",
        aad=aad.encode("utf-8") if aad else b"",
        warn_weak=False,
    )
    if op == "enc":
        out = cc.do_crypt(data=text.encode("utf-8"), **kw)
        payload = cc.encode_bytes(out, encoding)
    else:
        cipher_bytes = cc.decode_text(text, encoding)
        out = cc.do_crypt(data=cipher_bytes, **kw)
        payload = out.decode("utf-8", errors="replace")
    integrity = cc.has_integrity_check(kw["mode"], kw["padding"])
    return {"payload": payload, "integrity_checked": integrity}


def tool_encrypt(alg, key, text, mode="cbc", padding="pkcs7", iv="", encoding="base64", aad="") -> str:
    try:
        r = _do("enc", alg, key, text, mode, padding, iv, encoding, aad)
        return json.dumps({"status": "ok", "alg": alg, "mode": mode, "padding": padding,
                           "encoding": encoding, "cipher": r["payload"],
                           "cipher_len": len(r["payload"]),
                           "integrity_checked": r["integrity_checked"]},
                          ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"status": "error", "message": str(exc)}, ensure_ascii=False)


def tool_decrypt(alg, key, text, mode="cbc", padding="pkcs7", iv="", encoding="base64", aad="") -> str:
    try:
        r = _do("dec", alg, key, text, mode, padding, iv, encoding, aad)
        return json.dumps({"status": "ok", "alg": alg, "mode": mode, "padding": padding,
                           "encoding": encoding, "plain": r["payload"],
                           "plain_len": len(r["payload"]),
                           "integrity_checked": r["integrity_checked"]},
                          ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"status": "error", "message": str(exc)}, ensure_ascii=False)


def tool_scan(path: str) -> str:
    try:
        import file_crypto_scanner as fcs  # 延迟导入
        res = fcs.scan_file(path)
        return json.dumps(res, ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"status": "error", "message": str(exc)}, ensure_ascii=False)


def tool_capabilities() -> str:
    return json.dumps(cc.capability_matrix(), ensure_ascii=False)


# ============================================================================
# MCP 服务器装配（仅在 mcp SDK 可用时）
# ============================================================================
def build_server():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        sys.stderr.write(
            "缺少依赖 mcp。请在本机 Python 环境执行：pip install mcp\n"
            "（MCP 服务器为独立集成组件，不打包进离线 EXE。）\n"
        )
        sys.exit(1)

    mcp = FastMCP("jiejieEAD")

    @mcp.tool()
    def crypto_encrypt(alg: str, key: str, text: str, mode: str = "cbc",
                       padding: str = "pkcs7", iv: str = "", encoding: str = "base64",
                       aad: str = "") -> str:
        """对称加密。alg: sm4/aes128/aes192/aes256/des/des3/rc4/rc5/rc5_16/rc5_64/rc6/rc6_16/blowfish/cast5/rc2/chacha20/salsa20；
        mode: ecb/cbc/cfb/ofb/ctr/gcm；padding: pkcs7/zero/none/iso7816/ansix923；
        encoding: base64/hex/raw。返回 JSON（含 cipher）。"""
        return tool_encrypt(alg, key, text, mode, padding, iv, encoding, aad)

    @mcp.tool()
    def crypto_decrypt(alg: str, key: str, text: str, mode: str = "cbc",
                       padding: str = "pkcs7", iv: str = "", encoding: str = "base64",
                       aad: str = "") -> str:
        """对称解密。参数同 crypto_encrypt，text 为密文文本；返回 JSON（含 plain）。"""
        return tool_decrypt(alg, key, text, mode, padding, iv, encoding, aad)

    @mcp.tool()
    def scan_crypto_file(path: str) -> str:
        """分析文件里的密码特征：识别算法/模式/填充、提取硬编码密钥、输出可回填配置。
        返回结构化的 JSON（含 logic.apply_crypto）。"""
        return tool_scan(path)

    @mcp.tool()
    def list_capabilities() -> str:
        """返回本工具支持的算法/模式/填充/编码能力矩阵。"""
        return tool_capabilities()

    return mcp


def _selftest() -> int:
    print("=" * 64)
    print(" jiejieEAD MCP 服务器自检（底层能力，无需 mcp SDK）")
    print("=" * 64)
    fails = 0

    # 直接用业务函数验证（与 MCP 工具逻辑同源）
    enc = json.loads(tool_encrypt("sm4", "0123456789abcdeffedcba9876543210", "hello",
                                  "cbc", "pkcs7", "00000000000000000000000000000000", "base64"))
    ok1 = enc.get("status") == "ok" and enc.get("cipher") == "2wZpvYQeVFDsFlLs1CttYA=="
    print("   [ %s ] SM4-CBC 加密 == 2wZpvYQeVFDsFlLs1CttYA==" % ("OK" if ok1 else "!!"))
    if not ok1:
        fails += 1

    dec = json.loads(tool_decrypt("sm4", "0123456789abcdeffedcba9876543210",
                                  "2wZpvYQeVFDsFlLs1CttYA==", "cbc", "pkcs7",
                                  "00000000000000000000000000000000", "base64"))
    ok2 = dec.get("status") == "ok" and dec.get("plain") == "hello"
    print("   [ %s ] SM4-CBC 解密还原 == hello" % ("OK" if ok2 else "!!"))
    if not ok2:
        fails += 1

    ecb = json.loads(tool_encrypt("sm4", "0123456789abcdeffedcba9876543210", "hello world",
                                  "ecb", "zero", "", "base64"))
    ok3 = ecb.get("status") == "ok" and ecb.get("cipher") == "RzFLNQQYCfWdX1o0NeuInQ=="
    print("   [ %s ] SM4-ECB+Zero 加密 == RzFLNQQYCfWdX1o0NeuInQ==" % ("OK" if ok3 else "!!"))
    if not ok3:
        fails += 1

    cap = json.loads(tool_capabilities())
    ok4 = "algorithms" in cap and "modes" in cap and "paddings" in cap
    print("   [ %s ] 能力矩阵字段齐全" % ("OK" if ok4 else "!!"))
    if not ok4:
        fails += 1

    # scan：构造一个临时 JS 样本
    import tempfile
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".js", prefix="mcp_scan_")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("var KEY='0123456789abcdeffedcba9876543210'; sm4.encrypt(d,KEY,{mode:'ecb',padding:'ZeroPadding'});")
        sc = json.loads(tool_scan(tmp))
        ok5 = sc.get("logic", {}).get("primary_algorithm") == "SM4"
        print("   [ %s ] scan 识别 SM4" % ("OK" if ok5 else "!!"))
        if not ok5:
            fails += 1
    finally:
        if tmp and os.path.isfile(tmp):
            os.remove(tmp)

    print("-" * 64)
    if fails:
        print(" [FAIL] %d 项未通过。" % fails)
        return 2
    print(" [PASS] MCP 服务器底层能力自检通过。运行 `python crypto_mcp_server.py` 即以 MCP stdio 启动。")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="jiejieEAD MCP 服务器")
    p.add_argument("--selftest", action="store_true", help="自检底层能力（无需 mcp SDK）")
    args = p.parse_args(argv)

    if args.selftest:
        return _selftest()

    server = build_server()
    server.run()  # stdio 传输
    return 0


if __name__ == "__main__":
    sys.exit(main())
