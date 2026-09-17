#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 jiejieEAD | 模块一：对称加解密工作台（CLI 入口）
 文件：cli_crypto.py
================================================================================

【免责声明】
    本工具仅用于拥有书面授权的安全测试、安全研究。未授权对系统进行渗透、
    破解属于违法行为。使用者需自行承担因违规使用产生的一切法律责任。
    本工具全部运算在本地离线完成，不上传任何密钥、明文或密文。

【版本说明 · v2】
    本版本把密码运算全部下沉到共享引擎 crypto_core.py，CLI 只做参数解析与
    输入输出。能力从「2 算法 × 1 模式 × 1 填充」扩展到：

      算法      sm4 / aes128 / aes192 / aes256 / des / des3 / rc4
      模式      ecb / cbc / cfb / ofb / ctr / gcm（RC4 为 stream）
      填充      pkcs7 / zero / none / iso7816 / ansix923
      编码      base64 / hex / raw

    这样「文件扫描分析」模块检出的工作模式与填充方式就能被直接复现，
    不再是"检测到 ECB/ZERO 但工具只支持 CBC/PKCS7"的尴尬局面。

【向后兼容】
    旧调用方式完全兼容：不指定 --mode / --padding 时默认 cbc + pkcs7，
    --alg aes256 / sm4 语义不变，JSON 字段 cipher / plain 保持原名。

【使用示例】
    # 1) 最简：SM4-CBC 文本加密（Base64）
    python cli_crypto.py --alg sm4 --op enc \
        --key 0123456789abcdeffedcba9876543210 \
        --iv  00000000000000000000000000000000 \
        --text "hello 国密" --encoding base64

    # 2) 复现扫描器查出的 AES-ECB + ZeroPadding
    python cli_crypto.py --alg aes128 --op dec --mode ecb --padding zero \
        --key <32位hex> --text "<Base64 密文>" --encoding base64

    # 3) AES-256-GCM（认证加密，密文末尾自动附带 16 字节认证标签）
    python cli_crypto.py --alg aes256 --op enc --mode gcm \
        --key <64位hex> --iv <24位hex=12字节nonce> --text "secret"

    # 4) 导出能力矩阵（GUI 启动时调用，用于动态渲染下拉框）
    python cli_crypto.py --spec --json

    # 5) 自检
    python cli_crypto.py --selftest

【退出码】
    0  成功
    1  参数/校验错误（用户输入问题）
    2  运行时错误（依赖缺失、IO 异常、认证失败等）
================================================================================
"""

from __future__ import annotations

import argparse
import json
import re
import os
import sys

# ----------------------------------------------------------------------------
# 让「以任意工作目录运行」都能找到同目录的 crypto_core.py
# （被 Tauri 以绝对路径调用时，脚本目录未必在 sys.path 首位）
# ----------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import crypto_core as cc  # noqa: E402

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_RUNTIME = 2

OP_ENC = "enc"
OP_DEC = "dec"


# ============================================================================
# 输入 / 输出处理
# ============================================================================

def load_input_bytes(args: argparse.Namespace) -> bytes:
    """
    读取待处理数据：
      · --text 加密时取 UTF-8 字节；解密时按 --encoding 解码为二进制密文；
      · --file 加密时读原始字节（二进制安全）；解密时按编码解码，
        若解码失败且编码为 hex/raw 则视作已是二进制密文；
      · 未指定时尝试读管道输入。
    """
    if args.text is not None and args.file is not None:
        raise cc.CryptoUsageError("--text 与 --file 不能同时使用，请二选一")

    if args.file:
        if not os.path.isfile(args.file):
            raise cc.CryptoUsageError(f"文件不存在：{args.file}")
        try:
            with open(args.file, "rb") as fp:
                raw = fp.read()
        except OSError as exc:
            raise cc.CryptoRuntimeError(f"读取文件失败：{exc}") from exc
        if not raw:
            raise cc.CryptoUsageError(f"文件内容为空：{args.file}")

        if args.op == OP_ENC:
            return raw
        try:
            return cc.decode_text(raw.decode("utf-8", errors="strict"), args.encoding)
        except UnicodeDecodeError:
            # 兜底：文件本身已是二进制密文（raw 编码，或 hex 已被上游转成二进制）
            if args.encoding in ("raw", "hex"):
                return raw
            raise cc.CryptoUsageError(
                f"密文文件不是合法的文本编码，无法按 {args.encoding} 解码。"
                "若为二进制密文请使用 --encoding raw。"
            )

    if args.text is not None:
        if args.op == OP_ENC:
            return args.text.encode("utf-8")
        return cc.decode_text(args.text, args.encoding)

    # 管道输入
    if not sys.stdin.isatty():
        piped = sys.stdin.read()
        if piped.strip():
            if args.op == OP_ENC:
                return piped.rstrip("\n").encode("utf-8")
            return cc.decode_text(piped, args.encoding)

    raise cc.CryptoUsageError("未指定输入：请使用 --text 或 --file 传入数据")


def write_result(text: str, out_path: str | None) -> None:
    """把结果写入文件（若指定）并打印到标准输出（便于 GUI 捕获）。"""
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8", newline="\n") as fp:
                fp.write(text)
        except OSError as exc:
            raise cc.CryptoRuntimeError(f"写入输出文件失败：{exc}") from exc
        print(f"[OK] 结果已保存到：{os.path.abspath(out_path)}")
    print(text)


# ============================================================================
# 主流程
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    """构建 argparse 解析器。"""
    parser = argparse.ArgumentParser(
        prog="cli_crypto.py",
        description=(
            "jiejieEAD 模块一：对称加解密 + 摘要 / HMAC / 密钥派生 + 非对称 / 压缩"
            "（SM4 / AES-128/192/256 / DES / 3DES / RC4，"
            "ECB·CBC·CFB·OFB·CTR·GCM 六种模式，五种填充；"
            "MD5/SHA1/SHA256/SHA512/SM3 摘要；HMAC 含 HMAC-SM3；"
            "密钥支持 HEX / UTF-8 字面量 / Base64，并可按预设派生）"
        ),
        epilog=(
            "示例：python cli_crypto.py --alg sm4 --op enc "
            "--key 0123456789abcdeffedcba9876543210 "
            "--iv 00000000000000000000000000000000 --text \"hello\" --encoding base64\n"
            "示例2（UTF-8 字面量密钥）：python cli_crypto.py --alg aes128 --key 4A7F2C1E9B3D5A08 "
            "--key-format utf8 --iv C6B1D90E37F2A485 --iv-format utf8 --text \"hello\"\n"
            "示例3（HMAC-SM3）：python cli_crypto.py --hmac hmac-sm3 --key <hex> --text \"msg\"\n"
            "示例4（派生密钥）：python cli_crypto.py --derive aes-cbc-then-sha256-slice "
            "--seed <种子> --derive-key 4A7F2C1E9B3D5A08 --derive-key-format utf8 "
            "--derive-iv C6B1D90E37F2A485 --derive-iv-format utf8 --slice 16:32\n"
            "示例5（SM2 加密）：python cli_crypto.py --sm2 enc --public-key <128位HEX> "
            "--text \"hello\" --json\n"
            "示例6（SM2 验签）：python cli_crypto.py --sm2 verify --public-key <HEX> "
            "--text \"原文\" --sig <128位HEX>\n"
            "示例7（RSA 长文本）：python cli_crypto.py --rsa enc --pub-file pub.pem "
            "--file big.bin --encoding hex --out cipher.bin\n"
            "示例8（压缩+Base64）：python cli_crypto.py --chain zlib,base64 --text \"<明文>\"\n"
            "示例9（混合信封）：python cli_crypto.py --envelope enc --recipient sm2 "
            "--public-key <SM2公钥> --text \"<敏感数据>\" --json\n"
            "示例10（生成密钥对）：python cli_crypto.py --keygen sm2 / --keygen rsa:2048\n"
            "示例11（★ 一键解密）：python cli_crypto.py --auto-solve --file 密文.txt "
            "--target-dir <目标前端目录>  → 自动分析 + 尝试解密 + 输出明文与依据\n"
            "提示：运行 --spec --json 可导出完整能力矩阵；运行 --selftest 可自检。\n"
            "注意：本工具仅用于已获书面授权的安全测试与研究。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--alg", default="aes256",
        help=("加密算法：sm4 / aes128 / aes192 / aes256 / des / des3 / rc4 / "
              "rc5 / rc5_16 / rc5_64 / rc6 / rc6_16 / blowfish / cast5 / rc2 / "
              "chacha20 / salsa20；也支持族名 aes（按密钥长度自动判定 128/192/256）。"
              "默认 aes256"),
    )
    parser.add_argument(
        "--rc2-effective-bits", type=int, default=None, metavar="N",
        help=("RC2 专用的「有效密钥位数」（RFC 2268 的 T1）。底层默认 128，"
              "但很多遗留系统用的是 40/56/63 等 —— **它不对是 RC2 解成乱码的头号原因**"
              "（RFC 2268 的测试向量用的是 63）。仅 --alg rc2 时有效"),
    )
    parser.add_argument(
        "--mode", default=None,
        help=("工作模式：ecb / cbc / cfb / ofb / ctr / gcm（rc4 固定 stream）。"
              "默认 cbc；流密码自动为 stream"),
    )
    parser.add_argument(
        "--padding", default=None,
        help=("填充方式：pkcs7 / zero / none / iso7816 / ansix923。"
              "仅 ecb/cbc 生效；流式模式自动为 none。默认分组模式用 pkcs7"),
    )
    parser.add_argument(
        "--op", choices=(OP_ENC, OP_DEC), default=OP_ENC,
        help="操作类型：enc 加密 / dec 解密，默认 enc",
    )
    parser.add_argument(
        "--key",
        help="HEX 密钥（长度随算法而定：SM4/AES-128=32 位，AES-192=48 位，"
             "AES-256=64 位，DES=16 位，3DES=48/32 位，RC4=10~512 位）",
    )
    parser.add_argument(
        "--iv",
        help="HEX 初始向量 / nonce（ECB 与 RC4 无需；GCM 用 12 或 16 字节；"
             "ChaCha20 用 8/12/24 字节、Salsa20 只能 8 字节；"
             "其余为分组长度：16 字节分组的算法（AES/SM4/RC6/RC5-64）用 32 位 HEX，"
             "8 字节分组的算法（DES/3DES/Blowfish/CAST5/RC2/RC5-32）用 16 位 HEX）",
    )
    parser.add_argument("--text", help="待处理文本（加密时为明文，解密时为密文文本）")
    parser.add_argument("--file", help="待处理文件路径（支持任意二进制文件）")
    parser.add_argument("--out", help="结果输出文件路径；不指定则仅打印到终端")
    parser.add_argument(
        "--encoding", choices=cc.ENCODINGS, default="base64",
        help="密文编码：base64 / hex / raw（raw 为原始二进制，仅适合文件模式）。默认 base64",
    )
    parser.add_argument(
        "--aad", default="",
        help="GCM 的附加认证数据 AAD（UTF-8 文本，可选）",
    )

    # ---- 密钥材料格式（真实目标的密钥常常不是 HEX）----------------------
    parser.add_argument(
        "--key-format", choices=cc.KEY_FORMATS, default=cc.KEY_HEX,
        help=("密钥文本格式：hex / utf8 / base64 / auto。默认 hex。"
              "★ 真实业务里密钥常是 UTF-8 字面量——如 '4A7F2C1E9B3D5A08' 这 16 个"
              "ASCII 字符按 utf8 是 16 字节（正确），按 hex 只有 8 字节（报错）"),
    )
    parser.add_argument(
        "--iv-format", choices=cc.KEY_FORMATS, default=cc.KEY_HEX,
        help="IV / nonce 文本格式，取值同 --key-format",
    )
    parser.add_argument(
        "--keyinfo", action="store_true",
        help="只解释 --key 在各格式下的字节数（排查「密钥长度不合法」最快的一步）",
    )

    # ---- 摘要 ----
    parser.add_argument(
        "--digest", metavar="算法",
        help="计算摘要：md5 / sha1 / sha256 / sha512 / sm3（配合 --text / --file）",
    )

    # ---- HMAC ----
    parser.add_argument(
        "--hmac", metavar="算法",
        help=("计算 HMAC：hmac-md5 / hmac-sha1 / hmac-sha256 / hmac-sha512 / hmac-sm3。"
              "用 --key + --key-format 指定密钥，--text 为消息"),
    )

    # ---- 密钥派生（KDF）----
    parser.add_argument(
        "--derive", metavar="预设",
        help=("按键派生密钥。预设见 --spec 的 kdf_presets，例如 "
              "aes-cbc-then-sha256-slice（种子→AES-CBC→SHA256→取区间，白盒前端最常见）"),
    )
    parser.add_argument(
        "--seed", help="派生种子（如报文里前置的随机数）；默认按 UTF-8 文本处理",
    )
    parser.add_argument(
        "--seed-format", choices=cc.KEY_FORMATS, default=cc.KEY_UTF8,
        help="派生种子格式，默认 utf8",
    )
    parser.add_argument("--derive-key", help="派生步骤里用的密钥（如 AES 密钥）")
    parser.add_argument("--derive-iv", help="派生步骤里用的 IV")
    parser.add_argument(
        "--derive-key-format", choices=cc.KEY_FORMATS, default=cc.KEY_HEX,
        help="--derive-key 的格式，默认 hex",
    )
    parser.add_argument(
        "--derive-iv-format", choices=cc.KEY_FORMATS, default=cc.KEY_HEX,
        help="--derive-iv 的格式，默认 hex",
    )
    parser.add_argument(
        "--slice", metavar="start:end",
        help="派生最后一步取字节区间（左闭右开，如 16:32；留空表示到末尾，如 16:）",
    )
    parser.add_argument(
        "--out-encoding", choices=("hex", "base64"), default="hex",
        help="摘要 / HMAC / 派生的输出编码，默认 hex",
    )

    # ---- 非对称：SM2 / RSA ----
    parser.add_argument(
        "--sm2", choices=("enc", "dec", "sign", "verify"), metavar="操作",
        help="SM2 国密非对称：enc 加密 / dec 解密 / sign 签名 / verify 验签",
    )
    parser.add_argument(
        "--rsa", choices=("enc", "dec", "sign", "verify"), metavar="操作",
        help="RSA 非对称：enc / dec / sign / verify（长文本自动分段）",
    )
    parser.add_argument("--public-key", help="公钥：SM2 为 128 位 HEX（可带 04 前缀）/ RSA 为 PEM 或文件路径")
    parser.add_argument("--private-key", help="私钥：SM2 为 64 位 HEX / RSA 为 PEM 或文件路径")
    parser.add_argument("--pub-file", help="从文件读公钥（省得命令行超长）")
    parser.add_argument("--priv-file", help="从文件读私钥")
    parser.add_argument(
        "--sm2-mode", choices=cc.SM2_CIPHER_MODES, default=cc.SM2_C1C3C2,
        help="SM2 密文格式，默认 c1c3c2（国标推荐）",
    )
    parser.add_argument("--asn1", action="store_true", help="SM2 签名/密钥使用 DER(asn1) 编码")
    parser.add_argument(
        "--prehashed", action="store_true",
        help="SM2 签名/验签时把输入当作 32 字节摘要（跳过 SM3+Z 预处理）",
    )
    parser.add_argument("--sig", help="SM2/RSA 验签用的签名（HEX 或 base64）")
    parser.add_argument(
        "--rsa-padding", choices=cc.RSA_PADDINGS, default=cc.RSA_PKCS1V15,
        help="RSA 加解密填充，默认 pkcs1v15（注意：它不含完整性校验，OAEP 更安全）",
    )
    parser.add_argument(
        "--rsa-scheme", choices=cc.RSA_SIGN_SCHEMES, default=cc.RSA_PKCS1V15,
        help="RSA 签名方案，默认 pkcs1v15（pss 为随机化填充）",
    )
    parser.add_argument(
        "--hash", default="sha256",
        help="RSA 摘要算法：md5/sha1/sha256/sha384/sha512，默认 sha256",
    )
    parser.add_argument("--keygen", metavar="算法", help="生成密钥对：sm2 / rsa[:位数]（默认 2048）")

    # ---- 压缩 / 编码链 ----
    parser.add_argument(
        "--zip", choices=("compress", "decompress"), metavar="操作",
        help="压缩 / 解压（配合 --zip-algo）",
    )
    parser.add_argument(
        "--zip-algo", choices=cc.COMPRESS_ALGOS, default=cc.COMPRESS_ZLIB,
        help="压缩算法：zlib / gzip / deflate / deflate-raw（pako 默认裸流），默认 zlib",
    )
    parser.add_argument(
        "--chain", metavar="步骤",
        help=("多级编码链，逗号分隔，如 zlib,base64 或 gzip,hex,base64；"
              "配合 --op enc 做编码、--op dec 反序解码。可用步骤见 --spec 的 chain_steps"),
    )

    # ---- 一键解密（贴密文自动分析 + 尝试解密）----
    parser.add_argument(
        "--auto-solve", action="store_true",
        help=("一键解密：把密文交给 cipher_auto_solver.py —— 自动识别报文形态、"
              "从 --target-dir/粘贴文本里挖常量、编排配方并尝试解密，输出明文与依据"),
    )
    parser.add_argument(
        "--target-dir", metavar="目录",
        help="一键解密的常量来源：目标前端 JS/jar 所在目录（可选，但强烈建议提供）",
    )
    parser.add_argument(
        "--target-file", metavar="文件",
        help="一键解密的常量来源：单个文件（JS / jar / class）",
    )

    # ---- 混合加密信封 ----
    parser.add_argument(
        "--envelope", choices=("enc", "dec"), metavar="操作",
        help="混合加密信封：SM2/RSA 包裹对称密钥 + 对称算法加密数据",
    )
    parser.add_argument(
        "--recipient", choices=cc.ASYM_CHOICES, default=cc.ASYM_SM2,
        help="信封的接收方算法：sm2（默认）/ rsa",
    )
    parser.add_argument("--wrapped-key", help="信封解密：被包裹的对称密钥（hex 或 base64）")
    parser.add_argument("--cipher-text", help="信封解密：对称密文（hex 或 base64）")
    parser.add_argument(
        "--input-format", choices=("hex", "base64"), default="hex",
        help="信封解密时 wrapped-key / cipher-text 的编码，默认 hex",
    )
    parser.add_argument(
        "--json", action="store_true", dest="as_json",
        help="以 JSON 格式输出结果，便于 GUI / 自动化脚本解析",
    )
    parser.add_argument(
        "--spec", action="store_true",
        help="导出能力矩阵（算法/模式/填充/编码），配合 --json 供 GUI 渲染下拉框",
    )
    parser.add_argument(
        "--selftest", action="store_true",
        help="执行内置自检（无需其它参数）",
    )
    return parser


def emit_spec() -> int:
    """导出能力矩阵。"""
    matrix = cc.capability_matrix()
    print(json.dumps(matrix, ensure_ascii=False, indent=2))
    return EXIT_OK


def _parse_slice(text: str) -> tuple[int | None, int | None]:
    """解析 '16:32' / '16:' / ':16' 形式的字节区间。"""
    if not text:
        return None, None
    if ":" not in text:
        raise cc.CryptoUsageError("--slice 需要 start:end 形式，例如 16:32（右开）")
    left, _, right = text.partition(":")
    start = int(left) if left.strip() else 0
    end = int(right) if right.strip() else None
    if end is not None and end <= start:
        raise cc.CryptoUsageError(f"--slice {text} 不合法：end 必须大于 start")
    return start, end


def run_aux_mode(args) -> int | None:
    """处理「摘要 / HMAC / 密钥格式解释 / 密钥派生」四类辅助模式。

    它们与加解密共用 --text / --file / --json / --out 约定，但不需要 --iv、--op。
    返回 None 表示当前不是辅助模式，交回主流程继续走加解密。
    """
    # ---- 密钥格式解释 ----
    if args.keyinfo:
        if not args.key:
            raise cc.CryptoUsageError("--keyinfo 需要同时提供 --key")
        info = cc.explain_key_material(args.key)
        if args.as_json:
            print(json.dumps(info, ensure_ascii=False))
        else:
            print(f"密钥文本：{info['text']}（{info['chars']} 个字符）")
            for item in info["interpretations"]:
                if item.get("ok"):
                    print(f"  按 {item['display']:<28} → {item['bytes']:>3} 字节  "
                          f"hex={item['hex']}")
                else:
                    print(f"  按 {item['display']:<28} → 不适用（{item['reason']}）")
            print("[提示] AES/SM4 需要 16 字节；看到 8 字节/16 字节两种结果时，"
                  "先确认原始代码里是不是拿这串字符当文本用（UTF-8 字面量）。")
        return EXIT_OK

    # ---- 摘要 ----
    if args.digest:
        payload = load_input_bytes(args)
        raw = cc.do_digest(args.digest, payload)
        text = cc.encode_bytes(raw, args.out_encoding)
        meta = {
            "status": "ok", "mode": "digest", "alg": args.digest,
            "digest_bytes": len(raw), "input_len": len(payload),
            "encoding": args.out_encoding, "hex": raw.hex(),
            "base64": cc.encode_bytes(raw, "base64"),
        }
        if args.as_json:
            print(json.dumps({**meta, "result": text}, ensure_ascii=False))
        else:
            print(text)
        return EXIT_OK

    # ---- HMAC ----
    if args.hmac:
        if not args.key:
            raise cc.CryptoUsageError("--hmac 需要同时提供 --key（以及 --key-format）")
        payload = load_input_bytes(args)
        key_bytes = cc.parse_key_material(args.key, args.key_format, "HMAC 密钥")
        raw = cc.do_hmac(args.hmac, key_bytes, payload)
        text = cc.encode_bytes(raw, args.out_encoding)
        meta = {
            "status": "ok", "mode": "hmac", "alg": args.hmac,
            "key_bytes": len(key_bytes), "key_format": args.key_format,
            "mac_bytes": len(raw), "input_len": len(payload),
            "encoding": args.out_encoding, "hex": raw.hex(),
            "base64": cc.encode_bytes(raw, "base64"),
        }
        if args.as_json:
            print(json.dumps({**meta, "result": text}, ensure_ascii=False))
        else:
            print(text)
        return EXIT_OK

    # ---- 密钥派生 ----
    if args.derive:
        if not args.seed:
            raise cc.CryptoUsageError(
                "--derive 需要提供种子：用 --seed '<种子文本>'（如报文里前置的随机数）")
        start, end = _parse_slice(args.slice)
        result = cc.derive_key_by_preset(
            args.seed, args.derive,
            seed_format=args.seed_format,
            key=args.derive_key or "", iv=args.derive_iv or "",
            key_format=args.derive_key_format, iv_format=args.derive_iv_format,
            slice_start=start, slice_end=end,
        )
        if args.as_json:
            print(json.dumps({"status": "ok", "mode": "derive", "preset": args.derive,
                              **result}, ensure_ascii=False))
            return EXIT_OK
        print(f"派生方式：{cc.KDF_PRESETS[args.derive]['display']}")
        print(f"种子    ：{args.seed}（{args.seed_format}）")
        for step in result["trace"]:
            print(f"  第 {step['step']} 步 {step['op']:<8} {step['detail']}"
                  f"  → {step['out_len']} 字节  {step['out_preview']}…")
        print(f"派生结果：{result['output_hex']}")
        print(f"         （{result['output_len']} 字节；base64: {result['output_base64']}）")
        if result["output_len"] in (8, 16, 24, 32):
            print(f"[提示] 可直接作为密钥使用：  --key {result['output_hex']} "
                  f"--key-format hex")
        return EXIT_OK

    return None


def _read_key(cli_value, file_path, label):
    """密钥优先从文件读（命令行长度有限，PEM 塞不进参数时用）。"""
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as fp:
                return fp.read().strip()
        except OSError as exc:
            raise cc.CryptoUsageError(f"读取{label}文件失败：{exc}") from exc
    return (cli_value or "").strip()


def run_auto_solve(args) -> int:
    """一键解密：交给 cipher_auto_solver 完成「分析 → 解密 → 说明」。"""
    try:
        import cipher_auto_solver as cas
    except Exception as exc:  # noqa: BLE001
        raise cc.CryptoRuntimeError(
            "缺少 cipher_auto_solver.py（应与本脚本同目录）：%s" % exc) from exc
    text = args.text
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fp:
                text = fp.read()
        except OSError as exc:
            raise cc.CryptoRuntimeError("读取密文文件失败：%s" % exc) from exc
    if not text:
        raise cc.CryptoUsageError("一键解密需要 --text 或 --file 提供密文")
    res = cas.auto_solve(text, target_dir=args.target_dir or "",
                         target_file=args.target_file or "")
    if args.as_json:
        print(json.dumps(res, ensure_ascii=False))
        return EXIT_OK if res.get("status") == "ok" else EXIT_RUNTIME
    cas._emit(res, False)
    return EXIT_OK if res.get("status") == "ok" else EXIT_RUNTIME


def _payload_for(args, decrypt: bool = False) -> bytes:
    """按方向读取输入。

    解密方向必须让 load_input_bytes 按 --encoding 解码（否则 --file 读到的
    HEX 文本会被当成密文原始字节，长度对不上却报不出可读错误）。
    `--op` 在非对称模式下不参与语义，这里临时改一下只影响输入读取。
    """
    prev = args.op
    args.op = OP_DEC if decrypt else OP_ENC
    try:
        return load_input_bytes(args)
    finally:
        args.op = prev


def run_asym_mode(args) -> int | None:
    """处理「SM2 / RSA / 压缩 / 编码链 / 混合信封」五类模式。

    它们与加解密共用 --text / --file / --json / --out 约定，但参数完全不同，
    所以在主流程之前拦截；返回 None 表示不是这些模式。
    """
    # Windows 命令行上限约 32767 字符：RSA 长密文/SM2 长密文必须走文件通道，
    # 否则会被系统静默截断（这里提前拦住并给出可操作的建议）。
    if args.text and len(args.text) > 30000:
        raise cc.CryptoUsageError(
            "--text 过长（%d 字符），超过 Windows 命令行上限。\n"
            "请把密文/密钥存成文件，再用 --file（配合 --encoding base64|hex）或 "
            "--pub-file/--priv-file 传路径。" % len(args.text))

    # ---- 密钥生成 ----
    if args.keygen:
        algo = str(args.keygen).strip().lower()
        if algo.startswith("rsa"):
            bits = 2048
            if ":" in algo:
                bits = int(algo.split(":", 1)[1] or 2048)
            out = cc.rsa_keygen(bits)
            head = {"status": "ok", "mode": "keygen", "alg": "rsa", "bits": bits}
        elif algo == "sm2":
            out = cc.sm2_keygen()
            head = {"status": "ok", "mode": "keygen", "alg": "sm2"}
        else:
            raise cc.CryptoUsageError("--keygen 只支持 sm2 / rsa / rsa:2048")
        if args.as_json:
            print(json.dumps({**head, **out}, ensure_ascii=False))
        else:
            print("【私钥】"); print(out.get("private_pem") or out.get("private_key"))
            print("【公钥】"); print(out.get("public_pem") or out.get("public_key"))
            print("[提示] 生成的密钥仅供调试/自检使用，生产请走标准密钥管理。")
        return EXIT_OK

    # ---- SM2 ----
    if args.sm2:
        payload = _payload_for(args, decrypt=(args.sm2 == "dec"))
        pub = _read_key(args.public_key, args.pub_file, "公钥")
        priv = _read_key(args.private_key, args.priv_file, "私钥")
        if args.sm2 == "verify":
            sig = _read_key(args.sig, None, "签名")
            r = cc.do_sm2("verify", data=payload, message=payload, sig=sig,
                          public_key=pub, cipher_mode=args.sm2_mode, asn1=args.asn1,
                          prehashed=args.prehashed)
            ok = r == b"OK"
            if args.as_json:
                print(json.dumps({"status": "ok" if ok else "fail",
                                  "mode": "sm2-verify", "result": r.decode("utf-8", "replace")},
                                 ensure_ascii=False))
            else:
                print(("SM2 验签通过" if ok else "SM2 验签失败") + "：" + r.decode("utf-8", "replace"))
            return EXIT_OK if ok else EXIT_RUNTIME
        if args.sm2 == "sign":
            out = cc.do_sm2("sign", data=payload, private_key=priv, public_key=pub,
                            asn1=args.asn1, prehashed=args.prehashed)
            text = out.decode("ascii")
        elif args.sm2 == "enc":
            out = cc.do_sm2("enc", data=payload, public_key=pub, cipher_mode=args.sm2_mode)
            text = cc.encode_bytes(out, "hex" if args.encoding == "raw" else args.encoding)
        else:
            out = cc.do_sm2("dec", data=payload, private_key=priv,
                            cipher_mode=args.sm2_mode)
            text = out.decode("utf-8", errors="replace")
        meta = {"status": "ok", "mode": "sm2-" + args.sm2, "cipher_mode": args.sm2_mode,
                "asn1": args.asn1, "key_bytes": len(payload)}
        if args.as_json:
            print(json.dumps({**meta, "result": text, "result_len": len(out)},
                             ensure_ascii=False))
        else:
            print(text)
        _maybe_write_out(args, out)
        return EXIT_OK

    # ---- RSA ----
    if args.rsa:
        payload = _payload_for(args, decrypt=(args.rsa == "dec"))
        key_text = _read_key(args.public_key or args.private_key,
                            args.priv_file or args.pub_file, "RSA 密钥")
        if not key_text:
            raise cc.CryptoUsageError("RSA 需要 --public-key / --private-key（或 --pub-file/--priv-file）")
        if args.rsa == "verify":
            sig_text = re.sub(r"[\s:]", "", _read_key(args.sig, None, "签名"))
            try:
                sig = bytes.fromhex(sig_text) if len(sig_text) % 2 == 0 else None
            except ValueError:
                sig = None
            if sig is None:
                sig = base64.b64decode(sig_text + "=" * ((-len(sig_text)) % 4))
            r = cc.do_rsa("verify", message=payload, sig=sig, key_text=key_text,
                          scheme=args.rsa_scheme, hash_alg=args.hash)
            ok = r == b"OK"
            if args.as_json:
                print(json.dumps({"status": "ok" if ok else "fail", "mode": "rsa-verify",
                                  "result": r.decode("utf-8", "replace")}, ensure_ascii=False))
            else:
                print(("RSA 验签通过" if ok else "RSA 验签失败") + "：" + r.decode("utf-8", "replace"))
            return EXIT_OK if ok else EXIT_RUNTIME
        if args.rsa == "sign":
            out = cc.do_rsa("sign", data=payload, key_text=key_text,
                            scheme=args.rsa_scheme, hash_alg=args.hash)
            text = cc.encode_bytes(out, "hex" if args.encoding == "raw" else args.encoding)
        elif args.rsa == "enc":
            out = cc.do_rsa("enc", data=payload, key_text=key_text,
                            padding=args.rsa_padding, hash_alg=args.hash)
            text = cc.encode_bytes(out, "hex" if args.encoding == "raw" else args.encoding)
        else:
            out = cc.do_rsa("dec", data=payload, key_text=key_text,
                            padding=args.rsa_padding, hash_alg=args.hash)
            text = out.decode("utf-8", errors="replace")
        meta = {"status": "ok", "mode": "rsa-" + args.rsa, "padding": args.rsa_padding,
                "scheme": args.rsa_scheme, "hash": args.hash, "input_len": len(payload)}
        if args.as_json:
            print(json.dumps({**meta, "result": text, "result_len": len(out)},
                             ensure_ascii=False))
        else:
            print(text)
        _maybe_write_out(args, out)
        return EXIT_OK

    # ---- 压缩 / 解压 ----
    if args.zip:
        payload = _payload_for(args, decrypt=(args.zip == "decompress"))
        if args.zip == "compress":
            out = cc.do_compress(payload, args.zip_algo)
            text = cc.encode_bytes(out, "hex" if args.encoding == "raw" else args.encoding)
        else:
            out = cc.do_decompress(payload, args.zip_algo)
            text = out.decode("utf-8", errors="replace")
        meta = {"status": "ok", "mode": "zip-" + args.zip, "algo": args.zip_algo,
                "input_len": len(payload), "output_len": len(out)}
        if args.as_json:
            print(json.dumps({**meta, "result": text}, ensure_ascii=False))
        else:
            print(text)
        _maybe_write_out(args, out)
        return EXIT_OK

    # ---- 多级编码链 ----
    if args.chain:
        steps = [x.strip().lower() for x in str(args.chain).split(",") if x.strip()]
        if args.op == OP_ENC:
            payload = load_input_bytes(args)
            out = cc.encode_chain(payload, steps)
            text = out.decode("utf-8", errors="replace")
            meta = {"status": "ok", "mode": "chain-encode", "steps": steps,
                    "output_len": len(out)}
        else:
            # 解码链：输入文本**原样**交给链上各步处理（链自己会做 base64/hex/url 解码）。
            # 这里不能用 --encoding 先解一次，否则会「解两遍」——实测踩过这个坑。
            if args.text:
                raw = args.text.encode("utf-8")
            elif args.file:
                with open(args.file, "rb") as fp:
                    raw = fp.read()
            else:
                raise cc.CryptoUsageError("解码链需要 --text 或 --file")
            out = cc.decode_chain(raw, steps)
            text = out.decode("utf-8", errors="replace")
            meta = {"status": "ok", "mode": "chain-decode", "steps": steps,
                    "output_len": len(out)}
        if args.as_json:
            print(json.dumps({**meta, "result": text}, ensure_ascii=False))
        else:
            print(text)
        _maybe_write_out(args, out)
        return EXIT_OK

    # ---- 混合加密信封 ----
    if args.envelope:
        pub = _read_key(args.public_key, args.pub_file, "公钥")
        priv = _read_key(args.private_key, args.priv_file, "私钥")
        if args.envelope == "enc":
            payload = _payload_for(args, decrypt=False)
            out = cc.envelope_encrypt(
                payload, recipient=args.recipient, public_key=pub,
                symmetric=args.alg, mode=args.mode or cc.MODE_ECB,
                padding=args.padding or cc.PAD_PKCS7,
                key_format=args.key_format, symmetric_key=args.key or "",
                iv=args.iv or "", iv_format=args.iv_format)
            if args.as_json:
                print(json.dumps({"status": "ok", "mode": "envelope-enc", **out},
                                 ensure_ascii=False))
            else:
                print("接收方算法 : " + out["recipient"].upper())
                print("对称算法   : %s / %s / %s" % (out["symmetric"].upper(),
                                                     out["mode"].upper(), out["padding"].upper()))
                print("包裹的密钥 : " + out["wrapped_key_hex"])
                print("对称密文   : " + out["cipher_hex"])
                if out["iv_hex"]:
                    print("IV         : " + out["iv_hex"])
                print("[提示] 解密端用「--envelope dec --wrapped-key <包裹密钥> "
                      "--cipher-text <对称密文> --private-key <接收方私钥>」还原文。")
            return EXIT_OK
        plain = cc.envelope_decrypt(
            recipient=args.recipient, wrapped_key=args.wrapped_key or "",
            cipher=args.cipher_text or "", private_key=priv,
            symmetric=args.alg, mode=args.mode or cc.MODE_ECB,
            padding=args.padding or cc.PAD_PKCS7, iv=args.iv or "",
            input_format=args.input_format)
        text = plain.decode("utf-8", errors="replace")
        if args.as_json:
            print(json.dumps({"status": "ok", "mode": "envelope-dec", "result": text},
                             ensure_ascii=False))
        else:
            print(text)
        _maybe_write_out(args, plain)
        return EXIT_OK

    return None


def _maybe_write_out(args, data: bytes) -> None:
    """--out 指定时把二进制结果落盘（否则只打印）。"""
    if not args.out:
        return
    try:
        with open(args.out, "wb") as fp:
            fp.write(data)
        print(f"[OK] 结果已保存到：{os.path.abspath(args.out)}", file=sys.stderr)
    except OSError as exc:
        raise cc.CryptoRuntimeError(f"写入输出文件失败：{exc}") from exc


def main(argv: list[str] | None = None) -> int:
    """程序主入口，返回进程退出码。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    # ---- 模式 1：导出能力矩阵（GUI 启动时调用）--------------------------
    if args.spec:
        try:
            cc.check_dependencies()
        except cc.CryptoRuntimeError as exc:
            print(f"[错误] {exc}", file=sys.stderr)
            return EXIT_RUNTIME
        return emit_spec()

    # ---- 模式 1.2：一键解密（优先级最高，因为它自己会决定用什么算法）----
    if args.auto_solve:
        try:
            cc.check_dependencies()
            return run_auto_solve(args)
        except (cc.CryptoUsageError, cc.CryptoRuntimeError) as exc:
            print(f"[错误] {exc}", file=sys.stderr)
            return EXIT_USAGE if isinstance(exc, cc.CryptoUsageError) else EXIT_RUNTIME

    # ---- 模式 1.5：非对称 / 压缩 / 编码链 / 信封（在加解密主流程之前拦截）----
    if args.sm2 or args.rsa or args.zip or args.chain or args.envelope or args.keygen:
        try:
            cc.check_dependencies()
            rc = run_asym_mode(args)
            if rc is not None:
                return rc
        except (cc.CryptoUsageError, cc.CryptoRuntimeError) as exc:
            print(f"[错误] {exc}", file=sys.stderr)
            return EXIT_USAGE if isinstance(exc, cc.CryptoUsageError) else EXIT_RUNTIME

    # ---- 模式 2：自检（优先级最高）--------------------------------------
    if args.selftest:
        try:
            return cc.run_selftest()
        except (cc.CryptoUsageError, cc.CryptoRuntimeError) as exc:
            print(f"[错误] {exc}", file=sys.stderr)
            return EXIT_RUNTIME

    try:
        # ---- 步骤 0：辅助模式（摘要 / HMAC / 密钥格式解释 / 密钥派生）----
        aux = run_aux_mode(args)
        if aux is not None:
            return aux

        # ---- 步骤 1：必填参数校验 --------------------------------------
        if not args.key:
            raise cc.CryptoUsageError(
                "缺少必填参数 --key（密钥文本；若原始密钥是 UTF-8 字面量，"
                "请加 --key-format utf8）")

        # 解析算法与模式，决定是否需要 IV
        key_bytes_len = len(cc.parse_key_material(args.key, args.key_format, "密钥 KEY"))
        spec = cc.get_spec_by_keylen(args.alg, key_bytes_len)

        # 未显式指定模式时按算法给默认：流密码用 stream，其余用 cbc
        mode_arg = args.mode
        if mode_arg is None:
            mode_arg = cc.MODE_STREAM if spec.is_stream else cc.MODE_CBC
        mode, padding, notes = cc.normalize_mode_padding(spec, mode_arg, args.padding)

        # RC2 的有效密钥位数：仅对 rc2 生效，且必须在 do_crypt 之前设好
        if args.alg.lower() == "rc2" and args.rc2_effective_bits is not None:
            cc.set_rc2_effective_bits(args.rc2_effective_bits)

        # 带 nonce 的流密码（ChaCha20/Salsa20）也要 IV —— 不能只看 is_stream，
        # 否则用户不传 nonce 时这里放行、到构造 cipher 才炸，报错点太远。
        needs_iv = not ((spec.is_stream and not spec.nonce_sizes) or mode == cc.MODE_ECB)
        if needs_iv and not args.iv:
            if spec.nonce_sizes:
                raise cc.CryptoUsageError(
                    "%s 需要 --iv 作为 nonce（允许 %s 字节）"
                    % (spec.display, " / ".join(str(n) for n in spec.nonce_sizes))
                )
            if mode == cc.MODE_GCM:
                raise cc.CryptoUsageError(
                    "GCM 模式需要 --iv 作为 nonce（建议 12 字节 = 24 位 HEX）"
                )
            raise cc.CryptoUsageError(
                f"{mode.upper()} 模式需要 --iv（{spec.block} 字节 = "
                f"{spec.block * 2} 位 HEX）"
            )

        # 对用户明确提示被自动忽略的设置，避免"我明明选了 padding 却没生效"的困惑
        for note in notes:
            print(f"[提示] {note}", file=sys.stderr)

        # ---- 步骤 2：读取输入 ------------------------------------------
        payload = load_input_bytes(args)

        # ---- 步骤 3：执行加解密 ----------------------------------------
        result_bytes = cc.do_crypt(
            alg=args.alg, op=args.op,
            key_hex=args.key, iv_hex=args.iv,
            data=payload, mode=mode, padding=padding,
            aad=args.aad.encode("utf-8") if args.aad else b"",
            key_format=args.key_format, iv_format=args.iv_format,
        )

        # ---- 步骤 3.5：完整性校验能力提示 ------------------------------
        # 对「无完整性校验」的组合（Zero/NoPadding、CFB/OFB/CTR/RC4）必须明确
        # 告知：解密不报错 ≠ 密钥正确。这是密码测评中最常见的假阳性来源。
        integrity_ok = cc.has_integrity_check(mode, padding)
        integ_note = cc.integrity_warning(mode, padding)
        if integ_note and args.op == OP_DEC:
            print(f"[注意] {integ_note}", file=sys.stderr)

        # ---- 步骤 4：输出 ----------------------------------------------
        base_meta = {
            "status": "ok",
            "alg": spec.aid,
            "alg_display": spec.display,
            "mode": mode,
            "padding": padding,
            "op": args.op,
            "integrity_checked": integrity_ok,
            "key_format": args.key_format,
        }

        if args.op == OP_ENC:
            if args.encoding == "raw":
                # 原始二进制输出：只能落盘
                if not args.out:
                    raise cc.CryptoUsageError(
                        "编码 raw 会产出二进制数据，必须用 --out 指定输出文件"
                    )
                try:
                    with open(args.out, "wb") as fp:
                        fp.write(result_bytes)
                except OSError as exc:
                    raise cc.CryptoRuntimeError(f"写入文件失败：{exc}") from exc
                if args.as_json:
                    print(json.dumps({**base_meta, "encoding": "raw",
                                      "cipher_len": len(result_bytes),
                                      "plain_len": len(payload),
                                      "out": os.path.abspath(args.out)},
                                     ensure_ascii=False))
                else:
                    print(f"[OK] 二进制密文（{len(result_bytes)} 字节）已保存到："
                          f"{os.path.abspath(args.out)}")
                return EXIT_OK

            encoded = cc.encode_bytes(result_bytes, args.encoding)
            if args.as_json:
                print(json.dumps({
                    **base_meta,
                    "encoding": args.encoding,
                    "cipher_len": len(result_bytes),
                    "plain_len": len(payload),
                    "cipher": encoded,
                }, ensure_ascii=False))
                if args.out:
                    with open(args.out, "w", encoding="utf-8", newline="\n") as fp:
                        fp.write(encoded)
                return EXIT_OK
            write_result(encoded, args.out)
            return EXIT_OK

        # ---- 解密输出 ---------------------------------------------------
        try:
            decoded_text = result_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # 二进制明文：终端给摘要，落盘写原始字节
            if args.out:
                try:
                    with open(args.out, "wb") as fp:
                        fp.write(result_bytes)
                except OSError as exc:
                    raise cc.CryptoRuntimeError(f"写入文件失败：{exc}") from exc
                print(f"[OK] 解密得到二进制明文（{len(result_bytes)} 字节），"
                      f"已保存到：{os.path.abspath(args.out)}")
            else:
                print(f"[提示] 解密结果为二进制数据（{len(result_bytes)} 字节）。"
                      "如需保存请指定 --out。")
                print(f"[HEX] {result_bytes.hex()}")
            if args.as_json:
                print(json.dumps({**base_meta, "plain_len": len(result_bytes),
                                  "plain_binary": True,
                                  "plain_hex": result_bytes.hex()},
                                 ensure_ascii=False))
            return EXIT_OK

        if args.as_json:
            print(json.dumps({**base_meta, "plain_len": len(result_bytes),
                              "plain": decoded_text}, ensure_ascii=False))
            if args.out:
                with open(args.out, "w", encoding="utf-8", newline="\n") as fp:
                    fp.write(decoded_text)
            return EXIT_OK
        write_result(decoded_text, args.out)
        return EXIT_OK

    except cc.CryptoUsageError as exc:
        print(f"[参数错误] {exc}", file=sys.stderr)
        return EXIT_USAGE
    except cc.CryptoRuntimeError as exc:
        print(f"[运行错误] {exc}", file=sys.stderr)
        return EXIT_RUNTIME
    except KeyboardInterrupt:
        print("\n[中断] 用户取消操作", file=sys.stderr)
        return EXIT_RUNTIME
    except Exception as exc:  # 兜底：任何未预期异常都转成友好提示
        print(f"[未知错误] {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_RUNTIME


if __name__ == "__main__":
    sys.exit(main())
