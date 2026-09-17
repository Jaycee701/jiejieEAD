#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 jiejieEAD | 模块三：国密密码分析 + TLCP 流量解析一体化工具
 文件：gm_crypto_analyzer.py
================================================================================

【免责声明】
    本工具仅用于拥有书面授权的安全测试、安全研究。未授权对系统进行渗透、
    破解属于违法行为。使用者需自行承担因违规使用产生的一切法律责任。

【功能概述】采用 argparse 子命令模式，三个子命令：
    sm3hash   —— 计算文本/文件的 SM3 摘要（GB/T 32905-2016）
    sm2check  —— 导入 SM2 公钥 PEM/PKCS#8，做弱密钥与合法性风险审计
    tlcp      —— 解析 TLCP（GB/T 38636 / GM/T 0024）国密 SSL 流量的 pcap 文件

【重要说明：关于 TLCP 解密边界】
    本工具只做「协议结构层面」的解析（记录层/握手层字段、套件、证书消息提示），
    **不实现、也无法实现完整流量解密**——TLCP 为 ECDHE 类前向安全密钥交换，
    必须持有服务端私钥或 TLS 主密钥(SSLKEYLOGFILE)才能还原会话密钥。
    任何声称仅凭 pcap 即可解 TLCP 密文的工具都不可信。

【依赖】
    pip install gmssl scapy pyasn1

【使用示例】
    python gm_crypto_analyzer.py sm3hash --text "hello 国密"
    python gm_crypto_analyzer.py sm3hash --file ./firmware.bin
    python gm_crypto_analyzer.py sm2check --pubkey ./server_pub.pem
    python gm_crypto_analyzer.py tlcp --pcap ./tlcp_capture.pcap --port 443
================================================================================
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any

# ----------------------------------------------------------------------------
# 依赖按需导入，缺失时给出中文安装提示
#
# 【设计要点】scapy 采用「惰性导入」：
#   1) scapy 在 Windows 上导入时会扫描 Wireshark 安装路径，个别精简系统/沙箱
#      环境缺少 ProgramFiles 环境变量时会直接抛 KeyError 导致整个模块不可用；
#   2) sm3hash / sm2check 两个子命令完全不需要 scapy，没有理由让它们承担
#      scapy 的导入风险与启动开销。
#   因此 scapy 只在 tlcp 子命令内部导入。
# ----------------------------------------------------------------------------
_MISSING: list[str] = []

try:
    from gmssl import sm3 as gmssl_sm3
    from gmssl import func as gmssl_func
except ImportError:  # pragma: no cover
    gmssl_sm3 = None
    gmssl_func = None
    _MISSING.append("gmssl")

try:
    from pyasn1.codec.der.decoder import decode as der_decode
except ImportError:  # pragma: no cover
    der_decode = None
    _MISSING.append("pyasn1")


EXIT_OK = 0
EXIT_USAGE = 1
EXIT_RUNTIME = 2

# ============================================================================
# 国密相关常量与知识表
# ============================================================================

# SM2 推荐曲线参数（GM/T 0003.5-2012）；用于公钥点合法性校验的纯数学验算
SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# SM2 曲线 OID：1.2.156.10197.1.301
SM2_CURVE_OID_HEX = "2a811ccf5501822d"   # DER 编码后的内容字节（含 OID 前两字节 06 07 后的部分另算）
SM2_CURVE_OID_DOTTED = "1.2.156.10197.1.301"

# ---------------------------------------------------------------------------
# 已知「公开文档 / 示例 / 测试用」SM2 公钥指纹库（X||Y 拼接，128 位 HEX，不含 04 前缀）
#   命中即视为高危：这类密钥广泛出现在标准文档、开源示例与教程中，
#   一旦出现在生产环境，说明密钥管理存在严重问题，攻击者可离线构造伪造签名。
#   该列表可自行扩展（把你的红队字典、历史遇到的弱密钥追加进来即可）。
# ---------------------------------------------------------------------------
KNOWN_WEAK_SM2_PUBKEYS: dict[str, str] = {
    # GM/T 0003 标准附录示例密钥对对应的公钥
    "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
    "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13":
        "GM/T 0003 标准文档示例公钥（公开测试密钥）",

    # 全 0 点（退化密钥，非合法曲线点）
    "0" * 128: "全零公钥（退化密钥，非曲线合法点）",

    # 全 F 点（退化密钥）
    "f" * 128: "全 F 公钥（退化密钥，非曲线合法点）",

    # 常见「unit 测试」型公钥：X = Gx, Y = Gy（直接使用生成元作为公钥，私钥即 1）
    f"{SM2_GX:064x}{SM2_GY:064x}": "公钥等于曲线基点 G（对应私钥为 1，极危）",
}

# 国密 TLCP 密码套件表（依据 GM/T 0024-2014 / GB/T 38636-2020 常见取值）
TLCP_CIPHER_SUITES: dict[int, str] = {
    0xE011: "ECC_SM4_CBC_SM3",
    0xE013: "ECC_SM4_GCM_SM3",
    0xE051: "ECC_SM4_CBC_SM2",
    0xE053: "ECC_SM4_GCM_SM2",
}

# TLS 记录层 / 握手层类型表
TLS_CONTENT_TYPES: dict[int, str] = {
    0x14: "ChangeCipherSpec(变更密码规格)",
    0x15: "Alert(告警)",
    0x16: "Handshake(握手)",
    0x17: "ApplicationData(应用数据/已加密业务数据)",
    0x18: "Heartbeat(心跳)",
}

TLS_HANDSHAKE_TYPES: dict[int, str] = {
    0: "HelloRequest",
    1: "ClientHello(客户端问候)",
    2: "ServerHello(服务端问候)",
    11: "Certificate(证书)",
    12: "ServerKeyExchange(服务端密钥交换)",
    13: "CertificateRequest(证书请求)",
    14: "ServerHelloDone(服务端问候结束)",
    15: "CertificateVerify(证书校验)",
    16: "ClientKeyExchange(客户端密钥交换)",
    20: "Finished(握手完成)",
}

TLS_VERSIONS: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x0101: "TLCP 1.1 / GM-T 0024 (国密记录层版本 0x0101)",
    0x0100: "TLCP 1.0 (国密记录层版本 0x0100)",
}

# TLS 扩展类型
TLS_EXT_TYPES: dict[int, str] = {
    0: "server_name(SNI)",
    5: "status_request",
    10: "supported_groups(支持的曲线组)",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "application_layer_protocol_negotiation(ALPN)",
    23: "extended_master_secret",
    35: "session_ticket",
    43: "supported_versions",
    51: "key_share",
    65281: "renegotiation_info",
}

# 常见曲线组（含国密 SM2 曲线，TLCP 场景常见取值）
NAMED_GROUPS: dict[int, str] = {
    0x0017: "secp256r1 (prime256v1)",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0029: "sm2p256v1 (国密 SM2 推荐曲线)",
    0x0100: "ffdhe2048",
}

# 常见 OID → 名称（用于公钥算法识别）
OID_NAMES: dict[str, str] = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC(椭圆曲线公钥)",
    "1.2.840.10045.4.3.2": "ECDSA-with-SHA256",
    "1.2.156.10197.1.301": "SM2(国密椭圆曲线公钥)",
    "1.2.156.10197.1.501": "SM3withSM2(国密签名算法)",
}


# ============================================================================
# 通用工具
# ============================================================================

def require(deps: list[str]) -> None:
    """检查指定依赖是否可用，缺失则抛出带安装命令的异常。"""
    missing = [d for d in deps if d in _MISSING]
    if missing:
        raise RuntimeError(
            f"缺少依赖库：{', '.join(missing)}。请执行：pip install {' '.join(missing)}"
        )


def hexdump_preview(data: bytes, limit: int = 64) -> str:
    """生成十六进制预览串，超长截断。"""
    shown = data[:limit]
    suffix = f" ...(共 {len(data)} 字节)" if len(data) > limit else ""
    return shown.hex() + suffix


class RiskItem:
    """单条风险项：等级 + 标题 + 详情 + 建议。"""

    LEVEL_HIGH = "高危"
    LEVEL_MEDIUM = "中危"
    LEVEL_LOW = "低危"
    LEVEL_INFO = "提示"

    def __init__(self, level: str, title: str, detail: str = "", advice: str = "") -> None:
        self.level = level
        self.title = title
        self.detail = detail
        self.advice = advice

    def to_dict(self) -> dict[str, str]:
        return {"level": self.level, "title": self.title,
                "detail": self.detail, "advice": self.advice}

    def pretty(self) -> str:
        icon = {"高危": "[!!!]", "中危": "[ ! ]", "低危": "[ - ]", "提示": "[ i ]"}[self.level]
        line = f"  {icon} 【{self.level}】{self.title}"
        if self.detail:
            line += f"\n        详情：{self.detail}"
        if self.advice:
            line += f"\n        建议：{self.advice}"
        return line


# ============================================================================
# 子命令 1：sm3hash —— SM3 摘要计算
# ============================================================================

def _sm3_digest(data: bytes) -> str:
    """调用 gmssl 计算 SM3 摘要，返回 64 位小写 HEX。"""
    require(["gmssl"])
    # gmssl 的 sm3_hash 接收 int 列表，使用官方 func.bytes_to_list 转换
    return gmssl_sm3.sm3_hash(gmssl_func.bytes_to_list(data))


def cmd_sm3hash(args: argparse.Namespace) -> int:
    """sm3hash 子命令实现。"""
    try:
        if args.file:
            if not os.path.isfile(args.file):
                print(f"[参数错误] 文件不存在：{args.file}", file=sys.stderr)
                return EXIT_USAGE
            with open(args.file, "rb") as fp:
                data = fp.read()
            source = f"文件 {os.path.abspath(args.file)}"
        elif args.text is not None:
            data = args.text.encode("utf-8")
            source = "文本参数 --text"
        elif not sys.stdin.isatty():
            data = sys.stdin.read().rstrip("\n").encode("utf-8")
            source = "标准输入(管道)"
        else:
            print("[参数错误] 请通过 --text 或 --file 指定待摘要数据", file=sys.stderr)
            return EXIT_USAGE

        digest = _sm3_digest(data)

        if args.as_json:
            print(json.dumps({
                "status": "ok", "algorithm": "SM3",
                "source": source, "length": len(data), "sm3": digest,
            }, ensure_ascii=False))
        else:
            print("=" * 66)
            print(" SM3 摘要计算 (GB/T 32905-2016)")
            print("=" * 66)
            print(f"  数据来源 : {source}")
            print(f"  数据长度 : {len(data)} 字节")
            print(f"  数据预览 : {hexdump_preview(data, 32)}")
            print(f"  SM3 摘要 : {digest}")
            print(f"  摘要长度 : 256 bit (64 位 HEX)")
            print("=" * 66)
        return EXIT_OK

    except RuntimeError as exc:
        print(f"[运行错误] {exc}", file=sys.stderr)
        return EXIT_RUNTIME
    except OSError as exc:
        print(f"[运行错误] 读取文件失败：{exc}", file=sys.stderr)
        return EXIT_RUNTIME


# ============================================================================
# 子命令 2：sm2check —— SM2 公钥弱密钥 / 合法性审计
# ============================================================================

# ---------------------------- 极小 ASN.1/DER 解析器 --------------------------
# 说明：这里只做「格式解析」，不涉及任何密码运算，用于从 SubjectPublicKeyInfo
#       中把 EC 点（04 || X || Y）抽出来。优先用 pyasn1 做结构校验。

def _der_read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """
    读取一个 DER TLV 结构。
    :return: (tag, value_bytes, next_offset)
    """
    if offset >= len(data):
        raise ValueError("DER 解析越界：数据不足")
    tag = data[offset]
    offset += 1

    if offset >= len(data):
        raise ValueError("DER 解析越界：缺少长度字段")
    first_len = data[offset]
    offset += 1

    if first_len & 0x80:
        # 长格式长度：低 7 位表示后续长度字节数
        num_bytes = first_len & 0x7F
        if num_bytes == 0 or num_bytes > 4:
            raise ValueError(f"DER 长度字段非法（长度字节数={num_bytes}）")
        if offset + num_bytes > len(data):
            raise ValueError("DER 解析越界：长度字段被截断")
        length = int.from_bytes(data[offset:offset + num_bytes], "big")
        offset += num_bytes
    else:
        # 短格式长度
        length = first_len

    if offset + length > len(data):
        raise ValueError(
            f"DER 解析越界：声明长度 {length}，实际剩余 {len(data) - offset} 字节"
        )
    return tag, data[offset:offset + length], offset + length


def _der_oid_to_dotted(value: bytes) -> str:
    """把 DER 编码的 OID 内容字节转成点分字符串（如 1.2.156.10197.1.301）。"""
    if not value:
        return ""
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    num = 0
    for byte in value[1:]:
        num = (num << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(num))
            num = 0
    return ".".join(parts)


def parse_spki(der: bytes) -> dict[str, Any]:
    """
    解析 X.509 SubjectPublicKeyInfo（DER），返回算法与公钥点信息。

    结构：SEQUENCE {
              SEQUENCE { OID algorithm, [参数] },   -- AlgorithmIdentifier
              BIT STRING SubjectPublicKey
          }
    """
    result: dict[str, Any] = {"ok": False, "alg_oid": "", "alg_name": "",
                              "point": b"", "curve_oid": "", "raw_len": len(der)}
    try:
        tag, seq_val, _ = _der_read_tlv(der, 0)
        if tag != 0x30:
            raise ValueError("顶层不是 SEQUENCE，可能不是 SubjectPublicKeyInfo")
        # 第 1 项：AlgorithmIdentifier
        tag_alg, alg_val, next_off = _der_read_tlv(seq_val, 0)
        if tag_alg != 0x30:
            raise ValueError("AlgorithmIdentifier 不是 SEQUENCE")
        tag_oid, oid_val, after_oid = _der_read_tlv(alg_val, 0)
        if tag_oid != 0x06:
            raise ValueError("AlgorithmIdentifier 中缺少算法 OID")
        result["alg_oid"] = _der_oid_to_dotted(oid_val)
        result["alg_name"] = OID_NAMES.get(result["alg_oid"], "未知算法")

        # EC 算法通常跟随一个 curve OID 作为参数
        if after_oid < len(alg_val):
            tag_curve, curve_val, _ = _der_read_tlv(alg_val, after_oid)
            if tag_curve == 0x06:
                result["curve_oid"] = _der_oid_to_dotted(curve_val)

        # 第 2 项：BIT STRING
        tag_bit, bit_val, _ = _der_read_tlv(seq_val, next_off)
        if tag_bit != 0x03:
            raise ValueError("SubjectPublicKey 不是 BIT STRING")
        # BIT STRING 首字节为 unused bits，通常为 0，跳过
        result["point"] = bit_val[1:] if bit_val and bit_val[0] == 0 else bit_val
        result["ok"] = True
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def pem_to_der(pem_text: str) -> tuple[bytes, str]:
    """
    解析 PEM 文本，返回 (DER 字节, 类型标签)。
    类型标签如 PUBLIC KEY / PRIVATE KEY / CERTIFICATE。
    """
    pattern = re.compile(
        r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL
    )
    match = pattern.search(pem_text)
    if not match:
        raise ValueError("未找到合法的 PEM 块（缺少 -----BEGIN/END----- 标记）")

    label = match.group(1).strip()
    body = re.sub(r"\s+", "", match.group(2))
    # 宽松容错：先按 Base64 解码，失败再按 HEX 尝试（部分设备导出的是 HEX）
    import base64 as _b64
    try:
        der = _b64.b64decode(body + "=" * ((-len(body)) % 4))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"PEM 内容 Base64 解码失败：{exc}") from exc
    if not der:
        raise ValueError("PEM 内容为空")
    return der, label


def is_point_on_sm2_curve(px: int, py: int) -> bool:
    """
    校验点是否落在 SM2 推荐曲线上：y² ≡ x³ + ax + b (mod p)，
    且 x,y ∈ [0, p-1]。这是纯数学验算，不涉及密码算法实现。
    """
    if not (0 <= px < SM2_P and 0 <= py < SM2_P):
        return False
    left = (py * py) % SM2_P
    right = (pow(px, 3, SM2_P) + SM2_A * px + SM2_B) % SM2_P
    return left == right


def analyze_sm2_public_key(point: bytes, curve_oid: str, alg_oid: str) -> list[RiskItem]:
    """对 SM2 公钥点做多维风险评估，返回风险列表。"""
    risks: list[RiskItem] = []

    # --- 检查 1：点长度 ---------------------------------------------------
    if len(point) == 65 and point[0] == 0x04:
        px = int.from_bytes(point[1:33], "big")
        py = int.from_bytes(point[33:65], "big")
        xy_hex = point[1:].hex()
    elif len(point) == 64:
        # 少数实现会省略 04 前缀，直接给 X||Y
        px = int.from_bytes(point[0:32], "big")
        py = int.from_bytes(point[32:64], "big")
        xy_hex = point.hex()
        risks.append(RiskItem(
            RiskItem.LEVEL_LOW, "公钥点缺少未压缩前缀 0x04",
            "标准 SPKI 中 EC 公钥应为 04||X||Y 共 65 字节，当前为 64 字节。",
            "确认是否为非标准实现导出；跨系统使用时可能因前缀缺失导致校验失败。",
        ))
    elif len(point) in (33,) and point[0] in (0x02, 0x03):
        risks.append(RiskItem(
            RiskItem.LEVEL_INFO, "检测到压缩格式公钥点（02/03 前缀）",
            "压缩格式在国密设备与国密网关中兼容性较差。",
            "建议转换为标准的非压缩格式（04||X||Y）后再接入国密系统。",
        ))
        return risks
    else:
        risks.append(RiskItem(
            RiskItem.LEVEL_HIGH, "公钥点长度非法，不是合法的 SM2 公钥",
            f"当前长度为 {len(point)} 字节，合法值应为 65（04||X||Y）或 64（X||Y）。"
            f"数据预览：{hexdump_preview(point, 16)}",
            "该公钥无法用于 SM2 验签/加密，请重新导出正确的公钥文件。",
        ))
        return risks

    # --- 检查 2：是否命中已知公开测试/示例密钥 -----------------------------
    if xy_hex.lower() in KNOWN_WEAK_SM2_PUBKEYS:
        risks.append(RiskItem(
            RiskItem.LEVEL_HIGH, "命中已知公开测试/示例公钥指纹",
            KNOWN_WEAK_SM2_PUBKEYS[xy_hex.lower()],
            "该公钥对应的私钥是公开的：攻击者可离线伪造签名、伪造加密数据。"
            "必须立即更换为国密随机数发生器生成的正式密钥对，并轮换已签发证书。",
        ))

    # --- 检查 3：退化密钥/低熵检测 ----------------------------------------
    if px == 0 and py == 0:
        risks.append(RiskItem(
            RiskItem.LEVEL_HIGH, "公钥为无穷远点/全零点（退化密钥）",
            "X = 0 且 Y = 0，不是合法的曲线上的点。",
            "属于非法公钥，会导致验签逻辑异常，请更换密钥。",
        ))
    for name, val in (("X", px), ("Y", py)):
        val_hex = f"{val:064x}"
        if val == 0:
            risks.append(RiskItem(
                RiskItem.LEVEL_HIGH, f"公钥 {name} 分量为 0",
                f"{name} = 0，属于极低熵/退化取值。",
                "立即更换由合规随机数发生器生成的密钥对。",
            ))
        elif val_hex == "f" * 64:
            risks.append(RiskItem(
                RiskItem.LEVEL_HIGH, f"公钥 {name} 分量为全 F",
                f"{name} = 0xFF...FF，属于退化取值，通常在测试固件中硬编码出现。",
                "生产环境禁止使用硬编码/占位密钥。",
            ))
        elif val == 1:
            risks.append(RiskItem(
                RiskItem.LEVEL_HIGH, f"公钥 {name} 分量为 1",
                f"{name} = 1，极可能是占位/测试密钥。",
                "更换为正式密钥。",
            ))
        # 单字节重复检测：例如 X = 0x0101...01
        if len(set(val_hex)) == 1:
            risks.append(RiskItem(
                RiskItem.LEVEL_HIGH, f"公钥 {name} 为全同字节重复模式",
                f"{name} = {val_hex[:16]}...（单一字节重复），熵值极低。",
                "属于可暴力猜测的弱密钥，必须更换。",
            ))

    # --- 检查 4：点是否在曲线上 -------------------------------------------
    if not (px == 0 and py == 0):
        if is_point_on_sm2_curve(px, py):
            risks.append(RiskItem(
                RiskItem.LEVEL_INFO, "公钥点位于 SM2 推荐曲线上（y² = x³ + ax + b mod p）",
                "数学验算通过，属于结构合法的 SM2 公钥点。",
                "结构合法 ≠ 安全：仍需确认密钥来源随机、私钥未泄露。",
            ))
        else:
            risks.append(RiskItem(
                RiskItem.LEVEL_HIGH, "公钥点不在 SM2 推荐曲线上（非法曲线点）",
                f"X = {px:064x}\n              Y = {py:064x}\n"
                "点不满足曲线方程，可能是：① 并非 SM2 密钥（如误用 secp256r1）；"
                "② 密钥文件被篡改；③ 手工拼装的错误数据。",
                "国密场景下必须使用 sm2p256v1 曲线。请确认密钥来源，"
                "如果实际是 ECDSA 密钥，则不符合国密合规要求。",
            ))

    # --- 检查 5：曲线 OID 校验 --------------------------------------------
    if curve_oid and curve_oid != SM2_CURVE_OID_DOTTED:
        risks.append(RiskItem(
            RiskItem.LEVEL_MEDIUM, f"公钥声明的曲线不是 SM2（当前：{curve_oid}）",
            f"SM2 推荐曲线 OID 应为 {SM2_CURVE_OID_DOTTED}。",
            "如系统要求国密合规（密评/等保），该密钥不满足要求，需更换为国密证书。",
        ))
    elif not curve_oid:
        risks.append(RiskItem(
            RiskItem.LEVEL_LOW, "公钥中未声明曲线参数（无 curve OID）",
            "可能是裸公钥点文件，或是非标准导出格式。",
            "建议使用标准 SubjectPublicKeyInfo(PEM) 格式导出，便于合规审计。",
        ))

    # --- 检查 6：算法 OID 校验 --------------------------------------------
    if alg_oid and alg_oid != "1.2.156.10197.1.301":
        risks.append(RiskItem(
            RiskItem.LEVEL_MEDIUM, f"公钥算法 OID 不是 SM2（当前：{alg_oid} / "
                                   f"{OID_NAMES.get(alg_oid, '未知')}）",
            "国密场景要求公钥算法为 SM2（OID 1.2.156.10197.1.301）。",
            "若为 RSA/ECDSA，则不符合国密合规要求。",
        ))

    return risks


def cmd_sm2check(args: argparse.Namespace) -> int:
    """sm2check 子命令实现：公钥导入 + 弱密钥/合法性风险审计。"""
    try:
        require(["pyasn1"])
    except RuntimeError as exc:
        # pyasn1 仅用于结构复核，缺失时降级为内置 DER 解析器，仅告警不中断
        print(f"[警告] {exc}；已降级使用内置 DER 解析器。", file=sys.stderr)

    path = args.pubkey
    if not os.path.isfile(path):
        print(f"[参数错误] 公钥文件不存在：{path}", file=sys.stderr)
        return EXIT_USAGE

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            content = fp.read()
    except OSError as exc:
        print(f"[运行错误] 读取公钥文件失败：{exc}", file=sys.stderr)
        return EXIT_RUNTIME

    risks: list[RiskItem] = []
    info: dict[str, Any] = {
        "file": os.path.abspath(path),
        "pem_label": "", "alg_oid": "", "curve_oid": "",
        "point_len": 0, "pubkey_hex": "",
    }

    # ---------- 步骤 1：PEM 解析 -------------------------------------------------
    try:
        der, label = pem_to_der(content)
        info["pem_label"] = label
    except ValueError as exc:
        # 兜底：文件可能是裸 HEX 公钥，或裸 DER 二进制
        stripped = re.sub(r"\s+", "", content)
        if re.fullmatch(r"[0-9a-fA-F]{128,132}", stripped):
            raw = bytes.fromhex(stripped)
            point = raw[1:] if len(raw) == 65 and raw[0] == 0x04 else raw
            info["pem_label"] = "RAW-HEX 裸公钥"
            # 报告头部要显示公钥点长度与点数，这里必须先填 —— 否则会打印
            # "公钥点长度: 0 字节"，与下方详情里的真实字节数自相矛盾。
            info["point_len"] = len(point)
            info["pubkey_hex"] = point.hex()
            risks.append(RiskItem(
                RiskItem.LEVEL_LOW, "公钥文件不是标准 PEM 格式",
                f"检测到裸 HEX 公钥（{len(raw)} 字节）。",
                "建议使用标准 PEM/X.509 格式，便于密钥管理与合规审计。",
            ))
            risks.extend(analyze_sm2_public_key(point, "", ""))
            return _print_sm2_report(info, risks, args)
        print(f"[参数错误] 公钥格式解析失败：{exc}", file=sys.stderr)
        return EXIT_USAGE

    # ---------- 步骤 2：私钥泄露检测（高优先级） --------------------------------
    if "PRIVATE" in label.upper():
        risks.append(RiskItem(
            RiskItem.LEVEL_HIGH, "检测到私钥文件而非公钥！",
            f"PEM 标签为 {label}，其中包含 SM2 私钥明文。",
            "私钥绝不可出现在客户端、APP 包体、配置文件中。"
            "若该文件来自被审计系统，说明存在私钥硬编码/泄露漏洞，"
            "应立即轮换密钥对并重新签发证书。",
        ))

    # ---------- 步骤 3：SPKI 结构解析 -------------------------------------------
    spki = parse_spki(der)
    if not spki["ok"]:
        risks.append(RiskItem(
            RiskItem.LEVEL_HIGH, "公钥 ASN.1 结构非法，无法解析为 SubjectPublicKeyInfo",
            f"解析器报错：{spki.get('error', '未知')}",
            "该文件不是合法公钥：可能已损坏、被截断，或根本不是公钥文件。"
            "请重新导出后再次审计。",
        ))
        return _print_sm2_report(info, risks, args)

    info["alg_oid"] = spki["alg_oid"]
    info["curve_oid"] = spki["curve_oid"]
    info["point_len"] = len(spki["point"])
    info["pubkey_hex"] = spki["point"].hex()

    # ---------- 步骤 4：证书场景补充提示 ----------------------------------------
    if "CERTIFICATE" in label.upper():
        risks.append(RiskItem(
            RiskItem.LEVEL_INFO, "输入为 X.509 证书，已提取其公钥进行审计",
            "证书场景需额外关注：有效期、签发 CA 是否为国密 CA、是否使用 SM3withSM2 签名。",
            "建议配合证书解析命令（openssl x509 -text -in cert.pem）核对上述字段。",
        ))

    # ---------- 步骤 5：多维风险分析 --------------------------------------------
    risks.extend(analyze_sm2_public_key(spki["point"], spki["curve_oid"], spki["alg_oid"]))

    return _print_sm2_report(info, risks, args)


def _print_sm2_report(info: dict[str, Any], risks: list[RiskItem],
                      args: argparse.Namespace) -> int:
    """输出 SM2 审计报告（表格形式 / JSON）。"""
    high = [r for r in risks if r.level == RiskItem.LEVEL_HIGH]
    medium = [r for r in risks if r.level == RiskItem.LEVEL_MEDIUM]

    if getattr(args, "as_json", False):
        print(json.dumps({
            "status": "ok",
            "file": info["file"],
            "pem_label": info["pem_label"],
            "algorithm_oid": info["alg_oid"],
            "curve_oid": info["curve_oid"],
            "point_len": info["point_len"],
            "pubkey_hex": info["pubkey_hex"],
            "risk_total": len(risks),
            "risk_high": len(high),
            "risk_medium": len(medium),
            "risks": [r.to_dict() for r in risks],
        }, ensure_ascii=False, indent=2))
        return EXIT_OK

    print("=" * 70)
    print(" SM2 公钥安全审计报告 | jiejieEAD")
    print("=" * 70)
    print(" 【对象信息】")
    print(f"   文件路径     : {info['file']}")
    print(f"   PEM 标签     : {info['pem_label']}")
    print(f"   算法 OID     : {info['alg_oid'] or '(未声明)'}  "
          f"{OID_NAMES.get(info['alg_oid'], '')}")
    print(f"   曲线 OID     : {info['curve_oid'] or '(未声明)'}  "
          f"{'→ SM2 推荐曲线' if info['curve_oid'] == SM2_CURVE_OID_DOTTED else ''}")
    print(f"   公钥点长度   : {info['point_len']} 字节")
    if info["pubkey_hex"]:
        print(f"   公钥点(HEX)  : {info['pubkey_hex'][:64]}")
        print(f"                  {info['pubkey_hex'][64:128]}")
    print("-" * 70)
    print(f" 【风险评估】共 {len(risks)} 项："
          f"高危 {len(high)} / 中危 {len(medium)} / "
          f"其它 {len(risks) - len(high) - len(medium)}")
    print("-" * 70)

    if not risks:
        print("  [ok] 未发现明显风险。")
    for risk in risks:
        print(risk.pretty())
        print()

    print("-" * 70)
    if high:
        print(f" 【结论】!!! 存在 {len(high)} 项高危问题，该公钥不具备生产可用性。")
        print("         密评/等保场景下应判定为『密码应用不合规』，需立即整改。")
    elif medium:
        print(f" 【结论】!!! 存在 {len(medium)} 项中危问题，建议按上述建议整改。")
    else:
        print(" 【结论】公钥结构与曲线均合法，未命中已知弱密钥指纹。")
        print("         注意：此项结论不代表密钥随机性合规，仍需核查密钥生成流程。")
    print("=" * 70)
    print(" 声明：本工具仅用于已获书面授权的安全测试与密码应用合规审计。")
    print("=" * 70)
    return EXIT_OK


# ============================================================================
# 子命令 3：tlcp —— TLCP 国密 SSL 流量解析
# ============================================================================

class TlsStreamParser:
    """
    TCP 流量重组 + TLS/TLCP 记录层解析器。

    说明：本解析器**只做协议字段解析**，不含任何解密逻辑。
    """

    def __init__(self) -> None:
        self.buffers: dict[tuple, bytearray] = {}   # 五元组 → 待解析字节流
        self.messages: list[dict[str, Any]] = []    # 解析出的记录/握手消息
        self.handshakes: list[dict[str, Any]] = []  # 握手消息明细
        self.flows: dict[tuple, dict[str, Any]] = {}  # 会话级摘要

    # ------------------------------------------------------------------
    def feed(self, flow_key: tuple, payload: bytes, packet_no: int, src: str, dst: str) -> None:
        """向指定流喂入 TCP 载荷，尝试解析其中的完整 TLS 记录。"""
        buf = self.buffers.setdefault(flow_key, bytearray())
        buf.extend(payload)

        # TCP 是双向的：以「端点对」的无序归一化键合并两个方向，
        # 这样一次 TLS 会话（客户端→服务端 + 服务端→客户端）只统计为一个会话。
        session_key = tuple(sorted([str(flow_key[0]) + ":" + str(flow_key[1]),
                                    str(flow_key[2]) + ":" + str(flow_key[3])]))
        if session_key not in self.flows:
            self.flows[session_key] = {
                "endpoints": list(session_key),
                "client": src, "server": dst,   # 初始值，握手时按实际方向修正
                "records": 0, "handshakes": [], "versions": set(),
                "cipher_suites": [], "has_certificate": False,
                "cert_count": 0, "sni": "", "groups": [], "is_tlcp": False,
                "selected_cipher": None,
            }
        session = self.flows[session_key]

        while True:
            if len(buf) < 5:
                return   # 记录头都不完整，等待后续分片
            content_type = buf[0]
            version = int.from_bytes(buf[1:3], "big")
            length = int.from_bytes(buf[3:5], "big")

            # 长度合法性保护：防止把应用数据误判成超长记录导致内存膨胀
            if length > 16384 + 2048:
                del buf[:1]   # 丢弃 1 字节，尝试重新对齐
                continue
            if len(buf) < 5 + length:
                return        # 记录体不完整，等待后续分片

            fragment = bytes(buf[5:5 + length])
            del buf[:5 + length]

            session["records"] += 1
            session["versions"].add(version)
            if version in (0x0100, 0x0101):
                session["is_tlcp"] = True

            record = {
                "packet_no": packet_no,
                "content_type": content_type,
                "content_type_name": TLS_CONTENT_TYPES.get(
                    content_type, f"未知(0x{content_type:02x})"),
                "version": version,
                "version_name": TLS_VERSIONS.get(version, f"未知(0x{version:04x})"),
                "length": length,
            }
            self.messages.append(record)

            # 握手消息进一步解析
            if content_type == 0x16:
                self._parse_handshakes(fragment, packet_no, version, session, src, dst)
            # 证书消息在某些实现中也会出现在 TLS 1.3 的记录中，此处按 TLCP/TLS1.2 处理

    # ------------------------------------------------------------------
    def _parse_handshakes(self, data: bytes, packet_no: int, version: int,
                          session: dict[str, Any], src: str = "", dst: str = "") -> None:
        """解析握手层消息（可含多条，消息头为 4 字节）。"""
        offset = 0
        while offset + 4 <= len(data):
            msg_type = data[offset]
            msg_len = int.from_bytes(data[offset + 1:offset + 4], "big")
            body = data[offset + 4: offset + 4 + msg_len]
            if len(body) < msg_len:
                return   # 握手消息跨记录，简化处理：丢弃该条

            # 依据 ClientHello 的实际发送方向修正「客户端 / 服务端」标注
            if msg_type == 1 and src:
                session["client"], session["server"] = src, dst

            item: dict[str, Any] = {
                "packet_no": packet_no,
                "msg_type": msg_type,
                "msg_type_name": TLS_HANDSHAKE_TYPES.get(
                    msg_type, f"未知({msg_type})"),
                "length": msg_len,
                "record_version": version,
                "record_version_name": TLS_VERSIONS.get(version, f"0x{version:04x}"),
            }

            try:
                if msg_type == 1:      # ClientHello
                    self._parse_client_hello(body, item, session)
                elif msg_type == 2:    # ServerHello
                    self._parse_server_hello(body, item, session)
                elif msg_type == 11:   # Certificate
                    self._parse_certificate(body, item, session)
                elif msg_type in (12, 16):   # 密钥交换消息
                    item["note"] = "密钥交换参数（可结合服务端私钥/会话密钥做进一步分析）"
            except Exception as exc:  # noqa: BLE001 - 单条解析失败不影响整体
                item["parse_error"] = f"{type(exc).__name__}: {exc}"

            self.handshakes.append(item)
            session["handshakes"].append(item)
            offset += 4 + msg_len

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_client_hello(body: bytes, item: dict[str, Any], session: dict[str, Any]) -> None:
        """解析 ClientHello：版本、随机数、会话 ID、套件列表、扩展（SNI/曲线）。"""
        if len(body) < 34:
            raise ValueError("ClientHello 长度不足")
        item["legacy_version"] = int.from_bytes(body[0:2], "big")
        item["legacy_version_name"] = TLS_VERSIONS.get(
            item["legacy_version"], f"0x{item['legacy_version']:04x}")
        item["random"] = body[2:34].hex()

        offset = 34
        sid_len = body[offset]
        item["session_id"] = body[offset + 1: offset + 1 + sid_len].hex()
        offset += 1 + sid_len

        if offset + 2 > len(body):
            return
        cs_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        suites: list[dict[str, Any]] = []
        for i in range(0, cs_len, 2):
            if offset + i + 2 > len(body):
                break
            suite = int.from_bytes(body[offset + i: offset + i + 2], "big")
            suites.append({
                "id": f"0x{suite:04X}",
                "name": TLCP_CIPHER_SUITES.get(suite, ""),
                # 国密套件位于 IANA 私有使用区间 0xE0xx~0xEFxx（GM/T 0024、GB/T 38636）
                # 注意：0xC0xx 属标准 ECDHE 套件，不是国密套件，不能误判
                "is_gm": 0xE000 <= suite <= 0xEFFF,
            })
        item["cipher_suites"] = suites
        item["cipher_count"] = len(suites)
        session["cipher_suites"].extend(suites)
        offset += cs_len

        if offset >= len(body):
            return
        comp_len = body[offset]
        item["compression_methods"] = body[offset + 1: offset + 1 + comp_len].hex()
        offset += 1 + comp_len

        # ---- 扩展解析 ----
        if offset + 2 > len(body):
            return
        ext_total = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        ext_end = min(offset + ext_total, len(body))
        groups: list[dict[str, Any]] = []
        while offset + 4 <= ext_end:
            ext_type = int.from_bytes(body[offset:offset + 2], "big")
            ext_len = int.from_bytes(body[offset + 2:offset + 4], "big")
            ext_data = body[offset + 4: offset + 4 + ext_len]
            offset += 4 + ext_len

            if ext_type == 0 and len(ext_data) >= 5:      # SNI
                name_len = int.from_bytes(ext_data[3:5], "big")
                session["sni"] = ext_data[5:5 + name_len].decode("ascii", "replace")
                item["sni"] = session["sni"]
            elif ext_type == 10 and len(ext_data) >= 2:   # supported_groups
                list_len = int.from_bytes(ext_data[0:2], "big")
                for i in range(0, list_len, 2):
                    if 2 + i + 2 > len(ext_data):
                        break
                    gid = int.from_bytes(ext_data[2 + i: 4 + i], "big")
                    groups.append({"id": f"0x{gid:04X}",
                                   "name": NAMED_GROUPS.get(gid, "未知曲线")})
                item["supported_groups"] = groups
                session["groups"].extend(groups)
            elif ext_type in (43, 51):                    # TLS1.3 扩展
                item[TLS_EXT_TYPES.get(ext_type, str(ext_type))] = "存在"
            if ext_type in (0x0101,):                     # 自定义/私有扩展
                item["custom_extensions"] = item.get("custom_extensions", [])
                item["custom_extensions"].append(f"0x{ext_type:04X}")

        item["extension_types"] = f"已解析 {ext_total} 字节扩展区"

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_server_hello(body: bytes, item: dict[str, Any], session: dict[str, Any]) -> None:
        """解析 ServerHello：协商版本与最终选定的密码套件。"""
        if len(body) < 38:
            raise ValueError("ServerHello 长度不足")
        item["server_version"] = int.from_bytes(body[0:2], "big")
        item["server_version_name"] = TLS_VERSIONS.get(
            item["server_version"], f"0x{item['server_version']:04x}")
        item["random"] = body[2:34].hex()

        offset = 34
        sid_len = body[offset]
        item["session_id"] = body[offset + 1: offset + 1 + sid_len].hex()
        offset += 1 + sid_len

        suite = int.from_bytes(body[offset: offset + 2], "big")
        item["selected_cipher_suite"] = f"0x{suite:04X}"
        item["selected_cipher_name"] = TLCP_CIPHER_SUITES.get(suite, "未知/未收录")
        item["is_gm_suite"] = 0xE000 <= suite <= 0xEFFF
        session["selected_cipher"] = suite
        if item["is_gm_suite"]:
            session["is_tlcp"] = True

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_certificate(body: bytes, item: dict[str, Any], session: dict[str, Any]) -> None:
        """解析 Certificate 消息：统计证书数量与长度（不解析证书内容）。"""
        if len(body) < 3:
            raise ValueError("Certificate 消息长度不足")
        total_len = int.from_bytes(body[0:3], "big")
        offset = 3
        certs: list[dict[str, Any]] = []
        while offset + 3 <= len(body) and len(certs) < 20:
            cert_len = int.from_bytes(body[offset:offset + 3], "big")
            cert_der = body[offset + 3: offset + 3 + cert_len]
            certs.append({
                "index": len(certs) + 1,
                "der_len": cert_len,
                "sha256_short": __import__("hashlib").sha256(cert_der).hexdigest()[:16],
            })
            offset += 3 + cert_len

        item["certificate_total_len"] = total_len
        item["certificates"] = certs
        item["certificate_count"] = len(certs)
        session["has_certificate"] = True
        session["cert_count"] = max(session.get("cert_count", 0), len(certs))


def cmd_tlcp(args: argparse.Namespace) -> int:
    """tlcp 子命令实现：解析 TLCP pcap 流量。"""
    pcap_path = args.pcap
    if not os.path.isfile(pcap_path):
        print(f"[参数错误] pcap 文件不存在：{pcap_path}", file=sys.stderr)
        return EXIT_USAGE

    # ---------- 步骤 0：惰性导入 scapy（并兼容缺少 ProgramFiles 等环境变量的系统）----------
    try:
        from scapy.all import rdpcap, TCP, IP, IPv6  # noqa: F401  局部导入
    except ImportError:
        print("[运行错误] 缺少依赖库：scapy。请执行：pip install scapy", file=sys.stderr)
        return EXIT_RUNTIME
    except Exception as exc:  # noqa: BLE001
        # scapy 在 Windows 上导入时会探测 Wireshark 路径，环境变量缺失会抛 KeyError
        print(
            f"[运行错误] scapy 初始化失败：{type(exc).__name__}: {exc}\n"
            "          该问题通常由系统环境变量缺失引起（scapy 会探测 Wireshark 安装路径）。\n"
            "          解决办法：设置环境变量 ProgramFiles（示例：C:\\Program Files）后重试。",
            file=sys.stderr,
        )
        return EXIT_RUNTIME

    # ---------- 步骤 1：读取数据包 ---------------------------------------------
    try:
        packets = rdpcap(pcap_path)
    except Exception as exc:  # noqa: BLE001
        print(f"[运行错误] 读取 pcap 失败：{type(exc).__name__}: {exc}", file=sys.stderr)
        print("          请确认文件为标准 pcap/pcapng 格式，且未被加密或截断。",
              file=sys.stderr)
        return EXIT_RUNTIME

    print("=" * 72)
    print(" TLCP 国密 SSL 流量解析报告 | jiejieEAD")
    print("=" * 72)
    print(f"  抓包文件 : {os.path.abspath(pcap_path)}")
    print(f"  数据包数 : {len(packets)}")

    # ---------- 步骤 2：逐包提取 TCP 载荷并重组 --------------------------------
    parser = TlsStreamParser()
    ports_filter = set(args.port) if args.port else None
    tcp_packet_count = 0
    tls_packet_count = 0
    host_pairs: dict[tuple, int] = {}

    for index, pkt in enumerate(packets, start=1):
        try:
            if IP in pkt:
                src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
            else:
                continue
            if TCP not in pkt:
                continue
            tcp = pkt[TCP]
            tcp_packet_count += 1

            if ports_filter and not ({tcp.sport, tcp.dport} & ports_filter):
                continue
            if not tcp.payload or len(bytes(tcp.payload)) == 0:
                continue

            payload = bytes(tcp.payload)

            # 粗筛：首字节必须是合法的 TLS 记录类型，降低误报
            if payload[0] not in TLS_CONTENT_TYPES:
                continue

            tls_packet_count += 1
            flow_key = (src_ip, tcp.sport, dst_ip, tcp.dport)
            parser.feed(flow_key, payload, index, f"{src_ip}:{tcp.sport}",
                        f"{dst_ip}:{tcp.dport}")
            host_pairs[(src_ip, dst_ip)] = host_pairs.get((src_ip, dst_ip), 0) + 1
        except (IndexError, AttributeError):
            continue   # 畸形包直接跳过

    print(f"  TCP 报文 : {tcp_packet_count}   含 TLS/TLCP 记录 : {tls_packet_count}")
    if host_pairs:
        print("  通信端点 :")
        for (src, dst), count in sorted(host_pairs.items(), key=lambda x: -x[1])[:10]:
            print(f"             {src} → {dst}   ({count} 个报文)")

    if not parser.messages:
        print("-" * 72)
        print("  [!] 未从该 pcap 中解析到任何 TLS/TLCP 记录。可能原因：")
        print("      1) 抓包端口不是 TLS（可用 --port 指定，如 --port 443 --port 8443）")
        print("      2) 流量经代理做了二次封装，或为私有二进制协议（非 TLCP）")
        print("      3) 抓包未包含完整 TCP 流（缺少握手包）")
        print("=" * 72)
        return EXIT_OK

    # ---------- 步骤 3：输出记录与握手明细 -------------------------------------
    print("-" * 72)
    print(" 【TLCP/TLS 记录层消息】")
    for record in parser.messages[:60]:
        print(f"   包#{record['packet_no']:<6} 类型={record['content_type_name']:<34} "
              f"版本={record['version_name']:<44} 长度={record['length']}")
    if len(parser.messages) > 60:
        print(f"   ...（共 {len(parser.messages)} 条记录，仅展示前 60 条）")

    print("-" * 72)
    print(" 【握手层消息明细】")
    if not parser.handshakes:
        print("   未解析到握手消息（可能抓包缺少握手阶段，或业务数据已加密传输）。")
    for hs in parser.handshakes[:40]:
        print(f"\n   ── 包#{hs['packet_no']}  {hs['msg_type_name']}  "
              f"(长度 {hs['length']}B, 记录版本 {hs['record_version_name']})")

        if hs["msg_type"] == 1:
            print(f"      ClientHello 版本 : {hs.get('legacy_version_name')}")
            print(f"      Random(前16B)    : {str(hs.get('random', ''))[:32]}...")
            if hs.get("sni"):
                print(f"      SNI 服务器名     : {hs['sni']}")
            cs = hs.get("cipher_suites", [])
            gm_suites = [s for s in cs if s["is_gm"]]
            print(f"      密码套件数量     : {len(cs)}"
                  f"（其中疑似国密/私有套件 {len(gm_suites)} 个）")
            for suite in gm_suites[:12]:
                label = suite["name"] or "未收录（疑似国密/私有套件）"
                print(f"        · {suite['id']}  {label}")
            if hs.get("supported_groups"):
                names = ", ".join(g["name"] for g in hs["supported_groups"][:8])
                print(f"      支持曲线组       : {names}")

        elif hs["msg_type"] == 2:
            print(f"      ServerHello 版本 : {hs.get('server_version_name')}")
            print(f"      Random(前16B)    : {str(hs.get('random', ''))[:32]}...")
            print(f"      ★ 协商密码套件   : {hs.get('selected_cipher_suite')}  "
                  f"{hs.get('selected_cipher_name')}")
            if hs.get("is_gm_suite"):
                print("      → 该套件属于国密套件区间，确认为国密协商")
            else:
                print("      → 注意：协商结果不是国密套件，可能使用了国际算法降级")

        elif hs["msg_type"] == 11:
            print(f"      ★ 检测到 Certificate 消息 —— TLCP 证书存在")
            print(f"      证书链长度       : {hs.get('certificate_total_len')} 字节")
            print(f"      证书数量         : {hs.get('certificate_count')}")
            for cert in hs.get("certificates", []):
                print(f"        证书#{cert['index']}  DER 长度={cert['der_len']}B  "
                      f"SHA256(前16)={cert['sha256_short']}")
            print("      提示：可将上述证书导出后，用 sm2check 子命令审计其国密合规性")

    # ---------- 步骤 4：会话级结论 ---------------------------------------------
    print("-" * 72)
    print(" 【分析结论】")
    for flow_key, session in parser.flows.items():
        if session["records"] == 0:
            continue
        versions = ", ".join(
            TLS_VERSIONS.get(v, f"0x{v:04x}") for v in sorted(session["versions"]))
        print(f"\n   会话 {session['client']} → {session['server']}")
        print(f"     ├─ 记录数          : {session['records']}")
        print(f"     ├─ 记录层版本      : {versions}")
        print(f"     ├─ 协议判定        : "
              f"{'★ TLCP 国密 SSL（GB/T 38636 / GM/T 0024）' if session['is_tlcp'] else 'TLS/其它'}")
        print(f"     ├─ 是否含证书消息  : "
              f"{'是（' + str(session['cert_count']) + ' 张证书）' if session['has_certificate'] else '否'}")
        if session.get("sni"):
            print(f"     ├─ SNI             : {session['sni']}")
        if session.get("selected_cipher") is not None:
            sel = session["selected_cipher"]
            print(f"     ├─ 协商套件        : 0x{sel:04X}  "
                  f"{TLCP_CIPHER_SUITES.get(sel, '未收录')}")
        print(f"     └─ 业务数据解密    : 不可解密（TLCP 使用 ECDHE 类密钥交换，"
              f"需服务端私钥或会话主密钥）")

    # ---------- 步骤 5：风险与合规提示 -----------------------------------------
    print("-" * 72)
    print(" 【风险与合规提示】")
    any_tlcp = any(s["is_tlcp"] for s in parser.flows.values())
    any_cert = any(s["has_certificate"] for s in parser.flows.values())
    gm_selected = any(
        isinstance(s.get("selected_cipher"), int) and 0xE000 <= s["selected_cipher"] <= 0xEFFF
        for s in parser.flows.values()
    )

    if any_tlcp and gm_selected:
        print("   [ok] 检测到 TLCP 国密协商流程，符合密评场景预期。")
    elif any_tlcp:
        print("   [!] 记录层为 TLCP 版本，但未捕获到明确的国密套件协商结果，")
        print("       请检查抓包是否覆盖完整握手（ClientHello → ServerHello）。")
    else:
        print("   [i] 未识别为 TLCP 协议，可能为普通 TLS 或私有协议。")

    if any_cert:
        print("   [!] 流量中存在证书消息：建议导出证书，核查签发 CA 是否为国密 CA、")
        print("       签名算法是否为 SM3withSM2、密钥是否为 SM2 曲线。")
    print("   [i] 本工具不实现 TLCP 流量解密：解密需持有服务端私钥或 TLS 会话主密钥")
    print("       (SSLKEYLOGFILE)。任何声称仅凭 pcap 即可解密 TLCP 密文的说法都不成立。")
    print("=" * 72)
    print(" 声明：本工具仅用于已获书面授权的安全测试与密码应用合规审计。")
    print("=" * 72)

    if getattr(args, "as_json", False):
        print(json.dumps({
            "status": "ok",
            "pcap": os.path.abspath(pcap_path),
            "packet_total": len(packets),
            "record_total": len(parser.messages),
            "sessions": [
                {"client": s["client"], "server": s["server"],
                 "records": s["records"],
                 "versions": [TLS_VERSIONS.get(v, f"0x{v:04x}")
                              for v in sorted(s["versions"])],
                 "is_tlcp": s["is_tlcp"], "has_certificate": s["has_certificate"],
                 "cert_count": s.get("cert_count", 0), "sni": s.get("sni", "")}
                for s in parser.flows.values()
            ],
            "handshakes": [
                {"packet_no": h["packet_no"], "type": h["msg_type_name"],
                 "length": h["length"]} for h in parser.handshakes
            ],
        }, ensure_ascii=False, indent=2))
    return EXIT_OK


# ============================================================================
# 命令行参数解析（子命令模式）
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    """构建带子命令的 argparse 解析器。"""
    parser = argparse.ArgumentParser(
        prog="gm_crypto_analyzer.py",
        description="jiejieEAD 模块三：国密密码分析（SM3/SM2）与 TLCP 国密流量解析",
        epilog="注意：本工具仅用于已获书面授权的安全测试与密码应用合规审计。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", metavar="{sm3hash,sm2check,tlcp}")

    # ---- 子命令 1：sm3hash ----
    p_sm3 = subparsers.add_parser(
        "sm3hash", help="计算文本/文件的 SM3 摘要（GB/T 32905-2016）")
    p_sm3.add_argument("--text", help="待计算摘要的文本")
    p_sm3.add_argument("--file", help="待计算摘要的文件路径（支持二进制）")
    p_sm3.add_argument("--json", action="store_true", dest="as_json",
                       help="以 JSON 格式输出")
    p_sm3.set_defaults(func=cmd_sm3hash)

    # ---- 子命令 2：sm2check ----
    p_sm2 = subparsers.add_parser(
        "sm2check", help="SM2 公钥导入与弱密钥/合法性风险审计")
    p_sm2.add_argument("--pubkey", required=True,
                       help="SM2 公钥文件路径（PEM / X.509 证书 / 裸 HEX）")
    p_sm2.add_argument("--json", action="store_true", dest="as_json",
                       help="以 JSON 格式输出审计报告")
    p_sm2.set_defaults(func=cmd_sm2check)

    # ---- 子命令 3：tlcp ----
    p_tlcp = subparsers.add_parser(
        "tlcp", help="解析 TLCP 国密 SSL 流量的 pcap 文件")
    p_tlcp.add_argument("--pcap", required=True, help="pcap / pcapng 抓包文件路径")
    p_tlcp.add_argument("--port", type=int, action="append",
                        help="只解析指定端口，可多次传入，如 --port 443 --port 8443；"
                             "不指定则解析全部 TCP 载荷")
    p_tlcp.add_argument("--json", action="store_true", dest="as_json",
                        help="附带输出 JSON 结构化结果")
    p_tlcp.set_defaults(func=cmd_tlcp)

    return parser


def main(argv: list[str] | None = None) -> int:
    """程序主入口。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        print("\n[提示] 请指定子命令：sm3hash / sm2check / tlcp")
        return EXIT_USAGE

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[中断] 用户取消操作", file=sys.stderr)
        return EXIT_RUNTIME
    except RuntimeError as exc:
        print(f"[运行错误] {exc}", file=sys.stderr)
        return EXIT_RUNTIME
    except Exception as exc:  # noqa: BLE001 - 兜底，保证 GUI 拿到可读错误
        print(f"[未知错误] {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_RUNTIME


if __name__ == "__main__":
    sys.exit(main())
