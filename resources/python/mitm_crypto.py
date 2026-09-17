#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
================================================================================
 jiejieEAD | 模块二：mitmproxy 中间人自动加解密脚本
 文件：mitm_crypto.py
================================================================================

【免责声明】
    本工具仅用于拥有书面授权的安全测试、安全研究。未授权对系统进行渗透、
    破解属于违法行为。使用者需自行承担因违规使用产生的一切法律责任。

【适用场景】
    APP 渗透 / 护网实战中，接口 Body 全量密文（SM4 / AES256 + Base64）导致
    无法直接改包。本脚本让 mitmproxy 在中间自动完成「解密 → 明文透传给
    mitmweb → 人工改包 → 自动加密回注」的闭环，省去 CyberChef 反复复制粘贴。

【数据流】
    客户端 ──密文──▶ mitmproxy ──[base64解码 → 解密]──▶ mitmweb 展示明文
                        ▲                                     │
                        └────[加密 → base64编码]◀── 人工修改后的明文 ◀┘
                                        ▼
                                   服务端

【启动方式】
    # 命令行交互版（mitmproxy TUI）
    mitmproxy  -s mitm_crypto.py -p 8080

    # Web 界面版（推荐，配合浏览器改包更直观）
    mitmweb    -s mitm_crypto.py -p 8080 --web-port 8081

    # 只对特定域名生效（也可在下方 CONFIG 的 TARGET_HOSTS 中配置）
    mitmweb    -s mitm_crypto.py --set "ignore_hosts=^(?!api\.example\.com).*$"

【依赖】
    pip install mitmproxy pycryptodome gmssl
================================================================================
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import sys
import time

try:
    from mitmproxy import ctx, http      # mitmproxy 核心对象与事件钩子
    _MITMPROXY_AVAILABLE = True
except ImportError:  # 允许在未安装 mitmproxy 时直接运行做「配置自检」
    ctx = None
    http = None
    _MITMPROXY_AVAILABLE = False

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover
    AES = None

try:
    from gmssl import sm4 as gmssl_sm4
except ImportError:  # pragma: no cover
    gmssl_sm4 = None

# ----------------------------------------------------------------------------
# 共享密码引擎：加解密能力（算法/模式/填充）统一来自 crypto_core.py，
# 避免「扫描器认得的模式，插件却不支持」的能力漂移。
# 被 mitmproxy 以 -s 加载时脚本目录未必在 sys.path，故显式插入。
# ----------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import crypto_core as cc
except ImportError as _cc_exc:  # pragma: no cover
    cc = None  # type: ignore
    _CC_IMPORT_ERROR = _cc_exc
else:
    _CC_IMPORT_ERROR = None


# ============================================================================
# ★★★ 配置区（按需修改，代码其余部分无需改动）★★★
# ============================================================================

CONFIG = {
    # ---------------- 目标域名白名单 ------------------------------------
    # 仅对列表内的 Host 做加解密；其余域名的流量原样放行，避免污染其它业务。
    # 支持精确匹配与后缀匹配：写入 "example.com" 可匹配 a.example.com
    "TARGET_HOSTS": [
        "api.example.com",      # TODO: 替换为实际渗透目标域名
        "app.example.com",
    ],

    # ---------------- 算法与密钥 ----------------------------------------
    # 算法：sm4 / aes128 / aes192 / aes256 / des / des3 / rc4 / rc5 / rc6 / blowfish / cast5 / rc2 / chacha20 / salsa20
    "ALG": "sm4",
    # 工作模式：ecb / cbc / cfb / ofb / ctr / gcm（rc4 固定 stream）
    "MODE": "cbc",
    # 填充：pkcs7 / zero / none / iso7816 / ansix923（仅 ecb/cbc 生效）
    "PADDING": "pkcs7",
    # 密钥 / IV 均为 HEX 字符串，长度随算法而定：
    #   SM4/AES-128 → KEY 32 位 HEX，AES-192 → 48 位，AES-256 → 64 位
    #   DES → 16 位，3DES → 48 位，RC4 → 10~512 位（且无需 IV）
    #   IV：AES/SM4 = 32 位 HEX；DES/3DES = 16 位 HEX；
    #       GCM 用 12 字节（24 位 HEX）nonce；ECB 与 RC4 不需要 IV
    "KEY": "0123456789abcdeffedcba9876543210",
    "IV":  "00000000000000000000000000000000",

    # ---------------- 编码开关 ------------------------------------------
    # 接口 Body 在密文之外是否还套了一层 Base64：
    #   True  → 先 base64 解码再解密（请求）；加密后再 base64 编码（响应）
    #   False → Body 直接是二进制/HEX 密文，不做 base64 处理
    "ENABLE_BASE64": True,

    # 若密文以 HEX 文本形态出现在 Body 中，可把此项设为 "hex"（与 Base64 互斥）
    # 可选："base64" / "hex" / "none"
    "BODY_ENCODING": "base64",

    # ---------------- 生效方向 ------------------------------------------
    "DECRYPT_REQUEST": True,    # 解密请求体，供人工阅读/修改
    "ENCRYPT_RESPONSE": True,   # 加密响应体，返回给客户端

    # ---------------- 匹配规则 ------------------------------------------
    # 仅处理这些 Content-Type 的请求（空列表 = 不限制）
    "CONTENT_TYPES": ["application/json", "text/plain", "application/octet-stream"],

    # 跳过这些路径（探针、心跳、静态资源等），支持前缀匹配
    "SKIP_PATHS": ["/health", "/ping", "/favicon.ico", "/static/"],

    # ---------------- 调试 ----------------------------------------------
    "VERBOSE": True,            # 控制台实时打印解密后的明文
    "LOG_MAX_LEN": 4000,        # 单条日志明文最大打印长度，防止刷屏
}

# ============================================================================
# 常量
# ============================================================================

BLOCK_SIZE = 16
AES256_KEY_LEN = 32
SM4_KEY_LEN = 16
IV_LEN = 16


# ============================================================================
# 外部配置注入（供 jiejieEAD 桌面 GUI 使用）
# ----------------------------------------------------------------------------
# GUI（Tauri）启动代理时，会把界面上的配置序列化为 JSON，通过环境变量传入：
#     JIEJIEEAD_MITM_CONFIG       = JSON 字符串（优先级高）
#     JIEJIEEAD_MITM_CONFIG_FILE  = JSON 文件路径（优先级次之）
# 键名使用前端驼峰命名（hosts / port / webPort / alg / key / iv / bodyEncoding /
# decryptRequest / encryptResponse），此处映射到本文件的 CONFIG 结构。
# 命令行直接使用（mitmweb -s mitm_crypto.py）时不传环境变量，走文件顶部配置区。
# ============================================================================

def _apply_external_config() -> None:
    """从环境变量读取 GUI 注入的配置并覆盖 CONFIG。"""
    raw = os.environ.get("JIEJIEEAD_MITM_CONFIG", "").strip()
    if not raw:
        cfg_file = os.environ.get("JIEJIEEAD_MITM_CONFIG_FILE", "").strip()
        if cfg_file and os.path.isfile(cfg_file):
            try:
                with open(cfg_file, "r", encoding="utf-8") as fp:
                    raw = fp.read()
            except OSError as exc:
                log_warn(f"读取 GUI 配置文件失败，改用文件顶部默认配置：{exc}")
                return

    if not raw:
        return   # 无外部配置：使用文件顶部 CONFIG

    try:
        external = json.loads(raw)
    except json.JSONDecodeError as exc:
        log_warn(f"GUI 注入配置不是合法 JSON，已忽略：{exc}")
        return

    # 键名映射：前端驼峰 → CONFIG 键
    mapping = {
        "hosts": "TARGET_HOSTS",
        "alg": "ALG",
        "mode": "MODE",
        "padding": "PADDING",
        "key": "KEY",
        "iv": "IV",
        "keyFormat": "KEY_FORMAT",
        "ivFormat": "IV_FORMAT",
        "bodyEncoding": "BODY_ENCODING",
        "decryptRequest": "DECRYPT_REQUEST",
        "encryptResponse": "ENCRYPT_RESPONSE",
    }
    applied: list[str] = []
    for src_key, dst_key in mapping.items():
        if src_key in external and external[src_key] not in (None, ""):
            CONFIG[dst_key] = external[src_key]
            applied.append(dst_key)

    # bodyEncoding 与旧开关 ENABLE_BASE64 保持同步，避免两处配置冲突
    if "BODY_ENCODING" in applied:
        CONFIG["ENABLE_BASE64"] = str(CONFIG["BODY_ENCODING"]).lower() == "base64"

    log_info(f"已从 GUI 注入配置：{', '.join(applied) if applied else '（无有效字段）'}")


# ============================================================================
# 密码运算（与 cli_crypto.py 保持同一套填充与 CBC 组装逻辑）
# ============================================================================

def _resolved_spec_mode_padding():
    """
    把 CONFIG 解析成 (AlgoSpec, mode, padding)。

    统一在这里处理三件事，避免各处重复判断：
      · 流密码（RC4）模式固定 stream、且不需要 IV；
      · 流式模式（cfb/ofb/ctr/gcm）填充强制 none；
      · 族名（aes / des3）按密钥长度定位到具体算法。
    解析失败时抛异常（由 _validate_config 在启动阶段提前暴露）。
    """
    if cc is None:
        raise RuntimeError(
            "缺少共享密码引擎 crypto_core.py"
            f"（{_CC_IMPORT_ERROR}）——请确认该文件与 mitm_crypto.py 在同一目录"
        )
    alg = str(CONFIG.get("ALG", "sm4")).lower()
    key_len = len(_key_bytes())
    spec = cc.get_spec_by_keylen(alg, key_len)

    mode = str(CONFIG.get("MODE") or "cbc").lower()
    if spec.is_stream:
        mode = cc.MODE_STREAM
    mode, padding, _ = cc.normalize_mode_padding(
        spec, mode, str(CONFIG.get("PADDING") or "pkcs7"))
    return spec, mode, padding


def _key_format() -> str:
    """密钥文本格式：hex / utf8 / base64 / auto（默认 hex，向后兼容）。"""
    return str(CONFIG.get("KEY_FORMAT") or "hex").lower()


def _iv_format() -> str:
    return str(CONFIG.get("IV_FORMAT") or "hex").lower()


def _key_bytes() -> bytes:
    """按配置的格式解析密钥（真实业务里密钥常是 UTF-8 字面量而非 HEX）。"""
    return cc.parse_key_material(str(CONFIG["KEY"]), _key_format(), "CONFIG['KEY']")


def _iv_bytes() -> bytes:
    raw = str(CONFIG.get("IV") or "")
    if not raw:
        return b""
    return cc.parse_key_material(raw, _iv_format(), "CONFIG['IV']")


def _resolved_mode_padding() -> tuple[str, str]:
    """仅取 (模式, 填充)。"""
    _spec, mode, padding = _resolved_spec_mode_padding()
    return mode, padding


def crypto_encrypt(plain: bytes) -> bytes:
    """按配置加密明文，返回密文字节（GCM 会在末尾附带 16 字节认证标签）。"""
    _spec, mode, padding = _resolved_spec_mode_padding()
    return cc.do_crypt(
        alg=str(CONFIG["ALG"]).lower(), op="enc",
        key_hex=str(CONFIG["KEY"]), iv_hex=str(CONFIG.get("IV") or ""),
        data=plain, mode=mode, padding=padding, warn_weak=False,
        key_format=_key_format(), iv_format=_iv_format(),
    )


def crypto_decrypt(cipher_bytes: bytes) -> bytes:
    """
    按配置解密密文，返回去填充后的明文。

    任何失败都会抛出异常，绝不静默返回乱码 —— 这是本插件相对 gmssl 原生
    crypt_cbc 的关键改进（后者去填充不校验，错误密钥会「成功」解出乱码，
    在渗透测试中制造假阳性）。
    """
    _spec, mode, padding = _resolved_spec_mode_padding()
    return cc.do_crypt(
        alg=str(CONFIG["ALG"]).lower(), op="dec",
        key_hex=str(CONFIG["KEY"]), iv_hex=str(CONFIG.get("IV") or ""),
        data=cipher_bytes, mode=mode, padding=padding, warn_weak=False,
        key_format=_key_format(), iv_format=_iv_format(),
    )



# ============================================================================
# 日志输出：统一前缀，方便 GUI 端按行解析回显
# ============================================================================

def _now() -> str:
    return time.strftime("%H:%M:%S")


def log_info(message: str) -> None:
    print(f"[{_now()}][jiejieEAD][INFO ] {message}", flush=True)


def log_hit(message: str) -> None:
    print(f"[{_now()}][jiejieEAD][HIT  ] {message}", flush=True)


def log_warn(message: str) -> None:
    print(f"[{_now()}][jiejieEAD][WARN ] {message}", flush=True)


def log_error(message: str) -> None:
    print(f"[{_now()}][jiejieEAD][ERROR] {message}", flush=True)


def log_plain(prefix: str, text: str) -> None:
    """打印明文内容（带长度截断，避免刷屏）。"""
    if not CONFIG["VERBOSE"]:
        return
    limit = CONFIG["LOG_MAX_LEN"]
    shown = text if len(text) <= limit else f"{text[:limit]} ...(已截断，总长 {len(text)})"
    print(f"[{_now()}][jiejieEAD][PLAIN] {prefix}: {shown}", flush=True)


# ============================================================================
# Body 编解码：Base64 / HEX / RAW 三种形态
# ============================================================================

def body_to_cipher(raw: bytes) -> bytes:
    """把原始 Body 还原为二进制密文（按 BODY_ENCODING 剥壳）。"""
    mode = CONFIG["BODY_ENCODING"].lower()
    if mode == "none":
        return raw
    text = raw.decode("utf-8", errors="ignore").strip()
    if mode == "base64":
        cleaned = text.replace("\n", "").replace("\r", "").replace(" ", "")
        cleaned += "=" * ((-len(cleaned)) % 4)   # 补全 Base64 填充符
        return base64.b64decode(cleaned)
    if mode == "hex":
        return binascii.unhexlify(text)
    raise ValueError(f"未知的 BODY_ENCODING：{mode}")


def cipher_to_body(cipher_bytes: bytes) -> bytes:
    """把二进制密文重新包装成 Body（按 BODY_ENCODING 加壳）。"""
    mode = CONFIG["BODY_ENCODING"].lower()
    if mode == "none":
        return cipher_bytes
    if mode == "base64":
        return base64.b64encode(cipher_bytes)
    if mode == "hex":
        return cipher_bytes.hex().encode("ascii")
    raise ValueError(f"未知的 BODY_ENCODING：{mode}")


# ============================================================================
# mitmproxy 插件主体
# ============================================================================

class CryptoCryptoAddon:
    """
    mitmproxy Addon：对命中白名单的业务接口自动加解密。

    生命周期：
        load()    → 插件加载，打印配置摘要
        running() → mitmproxy 就绪
        request() → 请求阶段：解密 Body，明文透传给 mitmweb
        response()→ 响应阶段：把（可能被人工改过的）明文加密回客户端
    """

    # ------------------------------------------------------------------
    # 生命周期钩子
    # ------------------------------------------------------------------
    def load(self, loader) -> None:  # noqa: ARG002 - mitmproxy 固定签名
        """插件加载时执行：先合并 GUI 注入配置，再校验并打印配置摘要。"""
        if not _MITMPROXY_AVAILABLE:
            raise RuntimeError(
                "缺少 mitmproxy 库，无法作为插件运行。请执行：pip install mitmproxy"
            )
        _apply_external_config()
        self._validate_config()
        log_info("=" * 66)
        log_info(" jiejieEAD MITM 自动加解密插件已加载")
        log_info(f"  目标域名   : {', '.join(CONFIG['TARGET_HOSTS']) or '(未配置)'}")
        log_info(f"  算法       : {CONFIG.get('ALG', '').upper()} / "
                 f"模式 {str(CONFIG.get('MODE', '')).upper()} / "
                 f"填充 {cc.PAD_DISPLAY.get(CONFIG.get('PADDING'), CONFIG.get('PADDING'))}")
        log_info(f"  Key(HEX)   : {CONFIG['KEY']}")
        if str(CONFIG.get("IV") or ""):
            log_info(f"  IV (HEX)   : {CONFIG['IV']}")
        log_info(f"  Body 编码  : {CONFIG['BODY_ENCODING']}  "
                 f"(旧开关 ENABLE_BASE64={CONFIG['ENABLE_BASE64']})")
        log_info(f"  处理方向   : 请求解密={CONFIG['DECRYPT_REQUEST']}  "
                 f"响应加密={CONFIG['ENCRYPT_RESPONSE']}")
        log_info("=" * 66)

    def running(self) -> None:
        """mitmproxy 完全启动后回调。"""
        log_info("代理已就绪，请将目标 APP / 浏览器流量指向本代理。")

    def done(self) -> None:
        """插件卸载。"""
        log_info("插件已卸载，加解密拦截停止。")

    # ------------------------------------------------------------------
    # 内部工具方法
    # ------------------------------------------------------------------
    @staticmethod
    def _validate_config() -> None:
        """启动前校验配置合法性，尽早暴露密钥长度/模式/填充等低级错误。"""
        if cc is None:
            raise RuntimeError(
                "缺少共享密码引擎 crypto_core.py"
                f"（{_CC_IMPORT_ERROR}）——请确认该文件与 mitm_crypto.py 在同一目录"
            )

        # ENABLE_BASE64 与 BODY_ENCODING 的一致性兼容处理
        if not CONFIG["ENABLE_BASE64"] and CONFIG["BODY_ENCODING"] == "base64":
            CONFIG["BODY_ENCODING"] = "none"

        alg = str(CONFIG["ALG"]).lower()
        # 密钥长度 → 定位具体算法 → 校验模式/填充/IV 是否匹配
        # 注意：密钥文本要先按 KEY_FORMAT 解析（真实业务里常是 UTF-8 字面量，
        # 按 HEX 解会短一半，直接报「密钥长度不合法」）
        key = _key_bytes()
        spec = cc.get_spec_by_keylen(alg, len(key))
        cc.validate_key(spec, key)

        mode = str(CONFIG.get("MODE") or "cbc").lower()
        padding = str(CONFIG.get("PADDING") or "pkcs7").lower()
        if spec.is_stream:
            mode = cc.MODE_STREAM
            CONFIG["IV"] = ""
        mode, padding, _ = cc.normalize_mode_padding(spec, mode, padding)
        CONFIG["MODE"], CONFIG["PADDING"] = mode, padding

        iv = _iv_bytes() \
            if CONFIG.get("IV") else b""
        cc.validate_iv(spec, mode, iv)

        if not CONFIG["TARGET_HOSTS"]:
            log_warn("TARGET_HOSTS 为空：当前会拦截所有域名，请确认这是预期行为！")

    @staticmethod
    def _is_target(flow: http.HTTPFlow) -> bool:
        """判断该流量是否属于需要加解密的目标。"""
        host = (flow.request.pretty_host or "").lower()
        path = flow.request.path or ""

        # 条件 1：域名白名单（精确匹配或后缀匹配）
        hosts = [h.lower() for h in CONFIG["TARGET_HOSTS"]]
        if hosts:
            host_ok = any(host == h or host.endswith("." + h) for h in hosts)
            if not host_ok:
                return False

        # 条件 2：路径黑名单（前缀匹配）
        if any(path.startswith(p) for p in CONFIG["SKIP_PATHS"]):
            return False

        return True

    @staticmethod
    def _content_type_ok(flow: http.HTTPFlow) -> bool:
        """校验 Content-Type 是否在关注范围。"""
        allowed = CONFIG["CONTENT_TYPES"]
        if not allowed:
            return True
        ctype = (flow.request.headers.get("Content-Type", "") or "").lower()
        return any(a.lower() in ctype for a in allowed)

    @staticmethod
    def _is_cipher_like(body: bytes) -> bool:
        """
        粗筛：判断 Body 是否“像”密文，避免把明文接口误当密文处理。

        判据随模式而变（不能一律要求 16 字节整数倍）：
          · 分组模式 ECB/CBC → 长度必须是分组字节数的整数倍
          · GCM            → 至少要有 16 字节认证标签
          · 其它流式模式    → 长度不限（CFB/OFB/CTR/RC4 都是逐字节的）
        """
        if not body:
            return False
        try:
            cipher_bytes = body_to_cipher(body)
        except Exception:
            return False
        if not cipher_bytes:
            return False

        try:
            spec, mode, _padding = _resolved_spec_mode_padding()
        except Exception:
            # 配置尚未就绪（例如还没走 validate_config），退回最保守的判据
            return len(cipher_bytes) % BLOCK_SIZE == 0

        if mode in cc.BLOCK_MODES:
            return len(cipher_bytes) % spec.block == 0
        if mode == cc.MODE_GCM:
            return len(cipher_bytes) > 16
        return True

    # ------------------------------------------------------------------
    # 请求阶段：解密
    # ------------------------------------------------------------------
    def request(self, flow: http.HTTPFlow) -> None:
        """请求流过代理时触发：解密 Body，让 mitmweb 展示可读明文。"""
        if not CONFIG["DECRYPT_REQUEST"]:
            return
        if not self._is_target(flow):
            return
        if not self._content_type_ok(flow):
            return

        raw_body = flow.request.content or b""
        if not raw_body or not self._is_cipher_like(raw_body):
            # 非密文（可能是登录、探针等明文接口），原样放行
            if CONFIG["VERBOSE"] and raw_body:
                log_info(f"[放行] 非密文请求 {flow.request.method} {flow.request.pretty_url}")
            return

        try:
            cipher_bytes = body_to_cipher(raw_body)
            plain = crypto_decrypt(cipher_bytes)
            plain_text = plain.decode("utf-8", errors="replace")

            # 把明文写回 flow，mitmweb 中即可直接阅读并手工修改
            flow.request.content = plain_text.encode("utf-8")
            # 去掉可能存在的 content-encoding，避免 mitmproxy 二次解压报错
            flow.request.headers.pop("Content-Encoding", None)
            if "json" not in flow.request.headers.get("Content-Type", "").lower():
                flow.request.headers["Content-Type"] = "application/json"

            # 记录状态：响应阶段需要知道这条流是否被我们解密过
            flow.metadata["jiejieead_decrypted"] = True

            log_hit(
                f"[请求][解密成功] {flow.request.method} {flow.request.pretty_url}  "
                f"密文 {len(cipher_bytes)}B → 明文 {len(plain)}B"
            )
            log_plain("请求明文", plain_text)

        except Exception as exc:  # 解密失败不能让流量中断，放行原始密文并告警
            log_error(
                f"[请求][解密失败] {flow.request.pretty_url} → {type(exc).__name__}: {exc}；"
                "已按原始密文放行（请检查 ALG / KEY / IV / BODY_ENCODING 配置）"
            )

    # ------------------------------------------------------------------
    # 响应阶段：加密
    # ------------------------------------------------------------------
    def response(self, flow: http.HTTPFlow) -> None:
        """响应流过代理时触发：把明文（含人工修改）加密后返回客户端。"""
        if not CONFIG["ENCRYPT_RESPONSE"]:
            return
        if not self._is_target(flow):
            return
        if flow.response is None:
            return
        # 仅处理被我们解密过的流，避免把服务端本就返回的明文响应误加密
        if not flow.metadata.get("jiejieead_decrypted"):
            return

        raw_body = flow.response.content or b""
        if not raw_body:
            return

        try:
            # 响应阶段：Body 已是明文（人工可在 mitmweb 中直接修改）
            plain_bytes = raw_body
            cipher_bytes = crypto_encrypt(plain_bytes)
            packed = cipher_to_body(cipher_bytes)

            flow.response.content = packed
            flow.response.headers.pop("Content-Encoding", None)
            flow.response.headers["Content-Type"] = "application/octet-stream"
            flow.response.headers["Content-Length"] = str(len(packed))
            # 清除可能影响长度的头部
            flow.response.headers.pop("Transfer-Encoding", None)

            log_hit(
                f"[响应][加密成功] {flow.request.method} {flow.request.pretty_url}  "
                f"明文 {len(plain_bytes)}B → 密文 {len(cipher_bytes)}B "
                f"({CONFIG['BODY_ENCODING']} 后 {len(packed)}B)"
            )
            log_plain("响应明文", plain_bytes.decode("utf-8", errors="replace"))

        except Exception as exc:
            log_error(
                f"[响应][加密失败] {flow.request.pretty_url} → {type(exc).__name__}: {exc}；"
                "已原样返回服务端响应"
            )


# ============================================================================
# mitmproxy 插件注册入口
# ============================================================================

addons = [CryptoCryptoAddon()]

# 便于脱离 mitmproxy 直接运行做配置自检：python mitm_crypto.py
if __name__ == "__main__":
    try:
        # 支持通过环境变量注入配置，先做一次合并（与 GUI 启动路径一致）
        _apply_external_config()
        CryptoCryptoAddon._validate_config()

        print("=" * 66)
        print(" mitm_crypto.py 配置自检")
        print("=" * 66)
        _spec, _mode, _pad = _resolved_spec_mode_padding()
        print(f"  算法       : {_spec.display}")
        print(f"  模式/填充  : {_mode.upper()} / {cc.PAD_DISPLAY.get(_pad, _pad)}")
        print(f"  Body 编码  : {CONFIG['BODY_ENCODING']}")
        print(f"  目标域名   : {', '.join(CONFIG['TARGET_HOSTS']) or '(全部域名)'}")

        demo = '{"username":"admin","password":"P@ssw0rd","token":"abc123"}'.encode()
        enc = crypto_encrypt(demo)
        dec = crypto_decrypt(enc)
        assert dec == demo, "自检失败：往返不一致"
        print(f"  明文       : {demo.decode()}")
        print(f"  密文(HEX)  : {enc.hex()}")
        print(f"  密文(Body) : {cipher_to_body(enc)[:96]!r}")
        print("  [ OK ] 加解密往返一致")

        # 错误密钥检出能力：取决于「模式 + 填充」是否自带完整性校验。
        #   · GCM / PKCS#7 / ISO7816 / ANSIX923 → 错误密钥应被自动检出，否则视为缺陷
        #   · Zero / NoPadding / CFB / OFB / CTR / RC4 → 密码学上无法检出，
        #     只能提示使用者人工核对明文，而不是把"未报错"当成"密钥正确"
        if cc.has_integrity_check(_mode, _pad):
            # 错误密钥长度跟随当前算法（3DES 需保证等长且不退化）
            wrong_key = "".join("%02x" % ((i * 31 + 200) % 256)
                                for i in range(len(_key_bytes())))
            original_key = CONFIG["KEY"]
            CONFIG["KEY"] = wrong_key
            try:
                crypto_decrypt(enc)
                print("  [FAIL] 错误密钥未被检出（存在静默乱码风险）")
                sys.exit(2)
            except Exception:  # crypto_core 抛 CryptoUsageError / CryptoRuntimeError
                print("  [ OK ] 错误密钥被明确检出（去填充 / 认证校验生效）")
            finally:
                CONFIG["KEY"] = original_key
        else:
            print("  [注意] 当前组合不含完整性校验，错误密钥无法自动检出：")
            print(f"         {cc.integrity_warning(_mode, _pad)}")

        if not _MITMPROXY_AVAILABLE:
            print("  [提示] 未安装 mitmproxy，仅完成配置自检。")
            print("         作为插件运行前请执行：pip install mitmproxy")
        print("=" * 66)
        print(" 启动方式：mitmweb -s mitm_crypto.py -p 8080 --web-port 8081")
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] 配置自检失败：{type(exc).__name__}: {exc}")
        sys.exit(2)
