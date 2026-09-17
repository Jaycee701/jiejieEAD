#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jiejieEAD | 密文一键分析解密（贴一段密文 → 自动识别逻辑 → 尝试解密 → 输出明文与依据）
================================================================================

解决的是日常最常遇到的那句话：**「我手上只有一段密文，不知道它怎么来的」**。

本模块把前面几件工具串成一条自动流水线：

  ① 形态识别     整段 HTTP / 裸 base64 / 裸 base64url / 裸 HEX / URL 编码 /
                 种子前置（32hex+密文） / JSON 混合信封 / 混杂文本
  ② 常量获取     从「你粘贴的文本」「指定的目标目录或 JS 文件」「本地知识库」三处挖
                 （复用 key_material_analyzer：伪装 base64、定长切片、派生链）
  ③ 字段解析     按定长切片拿 AES 常量/IV、取报文里前置的随机种子
  ④ 配方编排     按「种子 → 密钥派生 → 对称解密 → 编码/压缩还原 → mac 校验」生成候选方案
  ⑤ 逐个试解     每个候选都跑一遍，明文按「UTF-8 合法性 / 可打印比例 / JSON 结构 /
                 业务字段名 / mac 是否对上」打分，mac 对上直接判定为确定结论
  ⑥ 输出结论     明文 + 逐步解密逻辑 + 依据（哪一步验证通过）+ 失败尝试的原因

设计原则（与工具其它部分一致）：
  · **绝不把乱码当成功**：明文必须过 UTF-8 与可打印阈值，否则判失败并说明原因；
  · **结论可复核**：每条结论都附「依据」与「复现命令」（能手工跑一遍）；
  · **常量不预置**：本模块不内置任何目标的密钥；常量只从你提供的材料里来，
    或在本地知识库（crypto_knowledge.json）里命中。
  · 纯离线、纯标准库 + 工具自带引擎。

用法：
  python cipher_auto_solver.py --text "<密文>" [--target-dir <目标目录>] [--json]
  python cipher_auto_solver.py --file <密文文件> --target-dir <目标目录>
  python cipher_auto_solver.py --selftest
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import crypto_core as cc            # noqa: E402
import key_material_analyzer as kma  # noqa: E402

# 明文打分时认为「像业务报文」的字段名（命中越多越可信）
BIZ_HINTS = (
    "reqhead", "reqdata", "reqhead", "rescode", "respcode", "resmsg",
    "txcd", "bizsceneno", "chnlno", "clienttraceno", "trancode", "appid",
    "requesttime", "menuid", "rsu", "sid", "mac", "busi", "acctno", "amt",
)
MAX_PLAIN_BYTES = 4 * 1024 * 1024     # 单次解密结果上限（防炸）
MAX_RECIPES = 900                     # 单一帧解释的候选方案上限（防组合爆炸）
MAX_ATTEMPTS = 400                    # 返回给界面的尝试记录上限（只影响展示，不影响试解）

# 源码里"命名密钥字面量"的关键词（真实前端几乎都这么写）
# 注意顺序即优先级：`priv` 必须排在 `key` 前面，否则 `PRIVATE_KEY`
# 会先被 key 规则吃掉（"privatekey" 也在 key 的提示词里）。
LITERAL_NAME_HINTS = {
    "priv": ("privatekey", "privkey", "priv", "private", "serverkey", "rsapriv",
             "sm2priv", "secretkey"),
    "key": ("key", "aeskey", "sm4key", "deskey", "des3key", "secret", "secretkey",
            "encryptkey", "appkey", "skey", "cryptkey"),
    "iv": ("iv", "nonce", "vector", "aesiv", "sm4iv", "ivhex", "ivstr"),
    "aad": ("aad", "associateddata", "additionaldata", "aadstr"),
    "seed": ("seed", "nonce", "rand", "random", "salt"),
}
# 多行 PEM 私钥（原来按单行字面量抓不到 —— LITERAL_RE 是单行的）
PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[A-Za-z0-9+/=\s]+?-----END \1-----")

# JSON 信封：哪个字段是被包裹的密钥、哪个是密文、哪个是 IV（按优先级排列）
ENV_KEY_FIELDS = ("enckey", "encryptkey", "encryptedkey", "wrappedkey", "wrapkey",
                  "keyenc", "sked", "skey", "rsk", "secretkey", "key")
ENV_DATA_FIELDS = ("encdata", "ciphertext", "cipher", "content", "payload", "body",
                   "data", "ct", "ed", "msg", "text")
ENV_IV_FIELDS = ("iv", "ivhex", "nonce", "vector")
LITERAL_RE = re.compile(r"""([A-Za-z_$][A-Za-z0-9_$.]{1,48})\s*[:=]\s*["']([^"'\n]{4,512})["']""")


# ============================================================================
# 一、形态识别
# ============================================================================
def _b64_len_ok(s: str) -> bool:
    t = re.sub(r"\s", "", s or "")
    return len(t) >= 16 and len(t) % 4 == 0 and bool(re.fullmatch(r"[A-Za-z0-9+/=]+", t))


def _hex32(s: str) -> bool:
    return len(s or "") == 32 and bool(re.fullmatch(r"[0-9a-fA-F]{32}", s))


def _try_b64(s: str) -> bytes | None:
    t = re.sub(r"[\s]", "", s or "")
    t += "=" * ((-len(t)) % 4)
    try:
        return base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return None


def _looks_b64url(t: str) -> bool:
    """看起来像 Base64URL / 去填充的 Base64。

    判据：出现 `-` / `_`；或者末尾没有 `=` 但长度 %4 余 2/3（就是去掉了填充）。
    """
    if re.search(r"[-_]", t or ""):
        return True
    return (not (t or "").endswith("=")) and len(t or "") % 4 in (2, 3)


def _b64_decode_any(s: str) -> bytes | None:
    """把 Base64 / Base64URL / 去填充 三种写法统一解码（解码失败返回 None）。"""
    t = re.sub(r"\s", "", s or "").replace("-", "+").replace("_", "/")
    t += "=" * ((-len(t)) % 4)
    try:
        return base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return None


def _norm_field(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


# 主抽取规则：≥120 字符的连续串直接当密文候选（长 token 基本不可能是别的东西）
LONG_RUN_RE = re.compile(r"[A-Za-z0-9+/=_-]{120,}")
# 放宽规则：长 token 找不到时，降到 44 字符（≈32 字节）再找一遍
SHORT_RUN_RE = re.compile(r"[A-Za-z0-9+/=]{44,}")
# 放宽规则下，解码结果的可打印比例高于此值就判为「源码常量」而不是密文
SHORT_RUN_MAX_PRINTABLE = 0.85


def _extract_short_cipher_run(text: str) -> str:
    """没有 ≥120 字符的长 token 时，再放宽一档找密文段。

    密文完全可能短于 120 字符（≈89 字节明文），和源码粘在一起时主规则就抽不出来。
    这里降到 44 字符（32 字节）再找一遍，并加两道闸把「源码里的普通字符串」滤掉：

      · **解码后不可打印** —— data URI 伪装常量、明文字符串解码出来是可读文本；
      · **解码后长度是 8 的倍数且 ≥16 字节** —— 密文按分组对齐，
        而源码里的长标识符/驼峰名解出来是 38、39、51 这类零散长度。

    两道闸都不改变主规则（≥120 字符）的行为，只作用于这条放宽路径。
    """
    def plausible(cand: str) -> bool:
        blk = _b64_decode_any(cand)
        if not blk or len(blk) < 16 or len(blk) % 8:
            return False      # 放宽规则只认分组对齐的密文长度
        printable = sum(1 for b in blk if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
        return printable / len(blk) <= SHORT_RUN_MAX_PRINTABLE

    best = ""
    for m in SHORT_RUN_RE.findall(text or ""):
        if len(m) <= len(best):
            continue
        # 候选可能本身就是「32 位 hex 前缀 + 密文」的组合形态（此时整段解码必然
        # 不是分组对齐的），所以整段不成时，剥掉 32 位 hex 前缀再判一次。
        if plausible(m) or (re.match(r"[0-9a-fA-F]{32}", m) and plausible(m[32:])):
            best = m
    return best


def _pick_field(fields: dict, order: tuple) -> str:
    """在 JSON 的字段里按优先级挑一个（先精确名，再前缀/包含）。"""
    for want in order:
        for k in fields:
            if _norm_field(k) == want:
                return k
    for want in order:
        for k in fields:
            if want in _norm_field(k):
                return k
    return ""


def _guess_encoding(text: str) -> tuple[str, bytes] | None:
    """猜一段文本是 HEX 还是 Base64，返回 (编码名, 字节)。"""
    t = re.sub(r"\s", "", text or "")
    if len(t) >= 16 and len(t) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", t):
        try:
            return "hex", bytes.fromhex(t)
        except ValueError:
            pass
    raw = _b64_decode_any(t)
    if raw:
        return "base64", raw
    return None


def _parse_json_envelope(raw: str) -> dict | None:
    """把一段 JSON 认成「混合信封」：包裹密钥 + IV + 对称密文。"""
    try:
        obj = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    fields = {k: v for k, v in obj.items()
              if isinstance(v, str) and len(v) >= 8 and not v.startswith("http")}
    if len(fields) < 2:
        return None
    key_f = _pick_field(fields, ENV_KEY_FIELDS)
    data_f = _pick_field(fields, ENV_DATA_FIELDS)
    if not key_f or not data_f or key_f == data_f:
        return None
    iv_f = _pick_field(fields, ENV_IV_FIELDS)
    k_guess = _guess_encoding(fields[key_f])
    d_guess = _guess_encoding(fields[data_f])
    if not d_guess:
        return None
    iv_hex = ""
    if iv_f:
        iv_guess = _guess_encoding(fields[iv_f])
        if iv_guess and len(iv_guess[1]) in (8, 12, 16):
            iv_hex = iv_guess[1].hex()
        elif 8 <= len(fields[iv_f]) <= 24:
            iv_hex = fields[iv_f].encode("utf-8").hex()
    return {
        "kind": "json-envelope",
        "envelope": {
            "key_field": key_f, "key_text": fields[key_f],
            "key_encoding": (k_guess or ("base64", b""))[0],
            "key_bytes": len((k_guess or ("", b""))[1]),
            "data_field": data_f, "cipher_text": fields[data_f],
            "data_encoding": d_guess[0],
            "iv_field": iv_f, "iv_hex": iv_hex,
            "other_fields": sorted(set(fields) - {key_f, data_f} - ({iv_f} if iv_f else set())),
        },
        "cipher_text": fields[data_f],
        "mac_b64": "",
        "label": ("JSON 混合信封（字段 %s = 包裹密钥 / %s = 对称密文%s）"
                  % (key_f, data_f, " / %s = IV" % iv_f if iv_f else "")),
    }


def detect_frames(text: str) -> list[dict]:
    """识别密文的「外形」，返回**所有合理解释**（通常 1 个，歧义形状 2~3 个）。

    为什么返回多个：`<32 位 hex><Base64>` 这种形状天生是歧义的 ——

      · 它可能是 **32hex 前缀 + mac 形态**：前 32 位是 16 字节标识，末尾 44 字符是 mac；
      · 也可能是**种子前置**：前 32 位就是本次请求的随机种子，整段尾巴才是密文；
      · 尾巴的最后 44 字符也可能**只是密文的一部分**，跟 mac 无关。

    形态上根本区分不了（长度都合法），所以这里不硬猜，而是把几种解释都产出，
    交给后面的「明文打分 + mac 校验」来裁决 —— mac 能对上就是硬证据。
    """
    raw = (text or "").strip()
    frame: dict = {"kind": "unknown", "raw_len": len(raw), "notes": []}

    # ---- 整段 HTTP：只取 body ----
    if "\n\n" in raw or "\r\n\r\n" in raw:
        for sep in ("\r\n\r\n", "\n\n"):
            if sep in raw:
                raw = raw.split(sep, 1)[1].strip()
                frame["notes"].append("输入像整段 HTTP 报文，已取 body 部分")
                break
    flat = re.sub(r"\s", "", raw)

    # ---- 0) 抽出「token 形状」的连续串：密文常常和源码/日志粘在一起 ----
    # 注意字符集要含 -_（Base64URL），否则带 -_ 的密文会被从中间截断。
    runs = re.findall(r"[A-Za-z0-9+/=_-]{120,}", raw)
    best_run = max(runs, key=len) if runs else ""
    if best_run and len(best_run) < len(flat):
        frame["notes"].append("输入里混有其它文本，已自动抽出其中的长密文段（%d 字符）"
                              % len(best_run))
        # 注：这里只记一条提示，**不要**立刻对密文段重新识别 ——
        # 否则 JSON 信封之类的整段形态会被里面的长 base64 段抢走（实测踩过）。
        # 真正的"切段重识别"放在最后兜底处。

    # ---- ⓪ JSON 混合信封：{"encKey": <包裹密钥>, "iv": ..., "data": <对称密文>} ----
    # 这是国密前端最标准的写法（随机对称密钥 + 非对称包裹，两字段一起传）。
    # 放在最前面判，因为 JSON 起手就是 `{`，不可能与后面的形态混淆。
    if raw.startswith("{") and raw.endswith("}"):
        env = _parse_json_envelope(raw)
        if env:
            f = dict(frame)
            f.update(env)
            return [f]

    # ---- ② 纯 HEX：**必须排在最前** ----
    # 纯 hex 串既满足 base64 字符集，也符合 `<32hex><base64>` 的形状，
    # 只要排在后面就会被切错密文（实测 05/11 就是这么失败的）。
    if len(flat) >= 32 and len(flat) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", flat):
        f = dict(frame)
        f.update({
            "kind": "raw-hex", "cipher_text": flat,
            "cipher_bytes": bytes.fromhex(flat),
            "label": "裸 HEX 密文（无报文框架）",
        })
        return [f]

    # ---- ②b URL 编码（encodeURIComponent(base64(ct)) 很常见）----
    if re.search(r"%[0-9A-Fa-f]{2}", flat):
        import urllib.parse
        try:
            unq = urllib.parse.unquote_to_bytes(flat).decode("latin-1")
        except Exception:  # noqa: BLE001
            unq = ""
        if unq and len(unq) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", unq):
            f = dict(frame)
            f.update({
                "kind": "raw-url", "cipher_text": flat, "cipher_after_url": unq,
                "label": "URL 编码密文（%XX 转义，解出来是 Base64/HEX 文本）",
            })
            return [f]

    # ---- ③ Base64URL / 去填充 Base64 ----
    if (len(flat) >= 16 and _looks_b64url(flat)
            and re.fullmatch(r"[A-Za-z0-9+/=_-]+", flat)):
        raw_bytes = _b64_decode_any(flat)
        if raw_bytes:
            f = dict(frame)
            f.update({
                "kind": "raw-base64url", "cipher_text": flat,
                "cipher_bytes": raw_bytes,
                "label": "裸 Base64URL 密文（含 -_ 或去掉了 = 填充）",
            })
            return [f]

    # ---- ④ `<32hex><Base64>`：歧义形状 → 产出多个解释 ----
    m_seed = re.match(r"^([0-9a-fA-F]{32})([A-Za-z0-9+/=]{16,})$", flat)
    if m_seed and len(flat) % 4 == 0:
        h32, tail = m_seed.group(1), m_seed.group(2)
        views: list[dict] = []

        def view(**kw) -> dict:
            f = dict(frame)
            f["cipher_text"] = tail
            f["hex32"] = h32
            f.update(kw)
            return f

        # 种子前置：整段尾巴都是密文，前 32 位当种子
        views.append(view(
            kind="seed-prefix", seed=h32.lower(),
            label="种子前置密文（前 32 字符是种子明文，其后是 Base64 密文）",
        ))
        return views

    # ---- ⑤ 裸 Base64 ----
    if _b64_len_ok(flat):
        raw_bytes = _try_b64(flat)
        f = dict(frame)
        f.update({
            "kind": "raw-base64", "cipher_text": flat,
            "cipher_bytes": raw_bytes or b"",
            "label": "裸 Base64 密文（无报文框架）",
        })
        return [f]

    # ---- ⑥ 兜底：上面全都没认出来，但其中有一段长 token 能解出字节 → 按裸编码处理。
    # 这样"任何密文"都至少能进解密矩阵试一轮，而不是在形态识别这一步就放弃
    # （试错由后面的明文打分兜底：解不出可读内容照样判失败）。
    # 长 token 找不到时再放宽一档 —— 短密文（≲89 字节明文）与源码粘在一起
    # 是最常见的粘贴形态，主规则（≥120 字符）会整个漏掉。
    cand_src = best_run
    if not cand_src:
        cand_src = _extract_short_cipher_run(raw)
        if cand_src:
            frame["notes"].append(
                "未找到长密文段，已按放宽规则抽出 %d 字符的候选" % len(cand_src))
    if cand_src:
        # ★ 兜底第一步：把抽出来的密文段**当成独立输入**重新判形态。
        # 源码/日志混在一起时整段的形状必然不成立，不切段就会丢掉"种子前缀"这类切分。
        if len(cand_src) < len(flat):
            sub = detect_frames(cand_src)
            if sub and sub[0].get("kind") != "unknown":
                for x in sub:
                    x.setdefault("notes", []).append(
                        "输入里混有其它文本，已自动抽出其中的密文段（%d 字符）"
                        % len(cand_src))
                    x["mixed_text"] = True
                return sub
        cand = re.sub(r"\s", "", cand_src).strip("\"'")
        blob = _b64_decode_any(cand)
        if blob and len(blob) >= 8:
            f = dict(frame)
            f.update({
                "kind": "raw-base64", "cipher_text": cand, "cipher_bytes": blob,
                "label": "裸 Base64 密文（从混杂文本中自动抽出）",
            })
            f["notes"].append("形态不典型，已按「抽出密文段 + Base64 解码」兜底处理")
            return [f]
        cand2 = re.sub(r"[\s:\"']", "", cand)
        if len(cand2) >= 32 and len(cand2) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", cand2):
            f = dict(frame)
            f.update({
                "kind": "raw-hex", "cipher_text": cand2, "cipher_bytes": bytes.fromhex(cand2),
                "label": "裸 HEX 密文（从混杂文本中自动抽出）",
            })
            f["notes"].append("形态不典型，已按「抽出密文段 + HEX 解码」兜底处理")
            return [f]

    frame["label"] = "无法识别的形态（既不是规整的报文框架，也不是 Base64/HEX）"
    frame["notes"].append("提示：若密文带前缀、data: 伪装，或存在换行截断，请检查后重试")
    return [frame]


def detect_frame(text: str) -> dict:
    """兼容入口：只要「最可能」的那一种解释（多解场景取第一个）。"""
    frames = detect_frames(text)
    return frames[0] if frames else {"kind": "unknown", "label": "空输入", "notes": []}


def extract_named_literals(text: str) -> dict:
    """从源码里提取"命名密钥字面量"。

    真实前端最常见的写法其实是：
        var AES_KEY = "4A7F2C1E9B3D5A08";
        var IV = "C6B1D90E37F2A485";
        var aad = "appid=9988&v=1";
    这些**不是** base64/hex 伪装常量，靠"解码可疑串"那套是抓不到的，必须按变量名抓。
    同一个值的解释方式可能不止一种（16 个字符既是 16 字节 UTF-8，也可能是 8 字节 HEX），
    所以这里把三种解释都收下，交给后面的配方去试。
    """
    out = {"key": [], "iv": [], "aad": [], "seed": [], "priv": []}
    if not text:
        return out
    seen = set()
    for m in LITERAL_RE.finditer(text):
        name, value = m.group(1).lower(), m.group(2)
        role = None
        for r, hints in LITERAL_NAME_HINTS.items():
            if any(h in name for h in hints):
                role = r
                break
        if not role:
            continue
        key = (role, value)
        if key in seen:
            continue
        seen.add(key)
        out[role].append(value)
    return out


def find_private_keys(text: str) -> list[dict]:
    """抓源码里的 PEM 私钥（多行，单行字面量正则抓不到）。"""
    out: list[dict] = []
    for m in PEM_RE.finditer(text or ""):
        out.append({"kind": m.group(1).strip(), "value": m.group(0)})
    return out


def literal_variants(value: str) -> list[dict]:
    """把一个字面量按 HEX / Base64 / UTF-8 三种方式解释成字节（都可能对）。"""
    res: list[dict] = []
    clean = re.sub(r"[\s:\-]", "", value or "")
    if 16 <= len(clean) <= 256 and len(clean) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", clean):
        try:
            raw = bytes.fromhex(clean)
            res.append({"as": "hex", "bytes": raw})
        except ValueError:
            pass
    raw_b64 = _try_b64(value)
    if raw_b64 and 5 <= len(raw_b64) <= 256:
        res.append({"as": "base64", "bytes": raw_b64})
    try:
        raw_u8 = value.encode("utf-8")
        if 5 <= len(raw_u8) <= 256:
            res.append({"as": "utf8", "bytes": raw_u8})
    except Exception:  # noqa: BLE001
        pass
    return res


# ============================================================================
# 二、材料（常量 / 种子 / 切片）获取
# ============================================================================
def materials_from_text(text: str) -> dict:
    """从**粘贴的文本**里挖常量：伪装 base64、定长切片、派生链线索。"""
    out = {"source": [], "constants": {}, "slices": [], "chains": [], "seeds": [],
           "literals": {"key": [], "iv": [], "aad": [], "seed": [], "priv": []},
           "private_keys": []}
    if not text:
        return out
    out["private_keys"] = find_private_keys(text)
    if out["private_keys"]:
        out["source"].append("粘贴文本里的 PEM 私钥（%d 个）" % len(out["private_keys"]))
    try:
        disguised = kma.find_disguised_base64(text)
        chains = kma.find_derive_chains(text)
    except Exception:  # noqa: BLE001
        return out
    for item in disguised:
        src = "粘贴文本"
        for sl in item.get("slices", []):
            entry = dict(sl)
            entry["source"] = src
            entry["from_text_len"] = item.get("decoded_len")
            out["slices"].append(entry)
        # 67 字符的 32+16+16+3 拼法：除了切片角色之外，再直接抽出两块 16 字节材料，
        # 作为派生链的候选 key/iv（有些目标的常量不带 data: 前缀，切片角色认不出来）
        text_val = item.get("decoded_text") or ""
        if len(text_val) == 67 and text_val[64:].isdigit():
            out["constants"].setdefault("secret_a", text_val[32:48])
            out["constants"].setdefault("secret_b", text_val[48:64])
        elif len(text_val) == 64:
            out["constants"].setdefault("secret_a", text_val[:32])
            out["constants"].setdefault("secret_b", text_val[32:64])
        out["source"].append("粘贴文本里的伪装常量（%d 字符，已切成候选密钥/IV）"
                             % len(text_val))
    out["chains"] = chains
    out["literals"] = extract_named_literals(text)
    return out


def materials_from_path(path: str) -> dict:
    """从目标目录 / 单个文件里挖常量、派生链与命名密钥字面量。"""
    out = {"source": [], "constants": {}, "slices": [], "chains": [], "seeds": [],
           "literals": {"key": [], "iv": [], "aad": [], "seed": [], "priv": []},
           "private_keys": []}
    if not path or not os.path.exists(path):
        return out
    try:
        res = kma.analyze_dir(path) if os.path.isdir(path) else kma.analyze_file(path)
    except Exception:  # noqa: BLE001
        return out

    def eat(item, origin):
        # 与 materials_from_text 同口径：67 / 64 字符定长常量直接抽出两块 16 字节材料
        text_val = item.get("decoded_text") or ""
        if len(text_val) == 67 and text_val[64:].isdigit():
            out["constants"].setdefault("secret_a", text_val[32:48])
            out["constants"].setdefault("secret_b", text_val[48:64])
            out["source"].append("目标里的 67 字符常量（%s）" % os.path.basename(str(origin)))
        elif len(text_val) == 64:
            out["constants"].setdefault("secret_a", text_val[:32])
            out["constants"].setdefault("secret_b", text_val[32:64])
        for sl in item.get("slices", []):
            entry = dict(sl)
            entry["source"] = os.path.basename(str(origin))
            out["slices"].append(entry)

    for item in res.get("disguised", []) or []:
        eat(item, item.get("origin", ""))
    for sub in res.get("files", []) or []:
        for item in sub.get("disguised", []) or []:
            eat(item, item.get("origin", ""))
    for chain in res.get("derive_chains", []) or []:
        out["chains"].append(chain)
        bound = chain.get("bound_constants") or {}
        if bound.get("derive_key"):
            out["constants"].setdefault("kdf_key", bound["derive_key"])
        if bound.get("derive_iv"):
            out["constants"].setdefault("kdf_iv", bound["derive_iv"])
    # 源码里的命名密钥字面量（AES_KEY / IV / aad …）单独抽一遍
    for fp in ([path] if os.path.isfile(path) else
               [os.path.join(dp, f) for dp, _, fs in os.walk(path) for f in fs
                if os.path.splitext(f)[1].lower() in
                (".js", ".mjs", ".cjs", ".ts", ".vue", ".java", ".py", ".php", ".kt", ".txt")]):
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        lits = extract_named_literals(content)
        for role, vals in lits.items():
            for v in vals:
                if v not in out["literals"][role]:
                    out["literals"][role].append(v)
        for pk in find_private_keys(content):
            if not any(x["value"] == pk["value"] for x in out["private_keys"]):
                pk["file"] = os.path.basename(fp)
                out["private_keys"].append(pk)
    if any(out["literals"].values()):
        out["source"].append("目标源码里的命名密钥字面量（AES_KEY / IV / aad 等）")
    if out["private_keys"]:
        out["source"].append("目标源码里的 PEM 私钥（%s）"
                             % "、".join(sorted({pk.get("file", "?")
                                                 for pk in out["private_keys"]})))
    if out["constants"] or out["chains"]:
        out["source"].append("目标路径：%s" % path)
    return out


def merge_materials(*parts: dict) -> dict:
    out = {"source": [], "constants": {}, "slices": [], "chains": [], "seeds": [],
           "literals": {"key": [], "iv": [], "aad": [], "seed": [], "priv": []},
           "private_keys": []}
    for part in parts:
        if not part:
            continue
        for pk in part.get("private_keys") or []:
            if not any(x["value"] == pk["value"] for x in out["private_keys"]):
                out["private_keys"].append(pk)
        for role, vals in (part.get("literals") or {}).items():
            for v in vals:
                if v not in out["literals"][role]:
                    out["literals"][role].append(v)
        out["source"].extend(part.get("source") or [])
        out["slices"].extend(part.get("slices") or [])
        out["chains"].extend(part.get("chains") or [])
        out["seeds"].extend(part.get("seeds") or [])
        for k, v in (part.get("constants") or {}).items():
            out["constants"].setdefault(k, v)
    # 同一份常量可能在多个文件里出现 → 来源去重（否则界面上一串重复）
    seen, uniq = set(), []
    for src in out["source"]:
        if src in seen:
            continue
        seen.add(src)
        uniq.append(src)
    out["source"] = uniq
    # 合并派生链里挖到的常量（作为 KDF 常量兜底）
    for chain in out["chains"]:
        bound = chain.get("bound_constants") or {}
        if bound.get("derive_key"):
            out["constants"].setdefault("kdf_key", bound["derive_key"])
        if bound.get("derive_iv"):
            out["constants"].setdefault("kdf_iv", bound["derive_iv"])
    return out


def _derive_sliced(seed: str, preset: str, sl, *, key: str = "", iv: str = "") -> dict:
    """按预设派生，并保证 `sl` 指定的切片**真的生效**。

    踩过的坑：引擎里 `digest-sha256` / `digest-sm3` / `digest-md5` 这几个预设
    只含一个 digest 步骤，**没有 slice 步骤** —— 直接往 `derive_key_by_preset`
    传 `slice_start/slice_end` 会被静默忽略，于是标着「SHA256(种子)[0:16]」的候选
    实际产出 32 字节，拿去当 SM4 密钥就必然解不开（样本 12 就是这么失败的）。
    这里显式补一个 slice 步骤，让标签和真实行为一致。
    """
    sl = sl or (None, None)
    steps = cc.build_kdf_steps(preset, key=key, iv=iv,
                               key_format=cc.KEY_UTF8, iv_format=cc.KEY_UTF8,
                               slice_start=sl[0], slice_end=sl[1])
    if sl[0] is not None and not any(st.get("op") == "slice" for st in steps):
        steps = list(steps) + [{"op": "slice", "start": sl[0], "end": sl[1]}]
    return cc.derive_key(seed, steps, cc.KEY_UTF8)


def _kdf_variants(seed: str, materials: dict, frame: dict) -> list[dict]:
    """给定种子，列出所有值得一试的派生方式。"""
    out: list[dict] = []
    if not seed:
        return out
    consts = materials.get("constants") or {}
    # 常量来源：① 派生链绑定的 kdf_key/kdf_iv；② 通用兜底 —— 伪装常量切出来的
    # 「16 字节密钥 × 16 字节 IV」的所有组合（不再依赖任何特定目标的固定字段名）
    pairs: list[tuple[str, str]] = []
    if consts.get("kdf_key") and consts.get("kdf_iv"):
        pairs.append((str(consts["kdf_key"]), str(consts["kdf_iv"])))
    slices = materials.get("slices") or []
    key_slices = [str(x.get("value") or "") for x in slices
                  if len(str(x.get("value") or "")) == 16 and "密钥" in str(x.get("role") or "")]
    iv_slices = [str(x.get("value") or "") for x in slices
                 if len(str(x.get("value") or "")) == 16 and "IV" in str(x.get("role") or "")]
    for ks in key_slices[:3]:
        for ivs in iv_slices[:3]:
            if (ks, ivs) not in pairs:
                pairs.append((ks, ivs))

    # ① 双层派生标准链：SHA256(AES-128-CBC(种子, 常量密钥, 常量 IV))，再取区间
    for kdf_key, kdf_iv in pairs[:6]:
        for preset, label, sl in (("aes-cbc-then-sha256-slice",
                                   "AES-128-CBC(种子)→SHA256→[16:32]", (16, 32)),
                                  ("aes-cbc-then-sha256",
                                   "AES-128-CBC(种子)→SHA256（整段 32 字节）", (0, 32))):
            try:
                r = _derive_sliced(seed, preset, sl, key=kdf_key, iv=kdf_iv)
            except Exception:  # noqa: BLE001
                continue
            out.append({"name": label, "kind": "derived", "key_hex": r["output_hex"],
                        "key_bytes": r["output_len"], "seed": seed, "preset": preset,
                        "kdf_key": kdf_key, "kdf_iv": kdf_iv, "trace": r.get("trace") or []})
        try:
            m = _derive_sliced(seed, "aes-cbc-then-sha256", None,
                               key=kdf_key, iv=kdf_iv)
            if m["output_len"] == 32:
                for c in out:
                    if not c.get("master_hex") and c.get("kdf_key") == kdf_key:
                        c["master_hex"] = m["output_hex"]
        except Exception:  # noqa: BLE001
            pass

    # ② 通用摘要派生：SHA256/SM3/MD5(种子) 再取前 16 / 前 32 / 中间 16 字节
    for preset, sl, label in (("digest-sha256", (0, 16), "SHA256(种子)[0:16]"),
                              ("digest-sha256", (0, 32), "SHA256(种子) 全 32 字节"),
                              ("digest-sha256", (16, 32), "SHA256(种子)[16:32]"),
                              ("digest-sha256", (0, 24), "SHA256(种子)[0:24]"),
                              ("digest-sm3", (0, 16), "SM3(种子)[0:16]"),
                              ("digest-sm3", (0, 32), "SM3(种子) 全 32 字节"),
                              ("digest-sm3", (16, 32), "SM3(种子)[16:32]"),
                              ("digest-md5", (0, 16), "MD5(种子) 全 16 字节"),
                              ("digest-sha512", (0, 16), "SHA512(种子)[0:16]"),
                              ("digest-sha512", (0, 32), "SHA512(种子)[0:32]")):
        try:
            r = _derive_sliced(seed, preset, sl)
        except Exception:  # noqa: BLE001
            continue
        out.append({"name": label, "kind": "derived-plain", "key_hex": r["output_hex"],
                    "key_bytes": r["output_len"], "seed": seed, "preset": preset,
                    "trace": r.get("trace") or []})

    # ③ 目标里识别出的派生链（含跨文件绑定的常量）
    for chain in materials.get("chains") or []:
        preset = chain.get("suggest_preset")
        bound = chain.get("bound_constants") or {}
        if not preset:
            continue
        sl = next((st for st in (chain.get("steps") or []) if st.get("op") == "slice"), None)
        try:
            r = _derive_sliced(
                seed, preset,
                ((sl or {}).get("start"), (sl or {}).get("end")),
                key=bound.get("derive_key") or kdf_key or "",
                iv=bound.get("derive_iv") or kdf_iv or "")
        except Exception:  # noqa: BLE001
            continue
        out.append({"name": "目标派生链：%s" % preset, "kind": "derived-chain",
                    "key_hex": r["output_hex"], "key_bytes": r["output_len"],
                    "seed": seed, "preset": preset, "trace": r.get("trace") or []})
    return out


def key_candidates(materials: dict, frame: dict) -> list[dict]:
    """汇总所有可能的对称密钥：派生（种子）+ 常量切片 + 源码命名字面量。"""
    cands: list[dict] = []
    consts = materials.get("constants") or {}
    literals = materials.get("literals") or {}

    # ① 派生类：种子来自报文（前置种子 / 32 位 HEX 前缀 / 源码里的 seed 字面量）
    seeds = []
    if frame.get("seed"):
        seeds.append((frame["seed"], "报文里前置的 32 位 HEX 前缀"))
    for v in literals.get("seed", [])[:3]:
        seeds.append((v, "源码 seed 字面量"))
    for seed, src in seeds[:4]:
        for k in _kdf_variants(seed, materials, frame):
            k["name"] = "%s（%s）" % (k["name"], src)
            cands.append(k)

    # ② 常量切片直接当密钥
    for sl in materials.get("slices", []):
        val = sl.get("value") or ""
        if not sl.get("candidate_key"):
            continue
        raws = []
        if sl.get("is_hex") and len(val) in (32, 48, 64):
            try:
                raws.append(bytes.fromhex(val))
            except ValueError:
                pass
        if len(val) in (5, 8, 16, 24, 32):
            raws.append(val.encode("utf-8"))
        for raw in raws:
            cands.append({"name": "常量切片[%s:%s] 直接作为密钥" % (sl["range"][0], sl["range"][1]),
                          "kind": "literal", "key_hex": raw.hex(), "key_bytes": len(raw),
                          "trace": []})

    # ③ 源码命名密钥字面量（AES_KEY / SM4_KEY / secret …），三种解释都收
    for value in literals.get("key", [])[:8]:
        for var in literal_variants(value):
            cands.append({
                "name": "源码字面量密钥「按 %s 解释」" % var["as"],
                "kind": "named-literal", "key_hex": var["bytes"].hex(),
                "key_bytes": len(var["bytes"]), "literal_as": var["as"],
                "literal_value": value, "trace": [],
            })

    # ④ 去重（同一把密钥只留一条，优先保留"派生类"描述）
    prio = {"derived": 0, "derived-chain": 1, "derived-plain": 2,
            "named-literal": 3, "literal": 4}
    seen: dict[str, dict] = {}
    for c in cands:
        k = c["key_hex"]
        if k not in seen or prio.get(c.get("kind"), 9) < prio.get(seen[k].get("kind"), 9):
            seen[k] = c
    return sorted(seen.values(), key=lambda x: prio.get(x.get("kind"), 9))


def iv_candidates(materials: dict, block: int) -> list[dict]:
    """IV / nonce 候选：源码字面量（按长度匹配分组）+ 常量切片。"""
    out: list[dict] = []
    for value in (materials.get("literals") or {}).get("iv", [])[:8]:
        for var in literal_variants(value):
            if len(var["bytes"]) in (8, 12, 16):
                out.append({"name": "源码 IV 字面量（按 %s 解释）" % var["as"],
                            "iv_hex": var["bytes"].hex(), "iv_bytes": len(var["bytes"])})
    consts = materials.get("constants") or {}
    if consts.get("secret_b") and block in (8, 16):
        raw = consts["secret_b"].encode("utf-8")
        if len(raw) == block:
            out.append({"name": "常量切片 IV（UTF-8 字面量）", "iv_hex": raw.hex(),
                        "iv_bytes": len(raw)})
    for sl in materials.get("slices", []):
        if "IV" not in (sl.get("role") or ""):
            continue
        raw = (sl.get("value") or "").encode("utf-8")
        if len(raw) in (8, 12, 16):
            out.append({"name": "常量切片[%s:%s] 作为 IV" % tuple(sl["range"]),
                        "iv_hex": raw.hex(), "iv_bytes": len(raw)})
    dedup, seen = [], set()
    for c in out:
        if c["iv_hex"] in seen:
            continue
        seen.add(c["iv_hex"])
        dedup.append(c)
    return dedup


def priv_key_candidates(materials: dict) -> list[dict]:
    """私钥候选：PEM（多行）+ 源码里命名的十六进制/Base64 私钥字面量。

    返回的 `value` 一律是"可以直接喂给引擎的文本"：
      · PEM  → 原样交给引擎（引擎自己解析 PKCS#1 / PKCS#8）；
      · HB64 → 十六进制或 Base64 文本，引擎按 auto 解析。
    """
    out: list[dict] = []
    for pk in (materials.get("private_keys") or [])[:4]:
        out.append({"name": "源码 PEM 私钥（%s%s）"
                             % (pk.get("kind"), "，来自 %s" % pk["file"] if pk.get("file") else ""),
                    "value": pk["value"], "as": "pem"})
    for v in ((materials.get("literals") or {}).get("priv") or [])[:6]:
        for var in literal_variants(v):
            if len(var["bytes"]) in (16, 20, 24, 28, 32, 48, 64):
                out.append({"name": "私钥字面量「按 %s 解释」（%d 字节）"
                                     % (var["as"], len(var["bytes"])),
                            "value": var["bytes"].hex(), "as": var["as"]})
    dedup, seen = [], set()
    for c in out:
        if c["value"] in seen:
            continue
        seen.add(c["value"])
        dedup.append(c)
    return dedup


def _envelope_recipes(frame: dict, materials: dict) -> list[dict]:
    """为 JSON 混合信封生成配方：先解封包裹密钥，再用它解正文。"""
    env = frame.get("envelope") or {}
    privs = priv_key_candidates(materials)
    if not privs:
        return []
    enc = env.get("data_encoding") or "base64"
    # 「解封」的候选做法：SM2 两种 C1 排序 + RSA 两种填充 + 字段本身就是明文密钥
    variants: list[dict] = []
    if env.get("key_encoding") in ("base64", "hex") and env.get("key_bytes", 0) in (16, 24, 32):
        variants.append({"asym": "none", "label": "该字段本身就是明文对称密钥"})
    for cm in (cc.SM2_C1C3C2, cc.SM2_C1C2C3):
        variants.append({"asym": "sm2", "cipher_mode": cm, "label": "SM2 解封（%s）" % cm})
    # OAEP 排在 PKCS#1 v1.5 **前面**：v1.5 解密没有完整性校验，解错也不报错，
    # 先试它容易用一段垃圾字节"假成功"挡住 OAEP。
    for h in ("sha256", "sha1"):
        variants.append({"asym": "rsa", "padding": cc.RSA_OAEP, "hash_alg": h,
                         "label": "RSA-OAEP/%s 解封" % h})
    for h in ("sha256", "sha1"):
        variants.append({"asym": "rsa", "padding": cc.RSA_PKCS1V15, "hash_alg": h,
                         "label": "RSA-PKCS1v1.5 解封（%s）" % h})
    out: list[dict] = []
    for pv in privs[:4]:
        for var in variants:
            for alg, mode, padding in (("sm4", "ecb", "pkcs7"), ("sm4", "cbc", "pkcs7"),
                                       ("aes128", "cbc", "pkcs7"), ("aes128", "ecb", "pkcs7"),
                                       ("aes256", "cbc", "pkcs7"), ("aes256", "ecb", "pkcs7"),
                                       ("sm4", "cbc", "zero"), ("sm4", "ecb", "zero")):
                out.append({
                    "name": "混合信封：%s｜%s → %s/%s/%s → 解 `%s`"
                            % (pv["name"], var["label"], alg.upper(), mode.upper(),
                               padding.upper(), env.get("data_field")),
                    "alg": alg, "mode": mode, "padding": padding,
                    "encoding_chain": [enc], "key_hex": "", "iv_hex": env.get("iv_hex") or "",
                    "iv_prefix": 0, "master_hex": None,
                    "unwrap": {"label": "%s + %s" % (pv["name"], var["label"]),
                               "priv": pv["value"],
                               "text": env.get("key_text", ""),
                               "encoding": env.get("key_encoding") or "base64",
                               "iv_hex": env.get("iv_hex") or "",
                               "variant": var},
                    "trace": [], "kind": "envelope", "aad": "",
                })
    return out


def aad_candidates(materials: dict) -> list[str]:
    vals = []
    for v in (materials.get("literals") or {}).get("aad", [])[:3]:
        if v not in vals:
            vals.append(v)
    return vals


# ---------------------------------------------------------------------------
# 配方编排：把「密钥 × 算法 × 模式 × 填充 × 编码链 × IV 来源」展开（有优先级、有上限）
# ---------------------------------------------------------------------------
ENCODING_CHAINS = [
    (["base64"], "Base64"),
    (["hex"], "HEX"),
    (["base64url"], "Base64URL"),
    (["base64", "base64"], "双层 Base64"),
    (["url"], "URL 编码"),
    (["hex", "base64"], "HEX→Base64"),
    (["url", "base64"], "URL→Base64"),
    (["base64", "hex"], "Base64→HEX"),
]
# 爆破优先级：常见 → 少见。新增算法追加在末尾（不影响既有目标的试解顺序）。
# 注意：RC5/RC6 是自实现的纯 Python，比 pycryptodome 慢约两个数量级，
# 放在最后可避免给常见目标平白增加试解耗时。
_ALG_ORDER = ("sm4", "aes128", "aes256", "aes192", "des3", "des", "rc4",
              "blowfish", "cast5", "rc2", "chacha20", "salsa20",
              "rc5", "rc5_16", "rc5_64", "rc6", "rc6_16")
_PAD_ORDER = {"ecb": ("pkcs7", "zero", "none"), "cbc": ("pkcs7", "zero", "none"),
              "ctr": ("none",), "cfb": ("none",), "ofb": ("none",), "gcm": ("none",),
              "stream": ("none",)}


def _algos_for_key(key_bytes: int) -> list[str]:
    out = []
    for aid in _ALG_ORDER:
        try:
            spec = cc.get_spec_by_keylen(aid, key_bytes)
        except Exception:  # noqa: BLE001
            continue
        if spec and key_bytes in spec.key_sizes:
            out.append(aid)
        elif spec and spec.is_key_range and spec.key_sizes[0] <= key_bytes <= spec.key_sizes[-1]:
            out.append(aid)
    return out


def _iv_sources(frame: dict, mode: str, ivs: list[dict]) -> list[dict]:
    """某个模式下的 IV 来源，按"最可能"排序。

    顺序：报文/源码里明确的 IV → 密文前置 16 字节 → 前置 12 字节(nonce) → 全零。
    「密文前置」之所以要默认试：很多接口把 IV 直接拼在密文头里，解码后长度会多出
    8/12/16 字节，光看长度很难区分（实测 16 字节前置时总长仍是 16 的倍数）。
    """
    if mode in ("ecb", "stream"):
        return [{"name": "无需 IV", "iv_hex": "", "iv_prefix": 0}]
    out: list[dict] = []
    for iv in ivs:
        if mode == "gcm" and iv["iv_bytes"] not in (12, 16):
            continue
        out.append({"name": iv["name"], "iv_hex": iv["iv_hex"], "iv_prefix": 0})
    if mode == "gcm":
        out.append({"name": "密文前 12 字节是 nonce", "iv_hex": "", "iv_prefix": 12})
        out.append({"name": "密文前 16 字节是 nonce", "iv_hex": "", "iv_prefix": 16})
    else:
        out.append({"name": "密文前 16 字节是 IV", "iv_hex": "", "iv_prefix": 16})
        out.append({"name": "密文前 8 字节是 IV", "iv_hex": "", "iv_prefix": 8})
    out.append({"name": "IV 全零（部分老接口确实这么写）", "iv_hex": "00" * 16, "iv_prefix": 0})
    return out


def score_plaintext(data: bytes) -> tuple[float, list[str]]:
    """给解密结果打分：UTF-8 合法性、可打印比例、JSON 结构、业务字段名。

    关键点：**必须先按字符判可打印，不能按字节判**。
    UTF-8 中文一个字占 3 字节，三字节全在 0x20~0x7E 之外 —— 按字节算的话，
    一篇纯中文明文（`{"respMsg":"交易成功"}`）可打印率只有七成，会被直接
    当成乱码丢掉（实测 02/04/12 就是这么被冤死的）。所以这里：
      ① 先尝试 UTF-8 解码，成功才有资格继续；
      ② 再按**字符**的 isprintable() 算比例（中文/全角标点都算可打印）；
      ③ 解码失败才退回按字节算，且阈值更严。
    """
    ev: list[str] = []
    if not data:
        return 0.0, ["结果为空"]
    if len(data) > MAX_PLAIN_BYTES:
        return 0.0, ["结果过大"]
    if b"\xef\xbf\xbd" in data:
        return 0.0, ["含替换字符 U+FFFD，判定为乱码"]

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
        return 0.0, ["不是合法 UTF-8（字节可打印率 %.0f%%），判定为乱码"
                     % (printable / len(data) * 100)]

    score = 0.30
    ev.append("是合法 UTF-8")

    # 字符级可打印比例（中文、全角符号都是 printable）
    printable_chars = sum(1 for ch in text if ch.isprintable() or ch in "\t\n\r")
    ratio = printable_chars / max(1, len(text))
    if ratio >= 0.98:
        score += 0.35
        ev.append("可打印字符比例 %.0f%%" % (ratio * 100))
    elif ratio >= 0.90:
        score += 0.20
        ev.append("可打印字符比例 %.0f%%（偏高但略含控制字符）" % (ratio * 100))
    else:
        return 0.0, ["可打印字符比例仅 %.0f%%，判定为乱码" % (ratio * 100)]

    stripped = text.strip()
    if (stripped.startswith("{") and stripped.endswith("}")) or \
       (stripped.startswith("[") and stripped.endswith("]")):
        try:
            obj = json.loads(stripped)
            score += 0.25
            ev.append("是合法 JSON")
            flat = json.dumps(obj, ensure_ascii=False).lower()
            hits = [h for h in BIZ_HINTS if h in flat]
            if hits:
                score += min(0.2, 0.05 * len(hits))
                ev.append("命中业务字段名：%s" % "、".join(hits[:6]))
        except ValueError:
            ev.append("形似 JSON 但解析失败")
    elif re.search(r"[A-Za-z\u4e00-\u9fff]{3,}", stripped):
        score += 0.05
    return min(score, 1.0), ev


def _decode_ciphertext(frame: dict, chain) -> bytes:
    """按编码链解码密文（支持双层 Base64 / Base64URL / URL / HEX）。

    每一步都把中间结果统一成 **latin-1 字符串**再做下一步，
    否则 `url` 步骤产出的 bytes 会被下一步的 `re.sub` 打挂（实测踩过）。
    """
    text = frame.get("cipher_text", "") or ""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("latin-1")
    raw = text.encode("latin-1", errors="replace")
    for step in (chain or ["base64"]):
        if isinstance(raw, (bytes, bytearray)):
            text = bytes(raw).decode("latin-1")
        if step == "base64":
            raw = _try_b64(text)
            if raw is None:
                raise cc.CryptoUsageError("Base64 解码失败")
        elif step == "base64url":
            cleaned = re.sub(r"\s", "", text).replace("-", "+").replace("_", "/")
            cleaned += "=" * ((-len(cleaned)) % 4)
            try:
                raw = base64.b64decode(cleaned, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise cc.CryptoUsageError("Base64URL 解码失败：%s" % exc) from exc
        elif step == "hex":
            cleaned = re.sub(r"[\s:]", "", text)
            if len(cleaned) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
                raise cc.CryptoUsageError("HEX 解码失败（长度或字符不合法）")
            raw = bytes.fromhex(cleaned)
        elif step == "url":
            import urllib.parse
            raw = urllib.parse.unquote_to_bytes(text)
        else:
            raise cc.CryptoUsageError("不支持的编码步骤：%s" % step)
    return bytes(raw)


def _post_process(data: bytes) -> tuple[bytes, list[str]]:
    """解密之后再试一次「压缩还原」——很多业务是"先压缩再加密"。"""
    notes: list[str] = []
    guess = cc.looks_compressed(data)
    for algo in ([guess] if guess else []) + [a for a in cc.COMPRESS_ALGOS if a != guess]:
        try:
            raw = cc.do_decompress(data, algo)
        except Exception:  # noqa: BLE001
            continue
        if raw and raw != data:
            s, _ = score_plaintext(raw)
            if s > 0:
                notes.append("解密结果经 %s 解压后得到可读内容" % algo)
                return raw, notes
    return data, notes


def try_recipe(frame: dict, recipe: dict, materials: dict) -> dict:
    """执行一条候选方案，返回 {ok, plain, score, evidence, reason, trace}。"""
    result = {"recipe": recipe, "ok": False, "plain": None, "score": 0.0,
              "evidence": [], "reason": "", "trace": list(recipe.get("trace") or [])}
    key_hex = recipe["key_hex"]
    # ---- 混合信封：先用私钥解封包裹密钥，再用它解正文 ----
    if recipe.get("unwrap"):
        uw = recipe["unwrap"]
        wrapped = _b64_decode_any(uw["text"]) if uw["encoding"] == "base64" else \
            (bytes.fromhex(uw["text"]) if re.fullmatch(r"[0-9a-fA-F]+", uw["text"] or "") else None)
        if wrapped is None:
            result["reason"] = "包裹密钥字段无法解码（既不像 Base64 也不像 HEX）"
            return result
        var = uw["variant"]
        try:
            if var["asym"] == "none":
                unwrapped = wrapped
            elif var["asym"] == "sm2":
                unwrapped = cc.do_sm2("dec", data=wrapped, private_key=uw["priv"],
                                      cipher_mode=var["cipher_mode"])
            else:
                unwrapped = cc.do_rsa("dec", data=wrapped, key_text=uw["priv"],
                                      padding=var["padding"], hash_alg=var["hash_alg"])
        except Exception as exc:  # noqa: BLE001
            result["reason"] = "包裹密钥解封失败（%s）：%s" % (var.get("label"), str(exc)[:90])
            return result
        # 解封出来的应该是**对称密钥**：长度必须是 16/24/32 字节。
        # 这一步是必要的：RSA PKCS#1 v1.5 解密没有完整性校验，用错填充解错也不报错、
        # 会返回一段垃圾字节，靠长度把它筛掉（实测踩过）。
        if not unwrapped or len(unwrapped) not in (16, 24, 32):
            result["reason"] = ("解封出来的不是对称密钥长度（%d 字节，应为 16/24/32）——"
                                "多半是填充/算法不匹配" % (len(unwrapped) if unwrapped else 0))
            return result
        result["trace"].append("· 用%s解封包裹密钥 → %d 字节 %s…"
                               % (var.get("label"), len(unwrapped), unwrapped.hex()[:24]))
        key_hex = unwrapped.hex()
        # 写回 recipe —— 否则 `out["best"]["key_hex"]` 还是空串，
        # 界面上就看不到"解封出来的密钥"，也没法手工复核。
        result["recipe"] = dict(recipe)
        result["recipe"]["key_hex"] = key_hex
        result["recipe"]["unwrap_asym"] = True

    try:
        cipher = _decode_ciphertext(frame, recipe.get("encoding_chain"))
    except Exception as exc:  # noqa: BLE001
        result["reason"] = "密文按 %s 解码失败：%s" % ("+".join(recipe.get("encoding_chain") or []), exc)
        return result

    # 前缀约定：密文前 N 字节是 IV / nonce
    iv_hex = recipe.get("iv_hex") or ""
    n = int(recipe.get("iv_prefix") or 0)
    if n:
        if len(cipher) <= n:
            result["reason"] = "密文过短，不足以容纳前置 IV"
            return result
        iv_hex = cipher[:n].hex()
        cipher = cipher[n:]
        result["trace"].append("· 取密文前 %d 字节作为 IV/nonce：%s…" % (n, iv_hex[:16]))

    if not cipher:
        result["reason"] = "密文为空"
        return result
    # ⚠ 用 spec.is_stream 判定而不是写死 "rc4"：v5 之后流密码不止 RC4
    #   （还有 ChaCha20 / Salsa20），写死会让它们走错分组对齐分支。
    _spec = cc.get_spec(recipe["alg"])
    block = 1 if _spec.is_stream else _spec.block
    if not _spec.is_stream and recipe["padding"] in (cc.PAD_PKCS7, cc.PAD_ZERO) \
            and len(cipher) % block:
        result["reason"] = "密文长度 %d 不是分组 %d 的整数倍" % (len(cipher), block)
        return result

    try:
        plain = cc.do_crypt(
            recipe["alg"], "dec", key_hex, (iv_hex or None), cipher,
            mode=recipe["mode"], padding=recipe["padding"],
            aad=(recipe.get("aad") or "").encode("utf-8"), warn_weak=False)
    except Exception as exc:  # noqa: BLE001
        result["reason"] = "解密失败：%s" % exc
        result["trace"].append("✗ %s/%s/%s → %s" % (recipe["alg"].upper(),
                                                    recipe["mode"].upper(),
                                                    recipe["padding"].upper(), exc))
        return result

    plain, post = _post_process(plain)
    score, evidence = score_plaintext(plain)
    result.update({"plain": plain, "score": score, "evidence": evidence + post,
                   "ok": score > 0})
    result["trace"].append("✓ %s/%s/%s 解出 %d 字节（可信度 %.2f）"
                           % (recipe["alg"].upper(), recipe["mode"].upper(),
                              recipe["padding"].upper(), len(plain), score))
    if not result["ok"]:
        result["reason"] = "；".join(evidence) or "明文不合格"
    return result


def _mac_algos_for_length(n: int) -> list[str]:
    """按 mac 的字节长度推断候选算法 —— 长度本身就是很强的线索。

    32 字节 → SM3 / SHA256（两者都是 32 字节，从长度上分不出来，只能都试）；
    20 字节 → SHA1；16 字节 → MD5。
    """
    table = {32: ["hmac-sm3", "hmac-sha256"], 20: ["hmac-sha1"], 16: ["hmac-md5"],
             64: ["hmac-sha512"]}
    return table.get(n) or ["hmac-sm3", "hmac-sha256"]


def verify_mac(frame: dict, recipe: dict) -> dict:
    """能验 mac 就验 mac —— 这是"确凿证据"，比打分可靠得多。

    算法不写死：先按 mac 的字节长度缩小范围，再逐个试（HMAC-SM3 与 HMAC-SHA256
    都是 32 字节，长度相同，只能都试一遍）。
    """
    mac_b64 = frame.get("mac_b64")
    if not mac_b64 or not recipe.get("master_hex"):
        return {"checked": False}
    scope = frame.get("mac_scope") or ""
    try:
        want = base64.b64decode(mac_b64 + "=" * ((-len(mac_b64)) % 4), validate=True)
    except (binascii.Error, ValueError):
        return {"checked": False, "error": "报文里的 mac 不是合法 Base64"}
    key = bytes.fromhex(recipe["master_hex"])
    tried: list[dict] = []
    for algo in _mac_algos_for_length(len(want)):
        try:
            calc = base64.b64encode(cc.do_hmac(algo, key, scope.encode("utf-8"))).decode("ascii")
        except Exception as exc:  # noqa: BLE001
            tried.append({"algo": algo, "error": str(exc)[:60]})
            continue
        if calc == mac_b64:
            return {"checked": True, "ok": True, "algo": algo.upper(),
                    "scope": scope_label(frame), "expected": mac_b64, "computed": calc,
                    "tried": [t.get("algo") for t in tried]}
        tried.append({"algo": algo, "computed": calc})
    return {
        "checked": True, "ok": False,
        "algo": "/".join(t.get("algo", "?") for t in tried),
        "scope": scope_label(frame), "expected": mac_b64,
        "computed": (tried[0].get("computed") if tried else ""),
    }


def scope_label(frame: dict) -> str:
    """mac 覆盖范围的说明文字（按形态给出，便于人工核对）。"""
    return {
        "seed-prefix": "32hex 种子 + cipher_b64",
    }.get(frame.get("kind"), "密文（解码前文本）")


def build_recipes(frame: dict, materials: dict, keys: list[dict]) -> list[dict]:
    """展开候选方案。策略：先"最像"的组合，再逐步放宽；总量有上限。"""
    if frame["kind"] == "json-envelope":
        return _envelope_recipes(frame, materials)[:MAX_RECIPES]

    recipes: list[dict] = []
    # 报文里带了种子/32hex 前缀时：派生类配方优先排队（省得被矩阵挤到候选上限之后）
    has_seed = bool(frame.get("seed"))
    ivs = iv_candidates(materials, 16)
    aads = aad_candidates(materials)
    seen: set[tuple] = set()

    # 编码链顺序要跟着**形态**走：裸 HEX 就先用 HEX 解，Base64URL 就先用 URL 解。
    # 否则矩阵按固定顺序铺开，很可能在轮到正确的编码链之前就撞上 MAX_RECIPES 上限。
    pref = {
        "raw-hex": [["hex"]],
        "raw-base64url": [["base64url"], ["base64"]],
        "raw-base64": [["base64"]],
        "json-envelope": [[frame.get("envelope", {}).get("data_encoding") or "base64"]],
        "raw-url": [["url", "base64"], ["url", "hex"], ["url"]],
    }.get(frame["kind"]) or [["base64"]]
    chains = sorted(ENCODING_CHAINS,
                    key=lambda c: 0 if list(c[0]) in pref else 1)
    # 剔除「根本解不开这段密文」的编码链：8 条链 × 多密钥 × 多算法很容易把
    # MAX_RECIPES 吃光，把真正正确的配方挤出去（实测样本 08 就这么被挤掉过）。
    viable = []
    for c in chains:
        try:
            data = _decode_ciphertext(frame, c[0])
        except Exception:  # noqa: BLE001
            continue
        if data:
            viable.append(c)
    chains = viable or chains

    def add(recipe: dict) -> None:
        sig = (recipe["alg"], recipe["mode"], recipe["padding"], recipe["key_hex"],
               tuple(recipe["encoding_chain"]), recipe.get("iv_hex", ""),
               recipe.get("iv_prefix", 0), recipe.get("aad", ""))
        if sig in seen or len(recipes) >= MAX_RECIPES:
            return
        seen.add(sig)
        recipes.append(recipe)

    # ---- ① 有种子时：把「派生 → 对称解密」的常见组合优先排队 ----
    if has_seed:
        for kc in keys:
            if kc.get("kind", "").startswith("derived") or kc.get("seed"):
                for alg, mode, padding in (("sm4", "ecb", "pkcs7"), ("sm4", "cbc", "pkcs7"),
                                           ("sm4", "ecb", "zero"), ("aes128", "ecb", "pkcs7")):
                    add({"name": "种子派生优先配方：%s + %s/%s/%s"
                                 % (kc["name"], alg.upper(), mode.upper(), padding.upper()),
                         "alg": alg, "mode": mode, "padding": padding,
                         "encoding_chain": ["base64"], "key_hex": kc["key_hex"],
                         "iv_hex": "", "iv_prefix": 0, "master_hex": kc.get("master_hex"),
                         "seed": kc.get("seed"), "preset": kc.get("preset"),
                         "kdf_key": kc.get("kdf_key"), "kdf_iv": kc.get("kdf_iv"),
                         "trace": kc.get("trace"), "kind": kc.get("kind"), "aad": ""})

    # ---- ② 全量矩阵（种子派生的优先配方已在前面排好队）----
    # ⚠ 每个密钥来源分到**均等配额**：同一串字面量的不同「解释方式」会产出不同字节数的
    #   密钥（16 个 ASCII 字符按 hex 只有 8 字节、按 utf8 才是 16 字节），而字节数决定
    #   可选算法集。若让排在前面的解释把 MAX_RECIPES 吃光，排在后面的正确那一支就永远
    #   轮不到 —— 实测踩过：新增一批经典算法后，8 字节那一支（DES/Blowfish/CAST5/RC2）
    #   把 900 条配额耗尽，utf8 的 AES-128-CBC 配方整条没生成，一键解密直接判失败。
    _share = max(1, MAX_RECIPES // max(1, len(keys)))
    for kc in keys:
        nb = kc["key_bytes"]
        _kc_deadline = len(recipes) + _share
        for alg in _algos_for_key(nb):
            if len(recipes) >= _kc_deadline:
                break                     # 该密钥的配额用完，让位给下一个来源
            spec = cc.get_spec(alg)
            iv_list = ivs if not spec.is_stream else [{"name": "流密码无 IV",
                                                       "iv_hex": "", "iv_prefix": 0}]
            for mode in spec.modes:
                if spec.is_stream and mode != cc.MODE_STREAM:
                    continue
                if not spec.is_stream and mode == cc.MODE_STREAM:
                    continue
                for padding in _PAD_ORDER.get(mode, ("none",)):
                    if padding not in (cc.PAD_PKCS7, cc.PAD_ZERO, cc.PAD_NONE):
                        continue
                    if mode not in (cc.MODE_ECB, cc.MODE_CBC) and padding != cc.PAD_NONE:
                        continue
                    for chain, chain_label in chains:
                        if len(recipes) >= _kc_deadline:
                            break
                        for iv in _iv_sources(frame, mode, iv_list):
                            if chain_label == "URL 编码" and len(recipes) > MAX_RECIPES // 2:
                                continue        # URL 编码少见，排在最后且超限就不试
                            for aad in (aads or [""]):
                                add({
                                    "name": "%s｜%s + %s/%s/%s｜%s%s"
                                            % (kc["name"], alg.upper(), mode.upper(),
                                               padding.upper(), "(无填充)" if padding == "none" else "",
                                               chain_label,
                                               "｜" + iv["name"] if iv["name"] else ""),
                                    "alg": alg, "mode": mode, "padding": padding,
                                    "encoding_chain": chain, "key_hex": kc["key_hex"],
                                    "iv_hex": iv["iv_hex"], "iv_prefix": iv["iv_prefix"],
                                    "master_hex": kc.get("master_hex"), "seed": kc.get("seed"),
                                    "preset": kc.get("preset"), "trace": kc.get("trace"),
                                    "kind": kc.get("kind"), "aad": aad,
                                })
    return recipes[:MAX_RECIPES]




# ============================================================================
# 四、主入口
# ============================================================================
_FRAME_LOGIC_ID = {
    "seed-prefix": "frame.seed-prefix",
    "raw-hex": "frame.raw-hex",
    "raw-base64": "frame.raw-base64",
    "raw-base64url": "frame.raw-base64url",
    "raw-url": "frame.raw-url",
    "json-envelope": "frame.json-envelope",
}

# 注意口径：这里的 chain 用「编码顺序」（与 crypto_logic_registry / crypto_core 一致）
_CHAIN_LOGIC_ID = {
    ("base64",): "chain.base64",
    ("base64", "base64"): "chain.base64-twice",
    ("base64", "hex"): "chain.base64-then-hex",
    ("base64", "url"): "chain.base64-then-url",
    ("hex", "base64"): "chain.hex-then-base64",
}


def _known_logic_ids(ids: list[str]) -> list[str]:
    """只保留登记表里真实存在的 ID（登记表缺席时原样返回，不让主流程失败）。"""
    try:
        import crypto_logic_registry as clr
        known = {x["id"] for x in clr.LOGICS} | {x["id"] for x in clr.COMPOSITES}
        return [i for i in ids if i in known]
    except Exception:  # noqa: BLE001
        return ids


def logics_used(frame: dict, materials: dict, best: dict | None,
                ambiguous: bool = False) -> list[str]:
    """把本次「分析 + 解密」用到的环节映射成《加密逻辑总览》里的逻辑 ID。

    这样 Tab 10 的结论就不只是"解出来了"，还能直接告诉你
    「这一路用了哪些逻辑」，编号与 Tab 11 一一对应、可点过去查用途与场景。
    """
    ids: list[str] = []

    def add(x):
        if x and x not in ids:
            ids.append(x)

    # ① 报文框架
    add(_FRAME_LOGIC_ID.get(frame.get("kind", ""), ""))
    if frame.get("notes"):
        for nt in frame["notes"]:
            if "抽出" in nt and "长密文段" in nt:
                add("frame.mixed-text")

    # ② 密钥来源与材料挖掘
    consts = materials.get("constants") or {}
    lits = materials.get("literals") or {}
    if consts.get("secret_a") or consts.get("kdf_key"):
        add("keysrc.disguised")
        add("keysrc.slice")
    if lits.get("key") or lits.get("iv"):
        add("keysrc.literal")
    if materials.get("chains"):
        add("keysrc.chain")
    if materials.get("private_keys") or lits.get("priv"):
        add("keysrc.pem")
    if frame.get("seed"):
        add("keysrc.header")
    if frame.get("mac_b64"):
        add("hmac.scope")

    if not best:
        return _known_logic_ids(ids)

    r = best["recipe"]

    # ③ 密钥从哪来：非对称解封 / 派生链 / 字面量
    if r.get("unwrap"):
        var = (r["unwrap"].get("variant") or {})
        asym = var.get("asym")
        if asym == "sm2":
            add("asym.sm2")
            add("envelope.sm2")
        elif asym == "rsa":
            add("asym.rsa")
            add("envelope.rsa")
        add("envelope.json")
        add("envelope.checks")
        if (r["unwrap"] or {}).get("priv"):
            add("keysrc.pem")
    elif r.get("preset"):
        add("kdf." + str(r["preset"]))
        if "slice" in str(r["preset"]):
            add("kdf.slice")
        if r.get("seed"):
            add("keysrc.header")
    else:
        add("keysrc.literal")

    # ④ 算法 / 模式 / 填充
    add("algo." + str(r.get("alg", "")))
    add("mode." + str(r.get("mode", "")))
    add("padding." + str(r.get("padding", "")))

    # ⑤ 编码链
    chain = tuple(r.get("encoding_chain") or ["base64"])
    if len(chain) > 1:
        add("chain.order")
        add(_CHAIN_LOGIC_ID.get(chain, ""))
    else:
        add("encoding." + (chain[0] if chain else "base64"))

    # ⑥ 完整性（能验 mac 就验 mac；算法按字节长度自适应）
    mac = best.get("mac") or {}
    if mac.get("checked") and mac.get("ok"):
        add("hmac." + str(mac.get("algo", "")).lower().replace("_", "-"))
        add("hmac.auto")

    # ⑦ 解密后的压缩还原
    for ev in best.get("evidence") or []:
        if "解压" in str(ev):
            add("compress.sniff")
            break

    return _known_logic_ids(ids)


def auto_solve(text: str, *, target_dir: str = "", target_file: str = "",
               extra_materials: dict | None = None) -> dict:
    """贴一段密文 → 自动分析 → 尝试解密 → 返回明文与依据。"""
    out: dict = {
        "status": "ok", "mode": "auto-solve",
        "frame": None, "materials": None, "attempts": [],
        "best": None, "decrypt_logic": [], "summary": "",
    }
    buf = (text or "").strip()
    # 支持「密文 + 目标源码片段」一起粘贴：先按形态切出密文，再用整段挖常量
    frames = detect_frames(buf)
    if not frames or frames[0]["kind"] == "unknown":
        out["status"] = "fail"
        out["summary"] = (frames[0]["label"] if frames else "空输入")
        out["frame"] = frames[0] if frames else {}
        return out

    mat_text = materials_from_text(buf)
    mat_dir = materials_from_path(target_dir) if target_dir else {}
    mat_file = materials_from_path(target_file) if target_file else {}
    materials = merge_materials(mat_text, mat_dir, mat_file, extra_materials)
    out["materials"] = {
        "sources": materials["source"],
        "constants": {k: v for k, v in (materials.get("constants") or {}).items()},
        "slice_count": len(materials.get("slices") or []),
        "chain_count": len(materials.get("chains") or []),
    }

    out["frames"] = [{"kind": f["kind"], "label": f["label"]} for f in frames]
    out["frame"] = frames[0]

    # JSON 混合信封只需要**私钥**（对称密钥是被包裹在报文里的），所以缺私钥要单独提示
    if frames[0]["kind"] == "json-envelope" and not priv_key_candidates(materials):
        out["status"] = "need_material"
        out["summary"] = ("已识别为 JSON 混合信封（包裹密钥 + 对称密文），但**没有拿到私钥**。"
                          "信封里的对称密钥是用非对称公钥包起来的，没有对应私钥无法解封。"
                          "请把服务端解密代码 / 密钥文件所在目录（--target-dir）或含私钥的"
                          "源码片段（PEM 或十六进制私钥）一起提供。")
        out["decrypt_logic"] = _logic_hint(frames[0], materials)
        return out

    best = None
    best_frame = None
    got_keys = False
    attempt_total = 0
    for frame in frames:
        keys = key_candidates(materials, frame)
        if frame["kind"] == "json-envelope":
            got_keys = True        # 信封走的是"解封"路径，不需要对称密钥候选
        if not keys and frame["kind"] != "json-envelope":
            continue
        got_keys = True
        recipes = build_recipes(frame, materials, keys)
        for recipe in recipes:
            res = try_recipe(frame, recipe, materials)
            mac = (verify_mac(frame, recipe)
                   if (res.get("ok") or frame.get("mac_b64")) else {"checked": False})
            res["mac"] = mac
            if mac.get("checked") and mac.get("ok"):
                res["score"] = 1.0
                res["evidence"].append("外层 mac(%s) 与报文完全一致 —— 确凿证据"
                                       % mac.get("algo"))
            elif mac.get("checked") and not mac.get("ok"):
                # 自带了 mac 却对不上 → 说明这个解释（尤其是"末尾 44 字符是 mac"的切法）
                # 多半是错的，轻微降权，让"不带 mac"的合理解释能赢过它。
                res["score"] = max(0.0, res["score"] - 0.08)
                res["ok"] = bool(res["score"] > 0)
            attempt_total += 1
            if len(out["attempts"]) < MAX_ATTEMPTS:
                out["attempts"].append({
                    "frame": frame["kind"],
                    "recipe": recipe["name"],
                    "ok": bool(res["ok"]),
                    "score": round(res["score"], 2),
                    "reason": res["reason"] or "；".join(res["evidence"][:3]),
                    "mac_ok": mac.get("ok") if mac.get("checked") else None,
                })
            if res["ok"] and (best is None or res["score"] > best["score"]):
                best = res
                best_frame = frame
            if best and best["score"] >= 0.99:      # mac 对上，无需继续
                break
        if best and best["score"] >= 0.99:
            break
    out["attempt_total"] = attempt_total

    out["logics_used"] = logics_used(frames[0], materials, None,
                                     ambiguous=len(frames) > 1)
    if not got_keys:
        out["status"] = "need_material"
        out["summary"] = ("已识别报文形态，但**没有拿到密钥材料**，无法解密。"
                          "请把目标的前端 JS/jar 目录（--target-dir）或包含常量的源码片段一起提供——"
                          "工具会自动从里面挖出伪装常量与派生链。")
        out["decrypt_logic"] = _logic_hint(frames[0], materials)
        return out

    if not best:
        out["status"] = "fail"
        out["summary"] = ("试了 %d 套候选方案都没能得到合格明文（都判为乱码或填充失败）。"
                          "常见原因：报文不是这套体系 / 常量取自别的版本 / 密文被截断。"
                          "可尝试提供更多材料（目标目录、JS 片段）或检查密文是否完整。"
                          % attempt_total)
        out["decrypt_logic"] = _logic_hint(frames[0], materials)
        return out

    out["frame"] = best_frame or frames[0]
    out["logics_used"] = logics_used(out["frame"], materials, best,
                                     ambiguous=len(frames) > 1)
    plain = best["plain"]
    try:
        plain_text = plain.decode("utf-8")
    except UnicodeDecodeError:
        plain_text = plain.decode("utf-8", errors="replace")
    out["best"] = {
        "plain": plain_text,
        "plain_len": len(plain),
        "confidence": round(best["score"], 2),
        "recipe_name": best["recipe"]["name"],
        "key_hex": best["recipe"]["key_hex"],
        "key_bytes": len(best["recipe"]["key_hex"]) // 2,
        "alg": best["recipe"]["alg"], "mode": best["recipe"]["mode"],
        "padding": best["recipe"]["padding"],
        "cipher_encoding": "+".join(best["recipe"].get("encoding_chain") or ["base64"]),
        "encoding_chain": best["recipe"].get("encoding_chain"),
        "iv_prefix": best["recipe"].get("iv_prefix", 0),
        "aad": best["recipe"].get("aad", ""),
        "seed": best["recipe"].get("seed"),
        "master_hex": best["recipe"].get("master_hex"),
        "unwrap_label": (best["recipe"].get("unwrap") or {}).get("label", ""),
        "unwrapped": bool(best["recipe"].get("unwrap")),
        "evidence": best["evidence"],
        "mac": best.get("mac") or {"checked": False},
        "trace": best["trace"],
    }
    out["decrypt_logic"] = decrypt_logic_text(out["frame"], materials, best)
    out["summary"] = ("解密成功（可信度 %.2f）%s"
                      % (best["score"],
                         "，并经外层 mac 校验确认" if (best.get("mac") or {}).get("ok") else ""))
    return out


def _logic_hint(frame: dict, materials: dict) -> list[str]:
    lines = ["① 形态：%s" % frame["label"]]
    if frame["kind"] == "json-envelope":
        env = frame.get("envelope") or {}
        lines.append("② 信封结构：`%s` 是被包裹的对称密钥（%s），`%s` 是对称密文（%s）%s"
                     % (env.get("key_field"), env.get("key_encoding"),
                        env.get("data_field"), env.get("data_encoding"),
                        "，IV 在 `%s`" % env.get("iv_field") if env.get("iv_field") else ""))
        lines.append("③ 解密顺序：先用**服务端私钥**解封 `%s` 得到对称密钥，再用它解 `%s`"
                     % (env.get("key_field"), env.get("data_field")))
    if frame.get("seed"):
        lines.append("② 报文里的 32 位 HEX 前缀（当候选种子）：%s" % frame["seed"])
    if frame.get("mac_b64"):
        lines.append("③ 报文自带 mac（44 字符 Base64），可用 HMAC-SM3 校验解密结论")
    if materials.get("source"):
        lines.append("④ 已从这些来源取得材料：%s" % "；".join(materials["source"]))
    else:
        lines.append("④ 未取得任何密钥材料 —— 需要目标前端 JS/jar 或直接给出常量")
    return lines


def decrypt_logic_text(frame: dict, materials: dict, best: dict) -> list[str]:
    """产出人类可读的"解密逻辑"说明（逐步 + 依据）。"""
    r = best["recipe"]
    lines: list[str] = []
    lines.append("① 形态识别：%s" % frame["label"])
    if frame["kind"] == "seed-prefix":
        lines.append("   · 前 32 个字符是本条报文的**随机种子**（明文前置），其后才是密文：seed = %s"
                     % frame.get("seed"))
    elif frame["kind"] == "json-envelope":
        env = frame.get("envelope") or {}
        lines.append("   · JSON 混合信封：字段 `%s` 是被包裹的对称密钥（%s，%d 字节），"
                     "`%s` 是对称密文（%s）%s"
                     % (env.get("key_field"), env.get("key_encoding"), env.get("key_bytes", 0),
                        env.get("data_field"), env.get("data_encoding"),
                        "，IV 字段 `%s`" % env.get("iv_field") if env.get("iv_field") else ""))
        lines.append("   · 需要先用**服务端私钥**解封该密钥 —— 私钥从你提供的材料里挖"
                     "（PEM 或多行源码里的字面量）")
    elif frame["kind"] == "raw-url":
        lines.append("   · URL 编码（%XX 转义），解开后是 Base64/HEX 文本，再按该编码解密密文")
    elif frame["kind"] in ("raw-hex", "raw-base64url", "raw-base64"):
        lines.append("   · 无报文框架，密文 %d 字符（按 %s 解码）"
                     % (len(frame.get("cipher_text") or ""), frame["kind"].replace("raw-", "")))

    consts = materials.get("constants") or {}
    if consts:
        lines.append("② 密钥材料来源：%s" % "；".join(materials.get("source") or ["（未记录）"]))
        for key, label in (("secret_a", "AES 密钥常量"), ("secret_b", "AES IV 常量"),
                           ("kdf_key", "派生用密钥"),
                           ("kdf_iv", "派生用 IV")):
            if consts.get(key):
                lines.append("   · %s = %s" % (label, consts[key]))
    if r.get("unwrap"):
        lines.append("③ 密钥解封：用私钥解 `%s` 字段（%s）得到正文密钥"
                     % ((frame.get("envelope") or {}).get("key_field", "包裹密钥字段"),
                        (r["unwrap"].get("label") or "")[:40]))
    else:
        lines.append("③ 密钥派生：%s" % (r.get("preset") or "（直接用常量切片当密钥）"))
    for step in (r.get("trace") or [])[:6]:
        lines.append("   · %s %s → %d 字节 %s…" % (step.get("op"),
                                                   step.get("detail", ""),
                                                   step.get("out_len", 0),
                                                   (step.get("out_preview") or "")[:16]))
    lines.append("   · 得到正文密钥 = %s（%d 字节）" % (r["key_hex"], len(r["key_hex"]) // 2))
    lines.append("④ 正文解密：%s-%s / %s，密文按 %s 解码"
                 % (r["alg"].upper(), r["mode"].upper(), r["padding"].upper(),
                    "+".join(r.get("encoding_chain") or ["base64"])))
    if r.get("iv_prefix"):
        lines.append("   · IV/nonce 取自密文前 %d 字节（先切掉再解密）" % r["iv_prefix"])
    if r.get("iv_hex"):
        lines.append("   · IV = %s" % r["iv_hex"])
    if r.get("aad"):
        lines.append("   · GCM AAD = %s" % r["aad"])
    if r.get("seed"):
        lines.append("   · 种子（来自报文/源码）= %s" % r["seed"])
    for ev in best.get("evidence", []):
        lines.append("   · 依据：%s" % ev)
    mac = best.get("mac") or {}
    if mac.get("checked"):
        lines.append("⑤ 外层 mac 校验（%s，覆盖范围：%s）：%s"
                     % (mac.get("algo"), mac.get("scope"),
                        "✅ 一致（结论确凿）" if mac.get("ok") else "❌ 不一致（密钥或密文有误）"))
    else:
        lines.append("⑤ 报文未带可校验的 mac，结论基于明文特征打分（%s）"
                     % "；".join(best.get("evidence", [])[:2]))
    lines.append("⑥ 复现：可用 Tab 1/8/9 手工复核 —— 先用该密钥解密，再用 HMAC 脚本校验 mac")
    return lines


# ============================================================================
# 五、自检
# ============================================================================
_FIXTURE = {}


def _sm4_ecb_enc(key: bytes, data: bytes) -> bytes:
    """SM4-ECB/PKCS7 加密（自检夹具用；引擎里走统一入口 do_crypt）。"""
    return cc.do_crypt("sm4", "enc", key.hex(), None, data,
                       mode=cc.MODE_ECB, padding=cc.PAD_PKCS7, warn_weak=False)


# 自检夹具的合成常量（与任何真实目标无关，仅用于自检）
# 这四个值同时被 crypto_core.py 的自检与 key_material_analyzer.py 的用例引用，
# 改动时必须四处同步，否则跨模块基线会对不上。
FIXTURE_SEED = "808dfc1c0b6471f557ba0e50979dca88"
FIXTURE_KEY = "4A7F2C1E9B3D5A08"       # 16 个 ASCII 字符 = 16 字节（UTF-8 字面量）
FIXTURE_IV = "C6B1D90E37F2A485"
FIXTURE_HEAD = "12c14a244b84be04c60933da198be3dd"


def _load_fixture() -> dict:
    """内置一条已知答案密文，用于端到端自检。

    形态用的是最通用的写法（不绑定任何具体目标）：
        <32 位 HEX 种子>  +  Base64(密文)  [ + Base64(mac) ]
    密钥由「伪装常量里的两块 16 字节材料」经 AES-CBC(种子) → SHA256 → 取 [16:32] 派生得到。
    返回里同时给出**不带 mac** 与**带 mac** 两种 token，前者覆盖 `seed-prefix` 形态，
    后者用于 `verify_mac` 的直测（引擎已不再有「32hex 前缀 + mac」这类形态）。
    """
    global _FIXTURE
    if _FIXTURE:
        return _FIXTURE
    seed = FIXTURE_SEED
    a, b = FIXTURE_KEY, FIXTURE_IV
    text67 = FIXTURE_HEAD + a + b + "007"          # 32+16+16+3 = 67 字符
    plain = '{"respCode":"000000","msg":"ok"}'
    master = hashlib.sha256(cc.do_crypt("aes128", "enc", a.encode().hex(), b.encode().hex(),
                                        seed.encode(), mode=cc.MODE_CBC,
                                        padding=cc.PAD_PKCS7, warn_weak=False)).digest()
    cipher_b64 = base64.b64encode(_sm4_ecb_enc(master[16:32], plain.encode())).decode()
    mac_b64 = base64.b64encode(cc.do_hmac("hmac-sm3", master,
                                          (seed + cipher_b64).encode())).decode()
    _FIXTURE = {
        "token": seed + cipher_b64,
        "token_mac": seed + cipher_b64 + mac_b64,
        "plain": plain,
        "seed": seed,
        "secret_a": a, "secret_b": b,
        "master_hex": master.hex(),
        "mac_b64": mac_b64,
        "text67": text67,
        "const_uri": "data:image/png;base64,"
                     + base64.b64encode(text67.encode()).decode(),
    }
    return _FIXTURE


def _selftest() -> int:
    print("=" * 78)
    print(" 密文一键分析解密 自检")
    print("=" * 78)
    fails = 0

    def check(name, cond, extra=""):
        nonlocal fails
        if cond:
            print("   [ OK ] %s" % name)
        else:
            print("   [ !! ] %s%s" % (name, ("\n          " + str(extra)) if extra else ""))
            fails += 1

    fx = _load_fixture()
    # 材料直接从伪装常量里挖（走真实提取路径：base64 → 定长切片 → 密钥/IV 候选）
    mat = materials_from_text('var K = "%s";' % fx["const_uri"])

    # ---- 1. 形态识别（通用形态）----
    frames = detect_frames(fx["token"])
    kinds = [x["kind"] for x in frames]
    check("种子前置形态被识别", "seed-prefix" in kinds, str(kinds))
    check("种子前置会给出前 32 字符作为种子",
          next(x for x in frames if x["kind"] == "seed-prefix").get("seed") == fx["seed"])
    check("切出密文", bool(frames[0].get("cipher_text")))
    check("整段 HTTP 也能剥出 body",
          "seed-prefix" in [x["kind"] for x in detect_frames(
              "POST /x HTTP/1.1\r\nHost: a\r\n\r\n" + fx["token"])])
    check("裸 base64 形态可识别",
          detect_frame(base64.b64encode(b"x" * 32).decode())["kind"] == "raw-base64")
    check("裸 HEX 形态可识别", detect_frame("ab" * 32)["kind"] == "raw-hex")
    check("乱码输入返回 unknown", detect_frame("这不是密文 @@@")["kind"] == "unknown")

    # ---- 2. 材料挖掘 ----
    check("能从粘贴文本的伪装常量里挖出切片",
          len(mat["slices"]) >= 3, len(mat["slices"]))
    check("切片里能认出 16 字节的密钥与 IV",
          any(len(str(sl.get("value") or "")) == 16 and "密钥" in str(sl.get("role"))
              for sl in mat["slices"])
          and any(len(str(sl.get("value") or "")) == 16 and "IV" in str(sl.get("role"))
                  for sl in mat["slices"]))

    # ---- 3. 端到端：一键解出 ----
    # 用不带 mac 的 token —— 引擎已不再把「种子 + 密文 + 44 字符尾巴」当作一种形态，
    # 带 mac 的密文只能靠 verify_mac 直测（见第 10b 节）。
    res = auto_solve(fx["token"], extra_materials=mat)
    check("auto_solve 成功", res["status"] == "ok", res.get("summary"))
    best = res.get("best") or {}
    check("明文与已知答案一致", (best.get("plain") or "").strip() == fx["plain"],
          (best.get("plain") or "")[:80])
    check("可信度达标", (best.get("confidence") or 0) >= 0.9, best.get("confidence"))
    check("给出解密逻辑说明", len(res.get("decrypt_logic") or []) >= 5)
    logic = " ".join(res.get("decrypt_logic") or [])
    check("逻辑说明里含密钥派生与正文解密",
          "密钥派生" in logic and "正文解密" in logic)
    check("派生出的正文密钥与真值一致",
          best.get("key_hex") == cc.derive_key_by_preset(
              fx["seed"], "aes-cbc-then-sha256-slice", seed_format=cc.KEY_UTF8,
              key=fx["secret_a"], iv=fx["secret_b"], key_format=cc.KEY_UTF8,
              iv_format=cc.KEY_UTF8, slice_start=16, slice_end=32)["output_hex"])

    # ---- 3b. 多解释字面量密钥：候选配额不能被某一种解释吃光 ----
    # 同一串 16 个 ASCII 字符会被收成三种解释：按 hex 只有 8 字节、按 base64 是 12 字节、
    # 按 utf8 才是 16 字节。字节数决定可选算法集，而 8 字节那一支会展开出
    # DES/Blowfish/CAST5/RC2 一大票组合。**必须保证每个解释都分到配额**，
    # 否则正确的 utf8 解释（AES-128）永远排不上，一键解密直接判失败。
    _lit_key = "4A7F2C1E9B3D5A08"
    _lit_iv = "C6B1D90E37F2A485"
    _lit_body = b'{"code":0,"msg":"ok"}'
    _lit_ct = base64.b64encode(cc.do_crypt(
        "aes128", "enc", _lit_key.encode().hex(), _lit_iv.encode().hex(), _lit_body,
        mode=cc.MODE_CBC, padding=cc.PAD_PKCS7, warn_weak=False)).decode()
    _lit_src = 'var AES_KEY="%s"; var AES_IV="%s";' % (_lit_key, _lit_iv)
    _lit_res = auto_solve(_lit_ct + "\n" + _lit_src)
    check("多解释字面量密钥下，utf8 解释（AES-128）仍能被解出",
          _lit_res["status"] == "ok"
          and (_lit_res.get("best") or {}).get("plain", "").strip() == _lit_body.decode(),
          "%s / %s" % (_lit_res.get("status"), _lit_res.get("summary", "")[:60]))

    # ---- 4. 从"文本材料"自动完成（不显式给 materials）----
    # 模拟「密文 + 目标源码片段一起粘」的场景：常量从粘贴文本里自动挖。
    _src_line = 'var K = "%s";' % fx["const_uri"]
    res2 = auto_solve(fx["token"] + "\n" + _src_line)
    check("密文与源码片段混贴也能抽出并解出",
          res2["status"] == "ok"
          and (res2.get("best") or {}).get("plain", "").strip() == fx["plain"],
          "%s / %s" % (res2.get("status"),
                       (res2.get("frame") or {}).get("kind")))

    # ---- 5. 种子派生形态（另一组种子，独立于夹具）----
    a, b = fx["secret_a"], fx["secret_b"]
    seed2 = "8899aabbccddeeff0011223344556677"
    master = hashlib.sha256(cc.do_crypt("aes128", "enc", a.encode().hex(), b.encode().hex(),
                                                seed2.encode(), mode=cc.MODE_CBC,
                                                padding=cc.PAD_PKCS7, warn_weak=False)).digest()
    body = '{"respCode":"000000"}'
    ct = base64.b64encode(_sm4_ecb_enc(master[16:32], body.encode())).decode()
    mac = base64.b64encode(cc.do_hmac("hmac-sm3", master, (seed2 + ct).encode())).decode()
    resp_token = seed2 + ct
    fs2 = detect_frames(resp_token)
    kinds2 = [f["kind"] for f in fs2]
    check("种子派生形态被识别且种子取值正确",
          "seed-prefix" in kinds2 and fs2[0].get("seed") == seed2, str(kinds2))
    res3 = auto_solve(resp_token, extra_materials=mat)
    check("种子派生形态能一键解开",
          res3["status"] == "ok" and (res3.get("best") or {}).get("plain", "").strip() == body,
          res3.get("summary"))
    # mac 只走 verify_mac 直测（引擎已不把「44 字符尾巴」当作一种形态）
    _mf2 = {"kind": fs2[0]["kind"], "cipher_text": resp_token, "label": "合成",
            "raw_len": len(resp_token), "notes": [], "mac_b64": mac,
            "mac_scope": resp_token}
    check("种子派生形态的 mac 也能被 verify_mac 确认",
          verify_mac(_mf2, {"master_hex": master.hex()}).get("ok") is True)

    # ---- 5b. 形态识别优先级 ----
    # 纯 HEX 串同时也是合法 base64 字符集，也曾符合 `<32hex><base64>` 的形状，
    # 一旦判错就会把末尾当成 mac 切掉 → 密文错、必然解不开（实测踩过）。
    hex_only = bytes.fromhex("00112233445566778899001122334455" * 8).hex().upper()
    fh = detect_frames(hex_only)[0]
    check("纯 HEX 一律判为 raw-hex（不被误判成响应/种子）",
          fh["kind"] == "raw-hex", fh.get("kind"))
    check("纯 HEX 解出的字节数正确",
          len(fh.get("cipher_bytes") or b"") == len(hex_only) // 2,
          len(fh.get("cipher_bytes") or b""))

    hex32_then_b64 = ("00112233445566778899aabbccddeeff"
                      + base64.b64encode(b"A" * 48).decode())
    fh2 = detect_frames(hex32_then_b64)[0]
    check("`32hex+base64` 不再被当作纯 HEX",
          fh2["kind"] == "seed-prefix", fh2.get("kind"))

    b64u = base64.urlsafe_b64encode(b"B" * 64).decode().rstrip("=")
    fu = detect_frames(b64u)[0]
    check("Base64URL（含 -_、无填充）被识别",
          fu["kind"] == "raw-base64url" and len(fu.get("cipher_bytes") or b"") == 64,
          "%s/%d" % (fu.get("kind"), len(fu.get("cipher_bytes") or b"")))

    # 打分：中文明文必须被认下来（原来按字节算可打印率，中文会被当乱码丢掉）
    cn = '{"respCode":"000000","respMsg":"交易成功"}'.encode("utf-8")
    sc, _ = score_plaintext(cn)
    check("含中文的 JSON 明文能拿到合格分数（不再按字节误杀）", sc >= 0.8, sc)

    # ---- 6. 负向：没有材料时必须明确要求材料，而不是瞎猜 ----
    res4 = auto_solve(fx["token"])
    check("没有材料时明确提示需要材料（不瞎猜）",
          res4["status"] in ("need_material", "fail"), res4.get("status"))

    # ---- 7. 负向：篡改密文后必须判失败（不会把乱码当成功）----
    # 种子占前 32 字符，从第 40 位起改掉 4 个字符即落在 Base64 密文内部
    # （此前用 [150:154] 越界，实际只是"尾部追加"，测的变成了"长度变了要失败"）
    bad = (fx["token"][:40]
           + ("AAAA" if fx["token"][40:44] != "AAAA" else "BBBB")
           + fx["token"][44:])
    res5 = auto_solve(bad, extra_materials=mat)
    check("篡改密文后不会输出'成功'",
          res5["status"] != "ok" or not (res5.get("best") or {}).get("mac", {}).get("ok"),
          res5.get("status"))

    # ---- 8. 打分函数本身 ----
    s_good, ev_good = score_plaintext(b'{"reqHead":{"txCd":"x"}}')
    s_bad, ev_bad = score_plaintext(bytes(range(1, 40)))
    check("合法 JSON 报文得高分（%.2f）" % s_good, s_good >= 0.6, ev_good)
    check("二进制乱码得 0 分", s_bad == 0.0, ev_bad)

    # ---- 9. URL 编码形态（encodeURIComponent(base64(ct))）----
    # 这一条曾经必挂：解码链里 "url" 步骤产出 bytes，下一步 base64 拿 bytes 去做 re.sub
    # 直接抛 "cannot use a string pattern on a bytes-like object"。
    import urllib.parse
    des_key, des_iv = b"deskey01", b"iv-12345"
    des_ct = cc.do_crypt("des", "enc", des_key.hex(), des_iv.hex(),
                         b'{"reqHead":{"txCd":"TEST-TXCD-0001"}}',
                         mode=cc.MODE_CBC, padding=cc.PAD_PKCS7, warn_weak=False)
    url_token = urllib.parse.quote(base64.b64encode(des_ct).decode("ascii"), safe="")
    fu = detect_frames(url_token)[0]
    check("URL 编码形态被识别", fu["kind"] == "raw-url", fu.get("kind"))
    res_u = auto_solve(url_token, extra_materials={"literals": {"key": ["deskey01"],
                                                                "iv": ["iv-12345"]}})
    check("URL→Base64 编码链能解开（url 步骤不再打成 bytes）",
          res_u["status"] == "ok" and (res_u.get("best") or {}).get("plain", "").strip()
          == '{"reqHead":{"txCd":"TEST-TXCD-0001"}}',
          res_u.get("summary"))

    # ---- 10. mac 算法自适应：同样 44 字符的 mac，算法换成 HMAC-SHA256 也要能验 ----
    a2, b2 = fx["secret_a"], fx["secret_b"]
    master2 = hashlib.sha256(cc.do_crypt("aes128", "enc", a2.encode().hex(), b2.encode().hex(),
                                         seed2.encode(), mode=cc.MODE_CBC,
                                         padding=cc.PAD_PKCS7, warn_weak=False)).digest()
    body2 = '{"respCode":"000000"}'
    ct2 = base64.b64encode(_sm4_ecb_enc(master2[16:32], body2.encode())).decode()
    sha_mac = base64.b64encode(cc.do_hmac("hmac-sha256", master2,
                                          (seed2 + ct2).encode())).decode()
    # 不带 mac 的种子派生形态仍能一键解出（mac 交给下面的 verify_mac 直测）
    res_m = auto_solve(seed2 + ct2, extra_materials=mat)
    check("HMAC-SHA256 样本的种子派生形态也能一键解出",
          res_m["status"] == "ok"
          and (res_m.get("best") or {}).get("plain", "").strip() == body2,
          res_m.get("summary"))

    # ---- 10b. verify_mac 直测（不经 auto_solve，覆盖正/负两向）----
    # 用到「同一串 32 字节 mac 有两种可能算法」这一事实：验证算法枚举顺序与
    # 覆盖范围（scope）改动必须被检出。
    _mf = {"kind": "raw-base64", "cipher_text": seed2 + ct2, "label": "合成",
           "raw_len": len(seed2 + ct2), "notes": [],
           "mac_b64": sha_mac, "mac_scope": seed2 + ct2}
    _got = verify_mac(_mf, {"master_hex": master2.hex()})
    check("verify_mac 直测：正确 mac 判定 ok 且 algo=HMAC-SHA256",
          _got.get("ok") is True and _got.get("algo") == "HMAC-SHA256", str(_got.get("algo")))
    check("verify_mac 直测：同长度的 HMAC-SM3 会先被试到（两种都要枚举）",
          "hmac-sm3" in (_got.get("tried") or []), str(_got.get("tried")))
    check("verify_mac 直测：错误主密钥必须被拒",
          verify_mac(_mf, {"master_hex": "00" * 32}).get("ok") is not True)
    _mf_scope = dict(_mf, mac_scope=_mf["mac_scope"] + "x")
    check("verify_mac 直测：mac 覆盖范围被改动后必须判不通过",
          verify_mac(_mf_scope, {"master_hex": master2.hex()}).get("ok") is not True)

    # ---- 11. SM2 混合信封（ed / sked 两字段形态）----
    kp = cc.sm2_keygen()
    env_key = bytes.fromhex("3c5e7a9b1d2f40618293a4b5c6d7e8f9")
    env_iv = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    body3 = '{"reqData":{"acctNo":"TEST-ACCOUNT-0001"}}'
    ed = base64.b64encode(cc.do_crypt("sm4", "enc", env_key.hex(), env_iv.hex(),
                                      body3.encode(), mode=cc.MODE_CBC,
                                      padding=cc.PAD_PKCS7, warn_weak=False)).decode()
    sked = cc.do_sm2("enc", data=env_key, public_key=kp["public_key"],
                     cipher_mode=cc.SM2_C1C3C2).hex()
    env_json = json.dumps({"appId": "9988", "ed": ed, "sked": sked, "iv": env_iv.hex()},
                          ensure_ascii=False)
    fe = detect_frames(env_json)[0]
    check("JSON 混合信封被识别", fe["kind"] == "json-envelope", fe.get("kind"))
    check("信封字段分工正确（sked=包裹密钥 / ed=密文 / iv=IV）",
          (fe.get("envelope") or {}).get("key_field") == "sked"
          and (fe.get("envelope") or {}).get("data_field") == "ed"
          and bool((fe.get("envelope") or {}).get("iv_hex")), str(fe.get("envelope")))
    res_e = auto_solve(env_json, extra_materials={"literals": {"priv": [kp["private_key"]]}})
    check("SM2 私钥解封信封并解出明文",
          res_e["status"] == "ok" and (res_e.get("best") or {}).get("plain", "").strip() == body3,
          res_e.get("summary"))
    check("解封出来的对称密钥与真值一致",
          (res_e.get("best") or {}).get("key_hex") == env_key.hex(),
          (res_e.get("best") or {}).get("key_hex"))

    # ---- 12. 信封缺私钥时必须明确说"缺私钥"，而不是瞎试 ----
    res_e2 = auto_solve(env_json)
    check("信封缺私钥时提示需要私钥而不是瞎猜",
          res_e2["status"] == "need_material" and "私钥" in res_e2["summary"],
          res_e2.get("summary", "")[:60])

    # ---- 13. RSA-OAEP 混合信封 ----
    rkp = cc.rsa_keygen(2048)
    wrapped = cc.do_rsa("enc", data=env_key, key_text=rkp["public_pem"],
                        padding=cc.RSA_OAEP, hash_alg="sha256")
    ed2 = base64.b64encode(cc.do_crypt("sm4", "enc", env_key.hex(), env_iv.hex(),
                                       body3.encode(), mode=cc.MODE_CBC,
                                       padding=cc.PAD_PKCS7, warn_weak=False)).decode()
    env_json2 = json.dumps({"appId": "9988", "encKey": base64.b64encode(wrapped).decode(),
                            "iv": env_iv.hex(), "data": ed2}, ensure_ascii=False)
    res_r = auto_solve(env_json2, extra_materials={"private_keys": [
        {"kind": "RSA PRIVATE KEY", "value": rkp["private_pem"]}]})
    check("RSA-OAEP 信封解封并解出明文（v1.5 不会假成功挡住 OAEP）",
          res_r["status"] == "ok" and (res_r.get("best") or {}).get("plain", "").strip() == body3,
          res_r.get("summary"))

    # ---- 14. 编码链剪枝：解不开的链不该把正确的配方挤掉 ----
    b64_only = base64.b64encode(cc.do_crypt("sm4", "enc", env_key.hex(), None,
                                            b'{"a":1}', mode=cc.MODE_ECB,
                                            padding=cc.PAD_PKCS7, warn_weak=False)).decode()
    fb = detect_frames(b64_only)[0]
    keys_b = key_candidates({"literals": {"key": [env_key.hex()]}, "constants": {}}, fb)
    recs = build_recipes(fb, {"literals": {"key": [env_key.hex()]}, "constants": {}}, keys_b)
    # 断言不能写成"只剩 base64" —— base64url 与 url 对纯 base64 串本来就**也解得到**
    # （字符集相同 / 没有 %XX 时 unquote 是恒等），它们不是错，只是冗余。
    # 真正要保证的是：解不开的链（HEX 系）不再被铺开，且留下的链都真的能解开。
    got_chains = {tuple(r["encoding_chain"]) for r in recs}
    check("解不开的编码链（HEX 系）已被剪掉",
          bool(recs) and ("hex",) not in got_chains and ("hex", "base64") not in got_chains
          and ("base64", "hex") not in got_chains, str(sorted(got_chains)))
    all_decodable = True
    for c in got_chains:
        try:
            _decode_ciphertext(fb, list(c))
        except Exception:  # noqa: BLE001
            all_decodable = False
    check("留下的编码链条条都能解开密文", all_decodable, str(sorted(got_chains)))

    print("-" * 78)
    if fails:
        print(" [FAIL] %d 项未通过。" % fails)
        return 2
    print(" [PASS] 密文一键分析解密自检全部通过（形态识别 / 材料挖掘 / 端到端 / mac 校验 / "
          "非对称信封 / 编码链 / 负向）。")
    return 0


# ============================================================================
# 六、CLI
# ============================================================================
def _emit(res: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(res, ensure_ascii=False))
        return
    f = res.get("frame") or {}
    print("=" * 78)
    print(" 密文一键分析解密")
    print("=" * 78)
    print(" 形态：%s" % f.get("label"))
    m = res.get("materials") or {}
    if m.get("sources"):
        print(" 材料来源：%s" % "；".join(m["sources"]))
    for line in res.get("decrypt_logic") or []:
        print(" " + line)
    print("-" * 78)
    print(" 结论：%s" % res.get("summary"))
    best = res.get("best") or {}
    if best:
        print(" 密钥：%s（%d 字节）" % (best.get("key_hex"), best.get("key_bytes")))
        print(" 明文（%d 字节）：" % best.get("plain_len"))
        print(best.get("plain"))
    if res.get("attempts"):
        print("-" * 78)
        print(" 尝试记录（%d 条）：" % len(res["attempts"]))
        for a in res["attempts"][:10]:
            print("   [%s] %.2f  %s" % ("OK" if a["ok"] else "  ", a["score"], a["recipe"]))
            if not a["ok"] and a.get("reason"):
                print("        → %s" % a["reason"][:100])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cipher_auto_solver.py",
        description="贴一段密文 → 自动分析加解密逻辑 → 尝试解密 → 输出明文与依据",
    )
    p.add_argument("--text", help="密文文本（整段 HTTP / JSON 信封 / 附带源码片段均可）")
    p.add_argument("--file", help="密文文件路径")
    p.add_argument("--target-dir", help="目标目录（从中自动挖密钥常量与派生链）")
    p.add_argument("--target-file", help="目标文件（JS/jar/class 等）")
    p.add_argument("--json", action="store_true", help="以 JSON 输出")
    p.add_argument("--selftest", action="store_true", help="运行自检")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.selftest:
        return _selftest()
    text = args.text
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print("读取密文文件失败：%s" % exc, file=sys.stderr)
            return 2
    if not text:
        build_parser().print_help()
        return 1
    res = auto_solve(text, target_dir=args.target_dir or "", target_file=args.target_file or "")
    _emit(res, args.json)
    return 0 if res.get("status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
