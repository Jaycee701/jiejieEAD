#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成「密文样本集」——覆盖多种算法 / 模式 / 编码 / 报文框架，用于验证 jiejieEAD 的
一键解密能力，并作为人工复核的对照材料。

每个样本是一个目录：
    cipher.txt   密文（原样，可能带前缀 / 报文框架 / 双层编码）
    app.js       目标前端源码片段（含密钥常量与派生逻辑）——工具从这里挖材料
    expect.json  标准答案（明文 / 算法 / 模式 / 填充 / 编码 / 密钥），仅验证脚本使用

用法：
    python make_cipher_samples.py --out <输出目录>
    python make_cipher_samples.py --out <输出目录> --only 03,07
"""
from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import json
import os
import sys
import urllib.parse
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
PY_DIR = os.path.normpath(os.path.join(HERE, "..", "python"))
for p in (PY_DIR, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import crypto_core as cc  # noqa: E402


# ============================================================================
# 基础工具
# ============================================================================
def h2b(s: str) -> bytes:
    return bytes.fromhex(s)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def enc(alg: str, mode: str, padding: str, key: bytes, data: bytes,
        iv: bytes = b"", aad: bytes = b"") -> bytes:
    return cc.do_crypt(alg, "enc", key.hex(), iv.hex() if iv else None, data,
                       mode=mode, padding=padding, aad=aad, warn_weak=False)


def key_of(alg: str) -> bytes:
    """按算法取一个定长测试密钥（内容可读，便于人工核对）。"""
    spec = cc.get_spec(alg)
    n = spec.default_key_len
    base = (b"0123456789abcdef" * 4)[:n]
    return base


PLAIN_JSON = ('{"reqHead":{"txCd":"TEST-TXCD-0001","chnlNo":"TEST-CHNL-0001"},'
              '"reqData":{"acctNo":"TEST-ACCOUNT-0001","amt":"1280.00"}}')
PLAIN_TEXT = "jiejieEAD 密文样本集 · 明文内容（含中文与符号 #@!）"


# ============================================================================
# 样本定义
# ============================================================================
def sample_03() -> dict:
    """AES-128-CBC + UTF-8 字面量密钥（源码里是普通字符串常量）。"""
    key, iv = b"4A7F2C1E9B3D5A08", b"C6B1D90E37F2A485"
    ct = b64(enc("aes128", "cbc", "pkcs7", key, PLAIN_JSON.encode(), iv))
    src = f'''// 微信/App 内嵌页常见：密钥直接写成字符串字面量（注意是 16 个 ASCII = 16 字节）
var AES_KEY = "{key.decode()}";
var AES_IV  = "{iv.decode()}";
var out = CryptoJS.AES.encrypt(plain, CryptoJS.enc.Utf8.parse(AES_KEY),
           {{ iv: CryptoJS.enc.Utf8.parse(AES_IV), mode: CryptoJS.mode.CBC,
              padding: CryptoJS.pad.Pkcs7 }}).toString();
'''
    return {
        "dir": "03-AES128-CBC-UTF8字面量密钥",
        "cipher": ct,
        "app_js": src,
        "expect": {"plain": PLAIN_JSON, "alg": "aes128", "mode": "cbc", "padding": "pkcs7",
                   "encoding": "base64", "framing": "raw-base64",
                   "key_hex": key.hex(), "iv_hex": iv.hex()},
        "feature": "裸 Base64 密文；密钥是 16 个可打印字符（按 HEX 解只有 8 字节，会报长度错）",
        "idea": "从源码里提「命名密钥字面量」→ 同时按 UTF-8 与 HEX 两种解释当候选 → AES-CBC 解密",
    }


def sample_04() -> dict:
    """AES-256-CBC + gzip 压缩 + Base64URL（编码链：压缩在前、编码在后）。"""
    key, iv = key_of("aes256"), b"1122334455667788"
    payload = (PLAIN_TEXT * 40).encode()
    ct = enc("aes256", "cbc", "pkcs7", key, gzip.compress(payload, mtime=0), iv)
    cipher = b64url(ct)
    src = f'''// 大字段先 gzip 压缩再加密，最后用 Base64URL（去 '='）传出
var AES_KEY = "{key.hex()}";
var IV = "{iv.decode()}";
var packed = pako.gzip(JSON.stringify(payload));      // 压缩在加密之前
var ct = aesEncrypt(packed, AES_KEY, IV, 'cbc');
var out = base64UrlEncode(ct);                        // '-' '_' 变体，去掉 '='
'''
    return {
        "dir": "04-AES256-CBC-gzip压缩-Base64URL",
        "cipher": cipher,
        "app_js": src,
        "expect": {"plain": PLAIN_TEXT * 40, "alg": "aes256", "mode": "cbc", "padding": "pkcs7",
                   "encoding": "base64url", "framing": "raw-base64",
                   "key_hex": key.hex(), "iv_hex": iv.hex(), "inner_compression": "gzip"},
        "feature": "Base64URL 编码（有 -_、无 =）；解密后还要 gzip 解压才是明文",
        "idea": "编码链要认 Base64URL；解密结果不是可读文本时自动试压缩还原（gzip 魔数 1F 8B）",
    }


def sample_05() -> dict:
    """3DES-CBC + PKCS7 + HEX 编码（老系统）。"""
    key, iv = key_of("des3"), b"0f1e2d3c4b5a6978"[:8]  # 3DES 分组 8 字节，IV 必须 8 字节
    ct = enc("des3", "cbc", "pkcs7", key, PLAIN_JSON.encode(), iv)
    src = f'''// 老核心系统的 3DES（密钥 24 字节，HEX 字面量）
var DES3_KEY = "{key.hex()}";
var DES3_IV  = "{iv.hex()}";
var ct = DES3.encrypt(plain, {cc.DES3.__name__ if False else "hexToBytes(DES3_KEY)"}, hexToBytes(DES3_IV), {{mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7}});
var out = ct.ciphertext.toString().toUpperCase();     // HEX 编码，大写
'''
    return {
        "dir": "05-3DES-CBC-HEX编码",
        "cipher": binascii.hexlify(ct).decode().upper(),
        "app_js": src,
        "expect": {"plain": PLAIN_JSON, "alg": "des3", "mode": "cbc", "padding": "pkcs7",
                   "encoding": "hex", "framing": "raw-hex",
                   "key_hex": key.hex(), "iv_hex": iv.hex()},
        "feature": "纯大写 HEX 密文（长度是 16 的倍数，容易和 Base64 混淆）",
        "idea": "形态识别时 HEX 优先于 Base64；3DES 分组是 8 字节，密钥 24 字节走 des3",
    }


def sample_06() -> dict:
    """RC4 流密码 + Base64。"""
    key = b"RC4-Stream-Key-2026"
    ct = enc("rc4", "stream", "none", key, PLAIN_JSON.encode())
    src = f'''// 仍有老接口在用 RC4（流密码，无分组/无填充/无 IV）
var RC4_KEY = "{key.decode()}";
var ct = RC4.encrypt(plain, RC4_KEY);
var out = btoa(ct.toString());
'''
    return {
        "dir": "06-RC4流密码-Base64",
        "cipher": b64(ct),
        "app_js": src,
        "expect": {"plain": PLAIN_JSON, "alg": "rc4", "mode": "stream", "padding": "none",
                   "encoding": "base64", "framing": "raw-base64",
                   "key_bytes": len(key)},
        "feature": "密文长度与明文**等长**（不是 8/16 的倍数！），这是流密码的典型特征",
        "idea": "密文长度不是分组整数倍 → 优先怀疑流密码（RC4）；密钥按 UTF-8 字面量取",
    }


def sample_07() -> dict:
    """SM4-CTR + IV 前置（cipher = iv(16) + ct）+ Base64。"""
    key, iv = key_of("sm4"), b"A1B2C3D4E5F60718"
    ct = enc("sm4", "ctr", "none", key, PLAIN_JSON.encode(), iv)
    src = f'''// IV 不单独传，直接拼在密文前面（16 字节）
var SM4_KEY = "{key.hex()}";
var iv = randomBytes(16);
var ct = sm4Encrypt(plain, SM4_KEY, iv, 'ctr');
var out = base64(iv.concat(ct));        // ← 注意这里：IV 前置
'''
    return {
        "dir": "07-SM4-CTR-IV前置",
        "cipher": b64(iv + ct),
        "app_js": src,
        "expect": {"plain": PLAIN_JSON, "alg": "sm4", "mode": "ctr", "padding": "none",
                   "encoding": "base64", "framing": "raw-base64", "iv_prefix": 16,
                   "key_hex": key.hex(), "iv_hex": iv.hex()},
        "feature": "密文比明文长 16 字节（多出的正是前置 IV）；CTR 是流式、无需填充",
        "idea": "试「密文前 16 字节是 IV」的配方变体；密钥是 HEX 字面量 → 走 sm4+ctr",
    }


def sample_08() -> dict:
    """AES-128-GCM + AAD + Base64（cipher = nonce(12) + ct + tag(16)）。"""
    key, nonce = key_of("aes128"), b"NONCE0123456"
    aad = b"appid=9988&v=1"
    ct = enc("aes128", "gcm", "none", key, PLAIN_JSON.encode(), nonce, aad)
    src = f'''var AES_KEY = "{key.hex()}";
var nonce = randomBytes(12);
var ct = gcmEncrypt(plain, AES_KEY, nonce, {{aad: "appid=9988&v=1"}});   // AAD 参与认证
var out = base64(nonce.concat(ct));    // nonce 前置，密文尾部带 16 字节认证标签
'''
    return {
        "dir": "08-AES128-GCM-AAD-nonce前置",
        "cipher": b64(nonce + ct),
        "app_js": src,
        "expect": {"plain": PLAIN_JSON, "alg": "aes128", "mode": "gcm", "padding": "none",
                   "encoding": "base64", "framing": "raw-base64", "iv_prefix": 12,
                   "key_hex": key.hex(), "iv_hex": nonce.hex(), "aad": aad.decode(),
                   "tag_tail": 16},
        "feature": "GCM 认证加密：密文尾部 16 字节是标签；nonce 12 字节前置；AAD 必须一致才解得开",
        "idea": "试「前 12 字节 nonce」变体；GCM 失败会报认证标签不通过（而不是乱码），可作为强判据",
    }


def sample_09() -> dict:
    """双层 Base64（外层 Base64 包住 Base64 密文）+ AES-128-ECB。"""
    key = key_of("aes128")
    ct = enc("aes128", "ecb", "pkcs7", key, PLAIN_JSON.encode())
    cipher = base64.b64encode(b64(ct).encode()).decode()
    src = f'''var AES_KEY = "{key.hex()}";
var ct = aesEcbEncrypt(plain, AES_KEY);
var once = btoa(ct);            // 第一层
var twice = btoa(once);         // 第二层（网关要求"二次编码"）
'''
    return {
        "dir": "09-AES128-ECB-双层Base64",
        "cipher": cipher,
        "app_js": src,
        "expect": {"plain": PLAIN_JSON, "alg": "aes128", "mode": "ecb", "padding": "pkcs7",
                   "encoding": "base64", "framing": "raw-base64", "encoding_chain": ["base64", "base64"],
                   "key_hex": key.hex()},
        "feature": "解一次 Base64 得到的还是 Base64 文本（长度仍是 4 的倍数），需要剥两层",
        "idea": "编码链支持 base64,base64；剥完两层后长度才对得上分组倍数",
    }


def sample_10() -> dict:
    """整段 HTTP 报文（body 是种子前置密文）——考察「自动剥 HTTP 头」。"""
    s12 = sample_12()          # 种子前置形态（通用）
    http = ("POST /h5/gateway.do HTTP/1.1\r\nHost: bank.example.com\r\n"
            "Content-Type: application/json\r\n\r\n" + s12["cipher"])
    return {
        "dir": "10-整段HTTP报文-自动剥头",
        "cipher": http,
        "app_js": s12["app_js"],
        "expect": dict(s12["expect"], framing="http+seed-prefix"),
        "feature": "整段 HTTP 文本（含请求行/头），真正的密文在 body 里",
        "idea": "先按 \\r\\n\\r\\n 剥掉 HTTP 头，再对 body 做形态识别（种子前置 → 派生 → 解密）",
    }


def sample_11() -> dict:
    """裸 HEX（无任何框架）+ SM4-ECB + 密钥是 Base64 字面量。"""
    key = key_of("sm4")
    ct = enc("sm4", "ecb", "pkcs7", key, PLAIN_JSON.encode())
    src = f'''// 密钥以 Base64 形式写在构建产物里
var SM4_KEY_B64 = "{b64(key)}";
var key = base64Decode(SM4_KEY_B64);        // 解出来才是 16 字节密钥
var ct = sm4Ecb(plain, key);
var out = bytesToHex(ct);
'''
    return {
        "dir": "11-SM4-ECB-裸HEX-Base64密钥",
        "cipher": binascii.hexlify(ct).decode(),
        "app_js": src,
        "expect": {"plain": PLAIN_JSON, "alg": "sm4", "mode": "ecb", "padding": "pkcs7",
                   "encoding": "hex", "framing": "raw-hex", "key_b64": b64(key)},
        "feature": "纯小写 HEX 密文，无任何前缀；密钥在源码里是 Base64 字面量",
        "idea": "命名密钥字面量按 Base64 解释；密文按 HEX 解码后长度正好是 16 的倍数",
    }


def sample_12() -> dict:
    """种子派生（SHA256(种子) 前 16 字节）+ 密文 = 种子(32hex) + Base64 密文。"""
    seed = "5f2c1a9b8e7d6c5b4a39281706f5e4d3"
    key = hashlib.sha256(seed.encode()).digest()[:16]
    ct = enc("sm4", "ecb", "pkcs7", key, PLAIN_TEXT.encode())
    src = '''// 密钥不是常量，而是"每次请求随机种子算出来的"，种子随密文一起传
var seed = randomHex(32);
var key = sha256(seed).slice(0, 32);        // 取前 16 字节（32 个 hex 字符）
var ct = sm4Ecb(plain, key);
var out = seed + base64(ct);                // 种子明文前置
'''
    return {
        "dir": "12-种子前置-SHA256派生-SM4ECB",
        "cipher": seed + b64(ct),
        "app_js": src,
        "expect": {"plain": PLAIN_TEXT, "alg": "sm4", "mode": "ecb", "padding": "pkcs7",
                   "encoding": "base64", "framing": "seed-prefix", "seed": seed,
                   "key_note": "SHA256(seed)[0:16]"},
        "feature": "密文开头是 32 个 hex 字符（种子明文），其后才是 Base64 密文",
        "idea": "试「前 32 字符是种子」的配方变体 + 派生链 SHA256(种子) 取前 16 字节",
    }




def sample_13() -> dict:
    """AES192-CBC + zlib 压缩 + 多级编码（hex(base64(密文))）。"""
    key = b"jiejieEAD-AES192-KEY-001"         # 24 字节
    iv = b"iv-abcdefghijklm"                   # 16 字节
    packed = zlib.compress(PLAIN_JSON.encode("utf-8"))
    ct = enc("aes192", "cbc", "pkcs7", key, packed, iv)
    out = b64(ct).encode("ascii").hex().upper()
    src = f'''// 大字段先 zlib 压缩再加密，最后套两层编码：hex(base64(密文))
var AES192_KEY = "{key.decode()}";
var AES192_IV  = "{iv.decode()}";
var packed = zlibDeflate(JSON.stringify(payload));   // 压缩在加密之前
var ct = aesEncrypt(packed, AES192_KEY, AES192_IV, 'cbc');
var out = bytesToHex(base64Encode(ct));              // 先 base64，再整个转 HEX
'''
    return {
        "dir": "13-AES192-CBC-zlib压缩-多级编码",
        "cipher": out,
        "app_js": src,
        "expect": {"plain": PLAIN_JSON, "alg": "aes192", "mode": "cbc", "padding": "pkcs7",
                   "encoding": "hex(base64)", "framing": "raw-hex",
                   "key_note": "源码字面量（UTF-8，24 字节）", "iv_utf8": iv.decode(),
                   "inner_compression": "zlib"},
        "feature": "纯 HEX，但解出来不是密文而是 Base64 文本（hex 包着 base64）；解密后还要 zlib 解压",
        "idea": "编码链要按「先解 HEX 再解 Base64」倒着还原；解密结果不是可读文本时自动试压缩还原（zlib 魔数 78 9C）",
    }


def sample_14() -> dict:
    """DES-CBC + URL 编码（encodeURIComponent(base64(密文))）。"""
    key = b"deskey01"          # 8 字节
    iv = b"iv-12345"           # 8 字节
    ct = enc("des", "cbc", "pkcs7", key, PLAIN_JSON.encode("utf-8"), iv)
    out = urllib.parse.quote(b64(ct), safe="")
    src = f'''// 老系统：DES-CBC，密文 base64 之后整体做一次 URL 编码
var DES_KEY = "{key.decode()}";
var DES_IV  = "{iv.decode()}";
var ct = DES.encrypt(plain, DES_KEY, {{iv: DES_IV, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7}});
var out = encodeURIComponent(ct.toString());   // %2B / %2F / %3D 满天飞
'''
    return {
        "dir": "14-DES-CBC-URL编码",
        "cipher": out,
        "app_js": src,
        "expect": {"plain": PLAIN_JSON, "alg": "des", "mode": "cbc", "padding": "pkcs7",
                   "encoding": "url(base64)", "framing": "raw-url",
                   "key_note": "源码字面量（UTF-8，8 字节）", "iv_utf8": iv.decode()},
        "feature": "满屏 %XX 转义，URL 解码后才是 Base64 密文；DES 分组 8 字节",
        "idea": "形态识别要认 URL 编码 → 先 unquote 拿到 Base64 → 再解码 → DES-CBC 解密",
    }


def sample_15() -> dict:
    """SM4-ECB + ZeroPadding + Base64（明文恰好对齐分组，零填充不加整块）。"""
    key = b"sm4-zero-pad-key"      # 16 字节
    body = PLAIN_JSON
    while len(body.encode("utf-8")) % 16:
        body += " "                # 补空格对齐，避免零填充真的写入 0x00（那会让打分变差）
    ct = enc("sm4", "ecb", "zero", key, body.encode("utf-8"))
    src = f'''// 老系统喜欢 ZeroPadding（补 0x00）而不是 PKCS7
var SM4_KEY = "{key.decode()}";
var ct = sm4.encrypt(plain, SM4_KEY, {{mode: 'ecb', padding: 'ZeroPadding'}});
var out = base64Encode(ct);
'''
    return {
        "dir": "15-SM4-ECB-ZeroPadding",
        "cipher": b64(ct),
        "app_js": src,
        "expect": {"plain": body, "alg": "sm4", "mode": "ecb", "padding": "zero",
                   "encoding": "base64", "framing": "raw-base64",
                   "key_note": "源码字面量（UTF-8，16 字节）"},
        "feature": "标准 Base64 密文；填充方式是补零（ZeroPadding）而非 PKCS7",
        "idea": "候选配方里 PKCS7 / Zero / None 都要试，只试 PKCS7 会解不开",
    }


def sample_17() -> dict:
    """RSA-2048 混合信封：RSA-OAEP 包裹 SM4 密钥，SM4-CBC 解正文（JSON 信封）。"""
    kp = cc.rsa_keygen(2048)
    sm4_key = bytes.fromhex("8f2a1c4e6b9d0f3a5c7e1b2d4f6a8c0e")
    iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    ct = enc("sm4", "cbc", "pkcs7", sm4_key, PLAIN_JSON.encode("utf-8"), iv)
    wrapped = cc.do_rsa("enc", data=sm4_key, key_text=kp["public_pem"],
                        padding=cc.RSA_OAEP, hash_alg="sha256")
    env = {"appId": "9988", "encKey": b64(wrapped), "iv": iv.hex(),
           "data": b64(ct), "t": "1699999999"}
    app_src = '''// 前端：随机生成对称密钥 → SM4-CBC 解正文 → RSA-OAEP 包裹该密钥 → JSON 信封
var RSA_PUB = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\\n-----END PUBLIC KEY-----";
var sm4Key = randomHex(16);
var iv = randomHex(16);
var envelope = { appId: "9988", encKey: rsaEncrypt(sm4Key, RSA_PUB),
                 iv: iv, data: sm4Cbc(JSON.stringify(payload), sm4Key, iv), t: Date.now() };
'''
    server_src = ('''// 【服务端解密片段】真实场景里私钥不会出现在前端；这里放出来是为了让样本可自证可解。
// 实战中它通常来自服务端代码仓库、配置文件或运维泄漏的密钥文件。
var RSA_PRIVATE_PEM = `%s`;
var sm4Key = rsaDecrypt(envelope.encKey, RSA_PRIVATE_PEM, 'oaep');  // OAEP/SHA-256
var plain = sm4Decrypt(envelope.data, sm4Key, envelope.iv, 'cbc');
''' % kp["private_pem"])
    return {
        "dir": "17-RSA2048混合信封-OAEP包裹SM4",
        "cipher": json.dumps(env, ensure_ascii=False),
        "app_js": app_src,
        "extra_files": {"server.js": server_src},
        "files_note": " · `server.js` 服务端解密片段（含私钥，工具从这里挖私钥 —— "
                      "真实场景中它来自服务端代码/配置，不会在前端）",
        "expect": {"plain": PLAIN_JSON, "alg": "sm4", "mode": "cbc", "padding": "pkcs7",
                   "encoding": "base64", "framing": "json-envelope",
                   "asym": "rsa-oaep-sha256", "key_hex": sm4_key.hex(), "iv_hex": iv.hex()},
        "feature": "整段 JSON：`encKey` 是 RSA-2048/OAEP 包裹的 SM4 密钥（256 字节），"
                   "`iv` 是十六进制 IV，`data` 是 SM4-CBC 密文",
        "idea": "先认成「混合信封」→ 从材料里挖出 PEM 私钥 → RSA-OAEP 解封得到 16 字节 SM4 密钥 "
                "→ 再用它解 data 字段（长度必须是 16/24/32，否则说明填充/算法不对）",
    }


def sample_18() -> dict:
    """SM2 混合信封（ed / sked）：SM2 包裹 SM4 密钥，两字段一起传。"""
    kp = cc.sm2_keygen()
    sm4_key = bytes.fromhex("3c5e7a9b1d2f40618293a4b5c6d7e8f9")
    iv = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    ct = enc("sm4", "cbc", "pkcs7", sm4_key, PLAIN_JSON.encode("utf-8"), iv)
    wrapped = cc.do_sm2("enc", data=sm4_key, public_key=kp["public_key"],
                        cipher_mode=cc.SM2_C1C3C2)
    env = {"appId": "9988", "ed": b64(ct), "sked": wrapped.hex(), "iv": iv.hex()}
    app_src = '''// 安全键盘同构写法：随机 SM4 密钥加密数据，再把该密钥用 SM2 公钥包起来
var SM2_PUB = "%s";
var o = generateSM4Key();                       // ① 随机 SM4 密钥
var ed = SM4(pad(keysSeq), o);                  // ② SM4 加密数据
var sked = sm2Encrypt(o, SM2_PUB);              // ③ SM2 包裹那把密钥（HEX 输出）
var envelope = { appId: "9988", ed: ed, sked: sked, iv: iv };
''' % kp["public_key"]
    server_src = ('''// 【服务端解密片段】SM2 私钥在服务端；这里放出来是为了让样本可自证可解。
var SM2_PRIV = "%s";
var o = sm2Decrypt(envelope.sked, SM2_PRIV);         // C1C3C2，HEX
var plain = sm4Decrypt(envelope.ed, o, envelope.iv, 'cbc');
''' % kp["private_key"])
    return {
        "dir": "18-SM2混合信封-ed-sked字段",
        "cipher": json.dumps(env, ensure_ascii=False),
        "app_js": app_src,
        "extra_files": {"server.js": server_src},
        "files_note": " · `server.js` 服务端解密片段（含 SM2 私钥）",
        "expect": {"plain": PLAIN_JSON, "alg": "sm4", "mode": "cbc", "padding": "pkcs7",
                   "encoding": "base64", "framing": "json-envelope",
                   "asym": "sm2-c1c3c2", "key_hex": sm4_key.hex(), "iv_hex": iv.hex()},
        "feature": "JSON 里 `sked` 是 SM2 密文（C1C3C2，HEX，113 字节），`ed` 是 SM4-CBC 密文，"
                   "`iv` 是十六进制 IV —— 字段命名沿用国密前端的常见约定",
        "idea": "SM2 私钥从服务端片段里挖出来（源里是 64 位十六进制）→ SM2 解封 sked 得到 16 字节密钥 "
                "→ 再用它解 ed（C1 排序 C1C3C2 / C1C2C3 两种都要试）",
    }


SAMPLES = [
    sample_03, sample_04, sample_05, sample_06, sample_07, sample_08, sample_09, sample_10,
    sample_11, sample_12, sample_13, sample_14, sample_15, sample_17, sample_18,
]


# ============================================================================
# 写盘
# ============================================================================
def write_all(out_dir: str, only: list[str] | None = None) -> list[dict]:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for fn in SAMPLES:
        s = fn()
        # ★ 编号取自 s["dir"] 自带的前两位真号（03…18），**不要**用列表下标 ——
        #   样本号是跳号的（缺 01/02/16），用下标会让目录名与登记表的 sample= 整体错位。
        dirname = s["dir"]
        idx = dirname[:2]
        if only and idx not in only:
            continue
        d = os.path.join(out_dir, dirname)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "cipher.txt"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(s["cipher"] + "\n")
        with open(os.path.join(d, "app.js"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(s["app_js"])
        for fname, body in (s.get("extra_files") or {}).items():
            with open(os.path.join(d, fname), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(body)
        with open(os.path.join(d, "expect.json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(s["expect"], fh, ensure_ascii=False, indent=2)
        with open(os.path.join(d, "README.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("# %s\n\n**密文特征**：%s\n\n**分析思路**：%s\n\n"
                     "%s**文件**：`cipher.txt` 密文 · `app.js` 目标源码片段（工具从这里挖材料） · "
                     "`expect.json` 标准答案\n"
                     % (dirname, s["feature"], s["idea"], s.get("files_note", "")))
        written.append(s)
        print("  ✓ %-42s 密文 %d 字符" % (dirname, len(s["cipher"])))
    return written


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="生成密文样本集")
    ap.add_argument("--out", required=True, help="输出目录")
    ap.add_argument("--only", help="只生成指定编号，如 03,07")
    a = ap.parse_args(argv)
    only = [x.strip() for x in a.only.split(",")] if a.only else None
    print("生成样本到：%s" % os.path.abspath(a.out))
    got = write_all(a.out, only)
    print("共 %d 个样本" % len(got))
    return 0


if __name__ == "__main__":
    sys.exit(main())
