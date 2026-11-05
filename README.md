# actuator-bypass-scanner

Spring Boot Actuator 变形绕过批量检测器 —— 覆盖 5 大类 30+ 手法，双因子判定压误报，纯 Python 标准库零依赖。

> ⚠️ **免责声明 / Disclaimer**
>
> 本工具仅供**已授权**的安全评估、渗透测试与安全加固自查使用。对未授权目标使用本工具属违法行为，使用者须对自身行为承担全部责任。请在当地法律与授权范围内使用。
>
> This tool is intended for **authorized** security assessments and hardening self-checks only.

## ✨ 特性

- **覆盖面**：路径解析差异 / 编码变形 / HTTP 语义 / 网关头欺骗 / 版本特性 5 大类 30+ 变形，对应 Spring Boot 1.x 与 2.x 双路径
- **误报控制（双因子判定）**：
  1. 每目标先取"任意不存在路径"的基准响应，与基准页一致的变形直接判定为**未绕过**
  2. 2xx 响应必须命中 Actuator 特征指纹（`_links` / `propertySources` / HPROF 二进制 / Jolokia MBean 等 10 类）才算绕过成功
- **字节级保真**：raw socket 实现 HTTP 请求，URL 编码、分号、反斜杠等变形**原样到达目标**，不受 requests 库 `unquote_unreserved` 等 URI 规范化影响
- **零依赖**：纯 Python 3.8+ 标准库，无需 pip install
- **Windows cmd 兼容**：VT 色彩自动启用/降级、ASCII 制表、中文 2 列显示宽度对齐
- **结果导出**：JSON / CSV，每条尝试的 payload 与结论逐行记录
- **内置演示靶场**：`demo_mock_actuator.py` 模拟"WAF 黑名单 + Tomcat 解析"，clone 后 30 秒复现完整检测效果

## 📋 覆盖手法

| 类别 | 手法 | 示例 Payload |
|------|------|-------------|
| **A 路径解析差异** | 分号参数截断 | `/actuator/env;x=1`、`;jsessionid=x` |
| | 空段分号（Shiro CVE-2020-1957 系列） | `/;/actuator/env` |
| | 目录段分号 | `/actuator;/env` |
| | `..;/` 穿越 | `/zzz/..;/actuator/env` |
| | 双斜杠 / 点段 | `//actuator/env`、`/./actuator/env`、`/actuator//env` |
| | 尾斜杠 / 索引无斜杠 | `/actuator/env/`、`/actuator` |
| | 反斜杠（Windows Tomcat） | `/\actuator/env` |
| **B 编码变形** | 单层 URL 编码 | `/%61ctuator/%65nv` |
| | 双重编码 | `/%252e%252e/actuator/env` |
| | 编码点段 | `/%2e/actuator/env`、`/%2e%2e/actuator/env` |
| | 控制字符干扰 | `/actuator/%09env` |
| **C HTTP 语义** | HEAD 方法探测（命中自动 GET 复核） | `HEAD /actuator/env` |
| | 超长 URL 填充 | `/actuator/env?pad=<a*3000>` |
| **D 网关头欺骗** | XFF 伪造内网来源 | `X-Forwarded-For: 127.0.0.1` |
| | 路由改写头 | `X-Original-URL` / `X-Rewrite-URL` |
| | Host 系列干扰 | `X-Forwarded-Host: localhost`、`X-Real-IP` |
| **E 版本特性** | Spring Boot 1.x 根路径 | `/env`、`/heapdump`、`/trace`、`/dump` |
| | 自定义 base-path 字典 | `/manage`、`/monitor`、`/admin`、`/ops` … |
| | Jolokia 独立 Servlet（ACL 高频漏保护点） | `/jolokia/list` |
| | 后缀模式匹配（Spring <2.6） | `/env.json`、`/env.html` |

默认探测端点：actuator 索引、`env`、`heapdump`、`jolokia/list`、`configprops`、`mappings`、`loggers`、`beans`、`threaddump`、`prometheus`、`gateway/routes` 等 16 个。

## 🔎 判定结论（五级）

| 标记 | 含义 |
|------|------|
| `[+]绕过成功` | 2xx 且命中 Actuator 特征指纹（可信，可直接进入利用验证） |
| `[?]疑似` | 2xx 但无特征，需人工复核 |
| `[x]被拦截` | 401/403 且拦截页与基准不同 |
| `[-]未绕过` | 响应与基准页一致（WAF 统一拦截页场景下即"该变形失效"） |
| `(失败)` | 连接失败/超时/重定向 |

基准响应若为 401/403，报告头部会输出情报提示：**WAF/ACL 疑似全站统一拦截**，此时变形路线基本失效，建议转攻源站直连 / 白名单路径前缀 / 请求走私。

## 🚀 快速开始

```bash
# 无任何第三方依赖, Python 3.8+ 直接运行
python actuator_bypass_scanner.py -u http://target:8080

# 批量目标 + 并发 + 导出
python actuator_bypass_scanner.py -f targets.txt -t 20 --json result.json --csv result.csv

# 全端点变形枚举（请求量约为默认 4-5 倍）
python actuator_bypass_scanner.py -u http://target --full

# 只看绕过/疑似/拦截行, 隐藏"未绕过"
python actuator_bypass_scanner.py -u http://target --brief

# 走 Burp 抓包核对（变形字节不被规范化）
python actuator_bypass_scanner.py -u http://target --proxy http://127.0.0.1:8080
```

### 演示靶场（回归自测）

```bash
# 终端 1: 启动本地靶场（模拟 WAF 精确黑名单 + Tomcat 规范化, 仅监听 127.0.0.1）
python demo_mock_actuator.py 18080

# 终端 2: 扫描
python actuator_bypass_scanner.py -u http://127.0.0.1:18080
```

模拟"WAF 全站统一拦截"场景（403 + 固定拦截页）：

```bash
python demo_mock_actuator.py 18081 --block-all
python actuator_bypass_scanner.py -u http://127.0.0.1:18081
```

## 📷 输出示例

```
 [A-路径解析差异] 尝试88条: CONFIRMED56 SUSPECTED0 BLOCKED17 NO_BYPASS15 SKIP0
------------------------------------------------------------------------------
 状态    方法    结论           尝试的Payload                        特征/说明
------------------------------------------------------------------------------
 200    GET    [+]绕过成功    /actuator/env;x=1                    env环境配置
 200    GET    [+]绕过成功    /zzz/..;/actuator/heapdump           heapdump二进制(HPROF/gzip)
 200    GET    [+]绕过成功    /%61ctuator/%65nv                    env环境配置
 403    GET    [x]被拦截      //actuator/env                       被WAF/ACL拦截(拦截页与基准不同)
 404    GET    [-]未绕过      /x;y/actuator/env                    响应与基准页一致,该变形未绕过
```

每条 payload 均落盘 JSON / CSV，可直接作为报告附件：

```json
{
  "variant": "A-分号参数:actuator/env",
  "payload": "/actuator/env;x=1",
  "method": "GET",
  "status": 200,
  "verdict": "CONFIRMED",
  "features": ["env环境配置"]
}
```

## ⚠️ 已知边界（人工复核项）

以下手法属 HTTP 层自动化盲区，报告尾部会提示人工跟进：

1. **请求走私**（CLB/stgw 与后端对 CL/TE 优先级差异）—— 用 smuggler 等工具单测
2. **Nginx off-by-slash**（`location /api { proxy_pass http://up/; }` 拼接穿越）—— 对照网关配置审计
3. **管理端口独立**（`management.port` 绑内网）—— 需 SSRF/内网可达性配合

## 🔧 加固自查对照

作为防守方可用本工具验证封禁规则的覆盖度，对应加固建议：

1. CLB/WAF 封禁正则需覆盖编码态：`(actuator|%61ctuator)`，`jolokia` 单独成条（不在 `/actuator` 前缀下）
2. 管理端点独立端口 + 安全组 socket 层白名单（勿用应用层 XFF 白名单）
3. Tomcat 确认 `removeSemicolonContent=true`；Spring Security 启用 `StrictHttpFirewall` 拒绝 `;`、`//`、`..`
4. 2.x 审计 `management.endpoints.web.exposure.include`，勿用 `*`

## License

[MIT](LICENSE)
