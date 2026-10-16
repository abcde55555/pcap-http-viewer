# PCAP HTTP Viewer

一个离线 PCAP/PCAPNG HTTP 会话查看器：Go 后端解析抓包并重组 TCP 流，单页 HTML 前端以
**左请求 / 右响应** 分栏展示，支持时间/关键词/方法/状态码等筛选，并内置**敏感信息规则扫描**。
整个程序编译成单个 exe，双击启动、自动打开浏览器，零外部依赖（无需装 Wireshark/tshark）。

## 功能

- 解析 `.pcap` / `.pcapng`（纯 Go，免 CGO）
- TCP 流重组，HTTP/1.1 请求/响应自动配对，支持 keep-alive、chunked、gzip/deflate 解压
- **左请求 / 右响应** 分栏：状态行、headers 表格、body
  - JSON 自动格式化高亮，图片直接渲染，二进制 Hex 视图，文本等宽展示
  - 大 body 默认截断 256KB，可下载完整内容
- HTTPS/TLS 流量：展示 SNI 域名、TLS 版本等元数据（无密钥时不展示明文）
- 筛选：关键词、方法、host、状态码类别、时间范围、仅看含敏感信息、隐藏加密会话
- **敏感信息规则引擎**（数据驱动，可导入/导出 YAML）：
  - 内置 15 条规则：身份证（校验位）、手机号、银行卡（Luhn）、邮箱、JWT、
    Authorization/Cookie、密码/密钥字段、PEM 私钥、AWS Key、微信 AppSecret、内网 IP/MAC、Bearer/Basic 认证等
  - 支持正则、header 名匹配、校验器、熵值过滤、值打码
  - 在界面中启用/禁用规则即时重新扫描；用户规则保存在配置目录
- 性能：40MB / 5万帧约 100~150ms 解析；10万级会话用虚拟滚动 + Web Worker 筛选保持流畅

## 运行

需要 Go 1.25+ 编译。

```bash
go build -o pcapview.exe .
./pcapview.exe                      # 启动后浏览器自动打开
./pcapview.exe -f capture.pcapng    # 启动时自动打开某抓包
./pcapview.exe -p 8080 -no-browser  # 指定端口、不开浏览器
```

浏览器中点 **"打开抓包…"** 选择文件（上传到本地服务解析），或用命令行 `-f` 直接传路径。

服务只监听 `127.0.0.1`，不会暴露到局域网。

## 目录结构

```
main.go                    入口，嵌入 web/ 和 rules/default.yaml
internal/
  parser/                  pcap 读取、TCP 重组、HTTP 解析、TLS SNI 提取
  storage/                 事务存储，小 body 内存、大 body 落盘 + Range 读取
  plugins/                 Plugin 接口 + 敏感信息规则引擎 + YAML 加载
  app/                     解析编排、进度广播、并发跑插件
  web/                     HTTP API、SSE 进度、静态资源服务
web/                       前端（单 HTML + 原生 JS ES module + Web Worker）
  index.html styles.css app.js worker-filter.js
rules/default.yaml         内置敏感信息规则
cmd/parsecheck/            命令行验证工具（不启动服务，打印解析摘要）
```

## 规则格式

```yaml
rules:
  - id: my-token
    name: 我的令牌
    severity: high            # info|low|medium|high|critical
    category: credential
    scope: [body, header]     # url|header|reqbody|respbody|body
    pattern: 'token=[a-f0-9]{32}'
    # headerName: Authorization   # 仅匹配该 header（不写 pattern 则标记 header 存在）
    # validator: luhn             # id-checksum | luhn | jwt
    # maskValue: true             # 展示时打码
    # context: 40                 # 命中前后上下文字符数
    # minEntropy: 3.5             # 最小香农熵
    enabled: true
```

> 正则使用 Go RE2 语法，**不支持** lookahead/lookbehind。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/upload` | multipart 上传抓包并开始解析 |
| POST | `/api/open?path=` | 按服务端本地路径打开抓包 |
| GET | `/api/progress` | SSE 推送解析进度 |
| GET | `/api/sessions` | NDJSON 流式返回所有会话元数据 |
| GET | `/api/session/:id` | 单会话详情（headers，不含 body） |
| GET | `/api/session/:id/body?side=req\|resp&offset=&limit=` | body 字节（Range 风格） |
| GET/PUT | `/api/rules` | 列出 / 替换规则 |
| POST | `/api/rules/import` | 上传 YAML 规则 |
| GET | `/api/rules/export` | 导出 YAML |
| GET | `/api/streams` | TCP 流汇总 |
| GET | `/api/status` | 当前文件/会话数/解析状态 |

## 已知限制

- 仅解析 HTTP/1.1 明文；不解密 TLS（如需解密 HTTPS，需提供 SSLKEYLOGFILE，留待后续版本）。
- 不解析 WebSocket / HTTP/2。
- 浏览器中文件选择走上传（写到临时目录）；命令行 `-f` 直接读路径更快。
