# Network Packet Lab · 网络协议数据包可视化实验室

项目 10：一个用于学习和演示网络协议解析过程的可视化实验室。当前版本聚焦模拟 HTTP / TCP 数据包，提供输入、场景选择、协议层级字段树、十六进制数据、解析时间线，以及可供 React 管理界面调用的 Node.js API。

## 技术栈

- **前端**：React 18、Vite、TypeScript
- **后端**：Node.js、Express、TypeScript
- **工程**：前后端共享 `shared/types.ts` 类型，根目录统一管理脚本

## 目录结构

```text
network-packet-lab/
├── client/
│   ├── index.html
│   └── src/
│       ├── App.tsx
│       ├── main.tsx
│       └── styles.css
├── server/
│   ├── index.ts
│   └── parser.ts
├── shared/
│   ├── types.ts
│   └── capture.ts
├── package.json
├── tsconfig.json
├── tsconfig.server.json
├── vite.config.ts
└── .gitignore
```

## 功能

1. **模拟数据选择**：在 HTTP / TCP 协议之间切换，并选择请求、响应或 TCP 握手场景。
2. **数据包输入**：编辑原始 HTTP 文本或 TCP 模拟摘要，点击“解析数据包”重新生成可视化结果。
3. **协议字段树**：HTTP 展示起始行、Header、Payload；TCP 展示 Ethernet、IPv4、TCP 和 Payload 层级，并支持折叠。
4. **十六进制视图**：以 offset、hex bytes、ASCII 三列展示当前 payload 的 UTF-8 字节。
5. **传输时间线**：展示抓包、解析、传输层解码和结构化输出等阶段。
6. **捕获包导入 / 导出**：把一次分析（协议、场景、原始输入、解析结果、导出时间）打包为带版本号的 JSON，支持导出当前帧或整个会话；导入时先校验格式、再由后端重新解析核对，不一致会逐字段列出并要求显式确认。
7. **解析 API / 模拟数据 API**：Express 服务提供 `/api/parse`、`/api/simulate`、`/api/packets`、`/api/capture/verify` 和 `/api/health`。

## 启动方式

当前只完整落盘项目文件，**没有安装依赖**。准备运行时，在本目录执行：

```bash
npm install
```

然后打开两个终端：

```bash
# 终端 1：启动 API 服务（默认 3001）
npm run dev:server

# 终端 2：启动 Vite 管理界面（默认 5173）
npm run dev:client
```

浏览器访问 `http://localhost:5173`。如需更换 API 地址，可设置 `VITE_API_BASE`，例如：

```bash
VITE_API_BASE=http://localhost:3001 npm run dev:client
```

生产构建：

```bash
npm run build
npm start
```

> `npm start` 会启动编译后的 API 服务；前端静态产物位于 `dist/client`，可交给任意静态服务器托管。

## API 示例

### 获取模拟数据

```bash
curl 'http://localhost:3001/api/simulate?protocol=HTTP&scenario=request'
curl 'http://localhost:3001/api/simulate?protocol=TCP&scenario=handshake'
```

### 解析输入数据包

```bash
curl -X POST 'http://localhost:3001/api/parse' \
  -H 'Content-Type: application/json' \
  -d '{"protocol":"HTTP","scenario":"request","raw":"GET /health HTTP/1.1\\r\\nHost: lab.local\\r\\n\\r\\n"}'
```

### 获取某协议的全部示例

```bash
curl 'http://localhost:3001/api/packets?protocol=TCP'
```

### 捕获包导入校验（前端选文件后自动调用）

```bash
curl -X POST 'http://localhost:3001/api/capture/verify' \
  -H 'Content-Type: application/json' \
  --data-binary @packet-frame-http-20260926-153000.json
```

响应中 `data.frames[].consistent` 表示归档内解析结果快照能否由当前解析器对
`raw` 重新解析重现；不一致时 `differences` 给出字段路径、快照值与重新解析值。
**导入采用的是重新解析结果，从不使用快照静默覆盖当前内容。**

## 捕获归档格式（v1）

顶层为带显式版本号的 JSON 信封，前后端共用 `shared/capture.ts` 中的
`validateCaptureDocument` 做严格校验：

```jsonc
{
  "format": "network-packet-lab-capture", // 固定 magic
  "version": 1,                           // 只接受 1，其余一律 422 拒绝
  "kind": "frame",                        // frame=当前帧 / session=整个会话
  "exportedAt": "2026-09-26T07:30:00.000Z",
  "generator": "network-packet-lab@1.0.0",
  "frame": {
    "protocol": "HTTP",                   // HTTP | TCP
    "scenario": "request",                // request | response | handshake
    "raw": "GET /health HTTP/1.1\r\n…",   // 原始输入（唯一重新解析依据）
    "capturedAt": "2026-09-26 07:29:58 UTC",
    "result": { /* SimulatedPacket 完整解析结果快照 */ }
  }
}
```

`kind: "session"` 时用 `frames: CaptureFrame[]` 替代 `frame`。

安全限制与拒绝策略：

| 限制 | 阈值 | 拒绝 |
| --- | --- | --- |
| 归档总大小 | 1 MiB（传输上限 2 MiB） | `413 too-large` |
| 单帧 `raw` | 64 KiB（UTF-8 字节） | `413 too-large` |
| 会话帧数 | 100 帧 | `400 limit-exceeded` |
| 未知版本 / 伪造版本类型 | 非整数 `1` | `422 unsupported-version` |
| 伪造字段类型 / 枚举 / 未知字段 | — | `400 type-mismatch / unknown-field` |
| 字段树深度 | 24 层 | `400 limit-exceeded` |

导入流程：浏览器端先做同构校验（即时反馈）→ 服务端 `/api/capture/verify`
用当前解析器逐帧重新解析并与快照 diff（`id`、`metadata.capturedAt` 等易变
字段除外）→ 预览弹窗逐帧展示一致/差异 → 用户显式确认后才替换工作台内容，
导入帧一律取自服务端的重新解析结果。会话导入会以归档帧替换当前会话历史。

## 说明

本项目是教学用模拟器，不执行真实网卡抓包，也不声称校验真实 TCP 校验和。十六进制内容由当前输入字符串的 UTF-8 字节生成，字段解析为面向演示的轻量级解析结果。
