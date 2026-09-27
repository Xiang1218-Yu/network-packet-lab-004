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
│   └── index.ts
├── shared/
│   └── types.ts
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
6. **解析 API / 模拟数据 API**：Express 服务提供 `/api/parse`、`/api/simulate`、`/api/packets` 和 `/api/health`。
7. **捕获导入 / 导出**：把一次分析完整导出为带版本号的 JSON 文件（单帧或整个会话），导入时先由后端校验格式并重新解析逐帧比对，预览确认后才覆盖当前会话。

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

### 校验待导入的捕获文件

```bash
curl -X POST 'http://localhost:3001/api/captures/verify' \
  -H 'Content-Type: application/json' \
  --data-binary @packet-lab-session-2026-09-26.json
```

返回中每一帧带 `status: "match" | "mismatch"` 与 `mismatches` 差异列表（如 `fields`、`hex`、`metadata.checksum`）。
服务端拒绝情况：未知/类型伪造的 `version`（如字符串 `"1"`）返回 400；非数组的 `frames`、篡改类型的 packet 字段返回 400；请求体超过 1MB、超过 100 帧、单帧 raw 超过 64KB 返回 413。

## 捕获文件格式

所有导出文件均为 JSON，UTF-8 编码，扩展名 `.json`：

```json
{
  "format": "network-packet-lab/capture",
  "version": 1,
  "kind": "frame",
  "exportedAt": "2026-09-26T08:30:00.000Z",
  "frames": [
    {
      "protocol": "HTTP",
      "scenario": "request",
      "raw": "GET /health HTTP/1.1\r\nHost: lab.local\r\n\r\n",
      "packet": { "id": "...", "fields": [], "hex": [], "timeline": [], "metadata": {} }
    }
  ]
}
```

- `format`：固定魔数标识，不匹配直接拒绝；
- `version`：格式版本（当前为 `1`），服务端只接受精确匹配的已知版本；
- `kind`：`frame`（当前帧）或 `session`（整个会话）；
- `exportedAt`：导出时间（ISO 8601）；
- `frames[]`：每帧包含**协议、场景、原始输入（raw）、解析结果（完整 `SimulatedPacket`）**。

导入流程：选择文件 → 前端预检大小与 JSON 合法性 → 后端 `/api/captures/verify` 做结构/类型/版本/大小校验，并对每帧用当前解析器重新解析，与文件内存储的解析结果逐项比对 → 前端预览弹窗逐帧展示「一致 / 不一致（差异方面）」→ 用户确认后才会覆盖当前会话；存在不一致时按钮变为「仍要导入」，导入后页面顶部保留琥珀色警示条。重新生成的 `id` 与 `capturedAt` 不参与比对。

## 说明

本项目是教学用模拟器，不执行真实网卡抓包，也不声称校验真实 TCP 校验和。十六进制内容由当前输入字符串的 UTF-8 字节生成，字段解析为面向演示的轻量级解析结果。
