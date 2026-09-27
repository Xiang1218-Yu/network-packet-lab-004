import express, { type NextFunction, type Request, type Response } from 'express';
import type { PacketScenario, ParseRequest } from '../shared/types.js';
import {
  CAPTURE_VERSION,
  MAX_CAPTURE_BYTES,
  diffParseResult,
  validateCaptureDocument,
  type CaptureVerifyResult,
  type FrameVerification,
  type ValidationIssue
} from '../shared/capture.js';
import { buildPacket, isProtocol, isScenario } from './parser.js';

const app = express();
const port = Number(process.env.PORT ?? 3001);

type RequestWithRawSize = Request & { rawBodyByteLength?: number };

// 留出传输余量；归档自身的 1MB 上限在 verify 路由里显式拒绝并给出清晰原因。
// verify 钩子在 JSON 解析前拿到原始字节，用于精确的归档大小判定（重序列化会因空白差异失真）。
app.use(express.json({
  limit: '2mb',
  verify: (request, _response, buffer) => {
    (request as RequestWithRawSize).rawBodyByteLength = buffer.length;
  }
}));

app.use((request, response, next) => {
  response.header('Access-Control-Allow-Origin', '*');
  response.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  response.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (request.method === 'OPTIONS') return response.sendStatus(204);
  next();
});

app.get('/api/health', (_request, response) => response.json({ ok: true, service: 'network-packet-lab-api' }));

app.get('/api/simulate', (request, response) => {
  const protocol = isProtocol(request.query.protocol) ? request.query.protocol : 'HTTP';
  const scenario = isScenario(request.query.scenario) ? request.query.scenario : (protocol === 'HTTP' ? 'request' : 'handshake');
  response.json({ data: buildPacket(protocol, scenario, '') });
});

app.get('/api/packets', (request, response) => {
  const protocol = isProtocol(request.query.protocol) ? request.query.protocol : 'HTTP';
  const scenarios: PacketScenario[] = protocol === 'HTTP' ? ['request', 'response'] : ['handshake', 'request', 'response'];
  response.json({ data: scenarios.map((scenario) => buildPacket(protocol, scenario, '')) });
});

app.post('/api/parse', (request: Request<unknown, unknown, Partial<ParseRequest>>, response: Response) => {
  const protocol = isProtocol(request.body?.protocol) ? request.body.protocol : 'HTTP';
  const scenario = isScenario(request.body?.scenario) ? request.body.scenario : 'request';
  const raw = typeof request.body?.raw === 'string' ? request.body.raw : '';
  if (!raw.trim()) return response.status(400).json({ error: 'raw is required' });
  response.json({ data: buildPacket(protocol, scenario, raw) });
});

/**
 * 导入前的权威校验：
 * 1. 拒绝未知版本、伪造字段类型、超尺寸 payload（validateCaptureDocument）；
 * 2. 对每帧的原始输入重新解析，与归档内快照逐字段对比；
 * 3. 不一致时返回差异明细，绝不静默用快照覆盖当前内容。
 */
app.post('/api/capture/verify', (request: Request, response: Response) => {
  const byteSize = (request as RequestWithRawSize).rawBodyByteLength;

  const validation = validateCaptureDocument(request.body, { byteSize });
  if (!validation.ok) {
    const status = validation.issues.some((issue) => issue.code === 'unsupported-version') ? 422
      : validation.issues.some((issue) => issue.code === 'too-large') ? 413
      : 400;
    return response.status(status).json({ error: 'capture-validation-failed', issues: validation.issues });
  }

  // 快照与重新解析结果的一致性核对：id / metadata.capturedAt 含时间戳，
  // 属于预期差异，在 diffParseResult 中已排除，其余字段必须完全一致。
  const verifications: FrameVerification[] = validation.frames.map((frame, index) => {
    const reparsed = buildPacket(frame.protocol, frame.scenario, frame.raw);
    const differences = diffParseResult(frame.result, reparsed);
    return {
      index,
      protocol: frame.protocol,
      scenario: frame.scenario,
      reparsed,
      consistent: differences.length === 0,
      differences
    };
  });

  response.status(200).json({
    data: {
      version: CAPTURE_VERSION,
      kind: validation.document.kind,
      exportedAt: validation.document.exportedAt,
      frameCount: validation.frames.length,
      consistent: verifications.every((item) => item.consistent),
      frames: verifications
    } satisfies CaptureVerifyResult
  });
});

// JSON 解析层（express.json limit）抛出的超大 body：统一 413 + 机器可读错误码。
app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
  if (error instanceof SyntaxError && 'type' in error && (error as { type?: string }).type === 'entity.parse.failed') {
    const issues: ValidationIssue[] = [{ code: 'invalid-shape', path: '$', message: '请求体不是合法的 JSON' }];
    return response.status(400).json({ error: 'capture-validation-failed', issues });
  }
  if (error instanceof Error && (error as Error & { type?: string }).type === 'entity.too.large') {
    const issues: ValidationIssue[] = [
      { code: 'too-large', path: '$', message: `请求体超过传输上限，归档文件不得大于 ${MAX_CAPTURE_BYTES} 字节` }
    ];
    return response.status(413).json({ error: 'capture-validation-failed', issues });
  }
  console.error(error);
  response.status(500).json({ error: 'internal-error' });
});

app.listen(port, () => {
  console.log(`Network Packet Lab API listening on http://localhost:${port}`);
});
