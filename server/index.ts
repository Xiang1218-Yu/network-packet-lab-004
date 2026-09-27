import express, { type NextFunction, type Request, type Response } from 'express';
import type {
  CaptureFile,
  CaptureFrame,
  CaptureVerification,
  FrameVerification,
  HexRow,
  PacketScenario,
  ParseRequest,
  Protocol,
  ProtocolField,
  SimulatedPacket,
  TimelineEvent
} from '../shared/types.js';
import { CAPTURE_FILE_FORMAT, CAPTURE_FILE_VERSION } from '../shared/types.js';

const app = express();
const port = Number(process.env.PORT ?? 3001);

app.use(express.json({ limit: '1mb' }));
app.use((request, response, next) => {
  response.header('Access-Control-Allow-Origin', '*');
  response.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  response.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (request.method === 'OPTIONS') return response.sendStatus(204);
  next();
});

const HTTP_SAMPLES: Record<PacketScenario, string> = {
  request: 'GET /api/devices?status=online HTTP/1.1\r\nHost: lab.local\r\nAccept: application/json\r\nUser-Agent: PacketLab/1.0\r\nX-Trace-Id: 7f3a9c\r\n\r\n',
  response: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 47\r\nCache-Control: no-store\r\n\r\n{"devices":[{"id":"edge-01","status":"online"}]}',
  handshake: 'GET / HTTP/1.1\r\nHost: lab.local\r\nConnection: keep-alive\r\n\r\n'
};

const TCP_SAMPLES: Record<PacketScenario, string> = {
  request: 'TCP 10.0.0.24:51842 > 10.0.0.8:443 | Seq=18492031 Ack=77120102 | Flags=ACK,PSH | Win=64240 | Len=128',
  response: 'TCP 10.0.0.8:443 > 10.0.0.24:51842 | Seq=77120102 Ack=18492159 | Flags=ACK,PSH | Win=28960 | Len=512',
  handshake: 'TCP 10.0.0.24:51842 > 10.0.0.8:443 | Seq=0 Ack=0 | Flags=SYN | Win=64240 | MSS=1460 | WS=7'
};

function hexDump(value: string): HexRow[] {
  const bytes = Array.from(Buffer.from(value, 'utf8'));
  const rows: HexRow[] = [];
  for (let index = 0; index < bytes.length; index += 16) {
    const slice = bytes.slice(index, index + 16);
    rows.push({
      offset: index.toString(16).padStart(4, '0'),
      bytes: slice.map((byte) => byte.toString(16).padStart(2, '0')),
      ascii: slice.map((byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.')).join('')
    });
  }
  return rows;
}

function field(id: string, key: string, value: string, description: string, children?: ProtocolField[]): ProtocolField {
  return { id, key, value, description, ...(children ? { children } : {}) };
}

function parseHttpFields(raw: string): ProtocolField[] {
  const [head, body = ''] = raw.split(/\r?\n\r?\n/);
  const lines = head.split(/\r?\n/);
  const startLine = lines.shift() ?? '';
  const headers = lines.map((line, index) => {
    const separator = line.indexOf(':');
    const key = separator > -1 ? line.slice(0, separator).trim() : `Header-${index + 1}`;
    const value = separator > -1 ? line.slice(separator + 1).trim() : line.trim();
    return field(`header-${index}`, key, value || '(empty)', 'HTTP header field');
  });
  const isResponse = startLine.startsWith('HTTP/');
  const [first, second, third] = startLine.split(' ');
  return [
    field('http-start-line', isResponse ? 'Status-Line' : 'Request-Line', startLine, isResponse ? 'HTTP version and response status' : 'HTTP method, target and version', [
      field('http-part-1', isResponse ? 'Version' : 'Method', first ?? '—', isResponse ? 'Protocol version' : 'HTTP request method'),
      field('http-part-2', isResponse ? 'Status' : 'Target', second ?? '—', isResponse ? 'Status code' : 'Request target'),
      field('http-part-3', isResponse ? 'Reason' : 'Version', isResponse ? (third ?? '—') : (third ?? '—'), isResponse ? 'Reason phrase' : 'Protocol version')
    ]),
    field('http-headers', 'Headers', `${headers.length} fields`, 'Metadata carried by the application layer', headers),
    field('http-body', 'Payload', body || '(empty)', 'Application payload after the header terminator')
  ];
}

function parseTcpFields(raw: string): ProtocolField[] {
  const [route = '', ...parts] = raw.split(' | ');
  const [protocol, source = '—', arrow = '>', destination = '—'] = route.split(' ');
  const values = new Map(parts.map((part) => {
    const separator = part.indexOf('=');
    return separator > -1 ? [part.slice(0, separator), part.slice(separator + 1)] : [part, 'true'];
  }));
  return [
    field('ethernet', 'Link Layer', 'Ethernet II', 'Frame envelope', [
      field('ethernet-src', 'Source MAC', '02:42:ac:11:00:24', 'Simulated interface address'),
      field('ethernet-dst', 'Destination MAC', '02:42:ac:11:00:08', 'Simulated gateway address'),
      field('ethernet-type', 'Type', '0x0800 · IPv4', 'Network protocol identifier')
    ]),
    field('ipv4', 'Internet Layer', 'IPv4', 'Logical addressing and delivery', [
      field('ipv4-source', 'Source', source, 'Origin IP and port'),
      field('ipv4-destination', 'Destination', destination, 'Target IP and port'),
      field('ipv4-protocol', 'Next Protocol', protocol || 'TCP', 'Transport protocol')
    ]),
    field('tcp', 'Transport Layer', 'TCP', 'Reliable stream transport', [
      field('tcp-seq', 'Sequence', values.get('Seq') ?? '—', 'Byte sequence position'),
      field('tcp-ack', 'Acknowledgement', values.get('Ack') ?? '—', 'Next expected byte'),
      field('tcp-flags', 'Flags', values.get('Flags') ?? '—', 'Control bits'),
      field('tcp-window', 'Window', values.get('Win') ?? '—', 'Receive window size'),
      field('tcp-length', 'Payload Length', values.get('Len') ?? '0', 'TCP segment data length')
    ]),
    field('tcp-payload', 'Payload', values.get('Len') === '0' ? '(empty)' : 'Encrypted application data', 'Data carried by the segment')
  ];
}

function timelineFor(protocol: Protocol, scenario: PacketScenario): TimelineEvent[] {
  const prefix = protocol === 'HTTP' ? 'HTTP' : 'TCP';
  const steps = protocol === 'HTTP'
    ? [
        ['ingress', 'Frame captured', 'NIC received an application frame'],
        ['parse', 'Headers indexed', 'Start line and header fields identified'],
        ['application', `${prefix} payload decoded`, scenario === 'response' ? 'Response body is ready for inspection' : 'Request target and metadata extracted'],
        ['egress', 'Inspector ready', 'Structured representation emitted by parse API']
      ]
    : [
        ['ingress', 'Segment captured', 'Transport segment received from the simulated wire'],
        ['transport', 'TCP header decoded', 'Sequence, acknowledgement and flags extracted'],
        ['parse', 'Layer tree assembled', 'Ethernet → IPv4 → TCP hierarchy created'],
        ['egress', 'Inspector ready', 'Structured representation emitted by parse API']
      ];
  return steps.map(([phase, label, detail], index) => ({
    id: `${prefix.toLowerCase()}-${index}`,
    timestamp: `00:00:0${index}.${(index * 37 + 12).toString().padStart(2, '0')}`,
    label,
    phase: phase as TimelineEvent['phase'],
    detail
  }));
}

function checksum(raw: string): string {
  let hash = 0;
  for (const byte of Buffer.from(raw, 'utf8')) hash = (hash + byte * 31) % 65535;
  return `0x${hash.toString(16).padStart(4, '0').toUpperCase()}`;
}

function buildPacket(protocol: Protocol, scenario: PacketScenario, raw: string): SimulatedPacket {
  const safeRaw = raw.trim() ? raw : (protocol === 'HTTP' ? HTTP_SAMPLES[scenario] : TCP_SAMPLES[scenario]);
  const isHttp = protocol === 'HTTP';
  return {
    id: `${protocol.toLowerCase()}-${scenario}-${Date.now().toString(36).slice(-6)}`,
    protocol,
    scenario,
    summary: isHttp
      ? `${safeRaw.split(/\r?\n/)[0]} · ${scenario === 'response' ? 'server response' : 'client request'}`
      : `${scenario === 'handshake' ? 'TCP connection handshake' : 'TCP data segment'} · ${safeRaw.split(' | ')[0]}`,
    raw: safeRaw,
    hex: hexDump(safeRaw),
    fields: isHttp ? parseHttpFields(safeRaw) : parseTcpFields(safeRaw),
    timeline: timelineFor(protocol, scenario),
    metadata: {
      capturedAt: new Date().toISOString().replace('T', ' ').replace('Z', ' UTC'),
      source: isHttp ? '10.0.0.24:51842' : safeRaw.split(' > ')[0].replace('TCP ', ''),
      destination: isHttp ? '10.0.0.8:443' : (safeRaw.split(' > ')[1]?.split(' | ')[0] ?? '10.0.0.8:443'),
      length: Buffer.byteLength(safeRaw, 'utf8'),
      checksum: checksum(safeRaw)
    }
  };
}

function isProtocol(value: unknown): value is Protocol { return value === 'HTTP' || value === 'TCP'; }
function isScenario(value: unknown): value is PacketScenario { return value === 'request' || value === 'response' || value === 'handshake'; }

// ---------------------------------------------------------------------------
// Capture import: structural validation + re-parse verification
// ---------------------------------------------------------------------------

/** Hard per-request cap is enforced by express.json (1mb); these are semantic caps. */
const MAX_CAPTURE_FRAMES = 100;
const MAX_FRAME_RAW_BYTES = 64 * 1024;
const MAX_FIELD_DEPTH = 10;
const TIMELINE_PHASES: ReadonlyArray<TimelineEvent['phase']> = ['ingress', 'parse', 'transport', 'application', 'egress'];

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isHexRow(value: unknown): value is HexRow {
  return isPlainObject(value)
    && typeof value.offset === 'string'
    && Array.isArray(value.bytes) && value.bytes.every((byte) => typeof byte === 'string')
    && typeof value.ascii === 'string';
}

function isProtocolField(node: unknown, depth = 0): node is ProtocolField {
  if (depth > MAX_FIELD_DEPTH || !isPlainObject(node)) return false;
  if (typeof node.id !== 'string' || typeof node.key !== 'string'
    || typeof node.value !== 'string' || typeof node.description !== 'string') return false;
  if (node.children === undefined) return true;
  return Array.isArray(node.children) && node.children.every((child) => isProtocolField(child, depth + 1));
}

function isTimelineEvent(value: unknown): value is TimelineEvent {
  return isPlainObject(value)
    && typeof value.id === 'string'
    && typeof value.timestamp === 'string'
    && typeof value.label === 'string'
    && typeof value.phase === 'string' && TIMELINE_PHASES.includes(value.phase as TimelineEvent['phase'])
    && typeof value.detail === 'string';
}

function isSimulatedPacket(value: unknown): value is SimulatedPacket {
  if (!isPlainObject(value)) return false;
  return typeof value.id === 'string'
    && isProtocol(value.protocol)
    && isScenario(value.scenario)
    && typeof value.summary === 'string'
    && typeof value.raw === 'string'
    && Array.isArray(value.hex) && value.hex.every(isHexRow)
    && Array.isArray(value.fields) && value.fields.every((node) => isProtocolField(node))
    && Array.isArray(value.timeline) && value.timeline.every(isTimelineEvent)
    && isPlainObject(value.metadata)
    && typeof value.metadata.capturedAt === 'string'
    && typeof value.metadata.source === 'string'
    && typeof value.metadata.destination === 'string'
    && typeof value.metadata.length === 'number' && Number.isFinite(value.metadata.length)
    && typeof value.metadata.checksum === 'string';
}

type CaptureValidation =
  | { ok: true; file: CaptureFile }
  | { ok: false; status: number; error: string };

function validateCaptureFile(input: unknown): CaptureValidation {
  if (!isPlainObject(input)) return { ok: false, status: 400, error: '捕获文件必须是一个 JSON 对象' };
  if (input.format !== CAPTURE_FILE_FORMAT) {
    return { ok: false, status: 400, error: `无法识别的文件格式（format 应为 "${CAPTURE_FILE_FORMAT}"）` };
  }
  // Type is checked before the value so a forged version like "1" (string) is rejected.
  if (typeof input.version !== 'number' || !Number.isInteger(input.version)) {
    return { ok: false, status: 400, error: 'version 字段类型错误（必须是整数）' };
  }
  if (input.version !== CAPTURE_FILE_VERSION) {
    return { ok: false, status: 400, error: `不支持的捕获文件版本 v${input.version}（当前仅支持 v${CAPTURE_FILE_VERSION}）` };
  }
  if (input.kind !== 'frame' && input.kind !== 'session') {
    return { ok: false, status: 400, error: 'kind 字段非法（必须是 "frame" 或 "session"）' };
  }
  if (typeof input.exportedAt !== 'string' || Number.isNaN(Date.parse(input.exportedAt))) {
    return { ok: false, status: 400, error: 'exportedAt 必须是有效的 ISO 时间字符串' };
  }
  if (!Array.isArray(input.frames) || input.frames.length === 0) {
    return { ok: false, status: 400, error: 'frames 必须是非空数组' };
  }
  if (input.frames.length > MAX_CAPTURE_FRAMES) {
    return { ok: false, status: 413, error: `捕获文件包含 ${input.frames.length} 帧，超过 ${MAX_CAPTURE_FRAMES} 帧上限` };
  }
  for (let index = 0; index < input.frames.length; index += 1) {
    const label = `第 ${index + 1} 帧`;
    const frame = input.frames[index];
    if (!isPlainObject(frame)) return { ok: false, status: 400, error: `${label}必须是对象` };
    if (!isProtocol(frame.protocol)) return { ok: false, status: 400, error: `${label}的 protocol 字段缺失或非法` };
    if (!isScenario(frame.scenario)) return { ok: false, status: 400, error: `${label}的 scenario 字段缺失或非法` };
    if (typeof frame.raw !== 'string') return { ok: false, status: 400, error: `${label}的 raw 必须是字符串` };
    if (!frame.raw.trim()) return { ok: false, status: 400, error: `${label}的 raw 不能为空` };
    if (Buffer.byteLength(frame.raw, 'utf8') > MAX_FRAME_RAW_BYTES) {
      return { ok: false, status: 413, error: `${label}的原始输入超过 ${MAX_FRAME_RAW_BYTES / 1024}KB 上限` };
    }
    if (!isSimulatedPacket(frame.packet)) {
      return { ok: false, status: 400, error: `${label}的 packet 结构不完整或字段类型被篡改` };
    }
  }
  return { ok: true, file: input as unknown as CaptureFile };
}

/** Order-independent JSON serialization for structural comparison. */
function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

/**
 * Re-runs the parser on the stored raw input and reports which aspects of the
 * stored result differ. `id` and `metadata.capturedAt` are regenerated on
 * every parse and are deliberately excluded.
 */
function diffStoredFrame(frame: CaptureFrame): string[] {
  const reparsed = buildPacket(frame.protocol, frame.scenario, frame.raw);
  const stored = frame.packet;
  const mismatches: string[] = [];
  if (stored.protocol !== frame.protocol) mismatches.push('packet.protocol');
  if (stored.scenario !== frame.scenario) mismatches.push('packet.scenario');
  if (stored.raw !== frame.raw) mismatches.push('packet.raw');
  const checks: Array<[string, unknown, unknown]> = [
    ['summary', stored.summary, reparsed.summary],
    ['hex', stored.hex, reparsed.hex],
    ['fields', stored.fields, reparsed.fields],
    ['timeline', stored.timeline, reparsed.timeline],
    ['metadata.source', stored.metadata.source, reparsed.metadata.source],
    ['metadata.destination', stored.metadata.destination, reparsed.metadata.destination],
    ['metadata.length', stored.metadata.length, reparsed.metadata.length],
    ['metadata.checksum', stored.metadata.checksum, reparsed.metadata.checksum]
  ];
  for (const [label, storedValue, reparsedValue] of checks) {
    if (canonicalize(storedValue) !== canonicalize(reparsedValue)) mismatches.push(label);
  }
  return mismatches;
}

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

app.post('/api/captures/verify', (request: Request, response: Response) => {
  const validation = validateCaptureFile(request.body);
  if (!validation.ok) return response.status(validation.status).json({ error: validation.error });
  const frames: FrameVerification[] = validation.file.frames.map((frame, index) => {
    const mismatches = diffStoredFrame(frame);
    return {
      index,
      protocol: frame.protocol,
      scenario: frame.scenario,
      summary: frame.packet.summary,
      status: mismatches.length ? 'mismatch' : 'match',
      mismatches
    };
  });
  const data: CaptureVerification = {
    version: validation.file.version,
    kind: validation.file.kind,
    exportedAt: validation.file.exportedAt,
    frameCount: frames.length,
    frames
  };
  response.json({ data });
});

// Turn body-parser errors (oversized payload, invalid JSON) into JSON messages.
app.use((error: unknown, _request: Request, response: Response, next: NextFunction) => {
  const typed = error as { type?: string };
  if (typed?.type === 'entity.too.large') {
    return response.status(413).json({ error: '请求体超过 1MB 上限，捕获文件过大' });
  }
  if (typed?.type === 'entity.parse.failed') {
    return response.status(400).json({ error: '请求体不是合法的 JSON' });
  }
  return next(error);
});

app.listen(port, () => {
  console.log(`Network Packet Lab API listening on http://localhost:${port}`);
});
