import type { PacketScenario, Protocol, SimulatedPacket } from './types.js';

/**
 * 捕获包归档格式（Capture Archive Format）
 *
 * 设计目标：让一次协议分析可以作为单个 JSON 文件完整交给他人，
 * 并在相同解析器版本下重现“原始输入 → 解析结果”的全过程。
 *
 * 顶层信封带显式版本号，version 不被接受时必须拒绝导入，
 * 而不是猜测调用方意图，字段结构在前后端使用同一套严格校验。
 */

export const CAPTURE_FORMAT = 'network-packet-lab-capture';
export const CAPTURE_VERSION = 1;
export const LAB_VERSION = '1.0.0';
export const GENERATOR = `network-packet-lab@${LAB_VERSION}`;

/** 单帧原始输入上限（64 KiB，UTF-8 字节）。 */
export const MAX_FRAME_RAW_BYTES = 64 * 1024;
/** 整个归档文件上限（1 MB）。 */
export const MAX_CAPTURE_BYTES = 1024 * 1024;
/** 会话归档允许的最大帧数。 */
export const MAX_SESSION_FRAMES = 100;
/** 字段树递归校验的最大深度，防止伪造的深层嵌套。 */
const MAX_FIELD_TREE_DEPTH = 24;

const PROTOCOLS: ReadonlySet<unknown> = new Set(['HTTP', 'TCP']);
const SCENARIOS: ReadonlySet<unknown> = new Set(['request', 'response', 'handshake']);
const TIMELINE_PHASES: ReadonlySet<unknown> = new Set([
  'ingress',
  'parse',
  'transport',
  'application',
  'egress'
]);

/** 归档中的一帧：复现所需的最小信息（协议、场景、原始输入、解析结果快照）。 */
export interface CaptureFrame {
  protocol: Protocol;
  scenario: PacketScenario;
  raw: string;
  /** 导出时的解析结果快照；导入时会被重新解析结果核对，不会被盲信。 */
  result: SimulatedPacket;
  /** 该帧最初被解析的时间（展示用，允许缺失）。 */
  capturedAt?: string;
}

interface CaptureEnvelope {
  format: typeof CAPTURE_FORMAT;
  version: typeof CAPTURE_VERSION;
  kind: 'frame' | 'session';
  exportedAt: string;
  generator?: string;
}

export interface FrameCapture extends CaptureEnvelope {
  kind: 'frame';
  frame: CaptureFrame;
}

export interface SessionCapture extends CaptureEnvelope {
  kind: 'session';
  frames: CaptureFrame[];
}

export type CaptureDocument = FrameCapture | SessionCapture;

export type IssueCode =
  | 'unsupported-version'
  | 'invalid-format'
  | 'invalid-shape'
  | 'type-mismatch'
  | 'unknown-field'
  | 'too-large'
  | 'limit-exceeded';

export interface ValidationIssue {
  code: IssueCode;
  path: string;
  message: string;
}

export type ValidationOutcome =
  | { ok: true; document: CaptureDocument; frames: CaptureFrame[] }
  | { ok: false; issues: ValidationIssue[] };

export interface ParseDifference {
  /** 相对于解析结果根对象的差异路径，例如 metadata.checksum / fields[0].value。 */
  path: string;
  snapshot: string;
  reparsed: string;
}

const encoder = new TextEncoder();

export function utf8ByteLength(value: string): number {
  return encoder.encode(value).length;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function addIssue(issues: ValidationIssue[], code: IssueCode, path: string, message: string): void {
  issues.push({ code, path, message });
}

function checkExactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  path: string,
  issues: ValidationIssue[]
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      addIssue(issues, 'unknown-field', path ? `${path}.${key}` : key || '$', `不允许出现未知字段 "${key}"`);
    }
  }
}

function requireString(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
  { nonEmpty = false }: { nonEmpty?: boolean } = {}
): value is string {
  if (typeof value !== 'string') {
    addIssue(issues, 'type-mismatch', path, `应为字符串，实际为 ${describeType(value)}`);
    return false;
  }
  if (nonEmpty && !value.trim()) {
    addIssue(issues, 'invalid-shape', path, '不能为空字符串');
    return false;
  }
  return true;
}

function describeType(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function validateHexRow(value: unknown, path: string, issues: ValidationIssue[]): void {
  if (!isPlainObject(value)) {
    addIssue(issues, 'type-mismatch', path, `应为对象，实际为 ${describeType(value)}`);
    return;
  }
  checkExactKeys(value, ['offset', 'bytes', 'ascii'], path, issues);
  requireString(value.offset, `${path}.offset`, issues);
  requireString(value.ascii, `${path}.ascii`, issues);
  if (!Array.isArray(value.bytes)) {
    addIssue(issues, 'type-mismatch', `${path}.bytes`, `应为数组，实际为 ${describeType(value.bytes)}`);
    return;
  }
  value.bytes.forEach((byte, index) => {
    const bytePath = `${path}.bytes[${index}]`;
    if (typeof byte !== 'string' || !/^[0-9a-fA-F]{2}$/.test(byte)) {
      addIssue(issues, 'type-mismatch', bytePath, '应为两位十六进制字符串，例如 "7f"');
    }
  });
}

function validateField(
  value: unknown,
  path: string,
  depth: number,
  issues: ValidationIssue[]
): void {
  if (!isPlainObject(value)) {
    addIssue(issues, 'type-mismatch', path, `应为对象，实际为 ${describeType(value)}`);
    return;
  }
  checkExactKeys(value, ['id', 'key', 'value', 'description', 'children'], path, issues);
  requireString(value.id, `${path}.id`, issues);
  requireString(value.key, `${path}.key`, issues);
  requireString(value.value, `${path}.value`, issues);
  requireString(value.description, `${path}.description`, issues);
  if (value.children !== undefined) {
    if (!Array.isArray(value.children)) {
      addIssue(issues, 'type-mismatch', `${path}.children`, `应为数组，实际为 ${describeType(value.children)}`);
    } else if (depth >= MAX_FIELD_TREE_DEPTH) {
      addIssue(issues, 'limit-exceeded', `${path}.children`, `字段嵌套超过 ${MAX_FIELD_TREE_DEPTH} 层`);
    } else {
      value.children.forEach((child, index) => validateField(child, `${path}.children[${index}]`, depth + 1, issues));
    }
  }
}

function validateTimelineEvent(value: unknown, path: string, issues: ValidationIssue[]): void {
  if (!isPlainObject(value)) {
    addIssue(issues, 'type-mismatch', path, `应为对象，实际为 ${describeType(value)}`);
    return;
  }
  checkExactKeys(value, ['id', 'timestamp', 'label', 'phase', 'detail'], path, issues);
  requireString(value.id, `${path}.id`, issues);
  requireString(value.timestamp, `${path}.timestamp`, issues);
  requireString(value.label, `${path}.label`, issues);
  requireString(value.detail, `${path}.detail`, issues);
  if (!TIMELINE_PHASES.has(value.phase)) {
    addIssue(issues, 'type-mismatch', `${path}.phase`, `未知的时间线阶段 ${JSON.stringify(value.phase)}`);
  }
}

function validateResult(value: unknown, path: string, issues: ValidationIssue[]): void {
  if (!isPlainObject(value)) {
    addIssue(issues, 'type-mismatch', path || 'result', `解析结果应为对象，实际为 ${describeType(value)}`);
    return;
  }
  const resultPath = path || 'result';
  checkExactKeys(value, ['id', 'protocol', 'scenario', 'summary', 'raw', 'hex', 'fields', 'timeline', 'metadata'], resultPath, issues);

  requireString(value.id, `${resultPath}.id`, issues);
  if (!PROTOCOLS.has(value.protocol)) {
    addIssue(issues, 'type-mismatch', `${resultPath}.protocol`, `协议只允许 HTTP / TCP，实际为 ${JSON.stringify(value.protocol)}`);
  }
  if (!SCENARIOS.has(value.scenario)) {
    addIssue(issues, 'type-mismatch', `${resultPath}.scenario`, `场景只允许 request / response / handshake，实际为 ${JSON.stringify(value.scenario)}`);
  }
  requireString(value.summary, `${resultPath}.summary`, issues);
  requireString(value.raw, `${resultPath}.raw`, issues);

  if (!Array.isArray(value.hex)) {
    addIssue(issues, 'type-mismatch', `${resultPath}.hex`, `应为数组，实际为 ${describeType(value.hex)}`);
  } else {
    value.hex.forEach((row, index) => validateHexRow(row, `${resultPath}.hex[${index}]`, issues));
  }

  if (!Array.isArray(value.fields)) {
    addIssue(issues, 'type-mismatch', `${resultPath}.fields`, `应为数组，实际为 ${describeType(value.fields)}`);
  } else {
    value.fields.forEach((item, index) => validateField(item, `${resultPath}.fields[${index}]`, 0, issues));
  }

  if (!Array.isArray(value.timeline)) {
    addIssue(issues, 'type-mismatch', `${resultPath}.timeline`, `应为数组，实际为 ${describeType(value.timeline)}`);
  } else {
    value.timeline.forEach((item, index) => validateTimelineEvent(item, `${resultPath}.timeline[${index}]`, issues));
  }

  if (!isPlainObject(value.metadata)) {
    addIssue(issues, 'type-mismatch', `${resultPath}.metadata`, `应为对象，实际为 ${describeType(value.metadata)}`);
    return;
  }
  const metadataPath = `${resultPath}.metadata`;
  checkExactKeys(value.metadata, ['capturedAt', 'source', 'destination', 'length', 'checksum'], metadataPath, issues);
  requireString(value.metadata.capturedAt, `${metadataPath}.capturedAt`, issues);
  requireString(value.metadata.source, `${metadataPath}.source`, issues);
  requireString(value.metadata.destination, `${metadataPath}.destination`, issues);
  requireString(value.metadata.checksum, `${metadataPath}.checksum`, issues);
  if (typeof value.metadata.length !== 'number' || !Number.isFinite(value.metadata.length) || value.metadata.length < 0) {
    addIssue(issues, 'type-mismatch', `${metadataPath}.length`, '应为非负数字');
  }
}

function validateFrame(value: unknown, path: string, issues: ValidationIssue[]): void {
  if (!isPlainObject(value)) {
    addIssue(issues, 'type-mismatch', path || 'frame', `帧数据应为对象，实际为 ${describeType(value)}`);
    return;
  }
  const framePath = path || 'frame';
  checkExactKeys(value, ['protocol', 'scenario', 'raw', 'result', 'capturedAt'], framePath, issues);

  if (!PROTOCOLS.has(value.protocol)) {
    addIssue(issues, 'type-mismatch', `${framePath}.protocol`, `协议只允许 HTTP / TCP，实际为 ${JSON.stringify(value.protocol)}`);
  }
  if (!SCENARIOS.has(value.scenario)) {
    addIssue(issues, 'type-mismatch', `${framePath}.scenario`, `场景只允许 request / response / handshake，实际为 ${JSON.stringify(value.scenario)}`);
  }
  if (requireString(value.raw, `${framePath}.raw`, issues, { nonEmpty: true })) {
    const bytes = utf8ByteLength(value.raw);
    if (bytes > MAX_FRAME_RAW_BYTES) {
      addIssue(
        issues,
        'too-large',
        `${framePath}.raw`,
        `原始输入为 ${bytes} 字节，超过单帧上限 ${MAX_FRAME_RAW_BYTES} 字节`
      );
    }
  }
  if (value.capturedAt !== undefined) requireString(value.capturedAt, `${framePath}.capturedAt`, issues);
  validateResult(value.result, `${framePath}.result`, issues);
}

/**
 * 严格校验一份捕获归档。校验在浏览器（选文件后即时反馈）和
 * 服务端（权威拒绝）上使用同一份实现。
 */
export function validateCaptureDocument(
  input: unknown,
  options: { byteSize?: number } = {}
): ValidationOutcome {
  const issues: ValidationIssue[] = [];

  if (options.byteSize !== undefined && options.byteSize > MAX_CAPTURE_BYTES) {
    addIssue(
      issues,
      'too-large',
      '$',
      `归档文件为 ${options.byteSize} 字节，超过上限 ${MAX_CAPTURE_BYTES} 字节`
    );
  }

  if (!isPlainObject(input)) {
    addIssue(issues, 'invalid-shape', '$', '归档文件必须是 JSON 对象');
    return { ok: false, issues };
  }

  checkExactKeys(input, ['format', 'version', 'kind', 'exportedAt', 'generator', 'frame', 'frames'], '$', issues);

  if (input.format !== CAPTURE_FORMAT) {
    addIssue(issues, 'invalid-format', '$.format', `文件标识应为 "${CAPTURE_FORMAT}"，实际为 ${JSON.stringify(input.format)}`);
  }

  // 版本号是最关键的门槛：任何非当前版本（包括伪造类型）都必须拒绝。
  if (typeof input.version !== 'number' || !Number.isInteger(input.version) || input.version !== CAPTURE_VERSION) {
    addIssue(
      issues,
      'unsupported-version',
      '$.version',
      `不支持的归档版本 ${JSON.stringify(input.version)}：当前解析器只接受版本 ${CAPTURE_VERSION}`
    );
  }

  if (input.kind !== 'frame' && input.kind !== 'session') {
    addIssue(issues, 'invalid-shape', '$.kind', `kind 只允许 frame / session，实际为 ${JSON.stringify(input.kind)}`);
  }

  if (typeof input.exportedAt !== 'string' || Number.isNaN(Date.parse(input.exportedAt))) {
    addIssue(issues, 'type-mismatch', '$.exportedAt', '应为合法的 ISO 时间字符串');
  }
  if (input.generator !== undefined) requireString(input.generator, '$.generator', issues);

  if (input.kind === 'frame') {
    if (input.frames !== undefined) {
      addIssue(issues, 'unknown-field', '$.frames', 'kind=frame 时不应提供 frames 字段');
    }
    validateFrame(input.frame, '$.frame', issues);
  } else if (input.kind === 'session') {
    if (input.frame !== undefined) {
      addIssue(issues, 'unknown-field', '$.frame', 'kind=session 时不应提供 frame 字段');
    }
    if (!Array.isArray(input.frames)) {
      addIssue(issues, 'type-mismatch', '$.frames', `应为数组，实际为 ${describeType(input.frames)}`);
    } else {
      if (input.frames.length === 0) addIssue(issues, 'invalid-shape', '$.frames', '会话归档至少包含一帧');
      if (input.frames.length > MAX_SESSION_FRAMES) {
        addIssue(issues, 'limit-exceeded', '$.frames', `会话最多包含 ${MAX_SESSION_FRAMES} 帧，实际为 ${input.frames.length} 帧`);
      }
      input.frames
        .slice(0, MAX_SESSION_FRAMES)
        .forEach((item, index) => validateFrame(item, `$.frames[${index}]`, issues));
    }
  }

  if (issues.length > 0) return { ok: false, issues };
  const document = input as unknown as CaptureDocument;
  return {
    ok: true,
    document,
    frames: document.kind === 'frame' ? [document.frame] : document.frames
  };
}

/** 单帧导入前核对结果（由 /api/capture/verify 返回）。 */
export interface FrameVerification {
  index: number;
  protocol: CaptureFrame['protocol'];
  scenario: CaptureFrame['scenario'];
  /** 用当前解析器对原始输入重新解析的权威结果。 */
  reparsed: SimulatedPacket;
  /** 归档内的解析结果快照与重新解析结果是否一致（易变时间字段除外）。 */
  consistent: boolean;
  differences: ParseDifference[];
}

export interface CaptureVerifyResult {
  version: number;
  kind: 'frame' | 'session';
  exportedAt: string;
  frameCount: number;
  /** 所有帧快照都能由当前解析器重现。 */
  consistent: boolean;
  frames: FrameVerification[];
}

/** 每次解析都会变化、不参与一致性核对的字段。 */
const VOLATILE_RESULT_PATHS = new Set(['id', 'metadata.capturedAt']);

function previewValue(value: unknown): string {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return text.length > 80 ? `${text.slice(0, 77)}…` : text;
}

/**
 * 深度对比归档内的解析结果快照与用当前解析器重新解析的结果。
 * id / metadata.capturedAt 含时间戳，属于预期差异，已排除。
 */
export function diffParseResult(snapshot: unknown, reparsed: unknown, maxDiffs = 40): ParseDifference[] {
  const differences: ParseDifference[] = [];

  const walk = (left: unknown, right: unknown, path: string): void => {
    if (differences.length >= maxDiffs) return;
    if (VOLATILE_RESULT_PATHS.has(path)) return;

    const leftObject = isPlainObject(left);
    const rightObject = isPlainObject(right);
    if (leftObject && rightObject) {
      for (const key of new Set([...Object.keys(left), ...Object.keys(right)])) {
        walk((left as Record<string, unknown>)[key], (right as Record<string, unknown>)[key], path ? `${path}.${key}` : key);
      }
      return;
    }

    const leftArray = Array.isArray(left);
    const rightArray = Array.isArray(right);
    if (leftArray || rightArray) {
      if (!leftArray || !rightArray) {
        differences.push({ path: path || '$', snapshot: previewValue(left), reparsed: previewValue(right) });
        return;
      }
      if (left.length !== right.length) {
        differences.push({ path: path || '$', snapshot: `数组长度 ${left.length}`, reparsed: `数组长度 ${right.length}` });
      }
      for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
        walk(left[index], right[index], `${path}[${index}]`);
      }
      return;
    }

    if (left !== right) {
      differences.push({ path: path || '$', snapshot: previewValue(left), reparsed: previewValue(right) });
    }
  };

  walk(snapshot, reparsed, '');
  return differences;
}

function toFrame(packet: SimulatedPacket): CaptureFrame {
  return {
    protocol: packet.protocol,
    scenario: packet.scenario,
    raw: packet.raw,
    capturedAt: packet.metadata.capturedAt,
    result: packet
  };
}

/** 导出当前帧（kind=frame）。 */
export function createFrameCapture(packet: SimulatedPacket, now: Date = new Date()): FrameCapture {
  return {
    format: CAPTURE_FORMAT,
    version: CAPTURE_VERSION,
    kind: 'frame',
    exportedAt: now.toISOString(),
    generator: GENERATOR,
    frame: toFrame(packet)
  };
}

/** 导出整个会话（kind=session，帧按分析时间顺序排列）。 */
export function createSessionCapture(packets: SimulatedPacket[], now: Date = new Date()): SessionCapture {
  return {
    format: CAPTURE_FORMAT,
    version: CAPTURE_VERSION,
    kind: 'session',
    exportedAt: now.toISOString(),
    generator: GENERATOR,
    frames: packets.map(toFrame)
  };
}
