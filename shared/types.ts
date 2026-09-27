export type Protocol = 'HTTP' | 'TCP';
export type PacketScenario = 'request' | 'response' | 'handshake';

export interface HexRow {
  offset: string;
  bytes: string[];
  ascii: string;
}

export interface ProtocolField {
  id: string;
  key: string;
  value: string;
  description: string;
  children?: ProtocolField[];
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  label: string;
  phase: 'ingress' | 'parse' | 'transport' | 'application' | 'egress';
  detail: string;
}

export interface SimulatedPacket {
  id: string;
  protocol: Protocol;
  scenario: PacketScenario;
  summary: string;
  raw: string;
  hex: HexRow[];
  fields: ProtocolField[];
  timeline: TimelineEvent[];
  metadata: {
    capturedAt: string;
    source: string;
    destination: string;
    length: number;
    checksum: string;
  };
}

export interface ParseRequest {
  protocol: Protocol;
  scenario: PacketScenario;
  raw: string;
}

// ---------------------------------------------------------------------------
// Capture file format (import / export)
// ---------------------------------------------------------------------------

/** Magic identifier written into every capture file so unknown JSON is rejected. */
export const CAPTURE_FILE_FORMAT = 'network-packet-lab/capture';
/** Only this exact format version is accepted on import. Bump on breaking changes. */
export const CAPTURE_FILE_VERSION = 1;

export type CaptureKind = 'frame' | 'session';

/** One captured analysis step: inputs plus the parse result at export time. */
export interface CaptureFrame {
  protocol: Protocol;
  scenario: PacketScenario;
  raw: string;
  packet: SimulatedPacket;
}

/**
 * Versioned capture document handed to a teaching assistant.
 * Required fields: protocol/scenario/raw (inside each frame), packet (parse
 * result), exportedAt (export time), plus format/version for compatibility.
 */
export interface CaptureFile {
  format: typeof CAPTURE_FILE_FORMAT;
  version: number;
  kind: CaptureKind;
  exportedAt: string;
  frames: CaptureFrame[];
}

export type FrameVerifyStatus = 'match' | 'mismatch';

export interface FrameVerification {
  index: number;
  protocol: Protocol;
  scenario: PacketScenario;
  summary: string;
  status: FrameVerifyStatus;
  /** Aspects that differ between the stored parse result and a fresh re-parse, e.g. ['fields', 'hex']. */
  mismatches: string[];
}

export interface CaptureVerification {
  version: number;
  kind: CaptureKind;
  exportedAt: string;
  frameCount: number;
  frames: FrameVerification[];
}
