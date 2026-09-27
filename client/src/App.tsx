import { useEffect, useMemo, useRef, useState, type ChangeEvent, type CSSProperties } from 'react';
import {
  CAPTURE_FILE_FORMAT,
  CAPTURE_FILE_VERSION
} from '../../shared/types';
import type {
  CaptureFile,
  CaptureFrame,
  CaptureVerification,
  PacketScenario,
  ParseRequest,
  Protocol,
  ProtocolField,
  SimulatedPacket,
  TimelineEvent
} from '../../shared/types';

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:3001';
const MAX_IMPORT_FILE_BYTES = 1024 * 1024;
const MAX_SESSION_FRAMES = 100;

const scenarioLabels: Record<PacketScenario, string> = {
  request: '请求 / Request',
  response: '响应 / Response',
  handshake: '握手 / Handshake'
};

const mismatchLabels: Record<string, string> = {
  'packet.protocol': '协议',
  'packet.scenario': '场景',
  'packet.raw': '包内原始输入',
  summary: '摘要',
  hex: '十六进制视图',
  fields: '协议字段树',
  timeline: '时间线',
  'metadata.source': '源地址',
  'metadata.destination': '目的地址',
  'metadata.length': '长度',
  'metadata.checksum': '校验和'
};

function mismatchLabel(key: string): string {
  return mismatchLabels[key] ?? key;
}

function App() {
  const [protocol, setProtocol] = useState<Protocol>('HTTP');
  const [scenario, setScenario] = useState<PacketScenario>('request');
  const [rawInput, setRawInput] = useState('');
  const [packet, setPacket] = useState<SimulatedPacket | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeView, setActiveView] = useState<'overview' | 'hex'>('overview');
  const [sessionFrames, setSessionFrames] = useState<CaptureFrame[]>([]);
  const [importPreview, setImportPreview] = useState<{ file: CaptureFile; verification: CaptureVerification } | null>(null);
  const [importWarning, setImportWarning] = useState('');
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const availableScenarios = useMemo<PacketScenario[]>(
    () => (protocol === 'TCP' ? ['handshake', 'request', 'response'] : ['request', 'response']),
    [protocol]
  );

  const activeFrameIndex = packet
    ? sessionFrames.findIndex((frame) => frame.packet === packet)
    : -1;
  const importMismatchCount = importPreview
    ? importPreview.verification.frames.filter((frame) => frame.status === 'mismatch').length
    : 0;

  const request = async (path: string, init?: RequestInit) => {
    const response = await fetch(`${API_BASE}${path}`, init);
    if (!response.ok) throw new Error(`API 请求失败：${response.status}`);
    return response.json() as Promise<{ data: SimulatedPacket }>;
  };

  const recordFrame = (parsed: SimulatedPacket) => {
    setSessionFrames((previous) => {
      const last = previous[previous.length - 1];
      if (last && last.protocol === parsed.protocol && last.scenario === parsed.scenario && last.raw === parsed.raw) {
        return previous;
      }
      return [
        ...previous,
        { protocol: parsed.protocol, scenario: parsed.scenario, raw: parsed.raw, packet: parsed }
      ].slice(-MAX_SESSION_FRAMES);
    });
  };

  const loadSample = async (nextProtocol = protocol, nextScenario = scenario) => {
    setLoading(true);
    setError('');
    try {
      const result = await request(
        `/api/simulate?protocol=${nextProtocol}&scenario=${nextScenario}`
      );
      setPacket(result.data);
      setRawInput(result.data.raw);
      recordFrame(result.data);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '加载模拟数据失败');
    } finally {
      setLoading(false);
    }
  };

  const parsePacket = async () => {
    setLoading(true);
    setError('');
    const body: ParseRequest = { protocol, scenario, raw: rawInput };
    try {
      const result = await request('/api/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      setPacket(result.data);
      setRawInput(result.data.raw);
      recordFrame(result.data);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '解析数据包失败');
    } finally {
      setLoading(false);
    }
  };

  // ---- Capture export ----------------------------------------------------

  const downloadCapture = (file: CaptureFile) => {
    const blob = new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `packet-lab-${file.kind}-${file.exportedAt.replace(/[:.]/g, '-')}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };

  const buildCaptureFile = (kind: CaptureFile['kind'], frames: CaptureFrame[]): CaptureFile => ({
    format: CAPTURE_FILE_FORMAT,
    version: CAPTURE_FILE_VERSION,
    kind,
    exportedAt: new Date().toISOString(),
    frames
  });

  const exportCurrentFrame = () => {
    if (!packet) return;
    downloadCapture(buildCaptureFile('frame', [{ protocol: packet.protocol, scenario: packet.scenario, raw: packet.raw, packet }]));
  };

  const exportSession = () => {
    if (!sessionFrames.length) return;
    downloadCapture(buildCaptureFile('session', sessionFrames));
  };

  // ---- Capture import ----------------------------------------------------

  const handleImportFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const input = event.target;
    const selected = input.files?.[0];
    input.value = '';
    if (!selected) return;
    setError('');
    if (selected.size > MAX_IMPORT_FILE_BYTES) {
      setError(`文件过大：捕获文件上限为 ${MAX_IMPORT_FILE_BYTES / 1024}KB`);
      return;
    }
    const text = await selected.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      setError('所选文件不是合法的 JSON，无法作为捕获文件导入');
      return;
    }
    try {
      const response = await fetch(`${API_BASE}/api/captures/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: text
      });
      const payload = await response.json().catch(() => null) as { error?: string; data?: CaptureVerification } | null;
      if (!response.ok) {
        setError(payload?.error ?? `捕获文件校验失败：HTTP ${response.status}`);
        return;
      }
      setImportPreview({ file: parsed as CaptureFile, verification: payload!.data! });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '捕获文件校验失败，请检查 API 服务');
    }
  };

  const loadSessionFrame = (frame: CaptureFrame) => {
    setProtocol(frame.protocol);
    setScenario(frame.scenario);
    setRawInput(frame.raw);
    setPacket(frame.packet);
  };

  const confirmImport = () => {
    if (!importPreview) return;
    const { file, verification } = importPreview;
    setSessionFrames(file.frames.slice(-MAX_SESSION_FRAMES));
    const first = file.frames[0];
    setProtocol(first.protocol);
    setScenario(first.scenario);
    setRawInput(first.raw);
    setPacket(first.packet);
    const mismatched = verification.frames.filter((frame) => frame.status === 'mismatch');
    setImportWarning(mismatched.length
      ? `已按文件内容导入 ${file.frames.length} 帧，其中 ${mismatched.length} 帧与重新解析结果不一致：${mismatched
          .map((frame) => `#${frame.index + 1}（${frame.mismatches.map(mismatchLabel).join('、')}）`)
          .join('，')}。请勿直接采信这些帧的内容，请核对文件来源。`
      : '');
    setImportPreview(null);
  };

  useEffect(() => {
    void loadSample('HTTP', 'request');
  }, []);

  const changeProtocol = (nextProtocol: Protocol) => {
    const nextScenario = nextProtocol === 'TCP' && scenario === 'response' ? 'handshake' : scenario;
    setProtocol(nextProtocol);
    setScenario(nextScenario);
    void loadSample(nextProtocol, nextScenario);
  };

  const changeScenario = (nextScenario: PacketScenario) => {
    setScenario(nextScenario);
    void loadSample(protocol, nextScenario);
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark"><span /> <span /> <span /></div>
          <div>
            <p className="eyebrow">PROJECT 10 / PACKET OBSERVATORY</p>
            <h1>网络协议数据包可视化实验室</h1>
          </div>
        </div>
        <div className="connection-status"><i /> API ONLINE <span>localhost:3001</span></div>
      </header>

      <main className="dashboard">
        <section className="hero-copy">
          <div>
            <p className="section-kicker">解析工作台 · INSPECTOR</p>
            <h2>把每一个字节，<em>还原成可读的网络故事。</em></h2>
            <p className="hero-subtitle">选择协议和场景，载入模拟流量，逐层查看字段、时间线与十六进制原始数据。</p>
          </div>
          <div className="hero-stat"><strong>{packet?.metadata.length ?? '—'}</strong><span>BYTES<br />CURRENT FRAME</span></div>
        </section>

        <section className="control-panel panel">
          <div className="control-group">
            <label>协议 <span>PROTOCOL</span></label>
            <div className="segmented-control">
              {(['HTTP', 'TCP'] as Protocol[]).map((item) => (
                <button key={item} className={protocol === item ? 'active' : ''} onClick={() => changeProtocol(item)}>{item}</button>
              ))}
            </div>
          </div>
          <div className="control-group scenario-control">
            <label>模拟场景 <span>SCENARIO</span></label>
            <select value={scenario} onChange={(event) => changeScenario(event.target.value as PacketScenario)}>
              {availableScenarios.map((item) => <option key={item} value={item}>{scenarioLabels[item]}</option>)}
            </select>
          </div>
          <div className="control-group capture-control">
            <label>捕获文件 <span>CAPTURE · v{CAPTURE_FILE_VERSION}</span></label>
            <div className="capture-buttons">
              <button className="button ghost" onClick={exportCurrentFrame} disabled={!packet}>⤓ 导出当前帧</button>
              <button className="button ghost" onClick={exportSession} disabled={!sessionFrames.length}>⤓ 导出会话 ({sessionFrames.length})</button>
              <button className="button ghost" onClick={() => fileInputRef.current?.click()}>⤒ 选择文件导入</button>
              <input ref={fileInputRef} type="file" accept=".json,application/json" hidden onChange={(event) => void handleImportFile(event)} />
            </div>
          </div>
          <div className="control-actions">
            <button className="button ghost" onClick={() => void loadSample()} disabled={loading}>↻ 载入模拟包</button>
            <button className="button primary" onClick={() => void parsePacket()} disabled={loading || !rawInput.trim()}>{loading ? '处理中…' : '解析数据包 →'}</button>
          </div>
        </section>

        {error && <div className="error-banner">⚠ {error} <button onClick={() => setError('')}>关闭</button></div>}
        {importWarning && <div className="warning-banner">⚠ {importWarning} <button onClick={() => setImportWarning('')}>关闭</button></div>}

        {sessionFrames.length > 0 && (
          <section className="session-strip panel">
            <span className="session-label">SESSION · {sessionFrames.length} 帧</span>
            <div className="session-chips">
              {sessionFrames.map((frame, index) => (
                <button
                  key={index}
                  className={`session-chip ${index === activeFrameIndex ? 'active' : ''}`}
                  title={frame.packet.summary}
                  onClick={() => loadSessionFrame(frame)}
                >
                  #{index + 1} {frame.protocol} · {frame.scenario}
                </button>
              ))}
            </div>
            <button className="session-clear" onClick={() => setSessionFrames([])}>清空会话</button>
          </section>
        )}

        <section className="workspace-grid">
          <div className="left-column">
            <div className="panel packet-input-panel">
              <div className="panel-heading"><div><p className="section-kicker">01 / INPUT STREAM</p><h3>数据包输入</h3></div><span className="badge">{protocol}</span></div>
              <textarea value={rawInput} onChange={(event) => setRawInput(event.target.value)} spellCheck={false} aria-label="原始数据包输入" />
              <div className="input-footer"><span>{rawInput.length} chars · editable payload</span><button onClick={() => setRawInput('')}>清空输入</button></div>
            </div>
            <div className="panel timeline-panel">
              <div className="panel-heading"><div><p className="section-kicker">02 / EVENT TRACE</p><h3>传输时间线</h3></div><span className="trace-id">{packet?.id ?? 'WAITING'}</span></div>
              <Timeline events={packet?.timeline ?? []} />
            </div>
          </div>

          <div className="right-column">
            <div className="panel packet-summary">
              <div className="summary-top"><div><p className="section-kicker">ACTIVE FRAME</p><h3>{packet?.summary ?? '等待数据包'}</h3></div><div className="live-chip"><i /> DECODED</div></div>
              <div className="metadata-grid">
                <Meta label="SOURCE" value={packet?.metadata.source ?? '—'} />
                <Meta label="DESTINATION" value={packet?.metadata.destination ?? '—'} />
                <Meta label="CAPTURED AT" value={packet?.metadata.capturedAt ?? '—'} />
                <Meta label="CHECKSUM" value={packet?.metadata.checksum ?? '—'} />
              </div>
            </div>

            <div className="panel details-panel">
              <div className="tabs"><button className={activeView === 'overview' ? 'selected' : ''} onClick={() => setActiveView('overview')}>协议字段树</button><button className={activeView === 'hex' ? 'selected' : ''} onClick={() => setActiveView('hex')}>十六进制视图</button></div>
              {activeView === 'overview' ? <FieldTree fields={packet?.fields ?? []} /> : <HexView rows={packet?.hex ?? []} />}
            </div>
          </div>
        </section>
      </main>
      <footer className="footer"><span>PACKET LAB / EDUCATIONAL SIMULATOR</span><span>React + Vite + TypeScript · Express API</span></footer>

      {importPreview && (
        <div className="modal-backdrop" onClick={() => setImportPreview(null)}>
          <div className="modal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <div className="panel-heading">
              <div>
                <p className="section-kicker">IMPORT PREVIEW</p>
                <h3>导入预览 · 共 {importPreview.verification.frameCount} 帧</h3>
              </div>
              <span className="badge">v{importPreview.verification.version} · {importPreview.verification.kind === 'session' ? '会话' : '单帧'}</span>
            </div>
            <div className="import-meta">
              <Meta label="导出时间 EXPORTED AT" value={importPreview.verification.exportedAt} />
              <Meta label="重新解析校验 VERIFY" value={importMismatchCount ? `${importMismatchCount} 帧不一致` : '全部一致'} />
            </div>
            {importMismatchCount > 0 && (
              <div className="import-alert">
                ⚠ {importMismatchCount} 帧的存储解析结果与当前解析器的重新解析结果不一致，说明文件被修改、来自更新/更旧的解析器或导出时数据损坏。
                确认导入会用文件内容替换当前会话，而不是静默覆盖；请核对来源后再决定。
              </div>
            )}
            <div className="import-frames">
              {importPreview.verification.frames.map((frame) => (
                <div className="import-frame" key={frame.index}>
                  <span className="import-index">#{frame.index + 1}</span>
                  <span className="import-proto">{frame.protocol} · {scenarioLabels[frame.scenario]}</span>
                  <span className="import-summary" title={frame.summary}>{frame.summary}</span>
                  <span className={`verify-badge ${frame.status}`}>
                    {frame.status === 'match'
                      ? '✓ 重新解析一致'
                      : `✕ 不一致：${frame.mismatches.map(mismatchLabel).join('、')}`}
                  </span>
                </div>
              ))}
            </div>
            <div className="modal-actions">
              <button className="button ghost" onClick={() => setImportPreview(null)}>取消</button>
              <button className="button primary" onClick={confirmImport}>
                {importMismatchCount > 0 ? `仍要导入（${importMismatchCount} 帧不一致）` : '确认导入'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return <div className="meta-item"><span>{label}</span><strong>{value}</strong></div>;
}

function FieldTree({ fields }: { fields: ProtocolField[] }) {
  if (!fields.length) return <div className="empty-state">解析后将在这里显示协议层级字段。</div>;
  return <div className="field-tree">{fields.map((field) => <FieldNode key={field.id} field={field} depth={0} />)}</div>;
}

function FieldNode({ field, depth }: { field: ProtocolField; depth: number }) {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = Boolean(field.children?.length);
  return <div className="field-node" style={{ '--depth': depth } as CSSProperties}>
    <div className="field-row" onClick={() => hasChildren && setExpanded((value) => !value)}>
      <span className={`chevron ${hasChildren ? '' : 'invisible'} ${expanded ? 'open' : ''}`}>⌄</span>
      <span className="field-key">{field.key}</span>
      <span className="field-value">{field.value}</span>
      <span className="field-description">{field.description}</span>
    </div>
    {hasChildren && expanded && <div className="field-children">{field.children!.map((child) => <FieldNode key={child.id} field={child} depth={depth + 1} />)}</div>}
  </div>;
}

function Timeline({ events }: { events: TimelineEvent[] }) {
  if (!events.length) return <div className="empty-state">还没有事件记录。</div>;
  return <div className="timeline">{events.map((event, index) => <div className="timeline-event" key={event.id}><div className="timeline-marker"><span>{String(index + 1).padStart(2, '0')}</span></div><div className="timeline-content"><div><strong>{event.label}</strong><time>{event.timestamp}</time></div><p>{event.detail}</p><span className={`phase phase-${event.phase}`}>{event.phase}</span></div></div>)}</div>;
}

function HexView({ rows }: { rows: SimulatedPacket['hex'] }) {
  if (!rows.length) return <div className="empty-state">没有可显示的十六进制内容。</div>;
  return <div className="hex-view"><div className="hex-header"><span>OFFSET</span><span>HEX BYTES</span><span>ASCII</span></div>{rows.map((row) => <div className="hex-row" key={row.offset}><code>{row.offset}</code><code>{row.bytes.join(' ')}</code><code className="ascii">{row.ascii}</code></div>)}</div>;
}

export default App;
