import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import type {
  PacketScenario,
  ParseRequest,
  Protocol,
  ProtocolField,
  SimulatedPacket,
  TimelineEvent
} from '../../shared/types';
import {
  CAPTURE_VERSION,
  MAX_CAPTURE_BYTES,
  MAX_SESSION_FRAMES,
  createFrameCapture,
  createSessionCapture,
  validateCaptureDocument,
  type CaptureDocument,
  type CaptureVerifyResult,
  type ValidationIssue
} from '../../shared/capture';

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:3001';
const SESSION_LIMIT = 30;

const scenarioLabels: Record<PacketScenario, string> = {
  request: '请求 / Request',
  response: '响应 / Response',
  handshake: '握手 / Handshake'
};

type ImportPreview =
  | { stage: 'client-error'; fileName: string; fileSize: number; issues: ValidationIssue[] }
  | { stage: 'verifying'; fileName: string; fileSize: number; document: CaptureDocument }
  | { stage: 'verify-error'; fileName: string; fileSize: number; issues: ValidationIssue[] }
  | { stage: 'ready'; fileName: string; fileSize: number; document: CaptureDocument; verification: CaptureVerifyResult };

function App() {
  const [protocol, setProtocol] = useState<Protocol>('HTTP');
  const [scenario, setScenario] = useState<PacketScenario>('request');
  const [rawInput, setRawInput] = useState('');
  const [packet, setPacket] = useState<SimulatedPacket | null>(null);
  /** 当前分析会话中已解析的帧，按时间顺序排列（导出整个会话的数据源）。 */
  const [session, setSession] = useState<SimulatedPacket[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeView, setActiveView] = useState<'overview' | 'hex'>('overview');
  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null);
  const [importing, setImporting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const availableScenarios = useMemo<PacketScenario[]>(
    () => (protocol === 'TCP' ? ['handshake', 'request', 'response'] : ['request', 'response']),
    [protocol]
  );

  /** 把一次新解析结果追加到会话历史，连续完全相同的帧不重复记录。 */
  const rememberFrame = (next: SimulatedPacket) => {
    setSession((previous) => {
      const last = previous[previous.length - 1];
      if (last && last.protocol === next.protocol && last.scenario === next.scenario && last.raw === next.raw) {
        return previous;
      }
      return [...previous, next].slice(-SESSION_LIMIT);
    });
  };

  const requestJson = async <T,>(path: string, init?: RequestInit): Promise<T> => {
    const response = await fetch(`${API_BASE}${path}`, init);
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const apiError: Error & { issues?: ValidationIssue[] } = new Error(
        typeof payload?.error === 'string' ? `API 拒绝了请求：${payload.error}（${response.status}）` : `API 请求失败：${response.status}`
      );
      if (Array.isArray(payload?.issues)) apiError.issues = payload.issues;
      throw apiError;
    }
    return payload as T;
  };

  const request = (path: string, init?: RequestInit) => requestJson<{ data: SimulatedPacket }>(path, init);

  const applyPacket = (next: SimulatedPacket) => {
    setPacket(next);
    setRawInput(next.raw);
    setProtocol(next.protocol);
    setScenario(next.scenario);
  };

  const loadSample = async (nextProtocol = protocol, nextScenario = scenario) => {
    setLoading(true);
    setError('');
    try {
      const result = await request(
        `/api/simulate?protocol=${nextProtocol}&scenario=${nextScenario}`
      );
      applyPacket(result.data);
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
      applyPacket(result.data);
      rememberFrame(result.data);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '解析数据包失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadSample('HTTP', 'request');
    // eslint-disable-next-line react-hooks/exhaustive-deps
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

  const restoreSessionFrame = (frame: SimulatedPacket) => {
    applyPacket(frame);
  };

  const downloadCapture = (captureDocument: CaptureDocument, fileName: string) => {
    const blob = new Blob([JSON.stringify(captureDocument, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const fileStamp = () => {
    const now = new Date();
    const pad = (value: number) => String(value).padStart(2, '0');
    return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  };

  const exportCurrentFrame = () => {
    if (!packet) return;
    downloadCapture(createFrameCapture(packet), `packet-frame-${packet.protocol.toLowerCase()}-${fileStamp()}.json`);
  };

  const exportSession = () => {
    if (!session.length) return;
    downloadCapture(createSessionCapture(session), `packet-session-${session.length}f-${fileStamp()}.json`);
  };

  const openImportPicker = () => fileInputRef.current?.click();

  const handleFileSelected = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;

    const buffer = await file.arrayBuffer();
    const fileSize = buffer.byteLength;
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(buffer));
    } catch {
      setImportPreview({
        stage: 'client-error',
        fileName: file.name,
        fileSize,
        issues: [{ code: 'invalid-shape', path: '$', message: '文件不是合法的 JSON，无法作为捕获归档打开' }]
      });
      return;
    }

    // 第一步：浏览器端用前后端共享的校验器检查版本与字段形状，不通过直接拒绝。
    const clientValidation = validateCaptureDocument(parsed, { byteSize: fileSize });
    if (!clientValidation.ok) {
      setImportPreview({ stage: 'client-error', fileName: file.name, fileSize, issues: clientValidation.issues });
      return;
    }

    // 第二步：交给后端用当前解析器重新解析并核对快照一致性。
    setImportPreview({ stage: 'verifying', fileName: file.name, fileSize, document: clientValidation.document });
    try {
      const verification = await requestJson<{ data: CaptureVerifyResult }>('/api/capture/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(clientValidation.document)
      });
      setImportPreview({
        stage: 'ready',
        fileName: file.name,
        fileSize,
        document: clientValidation.document,
        verification: verification.data
      });
    } catch (cause) {
      const fallbackIssues: ValidationIssue[] = [
        { code: 'invalid-shape', path: '$', message: cause instanceof Error ? cause.message : '服务端校验失败' }
      ];
      const issues = ApiIssueErrorLike(cause) ? cause.issues : fallbackIssues;
      setImportPreview({ stage: 'verify-error', fileName: file.name, fileSize, issues });
    }
  };

  const confirmImport = () => {
    if (!importPreview || importPreview.stage !== 'ready') return;
    setImporting(true);
    try {
      const reparsedFrames = importPreview.verification.frames.map((item) => item.reparsed);
      if (importPreview.document.kind === 'frame') {
        const [first] = reparsedFrames;
        if (first) {
          applyPacket(first);
          rememberFrame(first);
        }
      } else {
        // 导入整个会话：以归档帧（均为重新解析结果）替换当前会话历史。
        setSession(reparsedFrames);
        const first = reparsedFrames[0];
        if (first) applyPacket(first);
      }
      setImportPreview(null);
    } finally {
      setImporting(false);
    }
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
          <div className="control-actions">
            <button className="button ghost" onClick={() => void loadSample()} disabled={loading}>↻ 载入模拟包</button>
            <button className="button primary" onClick={() => void parsePacket()} disabled={loading || !rawInput.trim()}>{loading ? '处理中…' : '解析数据包 →'}</button>
          </div>
        </section>

        <section className="capture-panel panel">
          <div className="capture-heading">
            <div>
              <p className="section-kicker">03 / CAPTURE ARCHIVE</p>
              <h3>捕获包导入 / 导出</h3>
            </div>
            <span className="capture-format-tag">FORMAT network-packet-lab-capture · v{CAPTURE_VERSION}</span>
          </div>
          <div className="capture-actions">
            <button className="button ghost" onClick={exportCurrentFrame} disabled={!packet}>⬇ 导出当前帧</button>
            <button className="button ghost" onClick={exportSession} disabled={!session.length}>⬇ 导出整个会话（{session.length} 帧）</button>
            <button className="button primary" onClick={openImportPicker}>⬆ 选择文件导入…</button>
            <input ref={fileInputRef} type="file" accept="application/json,.json" hidden onChange={(event) => void handleFileSelected(event)} />
          </div>
          <p className="capture-hint">
            归档为带版本号的 JSON（协议、场景、原始输入、解析结果、导出时间）。导入时会先用当前解析器重新解析并核对，
            快照与重新解析不一致的帧会被明确标出，且不会静默覆盖当前内容；每个会话最多保留 {MAX_SESSION_FRAMES} 帧、单帧原始输入不超过 64 KiB。
          </p>
          <SessionStrip frames={session} onSelect={restoreSessionFrame} activeId={packet?.id ?? ''} />
        </section>

        {error && <div className="error-banner">⚠ {error} <button onClick={() => setError('')}>关闭</button></div>}

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
        <ImportModal
          preview={importPreview}
          importing={importing}
          onClose={() => setImportPreview(null)}
          onConfirm={confirmImport}
        />
      )}
    </div>
  );
}

// instanceof 在不同错误构造来源间不可靠，这里按结构判断。
function ApiIssueErrorLike(cause: unknown): cause is Error & { issues: ValidationIssue[] } {
  return typeof cause === 'object' && cause !== null && Array.isArray((cause as { issues?: unknown }).issues);
}

function SessionStrip({ frames, onSelect, activeId }: { frames: SimulatedPacket[]; onSelect: (frame: SimulatedPacket) => void; activeId: string }) {
  if (!frames.length) {
    return <div className="session-strip empty">本次会话还没有解析记录；点击“解析数据包”后，帧会按顺序出现在这里，可整体导出。</div>;
  }
  return (
    <div className="session-strip">
      {frames.map((frame, index) => (
        <button
          key={`${frame.id}-${index}`}
          className={`session-chip${frame.id === activeId ? ' active' : ''}`}
          title={frame.raw}
          onClick={() => onSelect(frame)}
        >
          <span className="session-index">{String(index + 1).padStart(2, '0')}</span>
          <span className="session-protocol">{frame.protocol}</span>
          <span className="session-scenario">{scenarioLabels[frame.scenario]?.split(' / ')[0] ?? frame.scenario}</span>
          <span className="session-size">{frame.metadata.length}B</span>
        </button>
      ))}
    </div>
  );
}

function ImportModal({
  preview,
  importing,
  onClose,
  onConfirm
}: {
  preview: ImportPreview;
  importing: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="导入捕获包预览">
      <div className="modal panel">
        <div className="modal-heading">
          <div>
            <p className="section-kicker">IMPORT PREVIEW</p>
            <h3>{preview.fileName}</h3>
          </div>
          <button className="modal-close" onClick={onClose} aria-label="关闭预览">✕</button>
        </div>

        <p className="modal-filemeta">
          {formatBytes(preview.fileSize)}
          {preview.stage === 'ready' && <> · {preview.verification.kind === 'frame' ? '单帧归档' : `会话归档（${preview.verification.frameCount} 帧）`} · 导出于 {formatExportedAt(preview.verification.exportedAt)}</>}
          {preview.stage === 'verifying' && ' · 正在请求服务端重新解析核对…'}
        </p>

        {preview.stage === 'verifying' && (
          <div className="empty-state">正在用当前解析器重新解析归档内的原始输入，请稍候…</div>
        )}

        {(preview.stage === 'client-error' || preview.stage === 'verify-error') && (
          <div className="import-rejected">
            <strong>导入被拒绝：文件未通过校验。</strong>
            <IssueList issues={preview.issues} />
            <p className="import-note">当前工作台内容未被修改。请修正文件后重新选择。</p>
          </div>
        )}

        {preview.stage === 'ready' && (
          <ImportReadyPreview preview={preview} />
        )}

        <div className="modal-actions">
          <button className="button ghost" onClick={onClose} disabled={importing}>取消</button>
          {preview.stage === 'ready' && (
            <button className="button primary" onClick={onConfirm} disabled={importing}>
              {importing ? '导入中…' : preview.verification.consistent
                ? `确认导入（${preview.verification.kind === 'frame' ? '载入当前帧' : `替换会话，载入 ${preview.verification.frameCount} 帧`}）`
                : '我已知晓差异，仍按重新解析结果导入'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function ImportReadyPreview({ preview }: { preview: Extract<ImportPreview, { stage: 'ready' }> }) {
  const { verification } = preview;
  const mismatchCount = verification.frames.filter((item) => !item.consistent).length;
  return (
    <div className="import-ready">
      {verification.consistent ? (
        <div className="import-banner ok">
          ✓ 核对通过：{verification.frameCount} 帧的原始输入均可由当前解析器重现，快照与重新解析结果一致（时间戳字段除外）。
        </div>
      ) : (
        <div className="import-banner warn">
          ⚠ 发现 {mismatchCount} / {verification.frameCount} 帧不一致：归档内保存的解析结果无法由当前解析器重现
          （可能来自不同版本或被手工修改）。导入将使用<strong>对原始输入重新解析</strong>的结果，归档快照仅用于对照展示，不会覆盖它。
        </div>
      )}
      <div className="import-frame-list">
        {verification.frames.map((item) => (
          <details key={item.index} className={`import-frame ${item.consistent ? 'consistent' : 'mismatch'}`} open={!item.consistent}>
            <summary>
              <span className={`consistency-dot ${item.consistent ? 'ok' : 'warn'}`} />
              <span className="import-frame-title">#{item.index + 1} · {item.protocol} · {scenarioLabels[item.scenario] ?? item.scenario}</span>
              <span className="import-frame-status">{item.consistent ? '一致' : `${item.differences.length} 处差异`}</span>
            </summary>
            <div className="import-frame-body">
              <p className="import-raw-label">原始输入（重新解析的唯一依据）：</p>
              <pre className="import-raw">{item.reparsed.raw}</pre>
              {!item.consistent && (
                <div className="diff-table-wrap">
                  <p className="import-raw-label">快照与重新解析结果的差异（{item.differences.length} 处）：</p>
                  <table className="diff-table">
                    <thead><tr><th>字段路径</th><th>归档快照</th><th>重新解析</th></tr></thead>
                    <tbody>
                      {item.differences.map((difference, index) => (
                        <tr key={index}>
                          <td><code>{difference.path || '（根）'}</code></td>
                          <td className="diff-snapshot">{difference.snapshot}</td>
                          <td className="diff-reparsed">{difference.reparsed}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </details>
        ))}
      </div>
    </div>
  );
}

function IssueList({ issues }: { issues: ValidationIssue[] }) {
  const codeLabels: Record<ValidationIssue['code'], string> = {
    'unsupported-version': '未知版本',
    'invalid-format': '格式标识错误',
    'invalid-shape': '结构错误',
    'type-mismatch': '字段类型伪造',
    'unknown-field': '未知字段',
    'too-large': '载荷过大',
    'limit-exceeded': '超出数量上限'
  };
  return (
    <ul className="issue-list">
      {issues.slice(0, 30).map((issue, index) => (
        <li key={index}>
          <span className={`issue-code issue-${issue.code}`}>{codeLabels[issue.code] ?? issue.code}</span>
          <code className="issue-path">{issue.path}</code>
          <span className="issue-message">{issue.message}</span>
        </li>
      ))}
      {issues.length > 30 && <li>…另有 {issues.length - 30} 个问题未展示</li>}
    </ul>
  );
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < MAX_CAPTURE_BYTES) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 / 1024).toFixed(2)} MiB`;
}

function formatExportedAt(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour12: false });
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
