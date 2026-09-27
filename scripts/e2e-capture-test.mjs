const BASE = 'http://localhost:3001';

let pass = 0;
let fail = 0;
function check(name, condition, extra = '') {
  if (condition) {
    pass += 1;
    console.log(`  ✓ ${name}`);
  } else {
    fail += 1;
    console.log(`  ✗ ${name} ${extra}`);
  }
}

async function parse(protocol, scenario, raw) {
  const response = await fetch(`${BASE}/api/parse`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ protocol, scenario, raw })
  });
  if (!response.ok) throw new Error(`parse failed ${response.status}`);
  const payload = await response.json();
  return payload.data;
}

async function verify(document, expectStatus = 200) {
  const response = await fetch(`${BASE}/api/capture/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(document)
  });
  const payload = await response.json();
  return { status: response.status, payload };
}

const envelope = (kind, extra) => ({
  format: 'network-packet-lab-capture',
  version: 1,
  kind,
  exportedAt: new Date().toISOString(),
  generator: 'network-packet-lab@1.0.0',
  ...extra
});

console.log('1) 合法单帧归档（快照与重新解析一致）');
{
  const packet = await parse('HTTP', 'request', 'GET /hello HTTP/1.1\r\nHost: lab.local\r\n\r\n');
  const doc = envelope('frame', { frame: { protocol: 'HTTP', scenario: 'request', raw: packet.raw, result: packet } });
  const { status, payload } = await verify(doc);
  check('HTTP 200', status === 200, `status=${status}`);
  check('frameCount=1', payload.data?.frameCount === 1);
  check('consistent=true', payload.data?.consistent === true);
  check('无差异', payload.data?.frames[0]?.differences.length === 0);
}

console.log('2) 合法 TCP 会话归档（多帧）');
{
  const packets = [];
  packets.push(await parse('TCP', 'handshake', 'TCP 10.0.0.24:51842 > 10.0.0.8:443 | Seq=0 Ack=0 | Flags=SYN | Win=64240 | MSS=1460'));
  packets.push(await parse('TCP', 'request', 'TCP 10.0.0.24:51842 > 10.0.0.8:443 | Seq=1 Ack=1 | Flags=ACK,PSH | Win=64240 | Len=128'));
  const doc = envelope('session', {
    frames: packets.map((p) => ({ protocol: p.protocol, scenario: p.scenario, raw: p.raw, result: p }))
  });
  const { status, payload } = await verify(doc);
  check('HTTP 200', status === 200);
  check('frameCount=2', payload.data?.frameCount === 2);
  check('全部一致', payload.data?.consistent === true);
}

console.log('3) 快照被篡改（与重新解析不一致）→ 明确报告差异，不报错');
{
  const packet = await parse('HTTP', 'request', 'GET /hello HTTP/1.1\r\nHost: lab.local\r\n\r\n');
  const tampered = JSON.parse(JSON.stringify(packet));
  tampered.metadata.checksum = '0xFAKE';
  tampered.summary = '被助教手改过的摘要';
  const doc = envelope('frame', { frame: { protocol: 'HTTP', scenario: 'request', raw: packet.raw, result: tampered } });
  const { status, payload } = await verify(doc);
  check('HTTP 200（不是拒绝，是核对报告）', status === 200);
  check('consistent=false', payload.data?.consistent === false);
  const diffs = payload.data?.frames[0]?.differences ?? [];
  check('报告 checksum 差异', diffs.some((d) => d.path === 'metadata.checksum'), JSON.stringify(diffs));
  check('报告 summary 差异', diffs.some((d) => d.path === 'summary'));
  check('重新解析结果带回正确 checksum', payload.data?.frames[0]?.reparsed.metadata.checksum !== '0xFAKE');
}

console.log('4) 原始输入被替换（raw 与 result.raw 不一致）→ 差异被捕获');
{
  const packet = await parse('HTTP', 'request', 'GET /a HTTP/1.1\r\nHost: lab.local\r\n\r\n');
  const doc = envelope('frame', {
    frame: { protocol: 'HTTP', scenario: 'request', raw: 'GET /totally-different HTTP/1.1\r\nHost: evil.example\r\n\r\n', result: packet }
  });
  const { status, payload } = await verify(doc);
  check('HTTP 200', status === 200);
  check('consistent=false', payload.data?.consistent === false);
  check('差异条数 > 0', payload.data?.frames[0]?.differences.length > 0);
}

console.log('5) 未知版本 → 422 拒绝');
{
  const packet = await parse('HTTP', 'request', 'GET /hello HTTP/1.1\r\nHost: lab.local\r\n\r\n');
  const doc = envelope('frame', { version: 99, frame: { protocol: 'HTTP', scenario: 'request', raw: packet.raw, result: packet } });
  const { status, payload } = await verify(doc);
  check('HTTP 422', status === 422, `status=${status}`);
  check('错误码 unsupported-version', payload.issues?.some((i) => i.code === 'unsupported-version'), JSON.stringify(payload.issues));
}

console.log('6) 版本号伪造为字符串 → 422（版本门槛优先）');
{
  const { status, payload } = await verify({ format: 'network-packet-lab-capture', version: '1', kind: 'frame', exportedAt: new Date().toISOString(), frame: null });
  check('HTTP 422', status === 422, `status=${status}`);
  check('报告 unsupported-version', payload.issues?.some((i) => i.code === 'unsupported-version'));
}

console.log('7) 字段类型伪造（raw 为数字、protocol 非法、length 为字符串）');
{
  const packet = await parse('HTTP', 'request', 'GET /hello HTTP/1.1\r\nHost: lab.local\r\n\r\n');
  const bad = JSON.parse(JSON.stringify(packet));
  bad.metadata.length = '一百二十八';
  const doc = envelope('frame', { frame: { protocol: 'FOO', scenario: 'request', raw: 42, result: bad } });
  const { status, payload } = await verify(doc);
  check('HTTP 400', status === 400, `status=${status}`);
  const codes = (payload.issues ?? []).map((i) => i.code + '@' + i.path);
  check('protocol 类型错误', codes.some((c) => c.includes('frame.protocol')));
  check('raw 类型错误', codes.some((c) => c.includes('frame.raw')));
  check('length 类型错误', codes.some((c) => c.includes('metadata.length')), JSON.stringify(codes));
}

console.log('8) 未知/多余字段 → unknown-field');
{
  const packet = await parse('HTTP', 'request', 'GET /hello HTTP/1.1\r\nHost: lab.local\r\n\r\n');
  const doc = envelope('frame', { injected: 'evil', frame: { protocol: 'HTTP', scenario: 'request', raw: packet.raw, result: packet, extraField: 1 } });
  const { status, payload } = await verify(doc);
  check('HTTP 400', status === 400);
  check('根未知字段被拦', payload.issues?.some((i) => i.path === '$.injected'));
  check('帧未知字段被拦', payload.issues?.some((i) => i.path === '$.frame.extraField'), JSON.stringify(payload.issues?.map((i) => i.path)));
}

console.log('9) 单帧 payload 超 64 KiB → 413');
{
  const huge = 'x'.repeat(70 * 1024);
  const { status, payload } = await verify(
    envelope('frame', { frame: { protocol: 'HTTP', scenario: 'request', raw: huge, result: null } })
  );
  check('HTTP 413', status === 413, `status=${status}`);
  check('报告 too-large', payload.issues?.some((i) => i.code === 'too-large' && i.path === '$.frame.raw'));
}

console.log('10) 会话帧数超 100 → 400 limit-exceeded');
{
  const packet = await parse('HTTP', 'request', 'GET /hello HTTP/1.1\r\nHost: lab.local\r\n\r\n');
  const frames = Array.from({ length: 101 }, () => ({ protocol: 'HTTP', scenario: 'request', raw: packet.raw, result: packet }));
  const { status, payload } = await verify(envelope('session', { frames }));
  check('HTTP 400', status === 400);
  check('报告 limit-exceeded', payload.issues?.some((i) => i.code === 'limit-exceeded'), JSON.stringify(payload.issues?.map((i) => i.code)));
}

console.log('11) format 标识错误 / kind 非法 / exportedAt 非法');
{
  const { status, payload } = await verify({ format: 'wireshark-capture', version: 1, kind: 'bundle', exportedAt: 'not-a-date', frames: [] });
  check('HTTP 400', status === 400);
  const paths = (payload.issues ?? []).map((i) => i.path);
  check('format 被拦', paths.includes('$.format'));
  check('kind 被拦', paths.includes('$.kind'));
  check('exportedAt 被拦', paths.includes('$.exportedAt'));
}

console.log('12) 整体 body 超 1MB → 413（express 层，2MB 传输上限内）');
{
  // 构造约 1.4MB 但结构有效到 raw 检查之前也会因 1MB 总上限被拒
  const raw = 'A'.repeat(60 * 1024);
  const frames = Array.from({ length: 25 }, () => ({ protocol: 'HTTP', scenario: 'request', raw }));
  const body = JSON.stringify(envelope('session', { frames }));
  check('body > 1MB', Buffer.byteLength(body) > 1024 * 1024, `${Buffer.byteLength(body)} bytes`);
  const response = await fetch(`${BASE}/api/capture/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body
  });
  check('HTTP 413', response.status === 413, `status=${response.status}`);
  const payload = await response.json();
  check('报告 too-large @ $', payload.issues?.some((i) => i.code === 'too-large' && i.path === '$'));
}

console.log('13) 非法 JSON → 400');
{
  const response = await fetch(`${BASE}/api/capture/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{ not json'
  });
  const payload = await response.json();
  check('HTTP 400', response.status === 400);
  check('invalid-shape', payload.issues?.some((i) => i.code === 'invalid-shape'));
}

console.log(`\n结果：${pass} 通过, ${fail} 失败`);
process.exit(fail === 0 ? 0 : 1);
