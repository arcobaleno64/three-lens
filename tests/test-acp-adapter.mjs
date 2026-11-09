import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ACP_DIAGNOSTIC_SEVERITY,
  mapSeverityToAcpDiagnostic,
  formatAcpDiagnostic,
  serializeJsonRpcNotification,
  formatPublishDiagnosticsNotification,
  parseJsonRpcMessage,
  createAcpDiagnosticEmitter
} from '../scripts/adapters/acp-adapter.mjs';

test('ACP Adapter: mapSeverityToAcpDiagnostic severity mapping', () => {
  assert.equal(mapSeverityToAcpDiagnostic('CRITICAL'), ACP_DIAGNOSTIC_SEVERITY.ERROR);
  assert.equal(mapSeverityToAcpDiagnostic('HIGH'), ACP_DIAGNOSTIC_SEVERITY.ERROR);
  assert.equal(mapSeverityToAcpDiagnostic('MEDIUM'), ACP_DIAGNOSTIC_SEVERITY.WARNING);
  assert.equal(mapSeverityToAcpDiagnostic('LOW'), ACP_DIAGNOSTIC_SEVERITY.INFORMATION);
  assert.equal(mapSeverityToAcpDiagnostic('INFO'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic('NONE'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic('UNKNOWN'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic(null), ACP_DIAGNOSTIC_SEVERITY.HINT);
});

test('ACP Adapter: formatAcpDiagnostic produces standard LSP range and metadata', () => {
  const finding = {
    id: 'FIND-001',
    ruleId: 'CWE-89',
    title: 'SQL Injection via query concatenation',
    severity: 'HIGH',
    location: {
      uri: 'src/db.js',
      startLine: 42,
      endLine: 45,
      startColumn: 5,
      endColumn: 30
    },
    lineageId: 'lin-abc-123',
    securityProperty: 'injection-prevention',
    findingType: 'VULNERABILITY',
    proofKind: 'STATIC_TRACE',
    remediation: 'Use parameterized queries'
  };

  const diag = formatAcpDiagnostic(finding);

  assert.equal(diag.code, 'CWE-89');
  assert.equal(diag.source, 'Three-Lens');
  assert.equal(diag.severity, 1);
  assert.equal(diag.message, 'SQL Injection via query concatenation');
  assert.deepEqual(diag.range, {
    start: { line: 41, character: 4 },
    end: { line: 44, character: 29 }
  });
  assert.equal(diag.data.id, 'FIND-001');
  assert.equal(diag.data.lineageId, 'lin-abc-123');
  assert.equal(diag.data.remediation, 'Use parameterized queries');
});

test('ACP Adapter: serializeJsonRpcNotification single-line JSON with trailing LF', () => {
  const line = serializeJsonRpcNotification('test/method', { foo: 'bar' });
  assert.ok(line.endsWith('\n'), 'Must end with trailing LF');
  assert.ok(!line.slice(0, -1).includes('\n'), 'Must be a single line JSON');

  const obj = JSON.parse(line.trim());
  assert.equal(obj.jsonrpc, '2.0');
  assert.equal(obj.method, 'test/method');
  assert.deepEqual(obj.params, { foo: 'bar' });
});

test('ACP Adapter: formatPublishDiagnosticsNotification formats full notification', () => {
  const findings = [
    {
      id: 'F-1',
      ruleId: 'CWE-79',
      title: 'XSS flaw',
      severity: 'MEDIUM',
      location: { startLine: 10 }
    }
  ];

  const raw = formatPublishDiagnosticsNotification('file:///path/to/app.js', findings);
  const parsed = JSON.parse(raw.trim());

  assert.equal(parsed.jsonrpc, '2.0');
  assert.equal(parsed.method, 'textDocument/publishDiagnostics');
  assert.equal(parsed.params.uri, 'file:///path/to/app.js');
  assert.equal(parsed.params.diagnostics.length, 1);
  assert.equal(parsed.params.diagnostics[0].code, 'CWE-79');
  assert.equal(parsed.params.diagnostics[0].severity, 2);
});

test('ACP Adapter: parseJsonRpcMessage validation and error handling', () => {
  assert.equal(parseJsonRpcMessage(''), null);
  assert.equal(parseJsonRpcMessage('   '), null);

  const valid = '{"jsonrpc": "2.0", "method": "initialize", "params": {}}\n';
  const parsedValid = parseJsonRpcMessage(valid);
  assert.equal(parsedValid.jsonrpc, '2.0');
  assert.equal(parsedValid.method, 'initialize');

  const invalidVersion = '{"jsonrpc": "1.0", "method": "test"}';
  const parsedInvalid = parseJsonRpcMessage(invalidVersion);
  assert.equal(parsedInvalid.error, 'INVALID_JSONRPC_VERSION');

  const malformed = '{"jsonrpc": "2.0", incomplete...';
  const parsedMalformed = parseJsonRpcMessage(malformed);
  assert.equal(parsedMalformed.error, 'PARSE_ERROR');
});

test('ACP Adapter: createAcpDiagnosticEmitter stream writing', () => {
  const chunks = [];
  const mockStream = {
    write(chunk) {
      chunks.push(chunk);
    }
  };

  const emitter = createAcpDiagnosticEmitter(mockStream);
  emitter.emitDiagnostic('src/index.js', {
    id: 'F-1',
    ruleId: 'CWE-22',
    severity: 'CRITICAL',
    location: { startLine: 1 }
  });

  assert.equal(chunks.length, 1);
  const parsed = JSON.parse(chunks[0].trim());
  assert.equal(parsed.method, 'textDocument/publishDiagnostics');
  assert.equal(parsed.params.diagnostics[0].code, 'CWE-22');
  assert.equal(parsed.params.diagnostics[0].severity, 1);
});
