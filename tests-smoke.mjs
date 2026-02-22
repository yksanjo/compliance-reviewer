import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ComplianceReviewer } from './dist/index.js';

test('ComplianceReviewer reviews a SOC2 document and persists report', async () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'compliance-reviewer-'));
  const docPath = join(tempDir, 'policy.txt');
  writeFileSync(docPath, 'security policy access control monitoring incident response encryption');

  const reviewer = new ComplianceReviewer({ dataDirectory: tempDir });
  await reviewer.initialize();

  const report = await reviewer.review(docPath, 'SOC2');

  assert.equal(report.framework, 'SOC2');
  assert.ok(report.summary.total > 0);
  assert.ok(existsSync(join(tempDir, 'report-' + report.id + '.json')));
});
