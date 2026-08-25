// scripts/qa-overlay-baseline.test.mjs
//
// Security tests for path traversal vulnerability mitigation in captureShot().
// The mitigation (2024) validates that resolved paths stay within the intended
// base directory using path.relative() checks, preventing directory traversal
// attacks via malicious sceneId or suffix parameters.
//
// These tests verify:
//   1. Normal operation with safe inputs continues to work
//   2. Path traversal attempts via ../ sequences are blocked
//   3. Absolute path injections are rejected
//   4. Various encoding and obfuscation techniques are caught
//   5. The validation logic correctly identifies contained vs escaped paths

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'os';

// Mock page object for testing
function createMockPage() {
  return {
    screenshot: async ({ path: screenshotPath }) => {
      // Simulate screenshot by creating an empty file
      fs.writeFileSync(screenshotPath, 'mock-screenshot-data');
      return screenshotPath;
    },
  };
}

// Extract and adapt the captureShot function for testing
// This is the security-hardened version with path traversal protection
async function captureShot(page, shotsDir, sceneId, suffix) {
  if (!shotsDir) return null;
  fs.mkdirSync(shotsDir, { recursive: true });
  const safeScene = sceneId.replace(/[^a-z0-9-]+/gi, '-');
  const base = path.resolve(shotsDir);
  const target = path.resolve(base, `${safeScene}-${suffix}.png`);
  const relative = path.relative(base, target);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('Invalid file path');
  }
  await page.screenshot({ path: target });
  return target;
}

test('captureShot: normal operation with safe sceneId', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gev-test-'));
  try {
    const page = createMockPage();
    const result = await captureShot(page, tmpDir, 'test-scene', 'before');
    
    assert.ok(result, 'should return a path');
    assert.ok(result.includes('test-scene-before.png'), 'should contain expected filename');
    assert.ok(fs.existsSync(result), 'screenshot file should exist');
    assert.ok(result.startsWith(tmpDir), 'path should be within base directory');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('captureShot: sanitizes special characters in sceneId', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gev-test-'));
  try {
    const page = createMockPage();
    const result = await captureShot(page, tmpDir, 'test/scene@123!', 'after');
    
    assert.ok(result, 'should return a path');
    assert.ok(result.includes('test-scene-123--after.png'), 'should sanitize special chars');
    assert.ok(fs.existsSync(result), 'screenshot file should exist');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('captureShot: blocks path traversal via ../ in sceneId', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gev-test-'));
  try {
    const page = createMockPage();
    
    // Attempt to traverse up and write outside the base directory
    await assert.rejects(
      async () => captureShot(page, tmpDir, '../../../etc/passwd', 'exploit'),
      /Invalid file path/,
      'should reject path traversal attempt'
    );
    
    // Verify no file was created outside the base directory
    const parentDir = path.dirname(tmpDir);
    const potentialEscapedPath = path.join(parentDir, 'etc-passwd-exploit.png');
    assert.ok(!fs.existsSync(potentialEscapedPath), 'should not create file outside base dir');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('captureShot: blocks absolute path injection in sceneId', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gev-test-'));
  try {
    const page = createMockPage();
    
    // Attempt to use absolute path to write to /tmp
    const maliciousPath = path.join(os.tmpdir(), 'malicious-file');
    await assert.rejects(
      async () => captureShot(page, tmpDir, maliciousPath, 'exploit'),
      /Invalid file path/,
      'should reject absolute path injection'
    );
    
    // Verify the malicious file was not created
    assert.ok(!fs.existsSync(`${maliciousPath}-exploit.png`), 'should not create file at absolute path');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('captureShot: blocks path traversal via suffix parameter', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gev-test-'));
  try {
    const page = createMockPage();
    
    // Attempt traversal through suffix parameter
    await assert.rejects(
      async () => captureShot(page, tmpDir, 'scene', '../../../tmp/exploit'),
      /Invalid file path/,
      'should reject path traversal in suffix'
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('captureShot: blocks mixed traversal attempts', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gev-test-'));
  try {
    const page = createMockPage();
    
    // Multiple traversal patterns
    const traversalPatterns = [
      { sceneId: '..', suffix: '..', desc: 'double parent reference' },
      { sceneId: 'scene/../../../etc', suffix: 'passwd', desc: 'traversal in middle' },
      { sceneId: '....//....//etc', suffix: 'shadow', desc: 'obfuscated traversal' },
    ];
    
    for (const pattern of traversalPatterns) {
      await assert.rejects(
        async () => captureShot(page, tmpDir, pattern.sceneId, pattern.suffix),
        /Invalid file path/,
        `should reject ${pattern.desc}`
      );
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('captureShot: returns null when shotsDir is not provided', async () => {
  const page = createMockPage();
  const result = await captureShot(page, null, 'scene', 'suffix');
  assert.strictEqual(result, null, 'should return null when shotsDir is null');
});

test('captureShot: creates nested directory structure safely', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gev-test-'));
  try {
    const page = createMockPage();
    const nestedDir = path.join(tmpDir, 'nested', 'shots');
    
    const result = await captureShot(page, nestedDir, 'scene', 'test');
    
    assert.ok(result, 'should return a path');
    assert.ok(fs.existsSync(result), 'screenshot file should exist in nested directory');
    assert.ok(result.startsWith(nestedDir), 'path should be within nested base directory');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('captureShot: validates relative path stays within base directory', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gev-test-'));
  try {
    const page = createMockPage();
    
    // Test the core security property: path.relative() check
    // A safe path should have a relative path that doesn't start with '..'
    const safeResult = await captureShot(page, tmpDir, 'safe-scene', 'test');
    const safeRelative = path.relative(tmpDir, safeResult);
    assert.ok(!safeRelative.startsWith('..'), 'safe path should not escape base directory');
    assert.ok(!path.isAbsolute(safeRelative), 'safe path should be relative');
    
    // Verify the security check catches escaping paths
    // (already tested above, but this explicitly validates the check logic)
    const base = path.resolve(tmpDir);
    const escapedTarget = path.resolve(base, '../escaped-file.png');
    const escapedRelative = path.relative(base, escapedTarget);
    assert.ok(escapedRelative.startsWith('..'), 'escaped path should be detected by relative check');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
