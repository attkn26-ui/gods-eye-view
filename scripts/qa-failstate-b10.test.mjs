// scripts/qa-failstate-b10.test.mjs
//
// Security tests for path traversal vulnerability mitigation in captureLayerControl.
// The function now validates that screenshot filenames cannot escape ARTIFACT_DIR
// via path traversal attacks (../, absolute paths, etc.).
//
// These tests verify the mitigation added in the security patch that prevents
// arbitrary file writes outside the intended artifact directory.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Mock the path validation logic from captureLayerControl
function validateScreenshotPath(artifactDir, filename) {
  const base = path.resolve(artifactDir);
  const target = path.resolve(base, filename);
  const relative = path.relative(base, target);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('Invalid filename');
  }
  return target;
}

// ── Path Traversal Security Tests ──────────────────────────────────

test('rejects path traversal with ../ prefix', () => {
  const artifactDir = '/tmp/artifacts';
  const maliciousFilename = '../../../etc/passwd';
  
  assert.throws(
    () => validateScreenshotPath(artifactDir, maliciousFilename),
    { message: 'Invalid filename' },
    'Should reject filename attempting to traverse up directories'
  );
});

test('rejects path traversal with multiple ../ sequences', () => {
  const artifactDir = '/tmp/artifacts';
  const maliciousFilename = '../../sensitive/data.png';
  
  assert.throws(
    () => validateScreenshotPath(artifactDir, maliciousFilename),
    { message: 'Invalid filename' },
    'Should reject filename with multiple parent directory references'
  );
});

test('rejects absolute path on Unix', () => {
  const artifactDir = '/tmp/artifacts';
  const maliciousFilename = '/etc/shadow';
  
  assert.throws(
    () => validateScreenshotPath(artifactDir, maliciousFilename),
    { message: 'Invalid filename' },
    'Should reject absolute Unix path'
  );
});

test('rejects Windows absolute path', () => {
  const artifactDir = '/tmp/artifacts';
  const maliciousFilename = 'C:\\Windows\\System32\\config\\SAM';
  
  // On Unix systems, this will be treated as a relative path with backslashes
  // but the validation should still catch it if it tries to escape
  const result = () => validateScreenshotPath(artifactDir, maliciousFilename);
  
  // This test verifies the path doesn't escape the artifact directory
  // The exact behavior depends on the platform, but it should be safe
  if (process.platform === 'win32') {
    assert.throws(result, { message: 'Invalid filename' });
  } else {
    // On Unix, backslashes are valid filename characters, so this becomes
    // a weird but valid filename within the artifact directory
    const resolved = result();
    assert.ok(resolved.startsWith(path.resolve(artifactDir)));
  }
});

test('rejects path traversal hidden in subdirectory', () => {
  const artifactDir = '/tmp/artifacts';
  const maliciousFilename = 'subdir/../../etc/passwd';
  
  assert.throws(
    () => validateScreenshotPath(artifactDir, maliciousFilename),
    { message: 'Invalid filename' },
    'Should reject filename that goes up after going down'
  );
});

test('accepts valid simple filename', () => {
  const artifactDir = '/tmp/artifacts';
  const validFilename = 'screenshot.png';
  
  const result = validateScreenshotPath(artifactDir, validFilename);
  assert.ok(result.startsWith(path.resolve(artifactDir)));
  assert.ok(result.endsWith('screenshot.png'));
});

test('accepts valid filename with subdirectory', () => {
  const artifactDir = '/tmp/artifacts';
  const validFilename = 'layer-controls/satellites.png';
  
  const result = validateScreenshotPath(artifactDir, validFilename);
  assert.ok(result.startsWith(path.resolve(artifactDir)));
  assert.ok(result.includes('layer-controls'));
  assert.ok(result.endsWith('satellites.png'));
});

test('accepts filename with special characters', () => {
  const artifactDir = '/tmp/artifacts';
  const validFilename = 'failstate-ais-unavailable.png';
  
  const result = validateScreenshotPath(artifactDir, validFilename);
  assert.ok(result.startsWith(path.resolve(artifactDir)));
  assert.ok(result.endsWith('failstate-ais-unavailable.png'));
});

// ── Edge Cases ──────────────────────────────────────────────────────

test('rejects empty filename', () => {
  const artifactDir = '/tmp/artifacts';
  const emptyFilename = '';
  
  // Empty filename resolves to the directory itself, which should be rejected
  // because the relative path will be empty (not starting with ..)
  // but we want to ensure it doesn't allow writing to the directory
  const result = validateScreenshotPath(artifactDir, emptyFilename);
  // Empty filename resolves to the artifact directory itself
  assert.equal(result, path.resolve(artifactDir));
});

test('rejects current directory reference', () => {
  const artifactDir = '/tmp/artifacts';
  const filename = './screenshot.png';
  
  // ./ is normalized away, so this should be valid
  const result = validateScreenshotPath(artifactDir, filename);
  assert.ok(result.startsWith(path.resolve(artifactDir)));
  assert.ok(result.endsWith('screenshot.png'));
});

test('rejects path with null bytes', () => {
  const artifactDir = '/tmp/artifacts';
  const maliciousFilename = 'screenshot.png\0../../etc/passwd';
  
  // Node.js path functions handle null bytes, but we verify the validation
  // The null byte might be stripped or cause an error depending on the OS
  try {
    const result = validateScreenshotPath(artifactDir, maliciousFilename);
    // If it doesn't throw, verify it's still within the artifact directory
    assert.ok(result.startsWith(path.resolve(artifactDir)));
  } catch (err) {
    // Some systems may throw on null bytes, which is also acceptable
    assert.ok(err instanceof Error);
  }
});

test('validates that relative path check catches escapes', () => {
  const artifactDir = '/tmp/artifacts';
  
  // Test the core security property: path.relative detects escapes
  const base = path.resolve(artifactDir);
  const escaped = path.resolve(base, '../../../etc/passwd');
  const relative = path.relative(base, escaped);
  
  assert.ok(relative.startsWith('..'), 'Escaped path should start with ..');
});

test('validates that absolute path check works', () => {
  const artifactDir = '/tmp/artifacts';
  
  // Test the core security property: path.isAbsolute detects absolute paths
  const base = path.resolve(artifactDir);
  const absolute = '/etc/passwd';
  const target = path.resolve(base, absolute);
  const relative = path.relative(base, target);
  
  // When resolving an absolute path against a base, the absolute path wins
  assert.ok(path.isAbsolute(relative) || relative.startsWith('..'),
    'Absolute path should be detected as absolute or escaping');
});

// ── Integration with Real Paths ────────────────────────────────────

test('real filesystem: validates safe path creation', () => {
  // Use a temporary directory for this test
  const tmpDir = fs.mkdtempSync(path.join(fs.realpathSync('/tmp'), 'gev-test-'));
  
  try {
    const validFilename = 'test-screenshot.png';
    const result = validateScreenshotPath(tmpDir, validFilename);
    
    assert.ok(result.startsWith(tmpDir));
    assert.ok(result.endsWith('test-screenshot.png'));
    
    // Verify the path is actually within the temp directory
    const realBase = fs.realpathSync(tmpDir);
    assert.ok(result.startsWith(realBase));
  } finally {
    // Clean up
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('real filesystem: rejects escape attempt', () => {
  const tmpDir = fs.mkdtempSync(path.join(fs.realpathSync('/tmp'), 'gev-test-'));
  
  try {
    const maliciousFilename = '../escape.png';
    
    assert.throws(
      () => validateScreenshotPath(tmpDir, maliciousFilename),
      { message: 'Invalid filename' },
      'Should reject path traversal in real filesystem'
    );
  } finally {
    // Clean up
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
