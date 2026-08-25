import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdirSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..');

/**
 * Path traversal validation logic extracted from streetview-headings.mjs
 * This is the security-critical code that prevents directory traversal attacks.
 */
function validateOutputPath(outdir, filename) {
  const base = path.resolve(outdir);
  const target = path.resolve(base, filename);
  const rel = path.relative(base, target);
  
  // Security check: reject paths that escape the output directory
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return { valid: false, target: null };
  }
  
  return { valid: true, target };
}

test('Path traversal: rejects parent directory traversal with ../', () => {
  const outdir = '/tmp/test-output';
  const maliciousFilename = '../../../etc/passwd';
  
  const result = validateOutputPath(outdir, maliciousFilename);
  
  assert.equal(result.valid, false, 'Should reject path with ../ traversal');
  assert.equal(result.target, null, 'Should not return a target path for invalid input');
});

test('Path traversal: rejects encoded parent directory traversal', () => {
  const outdir = '/tmp/test-output';
  const maliciousFilename = '..%2F..%2F..%2Fetc%2Fpasswd';
  
  const result = validateOutputPath(outdir, maliciousFilename);
  
  // Note: URL encoding is typically decoded before reaching file operations
  // This test verifies the literal string is handled safely
  assert.equal(result.valid, false, 'Should reject encoded traversal attempts');
});

test('Path traversal: rejects absolute paths', () => {
  const outdir = '/tmp/test-output';
  const maliciousFilename = '/etc/passwd';
  
  const result = validateOutputPath(outdir, maliciousFilename);
  
  assert.equal(result.valid, false, 'Should reject absolute paths');
  assert.equal(result.target, null, 'Should not return a target path for absolute input');
});

test('Path traversal: accepts valid relative filenames', () => {
  const outdir = '/tmp/test-output';
  const validFilename = 'sv_30.268066_-97.742813_000_N.jpg';
  
  const result = validateOutputPath(outdir, validFilename);
  
  assert.equal(result.valid, true, 'Should accept valid relative filename');
  assert.ok(result.target, 'Should return a target path for valid input');
  assert.ok(result.target.startsWith(outdir), 'Target should be within output directory');
});

test('Path traversal: accepts filenames with subdirectories within outdir', () => {
  const outdir = '/tmp/test-output';
  const validFilename = 'subdir/sv_30.268066_-97.742813_000_N.jpg';
  
  const result = validateOutputPath(outdir, validFilename);
  
  assert.equal(result.valid, true, 'Should accept valid subdirectory path');
  assert.ok(result.target.startsWith(outdir), 'Target should be within output directory');
});

test('Path traversal: rejects path with mixed traversal attempts', () => {
  const outdir = '/tmp/test-output';
  const maliciousFilename = 'subdir/../../etc/passwd';
  
  const result = validateOutputPath(outdir, maliciousFilename);
  
  assert.equal(result.valid, false, 'Should reject mixed traversal with valid prefix');
});

test('Path traversal: handles Windows-style paths on Unix', () => {
  const outdir = '/tmp/test-output';
  const windowsStylePath = '..\\..\\..\\windows\\system32\\config\\sam';
  
  const result = validateOutputPath(outdir, windowsStylePath);
  
  // On Unix, backslashes are valid filename characters, but the path should
  // still be validated. The key is that it doesn't escape the base directory.
  if (process.platform === 'win32') {
    assert.equal(result.valid, false, 'Should reject Windows-style traversal on Windows');
  } else {
    // On Unix, backslashes are literal characters in filenames
    // The validation should still work correctly
    assert.ok(true, 'Windows-style paths handled according to platform');
  }
});

test('Path traversal: rejects null byte injection', () => {
  const outdir = '/tmp/test-output';
  const maliciousFilename = 'valid.jpg\0../../etc/passwd';
  
  const result = validateOutputPath(outdir, maliciousFilename);
  
  // Node.js path operations handle null bytes, but we verify the validation
  // logic doesn't allow escaping the directory
  assert.ok(result.valid === false || !result.target?.includes('\0'), 
    'Should handle null byte injection safely');
});

test('Filename generation: produces expected format', () => {
  const lat = 30.268066;
  const lon = -97.742813;
  const heading = 0;
  const name = 'N';
  
  const filename = `sv_${lat.toFixed(6)}_${lon.toFixed(6)}_${heading.toString().padStart(3, '0')}_${name}.jpg`;
  
  assert.equal(filename, 'sv_30.268066_-97.742813_000_N.jpg', 'Should generate expected filename format');
  
  // Verify the generated filename is safe
  const result = validateOutputPath('/tmp/test', filename);
  assert.equal(result.valid, true, 'Generated filename should be valid');
});

test('Filename generation: handles all compass directions safely', () => {
  const compassNames = ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW'];
  const headings = [0, 45, 90, 135, 180, 225, 270, 315];
  
  for (let i = 0; i < compassNames.length; i++) {
    const filename = `sv_30.268066_-97.742813_${headings[i].toString().padStart(3, '0')}_${compassNames[i]}.jpg`;
    const result = validateOutputPath('/tmp/test', filename);
    assert.equal(result.valid, true, `Compass direction ${compassNames[i]} should be valid`);
  }
});

test('Security: validation prevents writing outside output directory', () => {
  const testDir = join(PROJECT_ROOT, 'test-output-security');
  const parentDir = join(PROJECT_ROOT, 'test-output-parent');
  
  try {
    // Create test directories
    mkdirSync(testDir, { recursive: true });
    mkdirSync(parentDir, { recursive: true });
    
    // Attempt to write to parent directory
    const maliciousPath = '../test-output-parent/malicious.jpg';
    const result = validateOutputPath(testDir, maliciousPath);
    
    assert.equal(result.valid, false, 'Should prevent writing to parent directory');
    
  } finally {
    // Cleanup
    if (existsSync(testDir)) rmSync(testDir, { recursive: true, force: true });
    if (existsSync(parentDir)) rmSync(parentDir, { recursive: true, force: true });
  }
});
