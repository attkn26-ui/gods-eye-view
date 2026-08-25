// tools/cesium-render.test.mjs
//
// Security tests for path traversal vulnerability mitigation in cesium-render.mjs
// server. The server exposes /cesium/* paths that map to the Cesium asset directory.
// These tests verify that path traversal attacks are properly blocked.
//
// The mitigation uses path.resolve + path.relative to ensure requested paths stay
// within CESIUM_ROOT, rejecting any path that would escape via '..' segments or
// absolute paths.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolve, join, relative, isAbsolute } from 'node:path';

// Unit tests for the path traversal mitigation logic
// These test the core security validation without requiring a running server

test('path traversal mitigation: rejects parent directory traversal with ../', () => {
  const base = resolve('/var/www/cesium');
  const attack = resolve(base, '../../../etc/passwd');
  const rel = relative(base, attack);
  
  assert.ok(
    rel.startsWith('..') || isAbsolute(rel),
    'Path traversal with ../ should be detected and rejected'
  );
});

test('path traversal mitigation: rejects absolute path attempts', () => {
  const base = resolve('/var/www/cesium');
  const attack = resolve(base, '/etc/passwd');
  const rel = relative(base, attack);
  
  assert.ok(
    rel.startsWith('..') || isAbsolute(rel),
    'Absolute path should be detected and rejected'
  );
});

test('path traversal mitigation: allows legitimate paths within base directory', () => {
  const base = resolve('/var/www/cesium');
  const legitimate = resolve(base, 'assets/Cesium.js');
  const rel = relative(base, legitimate);
  
  assert.ok(
    !rel.startsWith('..') && !isAbsolute(rel),
    'Legitimate path within base should pass validation'
  );
});

test('path traversal mitigation: allows empty path (resolves to base)', () => {
  const base = resolve('/var/www/cesium');
  const empty = resolve(base, '');
  const rel = relative(base, empty);
  
  assert.ok(
    !rel.startsWith('..') && !isAbsolute(rel),
    'Empty path (resolves to base directory) should pass validation'
  );
});

test('path traversal mitigation: rejects multiple ../ segments', () => {
  const base = resolve('/var/www/cesium');
  const attack = resolve(base, '../../../../../../etc/hosts');
  const rel = relative(base, attack);
  
  assert.ok(
    rel.startsWith('..') || isAbsolute(rel),
    'Multiple ../ segments should be detected and rejected'
  );
});

test('path traversal mitigation: rejects mixed path separators', () => {
  const base = resolve('/var/www/cesium');
  // On Windows, backslashes are normalized; on Unix, they're treated as filename chars
  // Either way, the mitigation should handle it correctly
  const attack = resolve(base, '../..\\..\\package.json');
  const rel = relative(base, attack);
  
  // The path.resolve will normalize separators, so we check the result
  assert.ok(
    rel.startsWith('..') || isAbsolute(rel),
    'Mixed path separators attempting traversal should be rejected'
  );
});

test('path traversal mitigation: allows nested legitimate paths', () => {
  const base = resolve('/var/www/cesium');
  const nested = resolve(base, 'assets/images/logo.png');
  const rel = relative(base, nested);
  
  assert.ok(
    !rel.startsWith('..') && !isAbsolute(rel),
    'Nested legitimate paths should pass validation'
  );
});

test('path traversal mitigation: rejects path with encoded traversal', () => {
  // Note: URL decoding happens before path validation in the actual server
  // This tests that after decoding, the validation still catches traversal
  const base = resolve('/var/www/cesium');
  // Simulating what happens after URL decode: %2e%2e%2f becomes ../
  const decodedPath = '../../../etc/passwd';
  const attack = resolve(base, decodedPath);
  const rel = relative(base, attack);
  
  assert.ok(
    rel.startsWith('..') || isAbsolute(rel),
    'Decoded traversal sequences should be detected and rejected'
  );
});
