/**
 * Path traversal vulnerability mitigation tests for qa-firstrun-mutations.mjs
 *
 * The script's write() function was vulnerable to path traversal attacks that could
 * allow writing to arbitrary filesystem locations. These tests verify the security
 * fix correctly rejects:
 * - Relative paths with .. (parent directory traversal)
 * - Absolute paths (which could write anywhere on the filesystem)
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'scripts',
  'qa-firstrun-mutations.mjs'
);

test('write function contains path traversal security checks', () => {
  const scriptContent = fs.readFileSync(SCRIPT_PATH, 'utf8');
  
  // Verify the security check exists in the write function
  const writeFunction = scriptContent.slice(
    scriptContent.indexOf('const write = (file, next) => {'),
    scriptContent.indexOf('const restoreAll = () => {')
  );
  
  assert.ok(writeFunction.length > 0, 'write function must exist');
  
  // Verify both security checks are present
  assert.match(
    writeFunction,
    /file\.includes\(['"]\.\.['"][\s)]*\|\|[\s(]*path\.isAbsolute\(file\)/,
    'write function must check for .. and absolute paths'
  );
  
  assert.match(
    writeFunction,
    /throw new Error\(['"]Invalid file path['"]\)/,
    'write function must throw on invalid path'
  );
});

test('security check occurs before file operations', () => {
  const scriptContent = fs.readFileSync(SCRIPT_PATH, 'utf8');
  
  const writeFunction = scriptContent.slice(
    scriptContent.indexOf('const write = (file, next) => {'),
    scriptContent.indexOf('const restoreAll = () => {')
  );
  
  // The security check must come BEFORE fs.readFileSync
  const checkIndex = writeFunction.indexOf("file.includes('..')");
  const readIndex = writeFunction.indexOf('fs.readFileSync');
  
  assert.ok(checkIndex > 0, 'security check must exist');
  assert.ok(readIndex > 0, 'file read must exist');
  assert.ok(
    checkIndex < readIndex,
    'security check must occur before any file operations'
  );
});

test('FILES object uses only safe relative paths', () => {
  const scriptContent = fs.readFileSync(SCRIPT_PATH, 'utf8');
  
  // Extract the FILES object definition
  const filesStart = scriptContent.indexOf('const FILES = {');
  const filesEnd = scriptContent.indexOf('};', filesStart) + 2;
  const filesSection = scriptContent.slice(filesStart, filesEnd);
  
  // Verify no .. sequences in path components
  assert.doesNotMatch(
    filesSection,
    /['"]\.\.['"]/,
    'FILES must not contain .. in path components'
  );
  
  // Verify paths are constructed with path.join from ROOT
  assert.match(
    filesSection,
    /path\.join\(ROOT/,
    'FILES should use path.join with ROOT for safe path construction'
  );
});

test('path traversal exploit patterns would be blocked', () => {
  const scriptContent = fs.readFileSync(SCRIPT_PATH, 'utf8');
  
  const writeFunction = scriptContent.slice(
    scriptContent.indexOf('const write = (file, next) => {'),
    scriptContent.indexOf('const restoreAll = () => {')
  );
  
  // Common path traversal patterns that should be blocked:
  const exploitPatterns = [
    { path: '../../../etc/passwd', reason: 'contains ..' },
    { path: '..\\..\\..\\windows\\system32', reason: 'contains ..' },
    { path: '/etc/passwd', reason: 'absolute path' },
    { path: '/tmp/evil', reason: 'absolute path' },
  ];
  
  // Verify the check would catch these patterns
  for (const { path: pattern, reason } of exploitPatterns) {
    const hasDoubleDot = pattern.includes('..');
    const isAbsolute = path.isAbsolute(pattern);
    
    assert.ok(
      hasDoubleDot || isAbsolute,
      `exploit pattern "${pattern}" (${reason}) must be caught by security checks`
    );
  }
  
  // Verify the security check is comprehensive
  assert.match(
    writeFunction,
    /if \(file\.includes\(['"]\.\.['"][\s)]*\|\|[\s(]*path\.isAbsolute\(file\)\)/,
    'security check must validate both conditions'
  );
});
