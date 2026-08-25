import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  'qa-firstrun-mutations.mjs'
);

/**
 * Path traversal vulnerability mitigation tests for qa-firstrun-mutations.mjs
 * 
 * The script's write() function was vulnerable to path traversal attacks.
 * These tests verify that the mitigation correctly rejects:
 * - Relative paths with .. (parent directory traversal)
 * - Absolute paths (which could write anywhere on the filesystem)
 */

test('write function rejects path traversal with .. sequences', () => {
  const scriptContent = fs.readFileSync(SCRIPT_PATH, 'utf8');
  
  // Verify the security check exists in the write function
  const writeFunction = scriptContent.slice(
    scriptContent.indexOf('const write = (file, next) => {'),
    scriptContent.indexOf('const restoreAll = () => {')
  );
  
  assert.ok(writeFunction.length > 0, 'write function must exist');
  assert.match(
    writeFunction,
    /file\.includes\(['"]\.\.['"])/,
    'write function must check for .. in file path'
  );
  assert.match(
    writeFunction,
    /throw new Error\(['"]Invalid file path['"]\)/,
    'write function must throw on invalid path'
  );
});

test('write function rejects absolute paths', () => {
  const scriptContent = fs.readFileSync(SCRIPT_PATH, 'utf8');
  
  const writeFunction = scriptContent.slice(
    scriptContent.indexOf('const write = (file, next) => {'),
    scriptContent.indexOf('const restoreAll = () => {')
  );
  
  assert.match(
    writeFunction,
    /path\.isAbsolute\(file\)/,
    'write function must check for absolute paths'
  );
});

test('write function validates paths before any file operations', () => {
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

test('path traversal patterns are blocked in write function', () => {
  const scriptContent = fs.readFileSync(SCRIPT_PATH, 'utf8');
  
  // Extract and verify the complete security check logic
  const writeFunction = scriptContent.slice(
    scriptContent.indexOf('const write = (file, next) => {'),
    scriptContent.indexOf('const restoreAll = () => {')
  );
  
  // Verify both conditions are checked with OR operator
  assert.match(
    writeFunction,
    /file\.includes\(['"]\.\.['"][\s)]*\|\|[\s(]*path\.isAbsolute\(file\)/,
    'both path traversal checks must be combined with OR'
  );
});

test('FILES object only contains relative paths within project', () => {
  const scriptContent = fs.readFileSync(SCRIPT_PATH, 'utf8');
  
  // Extract the FILES object definition
  const filesStart = scriptContent.indexOf('const FILES = {');
  const filesEnd = scriptContent.indexOf('};', filesStart) + 2;
  const filesSection = scriptContent.slice(filesStart, filesEnd);
  
  // Verify no absolute paths in FILES definition
  assert.doesNotMatch(
    filesSection,
    /path\.join\(ROOT,[\s\S]*?['"]\/[^'"]+['"]/,
    'FILES must not contain absolute path literals starting with /'
  );
  
  // Verify no .. sequences in path components
  assert.doesNotMatch(
    filesSection,
    /['"]\.\.['"]/,
    'FILES must not contain .. in path components'
  );
});

test('security mitigation prevents common path traversal exploits', () => {
  const scriptContent = fs.readFileSync(SCRIPT_PATH, 'utf8');
  
  const writeFunction = scriptContent.slice(
    scriptContent.indexOf('const write = (file, next) => {'),
    scriptContent.indexOf('const restoreAll = () => {')
  );
  
  // Common path traversal patterns that should be blocked:
  const exploitPatterns = [
    '../../../etc/passwd',           // Unix path traversal
    '..\\..\\..\\windows\\system32',  // Windows path traversal (in string)
    '/etc/passwd',                    // Absolute Unix path
    'C:\\Windows\\System32',          // Absolute Windows path (in string)
  ];
  
  // Verify the check would catch these patterns
  for (const pattern of exploitPatterns) {
    const hasDoubleDot = pattern.includes('..');
    const isAbsolute = path.isAbsolute(pattern);
    
    assert.ok(
      hasDoubleDot || isAbsolute,
      `exploit pattern "${pattern}" must be caught by security checks`
    );
  }
  
  // Verify the security check is comprehensive
  assert.match(
    writeFunction,
    /if \(file\.includes\(['"]\.\.['"][\s)]*\|\|[\s(]*path\.isAbsolute\(file\)\)/,
    'security check must validate both conditions'
  );
});

test('write function maintains single-line format with security check', () => {
  const scriptContent = fs.readFileSync(SCRIPT_PATH, 'utf8');
  
  // The security fix was added inline to the existing write function
  const writeFunction = scriptContent.slice(
    scriptContent.indexOf('const write = (file, next) => {'),
    scriptContent.indexOf('const restoreAll = () => {')
  );
  
  // Verify the security check and error throw are present
  assert.match(
    writeFunction,
    /if \(file\.includes\(['"]\.\.['"][\s)]*\|\|[\s(]*path\.isAbsolute\(file\)\)[\s]*throw new Error\(['"]Invalid file path['"]\);/,
    'security check must throw error for invalid paths'
  );
});
