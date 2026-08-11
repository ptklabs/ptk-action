#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const ALLOWED_TOP_LEVEL = new Set([
  '.git',
  '.github',
  '.gitignore',
  'LICENSE.txt',
  'README.md',
  'SECURITY.md',
  'action.yml',
  'examples',
  'package-lock.json',
  'package.json',
  'scripts',
  'test'
]);
const GENERATED_OR_SECRET_PATH = /(^|\/)(?:\.env(?:\..*)?|node_modules|\.ptk|coverage)(?:\/|$)|\.(?:crx|xpi|tgz|zip|pem|key|p12|pfx)$/i;
const SECRET_TEXT = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9_]{20,}\b|\bnpm_[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b/;

function fail(message) {
  process.stderr.write(`Repository validation failed: ${message}\n`);
  process.exitCode = 1;
}

function walk(directory, relative = '') {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (!relative && entry.name === '.git') continue;
    const childRelative = relative ? `${relative}/${entry.name}` : entry.name;
    const child = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      fail(`symbolic links are not allowed: ${childRelative}`);
      continue;
    }
    if (entry.isDirectory()) files.push(...walk(child, childRelative));
    else if (entry.isFile()) files.push(childRelative);
  }
  return files;
}

for (const entry of fs.readdirSync(ROOT)) {
  if (!ALLOWED_TOP_LEVEL.has(entry)) fail(`unexpected top-level entry: ${entry}`);
}

const files = walk(ROOT);
for (const file of files) {
  if (GENERATED_OR_SECRET_PATH.test(file)) fail(`generated or sensitive path must not be committed: ${file}`);
  const absolute = path.join(ROOT, file);
  const content = fs.readFileSync(absolute);
  if (content.includes(0)) fail(`NUL byte found in source file: ${file}`);
  if (content.length <= 2_000_000 && SECRET_TEXT.test(content.toString('utf8'))) {
    fail(`possible secret material found in: ${file}`);
  }
}

const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
if (manifest.license !== 'AGPL-3.0-only') fail('package.json must declare AGPL-3.0-only');
if (manifest.private !== true) fail('the Action helper package must remain private');
if (manifest.dependencies || manifest.devDependencies || manifest.optionalDependencies) {
  fail('the Action repository must have zero npm runtime and development dependencies');
}

const license = fs.readFileSync(path.join(ROOT, 'LICENSE.txt'), 'utf8');
if (!license.includes('GNU AFFERO GENERAL PUBLIC LICENSE') || !license.includes('Version 3, 19 November 2007')) {
  fail('LICENSE.txt must contain the complete GNU AGPL version 3 license');
}

const textFiles = files.filter(file =>
  /\.(?:json|md|ya?ml|txt)$/.test(file) &&
  !file.startsWith('scripts/') &&
  !file.startsWith('test/')
);
const combined = textFiles.map(file => fs.readFileSync(path.join(ROOT, file), 'utf8')).join('\n');
for (const stale of ['ptklabs/owasp-ptk-action', 'pentestkit@latest', 'MIT License']) {
  if (combined.includes(stale)) fail(`stale or unsafe public reference found: ${stale}`);
}

for (const file of files.filter(file => /\.(?:yml|yaml)$/.test(file))) {
  const content = fs.readFileSync(path.join(ROOT, file), 'utf8');
  for (const match of content.matchAll(/^\s*-?\s*uses:\s*([^\s#]+).*$/gm)) {
    const reference = match[1];
    if (reference.startsWith('./')) continue;
    if (reference === 'ptklabs/ptk-action@v1') continue;
    if (!/@[0-9a-f]{40}$/.test(reference)) fail(`${file} contains an external Action that is not pinned to a full commit SHA: ${reference}`);
  }
}

const action = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8');
for (const required of [
  'using: composite',
  'target:',
  'engines:',
  'fail-on:',
  'sarif-file:',
  'output-dir:',
  'pentestkit-version:',
  'pentestkit-package:',
  'install-browsers:',
  'extra-args:'
]) {
  if (!action.includes(required)) fail(`action.yml is missing required metadata: ${required}`);
}
if (/\b(?:eval|curl|wget)\b/.test(action)) fail('action.yml must delegate to the checked-in Node launcher without dynamic shell evaluation or downloads');

if (!process.exitCode) process.stdout.write(`Repository validation passed (${files.length} files).\n`);
