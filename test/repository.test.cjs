'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');

test('Action metadata delegates untrusted inputs through environment variables', () => {
  const action = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8');
  assert.match(action, /using: composite/);
  assert.match(action, /PTK_INPUT_TARGET: \$\{\{ inputs\.target \}\}/);
  assert.match(action, /run: node "\$PTK_ACTION_PATH\/scripts\/run\.cjs"/);
  assert.doesNotMatch(action, /run:.*inputs\./);
  assert.doesNotMatch(action, /pentestkit@latest/);
});

test('package metadata is AGPL-only and dependency-free', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.equal(manifest.license, 'AGPL-3.0-only');
  assert.equal(manifest.private, true);
  assert.equal(manifest.dependencies, undefined);
  assert.equal(manifest.devDependencies, undefined);
  assert.equal(manifest.repository.url, 'git+https://github.com/ptklabs/ptk-action.git');
});

test('the Action does not vendor PTK engines, extensions, or providers', () => {
  for (const forbidden of ['src', 'engines', 'extensions', 'providers', 'browser']) {
    assert.equal(fs.existsSync(path.join(ROOT, forbidden)), false, `${forbidden} must not be vendored`);
  }
});

