#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { fileURLToPath } = require('url');

const SUPPORTED_ENGINES = Object.freeze(['DAST', 'IAST', 'SAST', 'SCA']);
const SUPPORTED_THRESHOLDS = Object.freeze(['critical', 'high', 'medium', 'low', 'info', 'none']);
const EXACT_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const OFFICIAL_NPM_REGISTRY = 'https://registry.npmjs.org/';
const GITHUB_RUNTIME_LOCATIONS_FILE = 'github-code-scanning-runtime-findings.txt';
const DIRECT_CREDENTIAL_FLAGS = new Set(['--username', '--password']);
const EXTRA_ARG_SPECS = Object.freeze({
  '--scenario': { type: 'file' },
  '--route-hints-file': { type: 'file' },
  '--scenario-continue-on-failure': { type: 'boolean' },
  '--username-env': { type: 'environment' },
  '--password-env': { type: 'environment' },
  '--include-secrets': { type: 'boolean' },
  '--persona': { type: 'text', maxLength: 256 },
  '--max-routes': { type: 'integer', minimum: 1, group: 'max-routes' },
  '--crawl-pages': { type: 'integer', minimum: 1, group: 'max-routes' },
  '--crawl-depth': { type: 'integer', minimum: 0 },
  '--max-route-ms': { type: 'integer', minimum: 1 },
  '--max-action-ms': { type: 'integer', minimum: 1 },
  '--max-actions-per-route': { type: 'integer', minimum: 0 },
  '--max-forms-per-route': { type: 'integer', minimum: 0 },
  '--max-no-progress-actions': { type: 'integer', minimum: 0 },
  '--max-observation-ms': { type: 'integer', minimum: 1 },
  '--browser-launch-timeout-ms': { type: 'integer', minimum: 1 },
  '--agent-mode': { type: 'enum', values: ['off', 'mock', 'manager', 'provider', 'browser'] },
  '--agent-provider': { type: 'enum', values: ['opencode', 'codex'] },
  '--agent-model': { type: 'text', maxLength: 512 },
  '--max-agent-turns': { type: 'integer', minimum: 0 },
  '--max-provider-ms': { type: 'integer', minimum: 1 },
  '--max-steps-per-turn': { type: 'integer', minimum: 1 },
  '--require-agent-success': { type: 'boolean' }
});

function fail(message) {
  throw new Error(message);
}

function assertText(value, label, { multiline = false, allowEmpty = false } = {}) {
  const text = String(value ?? '');
  if (!allowEmpty && text.trim() === '') fail(`${label} must not be empty`);
  if (text.includes('\0')) fail(`${label} must not contain NUL bytes`);
  if (!multiline && /[\r\n]/.test(text)) fail(`${label} must be a single line`);
  return text;
}

function parseBoolean(value, label) {
  const normalized = assertText(value, label).trim().toLowerCase();
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  fail(`${label} must be true or false`);
}

function parseExactSemver(value) {
  const normalized = assertText(value, 'pentestkit-version').trim();
  if (!EXACT_SEMVER.test(normalized)) {
    fail('pentestkit-version must be an exact semantic version such as 9.9.8 or 9.9.8-rc.1; tags and ranges are not allowed');
  }
  return normalized;
}

function parseEngines(value) {
  const requested = assertText(value, 'engines')
    .split(',')
    .map(item => item.trim().toUpperCase())
    .filter(Boolean);
  if (requested.length === 0) fail('engines must contain at least one engine');
  const result = [];
  for (const engine of requested) {
    if (!SUPPORTED_ENGINES.includes(engine)) {
      fail(`Unsupported engine "${engine}"; use DAST, IAST, SAST, or SCA`);
    }
    if (!result.includes(engine)) result.push(engine);
  }
  return result;
}

function parseThreshold(value) {
  const normalized = assertText(value, 'fail-on').trim().toLowerCase();
  if (!SUPPORTED_THRESHOLDS.includes(normalized)) {
    fail('fail-on must be one of: critical, high, medium, low, info, none');
  }
  return normalized;
}

function validateTarget(value) {
  const raw = assertText(value, 'target').trim();
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    fail('target must be a valid absolute HTTP or HTTPS URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    fail('target must use http:// or https://');
  }
  if (parsed.username || parsed.password) {
    fail('target must not contain embedded credentials; use --username-env and --password-env through extra-args');
  }
  return parsed.href;
}

function normalizeExtraInteger(value, name, minimum) {
  if (!/^(?:0|[1-9]\d*)$/.test(value)) fail(`${name} must be an integer greater than or equal to ${minimum}`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    fail(`${name} must be a safe integer greater than or equal to ${minimum}`);
  }
  return String(parsed);
}

function resolveExtraArgFile(workspace, workingDirectory, value, name) {
  if (!workspace || !workingDirectory) fail(`${name} requires workspace path validation`);
  const lexical = path.resolve(workingDirectory, value);
  assertInside(workspace, lexical, name);
  let resolved;
  try {
    resolved = fs.realpathSync(lexical);
  } catch {
    fail(`${name} file does not exist: ${value}`);
  }
  assertInside(workspace, resolved, name);
  if (!fs.statSync(resolved).isFile()) fail(`${name} must reference a regular file`);
  return resolved;
}

function normalizeExtraArgValue(spec, value, name, context) {
  const normalized = assertText(value, `${name} value`).trim();
  if (spec.type === 'integer') return normalizeExtraInteger(normalized, name, spec.minimum);
  if (spec.type === 'environment') {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(normalized)) {
      fail(`${name} must name an environment variable, not contain a credential value`);
    }
    return normalized;
  }
  if (spec.type === 'enum') {
    const lower = normalized.toLowerCase();
    if (!spec.values.includes(lower)) fail(`${name} must be one of: ${spec.values.join(', ')}`);
    return lower;
  }
  if (spec.type === 'text') {
    if (normalized.length > spec.maxLength) fail(`${name} must be at most ${spec.maxLength} characters`);
    return normalized;
  }
  if (spec.type === 'file') {
    return resolveExtraArgFile(context.workspace, context.workingDirectory, normalized, name);
  }
  fail(`Internal error: unsupported extra-args type for ${name}`);
}

function validateAgentArgs(selected) {
  const mode = selected.get('--agent-mode');
  const provider = selected.get('--agent-provider');
  const agentOnly = [
    '--agent-provider',
    '--agent-model',
    '--max-agent-turns',
    '--max-provider-ms',
    '--max-steps-per-turn',
    '--require-agent-success'
  ];
  if (!mode && agentOnly.some(name => selected.has(name))) {
    fail('agent controls require an explicit --agent-mode');
  }
  if (mode === 'off' && agentOnly.some(name => selected.has(name))) {
    fail('--agent-mode off cannot be combined with other agent controls');
  }
  if (mode === 'provider' || mode === 'browser') {
    if (!provider) fail(`${mode} agent mode requires --agent-provider`);
  } else if (provider) {
    fail('--agent-provider is accepted only with --agent-mode provider or browser');
  }
  if (selected.has('--agent-model') && mode !== 'provider' && mode !== 'browser') {
    fail('--agent-model is accepted only with --agent-mode provider or browser');
  }
}

function parseExtraArgs(value, context = {}) {
  const raw = assertText(value ?? '', 'extra-args', { multiline: true, allowEmpty: true });
  if (raw.length > 65536) fail('extra-args exceeds the 64 KiB limit');
  const args = raw
    .split('\n')
    .map(line => line.endsWith('\r') ? line.slice(0, -1) : line)
    .map(line => line.trim())
    .filter(Boolean);
  if (args.length > 200) fail('extra-args may contain at most 200 arguments');
  const parsed = [];
  const selected = new Map();
  const groups = new Set();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    assertText(argument, 'each extra-args entry');
    if (argument.length > 8192) fail('each extra-args entry must be at most 8192 characters');
    if (!argument.startsWith('--') || argument === '--') {
      fail(`Unexpected extra-args value "${argument}"; every entry must belong to a supported option`);
    }
    const equalsIndex = argument.indexOf('=');
    const name = equalsIndex === -1 ? argument : argument.slice(0, equalsIndex);
    const inlineValue = equalsIndex === -1 ? undefined : argument.slice(equalsIndex + 1);
    if (name !== name.toLowerCase()) fail(`${name} must use lowercase option spelling`);
    if (DIRECT_CREDENTIAL_FLAGS.has(name)) {
      fail(`${name} is not accepted because workflow inputs can be exposed; use ${name}-env with a GitHub secret environment variable`);
    }
    const spec = EXTRA_ARG_SPECS[name];
    if (!spec) fail(`${name} is not supported by ptk-action v1`);
    const uniqueness = spec.group || name;
    if (groups.has(uniqueness)) fail(`${name} duplicates an option already supplied through extra-args`);
    groups.add(uniqueness);

    if (spec.type === 'boolean') {
      if (inlineValue !== undefined) fail(`${name} is a boolean option and does not take a value`);
      parsed.push(name);
      selected.set(name, true);
      continue;
    }

    let optionValue = inlineValue;
    if (optionValue === undefined) {
      optionValue = args[index + 1];
      if (optionValue === undefined || optionValue.startsWith('--')) fail(`${name} requires a value`);
      index += 1;
    }
    const normalized = normalizeExtraArgValue(spec, optionValue, name, context);
    parsed.push(name, normalized);
    selected.set(name, normalized);
  }
  validateAgentArgs(selected);
  return parsed;
}

function isInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function assertInside(root, candidate, label) {
  if (!isInside(root, candidate)) fail(`${label} must remain inside GITHUB_WORKSPACE`);
}

function realDirectory(value, label) {
  let resolved;
  try {
    resolved = fs.realpathSync(value);
  } catch {
    fail(`${label} does not exist: ${value}`);
  }
  if (!fs.statSync(resolved).isDirectory()) fail(`${label} must be a directory: ${value}`);
  return resolved;
}

function resolveWorkspace(workspaceValue) {
  const raw = assertText(workspaceValue, 'GITHUB_WORKSPACE').trim();
  return realDirectory(path.resolve(raw), 'GITHUB_WORKSPACE');
}

function resolveWorkingDirectory(workspace, value) {
  const raw = assertText(value, 'working-directory').trim();
  const lexical = path.resolve(workspace, raw);
  assertInside(workspace, lexical, 'working-directory');
  const resolved = realDirectory(lexical, 'working-directory');
  assertInside(workspace, resolved, 'working-directory');
  return resolved;
}

function nearestExistingAncestor(value) {
  let current = value;
  while (!fs.existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) fail(`Unable to resolve an existing parent for ${value}`);
    current = parent;
  }
  return current;
}

function assertSafeExistingOutput(value, kind, label) {
  if (!fs.existsSync(value)) return;
  const lstat = fs.lstatSync(value);
  if (lstat.isSymbolicLink()) fail(`${label} must not be a symbolic link`);
  if (kind === 'directory' && !lstat.isDirectory()) fail(`${label} must be a directory`);
  if (kind === 'file' && !lstat.isFile()) fail(`${label} must be a regular file`);
}

function resolveOutputPath(workspace, workingDirectory, value, { kind, label }) {
  const raw = assertText(value, label).trim();
  const candidate = path.resolve(workingDirectory, raw);
  assertInside(workspace, candidate, label);
  const ancestor = fs.realpathSync(nearestExistingAncestor(candidate));
  assertInside(workspace, ancestor, label);
  assertSafeExistingOutput(candidate, kind, label);

  if (kind === 'directory') fs.mkdirSync(candidate, { recursive: true });
  else fs.mkdirSync(path.dirname(candidate), { recursive: true });

  const containmentPath = kind === 'directory' ? fs.realpathSync(candidate) : fs.realpathSync(path.dirname(candidate));
  assertInside(workspace, containmentPath, label);
  assertSafeExistingOutput(candidate, kind, label);
  return candidate;
}

function resolvePackageSpec(workspace, packageValue, versionValue) {
  const version = parseExactSemver(versionValue);
  const packageInput = assertText(packageValue ?? '', 'pentestkit-package', { allowEmpty: true }).trim();
  if (!packageInput) return { spec: `pentestkit@${version}`, expectedVersion: version, local: false };
  if (!packageInput.toLowerCase().endsWith('.tgz')) fail('pentestkit-package must point to a .tgz file');
  const lexical = path.resolve(workspace, packageInput);
  assertInside(workspace, lexical, 'pentestkit-package');
  let resolved;
  try {
    resolved = fs.realpathSync(lexical);
  } catch {
    fail(`pentestkit-package does not exist: ${packageInput}`);
  }
  assertInside(workspace, resolved, 'pentestkit-package');
  if (!fs.statSync(resolved).isFile()) fail('pentestkit-package must be a regular .tgz file');
  return { spec: resolved, expectedVersion: version, local: true };
}

function toWorkspaceRelative(workspace, value) {
  assertInside(workspace, value, 'Action output');
  const relative = path.relative(workspace, value) || '.';
  return relative.split(path.sep).join('/');
}

function writeOutput(outputFile, name, value) {
  assertText(name, 'output name');
  const safeValue = assertText(value ?? '', `output ${name}`, { allowEmpty: true });
  if (!outputFile) fail('GITHUB_OUTPUT is not available');
  fs.appendFileSync(outputFile, `${name}=${safeValue}\n`, { encoding: 'utf8' });
}

function toSarifRelativeUri(workspace, value) {
  return toWorkspaceRelative(workspace, value)
    .split('/')
    .map(segment => encodeURIComponent(segment))
    .join('/');
}

function buildScanArgs({ target, engines, failOn, outputDirectory, sarif, sarifFile, extraArgs }) {
  const args = [target, ...extraArgs];
  args.push(
    '--engines', engines.join(','),
    '--output-dir', outputDirectory,
    '--fail-on', failOn,
    '--browser', 'chromium',
    '--headed',
    '--require-ptk-bridge',
    '--require-ptk-findings-export',
    '--wait-for-ptk-complete',
    '--require-ptk-attack-completion',
    '--immediate-analysis',
    '--memory-mode', 'off'
  );
  if (sarif) args.push('--format', 'sarif', '--output', sarifFile);
  return args;
}

function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env || process.env,
    encoding: 'utf8',
    stdio: options.stdio || 'inherit'
  });
  if (result.error) fail(`${options.label || command} could not start: ${result.error.message}`);
  if (options.allowFailure) return result.status === null ? 1 : result.status;
  if (result.status !== 0) fail(`${options.label || command} failed with exit code ${result.status}`);
  return 0;
}

function readInstalledPackage(prefix, expectedVersion) {
  const root = path.join(prefix, 'node_modules', 'pentestkit');
  const manifestPath = path.join(root, 'package.json');
  if (!fs.existsSync(manifestPath)) fail('npm did not install a pentestkit package');
  if (fs.lstatSync(manifestPath).isSymbolicLink()) fail('Installed pentestkit manifest must not be a symbolic link');
  const resolvedRoot = fs.realpathSync(root);
  assertInside(fs.realpathSync(prefix), resolvedRoot, 'installed pentestkit package');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (manifest.name !== 'pentestkit') fail(`Installed package has unexpected name: ${manifest.name || '(missing)'}`);
  if (!EXACT_SEMVER.test(String(manifest.version || ''))) fail('Installed pentestkit package has an invalid version');
  if (expectedVersion && manifest.version !== expectedVersion) {
    fail(`Installed pentestkit version ${manifest.version} does not match requested version ${expectedVersion}`);
  }
  const binValue = manifest.bin && manifest.bin['ptk-scan'];
  if (typeof binValue !== 'string' || !binValue) fail('Installed pentestkit package does not expose the ptk-scan CLI');
  const scanEntry = path.resolve(root, binValue);
  assertInside(root, scanEntry, 'ptk-scan entry');
  if (!fs.existsSync(scanEntry) || fs.lstatSync(scanEntry).isSymbolicLink() || !fs.statSync(scanEntry).isFile()) {
    fail('Installed ptk-scan CLI entry must be a regular non-symlink file');
  }
  assertInside(resolvedRoot, fs.realpathSync(scanEntry), 'ptk-scan entry');
  const playwrightCli = path.join(prefix, 'node_modules', 'playwright', 'cli.js');
  if (!fs.existsSync(playwrightCli) || fs.lstatSync(playwrightCli).isSymbolicLink() || !fs.statSync(playwrightCli).isFile()) {
    fail('Installed pentestkit package is missing a regular Playwright runtime dependency');
  }
  assertInside(fs.realpathSync(prefix), fs.realpathSync(playwrightCli), 'Playwright CLI entry');
  return { manifest, root, scanEntry, playwrightCli };
}

function createNpmInstallEnvironment(env, installRoot) {
  const commandEnv = { ...env };
  for (const key of Object.keys(commandEnv)) {
    const lower = key.toLowerCase();
    if (lower === 'npm_config_registry' || lower === 'npm_config_userconfig') delete commandEnv[key];
  }
  const userConfig = path.join(installRoot, '.npmrc');
  fs.writeFileSync(userConfig, '', { encoding: 'utf8', mode: 0o600 });
  commandEnv.npm_config_userconfig = userConfig;
  commandEnv.npm_config_registry = OFFICIAL_NPM_REGISTRY;
  commandEnv.npm_config_cache = env.PTK_NPM_CACHE || path.join(os.homedir(), '.npm');
  return commandEnv;
}

function assertGeneratedFile(workspace, filePath, label) {
  if (!fs.existsSync(filePath)) fail(`${label} was not written: ${toWorkspaceRelative(workspace, filePath)}`);
  const lstat = fs.lstatSync(filePath);
  if (lstat.isSymbolicLink() || !lstat.isFile()) fail(`${label} must be a regular file`);
  assertInside(workspace, fs.realpathSync(filePath), label);
}

function visitArtifactLocations(value, visitor, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return;
  seen.add(value);
  if (value.artifactLocation && typeof value.artifactLocation === 'object') {
    visitor(value.artifactLocation, value);
  }
  for (const [key, child] of Object.entries(value)) {
    if (key !== 'artifactLocation') visitArtifactLocations(child, visitor, seen);
  }
}

function normalizeRepositoryArtifactUri(workspace, uri) {
  if (typeof uri !== 'string' || uri.trim() === '') return null;
  const value = uri.trim();
  let candidate;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'file:') return null;
    candidate = fileURLToPath(parsed);
  } catch {
    let decoded;
    try {
      decoded = value
        .split(/[?#]/, 1)[0]
        .split('/')
        .map(segment => decodeURIComponent(segment))
        .join(path.sep);
    } catch {
      return null;
    }
    candidate = path.resolve(workspace, decoded);
  }
  if (!isInside(workspace, candidate) || !fs.existsSync(candidate)) return null;
  let resolved;
  try {
    resolved = fs.realpathSync(candidate);
    if (!isInside(workspace, resolved) || !fs.statSync(resolved).isFile()) return null;
  } catch {
    return null;
  }
  return toSarifRelativeUri(workspace, resolved);
}

function evidenceText(value) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 8192);
}

function writeTextAtomically(filePath, contents) {
  const temporary = `${filePath}.ptk-action-${process.pid}.tmp`;
  let created = false;
  try {
    fs.writeFileSync(temporary, contents, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600
    });
    created = true;
    fs.renameSync(temporary, filePath);
  } finally {
    if (created) fs.rmSync(temporary, { force: true });
  }
}

function writeJsonAtomically(filePath, value) {
  writeTextAtomically(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function normalizeSarifForGitHub(workspace, outputDirectory, sarifFile) {
  assertGeneratedFile(workspace, sarifFile, 'SARIF report');
  let sarif;
  try {
    sarif = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
  } catch (error) {
    fail(`SARIF report is not valid JSON: ${error.message}`);
  }
  if (sarif.version !== '2.1.0' || !Array.isArray(sarif.runs)) {
    fail('SARIF report must use version 2.1.0 and contain a runs array');
  }

  let runtimeFile = path.join(outputDirectory, GITHUB_RUNTIME_LOCATIONS_FILE);
  if (path.resolve(runtimeFile) === path.resolve(sarifFile)) {
    runtimeFile = path.join(outputDirectory, `github-code-scanning-runtime-findings-1.txt`);
  }
  const runtimeUri = toSarifRelativeUri(workspace, runtimeFile);
  const evidenceLines = [];

  for (const run of sarif.runs) {
    if (!run || typeof run !== 'object' || run.results === undefined) continue;
    if (!Array.isArray(run.results)) fail('Each SARIF run results value must be an array');
    for (const result of run.results) {
      if (!result || typeof result !== 'object') continue;
      const remappedUris = new Set();
      const remappedLocations = [];
      visitArtifactLocations(result, (artifactLocation, location) => {
        if (typeof artifactLocation.uri !== 'string') return;
        const repositoryUri = normalizeRepositoryArtifactUri(workspace, artifactLocation.uri);
        if (repositoryUri) {
          artifactLocation.uri = repositoryUri;
          delete artifactLocation.uriBaseId;
          delete artifactLocation.index;
          return;
        }
        remappedUris.add(artifactLocation.uri);
        remappedLocations.push({ artifactLocation, location });
      });
      if (remappedLocations.length === 0) continue;

      const line = evidenceLines.length + 1;
      const message = evidenceText(result.message && result.message.text);
      const ruleId = evidenceText(result.ruleId || 'PTK/runtime-finding');
      const originalUris = [...remappedUris].slice(0, 32).map(value => evidenceText(value).slice(0, 2048)).filter(Boolean);
      evidenceLines.push(evidenceText(
        `${ruleId} | ${message || 'Runtime finding'}${originalUris.length ? ` | artifacts=${originalUris.join(', ')}` : ''}`
      ));
      for (const { artifactLocation, location } of remappedLocations) {
        artifactLocation.uri = runtimeUri;
        delete artifactLocation.uriBaseId;
        delete artifactLocation.index;
        location.region = { startLine: line, startColumn: 1 };
      }
      result.properties = result.properties && typeof result.properties === 'object' && !Array.isArray(result.properties)
        ? result.properties
        : {};
      result.properties.githubCodeScanningLocation = 'runtime-evidence';
      if (originalUris.length > 0) result.properties.runtimeArtifactUris = originalUris;
    }
  }

  if (evidenceLines.length > 0) {
    assertSafeExistingOutput(runtimeFile, 'file', 'GitHub Code Scanning runtime evidence');
    writeTextAtomically(runtimeFile, `${evidenceLines.join('\n')}\n`);
    assertGeneratedFile(workspace, runtimeFile, 'GitHub Code Scanning runtime evidence');
  }

  visitArtifactLocations(sarif, artifactLocation => {
    if (typeof artifactLocation.uri !== 'string') return;
    let protocol = null;
    try {
      protocol = new URL(artifactLocation.uri).protocol;
    } catch {
      return;
    }
    if (protocol !== 'file:') {
      fail(`SARIF report still contains an unsupported artifact URI scheme: ${protocol}`);
    }
  });
  writeJsonAtomically(sarifFile, sarif);
  assertGeneratedFile(workspace, sarifFile, 'SARIF report');
  return {
    remappedResults: evidenceLines.length,
    runtimeFile: evidenceLines.length > 0 ? runtimeFile : null
  };
}

function run(env = process.env, dependencies = {}) {
  const execute = dependencies.runCommand || runCommand;
  if ((env.RUNNER_OS || '').toLowerCase() !== 'linux') {
    fail('ptk-action v1 supports Linux runners with Chromium; use runs-on: ubuntu-latest');
  }

  const workspace = resolveWorkspace(env.GITHUB_WORKSPACE);
  const workingDirectory = resolveWorkingDirectory(workspace, env.PTK_INPUT_WORKING_DIRECTORY || '.');
  const target = validateTarget(env.PTK_INPUT_TARGET);
  const engines = parseEngines(env.PTK_INPUT_ENGINES || 'DAST');
  const failOn = parseThreshold(env.PTK_INPUT_FAIL_ON || 'none');
  const sarif = parseBoolean(env.PTK_INPUT_SARIF || 'true', 'sarif');
  const installBrowsers = parseBoolean(env.PTK_INPUT_INSTALL_BROWSERS || 'true', 'install-browsers');
  const extraArgs = parseExtraArgs(env.PTK_INPUT_EXTRA_ARGS || '', { workspace, workingDirectory });
  const outputDirectory = resolveOutputPath(workspace, workingDirectory, env.PTK_INPUT_OUTPUT_DIR || '.ptk/artifacts', {
    kind: 'directory',
    label: 'output-dir'
  });
  const sarifFile = resolveOutputPath(workspace, workingDirectory, env.PTK_INPUT_SARIF_FILE || 'ptk-results.sarif', {
    kind: 'file',
    label: 'sarif-file'
  });
  const packageSpec = resolvePackageSpec(
    workspace,
    env.PTK_INPUT_PENTESTKIT_PACKAGE || '',
    env.PTK_INPUT_PENTESTKIT_VERSION || '9.9.8'
  );

  const runnerTemp = realDirectory(path.resolve(env.RUNNER_TEMP || os.tmpdir()), 'RUNNER_TEMP');
  const installRoot = fs.mkdtempSync(path.join(runnerTemp, 'ptk-action-'));
  const commandEnv = createNpmInstallEnvironment(env, installRoot);

  try {
    execute('npm', [
      'install',
      '--prefix', installRoot,
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      '--package-lock=false',
      '--install-strategy=hoisted',
      '--registry', OFFICIAL_NPM_REGISTRY,
      packageSpec.spec
    ], { cwd: installRoot, env: commandEnv, label: 'pentestkit installation' });

    const installed = readInstalledPackage(installRoot, packageSpec.expectedVersion);
    process.stdout.write(`OWASP PTK Action: installed pentestkit ${installed.manifest.version}\n`);

    if (installBrowsers) {
      execute(process.execPath, [installed.playwrightCli, 'install', 'chromium', '--with-deps'], {
        cwd: workingDirectory,
        env: commandEnv,
        label: 'Chromium installation'
      });
    }

    writeOutput(env.GITHUB_OUTPUT, 'output-dir', toWorkspaceRelative(workspace, outputDirectory));
    writeOutput(env.GITHUB_OUTPUT, 'sarif-file', sarif ? toWorkspaceRelative(workspace, sarifFile) : '');
    writeOutput(env.GITHUB_OUTPUT, 'pentestkit-version', installed.manifest.version);

    const scanArgs = buildScanArgs({
      target,
      engines,
      failOn,
      outputDirectory,
      sarif,
      sarifFile,
      extraArgs
    });
    const status = execute('xvfb-run', [
      '--auto-servernum',
      '--server-args=-screen 0 1280x800x24',
      process.execPath,
      installed.scanEntry,
      ...scanArgs
    ], {
      cwd: workingDirectory,
      env: commandEnv,
      label: 'OWASP PTK scan',
      allowFailure: true
    });

    if (sarif) normalizeSarifForGitHub(workspace, outputDirectory, sarifFile);
    if (status !== 0) {
      process.stderr.write(`OWASP PTK scan failed with exit code ${status}; generated artifacts were preserved.\n`);
    }
    return status;
  } finally {
    fs.rmSync(installRoot, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try {
    process.exitCode = run();
  } catch (error) {
    process.stderr.write(`PTK Action error: ${error && error.message ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  EXTRA_ARG_SPECS,
  GITHUB_RUNTIME_LOCATIONS_FILE,
  OFFICIAL_NPM_REGISTRY,
  buildScanArgs,
  createNpmInstallEnvironment,
  isInside,
  normalizeSarifForGitHub,
  parseBoolean,
  parseEngines,
  parseExactSemver,
  parseExtraArgs,
  parseThreshold,
  readInstalledPackage,
  run,
  resolveOutputPath,
  resolvePackageSpec,
  resolveWorkingDirectory,
  toWorkspaceRelative,
  validateTarget,
  writeOutput
};
