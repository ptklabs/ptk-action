'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  OFFICIAL_NPM_REGISTRY,
  buildScanArgs,
  createNpmInstallEnvironment,
  parseBoolean,
  parseEngines,
  parseExactSemver,
  parseExtraArgs,
  parseThreshold,
  resolveOutputPath,
  resolvePackageSpec,
  resolveWorkingDirectory,
  run,
  validateTarget,
  writeOutput
} = require('../scripts/run.cjs');

function temporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ptk-action-test-'));
  const resolved = fs.realpathSync(directory);
  t.after(() => fs.rmSync(resolved, { recursive: true, force: true }));
  return resolved;
}

test('parses booleans, exact versions, engines, and thresholds without loose package specs', () => {
  assert.equal(parseBoolean('TRUE', 'value'), true);
  assert.equal(parseBoolean('false', 'value'), false);
  assert.throws(() => parseBoolean('yes', 'value'), /true or false/);
  assert.equal(parseExactSemver('9.9.8-rc.1'), '9.9.8-rc.1');
  for (const unsafe of ['latest', '^9.9.8', '>=9', 'github:ptklabs/ptk-agent', 'v9.9.8']) {
    assert.throws(() => parseExactSemver(unsafe), /exact semantic version/);
  }
  assert.deepEqual(parseEngines('dast, IAST, DAST, sca'), ['DAST', 'IAST', 'SCA']);
  assert.throws(() => parseEngines('DAST,RCE'), /Unsupported engine/);
  assert.equal(parseThreshold('HIGH'), 'high');
  assert.throws(() => parseThreshold('warning'), /must be one of/);
});

test('accepts only credential-free absolute HTTP(S) targets', () => {
  assert.equal(validateTarget('http://localhost:3001/#/'), 'http://localhost:3001/#/');
  assert.equal(validateTarget('https://example.test/path?q=1'), 'https://example.test/path?q=1');
  assert.throws(() => validateTarget('file:///etc/passwd'), /http:\/\/ or https:\/\//);
  assert.throws(() => validateTarget('https://user:secret@example.test/'), /embedded credentials/);
  assert.throws(() => validateTarget('https://example.test/\n--fail-on=none'), /single line/);
});

test('accepts only reviewed newline-delimited scan and provider-agent controls', t => {
  const workspace = temporaryDirectory(t);
  const scenario = path.join(workspace, 'fixtures', 'my scenario.md');
  const hints = path.join(workspace, 'route-hints.json');
  fs.mkdirSync(path.dirname(scenario));
  fs.writeFileSync(scenario, '# authorized scenario');
  fs.writeFileSync(hints, '[]');
  const context = { workspace, workingDirectory: workspace };

  assert.deepEqual(parseExtraArgs('--max-routes\n8\n--scenario\nfixtures/my scenario.md', context), [
    '--max-routes',
    '8',
    '--scenario',
    scenario
  ]);
  assert.deepEqual(parseExtraArgs('--username-env\nPTK_USER\n--password-env\nPTK_PASSWORD\n--include-secrets', context), [
    '--username-env', 'PTK_USER', '--password-env', 'PTK_PASSWORD', '--include-secrets'
  ]);
  assert.deepEqual(parseExtraArgs([
    '--route-hints-file=route-hints.json',
    '--agent-mode', 'provider',
    '--agent-provider', 'codex',
    '--agent-model', 'gpt-5.3-codex-spark',
    '--max-agent-turns', '3',
    '--max-provider-ms', '60000',
    '--max-steps-per-turn', '1',
    '--require-agent-success'
  ].join('\n'), context), [
    '--route-hints-file', hints,
    '--agent-mode', 'provider',
    '--agent-provider', 'codex',
    '--agent-model', 'gpt-5.3-codex-spark',
    '--max-agent-turns', '3',
    '--max-provider-ms', '60000',
    '--max-steps-per-turn', '1',
    '--require-agent-success'
  ]);
});

test('rejects unknown, Action-owned, destructive, direct-secret, and malformed extra arguments', t => {
  const workspace = temporaryDirectory(t);
  const context = { workspace, workingDirectory: workspace };
  for (const unsafe of [
    '--output-dir\n/tmp',
    '--fail-on=none',
    '--allow-missing-ptk',
    '--ptk-drain-mode\noff',
    '--username=admin',
    '--password\nsecret',
    '--dry-run',
    '--config\nptk.config.json',
    '--chrome-binary\n/tmp/browser',
    '--profile-dir\n/tmp/profile',
    '--memory-mode\nread-write',
    '--aggressive',
    '--allow-destructive-actions',
    '--future-cli-option\nvalue'
  ]) {
    assert.throws(() => parseExtraArgs(unsafe, context), /not supported|not accepted/);
  }
  assert.throws(() => parseExtraArgs('--max-routes\n0', context), /greater than or equal to 1/);
  assert.throws(() => parseExtraArgs('--max-routes\n1.5', context), /must be an integer/);
  assert.throws(() => parseExtraArgs('--max-routes\n8\n--crawl-pages\n9', context), /duplicates/);
  assert.throws(() => parseExtraArgs('--include-secrets=true', context), /does not take a value/);
  assert.throws(() => parseExtraArgs('--username-env\nsecret-value@example.test', context), /name an environment variable/);
  assert.throws(() => parseExtraArgs('positional-value', context), /Unexpected extra-args value/);
});

test('requires coherent provider-agent option combinations', t => {
  const workspace = temporaryDirectory(t);
  const context = { workspace, workingDirectory: workspace };
  assert.deepEqual(parseExtraArgs('--agent-mode\nmock\n--max-agent-turns\n2', context), [
    '--agent-mode', 'mock', '--max-agent-turns', '2'
  ]);
  assert.throws(() => parseExtraArgs('--agent-mode\nprovider', context), /requires --agent-provider/);
  assert.throws(() => parseExtraArgs('--agent-provider\ncodex', context), /explicit --agent-mode/);
  assert.throws(
    () => parseExtraArgs('--agent-mode\nmock\n--agent-provider\ncodex', context),
    /only with --agent-mode provider or browser/
  );
  assert.throws(
    () => parseExtraArgs('--agent-mode\noff\n--max-agent-turns\n1', context),
    /cannot be combined/
  );
  assert.throws(
    () => parseExtraArgs('--agent-mode\nprovider\n--agent-provider\nunsupported', context),
    /must be one of: opencode, codex/
  );
});

test('contains scenario and route-hint inputs inside the workspace', t => {
  const workspace = temporaryDirectory(t);
  const outside = temporaryDirectory(t);
  const outsideScenario = path.join(outside, 'scenario.md');
  fs.writeFileSync(outsideScenario, '# outside');
  assert.throws(
    () => parseExtraArgs(`--scenario\n${outsideScenario}`, { workspace, workingDirectory: workspace }),
    /inside GITHUB_WORKSPACE/
  );
  const escapingLink = path.join(workspace, 'scenario.md');
  fs.symlinkSync(outsideScenario, escapingLink);
  assert.throws(
    () => parseExtraArgs('--scenario\nscenario.md', { workspace, workingDirectory: workspace }),
    /inside GITHUB_WORKSPACE/
  );
});

test('contains working, artifact, and local package paths inside the workspace', t => {
  const workspace = temporaryDirectory(t);
  const app = path.join(workspace, 'app');
  fs.mkdirSync(app);
  assert.equal(resolveWorkingDirectory(workspace, 'app'), app);
  assert.throws(() => resolveWorkingDirectory(workspace, '..'), /inside GITHUB_WORKSPACE/);

  const output = resolveOutputPath(workspace, app, '.ptk/results', { kind: 'directory', label: 'output-dir' });
  assert.equal(output, path.join(app, '.ptk', 'results'));
  assert.ok(fs.statSync(output).isDirectory());
  assert.throws(
    () => resolveOutputPath(workspace, app, '../../outside', { kind: 'directory', label: 'output-dir' }),
    /inside GITHUB_WORKSPACE/
  );

  const packageFile = path.join(workspace, 'pentestkit.tgz');
  fs.writeFileSync(packageFile, 'fixture');
  assert.deepEqual(resolvePackageSpec(workspace, 'pentestkit.tgz', '9.9.8'), {
    spec: packageFile,
    expectedVersion: '9.9.8',
    local: true
  });
  assert.deepEqual(resolvePackageSpec(workspace, '', '9.9.8'), {
    spec: 'pentestkit@9.9.8',
    expectedVersion: '9.9.8',
    local: false
  });
  const outsidePackage = path.join(os.tmpdir(), `outside-${process.pid}.tgz`);
  fs.writeFileSync(outsidePackage, 'fixture');
  t.after(() => fs.rmSync(outsidePackage, { force: true }));
  assert.throws(() => resolvePackageSpec(workspace, outsidePackage, '9.9.8'), /inside GITHUB_WORKSPACE/);
});

test('rejects output paths whose existing symlink parent escapes the workspace', t => {
  const workspace = temporaryDirectory(t);
  const outside = temporaryDirectory(t);
  const link = path.join(workspace, 'escaped');
  fs.symlinkSync(outside, link, 'dir');
  assert.throws(
    () => resolveOutputPath(workspace, workspace, 'escaped/results', { kind: 'directory', label: 'output-dir' }),
    /inside GITHUB_WORKSPACE/
  );
});

test('builds a strict scanner invocation after user arguments', () => {
  const args = buildScanArgs({
    target: 'https://example.test/',
    engines: ['DAST', 'IAST', 'SAST', 'SCA'],
    failOn: 'high',
    outputDirectory: '/workspace/.ptk/artifacts',
    sarif: true,
    sarifFile: '/workspace/ptk.sarif',
    extraArgs: ['--max-routes', '8']
  });
  assert.deepEqual(args.slice(0, 3), ['https://example.test/', '--max-routes', '8']);
  assert.ok(args.includes('--require-ptk-bridge'));
  assert.ok(args.includes('--require-ptk-findings-export'));
  assert.ok(args.includes('--wait-for-ptk-complete'));
  assert.ok(args.includes('--require-ptk-attack-completion'));
  assert.ok(args.includes('--immediate-analysis'));
  assert.equal(args[args.indexOf('--memory-mode') + 1], 'off');
  assert.equal(args[args.indexOf('--engines') + 1], 'DAST,IAST,SAST,SCA');
  assert.equal(args[args.indexOf('--output') + 1], '/workspace/ptk.sarif');
});

test('writes command-file outputs without accepting multiline values', t => {
  const directory = temporaryDirectory(t);
  const output = path.join(directory, 'outputs');
  fs.writeFileSync(output, '');
  writeOutput(output, 'sarif-file', 'ptk-results.sarif');
  assert.equal(fs.readFileSync(output, 'utf8'), 'sarif-file=ptk-results.sarif\n');
  assert.throws(() => writeOutput(output, 'unsafe', 'first\nsecond'), /single line/);
});

test('isolates npm user configuration and pins the official registry', t => {
  const installRoot = temporaryDirectory(t);
  const env = createNpmInstallEnvironment({
    HOME: installRoot,
    npm_config_registry: 'https://registry.invalid/',
    NPM_CONFIG_USERCONFIG: '/tmp/consumer.npmrc',
    PTK_NPM_CACHE: path.join(installRoot, 'cache')
  }, installRoot);
  assert.equal(env.npm_config_registry, OFFICIAL_NPM_REGISTRY);
  assert.equal(env.npm_config_userconfig, path.join(installRoot, '.npmrc'));
  assert.equal(env.npm_config_cache, path.join(installRoot, 'cache'));
  assert.equal(fs.readFileSync(env.npm_config_userconfig, 'utf8'), '');
  assert.equal(env.NPM_CONFIG_USERCONFIG, undefined);
});

test('orchestrates a local package scan and preserves SARIF on threshold failure', t => {
  const workspace = temporaryDirectory(t);
  const runnerTemp = path.join(workspace, '.runner-temp');
  fs.mkdirSync(runnerTemp);
  const packageFile = path.join(workspace, 'pentestkit-9.9.8.tgz');
  const githubOutput = path.join(workspace, 'github-output');
  fs.writeFileSync(packageFile, 'fixture');
  fs.writeFileSync(githubOutput, '');
  const calls = [];

  function mockedCommand(command, args, options) {
    calls.push({ command, args: [...args], cwd: options.cwd, env: options.env, label: options.label });
    if (command === 'npm') {
      assert.notEqual(options.cwd, workspace);
      assert.equal(options.env.npm_config_registry, OFFICIAL_NPM_REGISTRY);
      assert.equal(path.dirname(options.env.npm_config_userconfig), options.cwd);
      assert.ok(fs.existsSync(options.env.npm_config_userconfig));
      assert.equal(args[args.indexOf('--registry') + 1], OFFICIAL_NPM_REGISTRY);
      const prefix = args[args.indexOf('--prefix') + 1];
      const packageRoot = path.join(prefix, 'node_modules', 'pentestkit');
      const playwrightRoot = path.join(prefix, 'node_modules', 'playwright');
      fs.mkdirSync(path.join(packageRoot, 'bin'), { recursive: true });
      fs.mkdirSync(playwrightRoot, { recursive: true });
      fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({
        name: 'pentestkit',
        version: '9.9.8',
        bin: { 'ptk-scan': 'bin/ptk-scan' }
      }));
      fs.writeFileSync(path.join(packageRoot, 'bin', 'ptk-scan'), '# fixture');
      fs.writeFileSync(path.join(playwrightRoot, 'cli.js'), '# fixture');
      return 0;
    }
    if (command === 'xvfb-run') {
      const outputIndex = args.indexOf('--output');
      fs.writeFileSync(args[outputIndex + 1], JSON.stringify({ version: '2.1.0', runs: [] }));
      return 70;
    }
    return 0;
  }

  const status = run({
    ...process.env,
    RUNNER_OS: 'Linux',
    RUNNER_TEMP: runnerTemp,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: githubOutput,
    PTK_INPUT_TARGET: 'http://127.0.0.1:4173/',
    PTK_INPUT_ENGINES: 'DAST,IAST,SAST,SCA',
    PTK_INPUT_FAIL_ON: 'high',
    PTK_INPUT_SARIF: 'true',
    PTK_INPUT_SARIF_FILE: 'ptk-results.sarif',
    PTK_INPUT_OUTPUT_DIR: '.ptk/artifacts',
    PTK_INPUT_WORKING_DIRECTORY: '.',
    PTK_INPUT_PENTESTKIT_VERSION: '9.9.8',
    PTK_INPUT_PENTESTKIT_PACKAGE: path.basename(packageFile),
    PTK_INPUT_INSTALL_BROWSERS: 'true',
    PTK_INPUT_EXTRA_ARGS: '--max-routes\n8'
  }, { runCommand: mockedCommand });

  assert.equal(status, 70);
  assert.ok(fs.existsSync(path.join(workspace, 'ptk-results.sarif')));
  assert.match(fs.readFileSync(githubOutput, 'utf8'), /sarif-file=ptk-results\.sarif/);
  assert.match(fs.readFileSync(githubOutput, 'utf8'), /pentestkit-version=9\.9\.8/);
  assert.deepEqual(calls.map(call => call.label), [
    'pentestkit installation',
    'Chromium installation',
    'OWASP PTK scan'
  ]);
  const scanCall = calls.at(-1);
  assert.equal(scanCall.command, 'xvfb-run');
  assert.ok(scanCall.args.includes('--require-ptk-attack-completion'));
  assert.equal(scanCall.args[scanCall.args.indexOf('--memory-mode') + 1], 'off');
});

test('normal acquisition ignores a consumer project registry and installs the exact official package', t => {
  const workspace = temporaryDirectory(t);
  const runnerTemp = path.join(workspace, '.runner-temp');
  const githubOutput = path.join(workspace, 'github-output');
  fs.mkdirSync(runnerTemp);
  fs.writeFileSync(githubOutput, '');
  fs.writeFileSync(path.join(workspace, '.npmrc'), 'registry=https://consumer-registry.invalid/\n');
  let installObserved = false;

  function mockedCommand(command, args, options) {
    if (command === 'npm') {
      installObserved = true;
      const prefix = args[args.indexOf('--prefix') + 1];
      assert.equal(args.at(-1), 'pentestkit@9.9.8');
      assert.equal(args[args.indexOf('--registry') + 1], OFFICIAL_NPM_REGISTRY);
      assert.notEqual(options.cwd, workspace);
      assert.equal(options.cwd, prefix);
      assert.equal(options.env.npm_config_registry, OFFICIAL_NPM_REGISTRY);
      assert.equal(path.dirname(options.env.npm_config_userconfig), prefix);
      assert.notEqual(options.env.npm_config_userconfig, path.join(workspace, '.npmrc'));
      const packageRoot = path.join(prefix, 'node_modules', 'pentestkit');
      const playwrightRoot = path.join(prefix, 'node_modules', 'playwright');
      fs.mkdirSync(path.join(packageRoot, 'bin'), { recursive: true });
      fs.mkdirSync(playwrightRoot, { recursive: true });
      fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({
        name: 'pentestkit',
        version: '9.9.8',
        bin: { 'ptk-scan': 'bin/ptk-scan' }
      }));
      fs.writeFileSync(path.join(packageRoot, 'bin', 'ptk-scan'), '# fixture');
      fs.writeFileSync(path.join(playwrightRoot, 'cli.js'), '# fixture');
      return 0;
    }
    if (command === 'xvfb-run') {
      const outputIndex = args.indexOf('--output');
      fs.writeFileSync(args[outputIndex + 1], JSON.stringify({ version: '2.1.0', runs: [] }));
    }
    return 0;
  }

  const status = run({
    ...process.env,
    npm_config_registry: 'https://environment-registry.invalid/',
    RUNNER_OS: 'Linux',
    RUNNER_TEMP: runnerTemp,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: githubOutput,
    PTK_INPUT_TARGET: 'http://127.0.0.1:4173/',
    PTK_INPUT_PENTESTKIT_VERSION: '9.9.8',
    PTK_INPUT_INSTALL_BROWSERS: 'false'
  }, { runCommand: mockedCommand });

  assert.equal(status, 0);
  assert.equal(installObserved, true);
});

test('rejects a local tarball whose installed version differs from pentestkit-version', t => {
  const workspace = temporaryDirectory(t);
  const runnerTemp = path.join(workspace, '.runner-temp');
  const packageFile = path.join(workspace, 'pentestkit-local.tgz');
  const githubOutput = path.join(workspace, 'github-output');
  fs.mkdirSync(runnerTemp);
  fs.writeFileSync(packageFile, 'fixture');
  fs.writeFileSync(githubOutput, '');

  function mockedCommand(command, args) {
    if (command !== 'npm') return 0;
    const prefix = args[args.indexOf('--prefix') + 1];
    const packageRoot = path.join(prefix, 'node_modules', 'pentestkit');
    const playwrightRoot = path.join(prefix, 'node_modules', 'playwright');
    fs.mkdirSync(path.join(packageRoot, 'bin'), { recursive: true });
    fs.mkdirSync(playwrightRoot, { recursive: true });
    fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({
      name: 'pentestkit',
      version: '9.9.7',
      bin: { 'ptk-scan': 'bin/ptk-scan' }
    }));
    fs.writeFileSync(path.join(packageRoot, 'bin', 'ptk-scan'), '# fixture');
    fs.writeFileSync(path.join(playwrightRoot, 'cli.js'), '# fixture');
    return 0;
  }

  assert.throws(() => run({
    ...process.env,
    RUNNER_OS: 'Linux',
    RUNNER_TEMP: runnerTemp,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: githubOutput,
    PTK_INPUT_TARGET: 'http://127.0.0.1:4173/',
    PTK_INPUT_PENTESTKIT_VERSION: '9.9.8',
    PTK_INPUT_PENTESTKIT_PACKAGE: path.basename(packageFile),
    PTK_INPUT_INSTALL_BROWSERS: 'false'
  }, { runCommand: mockedCommand }), /does not match requested version 9\.9\.8/);
});
