#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const outputDirectory = path.resolve(process.argv[2] || '.ptk/artifacts');
const sarifFile = path.resolve(process.argv[3] || 'ptk-results.sarif');

function readJson(file) {
  const value = path.join(outputDirectory, file);
  if (!fs.existsSync(value)) throw new Error(`Missing PTK artifact: ${file}`);
  return JSON.parse(fs.readFileSync(value, 'utf8'));
}

const engineSummary = readJson('engine-summary.json');
const lifecycle = readJson('ptk-lifecycle-normalized.json');
const requested = [...(engineSummary.requestedEngines || [])].sort();
const expected = ['DAST', 'IAST', 'SAST', 'SCA'].sort();
if (JSON.stringify(requested) !== JSON.stringify(expected)) {
  throw new Error(`Unexpected engine selection: ${requested.join(',')}`);
}
for (const engine of ['dast', 'iast', 'sast', 'sca']) {
  if (engineSummary.enabled && engineSummary.enabled[engine] !== true) throw new Error(`${engine.toUpperCase()} was not enabled`);
}
if (!engineSummary.ptkLifecycle || engineSummary.ptkLifecycle.engineSelectionAppliedToPtk !== true) {
  throw new Error('PTK did not confirm the requested engine selection');
}
if (!lifecycle.bridgeDetected || !lifecycle.scanStarted || !lifecycle.scanStopped) {
  throw new Error('PTK bridge lifecycle was incomplete');
}
if (!lifecycle.exportSucceeded || !lifecycle.safeToStop) {
  throw new Error('PTK findings were not exported and drained safely');
}
if (!fs.existsSync(sarifFile) || !fs.statSync(sarifFile).isFile()) throw new Error('SARIF report is missing');
const sarif = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
if (sarif.version !== '2.1.0' || !Array.isArray(sarif.runs)) throw new Error('SARIF report is invalid');
const sarifResults = sarif.runs.flatMap(run => Array.isArray(run.results) ? run.results : []);
const sarifEngines = new Set(sarifResults.map(result => result.properties && result.properties.engine).filter(Boolean));
for (const engine of ['DAST', 'IAST', 'SAST', 'SCA']) {
  if (!sarifEngines.has(engine)) throw new Error(`${engine} did not produce a SARIF finding in the live fixture`);
}

function assertGitHubArtifactLocations(value, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return;
  seen.add(value);
  if (value.artifactLocation && typeof value.artifactLocation.uri === 'string') {
    let protocol = null;
    try {
      protocol = new URL(value.artifactLocation.uri).protocol;
    } catch {
      // Repository-relative and generated-build locations are expected here.
    }
    if (protocol && protocol !== 'file:') {
      throw new Error(`SARIF contains a GitHub-incompatible artifact URI: ${value.artifactLocation.uri}`);
    }
  }
  for (const child of Object.values(value)) assertGitHubArtifactLocations(child, seen);
}

assertGitHubArtifactLocations(sarif);
const runtimeResults = sarifResults.filter(result => result.properties && result.properties.githubCodeScanningLocation === 'runtime-evidence');
if (runtimeResults.length === 0) throw new Error('SARIF did not normalize runtime findings for GitHub Code Scanning');
const runtimeUri = runtimeResults[0].locations[0].physicalLocation.artifactLocation.uri;
if (!fs.existsSync(path.resolve(decodeURIComponent(runtimeUri)))) throw new Error('GitHub Code Scanning runtime evidence file is missing');

process.stdout.write('PTK Action live smoke assertions passed.\n');
