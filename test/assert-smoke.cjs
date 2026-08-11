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

process.stdout.write('PTK Action live smoke assertions passed.\n');

