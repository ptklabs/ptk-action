# OWASP PTK Security Scan

> Use this Action only against applications you own or are explicitly authorized to test.

`ptklabs/ptk-action` runs the [`pentestkit`](https://www.npmjs.com/package/pentestkit)
CLI in a GitHub-hosted Linux browser session. It enables selected OWASP PTK
engines, waits for PTK to complete, writes normal scan artifacts, and can
produce SARIF for GitHub Code Scanning.

The Action is intentionally a thin wrapper. PTK engines, browser extensions,
framework adapters, and provider integrations remain in
[`ptklabs/ptk-agent`](https://github.com/ptklabs/ptk-agent).

## Supported runner

Version 1 supports `ubuntu-latest` with Chromium. The Action runs Chromium
under Xvfb because PTK Auto must load in a full extension-capable browser
context. Firefox and macOS/Windows Action runners are not claimed by v1.

## Quick start

Start your application before the PTK step. The Action does not build or start
the target for you.

```yaml
name: PTK Security Scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6

      - name: Install and start the application
        run: |
          npm ci
          npm run start:test &
          for attempt in {1..60}; do
            if curl --fail --silent http://127.0.0.1:3000 >/dev/null; then
              exit 0
            fi
            sleep 1
          done
          exit 1

      - name: Run OWASP PTK
        id: ptk
        uses: ptklabs/ptk-action@v1
        with:
          target: http://127.0.0.1:3000
          engines: DAST,IAST,SAST,SCA
          fail-on: high

      - name: Upload PTK SARIF
        if: always() && steps.ptk.outputs.sarif-file != ''
        uses: github/codeql-action/upload-sarif@e4fba868fa4b1b91e1fdab776edc8cfbe6e9fb81 # v4
        with:
          sarif_file: ${{ steps.ptk.outputs.sarif-file }}
          category: owasp-ptk

      - name: Upload PTK artifacts
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7
        with:
          name: ptk-artifacts
          path: ${{ steps.ptk.outputs.output-dir }}
          if-no-files-found: error
```

Use a full commit SHA instead of `@v1` when your dependency policy requires an
immutable Action reference. The maintained `v1` tag follows compatible v1
releases.

## Inputs

| Input | Default | Purpose |
| --- | --- | --- |
| `target` | required | Authorized absolute HTTP or HTTPS target. Embedded URL credentials are rejected. |
| `engines` | `DAST` | Comma-separated `DAST`, `IAST`, `SAST`, and/or `SCA`. |
| `fail-on` | `none` | Return non-zero after artifacts are written for `critical`, `high`, `medium`, `low`, or `info`. |
| `sarif` | `true` | Produce a SARIF report. |
| `sarif-file` | `ptk-results.sarif` | SARIF path inside the workspace. Relative paths use `working-directory`. |
| `output-dir` | `.ptk/artifacts` | PTK artifact directory inside the workspace. |
| `working-directory` | `.` | Existing application directory inside the workspace. |
| `node-version` | `24` | Node.js version used by the Action. |
| `pentestkit-version` | `9.9.8` | Exact npm package version. Tags and ranges are rejected. |
| `pentestkit-package` | empty | Workspace-local `.tgz` used to validate an Agent package before npm publication. |
| `install-browsers` | `true` | Install Chromium and Linux browser dependencies through Playwright. |
| `extra-args` | empty | Reviewed `ptk-scan` crawl, scenario, authentication, and provider-agent controls, one argument per line. |

The `pentestkit-package` input is mainly for PTK Agent CI and release
validation. Normal users should select an exact published version through
`pentestkit-version`.

## Outputs

| Output | Purpose |
| --- | --- |
| `sarif-file` | Workspace-relative SARIF path; empty when `sarif` is disabled. |
| `output-dir` | Workspace-relative PTK artifact directory. |
| `pentestkit-version` | Version read from the installed package. |

SARIF upload remains explicit so each repository controls its own Code
Scanning permissions, category, retention, and fork policy.

## Authentication and extra arguments

`extra-args` is parsed as data, never evaluated by a shell. Put one complete
argument on each line. The Action uses a fail-closed allowlist: newly added CLI
flags are rejected until their Action security and ownership impact is
reviewed.

Supported scan controls are:

- scenario and route-hint files contained inside `GITHUB_WORKSPACE`;
- scenario continuation, persona selection, and environment-variable-based
  username/password references;
- explicit `--include-secrets` for authorized authenticated browser execution;
- route, depth, action, form, observation, browser-launch, and agent budgets;
- safe agent modes, `codex` or `opencode` provider/model selection, and agent
  success gating.

Direct `--username` and `--password` values are rejected; pass GitHub secrets
through named environment variables instead:

```yaml
- name: Run authenticated PTK scan
  uses: ptklabs/ptk-action@v1
  env:
    PTK_SCAN_USERNAME: ${{ secrets.PTK_SCAN_USERNAME }}
    PTK_SCAN_PASSWORD: ${{ secrets.PTK_SCAN_PASSWORD }}
  with:
    target: http://127.0.0.1:3000
    engines: DAST,IAST,SAST,SCA
    extra-args: |
      --username-env
      PTK_SCAN_USERNAME
      --password-env
      PTK_SCAN_PASSWORD
      --include-secrets
      --scenario
      test/ptk-login.md
```

The Action owns target, engines, browser, report paths, threshold behavior, and
strict PTK completion flags. It also forces site memory off so jobs do not
silently read or persist cross-run target state. Config replacement, custom
browser/extension/profile paths, output or lifecycle overrides, direct
credentials, aggressive/destructive modes, and unknown options fail before the
scan starts.

## Provider-assisted scans

PTK provider agents are supported in GitHub Actions; they are not disabled by
the Action safety boundary. Install and authenticate the matching `codex` or
`opencode` CLI in an earlier workflow step, then select it explicitly:

```yaml
- name: Run provider-assisted PTK scan
  uses: ptklabs/ptk-action@v1
  with:
    target: http://127.0.0.1:3000
    engines: DAST,IAST,SAST,SCA
    extra-args: |
      --agent-mode
      provider
      --agent-provider
      codex
      --agent-model
      your-approved-model
      --max-agent-turns
      3
      --max-provider-ms
      60000
      --require-agent-success
```

The Action does not install provider CLIs or accept provider API keys as Action
inputs. Supply provider authentication through that CLI's documented CI secret
environment, and do not expose provider secrets to workflows running untrusted
pull-request code. PTK keeps agent execution inside the same scan scope and
redacts replayable secrets from provider evidence, but prompts can still
contain application structure and security context; use only an approved
provider and data policy.

Agent modes remain safe by default. `--aggressive`,
`--allow-destructive-actions`, and destructive risk selection are deliberately
outside the v1 Action contract. Use the direct `pentestkit` CLI in a separately
controlled disposable environment when those behaviors are explicitly needed.

## Package acquisition

Published versions are installed by exact version from
`https://registry.npmjs.org/` using an isolated npm working directory and user
configuration. A scanned repository's `.npmrc` cannot redirect the
`pentestkit` package to a different registry. Enterprise mirrors are not an
implicit fallback in v1.

The optional workspace `.tgz` input is intended for PTK Agent package CI. Its
installed package name, CLI shape, path containment, and exact version must
match `pentestkit-version` before execution. npm lifecycle scripts remain
disabled for both acquisition modes.

## Workflow security

- Pin third-party Actions, including PTK, to full release commit SHAs when an
  immutable dependency is required.
- Do not combine `pull_request_target` with a checkout or execution of
  untrusted pull-request code.
- Give the job only the permissions it needs. SARIF upload needs
  `security-events: write`; ordinary artifact upload does not.
- Treat scan artifacts as security data and choose retention and access rules
  appropriate for the target.
- Provider-assisted scans must not expose CI secrets or unapproved application
  context to a third-party model provider.

## More information

- [OWASP Penetration Testing Kit](https://owasp.org/www-project-penetration-testing-kit/)
- [`pentestkit` on npm](https://www.npmjs.com/package/pentestkit)
- [PTK Agent automation documentation](https://github.com/ptklabs/ptk-agent/tree/main/docs/npm)
- [GitHub Actions integration guide](https://github.com/ptklabs/ptk-agent/blob/main/docs/npm/github-actions.md)

## License

OWASP PTK Security Scan is licensed under the
[GNU Affero General Public License v3.0](LICENSE.txt).
