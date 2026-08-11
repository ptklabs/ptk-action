# Security Policy

Please report suspected vulnerabilities privately through the repository's
[GitHub security advisory form](https://github.com/ptklabs/ptk-action/security/advisories/new).
Do not include credentials, API keys, customer targets, or unredacted scan
artifacts in a public issue.

The Action accepts application and provider authentication only through the
calling workflow's environment. Do not pass secret values through Action
inputs or `extra-args`, and do not run secret-bearing provider workflows on
untrusted pull-request code.
