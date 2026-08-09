# workflow-guard

Security-policy linter and hardening tool for GitHub Actions workflows.

`workflow-guard` scans `.github/workflows/*.yml` and `.yaml` files for common security and reliability problems:

- unpinned actions
- missing permissions
- excessive permissions
- dangerous `pull_request_target` usage
- script injection from untrusted GitHub event context
- secret echo patterns
- missing timeout limits

## Install

```bash
npm install workflow-guard
```

## CLI usage

Scan the current repository:

```bash
workflow-guard scan .
```

Scan with SARIF output:

```bash
workflow-guard scan . --format sarif --output workflow-guard.sarif
```

Fail on warnings too:

```bash
workflow-guard scan . --fail-on warning
```

Use a config file:

```bash
workflow-guard scan . --config workflow-guard.yml
```

## GitHub Action usage

```yaml
name: workflow-guard

on:
  pull_request:
  push:

permissions:
  contents: read

jobs:
  workflow-guard:
    timeout-minutes: 10
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fse08877-netizen/workflow-guard@v0
        with:
          fail_on: error
          format: pretty
```

## Configuration

Example `workflow-guard.yml`:

```yaml
version: 1
failOn: error

rules:
  unpinned-action:
    enabled: true
    allowed:
      - actions/checkout@v4
      - actions/setup-node@v4

  missing-permissions:
    enabled: true

  excessive-permissions:
    enabled: true

  dangerous-pull-request-target:
    enabled: true

  script-injection:
    enabled: true

  secret-echo:
    enabled: true

  missing-timeout:
    enabled: true
```

## Rules

| Rule | Severity | Description |
|---|---|---|
| `parse-error` | error | Workflow YAML cannot be parsed. |
| `unpinned-action` | warning | Action is not pinned by full commit SHA. |
| `missing-permissions` | warning | Workflow has no top-level permissions block. |
| `excessive-permissions` | error | Workflow uses `permissions: write-all`. |
| `dangerous-pull-request-target` | warning | Workflow uses `pull_request_target`. |
| `script-injection` | error | GitHub event context is interpolated directly. |
| `secret-echo` | warning | Secret may be printed to logs. |
| `missing-timeout` | warning | Workflow has no timeout limit. |

## Development

```bash
git clone https://github.com/fse08877-netizen/workflow-guard.git
cd workflow-guard
npm install
npm test
```

## Security

This tool helps reduce GitHub Actions risk. It is not a complete guarantee of pipeline security.

## License

MIT
