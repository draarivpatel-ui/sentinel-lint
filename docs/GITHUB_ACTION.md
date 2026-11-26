# GitHub Action

sentinel-lint ships as a composite GitHub Action. It uses the Node.js runtime
already present on GitHub hosted runners, invokes no shell commands internally,
and writes SARIF 2.1.0 that GitHub Code Scanning accepts directly.

## Basic pull request check

```yaml
name: security

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  sentinel-lint:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@v4
      - name: sentinel-lint
        uses: draarivpatel-ui/sentinel-lint@v0.2.0
        with:
          path: .
          fail-on: high
```

The step fails when a finding reaches the selected threshold. The default
`high` threshold means `error` and `critical` findings fail the step.

## GitHub Code Scanning

```yaml
name: security-scanning

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  sentinel-lint:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@v4
      - name: sentinel-lint
        id: sentinel
        uses: draarivpatel-ui/sentinel-lint@v0.2.0
        with:
          path: .
          format: sarif
          sarif-file: sentinel-lint.sarif
          fail-on: high
      - name: upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.sentinel.outputs.sarif-file }}
```

When `path` is a subdirectory, artifact URIs in the SARIF file are prefixed
back onto the workspace relative path so code scanning annotations land on the
correct files.

## Inputs

| Input | Default | Meaning |
| ----- | ------- | ------- |
| `path` | `.` | Directory or file to scan. The resolved path must stay inside the GitHub workspace. |
| `config` | empty | Optional path to a `.sentinelrc.json` file. |
| `format` | `sarif` | `sarif`, `text` or `json`. `text` uses the human terminal reporter. |
| `sarif-file` | `sentinel-lint.sarif` | SARIF output file used when `format` is `sarif`. It must stay inside the workspace. |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low` or `none`. |
| `args` | empty | Extra validated scan flags. Supported flags are `--include`, `--exclude`, `--plugin`, `--max-findings`, `--quiet`, `--color` and `--no-color`. |

The action input severities map onto the CLI severity names like this:

| Action value | CLI threshold | Behavior |
| ------------ | ------------- | -------- |
| `critical` | `critical` | Only critical findings fail |
| `high` | `error` | Error and critical findings fail |
| `medium` | `warning` | Warning, error and critical findings fail |
| `low` | `info` | Every finding fails |
| `none` | `off` | Findings are reported but never fail the step |

## Outputs

| Output | Meaning |
| ------ | ------- |
| `sarif-file` | Path to the generated SARIF file, empty when `format` is not `sarif` |
| `findings-count` | Total findings reported by the scan |
| `exit-code` | sentinel-lint exit code, using the same contract as the CLI |

Example using outputs:

```yaml
- name: sentinel-lint
  id: sentinel
  uses: draarivpatel-ui/sentinel-lint@v0.2.0
  with:
    fail-on: none
- name: print count
  run: echo "findings=${{ steps.sentinel.outputs.findings-count }}"
```

## Extra arguments

`args` is parsed as data, never evaluated by a shell. Quote values that contain
spaces. Flags that would override the dedicated action inputs, such as
`--format`, `--output`, `--config` and `--fail-on`, are rejected.

```yaml
- name: sentinel-lint
  uses: draarivpatel-ui/sentinel-lint@v0.2.0
  with:
    args: --exclude 'generated/**' --exclude 'vendor/**' --max-findings 50
```

A plugin is executable JavaScript. Use `--plugin` only for a trusted file in
the checked out workspace, exactly as you would treat a package install script.

## Step summary

Every completed scan appends a compact markdown table to
`GITHUB_STEP_SUMMARY`. Finding text is escaped before it is written so file
names and plugin messages cannot inject HTML or break the table.

## Security properties

- Input expressions are assigned to environment variables in `action.yml` and
  are never interpolated into a shell script.
- The runner is a Node.js program that scans through the same engine as the
  CLI. It does not call a shell.
- Scan, config, plugin and SARIF paths must resolve inside the workspace after
  symbolic links are resolved.
- `args` accepts only known long options and treats shell metacharacters as
  literal argument text.
- The composite action itself is covered by the repository self-scan, which
  also scans composite action metadata for script injection.

## How this repository validates the action

The CI workflow runs `npm test` and `npm run self-scan` on Linux and Windows
with Node.js 18, 20, 22 and 24. A separate smoke job invokes `uses: ./` on both
operating systems against `examples/clean-repo` and `examples/vulnerable-repo`,
then validates the outputs and parses the generated SARIF as version 2.1.0.
