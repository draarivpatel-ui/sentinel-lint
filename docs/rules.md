# Rule reference

Every rule below is part of the built in pack and is loaded through the same
public `defineRule` contract that third-party plugins use. Anchors match the
`docsUrl` value on each rule, which is what SARIF readers open.

Severity meanings:

- `critical`: direct path to secret disclosure or code execution, fail the build
- `error`: a real weakness that needs a human decision, fail the build
- `warning`: supply chain or disclosure hygiene, fail the build by default
- `info`: reserved for plugin rules that annotate without blocking

## actions/script-injection

- Severity: critical
- CWE: CWE-94
- Files: `.github/workflows/*.yml`, `.github/workflows/*.yaml`

Catches a GitHub expression from an attacker controlled context placed directly
inside a `run:` script, including block scalars. Pull request titles, issue
bodies, commit messages, branch names and `workflow_dispatch` inputs are all
outside contributor controlled.

```yaml
# finding
- run: echo "${{ github.event.pull_request.title }}"

# safe
- run: echo "$TITLE"
  env:
    TITLE: ${{ github.event.pull_request.title }}
```

The engine reads workflow YAML line by line. That is deliberate: a partially
malformed workflow is common in the wild and a line reader still finds the
dangerous line instead of rejecting the whole file.

## actions/unpinned-action

- Severity: warning
- CWE: CWE-1357
- Files: `.github/workflows/*.yml`, `.github/workflows/*.yaml`

Flags a third-party `uses:` reference that is a tag, a branch or missing
entirely. Tags move. The reference implementation of this attack class is a
maintainer account takeover followed by a retag.

```yaml
# finding
- uses: some-org/some-action@v4

# safe
- uses: some-org/some-action@0123456789abcdef0123456789abcdef01234567
```

First-party `actions/*` and `github/*` references, local `./path` actions and
`docker://` references are exempt. Docker references are a separate supply
chain problem that this rule does not model.

## actions/write-all-permissions

- Severity: error
- CWE: CWE-272
- Files: workflow files

Flags `permissions: write-all`, quoted or not. A workflow with a write scoped
token and one compromised step can push to the default branch, publish
packages, edit releases and rewrite issues. Most jobs need `contents: read`.

## actions/pull-request-target-checkout

- Severity: critical
- CWE: CWE-829
- Files: workflow files

Flags a workflow that uses `pull_request_target` (mapping, inline or list form)
and then checks out the pull request head or the fork repository. That
combination runs outside code with base repository secrets and a write token.

```yaml
on: pull_request_target
steps:
  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
    with:
      ref: ${{ github.event.pull_request.head.sha }}   # finding
```

The safe pattern is two workflows: an unprivileged `pull_request` workflow that
builds and uploads an artifact, and a privileged `workflow_run` workflow that
reads the artifact and never executes it.

## mcp/plaintext-secret

- Severity: critical
- CWE: CWE-798
- Files: `mcp.json`, `.mcp.json`, `claude_desktop_config.json`,
  `mcp-config.json`, `mcp_servers.json`, and any `.json` file containing an
  `mcpServers` key

Flags literal credentials in `env`, `headers`, URL query parameters and
`args`. Both documented manifest shapes are understood: `mcpServers` and
`servers`. Values that are environment references, template expressions,
placeholder text, file paths or plain endpoints are ignored.

```json
{
  "mcpServers": {
    "github": {
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_REDACTED" }
    }
  }
}
```

Rotate anything that was committed. Deleting the line in a later commit does
not remove it from history.

## mcp/unpinned-npx-package

- Severity: warning
- CWE: CWE-1357
- Files: MCP manifests

Flags `npx` based servers whose package has no exact version, including scoped
packages and the `-p`, `--package` and `--call` forms. Every launch can resolve
a different upstream release, running unreviewed code with the privileges of
the MCP client.

Pin `@scope/server@1.4.2` and update deliberately.

## mcp/shell-metacharacter-arg

- Severity: error
- CWE: CWE-78
- Files: MCP manifests

Flags command strings and arguments containing `;`, `&&`, `||`, `|`, backtick
substitution, `$(` or a newline. A manifest should carry a program and literal
arguments. If an argument contains shell syntax, some layer is passing strings
to a shell, and tool input can become code.

## mcp/broad-filesystem-root

- Severity: error
- CWE: CWE-732
- Files: MCP manifests

Flags a filesystem server argument that resolves to `/`, `~`, a drive root or a
UNC share, in both positional and `--root=/` form. A server rooted at `/` can
read SSH keys, browser profiles and every other repository on the machine.

## mcp/insecure-remote-url

- Severity: error
- CWE: CWE-319
- Files: MCP manifests

Flags `http://` endpoints for remote servers, whether in a URL field or in
arguments. Loopback addresses are exempt because local development over plain
HTTP is normal and does not cross a network.

## mcp/invalid-config

- Severity: warning
- Files: MCP manifests

Reports a manifest that is not valid JSON after comments and trailing commas
are accepted. The failure mode this prevents is subtle: a client and a scanner
can disagree about a file, and the scanner silently reports nothing.

## repo/hardcoded-token

- Severity: critical
- CWE: CWE-798
- Files: every text file except MCP manifests

Finds vendor credential shapes for AWS access key ids, GitHub tokens (classic
and fine grained), Slack tokens, Stripe live keys, Google API keys, npm tokens,
Anthropic and OpenAI style keys, Hugging Face tokens and PEM private key
headers. Documentation lines containing words such as `example`, `placeholder`
or `your_` are skipped.

The patterns match synthetic formats only. No real credential is embedded in
this repository or its tests.

## repo/dangerous-eval

- Severity: error
- CWE: CWE-95
- Files: `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.html`, `.htm`, `.vue`,
  `.svelte`

Flags `eval(` and `new Function(` outside comments and string literals. Comments
and strings are blanked with a scanner that preserves offsets, so reported line
and column values still match the source.

## repo/dangerous-html-sink

- Severity: error
- CWE: CWE-79
- Files: the same JavaScript and markup globs

Flags `dangerouslySetInnerHTML`, `.innerHTML =` / `.outerHTML =` and
`document.write`. Use `textContent`, an escaping template engine or a
maintained sanitizer.

## repo/child-process-injection

- Severity: error
- CWE: CWE-78
- Files: JavaScript globs that mention `child_process`

Flags `exec` and `execSync` calls whose first argument is a template literal
with interpolation or a concatenation. Use `execFile` or `spawn` with an
argument array so no shell parses the data.

```js
// finding
exec(`convert ${userPath} out.png`);

// safe
execFile('convert', [userPath, 'out.png']);
```

## repo/missing-security-policy

- Severity: warning
- Files: repository scope

Reports a repository with no `SECURITY.md` at the root, in `.github/` or in
`docs/`. The finding points at the README when one exists so editors can jump
somewhere useful. Without a policy, reporters often publish reproduction steps
in a public issue before a fix exists.

## Adding a rule

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the contract and
[GOOD_FIRST_ISSUES.md](../GOOD_FIRST_ISSUES.md) for ready to claim
specifications.
