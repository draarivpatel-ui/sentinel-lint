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
- Files: `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `action.yml`, `action.yaml`, `.github/actions/*/action.yml`, `.github/actions/*/action.yaml`

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
- Files: `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `action.yml`, `action.yaml`, `.github/actions/*/action.yml`, `.github/actions/*/action.yaml`

Flags a third-party `uses:` reference that is a tag, a branch or missing
entirely. Tags move. The reference implementation of this attack class is a
maintainer account takeover followed by a retag.

```yaml
# finding
- uses: some-org/some-action@v4

# safe
- uses: some-org/some-action@0123456789abcdef0123456789abcdef01234567
```

First-party `actions/*` and `github/*` references, workspace-local `./path`
actions, self-repository `$/path` actions and `docker://` references are exempt.
Docker references are a separate supply chain problem that this rule does not
model. A narrow exception can be declared with the `trustedActions` config array
for an owner such as `example-org` or a repository prefix such as
`example-org/example-action`; pinning to a commit SHA remains the stronger
default.

During a directory scan the rule also reads `.github/workflows/actions.lock`
when it is present. For lockfile schema `v0.0.3`, the scanner validates the
supported schema before trusting it: only the documented sections and fields,
no duplicate canonical keys or repeated sections, required `ref`, `commit`,
`owner_id` and `repo_id` fields with the correct types, valid dependency pins,
consistent ref and commit metadata, complete workflow and uses-graph
references, and no uses cycles. The complete YAML `uses:` scalar is decoded
before comparison, so quoted values cannot hide a different dependency.

A visible tag is accepted only for an eligible `.github/workflows/*.yml` or
`.github/workflows/*.yaml` file when that exact workflow path is onboarded,
the exact dependency key is listed there and the dependency records a valid
algorithm-prefixed hexadecimal commit. Composite action metadata never receives
lockfile suppression. Owner and repository casing is canonicalized, while ref
spelling and action path casing stay significant. If the lockfile is absent,
incomplete, stale or malformed for any part of the schema, the warning remains
and reports that the action is not commit-pinned in the workflow or lockfile.

## actions/write-all-permissions

- Severity: error
- CWE: CWE-272
- Files: workflow files and composite action metadata

Flags `permissions: write-all`, quoted or not. A workflow with a write scoped
token and one compromised step can push to the default branch, publish
packages, edit releases and rewrite issues. Most jobs need `contents: read`.

## actions/pull-request-target-checkout

- Severity: critical
- CWE: CWE-829
- Files: workflow files and composite action metadata

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

## actions/missing-permissions

- Severity: warning
- CWE: CWE-272
- OWASP: A05:2021-Security Misconfiguration
- Files: `.github/workflows/*.yml`, `.github/workflows/*.yaml`

Flags jobs that are not covered by an explicit `permissions` block. A workflow
level block covers every job. Without one, each job needs its own least
privilege declaration. A step input that happens to be named `permissions` does
not count because the reader understands workflow and job indentation.

```yaml
# finding
jobs:
  test:
    runs-on: ubuntu-latest

# safe
permissions:
  contents: read
```

The rule is a warning rather than a proof of exploitability: repository token
defaults differ, and some repositories intentionally set them read only. The
finding still matters because those defaults can change without a code review.

## actions/env-file-injection

- Severity: critical
- CWE: CWE-94
- OWASP: A03:2021-Injection
- Files: workflow files and composite action metadata

Flags attacker controlled GitHub expressions written to `GITHUB_ENV` or
`GITHUB_PATH`. Those files are runner command files, not ordinary output. A
pull request title, issue body, branch name or dispatch input written there can
poison later steps or alter executable resolution.

```yaml
# finding
- run: echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"

# safe when the value is only data for this one shell command
- run: echo "$TITLE"
  env:
    TITLE: ${{ github.event.pull_request.title }}
```

The scanner keeps independent commands in one `run:` block separate. A safe
write to `GITHUB_ENV` does not become dangerous merely because a later command
prints untrusted text to stdout. Continuation lines, heredocs, CRLF input and
multiline GitHub expressions are followed.

## agent/bidi-unicode-override

- Severity: critical
- CWE: CWE-838
- OWASP: LLM01:2023 Prompt Injection
- Files: `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, `SKILL.md` and `.github/copilot-instructions.md`

Flags Unicode bidirectional override and isolate characters in files that AI
coding agents read automatically. These characters can make rendered text appear
in one order while the model reads the underlying bytes in another, the same
Trojan Source trick that hides hostile instructions inside apparently benign
text.

The covered ranges are U+202A through U+202E and U+2066 through U+2069. Escaped
text such as the six characters `\u202e` is not flagged; only the real control
character is. Remove the control and rewrite the instruction plainly.

## agent/invisible-zero-width-unicode

- Severity: error
- CWE: CWE-838
- OWASP: LLM01:2023 Prompt Injection
- Files: agent instruction files

Flags invisible zero width characters U+200B through U+200F, a byte order mark
in the middle of a file, and Unicode tag characters U+E0000 through U+E007F.
These code points are invisible in most editors and can carry a hidden second
instruction stream.

A zero width joiner inside a recognizable emoji sequence is ignored because
that use is visible and legitimate. A zero width joiner embedded in ordinary
instruction text is still reported.

## agent/shell-override-instruction

- Severity: critical
- CWE: CWE-829
- OWASP: LLM01:2023 Prompt Injection
- Files: agent instruction files

Flags instructions that tell an agent to execute network content through a
shell, such as `curl ... | sh` or `wget ... | bash`, and instructions that tell
the agent to disable, bypass, ignore or not report security checks.

Protective documentation is not the target. A sentence such as "Never run curl
... | sh" is ignored, while an imperative instruction to run it is reported.
Quoted shell text that only prints an example is not confused with an executable
pipe, but a `sh -c` wrapper is.

## agent/exfiltration-instruction

- Severity: critical
- CWE: CWE-200
- OWASP: LLM01:2023 Prompt Injection
- Files: agent instruction files

Flags `curl` or `wget` instructions that upload credential references,
environment files or SSH private keys with a data or upload flag. Examples of
sensitive references are `$GITHUB_TOKEN`, another token or key variable,
`.env`, `~/.ssh` and common private key file names.

An authorization header used for an ordinary API request is not treated as
exfiltration because the credential is not being uploaded as data to a collector.
Protective warnings that tell the reader never to run the command are ignored.

## container/missing-non-root-user

- Severity: warning
- CWE: CWE-250
- OWASP: A05:2021-Security Misconfiguration
- Files: `Dockerfile`, `Dockerfile.*` and `*.dockerfile`

Flags a final image stage with no effective `USER` instruction. Multistage
builds are resolved through named stages, so a final `FROM base` inherits a
`USER` set in `base`. A variable such as `USER ${APP_USER}` counts as an
explicit decision because the scanner cannot evaluate build arguments.

A final literal `FROM scratch` stage is treated as artifact-only only when its
exact stage alias is listed in `trustedArtifactOnlyScratchStages`, it contains
a cross-stage `COPY`, and every instruction is limited to file transfer or
non-runtime metadata. `ENTRYPOINT`, `CMD`, `RUN`, `HEALTHCHECK`, `ONBUILD`,
`SHELL`, and other runtime-oriented instructions keep the finding. A normally
named final stage never receives the literal-scratch shortcut. The artifact
suppression never applies to `container/explicit-root-user`.

The rule also recognizes a narrow external non-root contract: the image must
be exactly the configured repository, or below a configured namespace prefix
ending in `/`, or under the built in `gcr.io/distroless/` prefix. Its tag must
contain lowercase `nonroot` as a whole component when split on hyphens,
underscores and dots; Docker tags are case sensitive. When a reference includes
a digest, the digest selects the image and tag inference is never trusted. A
random image whose tag merely contains the letters `nonroot` is still flagged.
Ending the final stage with an explicit non-root user remains the most
reviewable contract.

## container/explicit-root-user

- Severity: error
- CWE: CWE-250
- OWASP: A05:2021-Security Misconfiguration
- Files: Dockerfiles

Flags a final image whose effective user is `root`, uid `0` or root with an
explicit group. Intermediate build stages may use root when the final stage
switches back; only the runtime image is reported.

## container/curl-pipe-shell

- Severity: critical
- CWE: CWE-494
- OWASP: A08:2021-Software and Data Integrity Failures
- Files: Dockerfiles

Flags `RUN` instructions that pipe `curl` or `wget` output into `sh`, `bash` or
another shell, including `sudo` wrappers, shell `-c` wrappers and backslash
continuations. A quoted echo example that only prints text is not flagged.

Use a pinned artifact and verify a checksum or signature before execution.

## container/remote-add

- Severity: warning
- CWE: CWE-494
- OWASP: A08:2021-Software and Data Integrity Failures
- Files: Dockerfiles

Flags `ADD http://` and `ADD https://` remote fetches without a `--checksum`.
Remote `ADD` hides a network fetch in image metadata and historically bypasses
the expectations reviewers have for ordinary `COPY` instructions. A checksummed
remote artifact is accepted because its integrity is pinned.

## container/privileged-mode

- Severity: critical
- CWE: CWE-250
- OWASP: A05:2021-Security Misconfiguration
- Files: Compose YAML files whose names contain `compose`

Flags `privileged: true` in Compose services, including quoted or capitalized
forms. Privileged mode grants broad host capabilities and device access. Use a
specific capability or device mapping only after confirming that no narrower
integration exists.

## container/host-network

- Severity: error
- CWE: CWE-668
- OWASP: A05:2021-Security Misconfiguration
- Files: Compose YAML files

Flags `network_mode: host`. Host networking removes the network namespace
boundary, bypasses published port review and can expose listeners directly on
host interfaces. Use explicit Compose networks and ports instead.

## container/docker-socket-mount

- Severity: critical
- CWE: CWE-732
- OWASP: A05:2021-Security Misconfiguration
- Files: Compose YAML files

Flags a service volume whose source is `/var/run/docker.sock`, in both short
syntax and long `source:` syntax. The Docker socket controls the host daemon,
so write access is effectively host root. A target path that happens to be
`/var/run/docker.sock` without the host socket as source is not enough for a
finding.

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
