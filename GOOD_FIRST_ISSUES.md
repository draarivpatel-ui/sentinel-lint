# Good first issues

Twenty self contained specifications. Each one is a single rule or adapter that
fits the existing engine without touching it. Claim one by opening a draft pull
request that references the issue number, and read
[CONTRIBUTING.md](CONTRIBUTING.md) first.

Every item follows the same contract:

- one `defineRule` descriptor in a new module under `src/rules/`
- one line added to `src/rules/index.mjs`
- a section in `docs/rules.md` with a heading whose text is the rule id
- a row in the README rule table
- tests with a finding fixture, a clean fixture and a near miss

Difficulty is labelled on each item. `starter` means a single file rule with a
plain substring or line check. `moderate` means light parsing or state across
lines. No item requires a new dependency.

---

### 1. Dockerfile: container runs as root

**Difficulty:** starter
**Rule id:** `containers/dockerfile-root-user`
**Files:** `src/rules/containers.mjs`, `src/rules/index.mjs`, `tests/rules-containers.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** `**/Dockerfile`, `**/Dockerfile.*`, `**/*.dockerfile`
**Detection:** split the file into instructions, ignoring comments and
continuations. Report when a `FROM` instruction is present and no `USER`
instruction appears after the final `FROM`. Report at the last `FROM` line.
**Near miss:** a multi stage build whose final stage sets `USER 10001`.
**Acceptance criteria:**
- [ ] finding for a Dockerfile with no `USER`
- [ ] clean for a Dockerfile whose final stage sets a non-root user
- [ ] message names the final base image and suggests a numeric uid
- [ ] severity `error`, CWE-250

### 2. Dockerfile: mutable base image

**Difficulty:** starter
**Rule id:** `containers/dockerfile-mutable-base`
**Files:** `src/rules/containers.mjs`, `src/rules/index.mjs`, `tests/rules-containers.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** the Dockerfile globs above
**Detection:** parse every `FROM` line. Report when the image reference has no
tag, uses `latest`, or uses a distro channel tag such as `stable`. Allow an
image pinned by digest (`@sha256:`).
**Near miss:** `FROM node:20.11.1-bookworm-slim` and `FROM alpine@sha256:...`.
**Acceptance criteria:**
- [ ] finding for `FROM node:latest` and for a bare `FROM ubuntu`
- [ ] clean for a version tag and for a digest
- [ ] severity `warning`, CWE-1357

### 3. Kubernetes: privileged container

**Difficulty:** starter
**Rule id:** `k8s/privileged-container`
**Files:** `src/rules/kubernetes.mjs`, `src/rules/index.mjs`, `tests/rules-kubernetes.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** `**/*.yaml`, `**/*.yml` under `k8s/`, `manifests/`, `deploy/`, `charts/`
**Detection:** line based. Report any line where
`securityContext` is followed by `privileged: true` within the same block, and
any `--privileged` in a command list. Keep it to indentation aware scanning,
the same approach the Actions adapter uses.
**Near miss:** `privileged: false` and `allowPrivilegeEscalation: false`.
**Acceptance criteria:**
- [ ] finding on a privileged pod spec and on `--privileged` in args
- [ ] clean for a hardened security context
- [ ] severity `critical`, CWE-250

### 4. Kubernetes: hostPath mount of a sensitive path

**Difficulty:** moderate
**Rule id:** `k8s/host-path-mount`
**Files:** `src/rules/kubernetes.mjs`, `src/rules/index.mjs`, `tests/rules-kubernetes.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** the Kubernetes globs above
**Detection:** track `hostPath:` blocks and their `path:` value. Report `/`,
`/etc`, `/var/run`, `/proc`, `/sys`, the container runtime socket and any path
that is a prefix of those. Report at the `path:` line.
**Near miss:** an `emptyDir` volume and a `hostPath` under `/var/tmp/build`.
**Acceptance criteria:**
- [ ] finding for `/var/run/docker.sock` and for `/etc`
- [ ] clean for `emptyDir` and for a scoped build directory
- [ ] severity `error`, CWE-732

### 5. Terraform: public bucket ACL

**Difficulty:** starter
**Rule id:** `terraform/public-bucket-acl`
**Files:** `src/rules/terraform.mjs`, `src/rules/index.mjs`, `tests/rules-terraform.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** `**/*.tf`
**Detection:** line based. Report `acl = "public-read"`,
`acl = "public-read-write"` and `acl = "website"`. Also report an
`aws_s3_bucket_public_access_block` whose `block_public_acls` is `false`.
**Near miss:** `acl = "private"` and a public access block with every flag true.
**Acceptance criteria:**
- [ ] finding for each public ACL value
- [ ] clean for private ACLs and a fully blocking access block
- [ ] severity `critical`, CWE-732

### 6. package.json: dependency from a git or http URL

**Difficulty:** starter
**Rule id:** `supply-chain/git-url-dependency`
**Files:** `src/rules/supply-chain.mjs`, `src/rules/index.mjs`, `tests/rules-supply-chain.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** `**/package.json`
**Detection:** parse with the existing JSON reader. Walk
`dependencies`, `devDependencies`, `optionalDependencies` and
`peerDependencies`. Report values starting with `git`, `git+`, `http://`,
`https://`, `file:` or a GitHub shorthand `user/repo`. Point at the value.
**Near miss:** a normal semver range and a `workspace:*` reference.
**Acceptance criteria:**
- [ ] finding for a git URL, an http tarball and a shorthand
- [ ] clean for semver and workspace protocol
- [ ] severity `warning`, CWE-1357

### 7. package.json: install lifecycle script

**Difficulty:** starter
**Rule id:** `supply-chain/lifecycle-script`
**Files:** `src/rules/supply-chain.mjs`, `src/rules/index.mjs`, `tests/rules-supply-chain.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** `**/package.json`
**Detection:** report `preinstall`, `install` and `postinstall` scripts whose
command contains a shell pipeline, `curl`, `wget`, `node -e` or a call to a
script outside the repository. Report at the script value.
**Near miss:** a `postinstall` that runs `node ./scripts/build.js` inside the
repository, which the spec marks as acceptable and therefore clean.
**Acceptance criteria:**
- [ ] finding for `curl ... | sh`
- [ ] clean for a local build script and for no lifecycle scripts
- [ ] severity `error`, CWE-829

### 8. .npmrc: TLS verification disabled

**Difficulty:** starter
**Rule id:** `supply-chain/npmrc-strict-ssl-off`
**Files:** `src/rules/supply-chain.mjs`, `src/rules/index.mjs`, `tests/rules-supply-chain.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** `**/.npmrc`
**Detection:** report `strict-ssl=false` in any spacing form, and any
`registry=` value that is not `https://`.
**Near miss:** comments that mention `strict-ssl=false` and an https registry.
**Acceptance criteria:**
- [ ] finding for the disabled flag and for an http registry
- [ ] clean for an https registry
- [ ] severity `error`, CWE-319

### 9. requirements.txt: plaintext package index

**Difficulty:** starter
**Rule id:** `supply-chain/pip-trusted-host`
**Files:** `src/rules/supply-chain.mjs`, `src/rules/index.mjs`, `tests/rules-supply-chain.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** `**/requirements*.txt`, `**/constraints*.txt`
**Detection:** report `--trusted-host`, `--index-url http://...` and
`--extra-index-url http://...`. Ignore full line comments.
**Near miss:** an https index URL and a pinned package line.
**Acceptance criteria:**
- [ ] finding for both flags and for an http index
- [ ] clean for https and for ordinary pins
- [ ] severity `error`, CWE-319

### 10. GitLab CI: mutable job image

**Difficulty:** starter
**Rule id:** `gitlab/mutable-image-tag`
**Files:** `src/rules/gitlab.mjs`, `src/rules/index.mjs`, `tests/rules-gitlab.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** `.gitlab-ci.yml`, `**/.gitlab-ci.yml`, `**/.gitlab/ci/*.yml`
**Detection:** find `image:` lines. Report an image with no tag or with
`latest`. Allow `@sha256:` digests.
**Near miss:** `image: node:20.11.1` and a digest reference.
**Acceptance criteria:**
- [ ] finding for a bare image and for `:latest`
- [ ] clean for a version tag and a digest
- [ ] severity `warning`, CWE-1357

### 11. CircleCI: mutable orb version

**Difficulty:** starter
**Rule id:** `circleci/mutable-orb`
**Files:** `src/rules/circleci.mjs`, `src/rules/index.mjs`, `tests/rules-circleci.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** `**/.circleci/config.yml`, `**/.circleci/config.yaml`
**Detection:** report `orbs:` entries whose reference is `volatile`, a major
only version such as `1`, or missing entirely. Report at the orb line.
**Near miss:** `node: circleci/node@5.2.0`.
**Acceptance criteria:**
- [ ] finding for volatile and major only references
- [ ] clean for a full semver orb
- [ ] severity `warning`, CWE-1357

### 12. Actions: secret written into a run block

**Difficulty:** moderate
**Rule id:** `actions/secret-in-run`
**Files:** `src/rules/actions.mjs`, `src/rules/index.mjs`, `tests/rules-actions.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** the workflow globs
**Detection:** reuse `collectRunBlocks`. Inside a run block, report any
`${{ secrets.NAME }}` expression. Masking happens at the log level, but echo,
`set -x` and command substitution still leak fragments, and secrets in scripts
are a common accidental disclosure.
**Near miss:** a secret passed through `env:` and referenced as a shell
variable, which is the documented safe pattern in `actions/script-injection`.
**Acceptance criteria:**
- [ ] finding for an interpolated secret in `run:`
- [ ] clean for a secret passed through `env:` only
- [ ] severity `warning`, CWE-532
- [ ] does not duplicate `actions/script-injection` for the same line

### 13. Actions: workflow_run with secrets

**Difficulty:** moderate
**Rule id:** `actions/workflow-run-secrets`
**Files:** `src/rules/actions.mjs`, `src/rules/index.mjs`, `tests/rules-actions.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** the workflow globs
**Detection:** report a workflow triggered by `workflow_run` that also
references `secrets.` anywhere in the file or uses `actions/checkout` with a
head branch ref. Report at the trigger line.
**Near miss:** a `workflow_run` workflow that only downloads an artifact and
comments without secrets.
**Acceptance criteria:**
- [ ] finding when the trigger and a secret reference coexist
- [ ] clean when the privileged workflow holds no secrets
- [ ] severity `critical`, CWE-829

### 14. Actions: workflow without a permissions block

**Difficulty:** starter
**Rule id:** `actions/missing-permissions`
**Files:** `src/rules/actions.mjs`, `src/rules/index.mjs`, `tests/rules-actions.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** the workflow globs
**Detection:** report a workflow that has no `permissions:` key at all. Report
at line 1. This pairs with `actions/write-all-permissions`, which catches the
opposite mistake.
**Near miss:** `permissions: {}` and a scoped read block.
**Acceptance criteria:**
- [ ] finding for a workflow with no permissions key
- [ ] clean for an empty block and for a scoped block
- [ ] severity `warning`, CWE-272

### 15. MCP: shell wrapper command

**Difficulty:** starter
**Rule id:** `mcp/shell-command-wrapper`
**Files:** `src/rules/mcp.mjs`, `src/rules/index.mjs`, `tests/rules-mcp.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** the MCP manifest matcher
**Detection:** report a server whose `command` basename is `sh`, `bash`,
`zsh`, `cmd`, `powershell` or `pwsh`. A manifest should start a program, not a
shell.
**Near miss:** `command: "node"` and `command: "python3"`.
**Acceptance criteria:**
- [ ] finding for `sh`, `bash` and `cmd`
- [ ] clean for a direct interpreter or binary
- [ ] severity `error`, CWE-78

### 16. MCP: auto approved dangerous tool

**Difficulty:** moderate
**Rule id:** `mcp/auto-approve-dangerous-tool`
**Files:** `src/rules/mcp.mjs`, `src/rules/index.mjs`, `tests/rules-mcp.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** the MCP manifest matcher
**Detection:** report a server with an auto approve or always allow list that
contains a tool name matching `write`, `delete`, `remove`, `exec`, `shell`,
`run` or `shell_command`. Report at the list item.
**Near miss:** an auto approve list containing only `read_file` and `search`.
**Acceptance criteria:**
- [ ] finding for a destructive tool in the list
- [ ] clean for read only tools
- [ ] severity `warning`, CWE-250

### 17. MCP: runtime environment override

**Difficulty:** starter
**Rule id:** `mcp/env-runtime-override`
**Files:** `src/rules/mcp.mjs`, `src/rules/index.mjs`, `tests/rules-mcp.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** the MCP manifest matcher
**Detection:** report an `env` entry whose key is `PATH`, `NODE_OPTIONS`,
`PYTHONPATH`, `LD_PRELOAD` or `DYLD_INSERT_LIBRARIES`. These change what other
programs load, so a manifest can redirect execution without changing the
command.
**Near miss:** a normal API base URL variable and an explicit `PATH` set to a
project binary directory listed in an allow list constant in the rule.
**Acceptance criteria:**
- [ ] finding for `NODE_OPTIONS` and `LD_PRELOAD`
- [ ] clean for ordinary variables
- [ ] severity `error`, CWE-427

### 18. Repository: committed .env file

**Difficulty:** starter
**Rule id:** `repo/committed-dotenv`
**Files:** `src/rules/repo.mjs`, `src/rules/index.mjs`, `tests/rules-repo.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** repository scope, no file globs
**Detection:** report when a scanned path matches `.env`, `.env.local`,
`.env.production` or `*.env` and the file contains at least one `KEY=value`
line with a non-empty value that is not an obvious placeholder. Point at the
first such line.
**Near miss:** `.env.example` with empty values and a template file with
placeholder values.
**Acceptance criteria:**
- [ ] finding for a committed `.env` with a real looking value
- [ ] clean for `.env.example` and empty values
- [ ] severity `critical`, CWE-538

### 19. Repository: Python shell invocation

**Difficulty:** moderate
**Rule id:** `repo/python-shell-true`
**Files:** `src/rules/python.mjs`, `src/rules/index.mjs`, `tests/rules-python.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** `**/*.py`
**Detection:** report `subprocess.` calls with `shell=True`, and
`os.system(` with an f-string or `%` formatting argument. Ignore comments.
**Near miss:** `subprocess.run(["ls", "-la"])` and `shell=False`.
**Acceptance criteria:**
- [ ] finding for `shell=True` and for `os.system(f"...")`
- [ ] clean for an argument list and for `shell=False`
- [ ] severity `error`, CWE-78

### 20. Repository: unsafe deserialization

**Difficulty:** moderate
**Rule id:** `repo/unsafe-deserialization`
**Files:** `src/rules/repo.mjs`, `src/rules/index.mjs`, `tests/rules-repo.test.mjs`, `docs/rules.md`, `README.md`
**Globs:** `**/*.py`, `**/*.js`, `**/*.mjs`, `**/*.ts`
**Detection:** report `pickle.loads(` and `pickle.load(`, `yaml.load(` without
a `Loader=SafeLoader` argument on the same line, `marshal.loads(` and
Node.js `v8.deserialize(`. Ignore comments and string literals with the same
masking helpers the other JavaScript rules use.
**Near miss:** `yaml.safe_load(` and `yaml.load(data, Loader=SafeLoader)`.
**Acceptance criteria:**
- [ ] finding for each unsafe call
- [ ] clean for the safe alternatives
- [ ] severity `error`, CWE-502
- [ ] docs entry explains that `yaml.load` behavior differs between library
      versions

---

When all twenty are implemented the built in pack grows from 15 to 35 rules.
Update the README counts and the rule table in the same pull request that adds
the last one.
