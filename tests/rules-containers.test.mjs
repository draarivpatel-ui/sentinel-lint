import test from 'node:test';
import assert from 'node:assert/strict';
import { byRule, scanTree } from './helpers.mjs';
import {
  collectDockerInstructions,
  isComposeFile,
  isDockerSocketVolumeLine,
  isDockerfile,
} from '../src/rules/containers.mjs';

function dockerScan(t, text, name = 'Dockerfile') {
  return scanTree(t, { [name]: `${text}\n` });
}

function composeScan(t, text, name = 'compose.yml') {
  return scanTree(t, { [name]: `${text}\n` });
}

function composeService(lines) {
  return ['services:', '  app:', '    image: example/app:1.0.0', ...lines].join('\n');
}

test('isDockerfile accepts the standard Dockerfile name', () => {
  assert.equal(isDockerfile({ name: 'Dockerfile' }), true);
});

test('isDockerfile accepts a suffixed Dockerfile name', () => {
  assert.equal(isDockerfile({ name: 'Dockerfile.prod' }), true);
});

test('isDockerfile accepts a .dockerfile suffix case insensitively', () => {
  assert.equal(isDockerfile({ name: 'Web.Dockerfile' }), true);
});

test('isDockerfile rejects an ordinary source file', () => {
  assert.equal(isDockerfile({ name: 'docker-setup.sh' }), false);
});

test('isComposeFile accepts compose.yml and docker-compose.yaml', () => {
  assert.equal(isComposeFile({ name: 'compose.yml' }), true);
  assert.equal(isComposeFile({ name: 'docker-compose.yaml' }), true);
});

test('isComposeFile rejects an ordinary workflow YAML file', () => {
  assert.equal(isComposeFile({ name: 'ci.yml' }), false);
});

test('collectDockerInstructions joins backslash continuations', () => {
  const instructions = collectDockerInstructions('FROM example/base:1\nRUN curl example.com \\\n  -o artifact\n');
  assert.equal(instructions.length, 2);
  assert.equal(instructions[1].instruction, 'RUN');
  assert.match(instructions[1].text, /curl example\.com\s+-o artifact/);
});

test('collectDockerInstructions ignores comment lines', () => {
  const instructions = collectDockerInstructions('# syntax=docker/dockerfile:1\nFROM example/base:1\n# RUN curl x | sh\n');
  assert.equal(instructions.length, 1);
  assert.equal(instructions[0].instruction, 'FROM');
});

test('container/missing-non-root-user flags a Dockerfile with no USER', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nCOPY app /app\n');
  const found = byRule(result, 'container/missing-non-root-user');
  assert.equal(found.length, 1);
  assert.equal(found[0].line, 1);
  assert.equal(found[0].severity, 'warning');
});

test('container/missing-non-root-user accepts a non-root USER', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nRUN useradd app\nUSER app\n');
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 0);
  assert.equal(byRule(result, 'container/explicit-root-user').length, 0);
});

test('container/explicit-root-user flags USER root', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nUSER root\n');
  const found = byRule(result, 'container/explicit-root-user');
  assert.equal(found.length, 1);
  assert.equal(found[0].line, 2);
  assert.equal(found[0].severity, 'error');
});

test('container/explicit-root-user flags numeric uid zero', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nUSER 0\n');
  assert.equal(byRule(result, 'container/explicit-root-user').length, 1);
});

test('container/explicit-root-user flags root with an explicit group', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nUSER root:root\n');
  assert.equal(byRule(result, 'container/explicit-root-user').length, 1);
});

test('container/explicit-root-user does not confuse rootless with root', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nUSER rootless\n');
  assert.equal(byRule(result, 'container/explicit-root-user').length, 0);
});

test('container root rules understand the final stage in a multistage build', async (t) => {
  const result = await dockerScan(
    t,
    'FROM example/builder:1.0.0 AS build\nUSER root\nRUN build-app\nFROM example/runtime:1.0.0\nUSER app\n',
  );
  assert.equal(byRule(result, 'container/explicit-root-user').length, 0);
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 0);
});

test('container/missing-non-root-user flags a final stage without USER', async (t) => {
  const result = await dockerScan(
    t,
    'FROM example/builder:1.0.0 AS build\nUSER app\nRUN build-app\nFROM example/runtime:1.0.0\nCOPY --from=build /out /app\n',
  );
  const found = byRule(result, 'container/missing-non-root-user');
  assert.equal(found.length, 1);
  assert.equal(found[0].line, 4);
});

test('container/missing-non-root-user ignores an explicitly trusted artifact-only scratch export', async (t) => {
  const result = await scanTree(
    t,
    { Dockerfile: `${[
      'FROM example/builder:1.0.0 AS build',
      'RUN build-app',
      'FROM scratch AS artifacts',
      'COPY --from=build /out /',
      '',
    ].join('\n')}\n` },
    { config: { trustedArtifactOnlyScratchStages: ['artifacts'] } },
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 0);
});

test('container/missing-non-root-user still flags a runnable scratch image with an entrypoint', async (t) => {
  const result = await dockerScan(
    t,
    [
      'FROM example/builder:1.0.0 AS build',
      'RUN build-app',
      'FROM scratch',
      'COPY --from=build /out/server /server',
      'ENTRYPOINT ["/server"]',
      '',
    ].join('\n'),
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user still flags a runnable scratch image with a command', async (t) => {
  const result = await dockerScan(
    t,
    ['FROM scratch', 'COPY server /server', 'CMD ["/server"]', ''].join('\n'),
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user does not treat a scratch stage with RUN as artifact-only', async (t) => {
  const result = await dockerScan(
    t,
    ['FROM scratch', 'COPY server /server', 'RUN /server --self-test', ''].join('\n'),
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/explicit-root-user still flags a scratch export with USER root', async (t) => {
  const result = await dockerScan(
    t,
    ['FROM scratch', 'COPY server /server', 'USER root', ''].join('\n'),
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 0);
  assert.equal(byRule(result, 'container/explicit-root-user').length, 1);
});

test('container/missing-non-root-user accepts an allowlisted nonroot base image contract', async (t) => {
  const result = await dockerScan(
    t,
    ['FROM gcr.io/distroless/static-debian13:nonroot-amd64', 'COPY server /server', 'ENTRYPOINT ["/server"]', ''].join('\n'),
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 0);
});

test('container/missing-non-root-user accepts a distroless debug nonroot tag', async (t) => {
  const result = await dockerScan(
    t,
    ['FROM gcr.io/distroless/base-debian13:debug-nonroot', 'COPY server /server', 'ENTRYPOINT ["/server"]', ''].join('\n'),
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 0);
});

test('container/missing-non-root-user does not trust a nonroot tag when a digest selects the image', async (t) => {
  const result = await dockerScan(
    t,
    [
      'FROM gcr.io/distroless/static-debian13:nonroot@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      'COPY server /server',
      'ENTRYPOINT ["/server"]',
      '',
    ].join('\n'),
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user still flags a runtime base without a nonroot contract', async (t) => {
  const result = await dockerScan(
    t,
    ['FROM example/runtime:latest', 'COPY server /server', 'ENTRYPOINT ["/server"]', ''].join('\n'),
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user does not trust nonroot outside the allowlist', async (t) => {
  const result = await dockerScan(
    t,
    ['FROM example/runtime:nonroot-amd64', 'COPY server /server', 'ENTRYPOINT ["/server"]', ''].join('\n'),
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user requires nonroot to be a whole tag component', async (t) => {
  const result = await dockerScan(
    t,
    ['FROM gcr.io/distroless/static-debian13:nonrootish', 'COPY server /server', 'ENTRYPOINT ["/server"]', ''].join('\n'),
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user accepts a configured nonroot image prefix', async (t) => {
  const rootless = [
    'FROM images.example.com/team/runtime:nonroot-amd64',
    'COPY server /server',
    'ENTRYPOINT ["/server"]',
    '',
  ].join('\n');
  const result = await scanTree(t, { Dockerfile: `${rootless}\n` }, { config: { trustedNonRootImages: ['images.example.com/team/'] } });
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 0);
});

test('container/missing-non-root-user still requires a nonroot tag for a configured prefix', async (t) => {
  const runtime = [
    'FROM images.example.com/team/runtime:latest',
    'COPY server /server',
    'ENTRYPOINT ["/server"]',
    '',
  ].join('\n');
  const result = await scanTree(t, { Dockerfile: `${runtime}\n` }, { config: { trustedNonRootImages: ['images.example.com/team/'] } });
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user warns for a copy-only scratch image without explicit artifact policy', async (t) => {
  const result = await dockerScan(
    t,
    ['FROM example/builder:1.0.0 AS build', 'RUN build-app', 'FROM scratch AS artifacts', 'COPY --from=build /out /', ''].join('\n'),
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user keeps the warning for trusted scratch exports with healthcheck onbuild or shell metadata', async (t) => {
  for (const instruction of ['HEALTHCHECK CMD /health', 'ONBUILD RUN /setup', 'SHELL ["/bin/sh", "-c"]']) {
    const result = await scanTree(t, {
      Dockerfile: ['FROM example/builder:1.0.0 AS build', 'RUN build-app', 'FROM scratch AS artifacts', 'COPY --from=build /out /', instruction, ''].join('\n'),
    }, { config: { trustedArtifactOnlyScratchStages: ['artifacts'] } });
    assert.equal(byRule(result, 'container/missing-non-root-user').length, 1, instruction);
  }
});

test('container/missing-non-root-user keeps the warning for trusted scratch exports without a cross stage copy', async (t) => {
  const result = await scanTree(t, {
    Dockerfile: ['FROM scratch AS artifacts', 'COPY server /server', ''].join('\n'),
  }, { config: { trustedArtifactOnlyScratchStages: ['artifacts'] } });
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user does not apply the scratch shortcut through a normally named stage', async (t) => {
  const result = await scanTree(t, {
    Dockerfile: ['FROM scratch AS artifacts', 'COPY --from=build /out /', 'FROM artifacts', ''].join('\n'),
  }, { config: { trustedArtifactOnlyScratchStages: ['artifacts'] } });
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user treats Docker tags as case sensitive', async (t) => {
  const result = await dockerScan(
    t,
    ['FROM gcr.io/distroless/static-debian13:NONROOT', 'COPY server /server', 'ENTRYPOINT ["/server"]', ''].join('\n'),
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user does not extend an exact trusted repository to a lookalike repository', async (t) => {
  const result = await scanTree(t, {
    Dockerfile: ['FROM myorg/app-evil:nonroot', 'COPY server /server', 'ENTRYPOINT ["/server"]', ''].join('\n'),
  }, { config: { trustedNonRootImages: ['myorg/app'] } });
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user accepts an exact trusted repository but requires slash boundaries for descendants', async (t) => {
  const exact = await scanTree(t, {
    Dockerfile: ['FROM myorg/app:nonroot', 'COPY server /server', 'ENTRYPOINT ["/server"]', ''].join('\n'),
  }, { config: { trustedNonRootImages: ['myorg/app'] } });
  assert.equal(byRule(exact, 'container/missing-non-root-user').length, 0);

  const childWithoutNamespace = await scanTree(t, {
    Dockerfile: ['FROM myorg/app/worker:nonroot', 'COPY server /server', 'ENTRYPOINT ["/server"]', ''].join('\n'),
  }, { config: { trustedNonRootImages: ['myorg/app'] } });
  assert.equal(byRule(childWithoutNamespace, 'container/missing-non-root-user').length, 1);

  const childWithNamespace = await scanTree(t, {
    Dockerfile: ['FROM myorg/app/worker:nonroot', 'COPY server /server', 'ENTRYPOINT ["/server"]', ''].join('\n'),
  }, { config: { trustedNonRootImages: ['myorg/app/'] } });
  assert.equal(byRule(childWithNamespace, 'container/missing-non-root-user').length, 0);
});

test('container/missing-non-root-user does not exempt invalid uppercase image repositories', async (t) => {
  const result = await scanTree(t, {
    Dockerfile: ['FROM images.example.com/team/RUNTIME:nonroot', 'COPY server /server', 'ENTRYPOINT ["/server"]', ''].join('\n'),
  }, { config: { trustedNonRootImages: ['images.example.com/team/'] } });
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container/missing-non-root-user keeps the warning for trusted scratch exports with runnable instructions', async (t) => {
  for (const instruction of ['ENTRYPOINT ["/server"]', 'CMD ["/server"]', 'RUN /server --self-test']) {
    const result = await scanTree(t, {
      Dockerfile: ['FROM example/builder:1.0.0 AS build', 'RUN build-app', 'FROM scratch AS artifacts', 'COPY --from=build /out /', instruction, ''].join('\n'),
    }, { config: { trustedArtifactOnlyScratchStages: ['artifacts'] } });
    assert.equal(byRule(result, 'container/missing-non-root-user').length, 1, instruction);
  }
});

test('container/missing-non-root-user does not trust a configured nonroot tag when a digest selects the image', async (t) => {
  const result = await scanTree(t, {
    Dockerfile: ['FROM images.example.com/team/runtime:nonroot@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'COPY server /server', 'ENTRYPOINT ["/server"]', ''].join('\n'),
  }, { config: { trustedNonRootImages: ['images.example.com/team/'] } });
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 1);
});

test('container root rules inherit USER from an earlier named stage', async (t) => {
  const result = await dockerScan(
    t,
    'FROM example/runtime:1.0.0 AS base\nUSER app\nFROM base\nCOPY app /app\n',
  );
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 0);
});

test('container root rules inherit an explicit root USER from a named stage', async (t) => {
  const result = await dockerScan(
    t,
    'FROM example/runtime:1.0.0 AS base\nUSER root\nFROM base\nCOPY app /app\n',
  );
  assert.equal(byRule(result, 'container/explicit-root-user').length, 1);
});

test('container/missing-non-root-user accepts a variable user because it is explicit', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nARG APP_USER\nUSER ${APP_USER}\n');
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 0);
});

test('container root rules ignore a commented out USER root', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\n# USER root\nUSER app\n');
  assert.equal(byRule(result, 'container/explicit-root-user').length, 0);
});

test('container root rules produce no finding for a Dockerfile fragment without FROM', async (t) => {
  const result = await dockerScan(t, 'USER root\n');
  assert.equal(byRule(result, 'container/explicit-root-user').length, 0);
  assert.equal(byRule(result, 'container/missing-non-root-user').length, 0);
});

test('container/curl-pipe-shell flags curl piped to sh', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nRUN curl -fsSL https://example.com/install.sh | sh\nUSER app\n');
  const found = byRule(result, 'container/curl-pipe-shell');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'critical');
});

test('container/curl-pipe-shell flags wget output piped to bash', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nRUN wget -qO- https://example.com/install.sh | bash\nUSER app\n');
  assert.equal(byRule(result, 'container/curl-pipe-shell').length, 1);
});

test('container/curl-pipe-shell flags sudo shell execution', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nRUN curl https://example.com/install.sh | sudo sh\nUSER app\n');
  assert.equal(byRule(result, 'container/curl-pipe-shell').length, 1);
});

test('container/curl-pipe-shell sees a quoted URL when the pipe is executable', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nRUN curl -fsSL "https://example.com/install.sh" | sh\nUSER app\n');
  assert.equal(byRule(result, 'container/curl-pipe-shell').length, 1);
});

test('container/curl-pipe-shell ignores a quoted text example that only prints', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nRUN echo "curl https://example.com/install.sh | sh"\nUSER app\n');
  assert.equal(byRule(result, 'container/curl-pipe-shell').length, 0);
});

test('container/curl-pipe-shell flags a shell -c wrapper', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nRUN sh -c "curl https://example.com/install.sh | sh"\nUSER app\n');
  assert.equal(byRule(result, 'container/curl-pipe-shell').length, 1);
});

test('container/curl-pipe-shell follows a line continuation', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nRUN curl -fsSL https://example.com/install.sh \\\n  | sh\nUSER app\n');
  assert.equal(byRule(result, 'container/curl-pipe-shell').length, 1);
});

test('container/curl-pipe-shell ignores a pinned download without shell execution', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nRUN curl -fsSL https://example.com/tool.tar.gz -o /tmp/tool.tar.gz\nUSER app\n');
  assert.equal(byRule(result, 'container/curl-pipe-shell').length, 0);
});

test('container/curl-pipe-shell ignores comments', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\n# RUN curl https://example.com/install.sh | sh\nUSER app\n');
  assert.equal(byRule(result, 'container/curl-pipe-shell').length, 0);
});

test('container/curl-pipe-shell reports the RUN instruction line', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nCOPY app /app\nRUN curl https://example.com/install.sh | sh\nUSER app\n');
  assert.equal(byRule(result, 'container/curl-pipe-shell')[0].line, 3);
});

test('container/remote-add flags an HTTP URL', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nADD http://example.com/tool.tar.gz /tmp/\nUSER app\n');
  const found = byRule(result, 'container/remote-add');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'warning');
});

test('container/remote-add flags an HTTPS URL', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nADD https://example.com/tool.tar.gz /tmp/\nUSER app\n');
  assert.equal(byRule(result, 'container/remote-add').length, 1);
});

test('container/remote-add accepts a local source path', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nADD artifacts/tool.tar.gz /tmp/\nUSER app\n');
  assert.equal(byRule(result, 'container/remote-add').length, 0);
});

test('container/remote-add accepts a checksummed remote artifact', async (t) => {
  const result = await dockerScan(
    t,
    'FROM example/base:1.0.0\nADD --checksum=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef https://example.com/tool.tar.gz /tmp/\nUSER app\n',
  );
  assert.equal(byRule(result, 'container/remote-add').length, 0);
});

test('container/remote-add does not flag COPY instructions', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nCOPY artifacts/tool.tar.gz /tmp/\nUSER app\n');
  assert.equal(byRule(result, 'container/remote-add').length, 0);
});

test('container/remote-add joins a continuation before scanning', async (t) => {
  const result = await dockerScan(t, 'FROM example/base:1.0.0\nADD \\\n  https://example.com/tool.tar.gz /tmp/\nUSER app\n');
  assert.equal(byRule(result, 'container/remote-add').length, 1);
});

test('container/privileged-mode flags privileged true', async (t) => {
  const result = await composeScan(t, composeService(['    privileged: true']));
  const found = byRule(result, 'container/privileged-mode');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'critical');
});

test('container/privileged-mode flags quoted or capitalized true values', async (t) => {
  for (const value of ['"true"', "'true'", 'TRUE']) {
    const result = await composeScan(t, composeService([`    privileged: ${value}`]));
    assert.equal(byRule(result, 'container/privileged-mode').length, 1, value);
  }
});

test('container/privileged-mode ignores privileged false', async (t) => {
  const result = await composeScan(t, composeService(['    privileged: false']));
  assert.equal(byRule(result, 'container/privileged-mode').length, 0);
});

test('container/privileged-mode ignores commented out configuration', async (t) => {
  const result = await composeScan(t, composeService(['    # privileged: true']));
  assert.equal(byRule(result, 'container/privileged-mode').length, 0);
});

test('container/host-network flags network_mode host', async (t) => {
  const result = await composeScan(t, composeService(['    network_mode: host']));
  const found = byRule(result, 'container/host-network');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'error');
});

test('container/host-network flags a quoted host value', async (t) => {
  const result = await composeScan(t, composeService(['    network_mode: "host"']));
  assert.equal(byRule(result, 'container/host-network').length, 1);
});

test('container/host-network accepts an isolated bridge network', async (t) => {
  const result = await composeScan(t, composeService(['    network_mode: bridge']));
  assert.equal(byRule(result, 'container/host-network').length, 0);
});

test('container/host-network ignores comments', async (t) => {
  const result = await composeScan(t, composeService(['    # network_mode: host']));
  assert.equal(byRule(result, 'container/host-network').length, 0);
});

test('isDockerSocketVolumeLine accepts short syntax host socket mounts', () => {
  assert.equal(isDockerSocketVolumeLine('- /var/run/docker.sock:/var/run/docker.sock'), true);
  assert.equal(isDockerSocketVolumeLine('  - "/var/run/docker.sock:/var/run/docker.sock"'), true);
});

test('isDockerSocketVolumeLine accepts long syntax source mounts', () => {
  assert.equal(isDockerSocketVolumeLine('source: /var/run/docker.sock'), true);
  assert.equal(isDockerSocketVolumeLine('- { type: bind, source: /var/run/docker.sock, target: /sock }'), true);
});

test('isDockerSocketVolumeLine rejects target only and lookalike paths', () => {
  assert.equal(isDockerSocketVolumeLine('- ./socket-copy:/var/run/docker.sock'), false);
  assert.equal(isDockerSocketVolumeLine('- /var/run/docker.sock.backup:/sock'), false);
});

test('container/docker-socket-mount flags short syntax in a service volume list', async (t) => {
  const result = await composeScan(
    t,
    composeService(['    volumes:', '      - /var/run/docker.sock:/var/run/docker.sock']),
  );
  const found = byRule(result, 'container/docker-socket-mount');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'critical');
});

test('container/docker-socket-mount flags long syntax source entries', async (t) => {
  const result = await composeScan(
    t,
    composeService(['    volumes:', '      - type: bind', '        source: /var/run/docker.sock', '        target: /run/docker.sock']),
  );
  assert.equal(byRule(result, 'container/docker-socket-mount').length, 1);
});

test('container/docker-socket-mount flags a same-line flow volume list', async (t) => {
  const result = await composeScan(
    t,
    composeService(['    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]']),
  );
  const found = byRule(result, 'container/docker-socket-mount');
  assert.equal(found.length, 1);
  assert.equal(found[0].line, 4);
  assert.equal(found[0].column, 16);
});

test('container/docker-socket-mount flags a multiline flow volume list', async (t) => {
  const result = await composeScan(
    t,
    composeService(['    volumes: [', '      "./app:/app",', '      "/var/run/docker.sock:/var/run/docker.sock",', '    ]']),
  );
  const found = byRule(result, 'container/docker-socket-mount');
  assert.equal(found.length, 1);
  assert.equal(found[0].line, 6);
  assert.equal(found[0].column, 8);
});

test('container/docker-socket-mount flags a flow mapping inside a flow volume list', async (t) => {
  const result = await composeScan(
    t,
    composeService(['    volumes: [{ type: bind, source: /var/run/docker.sock, target: /sock }]']),
  );
  assert.equal(byRule(result, 'container/docker-socket-mount').length, 1);
});

test('container/docker-socket-mount flags a flow volume list starting on the next line', async (t) => {
  const result = await composeScan(
    t,
    composeService(['    volumes:', '      [', '        "/var/run/docker.sock:/var/run/docker.sock",', '      ]']),
  );
  const found = byRule(result, 'container/docker-socket-mount');
  assert.equal(found.length, 1);
  assert.equal(found[0].line, 6);
});

test('container/docker-socket-mount does not flag a flow target only socket path', async (t) => {
  const result = await composeScan(
    t,
    composeService(['    volumes: ["./socket-copy:/var/run/docker.sock"]']),
  );
  assert.equal(byRule(result, 'container/docker-socket-mount').length, 0);
});

test('container/docker-socket-mount does not flag the socket as only a target', async (t) => {
  const result = await composeScan(
    t,
    composeService(['    volumes:', '      - ./socket-copy:/var/run/docker.sock']),
  );
  assert.equal(byRule(result, 'container/docker-socket-mount').length, 0);
});

test('container/docker-socket-mount does not scan outside the volumes block', async (t) => {
  const result = await composeScan(
    t,
    composeService(['    command: ["echo", "/var/run/docker.sock"]', '    volumes:', '      - ./app:/app']),
  );
  assert.equal(byRule(result, 'container/docker-socket-mount').length, 0);
});

test('container/docker-socket-mount reports the mount line', async (t) => {
  const result = await composeScan(
    t,
    composeService(['    volumes:', '      - ./app:/app', '      - /var/run/docker.sock:/var/run/docker.sock']),
  );
  const found = byRule(result, 'container/docker-socket-mount');
  assert.equal(found[0].line, 6);
});

test('container compose rules do not scan ordinary YAML files', async (t) => {
  const result = await scanTree(t, {
    'config.yml': 'services:\n  app:\n    privileged: true\n    network_mode: host\n',
  });
  assert.equal(byRule(result, 'container/privileged-mode').length, 0);
  assert.equal(byRule(result, 'container/host-network').length, 0);
});

test('container dockerfile rules do not scan shell scripts', async (t) => {
  const result = await scanTree(t, {
    'docker-setup.sh': 'curl https://example.com/install.sh | sh\n',
  });
  assert.equal(byRule(result, 'container/curl-pipe-shell').length, 0);
});

test('a minimal non-root Dockerfile produces no container findings', async (t) => {
  const result = await dockerScan(
    t,
    'FROM example/base:1.0.0\nCOPY app /app\nUSER 10001\nENTRYPOINT ["/app/server"]\n',
  );
  assert.equal(result.findings.filter((finding) => finding.category === 'container').length, 0);
});

test('a minimal isolated Compose service produces no container findings', async (t) => {
  const result = await composeScan(
    t,
    composeService(['    privileged: false', '    network_mode: bridge', '    volumes:', '      - ./app:/app:ro']),
  );
  assert.equal(result.findings.filter((finding) => finding.category === 'container').length, 0);
});
