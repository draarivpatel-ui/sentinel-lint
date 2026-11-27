const TAG_RE = /^[\w][\w.-]{0,127}$/;
const REPOSITORY_COMPONENT_RE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const REGISTRY_RE = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]+)?$/;
const DIGEST_RE = /^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[a-f0-9]{32,}$/;

function invalidImageReference() {
  return { valid: false, name: null, registry: null, repository: null, tag: null, digest: null };
}

export function parseImageReference(reference) {
  if (typeof reference !== 'string' || reference.length === 0 || reference.trim() !== reference || /\s/.test(reference)) {
    return invalidImageReference();
  }

  let nameAndTag = reference;
  let digest = null;
  const at = nameAndTag.indexOf('@');
  if (at !== -1) {
    digest = nameAndTag.slice(at + 1);
    nameAndTag = nameAndTag.slice(0, at);
    if (nameAndTag.length === 0 || nameAndTag.includes('@') || !DIGEST_RE.test(digest)) return invalidImageReference();
  }

  const lastSlash = nameAndTag.lastIndexOf('/');
  const lastColon = nameAndTag.lastIndexOf(':');
  let name = nameAndTag;
  let tag = null;
  if (lastColon > lastSlash) {
    tag = nameAndTag.slice(lastColon + 1);
    name = nameAndTag.slice(0, lastColon);
    if (!TAG_RE.test(tag)) return invalidImageReference();
  }

  const segments = name.split('/');
  if (segments.some((segment) => segment.length === 0)) return invalidImageReference();
  const first = segments[0];
  const hasRegistry = first.includes('.') || first.includes(':') || first === 'localhost';
  const registry = hasRegistry ? first : null;
  if (registry !== null && !REGISTRY_RE.test(registry)) return invalidImageReference();
  const repositorySegments = hasRegistry ? segments.slice(1) : segments;
  if (repositorySegments.length === 0) return invalidImageReference();
  for (const segment of repositorySegments) {
    if (!REPOSITORY_COMPONENT_RE.test(segment) || segment === '.' || segment === '..') return invalidImageReference();
  }

  return {
    valid: true,
    name,
    registry,
    repository: repositorySegments.join('/'),
    tag,
    digest,
  };
}

export function isValidImageRepositoryPrefix(entry) {
  if (typeof entry !== 'string' || entry.length === 0 || entry.trim() !== entry || /\s/.test(entry) || entry.includes('@')) {
    return false;
  }
  const namespace = entry.endsWith('/');
  const base = namespace ? entry.slice(0, -1) : entry;
  if (base.length === 0 || base.endsWith('/')) return false;
  const parsed = parseImageReference(base);
  return parsed.valid && parsed.tag === null && parsed.digest === null;
}

export function imageRepositoryMatchesPrefix(name, prefix) {
  if (prefix.endsWith('/')) return name.startsWith(prefix) && name.length > prefix.length;
  return name === prefix;
}
