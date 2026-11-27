---
name: New rule proposal
about: Propose a security rule with a concrete failing shape
title: "rule: "
labels: new-rule
assignees: ""
---

## Rule id

`category/rule-name` (lowercase, hyphens, one slash).

## What it catches

One paragraph. Describe the failure mode, not the regex. What can an attacker
do because this shape exists?

## Failing shape

The smallest realistic input that should produce a finding. Redact anything
sensitive and use synthetic values.

```
paste the smallest failing example here
```

## Clean shapes that must not match

List at least two near misses. A rule that fires on clean code will be turned
off by users, which is worse than a rule that does not exist.

## Files it reads

Glob patterns, for example `.github/workflows/*.yml` or `**/requirements.txt`.
If the rule needs repository scope, say so and explain why a file rule cannot
express it.

## Severity and CWE

Proposed severity (`info`, `warning`, `error`, `critical`) and the closest CWE
identifier. Explain why it is not one level lower.

## Acceptance criteria

- [ ] `defineRule` descriptor with `rationale`, `fix` and a docs URL
- [ ] Finding fixture, clean fixture and a near miss in `tests/`
- [ ] Section in `docs/rules.md` with a matching heading
- [ ] Row in the README rule table
- [ ] `npm test` passes and `npm run self-scan` is clean

## Are you claiming this?

Say yes and open a draft pull request, or leave it for somebody else. See
GOOD_FIRST_ISSUES.md for ready to claim specifications.
