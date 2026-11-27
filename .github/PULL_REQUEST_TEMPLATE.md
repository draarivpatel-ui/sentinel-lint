## What this changes

One paragraph. Link the issue if there is one.

## Failure mode

What goes wrong today, and what changes after this pull request? For a new
rule, include the smallest failing input and the nearest clean input.

## Checklist

- [ ] `npm test` passes with no skipped tests
- [ ] `npm run self-scan` reports no findings
- [ ] New behavior has a finding fixture, a clean fixture and a near miss
- [ ] `docs/rules.md` has a section for every new rule, with an anchor that matches `docsUrl`
- [ ] The README rule table is updated when a rule is added or renamed
- [ ] No runtime dependencies were added
- [ ] Output stays deterministic: same input, same findings, same order
- [ ] Text is plain ASCII and messages are actionable
- [ ] No personal paths, credentials or generated binaries are included

## Notes for the reviewer

Anything you are unsure about, a tradeoff you made, or a follow up you
deliberately left out.
