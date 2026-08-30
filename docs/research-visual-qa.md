# Research Visual QA

Visual evidence is part of publication quality, not decoration. Mission
Control renders a deterministic publication probe at desktop and mobile
widths, checks overflow and contrast, and records the result as an audit.

## Required checks

- desktop and mobile render states are both captured;
- no element overflows its viewport;
- text meets the configured contrast threshold;
- every screenshot has descriptive alt text;
- a license or source attribution is recorded;
- screenshots are redacted and contain no secrets, private paths, customer
  data, or raw payloads.

## Attach evidence

When adding a screenshot to a Research Case, set the evidence type to
`screenshot` and provide:

- locator or local approved file;
- SHA-256 when a local file is used;
- viewport `desktop` or `mobile`;
- alt text;
- license or source attribution;
- provenance and a short note describing what is visible.

The dashboard exposes these fields in **Research -> Cases -> Add evidence**.
Attaching media resets an editorial draft to **Needs review**, so a reviewer
must inspect the updated article again.

## CLI

```bash
secopsai research reliability visual-qa RSC-XXXXXXXXXXXXXXXX --json
secopsai research case add-evidence RSC-XXXXXXXXXXXXXXXX \
  --evidence-type screenshot \
  --title "Reviewed publication screenshot" \
  --locator https://example.invalid/reviewed-screenshot.png \
  --visual-viewport desktop \
  --alt-text "Redacted desktop evidence view" \
  --license "Operator-approved source capture" \
  --source-attribution "Source report, accessed for defensive research" \
  --provenance "reviewed visual evidence" \
  --notes "No secrets or private identifiers are visible." \
  --json
```

Do not use a screenshot as proof of behavior that was not observed. A visual
check can show layout and evidence context; it cannot replace a registry
record, static finding, or approved sandbox result.
