# Artifact Rule Packs

The artifact fleet uses versioned rule-pack metadata under `rules/yara` and
`rules/sigma`. The generic pack covers build/install hooks, download-and-execute
behavior, credentials, PowerShell, persistence, browser data, DGA-like signals,
Rust proc-macros, and hard-coded C2 addresses.

Rules are loaded as data and validated before use. If the optional `yara-python`
compiler is installed, YARA syntax can be compiled during CI; the deterministic
Python rules remain the local fallback when it is unavailable. A rule hit is an
evidence lead, not an automatic maliciousness verdict.

Every hit carries a rule ID, severity, confidence, file path, bounded context,
artifact hash, and mitigation guidance. Rule changes require regression tests
and review before activation.
