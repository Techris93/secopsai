# SecOpsAI Hermes Plugin

This plugin gives Hermes Agent read-only access to normalized SecOpsAI findings, integration health, investigation sessions, triage counts, and Edge asset context.

It does not expose arbitrary commands, execute scans, close findings, publish content, read raw Hermes logs, or return Hermes credentials. Continuous collection is performed by the separately installed SecOpsAI Hermes monitor service.

Install the complete integration:

```bash
curl -fsSL https://secopsai.dev/install-hermes.sh | bash
```

Install only the plugin when Core is already available at `~/secopsai`:

```bash
hermes plugins install Techris93/secopsai/integrations/hermes --enable
```

Set `SECOPSAI_HOME` before starting Hermes when Core uses a different location.

