# Research Reliability Operations

This is the operator guide for the execution-grounded research controls in
Mission Control. It complements [Research Automation](research-automation.md)
and is intentionally conservative: the system can automate evidence handling
and review preparation, but it cannot turn model prose into fact or publish on
your behalf.

## When to use it

Use the reliability workspace for a material package, artifact, campaign,
vulnerability, extension, or malware investigation that may become a public
research report. Routine findings can continue through the normal Triage Ops
workflow. A case becomes publication-ready only when all hard gates pass.

## Dashboard click path

1. Open **Research -> Cases** and select the case.
2. Scroll to **Evidence reliability workspace**. The **Next** card names the
   single next action. When the case has a structured subject and evidence,
   click **Run Safe Automation**. It advances deterministic stages, queues at
   most one guarded read-only specialist run, and stops at the next real
   evidence or human decision boundary.
3. Open **Manual stage controls and recovery** only to diagnose or rerun a
   specific checkpoint. Click **Generate Hypotheses**, then **Rank Hypotheses**. Review the selected
   alternative and its falsifiers.
4. Click **Create Evidence Plan**. If a source disappears or the method
   changes, use **Revise Evidence Plan**; the earlier revision remains visible.
5. Run **Scaffold Research**, then **Verify Transition**, then **Full Safe
   Research**. These stages validate scope and fixtures before processing the
   complete approved evidence set.
6. Click **Build Claim Ledger** and **Verify Claims**. Use **Resolve Unsupported
   Claims** only to qualify or remove unsupported text; it never creates
   evidence.
7. Run **Specialist** and **Blind Review**. If the results disagree materially,
   review both evidence-linked outputs and use **Record adjudication** with an
   evidence-backed rationale. Accepting one result resolves only that
   disagreement; **Request more evidence** keeps the case blocked.
8. Run **Audit Completeness**, **Check Originality**, and **Render Publication
   Preview**. Fix hard blockers and attach viewport/alt/license metadata to
   screenshots.
9. Run **Publication Safety**. Only after the case and review are approved can
   you create a review-only draft. **Approve**, **Publish approved**, and
   **Deploy** remain separate controls in Publications.

The dashboard calls typed helper actions. It never executes a browser-supplied
shell string, installs a dependency, or activates an artifact.

The normal daily workflow invokes this same bounded coordinator for a limited
newest-first set of evidence-bearing cases. Repeated cycles reuse an unchanged
waiting result, so they do not create duplicate specialist jobs or repeatedly
rewrite the same claim decision. The case shows the latest automation stop,
reason, safe-step count, and next action directly below the primary button.

## CLI equivalent

```bash
case_id=RSC-XXXXXXXXXXXXXXXX

secopsai research reliability auto "$case_id" --json
# Or advance up to five eligible cases during an operator cycle:
secopsai research reliability auto-batch --limit 5 --json

# Granular recovery controls:
secopsai research reliability generate-hypotheses "$case_id" --json
secopsai research reliability rank-hypotheses "$case_id" --candidate-budget 6 --comparison-budget 15 --json
secopsai research reliability plan "$case_id" --json
secopsai research reliability run-scaffold "$case_id" --json
secopsai research reliability verify-transition "$case_id" --json
secopsai research reliability run-full "$case_id" --json
secopsai research reliability build-claim-ledger "$case_id" --json
secopsai research reliability verify-claims "$case_id" --json
secopsai research reliability queue-specialist "$case_id" --json
secopsai research reliability queue-blind-review "$case_id" --json
secopsai research reliability audit-completeness "$case_id" --json
secopsai research reliability audit-originality "$case_id" --json
secopsai research reliability visual-qa "$case_id" --json
secopsai research reliability status "$case_id" --json
```

Safe automation stops rather than guessing when evidence is missing, claims
remain unsupported or contradicted, the selected model is still running or
failed, reviewers materially disagree, real desktop/mobile screenshots are
absent, or publication approval is required. It never resolves those gates on
the operator's behalf.

To resolve a material reviewer disagreement, use the run ID shown in the
workspace. The rationale is deliberately bounded and must name the evidence
that supports the decision:

```bash
secopsai research reliability adjudicate-review SOR-XXXXXXXXXXXXXXXX \
  --decision accept_reviewer \
  --rationale "The independent interpretation matches the verified registry and static evidence." \
  --json
```

The available decisions are `accept_primary`, `accept_reviewer`, and
`request_more_evidence`.

## Reading the decision card

The workspace keeps these concepts separate:

- **Priority** determines queue order.
- **Detection confidence** describes the rule/evidence signal.
- **Assessment** is the analyst's maliciousness or benignness conclusion.
- **Potential impact** describes the affected environment, not certainty.
- **Local exposure** says what was checked in the named repository; absence is
  not proof that an external incident did not happen.
- **Evidence quality** describes provenance, completeness, contradictions, and
  whether the run was static or sandbox-backed.

An `inconclusive` assessment is a valid outcome. It is safer than filling an
evidence gap with a confident sentence.

## Model routing and resources

The OpenCodex model and fallback policy are captured when a job is created.
With fallback disabled, an unavailable provider leaves the job queued and
visible; it does not silently consume another provider. The bridge exposes a
durable Busy lease and heartbeat while a job is running. Run bundles record
queue depth, CPU, memory, disk, retries, latency, token estimates, and cost
estimates so operators can investigate capacity rather than infer it from a
stale probe.

## Safe failure handling

The correct response to a failed or incomplete stage is to inspect the error,
revise the evidence plan, and rerun from the recorded checkpoint. Never mark a
failed run successful, use an empty log as proof, or describe a sandbox result
that is not linked to the exact artifact hash. A missing artifact, unavailable
registry, or absent sandbox result is an evidence gap and appears in the next
action or publication blockers.

## Benchmarking

The offline benchmark uses synthetic fixtures and never changes production
controls:

```bash
secopsai research reliability benchmark --json
```

It compares full controls with claim clipping disabled, completeness auditing
disabled, and an unconstrained mock baseline. It reports unsupported claims,
evidence coverage, methodology divergence, selective reporting, originality,
false positives, false negatives, reviewer disagreement, publication-block
accuracy, latency, and estimated cost. A passing benchmark requires the full
control condition to block unsafe or unsupported publication.

## Safety boundary

No package, build script, extension, binary, container, or payload is executed
locally. External sandbox submission, disclosure, publication, deployment,
cloud mutation, destructive response, and external communication require a
separate human approval. Keep generated reports free of secrets, private paths,
customer data, raw payloads, and copied article text.
