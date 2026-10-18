// Retry eligibility is control-plane policy, never inferred by the dashboard.
export const ARTIFACT_REPAIR_VERSION = "artifact-choices-v3";
const repairedMessages = new Set([
  "DecisionError: decision: artifact result cites unsupplied evidence",
  "DecisionError: decision: artifact abstention must select a supplied missing-file identifier",
  "DecisionError: decision: finding verdict contradicts its disposition",
]);

export function intelligenceRecovery(job) {
  if (job.status !== "failed") return { eligible: false, action: "Monitor active stage", reason: "not_failed" };
  const message = String(job.error_message || "");
  if (/all configured bridge models failed\s*$/.test(message)) {
    return { eligible: false, action: "Investigate missing failure detail", reason: "historical_cause_not_recorded" };
  }
  if (Number(job.attempt || 0) >= 3) return { eligible: false, action: "Review exhausted attempts", reason: "attempt_limit" };
  if (["availability", "rate_limit", "timeout", "bridge_timeout"].includes(job.error_code)
      || (job.error_code === "bridge_failed" && /(?:429 Too Many Requests|Provider error 529|Provider connect timeout|timed out after \d+ seconds)/i.test(message))) {
    return { eligible: true, action: "Recover transient failure", reason: "transient_provider_failure" };
  }
  if (job.action === "triage_artifact" && repairedMessages.has(message)) {
    return { eligible: false, action: "Re-evaluate with repaired artifact contract", reason: "artifact_contract_repair", repair_version: ARTIFACT_REPAIR_VERSION };
  }
  if (job.error_code === "authentication") return { eligible: false, action: "Repair provider credentials", reason: "authentication" };
  return { eligible: false, action: "Inspect failure before recovery", reason: job.error_code || "unclassified" };
}
