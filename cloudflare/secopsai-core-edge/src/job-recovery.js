// Retry eligibility is control-plane policy, never inferred by the dashboard.
export const ARTIFACT_REPAIR_VERSION = "artifact-choices-v3";
const repairedMessages = new Set([
  "DecisionError: decision: artifact result cites unsupplied evidence",
  "DecisionError: decision: artifact abstention must select a supplied missing-file identifier",
  "DecisionError: decision: finding verdict contradicts its disposition",
  // The chain's last error during the same contract failures; the cause was not recorded.
  "DecisionError: decision: all configured bridge models failed",
]);

const transientFailureCodes = new Set(["availability", "rate_limit", "timeout", "bridge_timeout"]);
const permanentFailureCodes = new Set(["authentication", "invalid_request", "invalid_response", "safety", "unsupported_action"]);
const bridgeTransportMarkers = /(?:\b429\b(?:\s+too many requests)?|\b426\b(?:\s+upgrade required)?|provider error 529|provider connect timeout|timed out after \d+ seconds|timeoutexpired|adapter_eof|connection reset|temporarily unavailable|upstream|loopback 500)/i;
const invalidBridgeOutputMarkers = /invalid_json_schema|invalid output schema|invalid_request_error/i;

function failureDetails(job) {
  if (job?.failure_details && typeof job.failure_details === "object" && !Array.isArray(job.failure_details)) return job.failure_details;
  try {
    const parsed = JSON.parse(String(job?.failure_details_json || "{}"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

export function intelligenceRecovery(job, { maxAttempts = 3 } = {}) {
  if (job.status !== "failed") return { eligible: false, action: "Monitor active stage", reason: "not_failed" };
  const details = failureDetails(job);
  const detailCodes = [details.error_code, details.category].map(value => String(value || "").trim().toLowerCase()).filter(Boolean);
  const attempts = Array.isArray(details.attempts) ? details.attempts.filter((item) => typeof item === "string").join("\n") : "";
  const message = [job.error_message, details.error_message, details.message, attempts].filter((item) => typeof item === "string" && item.trim()).join("\n");
  const wrappedBridgeFailure = /all configured bridge models failed\s*$/.test(String(job.error_message || ""));
  const hasPermanentDetail = detailCodes.some(code => permanentFailureCodes.has(code));
  const hasStructuredTransientCause = !hasPermanentDetail && (detailCodes.some(code => transientFailureCodes.has(code))
    || (detailCodes.includes("bridge_failed") && bridgeTransportMarkers.test(message) && !invalidBridgeOutputMarkers.test(message)));
  const hasKnownTransientMarker = bridgeTransportMarkers.test(message) && !invalidBridgeOutputMarkers.test(message);
  // These rows record a safety detail code, so this comes first or a repair could never apply.
  // A repair stays explicit, and its new result is validated like any other.
  if (job.action === "triage_artifact" && job.error_code === "safety" && !detailCodes.some(code => transientFailureCodes.has(code)) && repairedMessages.has(String(job.error_message || ""))) {
    return { eligible: false, action: "Re-evaluate with repaired artifact contract", reason: "artifact_contract_repair", repair_version: ARTIFACT_REPAIR_VERSION };
  }
  if (hasPermanentDetail) return { eligible: false, action: "Inspect permanent or safety failure", reason: detailCodes.find(code => permanentFailureCodes.has(code)) };
  if (wrappedBridgeFailure && !hasStructuredTransientCause && !hasKnownTransientMarker) {
    return { eligible: false, action: "Investigate missing failure detail", reason: "historical_cause_not_recorded" };
  }
  if (Number(job.attempt || 0) >= maxAttempts) return { eligible: false, action: "Review exhausted attempts", reason: "attempt_limit" };
  // The bridge's model catalog could not be parsed, so no model ran. Explicit job IDs only:
  // the automatic pass selects by recoverable error code, and this one is not among them.
  if (/failed to parse model_catalog_json/.test(String(job.error_message || ""))) {
    return { eligible: true, action: "Recover bridge configuration failure", reason: "bridge_configuration_failure" };
  }
  const errorCode = detailCodes.find(code => transientFailureCodes.has(code) || code === "bridge_failed") || String(job.error_code || "").trim().toLowerCase();
  if (transientFailureCodes.has(errorCode)
      || (errorCode === "bridge_failed" && bridgeTransportMarkers.test(message) && !invalidBridgeOutputMarkers.test(message))) {
    return { eligible: true, action: "Recover transient failure", reason: "transient_provider_failure" };
  }
  if (job.action === "triage_artifact" && repairedMessages.has(message)) {
    return { eligible: false, action: "Re-evaluate with repaired artifact contract", reason: "artifact_contract_repair", repair_version: ARTIFACT_REPAIR_VERSION };
  }
  if (job.error_code === "authentication") return { eligible: false, action: "Repair provider credentials", reason: "authentication" };
  return { eligible: false, action: "Inspect failure before recovery", reason: job.error_code || "unclassified" };
}
