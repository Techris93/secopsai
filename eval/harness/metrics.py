"""
SecOpsAI Evaluation Harness - Core Metrics Module

Computes comprehensive evaluation metrics for detection performance.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import json
import statistics
from datetime import datetime


@dataclass
class DetectionResult:
    """Single detection result."""
    event_id: str
    rule_id: str
    severity: str
    confidence: float
    timestamp: datetime
    evidence: Dict[str, Any]
    matched: bool  # Whether this was a true match


@dataclass
class ConfusionMatrix:
    """Binary classification confusion matrix."""
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    
    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0
    
    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    
    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0
    
    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total > 0 else 0.0
    
    @property
    def specificity(self) -> float:
        return self.tn / (self.tn + self.fp) if (self.tn + self.fp) > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "true_positives": self.tp,
            "false_positives": self.fp,
            "true_negatives": self.tn,
            "false_negatives": self.fn,
            "precision": round(self.precision, 6),
            "recall": round(self.recall, 6),
            "f1_score": round(self.f1_score, 6),
            "fpr": round(self.fpr, 6),
            "accuracy": round(self.accuracy, 6),
            "specificity": round(self.specificity, 6),
        }


@dataclass
class RuleMetrics:
    """Metrics for a single detection rule."""
    rule_id: str
    matrix: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    avg_confidence: float = 0.0
    avg_latency_ms: float = 0.0
    events_evaluated: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            **self.matrix.to_dict(),
            "avg_confidence": round(self.avg_confidence, 4),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "events_evaluated": self.events_evaluated,
        }


@dataclass
class ScenarioMetrics:
    """Metrics for a test scenario category."""
    scenario_name: str
    matrix: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    rules_triggered: List[str] = field(default_factory=list)
    avg_detection_time_ms: float = 0.0
    coverage_pct: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario": self.scenario_name,
            **self.matrix.to_dict(),
            "rules_triggered": self.rules_triggered,
            "avg_detection_time_ms": round(self.avg_detection_time_ms, 2),
            "coverage_pct": round(self.coverage_pct, 2),
        }


@dataclass
class PerformanceMetrics:
    """System performance metrics."""
    events_per_second: float = 0.0
    avg_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    peak_memory_mb: float = 0.0
    cpu_percent: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "events_per_second": round(self.events_per_second, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "p50_latency_ms": round(self.p50_latency_ms, 2),
            "p95_latency_ms": round(self.p95_latency_ms, 2),
            "p99_latency_ms": round(self.p99_latency_ms, 2),
            "peak_memory_mb": round(self.peak_memory_mb, 2),
            "cpu_percent": round(self.cpu_percent, 2),
        }


@dataclass
class MitrAttackCoverage:
    """MITRE ATT&CK technique coverage."""
    technique_id: str
    technique_name: str
    tactic: str
    detected: bool
    detection_rules: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class EvaluationReport:
    """Complete evaluation report."""
    timestamp: datetime
    version: str
    duration_seconds: float
    
    # Overall metrics
    overall: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    
    # Per-rule metrics
    rule_metrics: Dict[str, RuleMetrics] = field(default_factory=dict)
    
    # Per-scenario metrics
    scenario_metrics: Dict[str, ScenarioMetrics] = field(default_factory=dict)
    
    # Performance metrics
    performance: PerformanceMetrics = field(default_factory=PerformanceMetrics)
    
    # ATT&CK coverage
    attack_coverage: List[MitrAttackCoverage] = field(default_factory=list)
    coverage_score: float = 0.0
    
    # Adversarial results
    adversarial_resilience: float = 0.0
    
    # Gates
    gates_passed: bool = True
    gate_failures: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "duration_seconds": round(self.duration_seconds, 2),
            "overall": self.overall.to_dict(),
            "rule_metrics": {k: v.to_dict() for k, v in self.rule_metrics.items()},
            "scenario_metrics": {k: v.to_dict() for k, v in self.scenario_metrics.items()},
            "performance": self.performance.to_dict(),
            "attack_coverage": [
                {
                    "technique_id": c.technique_id,
                    "technique_name": c.technique_name,
                    "tactic": c.tactic,
                    "detected": c.detected,
                    "detection_rules": c.detection_rules,
                    "confidence": c.confidence,
                }
                for c in self.attack_coverage
            ],
            "coverage_score": round(self.coverage_score, 2),
            "adversarial_resilience": round(self.adversarial_resilience, 2),
            "gates_passed": self.gates_passed,
            "gate_failures": self.gate_failures,
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class MetricsCalculator:
    """Calculate metrics from detection results."""
    
    @staticmethod
    def compute_confusion_matrix(
        detected_ids: set,
        events: List[Dict[str, Any]],
        id_key: str = "event_id",
        label_key: str = "label",
        malicious_label: str = "malicious"
    ) -> ConfusionMatrix:
        """Compute confusion matrix from detection results."""
        matrix = ConfusionMatrix()
        
        for event in events:
            is_malicious = event.get(label_key) == malicious_label
            is_detected = event.get(id_key) in detected_ids
            
            if is_malicious and is_detected:
                matrix.tp += 1
            elif not is_malicious and is_detected:
                matrix.fp += 1
            elif not is_malicious and not is_detected:
                matrix.tn += 1
            elif is_malicious and not is_detected:
                matrix.fn += 1
        
        return matrix
    
    @staticmethod
    def compute_performance_metrics(
        latencies_ms: List[float],
        event_count: int,
        duration_seconds: float,
        memory_samples_mb: List[float],
        cpu_samples: List[float],
    ) -> PerformanceMetrics:
        """Compute performance metrics."""
        if not latencies_ms:
            return PerformanceMetrics()
        
        sorted_latencies = sorted(latencies_ms)
        n = len(sorted_latencies)
        
        def percentile(p: float) -> float:
            idx = int(n * p / 100)
            return sorted_latencies[min(idx, n - 1)]
        
        return PerformanceMetrics(
            events_per_second=event_count / duration_seconds if duration_seconds > 0 else 0,
            avg_latency_ms=statistics.mean(latencies_ms),
            p50_latency_ms=percentile(50),
            p95_latency_ms=percentile(95),
            p99_latency_ms=percentile(99),
            peak_memory_mb=max(memory_samples_mb) if memory_samples_mb else 0,
            cpu_percent=statistics.mean(cpu_samples) if cpu_samples else 0,
        )
    
    @staticmethod
    def compute_attack_coverage(
        detections: List[DetectionResult],
        attack_mapping: Dict[str, List[str]]  # technique_id -> list of rule_ids
    ) -> Tuple[List[MitrAttackCoverage], float]:
        """Compute MITRE ATT&CK coverage."""
        triggered_rules = {d.rule_id for d in detections}
        
        coverage = []
        detected_count = 0
        
        for technique_id, rule_ids in attack_mapping.items():
            detected = bool(triggered_rules & set(rule_ids))
            if detected:
                detected_count += 1
            
            coverage.append(MitrAttackCoverage(
                technique_id=technique_id,
                technique_name="",  # To be populated from ATT&CK data
                tactic="",
                detected=detected,
                detection_rules=list(triggered_rules & set(rule_ids)),
                confidence=sum(d.confidence for d in detections if d.rule_id in rule_ids) / len(detections) if detections else 0,
            ))
        
        coverage_score = detected_count / len(attack_mapping) if attack_mapping else 0
        return coverage, coverage_score


def compute_metrics_by_severity(
    results: List[DetectionResult],
    ground_truth: Dict[str, str]  # event_id -> severity
) -> Dict[str, ConfusionMatrix]:
    """Compute metrics broken down by severity level."""
    by_severity = defaultdict(lambda: ConfusionMatrix())
    
    for result in results:
        expected_severity = ground_truth.get(result.event_id)
        if expected_severity:
            matrix = by_severity[expected_severity]
            # Simplified - assumes all detections are TPs for their severity
            matrix.tp += 1
    
    return dict(by_severity)
