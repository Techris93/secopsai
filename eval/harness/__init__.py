"""SecOpsAI Evaluation Harness v2."""

from eval.harness.metrics import (
    ConfusionMatrix,
    RuleMetrics,
    ScenarioMetrics,
    PerformanceMetrics,
    EvaluationReport,
    DetectionResult,
    MetricsCalculator,
)

from eval.harness.runner import EvaluationRunner

__version__ = "2.0.0"
__all__ = [
    "ConfusionMatrix",
    "RuleMetrics",
    "ScenarioMetrics",
    "PerformanceMetrics",
    "EvaluationReport",
    "DetectionResult",
    "MetricsCalculator",
    "EvaluationRunner",
]
