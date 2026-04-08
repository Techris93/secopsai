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


def __getattr__(name: str):
    if name == "EvaluationRunner":
        from eval.harness.runner import EvaluationRunner
        return EvaluationRunner
    raise AttributeError(name)
