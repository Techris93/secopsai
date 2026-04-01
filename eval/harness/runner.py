"""
SecOpsAI Evaluation Harness - Main Runner

Orchestrates comprehensive evaluation of SecOpsAI detection capabilities.
"""

import argparse
import json
import os
import sys
import time
import psutil
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detect import run_detection
from eval.harness.metrics import (
    MetricsCalculator,
    ConfusionMatrix,
    RuleMetrics,
    ScenarioMetrics,
    PerformanceMetrics,
    EvaluationReport,
    DetectionResult,
)


class EvaluationRunner:
    """Main evaluation orchestrator."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.project_root = Path(__file__).parent.parent.parent
        self.data_dir = self.project_root / "data"
        self.scenarios_dir = self.data_dir / "test_scenarios"
        self.results_dir = self.project_root / "eval" / "reports"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Load version
        self.version = self._get_version()
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load evaluation configuration."""
        default_config = {
            "thresholds": {
                "min_f1_score": 0.70,
                "min_precision": 0.60,
                "min_recall": 0.60,
                "max_fpr": 0.10,
                "min_coverage": 0.50,
            },
            "performance": {
                "min_throughput": 100,  # events/sec
                "max_p99_latency_ms": 1000,
                "max_memory_mb": 512,
            },
            "scenarios": {
                "include": "*",  # all
                "exclude": [],
            },
            "attack_coverage": {
                "enabled": True,
                "techniques_file": "eval/data/attack_techniques.json",
            },
            "adversarial": {
                "enabled": False,
                "mutation_rate": 0.1,
            },
            "reporting": {
                "formats": ["json", "html"],
                "output_dir": "eval/reports",
            },
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path) as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config
    
    def _get_version(self) -> str:
        """Get current version from git or package."""
        try:
            import subprocess
            result = subprocess.run(
                ["git", "describe", "--tags", "--always"],
                capture_output=True,
                text=True,
                cwd=self.project_root
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return "dev"
    
    def load_scenarios(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Load test scenarios from data directory."""
        scenarios = []
        
        if not self.scenarios_dir.exists():
            print(f"⚠️  Scenarios directory not found: {self.scenarios_dir}")
            return scenarios
        
        scenario_files = list(self.scenarios_dir.glob("*.json"))
        
        for file_path in scenario_files:
            try:
                with open(file_path) as f:
                    scenario = json.load(f)
                    scenario["_source_file"] = file_path.name
                    
                    # Add category based on filename or content
                    if "supply_chain" in file_path.name or "package" in file_path.name:
                        scenario["_category"] = "supply_chain"
                    elif "malware" in file_path.name or "rat" in file_path.name:
                        scenario["_category"] = "malware"
                    elif "exfil" in file_path.name:
                        scenario["_category"] = "exfiltration"
                    elif "persist" in file_path.name or "launchagent" in file_path.name:
                        scenario["_category"] = "persistence"
                    elif "sudo" in file_path.name or "escalation" in file_path.name:
                        scenario["_category"] = "privilege_escalation"
                    else:
                        scenario["_category"] = "general"
                    
                    scenarios.append(scenario)
            except Exception as e:
                print(f"⚠️  Failed to load {file_path}: {e}")
        
        if category:
            scenarios = [s for s in scenarios if s.get("_category") == category]
        
        return scenarios
    
    def run_detection_with_profiling(self, events: List[Dict]) -> tuple:
        """Run detection and collect performance metrics."""
        latencies = []
        results = []
        
        process = psutil.Process()
        memory_samples = []
        cpu_samples = []
        
        start_time = time.time()
        
        for event in events:
            event_start = time.perf_counter()
            
            # Sample resources before
            memory_samples.append(process.memory_info().rss / 1024 / 1024)  # MB
            cpu_samples.append(process.cpu_percent())
            
            # Run detection
            detection_result = run_detection(event)
            
            # Record latency
            latency_ms = (time.perf_counter() - event_start) * 1000
            latencies.append(latency_ms)
            
            # Record results
            if detection_result:
                results.append(DetectionResult(
                    event_id=event.get("event_id", "unknown"),
                    rule_id=detection_result.get("rule_id", "unknown"),
                    severity=detection_result.get("severity", "unknown"),
                    confidence=detection_result.get("confidence", 0.0),
                    timestamp=datetime.now(),
                    evidence=detection_result.get("evidence", {}),
                    matched=event.get("label") == "malicious"
                ))
        
        duration = time.time() - start_time
        
        performance = MetricsCalculator.compute_performance_metrics(
            latencies_ms=latencies,
            event_count=len(events),
            duration_seconds=duration,
            memory_samples_mb=memory_samples,
            cpu_samples=cpu_samples,
        )
        
        return results, performance
    
    def evaluate_accuracy(self, scenarios: List[Dict]) -> tuple:
        """Evaluate detection accuracy."""
        all_events = []
        for scenario in scenarios:
            events = scenario.get("events", [scenario])
            for event in events:
                event["_scenario"] = scenario.get("_source_file", "unknown")
                event["_category"] = scenario.get("_category", "general")
            all_events.extend(events)
        
        # Run detection
        results, performance = self.run_detection_with_profiling(all_events)
        
        # Compute overall metrics
        detected_ids = {r.event_id for r in results}
        overall_matrix = MetricsCalculator.compute_confusion_matrix(
            detected_ids=detected_ids,
            events=all_events
        )
        
        # Compute per-rule metrics
        rule_metrics = {}
        rule_events = {}
        for r in results:
            if r.rule_id not in rule_metrics:
                rule_metrics[r.rule_id] = RuleMetrics(rule_id=r.rule_id)
            rule_metrics[r.rule_id].events_evaluated += 1
        
        # Compute per-scenario metrics
        scenario_metrics = {}
        for scenario in scenarios:
            cat = scenario.get("_category", "general")
            if cat not in scenario_metrics:
                scenario_metrics[cat] = ScenarioMetrics(scenario_name=cat)
            
            scenario_events = scenario.get("events", [scenario])
            scenario_detected = {
                event.get("event_id")
                for event in scenario_events
                if event.get("event_id") in detected_ids
            }
            
            cat_matrix = MetricsCalculator.compute_confusion_matrix(
                detected_ids=scenario_detected,
                events=scenario_events
            )
            
            scenario_metrics[cat].matrix.tp += cat_matrix.tp
            scenario_metrics[cat].matrix.fp += cat_matrix.fp
            scenario_metrics[cat].matrix.tn += cat_matrix.tn
            scenario_metrics[cat].matrix.fn += cat_matrix.fn
        
        return overall_matrix, rule_metrics, scenario_metrics, performance
    
    def evaluate_gates(self, report: EvaluationReport) -> List[str]:
        """Evaluate quality gates."""
        failures = []
        thresholds = self.config["thresholds"]
        perf_thresholds = self.config["performance"]
        
        # Accuracy gates
        if report.overall.f1_score < thresholds["min_f1_score"]:
            failures.append(f"F1 score {report.overall.f1_score:.3f} < {thresholds['min_f1_score']}")
        
        if report.overall.precision < thresholds["min_precision"]:
            failures.append(f"Precision {report.overall.precision:.3f} < {thresholds['min_precision']}")
        
        if report.overall.recall < thresholds["min_recall"]:
            failures.append(f"Recall {report.overall.recall:.3f} < {thresholds['min_recall']}")
        
        if report.overall.fpr > thresholds["max_fpr"]:
            failures.append(f"FPR {report.overall.fpr:.3f} > {thresholds['max_fpr']}")
        
        # Performance gates
        if report.performance.events_per_second < perf_thresholds["min_throughput"]:
            failures.append(f"Throughput {report.performance.events_per_second:.1f} < {perf_thresholds['min_throughput']}")
        
        if report.performance.p99_latency_ms > perf_thresholds["max_p99_latency_ms"]:
            failures.append(f"P99 latency {report.performance.p99_latency_ms:.1f}ms > {perf_thresholds['max_p99_latency_ms']}ms")
        
        return failures
    
    def run(self, args: argparse.Namespace) -> EvaluationReport:
        """Run full evaluation."""
        start_time = time.time()
        
        print("🔬 SecOpsAI Evaluation Harness v2")
        print(f"Version: {self.version}")
        print("=" * 60)
        
        # Load scenarios
        print("\n📂 Loading test scenarios...")
        scenarios = self.load_scenarios(category=args.category)
        print(f"   Loaded {len(scenarios)} scenarios")
        
        if args.scenario:
            scenarios = [s for s in scenarios if args.scenario in s.get("_source_file", "")]
            print(f"   Filtered to {len(scenarios)} matching '{args.scenario}'")
        
        if not scenarios:
            print("❌ No scenarios to evaluate!")
            sys.exit(1)
        
        # Run evaluation
        print("\n🧪 Running detection evaluation...")
        overall, rule_metrics, scenario_metrics, performance = self.evaluate_accuracy(scenarios)
        
        # Build report
        report = EvaluationReport(
            timestamp=datetime.now(),
            version=self.version,
            duration_seconds=time.time() - start_time,
            overall=overall,
            rule_metrics=rule_metrics,
            scenario_metrics=scenario_metrics,
            performance=performance,
        )
        
        # Evaluate gates
        print("\n🚦 Evaluating quality gates...")
        report.gate_failures = self.evaluate_gates(report)
        report.gates_passed = len(report.gate_failures) == 0
        
        # Print results
        self._print_results(report)
        
        # Save report
        self._save_report(report, args)
        
        return report
    
    def _print_results(self, report: EvaluationReport):
        """Print evaluation results."""
        print("\n" + "=" * 60)
        print("📊 EVALUATION RESULTS")
        print("=" * 60)
        
        # Overall metrics
        print("\n🎯 Overall Metrics:")
        print(f"   F1 Score:    {report.overall.f1_score:.4f}")
        print(f"   Precision:   {report.overall.precision:.4f}")
        print(f"   Recall:      {report.overall.recall:.4f}")
        print(f"   FPR:         {report.overall.fpr:.4f}")
        print(f"   Accuracy:    {report.overall.accuracy:.4f}")
        
        # Confusion matrix
        print(f"\n📈 Confusion Matrix:")
        print(f"   TP: {report.overall.tp} | FP: {report.overall.fp}")
        print(f"   FN: {report.overall.fn} | TN: {report.overall.tn}")
        
        # Performance
        print(f"\n⚡ Performance:")
        print(f"   Throughput:  {report.performance.events_per_second:.1f} events/sec")
        print(f"   Avg Latency: {report.performance.avg_latency_ms:.2f}ms")
        print(f"   P99 Latency: {report.performance.p99_latency_ms:.2f}ms")
        print(f"   Peak Memory: {report.performance.peak_memory_mb:.1f}MB")
        
        # Per-scenario
        if report.scenario_metrics:
            print(f"\n📁 Per-Scenario:")
            for name, metrics in sorted(report.scenario_metrics.items()):
                print(f"   {name:20s} F1={metrics.matrix.f1_score:.3f} P={metrics.matrix.precision:.3f} R={metrics.matrix.recall:.3f}")
        
        # Gates
        print("\n" + "=" * 60)
        if report.gates_passed:
            print("✅ ALL GATES PASSED")
        else:
            print("❌ GATE FAILURES:")
            for failure in report.gate_failures:
                print(f"   • {failure}")
        print("=" * 60)
    
    def _save_report(self, report: EvaluationReport, args: argparse.Namespace):
        """Save evaluation report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON report
        json_path = self.results_dir / f"eval_report_{timestamp}.json"
        with open(json_path, "w") as f:
            f.write(report.to_json())
        print(f"\n💾 Report saved: {json_path}")
        
        # Latest symlink
        latest_path = self.results_dir / "latest_report.json"
        if latest_path.exists():
            latest_path.unlink()
        latest_path.symlink_to(json_path.name)


def main():
    parser = argparse.ArgumentParser(
        description="SecOpsAI Evaluation Harness v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m eval.harness.runner --full
  python -m eval.harness.runner --category supply_chain
  python -m eval.harness.runner --performance
  python -m eval.harness.runner --ci
        """
    )
    
    parser.add_argument("--full", action="store_true", help="Run full evaluation suite")
    parser.add_argument("--category", type=str, help="Evaluate specific category")
    parser.add_argument("--scenario", type=str, help="Evaluate specific scenario")
    parser.add_argument("--performance", action="store_true", help="Run performance benchmarks only")
    parser.add_argument("--ci", action="store_true", help="CI mode (strict gates, no interactive)")
    parser.add_argument("--config", type=str, default="eval/config.yaml", help="Config file path")
    parser.add_argument("--output", type=str, help="Output directory for reports")
    parser.add_argument("--compare-baseline", action="store_true", help="Compare against baseline")
    
    args = parser.parse_args()
    
    # Default to full if no specific mode
    if not any([args.full, args.category, args.scenario, args.performance]):
        args.full = True
    
    runner = EvaluationRunner(config_path=args.config)
    report = runner.run(args)
    
    # Exit with error code if gates failed in CI mode
    if args.ci and not report.gates_passed:
        sys.exit(1)
    
    sys.exit(0 if report.gates_passed else 1)


if __name__ == "__main__":
    main()
