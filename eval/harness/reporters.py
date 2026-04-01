"""
SecOpsAI Evaluation Harness - Report Generators

Generates evaluation reports in multiple formats.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from eval.harness.metrics import EvaluationReport


class JSONReporter:
    """Generate JSON reports."""
    
    @staticmethod
    def generate(report: EvaluationReport, output_path: Path):
        """Generate JSON report."""
        with open(output_path, "w") as f:
            f.write(report.to_json(indent=2))


class MarkdownReporter:
    """Generate Markdown reports."""
    
    @staticmethod
    def generate(report: EvaluationReport, output_path: Path):
        """Generate Markdown report."""
        lines = [
            "# SecOpsAI Evaluation Report",
            "",
            f"**Date:** {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Version:** {report.version}",
            f"**Duration:** {report.duration_seconds:.2f}s",
            "",
            "## Summary",
            "",
            f"- **Status:** {'✅ PASSED' if report.gates_passed else '❌ FAILED'}",
            f"- **F1 Score:** {report.overall.f1_score:.4f}",
            f"- **Precision:** {report.overall.precision:.4f}",
            f"- **Recall:** {report.overall.recall:.4f}",
            f"- **FPR:** {report.overall.fpr:.4f}",
            "",
            "## Confusion Matrix",
            "",
            "|          | Predicted + | Predicted - |",
            "|----------|-------------|-------------|",
            f"| Actual + | {report.overall.tp:4d} (TP)  | {report.overall.fn:4d} (FN)  |",
            f"| Actual - | {report.overall.fp:4d} (FP)  | {report.overall.tn:4d} (TN)  |",
            "",
            "## Performance Metrics",
            "",
            f"- **Throughput:** {report.performance.events_per_second:.1f} events/sec",
            f"- **Avg Latency:** {report.performance.avg_latency_ms:.2f}ms",
            f"- **P99 Latency:** {report.performance.p99_latency_ms:.2f}ms",
            f"- **Peak Memory:** {report.performance.peak_memory_mb:.1f}MB",
            "",
        ]
        
        if report.scenario_metrics:
            lines.extend([
                "## Per-Scenario Results",
                "",
                "| Scenario | F1 | Precision | Recall |",
                "|----------|-----|-----------|--------|",
            ])
            for name, metrics in sorted(report.scenario_metrics.items()):
                lines.append(
                    f"| {name} | {metrics.matrix.f1_score:.3f} | "
                    f"{metrics.matrix.precision:.3f} | {metrics.matrix.recall:.3f} |"
                )
            lines.append("")
        
        if report.gate_failures:
            lines.extend([
                "## Gate Failures",
                "",
            ])
            for failure in report.gate_failures:
                lines.append(f"- ❌ {failure}")
            lines.append("")
        
        with open(output_path, "w") as f:
            f.write("\n".join(lines))


class HTMLReporter:
    """Generate HTML reports with visualizations."""
    
    @staticmethod
    def generate(report: EvaluationReport, output_path: Path):
        """Generate HTML report."""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecOpsAI Evaluation Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a;
            color: #e5e5e5;
            line-height: 1.6;
            padding: 40px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #57df91; margin-bottom: 20px; }}
        h2 {{ color: #e5e5e5; margin: 30px 0 15px; border-bottom: 1px solid #333; padding-bottom: 10px; }}
        .meta {{ color: #666; margin-bottom: 30px; }}
        .status {{
            display: inline-block;
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: 600;
            margin-bottom: 30px;
        }}
        .status.pass {{ background: rgba(87, 223, 145, 0.2); color: #57df91; }}
        .status.fail {{ background: rgba(255, 95, 86, 0.2); color: #ff5f56; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: #111;
            border: 1px solid #222;
            border-radius: 8px;
            padding: 20px;
        }}
        .metric-value {{
            font-size: 32px;
            font-weight: 700;
            color: #57df91;
        }}
        .metric-label {{ color: #666; font-size: 14px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #222;
        }}
        th {{ color: #57df91; font-weight: 600; }}
        .gate-failure {{ color: #ff5f56; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔬 SecOpsAI Evaluation Report</h1>
        
        <div class="meta">
            <p>Version: {report.version}</p>
            <p>Date: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Duration: {report.duration_seconds:.2f}s</p>
        </div>
        
        <div class="status {'pass' if report.gates_passed else 'fail'}">
            {'✅ ALL GATES PASSED' if report.gates_passed else '❌ GATES FAILED'}
        </div>
        
        <h2>Overall Metrics</h2>
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{report.overall.f1_score:.3f}</div>
                <div class="metric-label">F1 Score</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report.overall.precision:.3f}</div>
                <div class="metric-label">Precision</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report.overall.recall:.3f}</div>
                <div class="metric-label">Recall</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report.overall.fpr:.3f}</div>
                <div class="metric-label">FPR</div>
            </div>
        </div>
        
        <h2>Performance</h2>
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{report.performance.events_per_second:.0f}</div>
                <div class="metric-label">Events/sec</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report.performance.avg_latency_ms:.1f}ms</div>
                <div class="metric-label">Avg Latency</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report.performance.p99_latency_ms:.1f}ms</div>
                <div class="metric-label">P99 Latency</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report.performance.peak_memory_mb:.0f}MB</div>
                <div class="metric-label">Peak Memory</div>
            </div>
        </div>
        
        {HTMLReporter._render_scenarios(report)}
        {HTMLReporter._render_failures(report)}
    </div>
</body>
</html>
"""
        with open(output_path, "w") as f:
            f.write(html)
    
    @staticmethod
    def _render_scenarios(report: EvaluationReport) -> str:
        if not report.scenario_metrics:
            return ""
        
        rows = ""
        for name, metrics in sorted(report.scenario_metrics.items()):
            rows += f"""
                <tr>
                    <td>{name}</td>
                    <td>{metrics.matrix.f1_score:.3f}</td>
                    <td>{metrics.matrix.precision:.3f}</td>
                    <td>{metrics.matrix.recall:.3f}</td>
                    <td>{metrics.matrix.tp}/{metrics.matrix.fp}/{metrics.matrix.fn}</td>
                </tr>"""
        
        return f"""
        <h2>Per-Scenario Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Scenario</th>
                    <th>F1</th>
                    <th>Precision</th>
                    <th>Recall</th>
                    <th>TP/FP/FN</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""
    
    @staticmethod
    def _render_failures(report: EvaluationReport) -> str:
        if not report.gate_failures:
            return ""
        
        items = "".join(f"<li class='gate-failure'>❌ {f}</li>" for f in report.gate_failures)
        return f"""
        
        <h2>Gate Failures</h2>
        <ul>{items}</ul>"""


class ReportGenerator:
    """Generate reports in multiple formats."""
    
    REPORTERS = {
        "json": JSONReporter,
        "markdown": MarkdownReporter,
        "html": HTMLReporter,
    }
    
    @classmethod
    def generate(cls, report: EvaluationReport, output_dir: Path, formats: List[str] = None):
        """Generate reports in specified formats."""
        if formats is None:
            formats = ["json"]
        
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for fmt in formats:
            if fmt in cls.REPORTERS:
                reporter = cls.REPORTERS[fmt]
                ext = "md" if fmt == "markdown" else fmt
                output_path = output_dir / f"eval_report_{timestamp}.{ext}"
                reporter.generate(report, output_path)
                print(f"  📄 Generated {fmt.upper()} report: {output_path}")
