#!/usr/bin/env python3
"""
SecOpsAI - Runtime Process Monitor
Monitors system processes for supply chain attack indicators

Usage:
    sudo python runtime_monitor.py --monitor
    sudo python runtime_monitor.py --check-existing
    python runtime_monitor.py --generate-systemd
"""

import argparse
import json
import sys
import time
import signal
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('runtime-monitor')

# Check if psutil is available
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not installed. Install with: pip install psutil")


@dataclass
class ProcessEvent:
    timestamp: str
    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: str
    username: str
    connections: List[Dict]
    children: List[int]
    risk_score: int
    alerts: List[str]


class ProcessAnalyzer:
    """Analyzes processes for suspicious behavior"""
    
    # Known suspicious patterns
    SUSPICIOUS_PATTERNS = {
        'npm_postinstall': {
            'parent': ['node', 'npm', 'npx'],
            'child': ['curl', 'wget', 'python', 'bash', 'sh', 'powershell'],
            'network': True,
            'risk': 90,
            'description': 'npm postinstall script performing network activity'
        },
        'editor_shell_spawn': {
            'parent': ['vim', 'nvim', 'emacs', 'gvim'],
            'child': ['bash', 'sh', 'zsh', 'python', 'curl', 'wget'],
            'network': True,
            'risk': 75,
            'description': 'Editor spawning shell with network connection'
        },
        'python_pth_execution': {
            'parent': ['python', 'python3'],
            'cmdline_patterns': ['.pth', 'site-packages', 'import', 'exec'],
            'risk': 80,
            'description': 'Python executing potentially malicious .pth file'
        },
        'suspicious_dropper': {
            'exe_patterns': [
                r'com\.apple\.act\.',  # macOS disguise
                r'wt\.exe',             # Windows disguise
                r'ld\.py',              # Linux dropper
            ],
            'risk': 95,
            'description': 'Known supply chain RAT payload detected'
        },
        'node_c2_beacon': {
            'parent': ['node'],
            'network_ports': [8000, 8080, 9000, 4444],
            'risk': 85,
            'description': 'Node.js process connecting to suspicious port'
        }
    }
    
    # Known C2 domains/IPs from research
    KNOWN_C2 = [
        'sfrclak.com',
        'models.litellm.cloud',
        'checkmarx.zone',
    ]
    
    def __init__(self):
        self.events = []
        self.process_cache = {}
        
    def analyze_process(self, proc: psutil.Process) -> Optional[ProcessEvent]:
        """Analyze a single process"""
        try:
            info = proc.info if hasattr(proc, 'info') else self._get_proc_info(proc)
            if not info:
                return None
            
            alerts = []
            risk_score = 0
            
            # Get connections
            connections = []
            try:
                for conn in proc.connections(kind='inet'):
                    if conn.status == 'ESTABLISHED':
                        connections.append({
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            'status': conn.status
                        })
                        
                        # Check for C2
                        if conn.raddr:
                            if any(c2 in conn.raddr.ip or conn.raddr.ip in c2 for c2 in self.KNOWN_C2):
                                alerts.append(f"Connection to known C2: {conn.raddr.ip}")
                                risk_score += 100
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Get parent info
            parent_name = ''
            try:
                parent = proc.parent()
                if parent:
                    parent_name = parent.name()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Check suspicious patterns
            for pattern_name, pattern in self.SUSPICIOUS_PATTERNS.items():
                if self._matches_pattern(info, parent_name, pattern):
                    alerts.append(f"{pattern_name}: {pattern['description']}")
                    risk_score += pattern['risk']
            
            # Check command line for suspicious content
            cmdline = ' '.join(info.get('cmdline', []))
            if self._is_suspicious_cmdline(cmdline):
                alerts.append('Suspicious command line patterns detected')
                risk_score += 40
            
            if risk_score > 0:
                return ProcessEvent(
                    timestamp=datetime.now().isoformat(),
                    pid=info['pid'],
                    ppid=info['ppid'],
                    name=info['name'],
                    exe=info['exe'],
                    cmdline=cmdline[:500],
                    username=info['username'],
                    connections=connections,
                    children=[c.pid for c in proc.children()],
                    risk_score=risk_score,
                    alerts=alerts
                )
            
            return None
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    def _get_proc_info(self, proc: psutil.Process) -> Optional[Dict]:
        """Safely get process info"""
        try:
            return {
                'pid': proc.pid,
                'ppid': proc.ppid(),
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': proc.cmdline(),
                'username': proc.username()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    def _matches_pattern(self, info: Dict, parent_name: str, pattern: Dict) -> bool:
        """Check if process matches a suspicious pattern"""
        proc_name = info['name'].lower()
        
        # Check parent
        if 'parent' in pattern:
            if parent_name.lower() not in [p.lower() for p in pattern['parent']]:
                return False
        
        # Check child
        if 'child' in pattern:
            if proc_name not in [c.lower() for c in pattern['child']]:
                return False
        
        # Check exe patterns
        if 'exe_patterns' in pattern:
            exe = info.get('exe', '')
            if not any(re.search(p, exe) for p in pattern['exe_patterns']):
                return False
        
        # Check cmdline patterns
        if 'cmdline_patterns' in pattern:
            cmdline = ' '.join(info.get('cmdline', [])).lower()
            if not all(p in cmdline for p in pattern['cmdline_patterns']):
                return False
        
        return True
    
    def _is_suspicious_cmdline(self, cmdline: str) -> bool:
        """Check for suspicious command line patterns"""
        suspicious = [
            r'base64\s+-d',
            r'eval\s*\(',
            r'exec\s*\(',
            r'curl\s+.*\|\s*sh',
            r'wget\s+.*\|\s*sh',
            r'python\s+-c\s+.*import',
            r'nc\s+-e',
            r'/dev/tcp/',
            r'Invoke-WebRequest',
            r'IEX\s*\(',
        ]
        
        return any(re.search(pattern, cmdline, re.IGNORECASE) for pattern in suspicious)
    
    def scan_all_processes(self) -> List[ProcessEvent]:
        """Scan all running processes"""
        events = []
        
        if not HAS_PSUTIL:
            logger.error("psutil required for process scanning")
            return events
        
        for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe', 'cmdline', 'username']):
            try:
                event = self.analyze_process(proc)
                if event:
                    events.append(event)
            except Exception as e:
                logger.debug(f"Error analyzing process: {e}")
        
        return events
    
    def monitor_new_processes(self, callback=None, duration: Optional[int] = None):
        """Monitor for new suspicious processes"""
        if not HAS_PSUTIL:
            logger.error("psutil required for monitoring")
            return
        
        seen_pids = set(psutil.pids())
        start_time = time.time()
        
        logger.info(f"Starting process monitor... (known PIDs: {len(seen_pids)})")
        
        try:
            while True:
                current_pids = set(psutil.pids())
                new_pids = current_pids - seen_pids
                
                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        event = self.analyze_process(proc)
                        if event:
                            self.events.append(event)
                            
                            if callback:
                                callback(event)
                            else:
                                self._print_event(event)
                    except Exception as e:
                        logger.debug(f"Error checking new process {pid}: {e}")
                
                seen_pids = current_pids
                
                # Check duration
                if duration and (time.time() - start_time) > duration:
                    break
                
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            logger.info("Monitor stopped")
    
    def _print_event(self, event: ProcessEvent):
        """Print process event"""
        risk_emoji = "🚨" if event.risk_score >= 80 else "⚠️" if event.risk_score >= 50 else "ℹ️"
        
        print(f"\n{risk_emoji} SUSPICIOUS PROCESS DETECTED (Risk: {event.risk_score})")
        print(f"   Time: {event.timestamp}")
        print(f"   PID: {event.pid} (Parent: {event.ppid})")
        print(f"   Process: {event.name}")
        print(f"   User: {event.username}")
        print(f"   Command: {event.cmdline[:100]}...")
        
        for alert in event.alerts:
            print(f"   🔔 {alert}")
        
        if event.connections:
            print(f"   Network Connections:")
            for conn in event.connections:
                print(f"     {conn['local']} -> {conn['remote']} ({conn['status']})")


class FileSystemMonitor:
    """Monitor file system for suspicious changes"""
    
    SUSPICIOUS_PATHS = [
        '/Library/Caches/com.apple.act.',  # macOS RAT
        '/tmp/ld.py',                       # Linux RAT
        'C:\\ProgramData\\wt.exe',          # Windows RAT
        '/.vim/plugin/',                    # Vim plugin injection
        '/.emacs.d/',                       # Emacs config injection
    ]
    
    def __init__(self):
        self.watched_dirs = set()
        self.known_hashes = {}
    
    def check_suspicious_files(self) -> List[Dict]:
        """Check for known suspicious files"""
        findings = []
        
        for path_pattern in self.SUSPICIOUS_PATHS:
            # Expand home directory
            if path_pattern.startswith('/'):
                expanded = path_pattern
            else:
                expanded = os.path.expanduser(path_pattern)
            
            # Check if exists
            if os.path.exists(expanded):
                findings.append({
                    'path': expanded,
                    'type': 'SUSPICIOUS_FILE',
                    'severity': 'CRITICAL',
                    'message': f'Known supply chain payload detected: {expanded}'
                })
        
        return findings


def generate_systemd_service():
    """Generate systemd service file for continuous monitoring"""
    service_content = '''[Unit]
Description=SecOpsAI Runtime Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/secopsai/runtime_monitor.py --monitor --log /var/log/secopsai/monitor.log
Restart=always
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
'''
    
    timer_content = '''[Unit]
Description=Run SecOpsAI Runtime Monitor periodically

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
'''
    
    print("="*60)
    print("Systemd Service Configuration")
    print("="*60)
    print("\n1. Save the following to /etc/systemd/system/secopsai-monitor.service:\n")
    print(service_content)
    print("\n2. Enable and start the service:\n")
    print("   sudo systemctl daemon-reload")
    print("   sudo systemctl enable secopsai-monitor")
    print("   sudo systemctl start secopsai-monitor")
    print("\n3. View logs:\n")
    print("   sudo journalctl -u secopsai-monitor -f")


def main():
    parser = argparse.ArgumentParser(description='SecOpsAI Runtime Monitor')
    parser.add_argument('--monitor', '-m', action='store_true', help='Monitor for new processes')
    parser.add_argument('--check-existing', '-c', action='store_true', help='Check existing processes')
    parser.add_argument('--check-files', '-f', action='store_true', help='Check for suspicious files')
    parser.add_argument('--duration', '-d', type=int, help='Monitor duration in seconds')
    parser.add_argument('--output', '-o', help='Output file for JSON results')
    parser.add_argument('--generate-systemd', action='store_true', help='Generate systemd service config')
    parser.add_argument('--log', '-l', help='Log file path')
    
    args = parser.parse_args()
    
    if args.generate_systemd:
        generate_systemd_service()
        return
    
    if not HAS_PSUTIL and (args.monitor or args.check_existing):
        print("Error: psutil is required for process monitoring")
        print("Install with: pip install psutil")
        sys.exit(1)
    
    results = {
        'timestamp': datetime.now().isoformat(),
        'events': [],
        'file_findings': []
    }
    
    # Check existing processes
    if args.check_existing:
        print("🔍 Scanning existing processes...")
        analyzer = ProcessAnalyzer()
        events = analyzer.scan_all_processes()
        results['events'] = [asdict(e) for e in events]
        
        if events:
            print(f"\n🚨 Found {len(events)} suspicious processes:\n")
            for event in events:
                analyzer._print_event(event)
        else:
            print("✅ No suspicious processes found")
    
    # Check suspicious files
    if args.check_files:
        print("\n🔍 Checking for suspicious files...")
        fs_monitor = FileSystemMonitor()
        findings = fs_monitor.check_suspicious_files()
        results['file_findings'] = findings
        
        if findings:
            print(f"\n🚨 Found {len(findings)} suspicious files:\n")
            for finding in findings:
                print(f"   🚨 [{finding['severity']}] {finding['path']}")
                print(f"      {finding['message']}")
        else:
            print("✅ No suspicious files found")
    
    # Monitor new processes
    if args.monitor:
        print(f"\n👁️  Monitoring for new processes... (Ctrl+C to stop)\n")
        analyzer = ProcessAnalyzer()
        
        def save_event(event):
            results['events'].append(asdict(event))
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
        
        analyzer.monitor_new_processes(callback=save_event, duration=args.duration)
    
    # Save results
    if args.output and not args.monitor:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to {args.output}")


if __name__ == '__main__':
    main()
