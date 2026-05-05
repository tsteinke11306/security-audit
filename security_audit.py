#!/usr/bin/env python3
"""
VPS Security Audit Script
Author: Trevor Steinke
Description: Comprehensive security audit tool for Ubuntu VPS environments.
             Generates human-readable reports with actionable findings.
"""

import subprocess
import json
import os
import re
import datetime
import socket
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class SecurityAudit:
    """Main security audit class."""
    
    def __init__(self):
        self.findings: List[Dict] = []
        self.hostname = socket.gethostname()
        self.timestamp = datetime.datetime.now().isoformat()
        self.os_info = self._get_os_info()
    
    def _run_cmd(self, cmd: str, shell: bool = True) -> Tuple[int, str, str]:
        """Run a shell command and return exit code, stdout, stderr."""
        try:
            result = subprocess.run(
                cmd, shell=shell, capture_output=True, text=True, timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)
    
    def _get_os_info(self) -> str:
        """Get OS version information."""
        _, out, _ = self._run_cmd("lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
        return out.strip() or "Unknown"
    
    def _add_finding(self, category: str, title: str, status: str, 
                     details: str, severity: str = "info", recommendation: str = ""):
        """Add a finding to the report."""
        self.findings.append({
            "category": category,
            "title": title,
            "status": status,
            "severity": severity,
            "details": details,
            "recommendation": recommendation,
            "timestamp": datetime.datetime.now().isoformat()
        })
    
    # ==================== AUDIT MODULES ====================
    
    def audit_ssh(self):
        """Audit SSH configuration."""
        ssh_config = Path("/etc/ssh/sshd_config")
        if not ssh_config.exists():
            self._add_finding("SSH", "SSH Config", "MISSING",
                            "SSH config file not found", "high",
                            "Verify SSH is installed properly")
            return
        
        with open(ssh_config, 'r') as f:
            config = f.read()
        
        checks = {
            "Password Authentication": (r"^PasswordAuthentication\s+no", "Should be disabled (key-only auth)"),
            "Root Login": (r"^PermitRootLogin\s+no", "Should be disabled"),
            "Pubkey Authentication": (r"^PubkeyAuthentication\s+yes", "Should be enabled"),
        }
        
        for check_name, (pattern, recommendation) in checks.items():
            if re.search(pattern, config, re.MULTILINE):
                self._add_finding("SSH", check_name, "PASS",
                                f"{check_name} is properly configured", "info")
            else:
                self._add_finding("SSH", check_name, "FAIL",
                                f"{check_name} may not be properly configured", "medium",
                                recommendation)
        
        # Check SSH port
        port_match = re.search(r"^Port\s+(\d+)", config, re.MULTILINE)
        ssh_port = int(port_match.group(1)) if port_match else 22
        
        if ssh_port != 22:
            self._add_finding("SSH", "SSH Port", "PASS",
                            f"SSH running on non-standard port {ssh_port}", "info")
        else:
            self._add_finding("SSH", "SSH Port", "WARN",
                            "SSH running on default port 22", "low",
                            "Consider moving SSH to a non-standard port")
    
    def audit_firewall(self):
        """Audit firewall status."""
        # Check UFW
        _, ufw_out, _ = self._run_cmd("ufw status 2>/dev/null")
        if "Status: active" in ufw_out:
            self._add_finding("Firewall", "UFW Status", "PASS",
                            "UFW firewall is active", "info")
        else:
            self._add_finding("Firewall", "UFW Status", "FAIL",
                            "UFW firewall is not active", "high",
                            "Enable UFW: sudo ufw enable")
        
        # Check iptables rules
        _, ipt_out, _ = self._run_cmd("iptables -L -n 2>/dev/null | head -20")
        if ipt_out.strip() and "Chain INPUT" in ipt_out:
            self._add_finding("Firewall", "iptables Rules", "INFO",
                            "iptables rules exist (see details)", "info",
                            "Review rules for correctness")
        
        # Check for firewalld
        _, fw_out, _ = self._run_cmd("systemctl is-active firewalld 2>/dev/null")
        if "active" in fw_out:
            self._add_finding("Firewall", "firewalld", "PASS",
                            "firewalld is active", "info")
    
    def audit_open_ports(self):
        """Audit listening network services."""
        _, ports_out, _ = self._run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        
        services = []
        lines = ports_out.strip().split('\n')[1:]  # Skip header
        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                services.append({
                    "protocol": parts[0],
                    "local_address": parts[3],
                    "state": parts[1],
                    "process": parts[-1]
                })
        
        # Check for exposed risky services
        risky_ports = [21, 23, 25, 53, 110, 143, 3306, 3389, 5432, 5900, 6379, 27017]
        exposed_risky = []
        for svc in services:
            port_str = svc["local_address"].split(":")[-1]
            try:
                port = int(port_str)
                if port in risky_ports:
                    exposed_risky.append(f"Port {port} ({svc['process']})")
            except ValueError:
                continue
        
        if exposed_risky:
            self._add_finding("Network", "Exposed Risky Ports", "WARN",
                            "Potentially risky services exposed: " + ", ".join(exposed_risky),
                            "medium",
                            "Verify these services need to be publicly accessible")
        
        self._add_finding("Network", "Listening Services", "INFO",
                        f"Found {len(services)} listening services", "info")
    
    def audit_failed_logins(self):
        """Check for recent failed login attempts."""
        _, fail_out, _ = self._run_cmd(
            "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -50 || "
            "grep 'authentication failure' /var/log/syslog 2>/dev/null | tail -50 || "
            "journalctl _COMM=sshd --since '7 days ago' 2>/dev/null | grep 'Failed' | tail -50"
        )
        
        fail_count = len(fail_out.strip().split('\n')) if fail_out.strip() else 0
        
        if fail_count > 20:
            self._add_finding("Authentication", "Failed Logins", "WARN",
                            f"{fail_count} failed login attempts in recent logs", "medium",
                            "Consider implementing fail2ban or reviewing IPs")
        elif fail_count > 0:
            self._add_finding("Authentication", "Failed Logins", "INFO",
                            f"{fail_count} failed login attempts (acceptable)", "low")
        else:
            self._add_finding("Authentication", "Failed Logins", "PASS",
                            "No failed login attempts found", "info")
    
    def audit_updates(self):
        """Check for pending security updates."""
        _, updates_out, _ = self._run_cmd(
            r"apt list --upgradable 2>/dev/null | grep -c '\[upgradable' || echo 0"
        )
        try:
            update_count = int(updates_out.strip())
        except:
            update_count = 0
        
        _, sec_out, _ = self._run_cmd(
            "apt-get -s dist-upgrade 2>/dev/null | grep '^Inst' | grep -i security | wc -l || echo 0"
        )
        try:
            sec_count = int(sec_out.strip())
        except:
            sec_count = 0
        
        if sec_count > 0:
            self._add_finding("Updates", "Security Updates", "WARN",
                            f"{sec_count} security updates pending", "high",
                            "Run: sudo apt update && sudo apt upgrade")
        elif update_count > 10:
            self._add_finding("Updates", "Pending Updates", "INFO",
                            f"{update_count} updates available", "low",
                            "Run: sudo apt update && sudo apt upgrade")
        else:
            self._add_finding("Updates", "System Updates", "PASS",
                            "System is up to date", "info")
    
    def audit_ssl_certificates(self):
        """Check SSL/TLS certificate expiry."""
        cert_paths = [
            "/etc/letsencrypt/live",
            "/etc/ssl/certs",
            "/etc/nginx/ssl"
        ]
        
        certs_found = False
        for base_path in cert_paths:
            base = Path(base_path)
            if not base.exists():
                continue
            
            for cert_file in base.rglob("*.pem"):
                if "chain" in cert_file.name or "fullchain" not in cert_file.name:
                    continue
                
                _, cert_out, _ = self._run_cmd(
                    f"openssl x509 -in {cert_file} -noout -dates -subject 2>/dev/null"
                )
                
                if "notAfter" in cert_out:
                    match = re.search(r'notAfter=(.+)', cert_out)
                    if match:
                        expiry_str = match.group(1).strip()
                        try:
                            expiry = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                            days_left = (expiry - datetime.datetime.now()).days
                            
                            if days_left < 7:
                                self._add_finding("SSL/TLS", f"Cert Expiry ({cert_file.name})", "FAIL",
                                                f"Certificate expires in {days_left} days", "high",
                                                "Renew certificate immediately")
                            elif days_left < 30:
                                self._add_finding("SSL/TLS", f"Cert Expiry ({cert_file.name})", "WARN",
                                                f"Certificate expires in {days_left} days", "medium",
                                                "Plan certificate renewal")
                            else:
                                self._add_finding("SSL/TLS", f"Cert Expiry ({cert_file.name})", "PASS",
                                                f"Certificate valid for {days_left} days", "info")
                            certs_found = True
                        except:
                            pass
        
        if not certs_found:
            self._add_finding("SSL/TLS", "Certificates", "INFO",
                            "No Let's Encrypt certificates found to check", "low",
                            "Verify SSL certificates are configured")
    
    def audit_fail2ban(self):
        """Check fail2ban status."""
        _, f2b_out, _ = self._run_cmd("systemctl is-active fail2ban 2>/dev/null")
        
        if "active" in f2b_out:
            self._add_finding("Intrusion Prevention", "fail2ban", "PASS",
                            "fail2ban is active and protecting against brute force", "info")
        else:
            self._add_finding("Intrusion Prevention", "fail2ban", "FAIL",
                            "fail2ban is not running", "medium",
                            "Install and configure fail2ban: sudo apt install fail2ban")
    
    def audit_system_resources(self):
        """Check CPU, memory, and disk usage."""
        # CPU load
        _, load_out, _ = self._run_cmd("uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ','")
        try:
            load = float(load_out.strip())
            if load > 2.0:
                self._add_finding("System", "CPU Load", "WARN",
                                f"High CPU load: {load}", "medium")
            else:
                self._add_finding("System", "CPU Load", "PASS",
                                f"CPU load normal: {load}", "info")
        except:
            pass
        
        # Memory usage
        _, mem_out, _ = self._run_cmd("free | grep Mem | awk '{printf \"%.1f\", $3/$2 * 100.0}'")
        try:
            mem_pct = float(mem_out.strip())
            if mem_pct > 90:
                self._add_finding("System", "Memory Usage", "WARN",
                                f"High memory usage: {mem_pct}%", "medium")
            else:
                self._add_finding("System", "Memory Usage", "PASS",
                                f"Memory usage: {mem_pct}%", "info")
        except:
            pass
        
        # Disk usage
        _, disk_out, _ = self._run_cmd("df -h / | tail -1 | awk '{print $5}' | tr -d '%'")
        try:
            disk_pct = int(disk_out.strip())
            if disk_pct > 90:
                self._add_finding("System", "Disk Usage", "WARN",
                                f"Critical disk usage: {disk_pct}%", "high",
                                "Free up disk space immediately")
            elif disk_pct > 80:
                self._add_finding("System", "Disk Usage", "WARN",
                                f"High disk usage: {disk_pct}%", "medium",
                                "Consider cleaning up old logs and packages")
            else:
                self._add_finding("System", "Disk Usage", "PASS",
                                f"Disk usage: {disk_pct}%", "info")
        except:
            pass
    
    def audit_users(self):
        """Check user accounts and sudo privileges."""
        _, users_out, _ = self._run_cmd("awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd")
        user_count = len(users_out.strip().split('\n')) if users_out.strip() else 0
        
        self._add_finding("Users", "Regular Users", "INFO",
                        f"Found {user_count} regular user accounts", "info",
                        "Review accounts for unauthorized users")
        
        # Check for users with no password
        _, nopass_out, _ = self._run_cmd("awk -F: '$2 == \"\" {print $1}' /etc/shadow 2>/dev/null")
        if nopass_out.strip():
            self._add_finding("Users", "Passwordless Accounts", "FAIL",
                            f"Accounts without passwords: {nopass_out.strip()}", "high",
                            "Set strong passwords for all accounts")
    
    # ==================== REPORTING ====================
    
    def generate_json_report(self) -> str:
        """Generate a JSON report."""
        report = {
            "audit_metadata": {
                "hostname": self.hostname,
                "timestamp": self.timestamp,
                "os": self.os_info,
                "script_version": "1.0.0"
            },
            "summary": {
                "total_checks": len(self.findings),
                "pass": len([f for f in self.findings if f["status"] == "PASS"]),
                "warn": len([f for f in self.findings if f["status"] == "WARN"]),
                "fail": len([f for f in self.findings if f["status"] == "FAIL"]),
                "info": len([f for f in self.findings if f["status"] == "INFO"])
            },
            "findings": self.findings
        }
        return json.dumps(report, indent=2)
    
    def generate_text_report(self) -> str:
        """Generate a human-readable text report."""
        lines = []
        lines.append("=" * 70)
        lines.append("  VPS SECURITY AUDIT REPORT")
        lines.append("=" * 70)
        lines.append(f"  Hostname:    {self.hostname}")
        lines.append(f"  OS:          {self.os_info}")
        lines.append(f"  Timestamp:   {self.timestamp}")
        lines.append("=" * 70)
        lines.append("")
        
        # Summary
        pass_count = len([f for f in self.findings if f["status"] == "PASS"])
        warn_count = len([f for f in self.findings if f["status"] == "WARN"])
        fail_count = len([f for f in self.findings if f["status"] == "FAIL"])
        info_count = len([f for f in self.findings if f["status"] == "INFO"])
        
        lines.append("SUMMARY")
        lines.append("-" * 70)
        lines.append(f"  Total Checks:  {len(self.findings)}")
        lines.append(f"  PASS:          {pass_count}")
        lines.append(f"  WARN:          {warn_count}")
        lines.append(f"  FAIL:          {fail_count}")
        lines.append(f"  INFO:          {info_count}")
        lines.append("")
        
        # Categorized findings
        categories = sorted(set(f["category"] for f in self.findings))
        for category in categories:
            lines.append(f"{category.upper()}")
            lines.append("-" * 70)
            
            cat_findings = [f for f in self.findings if f["category"] == category]
            for finding in cat_findings:
                status_symbol = {
                    "PASS": "[PASS]",
                    "WARN": "[WARN]",
                    "FAIL": "[FAIL]",
                    "INFO": "[INFO]"
                }.get(finding["status"], "[?]")
                
                lines.append(f"  {status_symbol} {finding['title']}")
                lines.append(f"           {finding['details']}")
                if finding["recommendation"]:
                    lines.append(f"           → {finding['recommendation']}")
                lines.append("")
        
        lines.append("=" * 70)
        lines.append("  End of Report")
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def generate_markdown_report(self) -> str:
        """Generate a Markdown report for GitHub."""
        lines = []
        lines.append("# Security Audit Report")
        lines.append("")
        lines.append(f"**Host:** `{self.hostname}`  ")
        lines.append(f"**OS:** {self.os_info}  ")
        lines.append(f"**Date:** {self.timestamp}  ")
        lines.append("")
        
        # Summary
        pass_count = len([f for f in self.findings if f["status"] == "PASS"])
        warn_count = len([f for f in self.findings if f["status"] == "WARN"])
        fail_count = len([f for f in self.findings if f["status"] == "FAIL"])
        info_count = len([f for f in self.findings if f["status"] == "INFO"])
        
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- Total Checks: {len(self.findings)}")
        lines.append(f"- PASS: {pass_count}")
        lines.append(f"- WARN: {warn_count}")
        lines.append(f"- FAIL: {fail_count}")
        lines.append(f"- INFO: {info_count}")
        lines.append("")
        
        # Findings table
        lines.append("## Findings")
        lines.append("")
        lines.append("| Category | Check | Status | Severity | Details |")
        lines.append("|----------|-------|--------|----------|---------|")
        
        for finding in self.findings:
            details_short = finding["details"][:60] + "..." if len(finding["details"]) > 60 else finding["details"]
            lines.append(
                f"| {finding['category']} | {finding['title']} | "
                f"{finding['status']} | {finding['severity']} | {details_short} |"
            )
        
        lines.append("")
        
        # Recommendations
        lines.append("## Recommendations")
        lines.append("")
        recs = [f for f in self.findings if f["recommendation"]]
        for i, finding in enumerate(recs, 1):
            lines.append(f"{i}. **{finding['title']}** ({finding['severity']})")
            lines.append(f"   - {finding['recommendation']}")
            lines.append("")
        
        return "\n".join(lines)
    
    def run_all_audits(self):
        """Run all audit modules."""
        print("Running security audit...")
        self.audit_ssh()
        self.audit_firewall()
        self.audit_open_ports()
        self.audit_failed_logins()
        self.audit_updates()
        self.audit_ssl_certificates()
        self.audit_fail2ban()
        self.audit_system_resources()
        self.audit_users()
        print(f"Completed {len(self.findings)} checks.")
    
    def save_reports(self, output_dir: str = "."):
        """Save all report formats to files."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # JSON report
        json_path = output_path / f"audit_{self.hostname}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w') as f:
            f.write(self.generate_json_report())
        print(f"JSON report saved: {json_path}")
        
        # Text report
        txt_path = output_path / f"audit_{self.hostname}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(txt_path, 'w') as f:
            f.write(self.generate_text_report())
        print(f"Text report saved: {txt_path}")
        
        # Markdown report
        md_path = output_path / f"audit_{self.hostname}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(md_path, 'w') as f:
            f.write(self.generate_markdown_report())
        print(f"Markdown report saved: {md_path}")


def main():
    """Main entry point."""
    audit = SecurityAudit()
    audit.run_all_audits()
    
    # Print text report to console
    print("\n" + audit.generate_text_report())
    
    # Save to files
    audit.save_reports("reports")
    
    print("\nAudit complete! Check the 'reports/' directory for saved reports.")


if __name__ == "__main__":
    main()
