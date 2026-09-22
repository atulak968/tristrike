#!/usr/bin/env python3
"""
TriStrike AI — Unified Autonomous Multi-Agent Security Tool
============================================================
Combines HexStrike (MCP/Arsenal), Agentic Bug Hunter (CLI/Workflow),
and BugTraceAI (Skeptical Reviewer & Patch Generator).
"""

import sys
import os
import argparse
import time
from datetime import datetime

# Suppress urllib3 InsecureRequestWarning cleanly
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.scope import ScopeManager
from engines.recon import ReconEngine
from engines.crawler import CrawlerEngine
from engines.vulnerability import VulnerabilityEngine
from agents.skeptic import SkepticalReviewer
from reports.generator import ReportGenerator

BANNER = r"""
  ______     _ _____ _        _ _            ___  _____ 
  | ___ \   (_)  ___| |      (_) |          / _ \|_   _|
  | |_/ / __ _| |__ | |_ _ __ _| | _____   / /_\ \ | |  
  | ___ \/ _` |  __|| __| '__| | |/ / _ \  |  _  | | |  
  | |_/ / (_| | |___| |_| |  | |   <  __/  | | | |_| |_ 
  \____/ \__,_\____/ \__|_|  |_|_|\_\___|  \_| |_/\___/ 
      Autonomous Multi-Agent Penetration Testing Platform
"""

def run_pipeline(target: str, scope: list = None, output_dir: str = "reports_output"):
    print(BANNER)
    start_time = time.time()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"https://{target}"

    print(f"[*] Target: {target}")
    scope_mgr = ScopeManager(target, scope)
    print(f"[*] Scope Enforced: {scope_mgr.scope_patterns}")

    # 1. Reconnaissance Agent
    print("\n[+] [1/4] Running Reconnaissance Agent (Subdomains, Ports, Tech)...")
    recon = ReconEngine(scope_mgr)
    recon_data = recon.run(target)
    print(f"    -> Discovered Subdomains: {len(recon_data['subdomains'])}")
    print(f"    -> Open Ports: {recon_data['open_ports']}")
    print(f"    -> Tech Stack Detected: {recon_data['tech_stack']}")

    # 2. Crawler & Discovery Agent
    print("\n[+] [2/4] Running Discovery & Crawler Agent (Routes, Parameters, Sensitive Paths)...")
    crawler = CrawlerEngine(scope_mgr)
    crawl_data = crawler.crawl(target)
    print(f"    -> Crawled Endpoints: {len(crawl_data['all_endpoints'])}")
    print(f"    -> Actionable Parameter Endpoints: {len(crawl_data['param_endpoints'])}")
    print(f"    -> Sensitive/Hidden Paths Detected: {len(crawl_data['hidden_paths'])}")

    # 3. Multi-Vector Vulnerability Testing Agent
    print("\n[+] [3/4] Running Active Vulnerability Agent...")
    vuln_engine = VulnerabilityEngine(scope_mgr)
    raw_findings = []

    # A. Security Header Audits
    print("    -> Checking Security Headers & Clickjacking defenses...")
    raw_findings.extend(vuln_engine.test_security_headers(target))

    # B. CORS Origin Reflection Audits
    print("    -> Testing CORS policies...")
    raw_findings.extend(vuln_engine.test_cors(target))

    # C. Sensitive Paths & Leakage Audits
    if crawl_data['hidden_paths']:
        print("    -> Auditing sensitive files & information disclosures...")
        raw_findings.extend(vuln_engine.test_sensitive_paths(crawl_data['hidden_paths']))

    # D. Active Injection & Parameter Audits (SQLi, XSS, Open Redirect)
    test_targets = crawl_data['param_endpoints']
    print(f"    -> Auditing {len(test_targets[:12])} dynamic parameter endpoints for SQLi, XSS, Redirects...")
    for ep in test_targets[:12]:
        raw_findings.extend(vuln_engine.test_sqli(ep))
        raw_findings.extend(vuln_engine.test_xss(ep))
        raw_findings.extend(vuln_engine.test_open_redirect(ep))

    print(f"    -> Total Potential Findings Identified: {len(raw_findings)}")

    # 4. Skeptical Reviewer & Reality Gate (BugTraceAI False Positive Elimination)
    print("\n[+] [4/4] Running Skeptical Reviewer Agent (False-Positive Elimination)...")
    verified_findings = []
    for f in raw_findings:
        is_valid, reason, meta = SkepticalReviewer.review(f)
        if is_valid:
            f["verification"] = meta
            verified_findings.append(f)
            print(f"    [VERIFIED FINDING] [{f.get('severity', 'INFO').upper()}] {f['title']}")
        else:
            print(f"    [REJECTED FALSE POSITIVE] {f['title']} -> {reason}")

    # 5. Report Generation
    print("\n[+] Generating Audit Reports (HTML, Markdown, JSON)...")
    report_data = {
        "target": target,
        "scan_time_seconds": round(time.time() - start_time, 2),
        "recon": recon_data,
        "discovery": crawl_data,
        "findings": verified_findings
    }
    paths = ReportGenerator.generate(report_data, output_dir=output_dir)

    print("\n" + "="*60)
    print("✅ TriStrike Assessment Complete!")
    print(f"⏱️  Duration: {report_data['scan_time_seconds']}s")
    print(f"🎯 Total Verified Findings: {len(verified_findings)}")
    print(f"📄 HTML Report:     {paths['html']}")
    print(f"📝 Markdown Report: {paths['markdown']}")
    print(f"📊 JSON Data:       {paths['json']}")
    print("="*60 + "\n")

def main():
    parser = argparse.ArgumentParser(description="TriStrike AI - Autonomous Multi-Agent Security Tool")
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("--scope", nargs="*", help="Allowed in-scope domains/patterns")
    parser.add_argument("--output", default="reports_output", help="Directory for generated reports")

    args = parser.parse_args()
    run_pipeline(args.target, args.scope, args.output)

if __name__ == "__main__":
    main()
