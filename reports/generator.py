"""
Unified Report Generator (HTML, Markdown, JSON)
Produces submission-ready security assessment reports.
"""

import json
import os
from datetime import datetime

class ReportGenerator:
    @staticmethod
    def generate(results: dict, output_dir: str = "output") -> dict:
        os.makedirs(output_dir, exist_ok=True)
        target = results.get("target", "unknown")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base_name = f"tristrike_report_{timestamp}"

        json_path = os.path.join(output_dir, f"{base_name}.json")
        md_path = os.path.join(output_dir, f"{base_name}.md")
        html_path = os.path.join(output_dir, f"{base_name}.html")

        # 1. JSON Report
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        # 2. Markdown Report
        findings = results.get("findings", [])
        recon = results.get("recon", {})
        md_content = [
            f"# TriStrike AI — Security Assessment Report",
            f"**Target:** `{target}`  ",
            f"**Scan Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Total Verified Findings:** {len(findings)}  ",
            "\n---\n",
            "## 1. Executive Summary",
            f"TriStrike AI multi-agent engine executed an autonomous assessment against `{target}`.",
            f"Detected Technologies: {', '.join(recon.get('tech_stack', [])) or 'None'}",
            f"Open Ports: {', '.join(map(str, recon.get('open_ports', []))) or 'None'}",
            "\n## 2. Verified Vulnerabilities (Skeptical Reviewer Validated)",
        ]

        if not findings:
            md_content.append("\n*No high-severity vulnerabilities confirmed during this assessment.*")
        else:
            for i, f in enumerate(findings, 1):
                md_content.extend([
                    f"\n### {i}. [{f.get('severity', 'INFO').upper()}] {f.get('title')}",
                    f"- **URL:** `{f.get('url')}`",
                    f"- **CWE:** {f.get('cwe', 'N/A')} | **CVSS:** {f.get('cvss', 'N/A')}",
                    f"- **Payload:** `{f.get('payload', 'N/A')}`",
                    f"- **Evidence:** {f.get('evidence')}",
                    f"\n**Remediation Patch:**",
                    "```javascript",
                    f"{f.get('verification', {}).get('remediation', 'N/A')}",
                    "```",
                ])

        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md_content))

        # 3. HTML Report
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>TriStrike AI Report — {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 2rem; }}
        .container {{ max-width: 960px; margin: 0 auto; background: #131b2e; border: 1px solid #1e293b; border-radius: 12px; padding: 2.5rem; }}
        h1 {{ color: #00f0ff; margin-top: 0; }}
        .badge {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 4px; font-weight: bold; font-size: 0.8rem; text-transform: uppercase; }}
        .critical {{ background: #dc2626; color: white; }}
        .high {{ background: #ea580c; color: white; }}
        .medium {{ background: #d97706; color: white; }}
        .info {{ background: #0284c7; color: white; }}
        .card {{ background: #1a233a; border: 1px solid #2d3b59; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; }}
        pre {{ background: #0a0d14; border: 1px solid #2d3b59; border-radius: 6px; padding: 1rem; overflow-x: auto; color: #38bdf8; }}
        code {{ font-family: monospace; color: #a78bfa; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>⚔️ TriStrike AI Security Assessment Report</h1>
        <p><strong>Target:</strong> <code>{target}</code> | <strong>Verified Findings:</strong> {len(findings)}</p>
        <p><strong>Technologies:</strong> {', '.join(recon.get('tech_stack', [])) or 'None'}</p>
        <hr style="border: 0; border-top: 1px solid #2d3b59; margin: 2rem 0;">
        <h2>Verified Vulnerabilities</h2>
        {"".join([f'''
        <div class="card">
            <span class="badge {f.get('severity', 'info')}">{f.get('severity', 'info')}</span>
            <h3 style="margin: 0.5rem 0;">{f.get('title')}</h3>
            <p><strong>URL:</strong> <code>{f.get('url')}</code></p>
            <p><strong>Evidence:</strong> {f.get('evidence')}</p>
            <p><strong>Remediation Patch:</strong></p>
            <pre>{f.get('verification', {}).get('remediation', 'Follow secure coding practices.')}</pre>
        </div>''' for f in findings]) if findings else "<p>No vulnerabilities detected.</p>"}
    </div>
</body>
</html>"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return {
            "json": json_path,
            "markdown": md_path,
            "html": html_path
        }
