# TriStrike AI ⚔️
### Unified Autonomous Multi-Agent Web Security & Vulnerability Engineering Platform
*Synthesizing the core architectures of **HexStrike AI**, **Agentic Bug Hunter**, and **BugTraceAI**.*

---

## 🏗️ Architecture

```
                                  [ User Target & Scope ]
                                             │
                                             ▼
                     ┌───────────────────────────────────────────────┐
                     │           TriStrike Execution Core            │
                     └───────────────────────┬───────────────────────┘
                                             │
          ┌──────────────────────────────────┼──────────────────────────────────┐
          ▼                                  ▼                                  ▼
┌──────────────────┐               ┌──────────────────┐               ┌──────────────────┐
│   HexStrike AI   │               │Agentic Bug Hunter│               │   BugTraceAI     │
│  (Recon Engine)  │               │ (Crawler Engine) │               │(Skeptical Review)│
│ • Subdomain enum │               │ • Sensitive Path │               │ • 7-Question Gate│
│ • Port probing   │               │   Probing        │               │ • False-Positive │
│ • Tech detection │               │ • Route & Param  │               │   Elimination    │
│                  │               │   Harvesting     │               │ • Code Patch Gen │
└──────────────────┘               └──────────────────┘               └──────────────────┘
          │                                  │                                  │
          └──────────────────────────────────┼──────────────────────────────────┘
                                             │
                                             ▼
                             ┌───────────────────────────────┐
                             │    Vulnerability Engine       │
                             │  (SQLi, XSS, Heuristic Fuzz)  │
                             └───────────────┬───────────────┘
                                             │
                                             ▼
                             ┌───────────────────────────────┐
                             │   Verified Audit Reports      │
                             │   • HTML Interactive Report   │
                             │   • Markdown Executive Doc    │
                             │   • JSON Machine Feed         │
                             └───────────────────────────────┘
```

---

## 🚀 Quick Start (Single Command Autonomous Scan)

Run a complete automated security audit on any authorized target:

```bash
# Basic usage
python3 tristrike.py "https://example.com"

# Specify custom scope patterns and custom reports folder
python3 tristrike.py "https://example.com" --scope "example.com" "*.example.com" --output my_reports/
```

---

## 🌟 Key Features

1. **100% Automated Multi-Agent Pipeline**:
   - Give only the **Target** and **Scope**; all 4 phases (Recon -> Crawling -> Active Testing -> Skeptical Verification -> Reporting) execute end-to-end autonomously.
2. **Skeptical Reviewer (Zero False-Positive Gate)**:
   - High/Critical findings require reproducible response evidence and valid payload execution proof before reaching the final report.
3. **Automated Developer Remediation**:
   - Every confirmed finding includes copy-paste secure code patch snippets.
4. **Triple-Format Reports**:
   - Generates interactive **HTML**, submission-ready **Markdown** (for HackerOne / Bugcrowd), and structured **JSON** simultaneously in ~25 seconds.
