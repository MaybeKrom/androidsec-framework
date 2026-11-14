<p align="center">
  <img src="design/androsec-logo.png" alt="androsec logo" width="720"/>
</p>

<h1 align="center">androsec</h1>

<p align="center">
  <strong>Android VAPT Assessment Framework</strong><br/>
  Graduation Project — College of Computer and Information Sciences<br/>
  <em>King Saud University (KSU)</em>
</p>

<p align="center">
  <a href="https://github.com/MaybeKrom/androidsec-framework"><img alt="GitHub" src="https://img.shields.io/badge/GitHub-MaybeKrom%2Fandroidsec--framework-181717?logo=github"/></a>
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white"/>
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Android-3DDC84?logo=android&logoColor=white"/>
  <img alt="MASVS" src="https://img.shields.io/badge/OWASP-MASVS-000000"/>
  <img alt="License" src="https://img.shields.io/badge/Use-Authorized%20lab%20testing%20only-B8FF30"/>
</p>

<p align="center">
  Automated static &amp; dynamic Android security assessment · AI-assisted exploitation PoCs · MSS-style PDF reports
</p>

---

## Overview

**androsec** is a King Saud University graduation project that turns Android APK assessment into a practical VAPT workflow: scan → prioritize findings → dynamically verify → generate professional evidence-backed reports.

It is designed for **authorized lab environments** and intentionally vulnerable training apps (DIVA, AndroGoat, InsecureBankv2, UnCrackable, Damn Vulnerable Bank), with a path toward MSS-style engagement deliverables.

| Pillar | What you get |
|--------|----------------|
| **Static analysis** | Manifest, components, secrets, crypto/SQL/WebView, network/NSC, SBOM, intent abuse, native libs, lab challenge mapping, attack-chain correlation |
| **Dynamic analysis** | ADB readiness, runtime crashes, run-as storage extraction, UIAutomator menus, Frida hooks, logcat secret detection |
| **AI exploitation** | Grounded PoC planning → ADB/Frida execution → Python evidence gate → single-finding exploitation PDF |
| **Reporting** | HTML · JSON · WeasyPrint PDF (cover, TOC, CVSS estimate, section page-breaks) |

---

## Academic context

| Field | Detail |
|-------|--------|
| **Institution** | King Saud University (KSU), Riyadh |
| **College** | College of Computer and Information Sciences |
| **Type** | Senior / graduation project |
| **Author** | [Abdulkarim Alshehri](https://github.com/MaybeKrom) (`MaybeKrom`) |
| **Focus** | Android application security assessment & automated PoC evidence |

---

## Screenshots & deliverables

Security assessment PDFs and AI exploitation reports are produced locally under `output_reports/` and `exploitations/`. The web UI provides one-click PDF download for both full-app assessments and single-finding exploitation write-ups.

---

## Feature highlights

### Core static analyzers
- APK metadata, certificates, native ABIs  
- Manifest security flags (`debuggable`, backup, cleartext, affinity, `sharedUserId`)  
- Exported components & provider authorities  
- Secret detection across DEX, assets/configs, and `.so` libraries  
- Weak crypto / TrustAll / HostnameVerifier / resilience controls  

### MSS-oriented extensions (`extra/`)
- SQL injection & ContentProvider URI candidates  
- Hardcoded crypto keys / weak transforms  
- SSL pinning vs TrustAll conflict analysis  
- Intent/provider abuse candidates with PoC commands  
- Native anti-analysis strings · SBOM fingerprints  
- Lab challenge mapper (DIVA / AndroGoat / IBV2 / UnCrackable / DVB)  
- Multi-signal finding correlator  

### Dynamic (ADB device / emulator)
- Device & Frida/root readiness  
- Runtime crash monitoring  
- `run-as` SharedPreferences / database extraction  
- UIAutomator challenge-menu capture  
- Frida SharedPreferences + Cipher hooks  
- Logcat secrets (Luhn-checked PANs; tombstone noise filtered)  

### AI exploitation (web UI)
- Default provider: **Anthropic Claude** (`claude-sonnet-5`)  
- Also: OpenAI, Gemini, OpenRouter, DeepSeek, xAI, custom OpenAI-compatible  
- Evidence-gated confirmation: `CONFIRMED` · `PARTIAL` · `UNCONFIRMED`  
- **BYOK**: paste an API key in the Exploit form — used only for that HTTP request (Authorization header). Keys are **not** written to reports, prompts, git, or server logs.  
- **What the LLM sees**: finding JSON (rule/title/severity/evidence/recommendation), package metadata, device model/serial, and prior step stdout. The APK binary itself is **not** uploaded.  

**Analyzer count:** **27** registered tools (`python main.py --list-analyzers`).

---

## Architecture

```text
┌──────────────────┐     ┌─────────────────────┐     ┌──────────────────┐
│  APK + optional  │────▶│  Analyzer suite     │────▶│  HTML/JSON/PDF   │
│  ADB device      │     │  (static+dynamic)   │     │  security report │
└──────────────────┘     └──────────┬──────────┘     └────────┬─────────┘
                                    │                         │
                                    │ findings                │ Exploit
                                    ▼                         ▼
                         ┌─────────────────────┐     ┌──────────────────┐
                         │  Web UI (Flask)     │────▶│  AI PoC pipeline │
                         │  analyzer picker    │     │  + evidence gate │
                         └─────────────────────┘     └────────┬─────────┘
                                                              ▼
                                                     Exploitation PDF
```

```text
analyzers/    core static & dynamic scanners
extra/        MSS extensions (SQL, crypto, SSL, intent, SBOM, lab, …)
rules/        severity catalog, OWASP MASVS map, dedupe
reporter/     HTML + PDF security reports
webapp/       Flask UI + AI exploit module
scripts/      Frida helpers
tests/        unit tests
design/       brand assets (logo)
```

---

## Quick start

### Requirements
- Python **3.10+**
- `adb` on `PATH` (for dynamic analysis)
- Optional: Frida (`frida-tools` + `frida-server` on device)
- Optional: WeasyPrint (+ Pango libs on Debian/Kali) for PDFs

### Install

```bash
git clone https://github.com/MaybeKrom/androidsec-framework.git
cd androidsec-framework
pip install -r requirements.txt
pip install weasyprint   # PDF export
```

### CLI scan

```bash
# Full scan
python main.py target.apk

# Static only
python main.py target.apk --static-only

# Select analyzers
python main.py target.apk --only manifest component secret_detector sql_injection lab_mapper finding_correlator

# List analyzers
python main.py --list-analyzers
```

### Web UI

```bash
cd webapp
python app.py
# → http://127.0.0.1:5000
```

1. Select / upload an APK  
2. Choose analyzers (static + dynamic)  
3. Download the security PDF  
4. Open a finding → **Exploit** → AI PoC + exploitation PDF  

---

## Analyzer catalog

| ID | Type | Description |
|----|------|-------------|
| `apk_info` | Static | Metadata, certificates, ABIs |
| `manifest` | Static | Security-relevant manifest flags |
| `permission` | Static | Dangerous permission inventory |
| `component` | Static | Exported components + authorities |
| `attack_surface` | Static | Deep-link / intent-filter surface |
| `secret_detector` | Static | Embedded secrets (DEX / assets / `.so`) |
| `static_code` | Static | Crypto / TLS patterns + resilience |
| `storage` | Static | Insecure storage patterns |
| `network` | Static | Cleartext / HTTP / NSC signals |
| `webview` | Static | JS bridge / file access |
| `api_extractor` | Static | URL / S3 / staging endpoint recon |
| `deeplink_fuzzer` | Static | Browsable activities + PoC URIs |
| `cloud_checker` | Static/Live | Firebase open-read probe |
| `sql_injection` | Static | SQL concatenation / provider URIs |
| `crypto_key` | Static | Hardcoded keys / weak transforms |
| `ssl_pinning` | Static | Pinning vs TrustAll |
| `intent_abuse` | Static | Exported Intent/provider abuse PoCs |
| `native_security` | Static | Native library security strings |
| `sbom` | Static | Third-party library fingerprints |
| `lab_mapper` | Static | Known lab-app challenge inventory |
| `finding_correlator` | Static | Correlated attack chains |
| `adb_inspector` | Dynamic | Device / env readiness |
| `runtime` | Dynamic | Launch + crash monitoring |
| `backup_extractor` | Dynamic | `run-as` prefs/DB extraction |
| `uiautomator` | Dynamic | UI / challenge menu dump |
| `frida` | Dynamic | Runtime hooks |
| `log` | Dynamic | Sensitive logcat findings |

---

## Reporting notes

- Noisy duplicate rules are **collapsed** for readability.  
- Cleartext / provider / TrustAll overlaps from multiple tools are **deduplicated**.  
- Correlator rows are **informational attack-chain notes** (do not double-count score).  
- `LAB_CHALLENGE` rows are **coverage inventory**, not automatic Confirmed vulns.  
- AWS key hits are **format-only** (not live-validated); known docs placeholders are Info.  
- Library DEX noise (OkHttp HostnameVerifier type refs, bare `checkServerTrusted`) is filtered.  
- Logcat scanning prefers **PID / package** scope and blocks UIAutomator dump tags.  
- Exploitation PDFs are **single-finding** reports (not the full-app scorecard).  
- Exploitation covers show **Severity + `CVSS X.X`** (severity-mapped estimate; not a full vector).  
- AI exploit ranking prefers deterministic ADB surfaces (provider / WebView / run-as) over TrustAll/TLS.  
- Skipped Frida/ADB tools are called out as **reduced dynamic coverage**.

---

## Lab environment tips

- Works well with VirtualBox **Kali + Android-x86** for ADB install/launch/logcat/content.  
- **Frida** is often flaky on android-x86 — prefer Genymotion, the official emulator, or a rooted phone for Frida-heavy PoCs.  
- Set `ANDROID_SERIAL` when multiple devices are connected.

---

## Tests

```bash
python -m unittest discover -s tests -p "test_*.py"
```

Lab expected-findings seeds (precision / recall benchmark helpers):

```text
tests/fixtures/lab_expected_findings.json
```

---

## Disclaimer

This framework is intended for **authorized security testing and academic evaluation** only. The authors are not responsible for misuse, unauthorized testing, or third-party API costs incurred by the AI exploitation module.

---

## Author

**Abdulkarim Alshehri** · King Saud University  
GitHub: [@MaybeKrom](https://github.com/MaybeKrom)

<p align="center">
  <sub>androsec · KSU Graduation Project</sub>
</p>
