# androsec — Android VAPT Assessment Framework

**androsec** is an Android application security assessment framework built for lab VAPT and graduation / MSS-style reporting. It combines **static analyzers**, **dynamic ADB/Frida/UIAutomator checks**, an **AI-assisted exploitation PoC pipeline**, and professional **HTML / JSON / PDF** deliverables mapped to **OWASP MASVS**.

> Authorized testing only. Use on apps and devices you own or have explicit permission to assess (DIVA, AndroGoat, InsecureBankv2, UnCrackable, Damn Vulnerable Bank, etc.).

## What’s inside

| Layer | Capability |
|-------|------------|
| Static | Manifest, components, secrets, crypto/SQL/WebView, network/NSC, SBOM, intent abuse, native `.so`, lab challenge mapper, attack-chain correlator |
| Dynamic | ADB device readiness, runtime crash watch, run-as prefs/DB extraction, UIAutomator challenge menus, Frida hooks, logcat secrets |
| AI Exploit | Grounded PoC planning → ADB/Frida execution → evidence gate → MSS PDF write-up with CVSS estimate + TOC |
| Reports | HTML + JSON + WeasyPrint PDF; single-finding exploitation PDFs |

## Feature highlights

### Core static analyzers
- **apk_info** — package/version/SDK, certs, native ABIs  
- **manifest** — debuggable, backup, cleartext, legacy storage, taskAffinity, sharedUserId  
- **permission** — dangerous permission inventory (informational by default)  
- **component** — exported activities/services/receivers/providers + authorities  
- **attack_surface** / **deeplink_fuzzer** — browsable links + generated `am start -d` PoCs  
- **secret_detector** — AWS/Google/Firebase/JWT/keys in DEX, configs, and `.so`  
- **static_code** — weak crypto, insecure random, TrustAll / HostnameVerifier, resilience controls  
- **storage** / **network** / **webview** — storage modes, cleartext/HTTP, JS bridge  

### MSS-oriented tools (`extra/`)
- **sql_injection** — rawQuery/execSQL / provider URI candidates  
- **crypto_key** — hardcoded keys/IVs and weak transforms  
- **ssl_pinning** — OkHttp/NSC pins vs TrustAll conflicts  
- **intent_abuse** — unprotected exported surfaces + PoC commands  
- **native_security** — anti-analysis / sensitive strings in native libs  
- **sbom** — third-party library fingerprints  
- **lab_mapper** — DIVA / AndroGoat / IBV2 / UnCrackable / DVB challenge inventory  
- **finding_correlator** — multi-signal attack chains (e.g. exported WebView + JS bridge)  
- **api_extractor** / **cloud_checker** — endpoint recon + Firebase open-read probe  

### Dynamic tools (need ADB device/emulator)
- **adb_inspector** — device props, ABI, root/Frida readiness  
- **runtime** — launch + FATAL EXCEPTION watch  
- **backup_extractor** — `run-as` SharedPreferences / databases when debuggable  
- **uiautomator** — UI hierarchy / challenge-menu capture  
- **frida** — SharedPreferences + Cipher hooks  
- **log** — password/token/email/CC (Luhn-validated) with tombstone noise filtered  

### AI exploitation (web UI)
- Provider support: Anthropic (default `claude-sonnet-5`), OpenAI, Gemini, OpenRouter, DeepSeek, xAI, custom  
- Evidence-gated confirmation (`CONFIRMED` / `PARTIAL` / `UNCONFIRMED`)  
- PDF: cover CVSS estimate, table of contents, section page-breaks, captured evidence  

## Installation

```bash
pip install -r requirements.txt

# PDF reports
pip install weasyprint
# Debian/Kali also need: sudo apt install libpango-1.0-0 libpangoft2-1.0-0

# Dynamic analysis
# - adb on PATH, device/emulator authorized
# - frida-tools + frida-server on device (for frida analyzer / AI Frida steps)
```

## CLI usage

```bash
# Full scan (static + dynamic)
python main.py target.apk

# Static only
python main.py target.apk --static-only

# Custom output directory
python main.py target.apk -o ./my_reports

# Select / skip analyzers
python main.py target.apk --only manifest component secret_detector sql_injection lab_mapper
python main.py target.apk --skip frida uiautomator

# List analyzers
python main.py --list-analyzers

# Tests
python -m unittest discover -s tests -p "test_*.py"
```

## Web UI

```bash
cd webapp
python app.py
# open http://127.0.0.1:5000
```

Flow: upload/select APK → choose analyzers → (optional) attach device → HTML/PDF security report → **Exploit** on a finding → AI PoC + exploitation PDF download.

## Analyzer IDs

| ID | Type | Description |
|----|------|-------------|
| `apk_info` | Static | Metadata + certificates + ABIs |
| `manifest` | Static | Security-relevant manifest flags |
| `permission` | Static | Dangerous permission inventory |
| `component` | Static | Exported components + provider authorities |
| `attack_surface` | Static | Deep link / intent-filter surface |
| `secret_detector` | Static | Embedded secrets (DEX/assets/.so) |
| `static_code` | Static | Crypto / TLS code patterns + resilience |
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
| `backup_extractor` | Dynamic | run-as prefs/DB extraction |
| `uiautomator` | Dynamic | UI / challenge menu dump |
| `frida` | Dynamic | Runtime hooks |
| `log` | Dynamic | Sensitive logcat findings |

## Reporting notes

- Duplicate noisy rules are **collapsed** (e.g. many HostnameVerifier hits → one row).  
- `MANIFEST_CLEARTEXT` and `NETWORK_CLEARTEXT_ALLOWED` are treated as equivalents (one kept).  
- Lab challenge rows (`LAB_CHALLENGE`) are **coverage inventory**, not automatic Confirmed vulns — confirm with exploit / dynamic tools.  
- Exploitation PDFs are **single-finding** reports (not the full-app scorecard).

## Project layout

```
analyzers/          # core static + dynamic analyzers
extra/              # MSS extensions (sql, crypto, ssl, intent, sbom, lab, …)
rules/              # rules.json, OWASP map, consolidate
reporter/           # HTML + PDF security reports
webapp/             # Flask UI + AI exploit pipeline
scripts/            # Frida JS helpers
tests/              # unit tests
```

## Environment tips

- **Android-x86 in VirtualBox** is fine for ADB install/launch/logcat/content; **Frida is often flaky** there — prefer Genymotion, official emulator, or a rooted phone for Frida-heavy work.  
- Set `ANDROID_SERIAL` when multiple devices are connected.

## License / ethics

For educational and authorized security testing. You are responsible for lawful use, API token spend, and lab isolation.
