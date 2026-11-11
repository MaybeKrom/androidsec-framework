# androidsec — Android APK Security Assessment Tool

**androidsec** is an integrated Android application security assessment tool that performs both **static** and **dynamic** analysis on APK files. It produces detailed HTML and JSON security reports mapped to the **OWASP MASVS** (Mobile Application Security Verification Standard).

## Features

### Static Analysis
- **APK Information** — Package name, version, signing certificates, SDK versions
- **Manifest Analysis** — `debuggable`, `allowBackup`, `usesCleartextTraffic`, legacy storage flags
- **Permission Analysis** — Categorises permissions by sensitivity (location, SMS, contacts, camera, etc.)
- **Exported Component Detection** — Identifies exported activities, services, receivers, and providers
- **Attack Surface Analysis** — Deep link enumeration, browsable intent-filters, wildcard hosts
- **Secret Detection** — AWS keys, Google API keys, Firebase tokens, private keys, JWTs, hardcoded passwords, hex blobs — scans both DEX strings and native `.so` files
- **Static Code Scan** — Weak crypto (ECB, DES), insecure random, trust-all certificates, hostname verifier bypass
- **Resilience Controls** — Detects root/Frida/Xposed/debug/emulator checks (positive controls)
- **Storage Analysis** — World-readable/writable files, external storage usage, sensitive data logging
- **Network Configuration** — `networkSecurityConfig` presence, cleartext traffic, hardcoded HTTP URLs
- **WebView Security** — JavaScript bridge, file access, universal access misconfigurations
- **API & Endpoint Extraction** — URL and S3 bucket discovery from DEX strings
- **Cloud Misconfiguration** — Firebase database read-access testing

### Dynamic Analysis (requires ADB device/emulator)
- **ADB Device Inspector** — Device properties, app installation status
- **Runtime Inspector** — App launch monitoring, crash detection via logcat
- **Frida Runtime Analyzer** — Hooks SharedPreferences writes and Cipher operations at runtime
- **Log Analyzer** — Scans logcat for leaked passwords, tokens, credit card numbers, emails

### Reporting
- **HTML Report** — Professional styled report with executive summary, findings table, severity badges, MASVS categories
- **JSON Report** — Machine-readable format for CI/CD integration
- **Risk Scoring** — Weighted severity × confidence model, capped at 100, with PASS/LOW/MEDIUM/HIGH/CRITICAL levels

## Installation

```bash
# Install Python dependencies
pip install -r requirements.txt

# For dynamic analysis, ensure the following are available:
# - ADB (Android Debug Bridge) on PATH
# - Frida server running on the target device/emulator
```

## Usage

```bash
# Basic scan (runs static + dynamic analyzers)
python main.py target.apk

# Run only static analysis (no ADB device or emulator required)
python main.py target.apk --static-only

# Scan with specific output directory
python main.py target.apk -o ./my_reports

# Run only specific analyzers
python main.py target.apk --only manifest permission component secret_detector

# Skip specific analyzers
python main.py target.apk --skip frida runtime adb_inspector

# List all available analyzers
python main.py --list-analyzers

# Run unit test suite
python -m unittest discover -s tests -p "test_*.py"
```

### Available Analyzer IDs

| ID | Type | Description |
|----|------|-------------|
| `apk_info` | Static | APK metadata and certificate info |
| `manifest` | Static | AndroidManifest.xml security flags |
| `permission` | Static | Permission sensitivity analysis |
| `component` | Static | Exported component detection (activities, services, receivers, providers) |
| `attack_surface` | Static | Deep link / intent-filter analysis |
| `secret_detector` | Static | Secret / credential detection in DEX and native .so libraries |
| `static_code` | Static | Cryptographic & security code pattern scanning |
| `storage` | Static | Storage security patterns |
| `network` | Static | Network security configuration & cleartext detection |
| `webview` | Static | WebView security analysis |
| `api_extractor` | Static | URL / S3 bucket extraction |
| `deeplink_fuzzer` | Static | Browsable activity enumeration |
| `cloud_checker` | Static | Firebase misconfiguration testing |
| `adb_inspector` | Dynamic | ADB device inspection |
| `runtime` | Dynamic | Runtime crash & monkey trace monitoring |
| `frida` | Dynamic | Frida runtime instrumentation |
| `log` | Dynamic | Logcat sensitive data scanning |

## Architecture

```
main.py                  # CLI Orchestrator — runs analyzers, enriches findings, generates reports
context.py               # AppContext — lazy-loaded APK/DEX/ZIP access with caching
├── analyzers/           # 13 analyzer modules (static + dynamic)
│   ├── utils.py         # Shared utilities (SHA-256, device checks, formatting)
│   ├── apk_info_analyzer.py
│   ├── manifest_analyzer.py
│   ├── permission_analyzer.py
│   ├── component_analyzer.py
│   ├── attack_surface_analyzer.py
│   ├── secret_detector.py
│   ├── static_code_scanner.py
│   ├── storage_analyzer.py
│   ├── network_config_analyzer.py
│   ├── adb_device_inspector.py
│   ├── runtime_inspector.py
│   ├── frida_runtime_analyzer.py
│   └── log_analyzer.py
├── extra/               # Additional analysis modules
│   ├── webview_analyzer.py
│   ├── api_extractor.py
│   ├── deeplink_fuzzer.py
│   └── cloud_misconfig_checker.py
├── engine/
│   └── risk_engine.py   # Severity × confidence risk scoring
├── rules/
│   ├── rules.json       # Rule definitions (severity, description, recommendation)
│   ├── owasp_mapping.json  # Rule → OWASP MASVS mapping
│   ├── rules_engine.py  # Enriches findings with rule metadata
│   └── owasp_mapper.py  # Applies MASVS tags
├── reporter/
│   └── report_generator.py  # HTML + JSON report generation
├── tests/               # Unit test suite
│   ├── test_rules.py    # Rule integrity & mapping tests
│   ├── test_risk_engine.py # Risk scoring tests
│   └── test_utils.py    # Utility function tests
├── scripts/
│   └── runtime_monitor.js   # Frida instrumentation script
└── output_reports/      # Generated reports (gitignored)
```

## OWASP MASVS Coverage

| Category | Coverage |
|----------|----------|
| MASVS-STORAGE | SharedPreferences, external storage, world-readable files, sensitive logging |
| MASVS-CRYPTO | Weak ciphers (ECB, DES), weak hashes (MD5, SHA-1), insecure random |
| MASVS-NETWORK | Cleartext traffic, missing networkSecurityConfig, HTTP URLs, trust-all certs |
| MASVS-PLATFORM | Permissions, exported components, deep links, WebView misconfigurations |
| MASVS-RESILIENCE | Root/Frida/Xposed/debug/emulator detection (positive controls) |
| MASVS-CODE | Runtime crash detection |

## Running Tests

Execute the automated test suite with Python's built-in `unittest`:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Sample APKs

The repository includes three test APKs:
- **DivaApplication.apk** — DIVA (Damn Insecure and Vulnerable App)
- **InsecureBankv2.apk** — InsecureBankv2
- **UnCrackable-Level1.apk** — OWASP UnCrackable Level 1

## License

Graduation project — for educational purposes only.
