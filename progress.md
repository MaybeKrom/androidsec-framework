# Progress

Record of the androidsec web UI through Phase 5 of `Android_Security_Framework_Web_Plan.md`.

`python main.py` still runs the command-line assessment. The site binds to `127.0.0.1:5000`. Phase 5 is a finding review. It calls the provider the user selects and does not run an exploit.

## Phase 0 and Phase 1 — Assessment in the browser

Goal: open the site, choose an APK and analyzers, run a scan without freezing the server, and read the HTML report.

- Read the CLI, analyzers, rules, and report generator before changing them.
- Moved the scan body in `main.py` into `run_scan(...)`. The CLI still parses arguments, opens the analyzer picker when no selection is given on the command line, and calls `run_scan`.
- Web scans call `run_scan` with `start_adb=False` and an `on_progress` callback. A failure in that callback does not break the CLI.
- Added the Flask app in `webapp/`. `python -m webapp.app` serves Home and Assessment.
- Home explains static and dynamic checks. Assessment lists the project APKs and uploads, shows analyzer checkboxes (static on, dynamic off), and keeps Start scan in a sticky bar.
- Each scan runs on a background thread. The scanning page polls `/scan/<id>/status`. The report is the generator's own HTML, including the link to `masvs_explanations.html`.
- Uploads are limited to 256 MB. A report file is served when its name belongs to a live scan. `masvs_explanations.html` is served with it.

Checked: `--list-analyzers`, `--help`, the unit tests, a CLI scan of UnCrackable with `--only apk_info manifest --no-gui --no-adb`, and a live web scan that kept answering while an analyzer was running.

## Phase 2 — Real APKs only

- An upload is kept only when it starts with a ZIP header and Androguard accepts it as an APK with a package name.
- The list shows package, version, and size, and selects the file that was just uploaded.
- Delete applies only to `upload:` files. The three sample APKs in the project root stay. The browser asks before a delete.
- Package details are cached in `webapp/meta/` by size and modification time, so an unchanged APK is not parsed again on every page load.
- A choice is only `root:<name>` or `upload:<name>`. Names with a slash or `..` are rejected.

Checked: a non-zip and a zip without a manifest were refused. Delete of `root:DivaApplication.apk` and of a traversal key was refused. An uploaded APK could be scanned and then deleted.

## Design

- Teal and ink layout: cards, a sticky launch bar, primary and danger buttons, a loading spinner, and a footer at the bottom of the page.
- Home, assessment, and the scanning page were screenshotted at a desktop width. Assessment was also checked at a phone width.
- Long APK names wrap inside the card.

## Phase 3 — Decompile, browse, and rebuild

- Added `webapp/decompile.py`, separate from scan jobs.
- Decode uses apktool. Java sources use jadx when it is installed.
- The browser shows one directory at a time. A file or a zip of that tree can be downloaded. Paths stay inside the job directory, and symlinks are skipped.
- Rebuild runs `apktool b` on a background thread. The SnakeYAML tag Debian apktool writes at the top of `apktool.yml` is removed before the build, and `--use-aapt2` is used when `aapt2` is on PATH.
- Assessment has a Decompile button. The decode page shows a spinner until the tree is ready.

Checked on UnCrackable: browse, text preview, zip download, a `../` download returned 404, and rebuild wrote an APK. `python main.py --list-analyzers` still listed the analyzers.

## Phase 4 — ADB device step

Goal from the plan: during an assessment, talk to a connected phone or emulator. Detect devices, allow an IP when none is ready, require the sentence "I confirm I am fully authorized to test this device and application.", install the APK only when that package is missing, and request root with a timeout.

- New page at `/device`, linked from the header.
- Starting a scan that includes any dynamic analyzer opens this page first. A static-only scan does not.
- The page lists `adb devices -l` and marks each one Ready, Unauthorized, Offline, or No permissions.
- Connect takes an IPv4 address and a port. The port defaults to 5555. Disconnect is limited to a serial that contains a port.
- Connect, install, and root run on a background thread. Connect stops after 15 seconds, root after 30 seconds, and install after 2 minutes. The waiting page polls until the device answers or the time limit hits.
- Install runs `pm path` first. When the package is already on the device, it stops there.
- Root runs `id`, then `adb root` for emulator and userdebug images, then `su -c id` so a phone can show its superuser prompt. The commands are fixed. The page does not offer a free-form shell. Serials and package names are checked before they are passed to adb.
- A dynamic scan sets `ANDROID_SERIAL` for that scan, under a lock, because the dynamic analyzers call `adb` without their own serial. The device inspector uses that serial when it is ready, and skips the check when it is not, so a scan does not move to a different phone. The scan still passes `start_adb=False`.
- With `ANDROID_SERIAL` unset, the CLI keeps the previous behavior and uses the first ready device.

Files:

- `webapp/device.py`
- `webapp/templates/device.html`
- `webapp/templates/device_wait.html`
- `webapp/app.py`
- `webapp/jobs.py`
- `webapp/templates/base.html`
- `webapp/templates/home.html`
- `webapp/templates/assess.html`
- `webapp/static/style.css`
- `analyzers/adb_device_inspector.py`
- `tests/test_device.py`

Checked against the attached VirtualBox device `10.0.2.5:5555` (Android 9, SDK 28, Innotek GmbH):

- The device page listed it as Ready and showed the model.
- Connect reported `already connected to 10.0.2.5:5555`.
- Install without the authorization checkbox did not start.
- Install while UnCrackable was present reported that `owasp.mstg.uncrackable1` was already installed.
- UnCrackable was uninstalled and installed again from the page. `pm path` shows the package is back.
- Request root succeeded. adbd on that emulator is now running as root (`uid=0`). `adb get-state` still reports `device`.
- A scan of only `adb_inspector`, with the checkbox and that serial, wrote `output_reports/security_report_20261111_162458.html`. The report says `Device: 10.0.2.5:5555` and that the package is installed.
- The same scan without the checkbox returned to the device page and did not start.
- `python main.py --list-analyzers` still lists the static and dynamic analyzers.
- 26 unit tests pass. The new tests cover device parsing, serial and IP checks, the install argument list, a root timeout, and the authorization gate. Those tests do not talk to the phone.
- Desktop and phone screenshots of the device page: on a narrow window the Device link wraps onto its own row, and the shell line shows `uid=0(root)`.

To put that emulator's adbd back to the normal shell user:

```
adb -s 10.0.2.5:5555 unroot
```

## Phase 5 — Finding review

Each new report row has a Review link. The page shows that finding’s evidence and recommendation. A new review requires both acknowledgments, a provider, a model name, and an API key. The first reply must contain `Hi, im fully ready`. Providers are OpenAI, Anthropic (Claude), Google Gemini, OpenRouter, DeepSeek, xAI, and any other OpenAI-compatible address. The model name can be edited. The key is not stored. The written review is saved in `webapp/reviews.sqlite` under the package name and rule id, so the same finding can be opened later with the key field empty.

The model is asked to explain the finding and how to fix it. The page does not ask for exploit code, and it does not store or run an attack script.

Checked: 42 unit tests pass, including the report link, the acknowledgment gate, a reply that is not ready, a saved review that does not contain the API key, and the OpenAI, Claude, Gemini, OpenRouter, DeepSeek, xAI, and custom request shapes.

## Still ahead

- Phase 6, the broader polish and documentation pass, was not started as its own phase. The device page uses the same layout as the rest of the site.

## How to run

```
python main.py --help
python -m webapp.app
```

Open http://127.0.0.1:5000. For a dynamic check, select the analyzer and continue. The device step asks for the authorization checkbox before it connects, installs, requests root, or starts the scan.
