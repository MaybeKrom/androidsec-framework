import os
import time
import subprocess

def run(ctx):
    L, F = ["=== Frida Runtime Analyzer ==="], []
    try:
        import frida
    except ImportError:
        L.append("[!] frida-python not installed — SKIPPED")
        return {"tool": "frida", "output": "\n".join(L), "findings": [], "skipped": True}

    try:
        # Safely get package name
        try:
            pkg = ctx.apk.get_package()
        except Exception:
            L.append("[!] Could not determine package name — SKIPPED")
            return {"tool": "frida", "output": "\n".join(L), "findings": [], "skipped": True}

        # Stop old instances
        subprocess.run(["adb", "shell", "am", "force-stop", pkg], capture_output=True)

        # Launch the app
        L.append(f"Launching {pkg} via ADB Monkey...")
        subprocess.run(["adb", "shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"], capture_output=True, timeout=10)
        
        L.append("Waiting 6 seconds for app to fully load...")
        time.sleep(6) 
        
        # 100% Reliable PID finding using ADB directly
        L.append("Finding PID via ADB...")
        pid_out = subprocess.run(["adb", "shell", "pidof", pkg], capture_output=True, text=True).stdout.strip()
        
        if not pid_out:
            L.append("[!] App process not found by ADB.")
            return {"tool": "frida", "output": "\n".join(L), "findings": [], "skipped": True}

        target_pid = int(pid_out.split()[0]) 
        L.append(f"Found PID: {target_pid}")

        # Connect to Frida
        dev = frida.get_usb_device(timeout=5)
        L.append(f"Attaching Frida to PID {target_pid}...")
        session = dev.attach(target_pid)

        L.append("Attached! Injecting script...")
        script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "runtime_monitor.js")
        
        with open(script_path, "r", encoding="utf-8") as f:
            js_code = f.read()

        script = session.create_script(js_code)
        frida_logs = []
        
        def on_message(message, data):
            try:
                if isinstance(message, dict):
                    mtype = message.get('type', '')
                    if mtype == 'send':
                        frida_logs.append(str(message.get('payload', '')))
                    elif mtype == 'error':
                        frida_logs.append(f"[Frida Error] {message.get('stack', '')}")
            except Exception:
                pass

        script.on('message', on_message)
        script.load()
        
        L.append("\nListening for runtime events (10 seconds)... Interact with the app now.")
        time.sleep(10) 

        session.detach()

        if frida_logs:
            L.append(f"\nCaptured {len(frida_logs)} Frida events:")
            for log in frida_logs[:50]:
                L.append(f"  {log}")
            
            for log in frida_logs:
                if "[SharedPreferences] Saved" in log:
                    F.append({"rule_id": "RUNTIME_PREF_PASSWORD", "evidence": log})
                elif "[Crypto] Cipher Algorithm" in log:
                    F.append({"rule_id": "RUNTIME_CRYPTO", "evidence": log})
        else:
            L.append("  [-] No Frida events captured. Did you interact with the app?")

    except Exception as e:
        L.append(f"[!] Frida runtime error: {e}")

    return {"tool": "frida", "output": "\n".join(L), "findings": F}
