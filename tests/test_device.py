"""Device-step checks. These tests do not talk to a real phone."""

import unittest

from analyzers.adb_device_inspector import choose_serial
from webapp.device import (
    AUTH_TEXT,
    parse_devices,
    parse_endpoint,
    perform_install,
    perform_root,
    valid_package,
    valid_serial,
)


SAMPLE_LIST = """List of devices attached
10.0.2.5:5555 device product:android_x86_64 model:VirtualBox device:x86_64 transport_id:1
emulator-5554 unauthorized
deadbeef offline
ABC123 no permissions
* daemon started successfully
"""


class ParseTests(unittest.TestCase):
    def test_parse_devices(self):
        devices = parse_devices(SAMPLE_LIST)
        by_serial = {item["serial"]: item for item in devices}
        self.assertEqual(set(by_serial), {"10.0.2.5:5555", "emulator-5554", "deadbeef", "ABC123"})
        ready = by_serial["10.0.2.5:5555"]
        self.assertTrue(ready["ready"])
        self.assertEqual(ready["model"], "VirtualBox")
        self.assertEqual(by_serial["emulator-5554"]["label"], "Unauthorized")
        self.assertEqual(by_serial["ABC123"]["state"], "no permissions")
        self.assertFalse(by_serial["deadbeef"]["ready"])

    def test_choose_serial_prefers_only_a_ready_match(self):
        self.assertEqual(choose_serial(SAMPLE_LIST), "10.0.2.5:5555")
        self.assertEqual(choose_serial(SAMPLE_LIST, "10.0.2.5:5555"), "10.0.2.5:5555")
        self.assertIsNone(choose_serial(SAMPLE_LIST, "emulator-5554"))
        self.assertIsNone(choose_serial(SAMPLE_LIST, "no-such-device"))
        self.assertIsNone(choose_serial(""))

    def test_serial_and_package_rules(self):
        self.assertTrue(valid_serial("10.0.2.5:5555"))
        self.assertTrue(valid_serial("emulator-5554"))
        self.assertFalse(valid_serial("10.0.2.5:5555;reboot"))
        self.assertFalse(valid_serial("-s"))
        self.assertFalse(valid_serial("serial name"))
        self.assertFalse(valid_serial(""))
        self.assertTrue(valid_package("owasp.mstg.uncrackable1"))
        self.assertFalse(valid_package("owasp.mstg.uncrackable1;id"))
        self.assertFalse(valid_package("-p"))
        self.assertFalse(valid_package("not a package"))

    def test_parse_endpoint(self):
        self.assertEqual(parse_endpoint("10.0.2.5", ""), ("10.0.2.5", 5555))
        self.assertEqual(parse_endpoint("10.0.2.5", "5555"), ("10.0.2.5", 5555))
        self.assertEqual(parse_endpoint("10.0.2.5:5555", ""), ("10.0.2.5", 5555))
        for host, port in (("example.com", "5555"), ("10.0.2.5", "0"), ("10.0.2.5", "abc"), ("10.0.2.5;id", "5555"), ("::1", "5555")):
            with self.assertRaises(ValueError):
                parse_endpoint(host, port)


class ActionTests(unittest.TestCase):
    def test_install_skips_when_package_is_present(self):
        import webapp.device as device

        calls = []

        def fake(args, timeout):
            calls.append(list(args))
            if args[2:4] == ["shell", "pm"]:
                return 0, "package:/data/app/owasp.mstg.uncrackable1/base.apk"
            raise AssertionError(args)

        original = device.run_adb
        device.run_adb = fake
        try:
            ok, message = perform_install("emulator-5554", "root:UnCrackable-Level1.apk")
        finally:
            device.run_adb = original
        self.assertTrue(ok)
        self.assertIn("already installed", message)
        self.assertTrue(all("install" not in call for call in calls))

    def test_install_uses_a_fixed_argument_list(self):
        import webapp.device as device

        calls = []

        def fake(args, timeout):
            calls.append(list(args))
            if args[2:4] == ["shell", "pm"]:
                return 1, ""
            if "install" in args:
                return 0, "Success"
            raise AssertionError(args)

        original = device.run_adb
        device.run_adb = fake
        try:
            ok, message = perform_install("emulator-5554", "root:UnCrackable-Level1.apk")
        finally:
            device.run_adb = original
        self.assertTrue(ok)
        self.assertIn("Installed", message)
        install = calls[-1]
        self.assertEqual(install[:4], ["-s", "emulator-5554", "install", "-r"])
        self.assertTrue(install[-1].endswith("UnCrackable-Level1.apk"))
        self.assertNotIn("shell", install)

    def test_root_timeout_does_not_become_success(self):
        import webapp.device as device

        def fake(args, timeout):
            if args[-3:] == ["su", "-c", "id"]:
                raise device.AdbError("adb timed out after 30 seconds.")
            if args[-1:] == ["id"]:
                return 0, "uid=2000(shell) gid=2000(shell)"
            if args[-1:] == ["root"]:
                return 1, "adbd cannot run as root in production builds"
            raise AssertionError(args)

        original = device.run_adb
        device.run_adb = fake
        try:
            ok, message = perform_root("emulator-5554")
        finally:
            device.run_adb = original
        self.assertFalse(ok)
        self.assertIn("Timed out waiting for root approval", message)


class GateTests(unittest.TestCase):
    def setUp(self):
        import webapp.app as web
        import webapp.device as device

        self.web = web
        self.device = device
        self.client = web.app.test_client()
        self.saved = {
            "create_job": web.create_job,
            "ready_serial": web.ready_serial,
            "action": device._start_action,
            "run_adb": device.run_adb,
            "device_ready": device.ready_serial,
            "list_devices": device.list_devices,
            "device_facts": device.device_facts,
            "shell_identity": device.shell_identity,
            "install_status": device.install_status,
        }

    def tearDown(self):
        self.web.create_job = self.saved["create_job"]
        self.web.ready_serial = self.saved["ready_serial"]
        self.device._start_action = self.saved["action"]
        self.device.run_adb = self.saved["run_adb"]
        self.device.ready_serial = self.saved["device_ready"]
        self.device.list_devices = self.saved["list_devices"]
        self.device.device_facts = self.saved["device_facts"]
        self.device.shell_identity = self.saved["shell_identity"]
        self.device.install_status = self.saved["install_status"]

    def test_dynamic_scan_requires_the_device_step(self):
        created = []
        self.web.create_job = lambda *args, **kwargs: created.append(kwargs) or "deadbeefdead"
        response = self.client.post("/scan", data={
            "apk": "root:UnCrackable-Level1.apk",
            "analyzers": ["manifest", "adb_inspector"],
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn("/device", response.headers["Location"])
        self.assertEqual(created, [])
        self.device.list_devices = lambda: {
            "available": True,
            "error": None,
            "devices": [{
                "serial": "emulator-5554",
                "state": "device",
                "model": "Test",
                "ready": True,
                "label": "Ready",
                "pill": "ready",
            }],
        }
        self.device.device_facts = lambda serial: {"facts": [{"label": "Model", "value": "Test"}], "error": None}
        self.device.shell_identity = lambda serial: "uid=2000(shell)"
        self.device.install_status = lambda serial, package: {"installed": False, "path": "", "error": None}
        page = self.client.get("/device")
        self.assertEqual(page.status_code, 200)
        self.assertIn(AUTH_TEXT.encode(), page.data)
        self.assertIn(b"adb_inspector", page.data)

    def test_bad_serial_never_starts_a_scan(self):
        created = []
        self.web.create_job = lambda *args, **kwargs: created.append(kwargs)
        response = self.client.post("/scan", data={
            "apk": "root:UnCrackable-Level1.apk",
            "analyzers": "adb_inspector",
            "authorized": "yes",
            "serial": "10.0.2.5:5555;reboot",
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn("/device", response.headers["Location"])
        self.assertEqual(created, [])

    def test_static_scan_does_not_need_a_device(self):
        created = []

        def fake(path, analyzers, serial=None):
            created.append(serial)
            return "abc123def456"

        self.web.create_job = fake
        response = self.client.post("/scan", data={
            "apk": "root:UnCrackable-Level1.apk",
            "analyzers": "manifest",
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn("/scan/abc123def456", response.headers["Location"])
        self.assertEqual(created, [None])

    def test_authorized_dynamic_scan_keeps_the_serial(self):
        created = []

        def fake(path, analyzers, serial=None):
            created.append((serial, list(analyzers)))
            return "abc123def456"

        self.web.create_job = fake
        self.web.ready_serial = lambda serial: serial == "10.0.2.5:5555"
        response = self.client.post("/scan", data={
            "apk": "root:UnCrackable-Level1.apk",
            "analyzers": "adb_inspector",
            "authorized": "yes",
            "serial": "10.0.2.5:5555",
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn("/scan/abc123def456", response.headers["Location"])
        self.assertEqual(created, [("10.0.2.5:5555", ["adb_inspector"])])

    def test_install_and_connect_require_authorization(self):
        started = []
        adb_calls = []
        self.device._start_action = lambda *args, **kwargs: started.append(args) or "abc123def456"
        self.device.run_adb = lambda *args, **kwargs: adb_calls.append(args) or (0, "")
        self.device.ready_serial = lambda serial: True

        blocked = self.client.post("/device/install", data={
            "apk": "root:UnCrackable-Level1.apk",
            "serial": "emulator-5554",
        })
        self.assertEqual(blocked.status_code, 302)
        self.assertEqual(started, [])

        bad_host = self.client.post("/device/connect", data={
            "authorized": "yes",
            "host": "10.0.2.5;id",
            "port": "5555",
        })
        self.assertEqual(bad_host.status_code, 302)
        self.assertEqual(adb_calls, [])
        self.assertEqual(started, [])

        allowed = self.client.post("/device/install", data={
            "authorized": "yes",
            "apk": "root:UnCrackable-Level1.apk",
            "serial": "emulator-5554",
        })
        self.assertEqual(allowed.status_code, 302)
        self.assertIn("/device/wait/abc123def456", allowed.headers["Location"])
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0][0], "install")


if __name__ == "__main__":
    unittest.main()
