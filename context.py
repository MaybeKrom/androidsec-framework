import hashlib
import os
import pickle
from zipfile import ZipFile
from lxml import etree

try:
    from loguru import logger
    logger.disable("androguard")
except ImportError:
    pass

CACHE_DIR = os.path.expanduser("~/.androidsec/cache")

def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

class AppContext:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self._apk = None
        self._dex = None
        self._dx = None
        self._zip = None
        self._sha = None
        self._manifest_root = None
        self._parsed_manifest = False

    @property
    def sha256(self):
        if self._sha is None:
            self._sha = _sha256_file(self.apk_path)
        return self._sha

    @property
    def zip(self):
        if self._zip is None:
            self._zip = ZipFile(self.apk_path)
        return self._zip

    @property
    def apk(self):
        if self._apk is None:
            from androguard.core.apk import APK
            self._apk = APK(self.apk_path)
        return self._apk

    @property
    def dex(self):
        if self._dex is not None:
            return self._dex
        cache_path = os.path.join(CACHE_DIR, f"{self.sha256}.pkl")
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "rb") as f:
                    self._apk, self._dex, self._dx = pickle.load(f)
                return self._dex
            except Exception:
                pass
        from androguard.misc import AnalyzeAPK
        self._apk, self._dex, self._dx = AnalyzeAPK(self.apk_path)
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(cache_path, "wb") as f:
                pickle.dump((self._apk, self._dex, self._dx), f)
        except Exception:
            pass
        return self._dex

    @property
    def dx(self):
        if self._dx is None:
            _ = self.dex
        return self._dx

    def get_manifest_root(self):
        if self._parsed_manifest:
            return self._manifest_root
            
        self._parsed_manifest = True
        try:
            # Use Androguard's AXMLPrinter directly on the zip bytes
            from androguard.core.axml import AXMLPrinter
            raw_axml = self.zip.read("AndroidManifest.xml")
            ap = AXMLPrinter(raw_axml)
            xml_str = ap.get_xml()
            if xml_str:
                self._manifest_root = etree.fromstring(xml_str, parser=etree.XMLParser(recover=True))
                return self._manifest_root
        except Exception:
            pass
        
        # Fallback to Androguard's parser
        try:
            root = self.apk.get_android_manifest_xml()
            if isinstance(root, str):
                self._manifest_root = etree.fromstring(root.encode('utf-8'), parser=etree.XMLParser(recover=True))
            else:
                self._manifest_root = root
            return self._manifest_root
        except Exception:
            return None
