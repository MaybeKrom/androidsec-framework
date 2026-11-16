/**
 * androsec lab Frida hooks — SharedPreferences, Cipher, and best-effort
 * SSL pinning bypass / HTTP URL logging for intentionally vulnerable apps
 * (DIVA, IB2, AndroGoat, OVAA, etc.).
 *
 * Each hook is independently try/caught so one failure does not break others.
 */
function startHooks() {
    if (typeof Java === "undefined" || !Java.available) {
        setTimeout(startHooks, 400);
        return;
    }

    Java.perform(function () {
        send("[*] Frida Script Injected Successfully!");

        try {
            var SharedPreferencesEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
            SharedPreferencesEditor.putString.implementation = function (key, value) {
                send("[SharedPreferences] Saved -> Key: " + key + " | Value: " + value);
                return this.putString(key, value);
            };
        } catch (e) {
            send("[-] Failed SharedPreferences: " + e);
        }

        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            Cipher.doFinal.overload("[B").implementation = function (data) {
                var algorithm = this.getAlgorithm();
                send("[Crypto] Cipher Algorithm: " + algorithm);
                var result = this.doFinal(data);
                send("[Crypto] Output Hex: " + bytesToHex(result));
                return result;
            };
        } catch (e) {
            send("[-] Failed Cipher: " + e);
        }

        // --- Lab SSL unpin / TrustAll-style hooks (educational apps) ---
        installSslUnpinHooks();
        installHttpUrlHooks();

        function bytesToHex(bytes) {
            var hex = [];
            for (var i = 0; i < bytes.length; i++) {
                hex.push(("0" + (bytes[i] & 0xff).toString(16)).slice(-2));
            }
            return hex.join("");
        }

        function installSslUnpinHooks() {
            // OkHttp CertificatePinner (common in lab samples / older apps)
            try {
                var CertificatePinner = Java.use("okhttp3.CertificatePinner");
                var checkOverloads = CertificatePinner.check.overloads;
                for (var i = 0; i < checkOverloads.length; i++) {
                    checkOverloads[i].implementation = function () {
                        send("[SSL-Unpin] OkHttp CertificatePinner.check bypassed");
                        return;
                    };
                }
                send("[SSL-Unpin] OkHttp CertificatePinner hooked");
            } catch (e) {
                send("[-] OkHttp CertificatePinner not present: " + e);
            }

            // HostnameVerifier → always true (lab TrustAll patterns)
            try {
                var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
                HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (v) {
                    send("[SSL-Unpin] setDefaultHostnameVerifier intercepted");
                    var TrustAll = Java.registerClass({
                        name: "androsec.lab.TrustAllHV" + Math.floor(Math.random() * 100000),
                        implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                        methods: {
                            verify: {
                                returnType: "boolean",
                                argumentTypes: ["java.lang.String", "javax.net.ssl.SSLSession"],
                                implementation: function (hostname, session) {
                                    send("[SSL-Unpin] HostnameVerifier.verify(" + hostname + ") → true");
                                    return true;
                                }
                            }
                        }
                    });
                    return this.setDefaultHostnameVerifier(TrustAll.$new());
                };
            } catch (e) {
                send("[-] HostnameVerifier hook skipped: " + e);
            }

            // Custom / TrustAll X509TrustManager: empty checkServerTrusted
            try {
                var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
                var SSLContext = Java.use("javax.net.ssl.SSLContext");
                SSLContext.init.overload(
                    "[Ljavax.net.ssl.KeyManager;",
                    "[Ljavax.net.ssl.TrustManager;",
                    "java.security.SecureRandom"
                ).implementation = function (km, tm, sr) {
                    send("[SSL-Unpin] SSLContext.init — installing permissive TrustManager (lab)");
                    var TrustManager = Java.registerClass({
                        name: "androsec.lab.PermissiveTrustManager" + Math.floor(Math.random() * 100000),
                        implements: [X509TrustManager],
                        methods: {
                            checkClientTrusted: {
                                returnType: "void",
                                argumentTypes: ["[Ljava.security.cert.X509Certificate;", "java.lang.String"],
                                implementation: function (chain, authType) {}
                            },
                            checkServerTrusted: {
                                returnType: "void",
                                argumentTypes: ["[Ljava.security.cert.X509Certificate;", "java.lang.String"],
                                implementation: function (chain, authType) {
                                    send("[SSL-Unpin] checkServerTrusted bypassed");
                                }
                            },
                            getAcceptedIssuers: {
                                returnType: "[Ljava.security.cert.X509Certificate;",
                                argumentTypes: [],
                                implementation: function () {
                                    return Java.array("java.security.cert.X509Certificate", []);
                                }
                            }
                        }
                    });
                    var permissive = Java.array("javax.net.ssl.TrustManager", [TrustManager.$new()]);
                    return this.init(km, permissive, sr);
                };
                send("[SSL-Unpin] SSLContext.init hooked");
            } catch (e) {
                send("[-] SSLContext.init hook skipped: " + e);
            }

            // NetworkSecurityTrustManager / platform TrustManagerImpl (best-effort)
            try {
                var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
                if (TrustManagerImpl.checkTrustedRecursive) {
                    TrustManagerImpl.checkTrustedRecursive.implementation = function () {
                        send("[SSL-Unpin] TrustManagerImpl.checkTrustedRecursive bypassed");
                        return Java.use("java.util.ArrayList").$new();
                    };
                }
            } catch (e) {
                send("[-] TrustManagerImpl hook skipped: " + e);
            }
        }

        function installHttpUrlHooks() {
            try {
                var URL = Java.use("java.net.URL");
                URL.openConnection.overload().implementation = function () {
                    var u = this.toString();
                    if (u && (u.indexOf("http://") === 0 || u.indexOf("https://") === 0)) {
                        send("[HTTP] URL.openConnection → " + u);
                    }
                    return this.openConnection();
                };
            } catch (e) {
                send("[-] URL.openConnection hook skipped: " + e);
            }
        }
    });
}

setTimeout(startHooks, 500);
