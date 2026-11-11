function startHooks() {
    if (typeof Java === 'undefined') {
        setTimeout(startHooks, 500);
        return;
    }
    
    Java.perform(function() {
        send("[*] Frida Script Injected Successfully!");

        try {
            var SharedPreferencesEditor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
            SharedPreferencesEditor.putString.implementation = function(key, value) {
                send("[SharedPreferences] Saved -> Key: " + key + " | Value: " + value);
                return this.putString(key, value);
            };
        } catch (e) { send("[-] Failed SharedPreferences: " + e); }

        try {
            var Cipher = Java.use('javax.crypto.Cipher');
            Cipher.doFinal.overload('[B').implementation = function(data) {
                var algorithm = this.getAlgorithm();
                send("[Crypto] Cipher Algorithm: " + algorithm);
                var result = this.doFinal(data);
                send("[Crypto] Output Hex: " + bytesToHex(result));
                return result;
            };
        } catch (e) { send("[-] Failed Cipher: " + e); }
        
        function bytesToHex(bytes) {
            var hex = [];
            for (var i = 0; i < bytes.length; i++) {
                hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
            }
            return hex.join('');
        }
    });
}

setTimeout(startHooks, 500);
