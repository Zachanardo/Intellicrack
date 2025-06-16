
// Sample Frida script: Registry Monitor
// This script hooks Windows Registry functions and logs access to licensing-related keys
Java.perform(function() {
    var registryKeys = [
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "HKEY_CURRENT_USER\\Software"
    ];

    // Hook RegOpenKeyExW
    var RegOpenKeyExW = Module.findExportByName("advapi32.dll", "RegOpenKeyExW");
    if (RegOpenKeyExW) {
        Interceptor.attach(RegOpenKeyExW, {
            onEnter: function(args) {
                var keyPath = args[1].readUtf16String();
                if (keyPath && registryKeys.some(key => keyPath.includes(key))) {
                    console.log("[Registry] Opening key: " + keyPath);
                }
            }
        });
    }

    // Hook RegQueryValueExW
    var RegQueryValueExW = Module.findExportByName("advapi32.dll", "RegQueryValueExW");
    if (RegQueryValueExW) {
        Interceptor.attach(RegQueryValueExW, {
            onEnter: function(args) {
                this.valueName = args[1].readUtf16String();
            },
            onLeave: function(retval) {
                if (this.valueName && this.valueName.toLowerCase().includes("licens")) {
                    console.log("[Registry] Querying value: " + this.valueName);
                }
            }
        });
    }
});
