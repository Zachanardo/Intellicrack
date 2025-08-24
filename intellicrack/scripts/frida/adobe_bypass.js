// adobe_bypass.js
send('[*] Adobe license patch injected.');

const targets = [
    'IsActivated',
    'IsLicenseValid',
    'GetLicenseStatus',
    'GetSerialNumber',
    'CheckSubscription'
];

for (let name of targets) {
    try {
        let addr = Module.findExportByName('AdobeLM.dll', name);
        if (addr) {
            Interceptor.replace(addr, new NativeCallback(function () {
                send('[✓] Spoofed: ' + name);
                return 1;
            }, 'int', []));
        }
    } catch {
        send('[-] Failed to patch: ' + name);
    }
}
