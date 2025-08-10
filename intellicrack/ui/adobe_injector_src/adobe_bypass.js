// adobe_bypass.js
console.log('[*] Adobe license patch injected.');

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
                console.log('[✓] Spoofed: ' + name);
                return 1;
            }, 'int', []));
        }
    } catch (e) {
        console.log('[-] Failed to patch: ' + name);
    }
}
