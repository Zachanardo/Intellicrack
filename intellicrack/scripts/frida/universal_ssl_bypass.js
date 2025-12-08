const detectedLibraries = [];
const activeBypasses = [];
const allCertificates = [];
const activity = [];
const MAX_LOG = 1000;

function log(message, level = 'info') {
    const entry = {
        timestamp: new Date().toISOString(),
        level: level,
        message: message,
    };
    send({ type: 'log', data: entry });
    activity.push(entry);
    if (activity.length > MAX_LOG) {
        activity.shift();
    }
}

function logError(message) {
    log(message, 'error');
}

const TLS_LIBRARY_SIGNATURES = {
    winhttp: ['winhttp.dll'],
    schannel: ['sspicli.dll', 'secur32.dll'],
    cryptoapi: ['crypt32.dll'],
    openssl: [
        'libssl.so',
        'libssl.so.1.1',
        'libssl.so.1.0.0',
        'libssl.so.3',
        'libssl.dylib',
        'libssl.1.1.dylib',
        'libssl.1.0.0.dylib',
        'libssl-1_1-x64.dll',
        'libssl-1_1.dll',
        'libssl-3-x64.dll',
        'libssl-3.dll',
        'ssleay32.dll',
        'libeay32.dll',
    ],
    boringssl: ['libboringssl.so', 'libboringssl.dylib', 'boringssl.dll'],
    nss: ['libnss3.so', 'libnss3.dylib', 'nss3.dll'],
    gnutls: ['libgnutls.so', 'libgnutls.dylib', 'gnutls.dll'],
    mbedtls: ['libmbedtls.so', 'libmbedtls.dylib', 'mbedtls.dll'],
};

function detectTLSLibraries() {
    log('Starting TLS library detection...');
    const detected = [];

    const modules = Process.enumerateModules();

    for (const [libType, signatures] of Object.entries(TLS_LIBRARY_SIGNATURES)) {
        for (const signature of signatures) {
            const module = modules.find(m => m.name.toLowerCase() === signature.toLowerCase());
            if (module) {
                const detectionInfo = {
                    type: libType,
                    name: module.name,
                    path: module.path,
                    base: module.base.toString(),
                    size: module.size,
                };
                detected.push(detectionInfo);
                detectedLibraries.push(detectionInfo);
                log(`Detected ${libType}: ${module.name} at ${module.base}`);
                send({ type: 'library_detected', data: detectionInfo });
                break;
            }
        }
    }

    if (Java.available) {
        log('Java runtime detected - Android platform');
        detected.push({ type: 'android', name: 'Java Runtime', platform: 'Android' });
        detectedLibraries.push({ type: 'android', name: 'Java Runtime', platform: 'Android' });
    }

    if (ObjC.available) {
        log('Objective-C runtime detected - iOS platform');
        detected.push({ type: 'ios', name: 'ObjC Runtime', platform: 'iOS' });
        detectedLibraries.push({ type: 'ios', name: 'ObjC Runtime', platform: 'iOS' });
    }

    if (detected.length === 0) {
        log('No TLS libraries detected - will use fallback generic bypass', 'warning');
    }

    return detected;
}

function loadBypassScript(scriptName, scriptContent) {
    try {
        log(`Loading bypass script: ${scriptName}`);
        eval(scriptContent);
        activeBypasses.push(scriptName);
        log(`Successfully loaded ${scriptName}`);
        return true;
    } catch (e) {
        logError(`Failed to load ${scriptName}: ${e.message}`);
        return false;
    }
}

function activateBypassForLibrary(libType) {
    const bypassMapping = {
        winhttp: 'winhttp_bypass.js',
        schannel: 'schannel_bypass.js',
        cryptoapi: 'cryptoapi_bypass.js',
        openssl: 'openssl_bypass.js',
        boringssl: 'openssl_bypass.js',
        android: 'android_pinning.js',
        ios: 'ios_pinning.js',
        nss: 'generic_ssl_bypass',
        gnutls: 'generic_ssl_bypass',
        mbedtls: 'generic_ssl_bypass',
    };

    const bypassScript = bypassMapping[libType];
    if (!bypassScript) {
        log(`No specific bypass for ${libType}, using generic bypass`);
        return activateGenericBypass();
    }

    if (bypassScript === 'generic_ssl_bypass') {
        return activateGenericBypass();
    }

    log(`Bypass for ${libType} should be loaded externally: ${bypassScript}`);
    send({ type: 'load_bypass_request', library: libType, script: bypassScript });

    return true;
}

function activateGenericBypass() {
    log('Activating generic SSL bypass (pattern-based)');

    const commonValidationPatterns = [
        'verify',
        'Verify',
        'VERIFY',
        'check',
        'Check',
        'CHECK',
        'validate',
        'Validate',
        'VALIDATE',
        'cert',
        'Cert',
        'CERT',
        'trust',
        'Trust',
        'TRUST',
        'ssl',
        'SSL',
        'Ssl',
        'tls',
        'TLS',
        'Tls',
    ];

    let hooksInstalled = 0;

    Process.enumerateModules().forEach(module => {
        try {
            const exports = module.enumerateExports();
            exports.forEach(exp => {
                if (exp.type === 'function') {
                    const { name } = exp;

                    const isLikelyCertFunc = commonValidationPatterns.some(
                        pattern =>
                            name.includes(pattern) &&
                            (name.includes('cert') ||
                                name.includes('Cert') ||
                                name.includes('ssl') ||
                                name.includes('SSL') ||
                                name.includes('tls') ||
                                name.includes('TLS') ||
                                name.includes('trust') ||
                                name.includes('Trust'))
                    );

                    if (isLikelyCertFunc) {
                        try {
                            Interceptor.attach(exp.address, {
                                onEnter: function (args) {
                                    this.funcName = name;
                                },
                                onLeave: function (retval) {
                                    const originalRet = retval.toInt32();

                                    if (originalRet === 0 || originalRet < 0) {
                                        log(
                                            `Generic bypass: ${this.funcName} returned ${originalRet}, forcing success`
                                        );
                                        retval.replace(ptr(1));
                                    }
                                },
                            });

                            hooksInstalled++;
                            log(`Generic hook installed: ${module.name}!${name}`);

                            if (hooksInstalled >= 50) {
                                return;
                            }
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {
            logError(`Failed to enumerate exports for ${module.name}: ${e.message}`);
        }
    });

    log(`Generic bypass activated with ${hooksInstalled} hooks`);
    activeBypasses.push('generic_ssl_bypass');
    return hooksInstalled > 0;
}

function monitorNewModules() {
    log('Starting runtime module monitoring...');

    const loadedModules = new Set(Process.enumerateModules().map(m => m.name.toLowerCase()));

    setInterval(() => {
        const currentModules = Process.enumerateModules();

        currentModules.forEach(module => {
            const moduleName = module.name.toLowerCase();

            if (!loadedModules.has(moduleName)) {
                loadedModules.add(moduleName);
                log(`New module loaded: ${module.name}`);

                for (const [libType, signatures] of Object.entries(TLS_LIBRARY_SIGNATURES)) {
                    if (signatures.some(sig => sig.toLowerCase() === moduleName)) {
                        log(`Newly loaded module is TLS library: ${libType}`);
                        const detectionInfo = {
                            type: libType,
                            name: module.name,
                            path: module.path,
                            base: module.base.toString(),
                            size: module.size,
                            loadedAtRuntime: true,
                        };
                        detectedLibraries.push(detectionInfo);
                        send({ type: 'runtime_library_detected', data: detectionInfo });

                        activateBypassForLibrary(libType);
                        break;
                    }
                }
            }
        });
    }, 2000);
}

function performSelfTest() {
    log('Performing self-test of bypass functionality');

    const testResults = {
        timestamp: new Date().toISOString(),
        detectedLibraries: detectedLibraries.length,
        activeBypasses: activeBypasses.length,
        hooksActive: true,
        testPassed: false,
    };

    if (detectedLibraries.length > 0 && activeBypasses.length > 0) {
        testResults.testPassed = true;
        testResults.status = 'All systems operational';
    } else if (detectedLibraries.length > 0 && activeBypasses.length === 0) {
        testResults.status =
            'Libraries detected but bypasses not loaded - may need external script injection';
    } else {
        testResults.status = 'No TLS libraries detected - target may not use SSL/TLS';
    }

    log(`Self-test result: ${testResults.status}`);
    send({ type: 'self_test_result', data: testResults });

    return testResults;
}

function initialize() {
    log('Universal SSL Bypass initializing...');

    const detected = detectTLSLibraries();

    if (detected.length === 0) {
        log('No specific TLS libraries found - activating generic bypass');
        activateGenericBypass();
    } else {
        detected.forEach(lib => {
            activateBypassForLibrary(lib.type);
        });
    }

    monitorNewModules();

    setTimeout(() => {
        performSelfTest();
    }, 1000);

    log('Universal SSL Bypass initialization complete');
    send({ type: 'bypass_ready', detectedLibraries: detected });
}

rpc.exports = {
    getDetectedLibraries: () => detectedLibraries,
    getActiveBypass: () => activeBypasses,
    getAllCertificates: () => allCertificates,
    getBypassStatus: () => ({
        active: true,
        detectedLibraryCount: detectedLibraries.length,
        activeBypassCount: activeBypasses.length,
        detectedLibraries: detectedLibraries.map(lib => lib.type),
        activeBypasses: activeBypasses,
        platform: Java.available ? 'Android' : ObjC.available ? 'iOS' : 'Desktop',
    }),
    testBypass: () => performSelfTest(),
    forceGenericBypass: () => {
        log('Forcing generic bypass activation (manual override)');
        return activateGenericBypass();
    },
    rescan: () => {
        log('Rescanning for TLS libraries (manual trigger)');
        const detected = detectTLSLibraries();
        return {
            success: true,
            newlyDetected: detected.length,
            libraries: detected,
        };
    },
    getActivity: () => activity,
    clearLogs: () => {
        activity.length = 0;
        allCertificates.length = 0;
        log('Activity logs cleared');
        return true;
    },
};

initialize();

log('Universal SSL Bypass script loaded successfully');
send({ type: 'universal_bypass_loaded' });
