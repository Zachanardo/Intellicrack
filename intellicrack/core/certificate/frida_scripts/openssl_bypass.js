const SSL_VERIFY_NONE = 0x00;
const SSL_VERIFY_PEER = 0x01;
const X509_V_OK = 0;
const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18;
const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19;
const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20;
const X509_V_ERR_CERT_UNTRUSTED = 27;
const X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21;

const connections = [];
const certificates = [];
const activity = [];
const MAX_LOG = 1000;

let openssl_module = null;
let is_boringssl = false;

function log(message, level = 'info') {
    const entry = {
        timestamp: new Date().toISOString(),
        level: level,
        message: message
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

function findOpenSSLModule() {
    const possible_names = [
        'libssl.so', 'libssl.so.1.1', 'libssl.so.1.0.0', 'libssl.so.3',
        'libssl.dylib', 'libssl.1.1.dylib', 'libssl.1.0.0.dylib',
        'libssl-1_1-x64.dll', 'libssl-1_1.dll', 'libssl-3-x64.dll', 'libssl-3.dll',
        'ssleay32.dll', 'libeay32.dll',
        'libboringssl.so', 'libboringssl.dylib', 'boringssl.dll'
    ];

    for (let name of possible_names) {
        try {
            const module = Process.findModuleByName(name);
            if (module) {
                log(`Found OpenSSL module: ${name} at ${module.base}`);

                if (name.includes('boring')) {
                    is_boringssl = true;
                    log('Detected BoringSSL variant');
                }

                return module;
            }
        } catch (e) {
        }
    }

    return null;
}

openssl_module = findOpenSSLModule();

if (!openssl_module) {
    logError('OpenSSL module not found');
} else {
    try {
        const SSL_CTX_set_verify = Module.findExportByName(openssl_module.name, 'SSL_CTX_set_verify');
        if (SSL_CTX_set_verify) {
            Interceptor.attach(SSL_CTX_set_verify, {
                onEnter: function(args) {
                    const ctx = args[0];
                    const mode = args[1].toInt32();
                    const callback = args[2];

                    log(`SSL_CTX_set_verify: Original mode=0x${mode.toString(16)}, callback=${callback}`);

                    args[1] = ptr(SSL_VERIFY_NONE);
                    args[2] = ptr(0);

                    this.originalMode = mode;
                    this.ctx = ctx;
                },
                onLeave: function(retval) {
                    log(`SSL_CTX_set_verify: Forced mode to SSL_VERIFY_NONE for context ${this.ctx}`);
                }
            });
            log('Successfully hooked SSL_CTX_set_verify');
        }
    } catch (e) {
        logError('Failed to hook SSL_CTX_set_verify: ' + e.message);
    }

    try {
        const SSL_set_verify = Module.findExportByName(openssl_module.name, 'SSL_set_verify');
        if (SSL_set_verify) {
            Interceptor.attach(SSL_set_verify, {
                onEnter: function(args) {
                    const ssl = args[0];
                    const mode = args[1].toInt32();
                    const callback = args[2];

                    log(`SSL_set_verify: Original mode=0x${mode.toString(16)} for SSL object ${ssl}`);

                    args[1] = ptr(SSL_VERIFY_NONE);
                    args[2] = ptr(0);

                    this.ssl = ssl;
                },
                onLeave: function(retval) {
                    log(`SSL_set_verify: Forced mode to SSL_VERIFY_NONE for SSL ${this.ssl}`);
                }
            });
            log('Successfully hooked SSL_set_verify');
        }
    } catch (e) {
        logError('Failed to hook SSL_set_verify: ' + e.message);
    }

    try {
        const SSL_get_verify_result = Module.findExportByName(openssl_module.name, 'SSL_get_verify_result');
        if (SSL_get_verify_result) {
            Interceptor.attach(SSL_get_verify_result, {
                onEnter: function(args) {
                    const ssl = args[0];
                    this.ssl = ssl;
                },
                onLeave: function(retval) {
                    const originalResult = retval.toInt32();

                    if (originalResult !== X509_V_OK) {
                        log(`SSL_get_verify_result: Original error=${originalResult}, forcing X509_V_OK`);

                        const certInfo = {
                            timestamp: new Date().toISOString(),
                            ssl: this.ssl.toString(),
                            originalError: originalResult,
                            bypassed: true
                        };
                        certificates.push(certInfo);
                        if (certificates.length > MAX_LOG) {
                            certificates.shift();
                        }
                        send({ type: 'certificate_bypass', data: certInfo });

                        retval.replace(ptr(X509_V_OK));
                    }
                }
            });
            log('Successfully hooked SSL_get_verify_result');
        }
    } catch (e) {
        logError('Failed to hook SSL_get_verify_result: ' + e.message);
    }

    try {
        const SSL_CTX_set_cert_verify_callback = Module.findExportByName(openssl_module.name, 'SSL_CTX_set_cert_verify_callback');
        if (SSL_CTX_set_cert_verify_callback) {
            const always_succeed_callback = new NativeCallback(function(x509_ctx, arg) {
                log('Custom verify callback invoked - returning success (1)');
                return 1;
            }, 'int', ['pointer', 'pointer']);

            Interceptor.attach(SSL_CTX_set_cert_verify_callback, {
                onEnter: function(args) {
                    const ctx = args[0];
                    const callback = args[1];
                    const arg = args[2];

                    log(`SSL_CTX_set_cert_verify_callback: Replacing callback ${callback} with always-succeed callback`);

                    args[1] = always_succeed_callback;

                    this.ctx = ctx;
                    this.originalCallback = callback;
                },
                onLeave: function(retval) {
                    log(`SSL_CTX_set_cert_verify_callback: Callback replaced for context ${this.ctx}`);
                }
            });
            log('Successfully hooked SSL_CTX_set_cert_verify_callback');
        }
    } catch (e) {
        logError('Failed to hook SSL_CTX_set_cert_verify_callback: ' + e.message);
    }

    try {
        const SSL_CTX_load_verify_locations = Module.findExportByName(openssl_module.name, 'SSL_CTX_load_verify_locations');
        if (SSL_CTX_load_verify_locations) {
            Interceptor.attach(SSL_CTX_load_verify_locations, {
                onEnter: function(args) {
                    const ctx = args[0];
                    const CAfile = args[1];
                    const CApath = args[2];

                    let cafile_str = 'NULL';
                    let capath_str = 'NULL';

                    if (!CAfile.isNull()) {
                        try {
                            cafile_str = CAfile.readCString();
                        } catch (e) {}
                    }

                    if (!CApath.isNull()) {
                        try {
                            capath_str = CApath.readCString();
                        } catch (e) {}
                    }

                    log(`SSL_CTX_load_verify_locations: CAfile="${cafile_str}", CApath="${capath_str}"`);
                },
                onLeave: function(retval) {
                    const result = retval.toInt32();
                    if (result === 0) {
                        log('SSL_CTX_load_verify_locations: Failed originally, forcing success');
                        retval.replace(ptr(1));
                    }
                }
            });
            log('Successfully hooked SSL_CTX_load_verify_locations');
        }
    } catch (e) {
        logError('Failed to hook SSL_CTX_load_verify_locations: ' + e.message);
    }

    try {
        const X509_verify_cert = Module.findExportByName(openssl_module.name, 'X509_verify_cert');
        if (X509_verify_cert) {
            Interceptor.attach(X509_verify_cert, {
                onEnter: function(args) {
                    const ctx = args[0];
                    this.ctx = ctx;
                },
                onLeave: function(retval) {
                    const result = retval.toInt32();
                    if (result !== 1) {
                        log(`X509_verify_cert: Failed with result=${result}, forcing success (1)`);
                        retval.replace(ptr(1));

                        try {
                            const X509_STORE_CTX_set_error = Module.findExportByName(openssl_module.name, 'X509_STORE_CTX_set_error');
                            if (X509_STORE_CTX_set_error) {
                                const set_error = new NativeFunction(X509_STORE_CTX_set_error, 'void', ['pointer', 'int']);
                                set_error(this.ctx, X509_V_OK);
                                log('X509_verify_cert: Set error to X509_V_OK in context');
                            }
                        } catch (e) {
                            logError('Failed to set X509 error: ' + e.message);
                        }
                    }
                }
            });
            log('Successfully hooked X509_verify_cert');
        }
    } catch (e) {
        logError('Failed to hook X509_verify_cert: ' + e.message);
    }

    try {
        const X509_STORE_CTX_get_error = Module.findExportByName(openssl_module.name, 'X509_STORE_CTX_get_error');
        if (X509_STORE_CTX_get_error) {
            Interceptor.attach(X509_STORE_CTX_get_error, {
                onEnter: function(args) {
                    this.ctx = args[0];
                },
                onLeave: function(retval) {
                    const error = retval.toInt32();
                    if (error !== X509_V_OK) {
                        log(`X509_STORE_CTX_get_error: Original error=${error}, returning X509_V_OK`);
                        retval.replace(ptr(X509_V_OK));
                    }
                }
            });
            log('Successfully hooked X509_STORE_CTX_get_error');
        }
    } catch (e) {
        logError('Failed to hook X509_STORE_CTX_get_error: ' + e.message);
    }

    try {
        const SSL_CTX_set_verify_depth = Module.findExportByName(openssl_module.name, 'SSL_CTX_set_verify_depth');
        if (SSL_CTX_set_verify_depth) {
            Interceptor.attach(SSL_CTX_set_verify_depth, {
                onEnter: function(args) {
                    const ctx = args[0];
                    const depth = args[1].toInt32();

                    log(`SSL_CTX_set_verify_depth: Original depth=${depth}, setting to 100`);
                    args[1] = ptr(100);
                }
            });
            log('Successfully hooked SSL_CTX_set_verify_depth');
        }
    } catch (e) {
        logError('Failed to hook SSL_CTX_set_verify_depth: ' + e.message);
    }

    try {
        const SSL_set_verify_depth = Module.findExportByName(openssl_module.name, 'SSL_set_verify_depth');
        if (SSL_set_verify_depth) {
            Interceptor.attach(SSL_set_verify_depth, {
                onEnter: function(args) {
                    const ssl = args[0];
                    const depth = args[1].toInt32();

                    log(`SSL_set_verify_depth: Original depth=${depth}, setting to 100`);
                    args[1] = ptr(100);
                }
            });
            log('Successfully hooked SSL_set_verify_depth');
        }
    } catch (e) {
        logError('Failed to hook SSL_set_verify_depth: ' + e.message);
    }

    if (is_boringssl) {
        try {
            const SSL_set_custom_verify = Module.findExportByName(openssl_module.name, 'SSL_set_custom_verify');
            if (SSL_set_custom_verify) {
                const boringssl_always_succeed = new NativeCallback(function(ssl, out_alert) {
                    log('BoringSSL custom verify callback invoked - returning ssl_verify_ok (1)');
                    return 1;
                }, 'int', ['pointer', 'pointer']);

                Interceptor.attach(SSL_set_custom_verify, {
                    onEnter: function(args) {
                        const ssl = args[0];
                        const mode = args[1].toInt32();
                        const callback = args[2];

                        log(`SSL_set_custom_verify (BoringSSL): mode=${mode}, replacing callback`);

                        args[1] = ptr(SSL_VERIFY_NONE);
                        args[2] = boringssl_always_succeed;
                    }
                });
                log('Successfully hooked SSL_set_custom_verify (BoringSSL)');
            }
        } catch (e) {
            logError('Failed to hook SSL_set_custom_verify: ' + e.message);
        }

        try {
            const SSL_CTX_set_custom_verify = Module.findExportByName(openssl_module.name, 'SSL_CTX_set_custom_verify');
            if (SSL_CTX_set_custom_verify) {
                const boringssl_ctx_always_succeed = new NativeCallback(function(ssl, out_alert) {
                    log('BoringSSL CTX custom verify callback invoked - returning ssl_verify_ok (1)');
                    return 1;
                }, 'int', ['pointer', 'pointer']);

                Interceptor.attach(SSL_CTX_set_custom_verify, {
                    onEnter: function(args) {
                        const ctx = args[0];
                        const mode = args[1].toInt32();
                        const callback = args[2];

                        log(`SSL_CTX_set_custom_verify (BoringSSL): mode=${mode}, replacing callback`);

                        args[1] = ptr(SSL_VERIFY_NONE);
                        args[2] = boringssl_ctx_always_succeed;
                    }
                });
                log('Successfully hooked SSL_CTX_set_custom_verify (BoringSSL)');
            }
        } catch (e) {
            logError('Failed to hook SSL_CTX_set_custom_verify: ' + e.message);
        }
    }

    try {
        const SSL_connect = Module.findExportByName(openssl_module.name, 'SSL_connect');
        if (SSL_connect) {
            Interceptor.attach(SSL_connect, {
                onEnter: function(args) {
                    const ssl = args[0];
                    this.ssl = ssl;
                    this.startTime = Date.now();
                },
                onLeave: function(retval) {
                    const result = retval.toInt32();
                    const duration = Date.now() - this.startTime;

                    const connInfo = {
                        timestamp: new Date().toISOString(),
                        ssl: this.ssl.toString(),
                        result: result,
                        duration: duration,
                        success: result === 1
                    };

                    connections.push(connInfo);
                    if (connections.length > MAX_LOG) {
                        connections.shift();
                    }

                    log(`SSL_connect: Result=${result}, Duration=${duration}ms`);
                    send({ type: 'ssl_connection', data: connInfo });
                }
            });
            log('Successfully hooked SSL_connect');
        }
    } catch (e) {
        logError('Failed to hook SSL_connect: ' + e.message);
    }
}

rpc.exports = {
    getOpenSSLConnections: function() {
        return connections;
    },
    getCertificateChains: function() {
        return certificates;
    },
    getActivity: function() {
        return activity;
    },
    clearLogs: function() {
        activity.length = 0;
        connections.length = 0;
        certificates.length = 0;
        log('All logs cleared');
        return true;
    },
    getBypassStatus: function() {
        return {
            active: true,
            library: openssl_module ? openssl_module.name : 'Unknown',
            variant: is_boringssl ? 'BoringSSL' : 'OpenSSL',
            moduleBase: openssl_module ? openssl_module.base.toString() : 'N/A',
            connectionCount: connections.length,
            certificateBypassCount: certificates.length
        };
    },
    testBypass: function() {
        log('Testing OpenSSL bypass functionality');
        return {
            success: openssl_module !== null,
            message: openssl_module ?
                `OpenSSL/BoringSSL bypass is active (${is_boringssl ? 'BoringSSL' : 'OpenSSL'})` :
                'OpenSSL module not found',
            stats: {
                connections: connections.length,
                certificateBypasses: certificates.length
            }
        };
    }
};

if (openssl_module) {
    log('OpenSSL certificate bypass script loaded successfully');
    send({ type: 'bypass_success', library: is_boringssl ? 'BoringSSL' : 'OpenSSL' });
} else {
    send({ type: 'bypass_failure', library: 'OpenSSL', reason: 'Module not found' });
}
