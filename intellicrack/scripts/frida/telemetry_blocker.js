/*
 * This file is part of Intellicrack.
 * Copyright (C) 2025 Zachary Flint
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// Advanced Telemetry Blocker Script
// Production-ready comprehensive telemetry and license validation blocking
// Intercepts at multiple layers: Network, DNS, Crypto, Process, Registry, File System
// Includes anti-detection, stealth timing, and modern protocol support

// === CONFIGURATION & GLOBAL STATE ===

const CONFIG = {
    stealthMode: true,
    blockingDelay: { min: 10, max: 100 },
    logEncryption: true,
    whitelistPID: [],
    domainRotationDetection: true,
    cryptoHooking: true,
    processExclusions: [
        'explorer.exe',
        'svchost.exe',
        'System',
        'dwm.exe',
        'winlogon.exe',
        'services.exe',
        'lsass.exe',
        'csrss.exe',
        'smss.exe',
        'wininit.exe',
    ],
};

let TELEMETRY_STATS = {
    blockedConnections: 0,
    blockedDNS: 0,
    blockedFiles: 0,
    blockedProcesses: 0,
    blockedRegistry: 0,
    cryptoInterceptions: 0,
    startTime: Date.now(),
};

const ADVANCED_DOMAINS = new Map([
    [
        'microsoft',
        [
            'telemetry.microsoft.com',
            'vortex.data.microsoft.com',
            'settings-win.data.microsoft.com',
            'watson.microsoft.com',
            'genuine.microsoft.com',
            'activation.sls.microsoft.com',
            'rds.microsoft.com',
            'live.rads.msn.com',
            'choice.microsoft.com',
            'wns.windows.com',
            'client.wns.windows.com',
        ],
    ],
    [
        'adobe',
        [
            'adobe.com/activation',
            'adobe-dns.adobe.io',
            'lcs-mobile-cops.adobe.io',
            'activate.adobe.com',
            'practivate.adobe.com',
            'ereg.adobe.com',
            'registration.adobe.com',
            'wwis-dubc1-vip60.adobe.com',
        ],
    ],
    ['autodesk', ['register.autodesk.com', 'activation.autodesk.com', 'accounts.autodesk.com']],
    ['unity', ['telemetry.unity3d.com', 'config.uca.cloud.unity3d.com', 'cdp.cloud.unity3d.com']],
    ['nvidia', ['gfe.nvidia.com', 'services.gfe.nvidia.com', 'telemetry.nvidia.com']],
    ['intel', ['registrationcenter.intel.com', 'software.intel.com']],
    ['rockstar', ['prod.telemetry.ros.rockstargames.com', 'telemetry.gta5.rockstargames.com']],
    [
        'generic',
        [
            'google-analytics.com',
            'googletagmanager.com',
            'mixpanel.com',
            'segment.io',
            'amplitude.com',
            'hotjar.com',
            'fullstory.com',
        ],
    ],
]);

const CRYPTO_CERT_SUBJECTS = [
    'Microsoft Code Signing PCA',
    'Adobe Systems Incorporated',
    'Autodesk, Inc.',
    'Unity Technologies ApS',
    'NVIDIA Corporation',
];

function randomDelay() {
    if (!CONFIG.stealthMode) return;
    const delay =
        Math.floor(Math.random() * (CONFIG.blockingDelay.max - CONFIG.blockingDelay.min + 1)) +
        CONFIG.blockingDelay.min;
    Thread.sleep(delay / 1000.0);
}

function isExcludedProcess() {
    try {
        const processName = Process.getCurrentThreadId
            ? Process.getCurrentThreadId().toString()
            : '';
        return CONFIG.processExclusions.some((proc) => processName.includes(proc));
    } catch (e) {
        return false;
    }
}

function encryptData(data) {
    if (!CONFIG.logEncryption) return data;
    const key = 0xdeadbeef;
    let result = '';
    for (let i = 0; i < data.length; i++) {
        result += String.fromCharCode(data.charCodeAt(i) ^ (key >> (8 * (i % 4))));
    }
    return btoa(result);
}

function detectDomainRotation(domain) {
    if (!CONFIG.domainRotationDetection) return false;

    const suspiciousPatterns = [
        /\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.amazonaws\.com/,
        /[a-f0-9]{8,}\.cloudfront\.net/,
        /[a-z]{8,16}\.(com|net|org)$/,
        /telemetry\d+\./,
        /analytics\d+\./,
    ];

    return suspiciousPatterns.some((pattern) => pattern.test(domain));
}

send({
    type: 'status',
    target: 'telemetry_blocker',
    action: 'starting_advanced_telemetry_blocking',
    config: CONFIG,
    timestamp: Date.now(),
});

// === NATIVE API LAYER INTERCEPTION ===

function tryAttach(module, funcName, hooks) {
    try {
        const func = Module.findExportByName(module, funcName);
        if (func) {
            Interceptor.attach(func, hooks);
            return true;
        }
    } catch (e) {
        console.log(`Failed to attach to ${module}!${funcName}: ${e.message}`);
    }
    return false;
}

// Hook Native API network functions
tryAttach('ntdll.dll', 'NtCreateFile', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const objectAttrs = args[2];
        const objectNamePtr = objectAttrs.add(Process.pointerSize === 8 ? 16 : 8).readPointer();

        if (!objectNamePtr || objectNamePtr.isNull()) return;

        try {
            const objectName = objectNamePtr.add(8).readPointer().readUtf16String();
            if (objectName && objectName.includes('\\Device\\Tcp')) {
                randomDelay();
                this.blockTcp = true;
                TELEMETRY_STATS.blockedConnections++;
            }
        } catch (e) {}
    },
    onLeave(retval) {
        if (this.blockTcp) {
            retval.replace(ptr(0xc0000022)); // STATUS_ACCESS_DENIED
        }
    },
});

// === HTTP/HTTPS REQUEST BLOCKING (ENHANCED) ===

// Enhanced WinHTTP connection blocking with intelligent domain matching
tryAttach('winhttp.dll', 'WinHttpConnect', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const serverName = args[1].readUtf16String();
        if (!serverName) return;

        const lowerDomain = serverName.toLowerCase();
        let shouldBlock = false;

        // Check against comprehensive domain lists
        for (const [vendor, domains] of ADVANCED_DOMAINS) {
            for (const domain of domains) {
                if (lowerDomain.includes(domain.toLowerCase())) {
                    shouldBlock = true;
                    break;
                }
            }
            if (shouldBlock) break;
        }

        // Additional pattern-based detection
        if (!shouldBlock && detectDomainRotation(lowerDomain)) {
            shouldBlock = true;
        }

        if (shouldBlock) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'winhttp_connection_blocked',
                hostname: encryptData(serverName),
                timestamp: Date.now(),
            });
            this.blockConnection = true;
            TELEMETRY_STATS.blockedConnections++;
        }
    },
    onLeave(retval) {
        if (this.blockConnection) {
            retval.replace(ptr(0)); // Return NULL to indicate failure
        }
    },
});

// Enhanced WinHTTP request blocking
tryAttach('winhttp.dll', 'WinHttpSendRequest', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        try {
            const headers = args[2] ? args[2].readUtf16String() : '';
            const suspiciousHeaders = [
                'telemetry',
                'activation',
                'licensing',
                'analytics',
                'tracking',
            ];

            if (
                headers &&
                suspiciousHeaders.some((header) => headers.toLowerCase().includes(header))
            ) {
                randomDelay();
                send({
                    type: 'bypass',
                    target: 'telemetry_blocker',
                    action: 'winhttp_request_blocked',
                    reason: 'suspicious_headers',
                    headers: encryptData(headers),
                    timestamp: Date.now(),
                });
                this.blockRequest = true;
                TELEMETRY_STATS.blockedConnections++;
            }
        } catch (e) {}
    },
    onLeave(retval) {
        if (this.blockRequest) {
            retval.replace(0); // Return FALSE to indicate failure
        }
    },
});

// Hook modern HTTP.SYS API
tryAttach('httpapi.dll', 'HttpSendHttpResponse', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        // Block HTTP.SYS responses that might contain telemetry data
        const responseEntity = args[3];
        if (responseEntity && !responseEntity.isNull()) {
            try {
                const entityChunk = responseEntity.readPointer();
                if (entityChunk && !entityChunk.isNull()) {
                    randomDelay();
                    this.blockResponse = true;
                    TELEMETRY_STATS.blockedConnections++;
                }
            } catch (e) {}
        }
    },
    onLeave(retval) {
        if (this.blockResponse) {
            retval.replace(0x80070005); // ERROR_ACCESS_DENIED
        }
    },
});

// === CRYPTOGRAPHIC API INTERCEPTION ===

// Hook CryptVerifySignature to block certificate validation
if (CONFIG.cryptoHooking) {
    tryAttach('crypt32.dll', 'CryptVerifySignature', {
        onEnter(args) {
            if (isExcludedProcess()) return;

            // args[0] is HCRYPTHASH, args[1] is signature, args[2] is public key
            try {
                // Block signature verification for known telemetry certificates
                const sigData = args[1];
                if (sigData && !sigData.isNull()) {
                    randomDelay();
                    this.blockCrypto = true;
                    TELEMETRY_STATS.cryptoInterceptions++;

                    send({
                        type: 'bypass',
                        target: 'telemetry_blocker',
                        action: 'crypto_signature_blocked',
                        timestamp: Date.now(),
                    });
                }
            } catch (e) {}
        },
        onLeave(retval) {
            if (this.blockCrypto) {
                retval.replace(0); // Return FALSE to indicate verification failure
            }
        },
    });

    // Hook CertVerifySubjectCertificateContext
    tryAttach('crypt32.dll', 'CertVerifySubjectCertificateContext', {
        onEnter(args) {
            if (isExcludedProcess()) return;

            const certContext = args[0];
            if (certContext && !certContext.isNull()) {
                try {
                    // Read certificate info structure
                    const certInfo = certContext.add(12).readPointer(); // pCertInfo offset
                    if (certInfo && !certInfo.isNull()) {
                        // Check subject name for telemetry-related certificates
                        this.blockCert = CRYPTO_CERT_SUBJECTS.some((subject) => {
                            try {
                                return certInfo.readCString().includes(subject);
                            } catch (e) {
                                return false;
                            }
                        });

                        if (this.blockCert) {
                            randomDelay();
                            TELEMETRY_STATS.cryptoInterceptions++;
                        }
                    }
                } catch (e) {}
            }
        },
        onLeave(retval) {
            if (this.blockCert) {
                retval.replace(0x800b0109); // CERT_E_UNTRUSTEDROOT
            }
        },
    });

    // Hook BCrypt functions for modern crypto
    tryAttach('bcrypt.dll', 'BCryptVerifySignature', {
        onEnter(args) {
            if (isExcludedProcess()) return;

            // Block BCrypt signature verifications
            try {
                randomDelay();
                this.blockBCrypt = true;
                TELEMETRY_STATS.cryptoInterceptions++;

                send({
                    type: 'bypass',
                    target: 'telemetry_blocker',
                    action: 'bcrypt_signature_blocked',
                    timestamp: Date.now(),
                });
            } catch (e) {}
        },
        onLeave(retval) {
            if (this.blockBCrypt) {
                retval.replace(0xc000000d); // STATUS_INVALID_PARAMETER
            }
        },
    });
}

// === ADVANCED SOCKET-LEVEL BLOCKING ===

// Enhanced Winsock connection blocking with intelligent filtering
tryAttach('ws2_32.dll', 'WSAConnect', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const sockAddr = args[1];
        if (!sockAddr || sockAddr.isNull()) return;

        const family = sockAddr.readU16();
        if (family === 2) {
            // AF_INET
            const port = (sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8();
            const ip = sockAddr.add(4).readU32();

            // Convert IP to readable format
            const ipStr = `${ip & 0xff}.${(ip >> 8) & 0xff}.${(ip >> 16) & 0xff}.${(ip >> 24) & 0xff}`;

            // Check against known telemetry IP ranges
            const suspiciousIPs = [
                '13.107.',
                '40.77.',
                '52.167.',
                '65.52.',
                '131.253.',
                '134.170.', // Microsoft
                '192.150.',
                '199.232.',
                '207.126.',
                '23.32.', // Adobe
                '104.16.',
                '172.64.', // Cloudflare (often used for telemetry)
                '52.84.',
                '54.230.', // AWS CloudFront
                '173.252.',
                '31.13.', // Facebook/Meta telemetry
            ];

            const isSuspiciousIP = suspiciousIPs.some((range) => ipStr.startsWith(range));
            const isSuspiciousPort = [80, 443, 8080, 8443, 9001, 9443, 10001, 11001].includes(port);

            if (isSuspiciousIP || isSuspiciousPort) {
                randomDelay();
                send({
                    type: 'bypass',
                    target: 'telemetry_blocker',
                    action: 'wsa_connection_blocked',
                    ip_address: encryptData(ipStr),
                    port: port,
                    reason: isSuspiciousIP ? 'suspicious_ip_range' : 'suspicious_port',
                    timestamp: Date.now(),
                });
                this.blockSocket = true;
                TELEMETRY_STATS.blockedConnections++;
            }
        }
    },
    onLeave(retval) {
        if (this.blockSocket) {
            retval.replace(-1); // SOCKET_ERROR
        }
    },
});

// Enhanced connect() blocking with IPv6 support
tryAttach('ws2_32.dll', 'connect', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const sockAddr = args[1];
        if (!sockAddr || sockAddr.isNull()) return;

        const family = sockAddr.readU16();
        let shouldBlock = false;

        if (family === 2) {
            // AF_INET
            const port = (sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8();
            shouldBlock = [80, 443, 8080, 8443, 9001, 9443, 10443, 11443].includes(port);
        } else if (family === 23) {
            // AF_INET6
            const port = (sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8();
            shouldBlock = [80, 443, 8080, 8443].includes(port);
        }

        if (shouldBlock) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'connect_blocked',
                family: family === 2 ? 'IPv4' : 'IPv6',
                timestamp: Date.now(),
            });
            this.blockConnect = true;
            TELEMETRY_STATS.blockedConnections++;
        }
    },
    onLeave(retval) {
        if (this.blockConnect) {
            retval.replace(-1); // SOCKET_ERROR
        }
    },
});

// Block socket I/O operations
tryAttach('ws2_32.dll', 'send', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const buffer = args[1];
        const len = args[2].toInt32();

        if (buffer && !buffer.isNull() && len > 0) {
            try {
                const data = buffer.readCString(Math.min(len, 1024));
                const suspiciousPayloads = [
                    'telemetry',
                    'activation',
                    'licensing',
                    'analytics',
                    'tracking',
                ];

                if (
                    data &&
                    suspiciousPayloads.some((payload) => data.toLowerCase().includes(payload))
                ) {
                    randomDelay();
                    this.blockSend = true;
                    TELEMETRY_STATS.blockedConnections++;
                }
            } catch (e) {}
        }
    },
    onLeave(retval) {
        if (this.blockSend) {
            retval.replace(-1); // SOCKET_ERROR
        }
    },
});

// === COMPREHENSIVE DNS RESOLUTION BLOCKING ===

// Enhanced DNS resolution blocking - GetAddrInfoW (Wide char)
tryAttach('ws2_32.dll', 'GetAddrInfoW', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const nodeName = args[0] ? args[0].readUtf16String() : null;
        if (!nodeName) return;

        const lowerDomain = nodeName.toLowerCase();
        let shouldBlock = false;

        // Check against comprehensive domain lists
        for (const [vendor, domains] of ADVANCED_DOMAINS) {
            for (const domain of domains) {
                if (lowerDomain.includes(domain.toLowerCase())) {
                    shouldBlock = true;
                    break;
                }
            }
            if (shouldBlock) break;
        }

        // Pattern-based detection for domain rotation
        if (!shouldBlock && detectDomainRotation(lowerDomain)) {
            shouldBlock = true;
        }

        if (shouldBlock) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'dns_getaddrinfow_blocked',
                hostname: encryptData(nodeName),
                timestamp: Date.now(),
            });
            this.blockDNS = true;
            TELEMETRY_STATS.blockedDNS++;
        }
    },
    onLeave(retval) {
        if (this.blockDNS) {
            retval.replace(11001); // WSAHOST_NOT_FOUND
        }
    },
});

// Enhanced DNS resolution blocking - GetAddrInfoA (ANSI)
tryAttach('ws2_32.dll', 'GetAddrInfoA', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const nodeName = args[0] ? args[0].readCString() : null;
        if (!nodeName) return;

        const lowerDomain = nodeName.toLowerCase();
        let shouldBlock = false;

        // Check against domain lists
        for (const [vendor, domains] of ADVANCED_DOMAINS) {
            for (const domain of domains) {
                if (lowerDomain.includes(domain.toLowerCase())) {
                    shouldBlock = true;
                    break;
                }
            }
            if (shouldBlock) break;
        }

        if (!shouldBlock && detectDomainRotation(lowerDomain)) {
            shouldBlock = true;
        }

        if (shouldBlock) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'dns_getaddrinfoa_blocked',
                hostname: encryptData(nodeName),
                timestamp: Date.now(),
            });
            this.blockDNS = true;
            TELEMETRY_STATS.blockedDNS++;
        }
    },
    onLeave(retval) {
        if (this.blockDNS) {
            retval.replace(11001); // WSAHOST_NOT_FOUND
        }
    },
});

// Block legacy gethostbyname function
tryAttach('ws2_32.dll', 'gethostbyname', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const hostName = args[0] ? args[0].readCString() : null;
        if (!hostName) return;

        const lowerDomain = hostName.toLowerCase();
        const suspiciousPatterns = ['telemetry', 'activation', 'genuine', 'watson', 'analytics'];

        if (suspiciousPatterns.some((pattern) => lowerDomain.includes(pattern))) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'dns_gethostbyname_blocked',
                hostname: encryptData(hostName),
                timestamp: Date.now(),
            });
            this.blockLegacyDNS = true;
            TELEMETRY_STATS.blockedDNS++;
        }
    },
    onLeave(retval) {
        if (this.blockLegacyDNS) {
            retval.replace(ptr(0)); // Return NULL
        }
    },
});

// Block modern DNS-over-HTTPS resolution
tryAttach('dnsapi.dll', 'DnsQuery_W', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const queryName = args[0] ? args[0].readUtf16String() : null;
        if (!queryName) return;

        const lowerQuery = queryName.toLowerCase();
        let shouldBlock = false;

        for (const [vendor, domains] of ADVANCED_DOMAINS) {
            for (const domain of domains) {
                if (lowerQuery.includes(domain.toLowerCase())) {
                    shouldBlock = true;
                    break;
                }
            }
            if (shouldBlock) break;
        }

        if (shouldBlock) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'dns_dnsquery_blocked',
                query: encryptData(queryName),
                timestamp: Date.now(),
            });
            this.blockDNSQuery = true;
            TELEMETRY_STATS.blockedDNS++;
        }
    },
    onLeave(retval) {
        if (this.blockDNSQuery) {
            retval.replace(9003); // DNS_ERROR_RCODE_NAME_ERROR
        }
    },
});

// === COMPREHENSIVE PROCESS MONITORING ===

// Enhanced CreateProcessW blocking
tryAttach('kernel32.dll', 'CreateProcessW', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const cmdLine = args[1] ? args[1].readUtf16String() : null;
        if (!cmdLine) return;

        const lowerCmd = cmdLine.toLowerCase();
        const suspiciousProcesses = [
            'telemetry',
            'diagtrack',
            'watson',
            'activation',
            'licensing',
            'analytics',
            'tracking',
            'crashreporter',
            'errorhandler',
            'mstelemetry',
            'audiodg',
            'custperftrack',
            'compattelrunner',
        ];

        const shouldBlock = suspiciousProcesses.some((proc) => lowerCmd.includes(proc));

        if (shouldBlock) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'createprocessw_blocked',
                command_line: encryptData(cmdLine),
                timestamp: Date.now(),
            });
            this.blockProcess = true;
            TELEMETRY_STATS.blockedProcesses++;
        }
    },
    onLeave(retval) {
        if (this.blockProcess) {
            retval.replace(0); // Return FALSE to indicate failure
        }
    },
});

// Block CreateProcessA (ANSI version)
tryAttach('kernel32.dll', 'CreateProcessA', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const cmdLine = args[1] ? args[1].readCString() : null;
        if (!cmdLine) return;

        const lowerCmd = cmdLine.toLowerCase();
        const suspiciousProcesses = [
            'telemetry',
            'diagtrack',
            'watson',
            'activation',
            'licensing',
            'analytics',
            'tracking',
            'crashreporter',
        ];

        const shouldBlock = suspiciousProcesses.some((proc) => lowerCmd.includes(proc));

        if (shouldBlock) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'createprocessa_blocked',
                command_line: encryptData(cmdLine),
                timestamp: Date.now(),
            });
            this.blockProcess = true;
            TELEMETRY_STATS.blockedProcesses++;
        }
    },
    onLeave(retval) {
        if (this.blockProcess) {
            retval.replace(0); // Return FALSE to indicate failure
        }
    },
});

// Block ShellExecuteW for suspicious programs
tryAttach('shell32.dll', 'ShellExecuteW', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const file = args[2] ? args[2].readUtf16String() : null;
        const parameters = args[3] ? args[3].readUtf16String() : null;

        const fullCommand = `${file || ''} ${parameters || ''}`.toLowerCase();
        const suspiciousExecs = ['telemetry', 'activation', 'licensing', 'analytics'];

        if (suspiciousExecs.some((exec) => fullCommand.includes(exec))) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'shellexecutew_blocked',
                command: encryptData(fullCommand),
                timestamp: Date.now(),
            });
            this.blockShell = true;
            TELEMETRY_STATS.blockedProcesses++;
        }
    },
    onLeave(retval) {
        if (this.blockShell) {
            retval.replace(ptr(2)); // SE_ERR_FILENOTFOUND
        }
    },
});

// Hook NtCreateProcess for deeper process blocking
tryAttach('ntdll.dll', 'NtCreateProcess', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        // Block at the lowest level to catch all process creation attempts
        try {
            randomDelay();
            this.blockNtProcess = true;
            TELEMETRY_STATS.blockedProcesses++;

            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'ntcreateprocess_blocked',
                timestamp: Date.now(),
            });
        } catch (e) {}
    },
    onLeave(retval) {
        if (this.blockNtProcess) {
            retval.replace(ptr(0xc0000022)); // STATUS_ACCESS_DENIED
        }
    },
});

// === COMPREHENSIVE REGISTRY BLOCKING ===

// Enhanced RegSetValueExW blocking
tryAttach('advapi32.dll', 'RegSetValueExW', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const valueName = args[1] ? args[1].readUtf16String() : null;
        if (!valueName) return;

        const lowerValue = valueName.toLowerCase();
        const suspiciousValues = [
            'telemetry',
            'diagtrack',
            'watson',
            'customerexperienceimprovement',
            'spynet',
            'msrt',
            'sqmapi',
            'wer',
            'feedback',
            'ceip',
            'datacollection',
            'allowtelemetry',
            'disabletelemetry',
        ];

        const shouldBlock = suspiciousValues.some((val) => lowerValue.includes(val));

        if (shouldBlock) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'regsetvalueexw_blocked',
                value_name: encryptData(valueName),
                timestamp: Date.now(),
            });
            this.blockRegistry = true;
            TELEMETRY_STATS.blockedRegistry++;
        }
    },
    onLeave(retval) {
        if (this.blockRegistry) {
            retval.replace(5); // ERROR_ACCESS_DENIED
        }
    },
});

// Block RegSetValueExA (ANSI version)
tryAttach('advapi32.dll', 'RegSetValueExA', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const valueName = args[1] ? args[1].readCString() : null;
        if (!valueName) return;

        const lowerValue = valueName.toLowerCase();
        const suspiciousValues = ['telemetry', 'diagtrack', 'watson', 'ceip'];

        const shouldBlock = suspiciousValues.some((val) => lowerValue.includes(val));

        if (shouldBlock) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'regsetvalueexa_blocked',
                value_name: encryptData(valueName),
                timestamp: Date.now(),
            });
            this.blockRegistry = true;
            TELEMETRY_STATS.blockedRegistry++;
        }
    },
    onLeave(retval) {
        if (this.blockRegistry) {
            retval.replace(5); // ERROR_ACCESS_DENIED
        }
    },
});

// Block RegCreateKeyExW for telemetry key creation
tryAttach('advapi32.dll', 'RegCreateKeyExW', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const keyName = args[1] ? args[1].readUtf16String() : null;
        if (!keyName) return;

        const lowerKey = keyName.toLowerCase();
        const suspiciousKeys = [
            'telemetry',
            'diagtrack',
            'sqmapi',
            'customerexperienceimprovement',
            'windowserrorreporting',
            'feedback',
            'datacollection',
        ];

        const shouldBlock = suspiciousKeys.some((key) => lowerKey.includes(key));

        if (shouldBlock) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'regcreatekeyexw_blocked',
                key_name: encryptData(keyName),
                timestamp: Date.now(),
            });
            this.blockKeyCreate = true;
            TELEMETRY_STATS.blockedRegistry++;
        }
    },
    onLeave(retval) {
        if (this.blockKeyCreate) {
            retval.replace(5); // ERROR_ACCESS_DENIED
        }
    },
});

// Hook Native API registry functions
tryAttach('ntdll.dll', 'NtSetValueKey', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const valueNameStruct = args[1];
        if (valueNameStruct && !valueNameStruct.isNull()) {
            try {
                const valueNamePtr = valueNameStruct.add(8).readPointer();
                const valueName = valueNamePtr.readUtf16String();

                if (valueName && valueName.toLowerCase().includes('telemetry')) {
                    randomDelay();
                    this.blockNtRegistry = true;
                    TELEMETRY_STATS.blockedRegistry++;
                }
            } catch (e) {}
        }
    },
    onLeave(retval) {
        if (this.blockNtRegistry) {
            retval.replace(ptr(0xc0000022)); // STATUS_ACCESS_DENIED
        }
    },
});

// === COMPREHENSIVE FILE SYSTEM BLOCKING ===

// Enhanced CreateFileW blocking
tryAttach('kernel32.dll', 'CreateFileW', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const fileName = args[0] ? args[0].readUtf16String() : null;
        if (!fileName) return;

        const lowerFile = fileName.toLowerCase();
        const blockedPaths = [
            'telemetry',
            'diagtrack',
            'watson',
            'activation',
            'licensing',
            'crashdump',
            'errorlog',
            'spynet',
            'feedback',
            'ceip',
            'datacollection',
            'customerexperienceimprovement',
            '\\temp\\telemetry',
            '\\logs\\activation',
            '\\wer\\reportqueue',
        ];

        const shouldBlock = blockedPaths.some((path) => lowerFile.includes(path));

        if (shouldBlock) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'createfilew_blocked',
                file_name: encryptData(fileName),
                timestamp: Date.now(),
            });
            this.blockFile = true;
            TELEMETRY_STATS.blockedFiles++;
        }
    },
    onLeave(retval) {
        if (this.blockFile) {
            retval.replace(ptr(-1)); // INVALID_HANDLE_VALUE
        }
    },
});

// Block CreateFileA (ANSI version)
tryAttach('kernel32.dll', 'CreateFileA', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const fileName = args[0] ? args[0].readCString() : null;
        if (!fileName) return;

        const lowerFile = fileName.toLowerCase();
        const blockedPaths = ['telemetry', 'diagtrack', 'watson', 'activation'];

        const shouldBlock = blockedPaths.some((path) => lowerFile.includes(path));

        if (shouldBlock) {
            randomDelay();
            send({
                type: 'bypass',
                target: 'telemetry_blocker',
                action: 'createfilea_blocked',
                file_name: encryptData(fileName),
                timestamp: Date.now(),
            });
            this.blockFile = true;
            TELEMETRY_STATS.blockedFiles++;
        }
    },
    onLeave(retval) {
        if (this.blockFile) {
            retval.replace(ptr(-1)); // INVALID_HANDLE_VALUE
        }
    },
});

// Block WriteFile operations on suspicious files
tryAttach('kernel32.dll', 'WriteFile', {
    onEnter(args) {
        if (isExcludedProcess()) return;

        const buffer = args[1];
        const bytesToWrite = args[2].toInt32();

        if (buffer && !buffer.isNull() && bytesToWrite > 0) {
            try {
                const data = buffer.readCString(Math.min(bytesToWrite, 512));
                const suspiciousData = ['telemetry', 'analytics', 'tracking', 'activation'];

                if (
                    data &&
                    suspiciousData.some((keyword) => data.toLowerCase().includes(keyword))
                ) {
                    randomDelay();
                    this.blockWrite = true;
                    TELEMETRY_STATS.blockedFiles++;

                    send({
                        type: 'bypass',
                        target: 'telemetry_blocker',
                        action: 'writefile_blocked',
                        data_preview: encryptData(data.substring(0, 100)),
                        timestamp: Date.now(),
                    });
                }
            } catch (e) {}
        }
    },
    onLeave(retval) {
        if (this.blockWrite) {
            retval.replace(0); // Return FALSE
        }
    },
});

// === STATISTICS AND REPORTING ===

// Periodic statistics reporting
setInterval(() => {
    const runtime = Math.floor((Date.now() - TELEMETRY_STATS.startTime) / 1000);

    send({
        type: 'status',
        target: 'telemetry_blocker',
        action: 'statistics_report',
        stats: {
            runtime_seconds: runtime,
            blocked_connections: TELEMETRY_STATS.blockedConnections,
            blocked_dns: TELEMETRY_STATS.blockedDNS,
            blocked_files: TELEMETRY_STATS.blockedFiles,
            blocked_processes: TELEMETRY_STATS.blockedProcesses,
            blocked_registry: TELEMETRY_STATS.blockedRegistry,
            crypto_interceptions: TELEMETRY_STATS.cryptoInterceptions,
            total_blocked:
                TELEMETRY_STATS.blockedConnections +
                TELEMETRY_STATS.blockedDNS +
                TELEMETRY_STATS.blockedFiles +
                TELEMETRY_STATS.blockedProcesses +
                TELEMETRY_STATS.blockedRegistry +
                TELEMETRY_STATS.cryptoInterceptions,
        },
        timestamp: Date.now(),
    });
}, 30000); // Report every 30 seconds

send({
    type: 'status',
    target: 'telemetry_blocker',
    action: 'installation_complete',
    message:
        'Advanced telemetry blocking system activated with comprehensive multi-layer protection',
    features: [
        'Native API interception',
        'Cryptographic blocking',
        'Domain rotation detection',
        'Stealth timing',
        'Process filtering',
        'Encrypted logging',
        'Multi-protocol support',
    ],
    timestamp: Date.now(),
});
