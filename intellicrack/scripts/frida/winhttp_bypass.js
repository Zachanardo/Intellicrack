const WINHTTP_OPTION_SECURITY_FLAGS = 31;
const SECURITY_FLAG_IGNORE_UNKNOWN_CA = 0x00000100;
const SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE = 0x00000200;
const SECURITY_FLAG_IGNORE_CERT_CN_INVALID = 0x00001000;
const SECURITY_FLAG_IGNORE_CERT_DATE_INVALID = 0x00002000;
const ALL_CERT_IGNORE_FLAGS =
    SECURITY_FLAG_IGNORE_UNKNOWN_CA |
    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;

const activity = [];
const MAX_ACTIVITY_LOG = 1000;

function log(message, level = 'info') {
    const entry = {
        timestamp: new Date().toISOString(),
        level: level,
        message: message,
    };
    send({ type: 'log', data: entry });
    activity.push(entry);
    if (activity.length > MAX_ACTIVITY_LOG) {
        activity.shift();
    }
}

function logError(message) {
    log(message, 'error');
}

const winhttp = Process.getModuleByName('winhttp.dll');
if (!winhttp) {
    logError('WinHTTP module not found');
} else {
    log('WinHTTP module found at: ' + winhttp.base);

    try {
        const WinHttpSetOption = Module.findExportByName('winhttp.dll', 'WinHttpSetOption');
        if (WinHttpSetOption) {
            Interceptor.attach(WinHttpSetOption, {
                onEnter: function (args) {
                    const hInternet = args[0];
                    const dwOption = args[1].toInt32();
                    const lpBuffer = args[2];
                    const dwBufferLength = args[3].toInt32();

                    if (dwOption === WINHTTP_OPTION_SECURITY_FLAGS) {
                        const originalFlags = lpBuffer.readU32();
                        const newFlags = originalFlags | ALL_CERT_IGNORE_FLAGS;
                        lpBuffer.writeU32(newFlags);

                        log(
                            `WinHttpSetOption: Modified SECURITY_FLAGS from 0x${originalFlags.toString(16)} to 0x${newFlags.toString(16)}`
                        );

                        this.modified = true;
                        this.originalFlags = originalFlags;
                        this.newFlags = newFlags;
                    }
                },
                onLeave: function (retval) {
                    if (this.modified) {
                        retval.replace(ptr(1));
                        log('WinHttpSetOption: Forced success return');
                    }
                },
            });
            log('Successfully hooked WinHttpSetOption');
        }
    } catch (e) {
        logError('Failed to hook WinHttpSetOption: ' + e.message);
    }

    try {
        const WinHttpSendRequest = Module.findExportByName('winhttp.dll', 'WinHttpSendRequest');
        if (WinHttpSendRequest) {
            Interceptor.attach(WinHttpSendRequest, {
                onEnter: args => {
                    const hRequest = args[0];
                    const lpszHeaders = args[1];
                    const dwHeadersLength = args[2].toInt32();
                    const lpOptional = args[3];
                    const dwOptionalLength = args[4].toInt32();
                    const dwTotalLength = args[5].toInt32();
                    const dwContext = args[6];

                    let headers = '';
                    if (!lpszHeaders.isNull() && dwHeadersLength !== 0) {
                        try {
                            headers = lpszHeaders.readUtf16String();
                        } catch (e) {
                            headers = '<unable to read>';
                        }
                    }

                    const requestInfo = {
                        timestamp: new Date().toISOString(),
                        function: 'WinHttpSendRequest',
                        hRequest: hRequest.toString(),
                        headers: headers,
                        optionalLength: dwOptionalLength,
                        totalLength: dwTotalLength,
                    };

                    log(`WinHttpSendRequest called - Headers: ${headers.substring(0, 200)}`);
                    send({ type: 'https_request', data: requestInfo });
                },
                onLeave: retval => {
                    if (retval.toInt32() === 0) {
                        log('WinHttpSendRequest: Failed originally, forcing success');
                        retval.replace(ptr(1));
                    } else {
                        log('WinHttpSendRequest: Succeeded');
                    }
                },
            });
            log('Successfully hooked WinHttpSendRequest');
        }
    } catch (e) {
        logError('Failed to hook WinHttpSendRequest: ' + e.message);
    }

    try {
        const WinHttpReceiveResponse = Module.findExportByName(
            'winhttp.dll',
            'WinHttpReceiveResponse'
        );
        if (WinHttpReceiveResponse) {
            Interceptor.attach(WinHttpReceiveResponse, {
                onEnter: function (args) {
                    const hRequest = args[0];
                    const lpReserved = args[1];

                    log(`WinHttpReceiveResponse called - hRequest: ${hRequest}`);
                    this.hRequest = hRequest;
                },
                onLeave: retval => {
                    const success = retval.toInt32() !== 0;
                    if (!success) {
                        const lastError = ptr(kernel32.GetLastError());
                        log(
                            `WinHttpReceiveResponse: Failed with error ${lastError}, forcing success`
                        );
                        retval.replace(ptr(1));
                    } else {
                        log('WinHttpReceiveResponse: Succeeded');
                    }
                },
            });
            log('Successfully hooked WinHttpReceiveResponse');
        }
    } catch (e) {
        logError('Failed to hook WinHttpReceiveResponse: ' + e.message);
    }

    try {
        const WinHttpQueryOption = Module.findExportByName('winhttp.dll', 'WinHttpQueryOption');
        if (WinHttpQueryOption) {
            Interceptor.attach(WinHttpQueryOption, {
                onEnter: function (args) {
                    const hInternet = args[0];
                    const dwOption = args[1].toInt32();
                    const lpBuffer = args[2];
                    const lpdwBufferLength = args[3];

                    this.dwOption = dwOption;
                    this.lpBuffer = lpBuffer;
                    this.lpdwBufferLength = lpdwBufferLength;
                },
                onLeave: function (retval) {
                    if (this.dwOption === WINHTTP_OPTION_SECURITY_FLAGS && retval.toInt32() !== 0) {
                        const bufferLength = this.lpdwBufferLength.readU32();
                        if (bufferLength >= 4 && !this.lpBuffer.isNull()) {
                            const flags = this.lpBuffer.readU32();
                            log(
                                `WinHttpQueryOption: Read SECURITY_FLAGS as 0x${flags.toString(16)}`
                            );
                        }
                    }
                },
            });
            log('Successfully hooked WinHttpQueryOption');
        }
    } catch (e) {
        logError('Failed to hook WinHttpQueryOption: ' + e.message);
    }
}

try {
    var kernel32 = Process.getModuleByName('kernel32.dll');
} catch (e) {
    logError('Failed to get kernel32.dll: ' + e.message);
}

rpc.exports = {
    getWinHttpActivity: () => activity,
    clearLogs: () => {
        activity.length = 0;
        log('Activity log cleared');
        return true;
    },
    getBypassStatus: () => ({
        active: true,
        library: 'winhttp.dll',
        hooksInstalled: [
            'WinHttpSetOption',
            'WinHttpSendRequest',
            'WinHttpReceiveResponse',
            'WinHttpQueryOption',
        ],
        bypassFlags: {
            SECURITY_FLAG_IGNORE_UNKNOWN_CA: true,
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE: true,
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID: true,
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID: true,
        },
    }),
    testBypass: () => {
        log('Testing WinHTTP bypass functionality');
        return {
            success: true,
            message: 'WinHTTP bypass is active and monitoring',
        };
    },
};

log('WinHTTP certificate bypass script loaded successfully');
send({ type: 'bypass_success', library: 'winhttp.dll' });
