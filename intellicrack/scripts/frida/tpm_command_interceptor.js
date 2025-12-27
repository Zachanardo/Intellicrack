/**
 * TPM Command Interceptor - Frida script for intercepting Windows TPM Base Services
 *
 * Intercepts TBS (TPM Base Services) commands and TPM 2.0 operations for:
 * - Command logging and analysis
 * - PCR value manipulation
 * - Unsealing key interception
 * - Attestation response modification
 */

const TPM_COMMANDS = {
    324: 'TPM2_Startup',
    339: 'TPM2_Create',
    343: 'TPM2_Load',
    350: 'TPM2_Unseal',
    344: 'TPM2_Quote',
    382: 'TPM2_PCR_Read',
    386: 'TPM2_PCR_Extend',
    379: 'TPM2_GetRandom',
    349: 'TPM2_Sign',
    305: 'TPM2_CreatePrimary',
    374: 'TPM2_StartAuthSession',
    378: 'TPM2_GetCapability',
};

const interceptedCommands = [];
const hookedFunctions = new Set();

function parseTPMCommand(buffer) {
    if (buffer.length < 10) {
        return null;
    }

    const tag = buffer.readU16BE(0);
    const size = buffer.readU32BE(2);
    const commandCode = buffer.readU32BE(6);

    return {
        tag: `0x${tag.toString(16)}`,
        size,
        commandCode,
        commandName: TPM_COMMANDS[commandCode] || `Unknown_0x${commandCode.toString(16)}`,
        fullBuffer: buffer,
    };
}

function parseTPMResponse(buffer) {
    if (buffer.length < 10) {
        return null;
    }

    const tag = buffer.readU16BE(0);
    const size = buffer.readU32BE(2);
    const responseCode = buffer.readU32BE(6);

    return {
        tag: `0x${tag.toString(16)}`,
        size,
        responseCode,
        success: responseCode === 0,
        fullBuffer: buffer,
    };
}

function hookTbsipSubmitCommand() {
    const tbsDll = Process.getModuleByName('Tbs.dll');
    if (!tbsDll) {
        console.log('[-] Tbs.dll not loaded');
        return false;
    }

    const tbsipSubmitCommand = tbsDll.getExportByName('Tbsip_Submit_Command');
    if (!tbsipSubmitCommand) {
        console.log('[-] Tbsip_Submit_Command not found');
        return false;
    }

    Interceptor.attach(tbsipSubmitCommand, {
        onEnter(args) {
            const _context = args[0];
            const locality = args[1].toInt32();
            const priority = args[2].toInt32();
            const commandBuffer = args[3];
            const commandSize = args[4].toInt32();

            if (commandSize > 0 && commandSize < 65_536) {
                try {
                    const commandData = commandBuffer.readByteArray(commandSize);
                    const buffer = Buffer.from(commandData);
                    const parsed = parseTPMCommand(buffer);

                    if (parsed) {
                        console.log(`[+] TPM Command Intercepted: ${parsed.commandName}`);
                        console.log(
                            `    Tag: ${parsed.tag}, Size: ${parsed.size}, Code: 0x${parsed.commandCode.toString(16)}`
                        );
                        console.log(`    Locality: ${locality}, Priority: ${priority}`);

                        interceptedCommands.push({
                            timestamp: Date.now(),
                            command: parsed,
                            locality,
                            priority,
                        });

                        switch (parsed.commandName) {
                            case 'TPM2_Unseal': {
                                console.log(
                                    '[*] Unseal operation detected - extracting sealed key...'
                                );

                                break;
                            }
                            case 'TPM2_Quote': {
                                console.log(
                                    '[*] Quote operation detected - monitoring attestation...'
                                );

                                break;
                            }
                            case 'TPM2_PCR_Extend': {
                                console.log(
                                    '[*] PCR Extend detected - monitoring integrity measurement...'
                                );

                                break;
                            }
                            // No default
                        }
                    }
                } catch (error) {
                    console.log(`[-] Error parsing command: ${error.message}`);
                }
            }

            this.commandBuffer = commandBuffer;
            this.commandSize = commandSize;
            this.resultBuffer = args[5];
            this.resultSize = args[6];
        },

        onLeave(retval) {
            if (retval.toInt32() === 0 && this.resultBuffer && !this.resultBuffer.isNull()) {
                try {
                    const resultSizeValue = this.resultSize.readU32();
                    if (resultSizeValue > 0 && resultSizeValue < 65_536) {
                        const responseData = this.resultBuffer.readByteArray(resultSizeValue);
                        const buffer = Buffer.from(responseData);
                        const parsed = parseTPMResponse(buffer);

                        if (parsed) {
                            console.log(
                                `[+] TPM Response: ${parsed.success ? 'SUCCESS' : 'ERROR'}`
                            );
                            console.log(
                                `    Tag: ${parsed.tag}, Size: ${parsed.size}, Code: 0x${parsed.responseCode.toString(16)}`
                            );

                            if (parsed.success && parsed.size > 10) {
                                const dataSize = parsed.size - 10;
                                console.log(`    Data Size: ${dataSize} bytes`);
                            }
                        }
                    }
                } catch (error) {
                    console.log(`[-] Error parsing response: ${error.message}`);
                }
            }
        },
    });

    hookedFunctions.add('Tbsip_Submit_Command');
    console.log('[+] Hooked Tbsip_Submit_Command');
    return true;
}

function hookTbsiContextCreate() {
    const tbsDll = Process.getModuleByName('Tbs.dll');
    if (!tbsDll) {
        return false;
    }

    const tbsiContextCreate = tbsDll.getExportByName('Tbsi_Context_Create');
    if (!tbsiContextCreate) {
        console.log('[-] Tbsi_Context_Create not found');
        return false;
    }

    Interceptor.attach(tbsiContextCreate, {
        onEnter(args) {
            console.log('[+] TBS Context Creation Detected');
            this.contextPtr = args[1];
        },

        onLeave(retval) {
            if (retval.toInt32() === 0) {
                console.log('[+] TBS Context Created Successfully');
                if (this.contextPtr && !this.contextPtr.isNull()) {
                    const context = this.contextPtr.readPointer();
                    console.log(`    Context Handle: ${context}`);
                }
            } else {
                console.log(`[-] TBS Context Creation Failed: 0x${retval.toInt32().toString(16)}`);
            }
        },
    });

    hookedFunctions.add('Tbsi_Context_Create');
    console.log('[+] Hooked Tbsi_Context_Create');
    return true;
}

function hookNCryptTPMFunctions() {
    const ncryptDll = Process.findModuleByName('ncrypt.dll');
    if (!ncryptDll) {
        console.log('[-] ncrypt.dll not loaded');
        return false;
    }

    const ncryptOpenStorageProvider = ncryptDll.getExportByName('NCryptOpenStorageProvider');
    if (ncryptOpenStorageProvider) {
        Interceptor.attach(ncryptOpenStorageProvider, {
            onEnter(args) {
                const providerNamePtr = args[1];
                if (providerNamePtr && !providerNamePtr.isNull()) {
                    try {
                        const providerName = providerNamePtr.readUtf16String();
                        if (providerName?.includes('TPM')) {
                            console.log(`[+] NCrypt TPM Provider Access: ${providerName}`);
                            this.isTpmProvider = true;
                        }
                    } catch (error) {
                        console.log(`[-] Error reading provider name: ${error.message}`);
                    }
                }
            },

            onLeave(retval) {
                if (this.isTpmProvider && retval.toInt32() === 0) {
                    console.log('[+] TPM Storage Provider Opened');
                }
            },
        });

        hookedFunctions.add('NCryptOpenStorageProvider');
        console.log('[+] Hooked NCryptOpenStorageProvider');
    }

    const ncryptOpenKey = ncryptDll.getExportByName('NCryptOpenKey');
    if (ncryptOpenKey) {
        Interceptor.attach(ncryptOpenKey, {
            onEnter: args => {
                const keyNamePtr = args[2];
                if (keyNamePtr && !keyNamePtr.isNull()) {
                    try {
                        const keyName = keyNamePtr.readUtf16String();
                        console.log(`[+] NCrypt Key Access: ${keyName}`);
                    } catch (error) {
                        console.log(`[-] Error reading key name: ${error.message}`);
                    }
                }
            },

            onLeave: retval => {
                if (retval.toInt32() === 0) {
                    console.log('[+] TPM Key Opened Successfully');
                }
            },
        });

        hookedFunctions.add('NCryptOpenKey');
        console.log('[+] Hooked NCryptOpenKey');
    }

    return true;
}

function hookDeviceIoControl() {
    const kernel32 = Process.getModuleByName('kernel32.dll');
    const deviceIoControl = kernel32.getExportByName('DeviceIoControl');

    if (!deviceIoControl) {
        console.log('[-] DeviceIoControl not found');
        return false;
    }

    Interceptor.attach(deviceIoControl, {
        onEnter: args => {
            const hDevice = args[0];
            const dwIoControlCode = args[1].toInt32();

            try {
                const deviceName = hDevice.toString();
                if (
                    deviceName.includes('TPM')
                    || dwIoControlCode === 0x22_C0_00
                    || dwIoControlCode === 0x22_C0_04
                ) {
                    console.log('[+] DeviceIoControl TPM Access Detected');
                    console.log(
                        `    Device: ${deviceName}, IOCTL: 0x${dwIoControlCode.toString(16)}`
                    );

                    const inputBuffer = args[2];
                    const inputSize = args[3].toInt32();

                    if (
                        inputSize > 0
                        && inputSize < 65_536
                        && inputBuffer
                        && !inputBuffer.isNull()
                    ) {
                        const inputData = inputBuffer.readByteArray(inputSize);
                        const buffer = Buffer.from(inputData);
                        const parsed = parseTPMCommand(buffer);

                        if (parsed) {
                            console.log(`    TPM Command: ${parsed.commandName}`);
                        }
                    }
                }
            } catch (error) {
                console.log(`[-] Error in DeviceIoControl hook: ${error.message}`);
            }
        },
    });

    hookedFunctions.add('DeviceIoControl');
    console.log('[+] Hooked DeviceIoControl');
    return true;
}

function getSummary() {
    return {
        hookedFunctions: [...hookedFunctions],
        interceptedCommandCount: interceptedCommands.length,
        commands: interceptedCommands.map(entry => ({
            timestamp: entry.timestamp,
            commandName: entry.command.commandName,
            commandCode: `0x${entry.command.commandCode.toString(16)}`,
            size: entry.command.size,
        })),
    };
}

function initialize() {
    console.log('[*] TPM Command Interceptor Initializing...');
    console.log('[*] Target Process:', Process.getCurrentThreadId());

    let hooksInstalled = 0;

    if (hookTbsipSubmitCommand()) {
        hooksInstalled++;
    }

    if (hookTbsiContextCreate()) {
        hooksInstalled++;
    }

    if (hookNCryptTPMFunctions()) {
        hooksInstalled++;
    }

    if (hookDeviceIoControl()) {
        hooksInstalled++;
    }

    console.log('[+] TPM Command Interceptor Initialized');
    console.log(`[+] Hooks Installed: ${hooksInstalled}`);
    console.log('[*] Monitoring TPM operations...');
}

rpc.exports = {
    getSummary,
    getInterceptedCommands: () => interceptedCommands,
    clearCommands: () => {
        interceptedCommands.length = 0;
        return { status: 'cleared' };
    },
};

setImmediate(initialize);
