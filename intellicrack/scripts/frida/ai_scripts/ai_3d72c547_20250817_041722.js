/*
 * AI-Generated Script
 * Prompt: Create a Frida script that hooks CreateFileW API calls and logs all file access attempts. Focus on detecting license file reads.
 * Generated: 2025-08-17T04:17:22.995050
 * Model: none
 * Confidence: 0.7999999999999999
 * Description: Create a Frida script that hooks CreateFileW API calls and logs all file access attempts
 */

// Hook CreateFileW to monitor file access
const CreateFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');

if (CreateFileW) {
    Interceptor.attach(CreateFileW, {
        onEnter: args => {
            const filename = args[0].readUtf16String();
            const accessMode = args[1].toInt32();

            // Check for license-related file access
            if (filename?.toLowerCase().includes('license')) {
                send({
                    type: 'license_file_access',
                    filename: filename,
                    accessMode: accessMode,
                    timestamp: Date.now(),
                });
            }

            // Log all file accesses
            send(`[CreateFileW] ${filename}`);
        },
        onLeave: function (retval) {
            // Handle value can be used for further monitoring
            this.handle = retval;
        },
    });
}

// Also hook CreateFileA for completeness
const CreateFileA = Module.findExportByName('kernel32.dll', 'CreateFileA');

if (CreateFileA) {
    Interceptor.attach(CreateFileA, {
        onEnter: args => {
            const filename = args[0].readCString();
            const accessMode = args[1].toInt32();

            // Check for license-related file access
            if (filename?.toLowerCase().includes('license')) {
                send({
                    type: 'license_file_access',
                    filename: filename,
                    accessMode: accessMode,
                    timestamp: Date.now(),
                });
            }

            // Log all file accesses
            send(`[CreateFileA] ${filename}`);
        },
        onLeave: function (retval) {
            // Handle value can be used for further monitoring
            this.handle = retval;
        },
    });
}
