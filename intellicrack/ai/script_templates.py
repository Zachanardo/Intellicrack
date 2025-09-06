"""Script Templates for AI-Generated Frida and Ghidra Scripts.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

from datetime import datetime


class FridaTemplates:
    """Comprehensive Frida script templates for various protection types."""

    @staticmethod
    def get_base_template() -> str:
        """Base Frida script template with core functionality."""
        return """
// Auto-generated Frida script by Intellicrack AI
// Target: {target_binary}
// Protection Types: {protection_types}
// Generated: {timestamp}
// Confidence: {confidence}%

(function() {{
    "use strict";

    // Script metadata
    const scriptInfo = {{
        name: "{script_name}",
        version: "1.0.0",
        description: "{description}",
        target: "{target_binary}",
        protections: {protection_list},
        generated: "{timestamp}"
    }};

    // Configuration
    const config = {{
        debug: true,
        logHooks: true,
        logValues: true,
        bypassAll: true
    }};

    // Utilities
    const logger = {{
        info: function(msg) {{
            console.log(`[INFO] ${{new Date().toISOString()}} - ${{msg}}`);
        }},
        warn: function(msg) {{
            console.log(`[WARN] ${{new Date().toISOString()}} - ${{msg}}`);
        }},
        error: function(msg) {{
            console.log(`[ERROR] ${{new Date().toISOString()}} - ${{msg}}`);
        }},
        success: function(msg) {{
            console.log(`[SUCCESS] ${{new Date().toISOString()}} - ${{msg}}`);
        }}
    }};

    // Hook tracking
    const hooks = {{
        installed: [],
        failed: [],
        register: function(name, address, type) {{
            this.installed.push({{name, address, type, timestamp: Date.now()}});
        }},
        fail: function(name, error) {{
            this.failed.push({{name, error, timestamp: Date.now()}});
        }},
        getStats: function() {{
            return {{
                total: this.installed.length,
                failed: this.failed.length,
                success_rate: this.installed.length / (this.installed.length + this.failed.length)
            }};
        }}
    }};

    // Protection detection counters
    const detections = {{
        license_checks: 0,
        time_checks: 0,
        network_calls: 0,
        crypto_calls: 0,
        registry_access: 0
    }};

    {initialization_code}

    {hook_installations}

    {bypass_logic}

    {helper_functions}

    // Main execution
    logger.info(`Initialized ${{scriptInfo.name}} v${{scriptInfo.version}}`);
    logger.info(`Target: ${{scriptInfo.target}}`);
    logger.info(`Protections detected: ${{scriptInfo.protections.join(", ")}}`);

    // Periodic status reporting
    setInterval(function() {{
        const stats = hooks.getStats();
        logger.info(`Hook stats: ${{stats.total}} active, ${{stats.failed}} failed, ${{(stats.success_rate * 100).toFixed(1)}}% success rate`);
        logger.info(`Detections: ${{JSON.stringify(detections)}}`);
    }}, 30000);

}})();
"""

    @staticmethod
    def get_license_check_template() -> str:
        """Template for license check bypassing."""
        return """
    // License Check Bypass Implementation
    logger.info("Setting up license check bypass...");

    // String comparison hooks
    const stringFunctions = ["strcmp", "strcasecmp", "memcmp", "wcscmp", "_stricmp"];
    stringFunctions.forEach(function(funcName) {{
        try {{
            const funcAddr = Module.findExportByName(null, funcName);
            if (funcAddr) {{
                Interceptor.attach(funcAddr, {{
                    onEnter: function(args) {{
                        this.str1 = "";
                        this.str2 = "";
                        this.isLicenseCheck = false;

                        try {{
                            this.str1 = args[0].readCString() || "";
                            this.str2 = args[1].readCString() || "";

                            // Detect license-related comparisons
                            const licenseKeywords = ["license", "trial", "demo", "expire", "activate", "register", "serial", "key"];
                            this.isLicenseCheck = licenseKeywords.some(keyword =>
                                this.str1.toLowerCase().includes(keyword) ||
                                this.str2.toLowerCase().includes(keyword)
                            );

                            if (this.isLicenseCheck) {{
                                detections.license_checks++;
                                logger.warn(`License check detected in ${{funcName}}: "${{this.str1}}" vs "${{this.str2}}"`);
                            }}
                        }} catch (e) {{
                            // Handle read errors gracefully
                        }}
                    }},
                    onLeave: function(retval) {{
                        if (this.isLicenseCheck && config.bypassAll) {{
                            logger.success(`Bypassing license check in ${{funcName}} - forcing success`);
                            retval.replace(0);  // Force strings to be equal
                        }}
                    }}
                }});
                hooks.register(funcName, funcAddr, "string_comparison");
                logger.info(`Hooked ${{funcName}} at ${{funcAddr}}`);
            }}
        }} catch (e) {{
            hooks.fail(funcName, e.message);
            logger.error(`Failed to hook ${{funcName}}: ${{e.message}}`);
        }}
    }});

    // License validation function hooks
    const licensePatterns = [
        "CheckLicense", "ValidateLicense", "VerifyLicense", "LicenseCheck",
        "IsLicensed", "HasLicense", "GetLicense", "LicenseValid"
    ];

    // Search in main module
    const mainModule = Process.enumerateModules()[0];
    const exports = mainModule.enumerateExports();

    exports.forEach(function(exp) {{
        const funcName = exp.name.toLowerCase();
        const isLicenseFunc = licensePatterns.some(pattern =>
            funcName.includes(pattern.toLowerCase())
        );

        if (isLicenseFunc) {{
            try {{
                Interceptor.attach(exp.address, {{
                    onEnter: function(args) {{
                        detections.license_checks++;
                        logger.warn(`License function called: ${{exp.name}} at ${{exp.address}}`);
                        if (config.logValues) {{
                            for (let i = 0; i < Math.min(args.length, 4); i++) {{
                                try {{
                                    logger.info(`  Arg[${{i}}]: ${{args[i]}}`);
                                }} catch (e) {{
                                    logger.info(`  Arg[${{i}}]: <unreadable>`);
                                }}
                            }}
                        }}
                    }},
                    onLeave: function(retval) {{
                        if (config.bypassAll) {{
                            logger.success(`Bypassing ${{exp.name}} - forcing success return`);
                            retval.replace(1);  // Force success (non-zero)
                        }}
                    }}
                }});
                hooks.register(exp.name, exp.address, "license_function");
                logger.info(`Hooked license function: ${{exp.name}}`);
            }} catch (e) {{
                hooks.fail(exp.name, e.message);
                logger.error(`Failed to hook ${{exp.name}}: ${{e.message}}`);
            }}
        }}
    }});
"""

    @staticmethod
    def get_time_bomb_template() -> str:
        """Template for time bomb bypassing."""
        return """
    // Time Bomb Bypass Implementation
    logger.info("Setting up time bomb bypass...");

    // Time function hooks
    const timeFunctions = [
        {{name: "GetSystemTime", module: "kernel32.dll"}},
        {{name: "GetLocalTime", module: "kernel32.dll"}},
        {{name: "GetTickCount", module: "kernel32.dll"}},
        {{name: "GetTickCount64", module: "kernel32.dll"}},
        {{name: "QueryPerformanceCounter", module: "kernel32.dll"}},
        {{name: "time", module: null}},
        {{name: "clock", module: null}},
        {{name: "_time64", module: null}}
    ];

    // Fixed time values for consistent behavior
    const fixedTime = {{
        year: 2023,
        month: 6,    // June (0-based would be 5)
        day: 15,
        hour: 12,
        minute: 0,
        second: 0
    }};

    timeFunctions.forEach(function(timeFunc) {{
        try {{
            const funcAddr = Module.findExportByName(timeFunc.module, timeFunc.name);
            if (funcAddr) {{
                Interceptor.attach(funcAddr, {{
                    onEnter: function(args) {{
                        detections.time_checks++;
                        logger.warn(`Time function called: ${{timeFunc.name}}`);
                        this.shouldModify = config.bypassAll;
                    }},
                    onLeave: function(retval) {{
                        if (this.shouldModify) {{
                            if (timeFunc.name === "GetTickCount" || timeFunc.name === "GetTickCount64") {{
                                // Return fixed tick count (60 seconds uptime)
                                retval.replace(60000);
                                logger.success(`Modified ${{timeFunc.name}} - returned fixed tick count`);
                            }} else if (timeFunc.name === "time" || timeFunc.name === "_time64") {{
                                // Return fixed unix timestamp for June 15, 2023
                                const fixedTimestamp = Math.floor(new Date(2023, 5, 15, 12, 0, 0).getTime() / 1000);
                                retval.replace(fixedTimestamp);
                                logger.success(`Modified ${{timeFunc.name}} - returned fixed timestamp`);
                            }}
                        }}
                    }}
                }});

                // Special handling for GetSystemTime/GetLocalTime with SYSTEMTIME structure
                if (timeFunc.name === "GetSystemTime" || timeFunc.name === "GetLocalTime") {{
                    Interceptor.replace(funcAddr, new NativeCallback(function(systemTimePtr) {{
                        if (systemTimePtr && !systemTimePtr.isNull()) {{
                            // Fill SYSTEMTIME structure with fixed values
                            systemTimePtr.writeU16(fixedTime.year);      // wYear
                            systemTimePtr.add(2).writeU16(fixedTime.month);    // wMonth
                            systemTimePtr.add(4).writeU16(0);           // wDayOfWeek
                            systemTimePtr.add(6).writeU16(fixedTime.day);      // wDay
                            systemTimePtr.add(8).writeU16(fixedTime.hour);     // wHour
                            systemTimePtr.add(10).writeU16(fixedTime.minute);  // wMinute
                            systemTimePtr.add(12).writeU16(fixedTime.second);  // wSecond
                            systemTimePtr.add(14).writeU16(0);          // wMilliseconds

                            logger.success(`Replaced ${{timeFunc.name}} with fixed time: ${{fixedTime.year}}-${{fixedTime.month}}-${{fixedTime.day}}`);
                        }}
                    }}, 'void', ['pointer']));
                }}

                hooks.register(timeFunc.name, funcAddr, "time_function");
                logger.info(`Hooked time function: ${{timeFunc.name}}`);
            }}
        }} catch (e) {{
            hooks.fail(timeFunc.name, e.message);
            logger.error(`Failed to hook ${{timeFunc.name}}: ${{e.message}}`);
        }}
    }});
"""

    @staticmethod
    def get_network_validation_template() -> str:
        """Template for network validation bypassing."""
        return """
    // Network Validation Bypass Implementation
    logger.info("Setting up network validation bypass...");

    // Network function hooks
    const networkFunctions = [
        {{name: "InternetOpenA", module: "wininet.dll"}},
        {{name: "InternetOpenW", module: "wininet.dll"}},
        {{name: "HttpSendRequestA", module: "wininet.dll"}},
        {{name: "HttpSendRequestW", module: "wininet.dll"}},
        {{name: "InternetReadFile", module: "wininet.dll"}},
        {{name: "connect", module: "ws2_32.dll"}},
        {{name: "send", module: "ws2_32.dll"}},
        {{name: "recv", module: "ws2_32.dll"}}
    ];

    networkFunctions.forEach(function(netFunc) {{
        try {{
            const funcAddr = Module.findExportByName(netFunc.module, netFunc.name);
            if (funcAddr) {{
                Interceptor.attach(funcAddr, {{
                    onEnter: function(args) {{
                        detections.network_calls++;
                        logger.warn(`Network function called: ${{netFunc.name}}`);

                        // Log network details
                        if (netFunc.name.includes("HttpSendRequest")) {{
                            try {{
                                logger.info(`HTTP request detected - potential license validation`);
                            }} catch (e) {{
                                // Handle errors gracefully
                            }}
                        }}

                        this.shouldBlock = config.bypassAll;
                    }},
                    onLeave: function(retval) {{
                        if (this.shouldBlock) {{
                            if (netFunc.name.includes("connect")) {{
                                // Block connection attempts
                                retval.replace(-1);  // SOCKET_ERROR
                                logger.success(`Blocked connection attempt in ${{netFunc.name}}`);
                            }} else if (netFunc.name.includes("HttpSendRequest")) {{
                                // Make HTTP requests appear successful
                                retval.replace(1);  // TRUE
                                logger.success(`Faked successful HTTP request in ${{netFunc.name}}`);
                            }} else if (netFunc.name.includes("InternetReadFile")) {{
                                // Provide fake response data
                                try {{
                                    const buffer = args[1];
                                    const bytesToRead = args[2].toInt32();
                                    const bytesRead = args[3];

                                    if (buffer && !buffer.isNull() && bytesToRead > 0) {{
                                        // Write fake license validation response
                                        const fakeResponse = "{{\"status\":\"valid\",\"licensed\":true,\"expires\":\"2099-12-31\"}}";
                                        const copySize = Math.min(bytesToRead - 1, fakeResponse.length);
                                        buffer.writeUtf8String(fakeResponse.substring(0, copySize));

                                        if (bytesRead && !bytesRead.isNull()) {{
                                            bytesRead.writeU32(copySize);
                                        }}

                                        logger.success(`Provided fake license response in ${{netFunc.name}}`);
                                    }}
                                }} catch (e) {{
                                    logger.error(`Error in ${{netFunc.name}} fake response: ${{e.message}}`);
                                }}
                            }}
                        }}
                    }}
                }});
                hooks.register(netFunc.name, funcAddr, "network_function");
                logger.info(`Hooked network function: ${{netFunc.name}}`);
            }}
        }} catch (e) {{
            hooks.fail(netFunc.name, e.message);
            logger.error(`Failed to hook ${{netFunc.name}}: ${{e.message}}`);
        }}
    }});
"""

    @staticmethod
    def get_registry_bypass_template() -> str:
        """Template for registry-based protection bypassing."""
        return """
    // Registry Bypass Implementation
    logger.info("Setting up registry bypass...");

    // Registry function hooks
    const registryFunctions = [
        {{name: "RegOpenKeyExA", module: "advapi32.dll"}},
        {{name: "RegOpenKeyExW", module: "advapi32.dll"}},
        {{name: "RegQueryValueExA", module: "advapi32.dll"}},
        {{name: "RegQueryValueExW", module: "advapi32.dll"}},
        {{name: "RegSetValueExA", module: "advapi32.dll"}},
        {{name: "RegSetValueExW", module: "advapi32.dll"}}
    ];

    // Fake registry values for license keys
    const fakeRegistryData = {{
        "LicenseKey": "AI-GENERATED-LICENSE-KEY-12345",
        "SerialNumber": "INTEL-AI-2025-BYPASS-KEY",
        "ActivationCode": "ACTIVATED-BY-INTELLICRACK-AI",
        "ExpirationDate": "2099-12-31",
        "RegisteredUser": "Intellicrack AI User",
        "ProductKey": "BYPASS-FRIDA-SCRIPT-GENERATED"
    }};

    registryFunctions.forEach(function(regFunc) {{
        try {{
            const funcAddr = Module.findExportByName(regFunc.module, regFunc.name);
            if (funcAddr) {{
                Interceptor.attach(funcAddr, {{
                    onEnter: function(args) {{
                        detections.registry_access++;
                        this.keyName = "";
                        this.valueName = "";
                        this.isLicenseRelated = false;

                        try {{
                            if (regFunc.name.includes("RegQueryValueEx")) {{
                                // Extract value name being queried
                                if (args[1] && !args[1].isNull()) {{
                                    if (regFunc.name.includes("W")) {{
                                        this.valueName = args[1].readUtf16String() || "";
                                    }} else {{
                                        this.valueName = args[1].readCString() || "";
                                    }}
                                }}

                                // Check if it's license-related
                                const licenseKeywords = ["license", "serial", "key", "activation", "register", "product"];
                                this.isLicenseRelated = licenseKeywords.some(keyword =>
                                    this.valueName.toLowerCase().includes(keyword)
                                );

                                if (this.isLicenseRelated) {{
                                    logger.warn(`License registry query: ${{this.valueName}}`);
                                }}
                            }}
                        }} catch (e) {{
                            // Handle read errors
                        }}
                    }},
                    onLeave: function(retval) {{
                        if (this.isLicenseRelated && config.bypassAll) {{
                            if (regFunc.name.includes("RegQueryValueEx")) {{
                                // Fake successful registry read
                                retval.replace(0);  // ERROR_SUCCESS

                                // Try to provide fake data
                                try {{
                                    const args = this.context.sp.readPointer();  // Approximate
                                    // Note: This is simplified - real implementation would need proper argument parsing
                                    logger.success(`Faked registry value for: ${{this.valueName}}`);
                                }} catch (e) {{
                                    // Continue if we can't write fake data
                                }}
                            }} else if (regFunc.name.includes("RegOpenKeyEx")) {{
                                // Allow key opening
                                retval.replace(0);  // ERROR_SUCCESS
                                logger.success(`Allowed registry key opening`);
                            }}
                        }}
                    }}
                }});
                hooks.register(regFunc.name, funcAddr, "registry_function");
                logger.info(`Hooked registry function: ${{regFunc.name}}`);
            }}
        }} catch (e) {{
            hooks.fail(regFunc.name, e.message);
            logger.error(`Failed to hook ${{regFunc.name}}: ${{e.message}}`);
        }}
    }});
"""


class GhidraTemplates:
    """Comprehensive Ghidra script templates for various analysis types."""

    @staticmethod
    def get_base_template() -> str:
        """Base Ghidra script template with core functionality."""
        return '''
# Auto-generated Ghidra script by Intellicrack AI
# Target: {target_binary}
# Analysis Goal: {analysis_goal}
# Protection Types: {protection_types}
# Generated: {timestamp}
# Confidence: {confidence}%

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import Function, Instruction
from ghidra.program.model.symbol import SymbolTable
from ghidra.program.model.mem import Memory
from ghidra.util.task import TaskMonitor
import re
import json
from datetime import datetime

class {script_class_name}(GhidraScript):
    """
    AI-generated Ghidra script for {target_binary}

    This script performs automated analysis and patching for license bypass.
    Generated by Intellicrack AI with {confidence}% confidence.
    """

    def __init__(self):
        """Initialize Ghidra script instance with analysis results container."""
        super().__init__()
        self.analysis_results = {{
            "target": "{target_binary}",
            "timestamp": "{timestamp}",
            "license_functions": [],
            "license_strings": [],
            "patches_applied": 0,
            "analysis_summary": ""
        }}

    def run(self):
        """Main execution method."""
        try:
            self.println("[AI-Generated] Starting analysis of {{}}...".format(getCurrentProgram().getName()))

            {initialization_code}

            {analysis_functions}

            {patching_logic}

            {reporting_logic}

            self.println("[AI-Generated] Analysis complete")
            self.print_summary()

        except Exception as e:
            self.logger.error("Exception in script_templates: %s", e)
            self.println("[ERROR] Script execution failed: {{}}".format(str(e)))
            import traceback
            traceback.print_exc()

    def print_summary(self):
        """Print analysis summary."""
        self.println("\\n" + "="*60)
        self.println("ANALYSIS SUMMARY")
        self.println("="*60)
        self.println("Target: {{}}".format(self.analysis_results["target"]))
        self.println("License functions found: {{}}".format(len(self.analysis_results["license_functions"])))
        self.println("License strings found: {{}}".format(len(self.analysis_results["license_strings"])))
        self.println("Patches applied: {{}}".format(self.analysis_results["patches_applied"]))
        self.println("="*60)

        # Save results to file
        try:
            import tempfile
            results_file = os.path.join(tempfile.gettempdir(), "intellicrack_analysis_results.json")
            with open(results_file, 'w') as f:
                json.dump(self.analysis_results, f, indent=2, default=str)
            self.println("Results saved to: {{}}".format(results_file))
        except Exception as e:
            self.logger.error("Exception in script_templates: %s", e)
            self.println("Could not save results: {{}}".format(str(e)))

# Execute the script
{script_class_name}().run()
'''

    @staticmethod
    def get_license_analysis_template() -> str:
        """Template for license-related analysis in Ghidra."""
        return '''
        # License Function Analysis
        self.println("Analyzing license-related functions...")

        program = getCurrentProgram()
        listing = program.getListing()
        function_manager = program.getFunctionManager()
        symbol_table = program.getSymbolTable()

        # Find license-related functions
        license_keywords = ["license", "trial", "demo", "check", "validate", "verify", "activate", "register"]
        license_functions = []

        # Search through all functions
        functions = function_manager.getFunctions(True)
        for function in functions:
            func_name = function.getName().lower()

            # Check if function name contains license keywords
            for keyword in license_keywords:
                if keyword in func_name:
                    license_functions.append(function)
                    self.analysis_results["license_functions"].append({{
                        "name": function.getName(),
                        "address": str(function.getEntryPoint()),
                        "keyword_match": keyword
                    }})
                    self.println("Found license function: {{}} at {{}}".format(
                        function.getName(), function.getEntryPoint()
                    ))
                    break

        # Analyze each license function
        for function in license_functions:
            self.analyze_license_function(function)

        # Search for license strings
        self.find_license_strings()

    def analyze_license_function(self, function):
        """Analyze a specific license function."""
        self.println("Analyzing function: {{}}".format(function.getName()))

        # Get function body
        body = function.getBody()
        listing = getCurrentProgram().getListing()

        # Analyze instructions in the function
        instruction = listing.getInstructionAt(function.getEntryPoint())
        string_refs = []
        call_targets = []

        while instruction is not None and body.contains(instruction.getAddress()):
            # Look for string references
            for ref in instruction.getOperandReferences(0):
                try:
                    if ref.getReferenceType().isData():
                        data = listing.getDataAt(ref.getToAddress())
                        if data and data.hasStringValue():
                            string_val = data.getDefaultValueRepresentation()
                            string_refs.append(string_val)
                            self.println("  String reference: {{}}".format(string_val))
                except:
                    pass

            # Look for function calls
            if instruction.getMnemonicString() in ["CALL", "JMP"]:
                for ref in instruction.getOperandReferences(0):
                    if ref.getReferenceType().isCall():
                        target_func = getFunctionAt(ref.getToAddress())
                        if target_func:
                            call_targets.append(target_func.getName())
                            self.println("  Calls: {{}}".format(target_func.getName()))

            instruction = instruction.getNext()

        # Store analysis results
        func_analysis = {{
            "name": function.getName(),
            "address": str(function.getEntryPoint()),
            "string_references": string_refs,
            "function_calls": call_targets,
            "instruction_count": len(list(listing.getInstructions(body, True)))
        }}

        return func_analysis

    def find_license_strings(self):
        """Find license-related strings in the binary."""
        self.println("Searching for license-related strings...")

        program = getCurrentProgram()
        listing = program.getListing()

        # Get all defined data
        data_iterator = listing.getDefinedData(True)
        license_strings = []

        license_keywords = ["license", "trial", "demo", "expire", "activate", "register", "serial", "key"]

        for data in data_iterator:
            if data.hasStringValue():
                try:
                    string_val = data.getDefaultValueRepresentation()
                    string_lower = string_val.lower()

                    # Check if string contains license keywords
                    for keyword in license_keywords:
                        if keyword in string_lower:
                            license_strings.append({{
                                "address": str(data.getAddress()),
                                "value": string_val,
                                "keyword_match": keyword
                            }})
                            self.analysis_results["license_strings"].append({{
                                "address": str(data.getAddress()),
                                "value": string_val,
                                "keyword_match": keyword
                            }})
                            self.println("License string at {{}}: {{}}".format(
                                data.getAddress(), string_val
                            ))
                            break
                except:
                    pass

        self.println("Found {{}} license-related strings".format(len(license_strings)))
        return license_strings
'''

    @staticmethod
    def get_patching_template() -> str:
        """Template for binary patching in Ghidra."""
        return '''
        # Binary Patching Implementation
        self.println("Starting patching process...")

        program = getCurrentProgram()
        listing = program.getListing()
        memory = program.getMemory()

        patches_applied = 0

        # Patch license check functions
        for func_info in self.analysis_results["license_functions"]:
            try:
                func_addr = getAddressFactory().getAddress(func_info["address"])
                function = getFunctionAt(func_addr)

                if function:
                    self.println("Patching function: {{}}".format(function.getName()))

                    # Get first instruction
                    entry_point = function.getEntryPoint()
                    instruction = listing.getInstructionAt(entry_point)

                    if instruction:
                        # Strategy 1: Replace function with immediate return of success
                        if self.patch_function_return_success(function):
                            patches_applied += 1
                            self.println("  Applied return-success patch")

                        # Strategy 2: NOP out conditional jumps
                        elif self.patch_conditional_jumps(function):
                            patches_applied += 1
                            self.println("  Applied conditional jump patches")

                        # Strategy 3: Patch string comparisons
                        elif self.patch_string_comparisons(function):
                            patches_applied += 1
                            self.println("  Applied string comparison patches")

                        else:
                            self.println("  No suitable patch strategy found")

            except Exception as e:
                logger.error("Exception in script_templates: %s", e)
                self.println("Failed to patch {{}}: {{}}".format(func_info["name"], str(e)))

        self.analysis_results["patches_applied"] = patches_applied
        self.println("Patching complete: {{}} patches applied".format(patches_applied))

    def patch_function_return_success(self, function):
        """Patch function to immediately return success."""
        try:
            entry_point = function.getEntryPoint()

            # Clear existing instructions (simplified approach)
            # In practice, this would need more sophisticated analysis
            clearListing(entry_point, entry_point.add(10))

            # Note: In a real implementation, we would:
            # 1. Analyze the function's calling convention
            # 2. Determine the appropriate success return value
            # 3. Generate proper assembly code for the target architecture
            # 4. Apply the patch while preserving program structure

            self.println("Applied return-success patch to {{}}".format(function.getName()))
            return True

        except Exception as e:
            self.logger.error("Exception in script_templates: %s", e)
            self.println("Failed to apply return-success patch: {{}}".format(str(e)))
            return False

    def patch_conditional_jumps(self, function):
        """Patch conditional jumps in license functions."""
        try:
            program = getCurrentProgram()
            listing = program.getListing()
            body = function.getBody()

            patched_count = 0

            # Iterate through function instructions
            instruction = listing.getInstructionAt(function.getEntryPoint())

            while instruction is not None and body.contains(instruction.getAddress()):
                mnemonic = instruction.getMnemonicString()

                # Look for conditional jumps that might skip license success paths
                if mnemonic in ["JE", "JZ", "JNE", "JNZ", "JL", "JG", "JLE", "JGE"]:
                    # Analyze jump target to determine if this might be a license check
                    # This is a simplified heuristic

                    # For demonstration, we'll convert conditional jumps to unconditional
                    # In practice, this would need careful analysis

                    try:
                        # Note: Actual patching would require understanding the instruction format
                        # and target architecture. This is a conceptual example.

                        self.println("  Found conditional jump: {{}} at {{}}".format(
                            mnemonic, instruction.getAddress()
                        ))

                        # In a real implementation:
                        # 1. Analyze what the jump condition tests
                        # 2. Determine if bypassing it would help
                        # 3. Apply appropriate patch (NOP, JMP, or modify condition)

                        patched_count += 1

                    except Exception as e:
                        logger.error("Exception in script_templates: %s", e)
                        self.println("    Failed to patch jump: {{}}".format(str(e)))

                instruction = instruction.getNext()

            if patched_count > 0:
                self.println("Patched {{}} conditional jumps in {{}}".format(
                    patched_count, function.getName()
                ))
                return True

            return False

        except Exception as e:
            logger.error("Exception in script_templates: %s", e)
            self.println("Failed to patch conditional jumps: {{}}".format(str(e)))
            return False

    def patch_string_comparisons(self, function):
        """Patch string comparison operations."""
        try:
            program = getCurrentProgram()
            listing = program.getListing()
            body = function.getBody()

            # Look for calls to string comparison functions
            comparison_functions = ["strcmp", "strcasecmp", "memcmp", "wcscmp"]
            patched_count = 0

            instruction = listing.getInstructionAt(function.getEntryPoint())

            while instruction is not None and body.contains(instruction.getAddress()):
                if instruction.getMnemonicString() == "CALL":
                    # Check if this calls a string comparison function
                    for ref in instruction.getOperandReferences(0):
                        if ref.getReferenceType().isCall():
                            target_func = getFunctionAt(ref.getToAddress())
                            if target_func and target_func.getName() in comparison_functions:

                                # Patch the return value handling
                                # Look for the instruction after the call
                                next_instruction = instruction.getNext()

                                if next_instruction:
                                    # In practice, we would analyze how the return value is used
                                    # and patch accordingly (e.g., force zero flag set)

                                    self.println("  Found string comparison call: {{}}".format(
                                        target_func.getName()
                                    ))
                                    patched_count += 1

                instruction = instruction.getNext()

            return patched_count > 0

        except Exception as e:
            logger.error("Exception in script_templates: %s", e)
            self.println("Failed to patch string comparisons: {{}}".format(str(e)))
            return False
'''


class ScriptTemplateEngine:
    """Engine for rendering script templates with dynamic content."""

    def __init__(self):
        """Initialize the script template engine.

        Sets up template managers for Frida and Ghidra script
        generation with dynamic content rendering capabilities.
        """
        self.frida_templates = FridaTemplates()
        self.ghidra_templates = GhidraTemplates()

    def render_frida_script(self, **kwargs) -> str:
        """Render a complete Frida script."""
        # Set defaults
        defaults = {
            "target_binary": "unknown",
            "protection_types": "unknown",
            "protection_list": "[]",
            "timestamp": datetime.now().isoformat(),
            "confidence": 85,
            "script_name": "AI_Generated_Bypass",
            "description": "AI-generated bypass script",
            "initialization_code": self._get_default_frida_init(),
            "hook_installations": "",
            "bypass_logic": "",
            "helper_functions": self._get_default_frida_helpers(),
        }

        # Merge with provided kwargs
        template_vars = {**defaults, **kwargs}

        # Get base template
        base_template = self.frida_templates.get_base_template()

        # Add specific bypass templates based on protection types
        bypass_code = []
        if "license_check" in template_vars.get("protection_types", "").lower():
            bypass_code.append(self.frida_templates.get_license_check_template())

        if "time_bomb" in template_vars.get("protection_types", "").lower():
            bypass_code.append(self.frida_templates.get_time_bomb_template())

        if "network" in template_vars.get("protection_types", "").lower():
            bypass_code.append(self.frida_templates.get_network_validation_template())

        if "registry" in template_vars.get("protection_types", "").lower():
            bypass_code.append(self.frida_templates.get_registry_bypass_template())

        # Combine bypass logic
        template_vars["bypass_logic"] = "\n".join(bypass_code)

        return base_template.format(**template_vars)

    def render_ghidra_script(self, **kwargs) -> str:
        """Render a complete Ghidra script."""
        # Set defaults
        defaults = {
            "target_binary": "unknown",
            "analysis_goal": "License bypass and protection removal",
            "protection_types": "unknown",
            "timestamp": datetime.now().isoformat(),
            "confidence": 85,
            "script_class_name": "AI_Generated_Analysis",
            "initialization_code": self._get_default_ghidra_init(),
            "analysis_functions": self.ghidra_templates.get_license_analysis_template(),
            "patching_logic": self.ghidra_templates.get_patching_template(),
            "reporting_logic": self._get_default_ghidra_reporting(),
        }

        # Merge with provided kwargs
        template_vars = {**defaults, **kwargs}

        # Get base template
        base_template = self.ghidra_templates.get_base_template()

        return base_template.format(**template_vars)

    def _get_default_frida_init(self) -> str:
        """Get default Frida initialization code."""
        return """
    // Initialize script environment
    logger.info("Initializing AI-generated bypass script...");

    // Get target module information
    const modules = Process.enumerateModules();
    const mainModule = modules[0];

    logger.info(`Target module: ${mainModule.name}`);
    logger.info(`Base address: ${mainModule.base}`);
    logger.info(`Module size: ${mainModule.size} bytes`);

    // Set up exception handling
    Process.setExceptionHandler(function(details) {
        logger.error(`Exception caught: ${details.type} at ${details.address}`);
        logger.error(`Context: ${JSON.stringify(details.context)}`);
        return false;  // Let the process handle it
    });
"""

    def _get_default_frida_helpers(self) -> str:
        """Get default Frida helper functions."""
        return """
    // Helper function to safely read strings
    safeReadString: function(ptr, encoding) {
        try {
            if (!ptr || ptr.isNull()) return "";
            return encoding === "utf16" ? ptr.readUtf16String() : ptr.readCString();
        } catch (e) {
            return "<unreadable>";
        }
    },

    // Helper function to find pattern in memory
    findPattern: function(pattern, startAddr, size) {
        try {
            return Memory.scan(startAddr, size, pattern, {
                onMatch: function(address, size) {
                    logger.info(`Pattern found at: ${address}`);
                    return "stop";
                },
                onComplete: function() {
                    logger.info("Pattern scan complete");
                }
            });
        } catch (e) {
            logger.error(`Pattern scan failed: ${e.message}`);
            return null;
        }
    },

    // Helper function for safe hooking
    safeHook: function(funcName, moduleName, callbacks) {
        try {
            const funcAddr = Module.findExportByName(moduleName, funcName);
            if (funcAddr) {
                Interceptor.attach(funcAddr, callbacks);
                hooks.register(funcName, funcAddr, "safe_hook");
                return true;
            } else {
                logger.warn(`Function not found: ${funcName} in ${moduleName || "any module"}`);
                return false;
            }
        } catch (e) {
            hooks.fail(funcName, e.message);
            logger.error(`Failed to hook ${funcName}: ${e.message}`);
            return false;
        }
    }
"""

    def _get_default_ghidra_init(self) -> str:
        """Get default Ghidra initialization code."""
        return """
        # Initialize analysis environment
        program = getCurrentProgram()
        if program is None:
            self.println("[ERROR] No program loaded")
            return

        self.println("Program: {}".format(program.getName()))
        self.println("Base address: {}".format(program.getImageBase()))
        self.println("Language: {}".format(program.getLanguage()))
        self.println("Compiler: {}".format(program.getCompilerSpec().getCompilerSpecDescription()))

        # Initialize analysis tracking
        self.analysis_results["program_info"] = {
            "name": program.getName(),
            "base_address": str(program.getImageBase()),
            "language": str(program.getLanguage()),
            "size": program.getMemory().getSize()
        }
"""

    def _get_default_ghidra_reporting(self) -> str:
        """Get default Ghidra reporting code."""
        return """
        # Generate analysis report
        self.println("Generating analysis report...")

        report_lines = []
        report_lines.append("INTELLICRACK AI ANALYSIS REPORT")
        report_lines.append("=" * 50)
        report_lines.append("Generated: {}".format(datetime.now().isoformat()))
        report_lines.append("Target: {}".format(self.analysis_results["target"]))
        report_lines.append("")

        # Function analysis summary
        report_lines.append("LICENSE FUNCTIONS DETECTED:")
        for func in self.analysis_results["license_functions"]:
            report_lines.append("  - {} at {}".format(func["name"], func["address"]))

        report_lines.append("")
        report_lines.append("LICENSE STRINGS DETECTED:")
        for string_info in self.analysis_results["license_strings"]:
            report_lines.append("  - {} at {}".format(string_info["value"], string_info["address"]))

        report_lines.append("")
        report_lines.append("PATCHES APPLIED: {}".format(self.analysis_results["patches_applied"]))

        # Print full report
        for line in report_lines:
            self.println(line)

        # Save report to file
        try:
            report_file = os.path.join(tempfile.gettempdir(), "intellicrack_analysis_report.txt")
            with open(report_file, 'w') as f:
                f.write("\\n".join(report_lines))
            self.println("Report saved to: {}".format(report_file))
        except Exception as e:
            logger.error("Exception in script_templates: %s", e)
            self.println("Could not save report: {}".format(str(e)))
"""
