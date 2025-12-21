"""Script Generation Tool for LLM Integration

Provides AI models with the ability to generate Frida and Ghidra scripts.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any, Dict, List

from ...utils.logger import get_logger

logger = get_logger(__name__)


class ScriptGenerationTool:
    """LLM tool for generating analysis scripts"""

    frida_templates: dict[str, str]
    ghidra_templates: dict[str, str]

    def __init__(self) -> None:
        """Initialize the script generation tool.

        Sets up the AI-powered script generation system for creating Frida
        and Ghidra analysis scripts. Loads template libraries and configures
        generation parameters for automated reverse engineering workflows.
        """
        self.frida_templates = self._load_frida_templates()
        self.ghidra_templates = self._load_ghidra_templates()

    def _load_frida_templates(self) -> dict[str, str]:
        """Load Frida script templates"""
        return {
            "hook_function": """// Hook function: {function_name}
Java.perform(function() {{
    var targetClass = Java.use("{class_name}");
    targetClass.{function_name}.implementation = function({args}) {{
        console.log("[*] {function_name} called");
        {log_args}
        var result = this.{function_name}({args});
        console.log("[*] {function_name} returned: " + result);
        return result;
    }};
}});""",
            "trace_api": """// Trace API calls
Interceptor.attach(Module.findExportByName({module}, "{function}"), {{
    onEnter: function(args) {{
        console.log("[+] {function} called");
        {arg_logging}
    }},
    onLeave: function(retval) {{
        console.log("[+] {function} returned: " + retval);
    }}
}});""",
            "bypass_protection": """// Bypass {protection_type} protection
var bypass_{protection_type} = function() {{
    {bypass_code}
}};

// Execute bypass
setImmediate(bypass_{protection_type});""",
            "memory_patch": """// Patch memory at address
var addr = ptr("{address}");
Memory.protect(addr, {size}, 'rwx');
{patch_code}
console.log("[*] Memory patched at " + addr);""",
            "ssl_pinning_bypass": """// SSL Pinning Bypass
Java.perform(function() {{
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');

    ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {{
        console.log('[*] Bypassing SSL Pinning');
        return array_list.$new();
    }};
}});""",
        }

    def _load_ghidra_templates(self) -> dict[str, str]:
        """Load Ghidra script templates"""
        return {
            "analyze_functions": '''# Analyze functions in binary
# @author LLM
# @category Analysis

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType

def analyze_functions():
    """Analyze all functions in the program"""
    fm = currentProgram.getFunctionManager()
    functions = fm.getFunctions(True)

    print("Analyzing functions...")
    for func in functions:
        print(f"Function: {{func.getName()}} at {{func.getEntryPoint()}}")
        {analysis_code}

analyze_functions()''',
            "patch_bytes": '''# Patch bytes at address
# @author LLM
# @category Patching

def patch_at_address(address, patch_bytes):
    """Patch bytes at specified address"""
    addr = toAddr(address)

    # Start transaction
    trans_id = currentProgram.startTransaction("Patch at {{}}".format(address))

    try:
        # Write patch bytes
        currentProgram.getMemory().setBytes(addr, patch_bytes)
        print("[+] Patched {{}} bytes at {{}}".format(len(patch_bytes), address))

        # Commit transaction
        currentProgram.endTransaction(trans_id, True)
    except Exception as e:
        print("[-] Patch failed: {{}}".format(e))
        currentProgram.endTransaction(trans_id, False)

# Apply patches
{patch_calls}''',
            "find_crypto": '''# Find cryptographic functions
# @author LLM
# @category Crypto

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def find_crypto_functions():
    """Find potential cryptographic functions"""
    crypto_indicators = ["crypt", "aes", "des", "rsa", "sha", "md5", "hash", "cipher"]

    fm = currentProgram.getFunctionManager()
    functions = fm.getFunctions(True)

    crypto_funcs = []

    for func in functions:
        name = func.getName().lower()
        if any(indicator in name for indicator in crypto_indicators):
            crypto_funcs.append(func)
            print(f"[+] Crypto function found: {{func.getName()}} at {{func.getEntryPoint()}}")

    return crypto_funcs

# Run analysis
crypto_functions = find_crypto_functions()
print(f"\\nFound {{len(crypto_functions)}} potential crypto functions")''',
            "deobfuscate": '''# Deobfuscate strings
# @author LLM
# @category Deobfuscation

def deobfuscate_strings():
    """Deobfuscate strings in the binary"""
    listing = currentProgram.getListing()

    # Find all strings
    strings = []
    data_iter = listing.getDefinedData(True)

    for data in data_iter:
        if data.hasStringValue():
            strings.append({
                'address': data.getAddress(),
                'value': data.getValue(),
                'references': data.getReferenceIteratorTo()
            })

    print(f"Found {{len(strings)}} strings to analyze")

    # Deobfuscation logic
    {deobfuscation_code}

deobfuscate_strings()''',
        }

    def get_tool_definition(self) -> dict[str, Any]:
        """Get tool definition for LLM registration"""
        return {
            "name": "script_generation",
            "description": "Generate Frida or Ghidra scripts for binary analysis and manipulation",
            "parameters": {
                "type": "object",
                "properties": {
                    "script_type": {
                        "type": "string",
                        "enum": ["frida", "ghidra"],
                        "description": "Type of script to generate",
                    },
                    "target": {"type": "string", "description": "Target binary or process name"},
                    "task": {"type": "string", "description": "Task description for the script"},
                    "protection_info": {
                        "type": "object",
                        "description": "Optional protection information from DIE analysis",
                    },
                    "custom_requirements": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional custom requirements for the script",
                    },
                },
                "required": ["script_type", "target", "task"],
            },
        }

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        """Execute script generation"""
        script_type = kwargs.get("script_type", "")
        target = kwargs.get("target", "")
        task = kwargs.get("task", "")
        protection_info: dict[str, Any] = kwargs.get("protection_info", {})
        custom_requirements: list[str] = kwargs.get("custom_requirements", [])

        try:
            if script_type == "frida":
                script = self._generate_frida_script(str(target), str(task), protection_info, custom_requirements)
            elif script_type == "ghidra":
                script = self._generate_ghidra_script(str(target), str(task), protection_info, custom_requirements)
            else:
                return {"success": False, "error": f"Unknown script type: {script_type}"}

            return {
                "success": True,
                "script_type": script_type,
                "target": target,
                "task": task,
                "script": script,
                "language": "javascript" if script_type == "frida" else "python",
            }

        except Exception as e:
            logger.error("Script generation error: %s", e, exc_info=True)
            return {"success": False, "error": str(e)}

    def _generate_frida_script(self, target: str, task: str, protection_info: dict[str, Any], requirements: list[str]) -> str:
        """Generate Frida script"""
        task_lower = task.lower()

        # Determine script type based on task
        if "hook" in task_lower:
            return self._generate_frida_hook(target, task, protection_info, requirements)
        elif "trace" in task_lower:
            return self._generate_frida_trace(target, task, protection_info, requirements)
        elif "bypass" in task_lower:
            return self._generate_frida_bypass(target, task, protection_info, requirements)
        elif "patch" in task_lower:
            return self._generate_frida_patch(target, task, protection_info, requirements)
        elif "ssl" in task_lower or "pinning" in task_lower:
            return self.frida_templates["ssl_pinning_bypass"]
        else:
            return self._generate_frida_custom(target, task, protection_info, requirements)

    def _generate_frida_hook(self, target: str, task: str, protection_info: dict[str, Any], requirements: list[str]) -> str:
        """Generate Frida hook script based on detected protections"""
        script_parts = [f"// Frida Hook Script for {target}", f"// Task: {task}"]

        if protection_info:
            script_parts.append(f"// Detected protections: {', '.join(protection_info.keys())}")
        script_parts.append("// Generated by Intellicrack LLM Tool\n")

        # Generate protection-specific hooks based on protection_info
        if protection_info:
            for protection_type, details in protection_info.items():
                if protection_type.lower() in ["vmprotect", "themida", "upx", "aspack"]:
                    script_parts.extend(
                        (
                            f"// Hooks for {protection_type} protection",
                            f"// Details: {details}",
                            self._generate_packer_hooks(protection_type),
                        )
                    )
                elif protection_type.lower() in ["licensing", "trial", "serial"]:
                    script_parts.extend(
                        (
                            f"// License/trial bypass hooks for {protection_type}",
                            self._generate_license_hooks(details),
                        )
                    )
                elif protection_type.lower() in ["anti_debug", "anti_vm"]:
                    script_parts.extend(
                        (
                            f"// Anti-analysis bypass for {protection_type}",
                            self._generate_anti_analysis_hooks(protection_type),
                        )
                    )
        # Determine if Java or native
        if ".apk" in target.lower() or "android" in task.lower():
            # Java hook
            script_parts.append(
                self.frida_templates["hook_function"].format(
                    class_name="com.example.TargetClass",
                    function_name="targetMethod",
                    args="arg1, arg2",
                    log_args="console.log('arg1: ' + arg1 + ', arg2: ' + arg2);",
                )
            )
        else:
            # Native hook - target specific functions based on protection info
            target_functions = self._get_target_functions_from_protection(protection_info)

            script_parts.append(f"""// Hook native functions based on protection analysis
var targetModule = Process.enumerateModules().filter(function(m) {{
    return m.name.toLowerCase().indexOf('{target.lower()}') !== -1;
}})[0];

if (targetModule) {{
    var exports = targetModule.enumerateExports();
    var targetFunctions = {target_functions};

    exports.forEach(function(exp) {{
        var shouldHook = targetFunctions.some(func => exp.name.toLowerCase().indexOf(func) !== -1);
        if (shouldHook) {{
            console.log('[*] Hooking: ' + exp.name + ' at ' + exp.address);
            Interceptor.attach(exp.address, {{
                onEnter: function(args) {{
                    console.log('[+] ' + exp.name + ' called');
                    this.context = {{
                        arg0: args[0],
                        arg1: args[1]
                    }};
                }},
                onLeave: function(retval) {{
                    console.log('[+] ' + exp.name + ' returned: ' + retval);
                    // Force return true for license checks
                    if (exp.name.toLowerCase().indexOf('check') !== -1 || exp.name.toLowerCase().indexOf('verify') !== -1) {{
                        retval.replace(1);
                    }}
                }}
            }});
        }}
    }});
}}""")

        # Add custom requirements
        if requirements:
            script_parts.append("\n// Custom requirements:")
            script_parts.extend(f"// - {req}" for req in requirements)
        return "\n".join(script_parts)

    def _generate_frida_trace(self, target: str, task: str, protection_info: dict[str, Any], requirements: list[str]) -> str:
        """Generate Frida trace script based on protection analysis"""
        script_parts = [f"// Frida Trace Script for {target}", f"// Task: {task}"]

        if protection_info:
            script_parts.append(f"// Targeting protections: {', '.join(protection_info.keys())}")
        script_parts.append("")

        # Customize API tracing based on protection_info
        apis_to_trace = self._get_apis_to_trace(protection_info)

        # Add protection-specific tracing
        if protection_info:
            for protection_type in protection_info:
                if protection_type.lower() in ["licensing", "trial", "serial"]:
                    script_parts.append("// License-related API tracing")
                    license_apis = [
                        ("kernel32.dll", "GetVolumeInformationW"),
                        ("kernel32.dll", "GetSystemInfo"),
                        ("wininet.dll", "InternetOpenW"),
                        ("wininet.dll", "HttpSendRequestW"),
                    ]
                    apis_to_trace.extend(license_apis)

                elif protection_type.lower() in ["anti_debug", "anti_vm"]:
                    script_parts.append("// Anti-analysis API tracing")
                    debug_apis = [
                        ("kernel32.dll", "IsDebuggerPresent"),
                        ("kernel32.dll", "CheckRemoteDebuggerPresent"),
                        ("ntdll.dll", "NtQueryInformationProcess"),
                        ("kernel32.dll", "GetSystemFirmwareTable"),
                    ]
                    apis_to_trace.extend(debug_apis)

                elif protection_type.lower() in ["packing", "upx", "vmprotect"]:
                    script_parts.append("// Unpacking/protection API tracing")
                    packer_apis = [
                        ("kernel32.dll", "VirtualAlloc"),
                        ("kernel32.dll", "VirtualProtect"),
                        ("kernel32.dll", "WriteProcessMemory"),
                        ("ntdll.dll", "NtMapViewOfSection"),
                    ]
                    apis_to_trace.extend(packer_apis)

        # Remove duplicates
        apis_to_trace = list(set(apis_to_trace))

        for module, func in apis_to_trace:
            script_parts.extend(
                (
                    self.frida_templates["trace_api"].format(
                        module=f'"{module}"' if module else "null",
                        function=func,
                        arg_logging="""        console.log("  arg0: " + args[0]);
        console.log("  arg1: " + args[1]);""",
                    ),
                    "",
                )
            )
        # Add custom requirement-based tracing
        if requirements:
            script_parts.append("// Custom requirement-based API tracing")
            for req in requirements:
                if any(keyword in req.lower() for keyword in ["network", "socket", "http"]):
                    apis_to_trace.extend(
                        [
                            ("ws2_32.dll", "WSAStartup"),
                            ("wininet.dll", "InternetConnectW"),
                            ("winhttp.dll", "WinHttpConnect"),
                        ]
                    )
                elif any(keyword in req.lower() for keyword in ["crypto", "encrypt", "hash"]):
                    apis_to_trace.extend(
                        [
                            ("advapi32.dll", "CryptCreateHash"),
                            ("advapi32.dll", "CryptEncrypt"),
                            ("bcrypt.dll", "BCryptGenerateSymmetricKey"),
                        ]
                    )
                elif any(keyword in req.lower() for keyword in ["registry", "reg"]):
                    apis_to_trace.extend(
                        [
                            ("advapi32.dll", "RegCreateKeyExW"),
                            ("advapi32.dll", "RegDeleteKeyExW"),
                            ("advapi32.dll", "RegSetValueExW"),
                        ]
                    )
                elif any(keyword in req.lower() for keyword in ["process", "thread"]):
                    apis_to_trace.extend(
                        [
                            ("kernel32.dll", "CreateProcessW"),
                            ("kernel32.dll", "CreateThread"),
                            ("kernel32.dll", "TerminateProcess"),
                        ]
                    )

                script_parts.append(f"// Requirement: {req}")

            # Remove duplicates after adding requirement-based APIs
            apis_to_trace = list(set(apis_to_trace))

        return "\n".join(script_parts)

    def _get_apis_to_trace(self, protection_info: dict[str, Any]) -> list[tuple[str, str]]:
        """Get list of APIs to trace based on protection info"""
        # Base APIs always traced
        base_apis = [
            ("kernel32.dll", "CreateFileW"),
            ("kernel32.dll", "ReadFile"),
            ("kernel32.dll", "WriteFile"),
            ("user32.dll", "MessageBoxW"),
        ]

        # Add protection-specific APIs
        if protection_info:
            protections = protection_info.keys()
            if any("network" in p.lower() for p in protections):
                base_apis.extend([("ws2_32.dll", "connect"), ("ws2_32.dll", "send"), ("ws2_32.dll", "recv")])
            if any("registry" in p.lower() for p in protections):
                base_apis.extend(
                    [
                        ("advapi32.dll", "RegOpenKeyExW"),
                        ("advapi32.dll", "RegQueryValueExW"),
                        ("advapi32.dll", "RegSetValueExW"),
                    ]
                )

        return base_apis

    def _generate_frida_bypass(self, target: str, task: str, protection_info: dict[str, Any], requirements: list[str]) -> str:
        """Generate Frida bypass script"""
        script_parts = [f"// Frida Bypass Script for {target}", f"// Task: {task}\n"]

        # Check protection info
        protections = protection_info.get("protections", [])

        bypass_code_parts = []

        # Anti-debug bypass
        if any("debug" in str(p).lower() for p in protections) or "debug" in task.lower():
            bypass_code_parts.append("""    // Bypass IsDebuggerPresent
    var isDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
    Interceptor.attach(isDebuggerPresent, {
        onLeave: function(retval) {
            retval.replace(0);
        }
    });

    // Bypass CheckRemoteDebuggerPresent
    var checkRemoteDebugger = Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent");
    Interceptor.attach(checkRemoteDebugger, {
        onEnter: function(args) {
            this.pDebuggerPresent = args[1];
        },
        onLeave: function(retval) {
            this.pDebuggerPresent.writeU8(0);
            retval.replace(1);
        }
    });""")

        # License check bypass
        if any("license" in str(p).lower() for p in protections) or "license" in task.lower():
            bypass_code_parts.append("""    // Bypass license checks
    var modules = Process.enumerateModules();
    modules.forEach(function(module) {
        var exports = module.enumerateExports();
        exports.forEach(function(exp) {
            if (exp.name.toLowerCase().indexOf('license') !== -1 ||
                exp.name.toLowerCase().indexOf('registration') !== -1 ||
                exp.name.toLowerCase().indexOf('validate') !== -1) {
                console.log('[*] Patching: ' + exp.name);
                Interceptor.attach(exp.address, {
                    onLeave: function(retval) {
                        retval.replace(1); // Return success
                    }
                });
            }
        });
    });""")

        # Add requirement-specific bypasses
        if requirements:
            script_parts.append("\n// Custom requirement-based bypasses")
            for req in requirements:
                if any(keyword in req.lower() for keyword in ["trial", "demo", "evaluation"]):
                    bypass_code_parts.append("""    // Bypass trial/demo restrictions
    var trialFunctions = ["GetTrialDays", "IsTrialExpired", "CheckDemoMode"];
    trialFunctions.forEach(function(funcName) {
        var func = Module.findExportByName(null, funcName);
        if (func) {
            Interceptor.attach(func, {
                onLeave: function(retval) {
                    retval.replace(0); // Return unlimited/not expired
                }
            });
        }
    });""")
                elif any(keyword in req.lower() for keyword in ["nag", "reminder", "popup"]):
                    bypass_code_parts.append("""    // Bypass nag screens and popups
    var uiFunctions = ["MessageBoxW", "MessageBoxA", "ShowWindow"];
    uiFunctions.forEach(function(funcName) {
        var func = Module.findExportByName("user32.dll", funcName);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    if (funcName.indexOf("MessageBox") !== -1) {
                        var message = args[1].readUtf16String();
                        if (message && (message.toLowerCase().indexOf("trial") !== -1 ||
                                      message.toLowerCase().indexOf("register") !== -1)) {
                            console.log("[*] Suppressing nag popup: " + message);
                            this.replace = true;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.replace) {
                        retval.replace(1); // IDOK
                    }
                }
            });
        }
    });""")
                elif any(keyword in req.lower() for keyword in ["time", "date", "expiry"]):
                    bypass_code_parts.append("""    // Bypass time/date based restrictions
    var timeFunctions = ["GetSystemTime", "GetLocalTime", "GetFileTime"];
    timeFunctions.forEach(function(funcName) {
        var func = Module.findExportByName("kernel32.dll", funcName);
        if (func) {
            Interceptor.attach(func, {
                onLeave: function(retval) {
                    console.log("[*] Intercepted time function: " + funcName);
                    // Could modify time here if needed
                }
            });
        }
    });""")

                script_parts.append(f"// Custom requirement: {req}")

        if bypass_code_parts:
            script_parts.append(
                self.frida_templates["bypass_protection"].format(protection_type="generic", bypass_code="\n".join(bypass_code_parts))
            )
        else:
            # Generic bypass
            script_parts.append("""// Generic protection bypass
var targetAddr = ptr("0x00401000"); // Update with actual address
Interceptor.attach(targetAddr, {
    onEnter: function(args) {
        console.log("[*] Protection check intercepted");
    },
    onLeave: function(retval) {
        console.log("[*] Bypassing protection check");
        retval.replace(1); // Force success
    }
});""")

        return "\n".join(script_parts)

    def _generate_frida_patch(self, target: str, task: str, protection_info: dict[str, Any], requirements: list[str]) -> str:
        """Generate Frida memory patch script"""
        script_parts = [
            f"// Frida Memory Patch Script for {target}",
            f"// Task: {task}",
        ]

        if protection_info:
            script_parts.append(f"// Target protections: {', '.join(protection_info.keys())}")
        script_parts.append("")

        # Generate protection-specific patches based on protection_info
        patch_code_parts = []

        if protection_info:
            for protection_type in protection_info:
                if protection_type.lower() in ["anti_debug", "debugger"]:
                    patch_code_parts.append("""    // Patch anti-debug checks
    var antiDebugOpcodes = [0x33, 0xC0, 0xC3]; // xor eax, eax; ret
    antiDebugOpcodes.forEach(function(opcode, index) {
        addr.add(index).writeU8(opcode);
    });
    console.log("[*] Patched anti-debug at " + addr);""")

                elif protection_type.lower() in ["license", "trial", "registration"]:
                    patch_code_parts.append("""    // Patch license/trial checks
    var licenseBypassOpcodes = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]; // mov eax, 1; ret
    licenseBypassOpcodes.forEach(function(opcode, index) {
        addr.add(index).writeU8(opcode);
    });
    console.log("[*] Patched license check at " + addr);""")

                elif protection_type.lower() in ["integrity", "checksum", "crc"]:
                    patch_code_parts.append("""    // Patch integrity/checksum verification
    var integrityBypassOpcodes = [0x90, 0x90, 0x90, 0x90, 0x90]; // NOP sled
    integrityBypassOpcodes.forEach(function(opcode, index) {
        addr.add(index).writeU8(opcode);
    });
    console.log("[*] Patched integrity check at " + addr);""")

        # Add requirements-based patches
        if requirements:
            script_parts.append("// Custom requirement-based patches")
            for req in requirements:
                if any(keyword in req.lower() for keyword in ["jmp", "jump", "branch"]):
                    patch_code_parts.append("""    // Patch conditional jumps (requirement-based)
    var jumpPatchOpcodes = [0xEB]; // JMP short (unconditional)
    jumpPatchOpcodes.forEach(function(opcode, index) {
        addr.add(index).writeU8(opcode);
    });""")
                elif any(keyword in req.lower() for keyword in ["call", "function"]):
                    patch_code_parts.append("""    // Patch function calls (requirement-based)
    var callPatchOpcodes = [0x90, 0x90, 0x90, 0x90, 0x90]; // NOP out call
    callPatchOpcodes.forEach(function(opcode, index) {
        addr.add(index).writeU8(opcode);
    });""")

                script_parts.append(f"// Requirement: {req}")

        # Use combined patch code or default
        if patch_code_parts:
            patch_code = "\n".join(patch_code_parts)
        else:
            # Default patch code
            patch_code = """    var opcodes = [0x90, 0x90, 0x90, 0x90, 0x90]; // NOP sled
    opcodes.forEach(function(opcode, index) {
        addr.add(index).writeU8(opcode);
    });"""

        script_parts.append(
            self.frida_templates["memory_patch"].format(
                address="0x00401000",  # Example address
                size=5,
                patch_code=patch_code,
            )
        )

        return "\n".join(script_parts)

    def _generate_frida_custom(self, target: str, task: str, protection_info: dict[str, Any], requirements: list[str]) -> str:
        """Generate custom Frida script"""
        script_parts = []

        script_parts.append(f"// Custom Frida Script for {target}")
        script_parts.append(f"// Task: {task}")
        if protection_info:
            script_parts.append(f"// Protection analysis: {', '.join(protection_info.keys())}")
        script_parts.append("// Generated by Intellicrack LLM Tool\n")

        # Build protection-aware patterns based on protection_info
        patterns = ["check", "verify", "validate", "auth", "license"]

        if protection_info:
            for protection_type in protection_info.keys():
                if protection_type.lower() in ["anti_debug", "debugger"]:
                    patterns.extend(["debug", "debugger", "isdebuggerpresent"])
                elif protection_type.lower() in ["anti_vm", "virtual"]:
                    patterns.extend(["vm", "virtual", "vbox", "vmware"])
                elif protection_type.lower() in ["packing", "upx", "compression"]:
                    patterns.extend(["unpack", "decompress", "expand"])
                elif protection_type.lower() in ["encryption", "crypto"]:
                    patterns.extend(["crypt", "encrypt", "decrypt", "cipher"])
                elif protection_type.lower() in ["obfuscation", "obfuscate"]:
                    patterns.extend(["obfus", "scramble", "encode"])

        # Remove duplicates and convert to JavaScript array format
        patterns = list(set(patterns))

        # Add requirements-based patterns
        if requirements:
            for req in requirements:
                if any(keyword in req.lower() for keyword in ["network", "http", "socket"]):
                    patterns.extend(["connect", "send", "recv", "http", "socket"])
                elif any(keyword in req.lower() for keyword in ["file", "io", "disk"]):
                    patterns.extend(["file", "read", "write", "open", "close"])
                elif any(keyword in req.lower() for keyword in ["memory", "alloc", "heap"]):
                    patterns.extend(["alloc", "malloc", "free", "heap"])

        patterns_js = str(patterns).replace("'", '"')

        # Basic structure with protection-aware patterns
        script_parts.append(f"""// Main script logic
console.log("[*] Script loaded for: " + Process.enumerateModules()[0].name);
console.log("[*] Protection-aware patterns: {patterns_js}");

// Enumerate modules
Process.enumerateModules().forEach(function(module) {{
    console.log("Module: " + module.name + " at " + module.base);
}});

// Your custom code here
// Based on task: {task}
// Protection info: {protection_info}

// Protection-aware function discovery and hooking
var patterns = {patterns_js};
Process.enumerateModules().forEach(function(module) {{
    if (module.name.indexOf("{target}") !== -1) {{
        module.enumerateExports().forEach(function(exp) {{
            patterns.forEach(function(pattern) {{
                if (exp.name.toLowerCase().indexOf(pattern) !== -1) {{
                    console.log("[+] Found protection-relevant function: " + exp.name + " at " + exp.address);
                    // Add your protection-specific hook here
                    Interceptor.attach(exp.address, {{
                        onEnter: function(args) {{
                            console.log("[*] Entered: " + exp.name);
                        }},
                        onLeave: function(retval) {{
                            console.log("[*] Left: " + exp.name + " with return: " + retval);
                        }}
                    }});
                }}
            }});
        }});
    }}
}});""")

        return "\n".join(script_parts)

    def _generate_ghidra_script(self, target: str, task: str, protection_info: dict[str, Any], requirements: list[str]) -> str:
        """Generate Ghidra script"""
        # Import here to avoid circular imports
        from ...scripting.ghidra_generator import GhidraScriptGenerator

        generator = GhidraScriptGenerator()

        # Build context
        context = {
            "target": target,
            "task": task,
            "protections": protection_info.get("protections", []),
            "file_type": protection_info.get("file_type", "PE"),
            "requirements": requirements,
        }

        # Generate script based on task
        if "analyze" in task.lower():
            return str(generator.generate_analysis_script(context))
        elif "patch" in task.lower():
            return str(generator.generate_patch_script(context))
        elif "deobfuscate" in task.lower():
            return str(generator.generate_deobfuscation_script(context))
        else:
            return str(generator.generate_custom_script(context))

    def _generate_packer_hooks(self, protection_type: str) -> str:
        """Generate hooks specific to packers/protectors"""
        if protection_type.lower() == "upx":
            return """
// UPX unpacking hooks
var upxEntryPoint = Module.findBaseAddress("main_module").add(0x1000);
Interceptor.attach(upxEntryPoint, {
    onEnter: function(args) {
        console.log("[+] UPX entry point reached");
        // Monitor for OEP jump
        this.context = args[0];
    },
    onLeave: function(retval) {
        console.log("[+] UPX unpacking complete, OEP likely at: " + retval);
    }
});

// Hook decompression routine
var decompress = Module.findExportByName(null, "decompress");
if (decompress) {
    Interceptor.attach(decompress, {
        onEnter: function(args) {
            console.log("[+] UPX decompression started");
        }
    });
}"""
        elif protection_type.lower() == "vmprotect":
            return """
// VMProtect VM entry hooks
var vmEntryPoints = Module.enumerateSymbols().filter(s => s.name.indexOf("vm_") !== -1);
vmEntryPoints.forEach(function(symbol) {
    Interceptor.attach(symbol.address, {
        onEnter: function(args) {
            console.log("[+] VMProtect VM entry: " + symbol.name);
            // Log VM context
            this.vmContext = args[0];
        },
        onLeave: function(retval) {
            console.log("[+] VM handler executed, result: " + retval);
        }
    });
});

// Hook virtualized code patterns
var vmPatterns = ["push", "pop", "mov", "jmp"];
Process.enumerateRanges('r-x').forEach(function(range) {
    Memory.scan(range.base, range.size, "48 8B ?? ?? ?? ?? ?? 48 89", {
        onMatch: function(address, size) {
            console.log("[+] Found potential VM handler at: " + address);
        }
    });
});"""
        elif protection_type.lower() == "themida":
            return """
// Themida/WinLicense hooks
var themidaChecks = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString"];
themidaChecks.forEach(function(funcName) {
    var funcAddr = Module.findExportByName(null, funcName);
    if (funcAddr) {
        Interceptor.attach(funcAddr, {
            onLeave: function(retval) {
                console.log("[+] Bypassing Themida check: " + funcName);
                retval.replace(0);
            }
        });
    }
});

// Hook Themida VM entry
var vmEntry = Module.findBaseAddress("main_module").add(0x10000); // Common offset
Interceptor.attach(vmEntry, {
    onEnter: function(args) {
        console.log("[+] Themida VM entry detected");
    }
});

// Hook anti-dump protection
var virtualProtect = Module.findExportByName("kernel32.dll", "VirtualProtect");
Interceptor.attach(virtualProtect, {
    onEnter: function(args) {
        var protection = args[2].toInt32();
        if (protection & 0x100) { // PAGE_GUARD
            console.log("[+] Blocking Themida anti-dump");
            args[2] = ptr(0x40); // PAGE_EXECUTE_READWRITE
        }
    }
});"""
        elif protection_type.lower() == "aspack":
            return """
// ASPack unpacking hooks
var aspackOEP = null;
var virtualAlloc = Module.findExportByName("kernel32.dll", "VirtualAlloc");
Interceptor.attach(virtualAlloc, {
    onLeave: function(retval) {
        if (!retval.isNull()) {
            console.log("[+] ASPack allocated memory at: " + retval);
            // Monitor for code execution in allocated region
            Memory.protect(retval, 0x1000, 'rwx');
            aspackOEP = retval;
        }
    }
});

// Hook common ASPack patterns
var loadLibrary = Module.findExportByName("kernel32.dll", "LoadLibraryA");
Interceptor.attach(loadLibrary, {
    onEnter: function(args) {
        var lib = args[0].readCString();
        if (lib && lib.indexOf("aspack") !== -1) {
            console.log("[+] ASPack loading: " + lib);
        }
    }
});"""
        elif protection_type.lower() == "mpress":
            return """
// MPRESS unpacking hooks
var mpressDecrypt = Module.findExportByName(null, "decrypt");
if (mpressDecrypt) {
    Interceptor.attach(mpressDecrypt, {
        onEnter: function(args) {
            console.log("[+] MPRESS decryption started");
            this.encData = args[0];
            this.size = args[1].toInt32();
        },
        onLeave: function(retval) {
            console.log("[+] MPRESS decrypted " + this.size + " bytes");
        }
    });
}

// Hook MPRESS decompression
var rtlDecompressBuffer = Module.findExportByName("ntdll.dll", "RtlDecompressBuffer");
if (rtlDecompressBuffer) {
    Interceptor.attach(rtlDecompressBuffer, {
        onEnter: function(args) {
            console.log("[+] MPRESS decompression, format: " + args[0]);
        }
    });
}"""
        elif protection_type.lower() == "enigma":
            return """
// Enigma Protector hooks
var enigmaChecks = ["CheckSum", "CRC32", "VerifySignature"];
enigmaChecks.forEach(function(funcName) {
    var funcAddr = Module.findExportByName(null, funcName);
    if (funcAddr) {
        Interceptor.attach(funcAddr, {
            onLeave: function(retval) {
                console.log("[+] Bypassing Enigma check: " + funcName);
                retval.replace(1); // Return valid
            }
        });
    }
});

// Hook Enigma registration check
var regCheck = Module.findExportByName(null, "IsRegistered");
if (regCheck) {
    Interceptor.attach(regCheck, {
        onLeave: function(retval) {
            console.log("[+] Bypassing Enigma registration");
            retval.replace(1);
        }
    });
}"""
        elif protection_type.lower() == "armadillo":
            return """
// Armadillo protection hooks
var armadilloAPIs = ["GetSystemTime", "GetLocalTime", "GetTickCount"];
armadilloAPIs.forEach(function(funcName) {
    var funcAddr = Module.findExportByName("kernel32.dll", funcName);
    if (funcAddr) {
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                console.log("[+] Armadillo timing check: " + funcName);
            }
        });
    }
});

// Hook CopyMem checks
var rtlMoveMemory = Module.findExportByName("ntdll.dll", "RtlMoveMemory");
if (rtlMoveMemory) {
    Interceptor.attach(rtlMoveMemory, {
        onEnter: function(args) {
            var size = args[2].toInt32();
            if (size > 0x10000) { // Large memory moves indicate unpacking
                console.log("[+] Armadillo unpacking detected, size: " + size);
            }
        }
    });
}"""
        elif protection_type.lower() == "obsidium":
            return """
// Obsidium protection hooks
var obsidiumChecks = Module.enumerateExports("obsidium.dll");
obsidiumChecks.forEach(function(exp) {
    if (exp.name.indexOf("Check") !== -1 || exp.name.indexOf("Verify") !== -1) {
        Interceptor.attach(exp.address, {
            onLeave: function(retval) {
                console.log("[+] Bypassing Obsidium: " + exp.name);
                retval.replace(1);
            }
        });
    }
});

// Hook Obsidium anti-debug
var ntQueryInfoProcess = Module.findExportByName("ntdll.dll", "NtQueryInformationProcess");
Interceptor.attach(ntQueryInfoProcess, {
    onEnter: function(args) {
        if (args[1].toInt32() === 7) { // ProcessDebugPort
            this.bypass = true;
        }
    },
    onLeave: function(retval) {
        if (this.bypass) {
            console.log("[+] Bypassing Obsidium debug check");
            retval.replace(0);
        }
    }
});"""
        else:
            return f"""
// Generic packer hooks for {protection_type}
var suspiciousFuncs = ["unpack", "decrypt", "decompress", "decode"];
Process.enumerateModules().forEach(function(module) {{
    module.enumerateExports().forEach(function(exp) {{
        suspiciousFuncs.forEach(function(pattern) {{
            if (exp.name.toLowerCase().indexOf(pattern) !== -1) {{
                console.log("[+] Found packer function: " + exp.name);
                Interceptor.attach(exp.address, {{
                    onEnter: function(args) {{
                        console.log("[+] Packer function called: " + exp.name);
                    }},
                    onLeave: function(retval) {{
                        console.log("[+] Packer function completed");
                    }}
                }});
            }}
        }});
    }});
}});

// Monitor memory allocations for unpacking
var virtualAlloc = Module.findExportByName("kernel32.dll", "VirtualAlloc");
if (virtualAlloc) {{
    Interceptor.attach(virtualAlloc, {{
        onLeave: function(retval) {{
            if (!retval.isNull()) {{
                var size = this.context.r8 || this.context.edx;
                console.log("[+] Memory allocated for unpacking at: " + retval + " size: " + size);
            }}
        }}
    }});
}}"""

    def _generate_license_hooks(self, details: str) -> str:
        """Generate license/trial bypass hooks based on protection details"""
        # Parse details to customize license hooks
        base_functions = ["CheckLicense", "VerifySerial", "ValidateKey", "IsTrialExpired"]

        # Add detail-specific functions if details contain hints
        if details and isinstance(details, str):
            details_lower = details.lower()
            if "trial" in details_lower:
                base_functions.extend(["GetTrialDays", "IsTrialValid", "TrialCheck"])
            if "serial" in details_lower or "key" in details_lower:
                base_functions.extend(["ValidateSerial", "CheckSerialKey", "VerifyProductKey"])
            if "online" in details_lower or "server" in details_lower:
                base_functions.extend(["ConnectLicenseServer", "ValidateOnline", "CheckServerLicense"])
            if "hardware" in details_lower or "hwid" in details_lower:
                base_functions.extend(["GetHardwareID", "CheckHWID", "ValidateFingerprint"])

        # Remove duplicates
        functions_list = list(set(base_functions))
        functions_js = str(functions_list).replace("'", '"')

        return f"""
// License check bypass hooks (based on details: {details})
var licenseCheckFunctions = {functions_js};
licenseCheckFunctions.forEach(function(funcName) {{
    var funcAddr = Module.findExportByName(null, funcName);
    if (funcAddr) {{
        Interceptor.attach(funcAddr, {{
            onLeave: function(retval) {{
                console.log("[+] Bypassing license function: " + funcName + " (details: {details})");
                retval.replace(1); // Return success
            }}
        }});
    }}
}});"""

    def _generate_anti_analysis_hooks(self, protection_type: str) -> str:
        """Generate anti-analysis bypass hooks"""
        if protection_type.lower() == "anti_debug":
            return """
// Anti-debug bypass
var antiDebugFunctions = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"];
antiDebugFunctions.forEach(function(funcName) {
    var funcAddr = Module.findExportByName("kernel32.dll", funcName) || Module.findExportByName("ntdll.dll", funcName);
    if (funcAddr) {
        Interceptor.attach(funcAddr, {
            onLeave: function(retval) {
                retval.replace(0); // Return false
            }
        });
    }
});

// Additional debug flags
var peb = Process.findModuleByName("ntdll.dll").base.add(0x60);
var debugFlags = [0x68, 0x70]; // BeingDebugged, NtGlobalFlag
debugFlags.forEach(function(offset) {
    var addr = peb.add(offset);
    Memory.protect(addr, 1, 'rw-');
    addr.writeU8(0);
});"""
        elif protection_type.lower() == "anti_vm":
            return """
// Anti-VM bypass
var antiVmChecks = ["GetSystemFirmwareTable", "GetAdaptersInfo", "RegQueryValueEx"];
antiVmChecks.forEach(function(funcName) {
    var funcAddr = Module.findExportByName(null, funcName);
    if (funcAddr) {
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                console.log("[+] Blocking VM check: " + funcName);
            },
            onLeave: function(retval) {
                retval.replace(0); // Fail VM detection
            }
        });
    }
});

// Registry key spoofing for VM detection
var regQueryValueEx = Module.findExportByName("advapi32.dll", "RegQueryValueExW");
if (regQueryValueEx) {
    Interceptor.attach(regQueryValueEx, {
        onEnter: function(args) {
            var keyName = args[1].readUtf16String();
            if (keyName && (keyName.indexOf("VMware") !== -1 || keyName.indexOf("VBox") !== -1)) {
                this.shouldBlock = true;
            }
        },
        onLeave: function(retval) {
            if (this.shouldBlock) {
                retval.replace(0x2); // ERROR_FILE_NOT_FOUND
            }
        }
    });
}"""
        elif protection_type.lower() == "anti_attach":
            return """
// Anti-attach bypass
var ptrace = Module.findExportByName(null, "ptrace");
if (ptrace) {
    Interceptor.attach(ptrace, {
        onEnter: function(args) {
            if (args[0].toInt32() === 31) { // PTRACE_TRACEME
                args[0] = ptr(0); // Change to PTRACE_PEEKTEXT
            }
        },
        onLeave: function(retval) {
            retval.replace(0); // Success
        }
    });
}

// Windows anti-attach
var ntSetInformationThread = Module.findExportByName("ntdll.dll", "NtSetInformationThread");
if (ntSetInformationThread) {
    Interceptor.attach(ntSetInformationThread, {
        onEnter: function(args) {
            if (args[1].toInt32() === 0x11) { // ThreadHideFromDebugger
                console.log("[+] Blocking ThreadHideFromDebugger");
                return 0; // Skip call
            }
        }
    });
}"""
        elif protection_type.lower() == "anti_dump":
            return """
// Anti-dump bypass
var virtualProtect = Module.findExportByName("kernel32.dll", "VirtualProtect");
if (virtualProtect) {
    Interceptor.attach(virtualProtect, {
        onEnter: function(args) {
            var protection = args[2].toInt32();
            if (protection & 0x100) { // PAGE_GUARD
                console.log("[+] Blocking PAGE_GUARD protection");
                args[2] = ptr(protection & ~0x100);
            }
        }
    });
}

// Hook memory allocation to prevent anti-dump tricks
var virtualAlloc = Module.findExportByName("kernel32.dll", "VirtualAlloc");
if (virtualAlloc) {
    Interceptor.attach(virtualAlloc, {
        onEnter: function(args) {
            var protection = args[3].toInt32();
            if (protection === 0x40000000) { // SEC_NO_CHANGE
                console.log("[+] Blocking anti-dump allocation");
                args[3] = ptr(0x40); // PAGE_EXECUTE_READWRITE
            }
        }
    });
}"""
        elif protection_type.lower() == "anti_tamper":
            return """
// Anti-tamper bypass
var crcChecks = ["VerifySignature", "CheckIntegrity", "ValidateChecksum", "CalculateCRC"];
crcChecks.forEach(function(funcName) {
    var funcAddr = Module.findExportByName(null, funcName);
    if (funcAddr) {
        Interceptor.attach(funcAddr, {
            onLeave: function(retval) {
                console.log("[+] Bypassing integrity check: " + funcName);
                retval.replace(1); // Return valid
            }
        });
    }
});

// Hook common hash functions used for integrity
var hashFuncs = ["CryptCreateHash", "CryptHashData", "BCryptHashData"];
hashFuncs.forEach(function(funcName) {
    var funcAddr = Module.findExportByName(null, funcName);
    if (funcAddr) {
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                console.log("[+] Intercepting hash function: " + funcName);
            }
        });
    }
});"""
        elif protection_type.lower() == "timing_check":
            return """
// Timing check bypass
var rdtsc = Module.findExportByName(null, "__rdtsc");
var lastTime = 0;
if (rdtsc) {
    Interceptor.attach(rdtsc, {
        onLeave: function(retval) {
            if (lastTime === 0) {
                lastTime = retval.toInt32();
            } else {
                // Return consistent time delta
                retval.replace(lastTime + 1000);
                lastTime = retval.toInt32();
            }
        }
    });
}

// Hook timing functions
var timingFuncs = ["GetTickCount", "GetTickCount64", "QueryPerformanceCounter"];
timingFuncs.forEach(function(funcName) {
    var funcAddr = Module.findExportByName("kernel32.dll", funcName);
    if (funcAddr) {
        var baseTime = 0;
        Interceptor.attach(funcAddr, {
            onLeave: function(retval) {
                if (baseTime === 0) {
                    baseTime = retval.toInt32();
                }
                // Return predictable timing
                retval.replace(baseTime + 1000);
            }
        });
    }
});"""
        elif protection_type.lower() == "anti_sandbox":
            return """
// Anti-sandbox bypass
var sandboxFiles = ["sbiedll.dll", "dbghelp.dll", "api_log.dll", "dir_watch.dll"];
var getModuleHandle = Module.findExportByName("kernel32.dll", "GetModuleHandleA");
if (getModuleHandle) {
    Interceptor.attach(getModuleHandle, {
        onEnter: function(args) {
            if (args[0].isNull()) return;
            var moduleName = args[0].readCString();
            if (sandboxFiles.some(f => moduleName.toLowerCase().indexOf(f) !== -1)) {
                console.log("[+] Blocking sandbox DLL check: " + moduleName);
                this.shouldFail = true;
            }
        },
        onLeave: function(retval) {
            if (this.shouldFail) {
                retval.replace(0); // Module not found
            }
        }
    });
}

// Hook process enumeration
var createToolhelp32Snapshot = Module.findExportByName("kernel32.dll", "CreateToolhelp32Snapshot");
if (createToolhelp32Snapshot) {
    Interceptor.attach(createToolhelp32Snapshot, {
        onEnter: function(args) {
            if (args[0].toInt32() & 0x2) { // TH32CS_SNAPPROCESS
                console.log("[+] Intercepting process enumeration");
            }
        }
    });
}"""
        else:
            return f"""
// Generic anti-analysis hooks for {protection_type}
var suspiciousFuncs = ["detect", "check", "verify", "protect", "guard"];
Process.enumerateModules().forEach(function(module) {{
    module.enumerateExports().forEach(function(exp) {{
        suspiciousFuncs.forEach(function(pattern) {{
            if (exp.name.toLowerCase().indexOf(pattern) !== -1 &&
                exp.name.toLowerCase().indexOf("{protection_type.lower().replace("_", "")}") !== -1) {{
                console.log("[+] Found protection function: " + exp.name);
                Interceptor.attach(exp.address, {{
                    onLeave: function(retval) {{
                        console.log("[+] Bypassing: " + exp.name);
                        retval.replace(0); // Bypass protection
                    }}
                }});
            }}
        }});
    }});
}});"""

    def _get_target_functions_from_protection(self, protection_info: dict[str, Any]) -> str:
        """Get JavaScript array of target function names based on protection info"""
        target_funcs = ["check", "verify", "validate", "license", "trial", "serial"]

        if protection_info:
            for protection_type in protection_info:
                if "license" in protection_type.lower():
                    target_funcs.extend(["getlicense", "checklicense", "validatelicense"])
                elif "trial" in protection_type.lower():
                    target_funcs.extend(["istrial", "trialexpired", "daysleft"])
                elif "debug" in protection_type.lower():
                    target_funcs.extend(["isdebugger", "debugger", "antidebug"])
                elif "vm" in protection_type.lower():
                    target_funcs.extend(["vm", "virtual", "sandbox"])

        return str(target_funcs).replace("'", '"')  # Convert to JavaScript array format


def create_script_tool() -> ScriptGenerationTool:
    """Factory function to create script generation tool"""
    return ScriptGenerationTool()
