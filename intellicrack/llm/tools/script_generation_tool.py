"""
Script Generation Tool for LLM Integration

Provides AI models with the ability to generate Frida and Ghidra scripts.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any, Dict, List

from ...utils.logger import get_logger

logger = get_logger(__name__)


class ScriptGenerationTool:
    """LLM tool for generating analysis scripts"""

    def __init__(self):
        """Initialize script generation tool"""
        self.frida_templates = self._load_frida_templates()
        self.ghidra_templates = self._load_ghidra_templates()

    def _load_frida_templates(self) -> Dict[str, str]:
        """Load Frida script templates"""
        return {
            "hook_function": '''// Hook function: {function_name}
Java.perform(function() {{
    var targetClass = Java.use("{class_name}");
    targetClass.{function_name}.implementation = function({args}) {{
        console.log("[*] {function_name} called");
        {log_args}
        var result = this.{function_name}({args});
        console.log("[*] {function_name} returned: " + result);
        return result;
    }};
}});''',

            "trace_api": '''// Trace API calls
Interceptor.attach(Module.findExportByName({module}, "{function}"), {{
    onEnter: function(args) {{
        console.log("[+] {function} called");
        {arg_logging}
    }},
    onLeave: function(retval) {{
        console.log("[+] {function} returned: " + retval);
    }}
}});''',

            "bypass_protection": '''// Bypass {protection_type} protection
var bypass_{protection_type} = function() {{
    {bypass_code}
}};

// Execute bypass
setImmediate(bypass_{protection_type});''',

            "memory_patch": '''// Patch memory at address
var addr = ptr("{address}");
Memory.protect(addr, {size}, 'rwx');
{patch_code}
console.log("[*] Memory patched at " + addr);''',

            "ssl_pinning_bypass": '''// SSL Pinning Bypass
Java.perform(function() {{
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');

    ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {{
        console.log('[*] Bypassing SSL Pinning');
        return array_list.$new();
    }};
}});'''
        }

    def _load_ghidra_templates(self) -> Dict[str, str]:
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
        logger.error("Exception in script_generation_tool: %s", e)
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

deobfuscate_strings()'''
        }

    def get_tool_definition(self) -> Dict[str, Any]:
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
                        "description": "Type of script to generate"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target binary or process name"
                    },
                    "task": {
                        "type": "string",
                        "description": "Task description for the script"
                    },
                    "protection_info": {
                        "type": "object",
                        "description": "Optional protection information from DIE analysis"
                    },
                    "custom_requirements": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional custom requirements for the script"
                    }
                },
                "required": ["script_type", "target", "task"]
            }
        }

    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute script generation"""
        script_type = kwargs.get("script_type")
        target = kwargs.get("target")
        task = kwargs.get("task")
        protection_info = kwargs.get("protection_info", {})
        custom_requirements = kwargs.get("custom_requirements", [])

        try:
            if script_type == "frida":
                script = self._generate_frida_script(target, task, protection_info, custom_requirements)
            elif script_type == "ghidra":
                script = self._generate_ghidra_script(target, task, protection_info, custom_requirements)
            else:
                return {
                    "success": False,
                    "error": f"Unknown script type: {script_type}"
                }

            return {
                "success": True,
                "script_type": script_type,
                "target": target,
                "task": task,
                "script": script,
                "language": "javascript" if script_type == "frida" else "python"
            }

        except Exception as e:
            logger.error(f"Script generation error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def _generate_frida_script(self, target: str, task: str, protection_info: Dict, requirements: List[str]) -> str:
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

    def _generate_frida_hook(self, target: str, task: str, protection_info: Dict, requirements: List[str]) -> str:
        """Generate Frida hook script based on detected protections"""
        script_parts = []

        # Add header with protection info
        script_parts.append(f"// Frida Hook Script for {target}")
        script_parts.append(f"// Task: {task}")
        if protection_info:
            script_parts.append(f"// Detected protections: {', '.join(protection_info.keys())}")
        script_parts.append("// Generated by Intellicrack LLM Tool\n")

        # Generate protection-specific hooks based on protection_info
        if protection_info:
            for protection_type, details in protection_info.items():
                if protection_type.lower() in ['vmprotect', 'themida', 'upx', 'aspack']:
                    script_parts.append(f"// Hooks for {protection_type} protection")
                    script_parts.append(f"// Details: {details}")
                    script_parts.append(self._generate_packer_hooks(protection_type))
                    
                elif protection_type.lower() in ['licensing', 'trial', 'serial']:
                    script_parts.append(f"// License/trial bypass hooks for {protection_type}")
                    script_parts.append(self._generate_license_hooks(details))
                    
                elif protection_type.lower() in ['anti_debug', 'anti_vm']:
                    script_parts.append(f"// Anti-analysis bypass for {protection_type}")
                    script_parts.append(self._generate_anti_analysis_hooks(protection_type))

        # Determine if Java or native
        if ".apk" in target.lower() or "android" in task.lower():
            # Java hook
            script_parts.append(self.frida_templates["hook_function"].format(
                class_name="com.example.TargetClass",
                function_name="targetMethod",
                args="arg1, arg2",
                log_args="console.log('arg1: ' + arg1 + ', arg2: ' + arg2);"
            ))
        else:
            # Native hook - target specific functions based on protection info
            target_functions = self._get_target_functions_from_protection(protection_info)
            
            script_parts.append(f'''// Hook native functions based on protection analysis
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
}}''')

        # Add custom requirements
        if requirements:
            script_parts.append("\n// Custom requirements:")
            for req in requirements:
                script_parts.append(f"// - {req}")

        return "\n".join(script_parts)

    def _generate_frida_trace(self, target: str, task: str, protection_info: Dict, requirements: List[str]) -> str:
        """Generate Frida trace script based on protection analysis"""
        script_parts = []

        script_parts.append(f"// Frida Trace Script for {target}")
        script_parts.append(f"// Task: {task}")
        if protection_info:
            script_parts.append(f"// Targeting protections: {', '.join(protection_info.keys())}")
        script_parts.append("")

        # Customize API tracing based on protection_info
        apis_to_trace = self._get_apis_to_trace(protection_info)
        
        # Add protection-specific tracing
        if protection_info:
            for protection_type, details in protection_info.items():
                if protection_type.lower() in ['licensing', 'trial', 'serial']:
                    script_parts.append("// License-related API tracing")
                    license_apis = [
                        ("kernel32.dll", "GetVolumeInformationW"),
                        ("kernel32.dll", "GetSystemInfo"),
                        ("wininet.dll", "InternetOpenW"),
                        ("wininet.dll", "HttpSendRequestW")
                    ]
                    apis_to_trace.extend(license_apis)
                    
                elif protection_type.lower() in ['anti_debug', 'anti_vm']:
                    script_parts.append("// Anti-analysis API tracing")
                    debug_apis = [
                        ("kernel32.dll", "IsDebuggerPresent"),
                        ("kernel32.dll", "CheckRemoteDebuggerPresent"),
                        ("ntdll.dll", "NtQueryInformationProcess"),
                        ("kernel32.dll", "GetSystemFirmwareTable")
                    ]
                    apis_to_trace.extend(debug_apis)
                    
                elif protection_type.lower() in ['packing', 'upx', 'vmprotect']:
                    script_parts.append("// Unpacking/protection API tracing")
                    packer_apis = [
                        ("kernel32.dll", "VirtualAlloc"),
                        ("kernel32.dll", "VirtualProtect"),
                        ("kernel32.dll", "WriteProcessMemory"),
                        ("ntdll.dll", "NtMapViewOfSection")
                    ]
                    apis_to_trace.extend(packer_apis)

        # Remove duplicates
        apis_to_trace = list(set(apis_to_trace))

        for module, func in apis_to_trace:
            script_parts.append(self.frida_templates["trace_api"].format(
                module=f'"{module}"' if module else "null",
                function=func,
                arg_logging='''        console.log("  arg0: " + args[0]);
        console.log("  arg1: " + args[1]);'''
            ))
            script_parts.append("")

        # Add custom requirement-based tracing
        if requirements:
            script_parts.append("// Custom requirement-based API tracing")
            for req in requirements:
                if any(keyword in req.lower() for keyword in ['network', 'socket', 'http']):
                    apis_to_trace.extend([
                        ("ws2_32.dll", "WSAStartup"),
                        ("wininet.dll", "InternetConnectW"),
                        ("winhttp.dll", "WinHttpConnect")
                    ])
                elif any(keyword in req.lower() for keyword in ['crypto', 'encrypt', 'hash']):
                    apis_to_trace.extend([
                        ("advapi32.dll", "CryptCreateHash"),
                        ("advapi32.dll", "CryptEncrypt"),
                        ("bcrypt.dll", "BCryptGenerateSymmetricKey")
                    ])
                elif any(keyword in req.lower() for keyword in ['registry', 'reg']):
                    apis_to_trace.extend([
                        ("advapi32.dll", "RegCreateKeyExW"),
                        ("advapi32.dll", "RegDeleteKeyExW"),
                        ("advapi32.dll", "RegSetValueExW")
                    ])
                elif any(keyword in req.lower() for keyword in ['process', 'thread']):
                    apis_to_trace.extend([
                        ("kernel32.dll", "CreateProcessW"),
                        ("kernel32.dll", "CreateThread"),
                        ("kernel32.dll", "TerminateProcess")
                    ])
                    
                script_parts.append(f"// Requirement: {req}")
            
            # Remove duplicates after adding requirement-based APIs
            apis_to_trace = list(set(apis_to_trace))

        return "\n".join(script_parts)
    
    def _get_apis_to_trace(self, protection_info: Dict) -> List[tuple]:
        """Get list of APIs to trace based on protection info"""
        # Base APIs always traced
        base_apis = [
            ("kernel32.dll", "CreateFileW"),
            ("kernel32.dll", "ReadFile"),
            ("kernel32.dll", "WriteFile"),
            ("user32.dll", "MessageBoxW")
        ]
        
        # Add protection-specific APIs
        if protection_info:
            protections = protection_info.keys()
            if any('network' in p.lower() for p in protections):
                base_apis.extend([
                    ("ws2_32.dll", "connect"),
                    ("ws2_32.dll", "send"),
                    ("ws2_32.dll", "recv")
                ])
            if any('registry' in p.lower() for p in protections):
                base_apis.extend([
                    ("advapi32.dll", "RegOpenKeyExW"),
                    ("advapi32.dll", "RegQueryValueExW"),
                    ("advapi32.dll", "RegSetValueExW")
                ])
                
        return base_apis

    def _generate_frida_bypass(self, target: str, task: str, protection_info: Dict, requirements: List[str]) -> str:
        """Generate Frida bypass script"""
        script_parts = []

        script_parts.append(f"// Frida Bypass Script for {target}")
        script_parts.append(f"// Task: {task}\n")

        # Check protection info
        protections = protection_info.get("protections", [])

        bypass_code_parts = []

        # Anti-debug bypass
        if any("debug" in str(p).lower() for p in protections) or "debug" in task.lower():
            bypass_code_parts.append('''    // Bypass IsDebuggerPresent
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
    });''')

        # License check bypass
        if any("license" in str(p).lower() for p in protections) or "license" in task.lower():
            bypass_code_parts.append('''    // Bypass license checks
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
    });''')

        # Add requirement-specific bypasses
        if requirements:
            script_parts.append("\n// Custom requirement-based bypasses")
            for req in requirements:
                if any(keyword in req.lower() for keyword in ['trial', 'demo', 'evaluation']):
                    bypass_code_parts.append('''    // Bypass trial/demo restrictions
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
    });''')
                elif any(keyword in req.lower() for keyword in ['nag', 'reminder', 'popup']):
                    bypass_code_parts.append('''    // Bypass nag screens and popups
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
    });''')
                elif any(keyword in req.lower() for keyword in ['time', 'date', 'expiry']):
                    bypass_code_parts.append('''    // Bypass time/date based restrictions
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
    });''')
                    
                script_parts.append(f"// Custom requirement: {req}")

        if bypass_code_parts:
            script_parts.append(self.frida_templates["bypass_protection"].format(
                protection_type="generic",
                bypass_code="\n".join(bypass_code_parts)
            ))
        else:
            # Generic bypass
            script_parts.append('''// Generic protection bypass
var targetAddr = ptr("0x00401000"); // Update with actual address
Interceptor.attach(targetAddr, {
    onEnter: function(args) {
        console.log("[*] Protection check intercepted");
    },
    onLeave: function(retval) {
        console.log("[*] Bypassing protection check");
        retval.replace(1); // Force success
    }
});''')

        return "\n".join(script_parts)

    def _generate_frida_patch(self, target: str, task: str, protection_info: Dict, requirements: List[str]) -> str:
        """Generate Frida memory patch script"""
        script_parts = []

        script_parts.append(f"// Frida Memory Patch Script for {target}")
        script_parts.append(f"// Task: {task}")
        if protection_info:
            script_parts.append(f"// Target protections: {', '.join(protection_info.keys())}")
        script_parts.append("")

        # Generate protection-specific patches based on protection_info
        patch_code_parts = []
        
        if protection_info:
            for protection_type, details in protection_info.items():
                if protection_type.lower() in ['anti_debug', 'debugger']:
                    patch_code_parts.append('''    // Patch anti-debug checks
    var antiDebugOpcodes = [0x33, 0xC0, 0xC3]; // xor eax, eax; ret
    antiDebugOpcodes.forEach(function(opcode, index) {
        addr.add(index).writeU8(opcode);
    });
    console.log("[*] Patched anti-debug at " + addr);''')
                    
                elif protection_type.lower() in ['license', 'trial', 'registration']:
                    patch_code_parts.append('''    // Patch license/trial checks
    var licenseBypassOpcodes = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]; // mov eax, 1; ret
    licenseBypassOpcodes.forEach(function(opcode, index) {
        addr.add(index).writeU8(opcode);
    });
    console.log("[*] Patched license check at " + addr);''')
                    
                elif protection_type.lower() in ['integrity', 'checksum', 'crc']:
                    patch_code_parts.append('''    // Patch integrity/checksum verification
    var integrityBypassOpcodes = [0x90, 0x90, 0x90, 0x90, 0x90]; // NOP sled
    integrityBypassOpcodes.forEach(function(opcode, index) {
        addr.add(index).writeU8(opcode);
    });
    console.log("[*] Patched integrity check at " + addr);''')
                    
        # Add requirements-based patches
        if requirements:
            script_parts.append("// Custom requirement-based patches")
            for req in requirements:
                if any(keyword in req.lower() for keyword in ['jmp', 'jump', 'branch']):
                    patch_code_parts.append('''    // Patch conditional jumps (requirement-based)
    var jumpPatchOpcodes = [0xEB]; // JMP short (unconditional)
    jumpPatchOpcodes.forEach(function(opcode, index) {
        addr.add(index).writeU8(opcode);
    });''')
                elif any(keyword in req.lower() for keyword in ['call', 'function']):
                    patch_code_parts.append('''    // Patch function calls (requirement-based)
    var callPatchOpcodes = [0x90, 0x90, 0x90, 0x90, 0x90]; // NOP out call
    callPatchOpcodes.forEach(function(opcode, index) {
        addr.add(index).writeU8(opcode);
    });''')
                    
                script_parts.append(f"// Requirement: {req}")

        # Use combined patch code or default
        if patch_code_parts:
            patch_code = "\n".join(patch_code_parts)
        else:
            # Default patch code
            patch_code = '''    var opcodes = [0x90, 0x90, 0x90, 0x90, 0x90]; // NOP sled
    opcodes.forEach(function(opcode, index) {
        addr.add(index).writeU8(opcode);
    });'''

        script_parts.append(self.frida_templates["memory_patch"].format(
            address="0x00401000",  # Example address
            size=5,
            patch_code=patch_code
        ))

        return "\n".join(script_parts)

    def _generate_frida_custom(self, target: str, task: str, protection_info: Dict, requirements: List[str]) -> str:
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
                if protection_type.lower() in ['anti_debug', 'debugger']:
                    patterns.extend(["debug", "debugger", "isdebuggerpresent"])
                elif protection_type.lower() in ['anti_vm', 'virtual']:
                    patterns.extend(["vm", "virtual", "vbox", "vmware"])
                elif protection_type.lower() in ['packing', 'upx', 'compression']:
                    patterns.extend(["unpack", "decompress", "expand"])
                elif protection_type.lower() in ['encryption', 'crypto']:
                    patterns.extend(["crypt", "encrypt", "decrypt", "cipher"])
                elif protection_type.lower() in ['obfuscation', 'obfuscate']:
                    patterns.extend(["obfus", "scramble", "encode"])

        # Remove duplicates and convert to JavaScript array format
        patterns = list(set(patterns))
        
        # Add requirements-based patterns
        if requirements:
            for req in requirements:
                if any(keyword in req.lower() for keyword in ['network', 'http', 'socket']):
                    patterns.extend(["connect", "send", "recv", "http", "socket"])
                elif any(keyword in req.lower() for keyword in ['file', 'io', 'disk']):
                    patterns.extend(["file", "read", "write", "open", "close"])
                elif any(keyword in req.lower() for keyword in ['memory', 'alloc', 'heap']):
                    patterns.extend(["alloc", "malloc", "free", "heap"])
                    
        patterns_js = str(patterns).replace("'", '"')

        # Basic structure with protection-aware patterns
        script_parts.append(f'''// Main script logic
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
}});''')

        return "\n".join(script_parts)

    def _generate_ghidra_script(self, target: str, task: str, protection_info: Dict, requirements: List[str]) -> str:
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
            "requirements": requirements
        }

        # Generate script based on task
        if "analyze" in task.lower():
            return generator.generate_analysis_script(context)
        elif "patch" in task.lower():
            return generator.generate_patch_script(context)
        elif "deobfuscate" in task.lower():
            return generator.generate_deobfuscation_script(context)
        else:
            return generator.generate_custom_script(context)

    def _generate_packer_hooks(self, protection_type: str) -> str:
        """Generate hooks specific to packers/protectors"""
        if protection_type.lower() == 'upx':
            return '''
// UPX unpacking hooks
var upxEntryPoint = Module.findBaseAddress("main_module").add(0x1000);
Interceptor.attach(upxEntryPoint, {
    onEnter: function(args) {
        console.log("[+] UPX entry point reached");
    }
});'''
        elif protection_type.lower() == 'vmprotect':
            return '''
// VMProtect VM entry hooks
var vmEntryPoints = Module.enumerateSymbols().filter(s => s.name.indexOf("vm_") !== -1);
vmEntryPoints.forEach(function(symbol) {
    Interceptor.attach(symbol.address, {
        onEnter: function(args) {
            console.log("[+] VMProtect VM entry: " + symbol.name);
        }
    });
});'''
        else:
            return f'// Hooks for {protection_type} not implemented yet'

    def _generate_license_hooks(self, details: str) -> str:
        """Generate license/trial bypass hooks based on protection details"""
        # Parse details to customize license hooks
        base_functions = ["CheckLicense", "VerifySerial", "ValidateKey", "IsTrialExpired"]
        
        # Add detail-specific functions if details contain hints
        if details and isinstance(details, str):
            details_lower = details.lower()
            if 'trial' in details_lower:
                base_functions.extend(["GetTrialDays", "IsTrialValid", "TrialCheck"])
            if 'serial' in details_lower or 'key' in details_lower:
                base_functions.extend(["ValidateSerial", "CheckSerialKey", "VerifyProductKey"])
            if 'online' in details_lower or 'server' in details_lower:
                base_functions.extend(["ConnectLicenseServer", "ValidateOnline", "CheckServerLicense"])
            if 'hardware' in details_lower or 'hwid' in details_lower:
                base_functions.extend(["GetHardwareID", "CheckHWID", "ValidateFingerprint"])
                
        # Remove duplicates
        functions_list = list(set(base_functions))
        functions_js = str(functions_list).replace("'", '"')
        
        return f'''
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
}});'''

    def _generate_anti_analysis_hooks(self, protection_type: str) -> str:
        """Generate anti-analysis bypass hooks"""
        if protection_type.lower() == 'anti_debug':
            return '''
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
});'''
        elif protection_type.lower() == 'anti_vm':
            return '''
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
});'''
        else:
            return f'// Anti-analysis hooks for {protection_type} not implemented'

    def _get_target_functions_from_protection(self, protection_info: Dict) -> str:
        """Get JavaScript array of target function names based on protection info"""
        target_funcs = ['check', 'verify', 'validate', 'license', 'trial', 'serial']
        
        if protection_info:
            for protection_type in protection_info.keys():
                if 'license' in protection_type.lower():
                    target_funcs.extend(['getlicense', 'checklicense', 'validatelicense'])
                elif 'trial' in protection_type.lower():
                    target_funcs.extend(['istrial', 'trialexpired', 'daysleft'])
                elif 'debug' in protection_type.lower():
                    target_funcs.extend(['isdebugger', 'debugger', 'antidebug'])
                elif 'vm' in protection_type.lower():
                    target_funcs.extend(['vm', 'virtual', 'sandbox'])
                    
        return str(target_funcs).replace("'", '"')  # Convert to JavaScript array format


def create_script_tool() -> ScriptGenerationTool:
    """Factory function to create script generation tool"""
    return ScriptGenerationTool()
