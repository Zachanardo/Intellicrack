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
        """Generate Frida hook script"""
        script_parts = []

        # Add header
        script_parts.append(f"// Frida Hook Script for {target}")
        script_parts.append(f"// Task: {task}")
        script_parts.append("// Generated by Intellicrack LLM Tool\n")

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
            # Native hook
            script_parts.append('''// Hook native function
var targetModule = Process.enumerateModules().filter(function(m) {
    return m.name.toLowerCase().indexOf('''' + target.lower() + '''') !== -1;
})[0];

if (targetModule) {
    var exports = targetModule.enumerateExports();
    exports.forEach(function(exp) {
        if (exp.name.indexOf('check') !== -1 || exp.name.indexOf('verify') !== -1) {
            console.log('[*] Hooking: ' + exp.name + ' at ' + exp.address);
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log('[+] ' + exp.name + ' called');
                    this.context = {
                        arg0: args[0],
                        arg1: args[1]
                    };
                },
                onLeave: function(retval) {
                    console.log('[+] ' + exp.name + ' returned: ' + retval);
                }
            });
        }
    });
}''')

        # Add custom requirements
        if requirements:
            script_parts.append("\n// Custom requirements:")
            for req in requirements:
                script_parts.append(f"// - {req}")

        return "\n".join(script_parts)

    def _generate_frida_trace(self, target: str, task: str, protection_info: Dict, requirements: List[str]) -> str:
        """Generate Frida trace script"""
        script_parts = []

        script_parts.append(f"// Frida Trace Script for {target}")
        script_parts.append(f"// Task: {task}\n")

        # Add API tracing
        apis_to_trace = [
            ("kernel32.dll", "CreateFileW"),
            ("kernel32.dll", "ReadFile"),
            ("kernel32.dll", "WriteFile"),
            ("kernel32.dll", "VirtualProtect"),
            ("ntdll.dll", "NtQueryInformationProcess"),
            ("user32.dll", "MessageBoxW")
        ]

        for module, func in apis_to_trace:
            script_parts.append(self.frida_templates["trace_api"].format(
                module=f'"{module}"' if module else "null",
                function=func,
                arg_logging='''        console.log("  arg0: " + args[0]);
        console.log("  arg1: " + args[1]);'''
            ))
            script_parts.append("")

        return "\n".join(script_parts)

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
        script_parts.append(f"// Task: {task}\n")

        # Example patch code
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
        script_parts.append("// Generated by Intellicrack LLM Tool\n")

        # Basic structure
        script_parts.append('''// Main script logic
console.log("[*] Script loaded for: " + Process.enumerateModules()[0].name);

// Enumerate modules
Process.enumerateModules().forEach(function(module) {
    console.log("Module: " + module.name + " at " + module.base);
});

// Your custom code here
// Based on task: ''' + task + '''

// Example: Find and hook interesting functions
var patterns = ["check", "verify", "validate", "auth", "license"];
Process.enumerateModules().forEach(function(module) {
    if (module.name.indexOf("''' + target + '''") !== -1) {
        module.enumerateExports().forEach(function(exp) {
            patterns.forEach(function(pattern) {
                if (exp.name.toLowerCase().indexOf(pattern) !== -1) {
                    console.log("[+] Found: " + exp.name + " at " + exp.address);
                    // Add your hook here
                }
            });
        });
    }
});''')

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


def create_script_tool() -> ScriptGenerationTool:
    """Factory function to create script generation tool"""
    return ScriptGenerationTool()
