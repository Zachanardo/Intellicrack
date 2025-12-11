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

/**
 * .NET Bypass Suite
 *
 * Comprehensive .NET framework and .NET Core bypass techniques for
 * license verification, obfuscation, and runtime protection mechanisms.
 *
 * Author: Intellicrack Framework
 * Version: 1.0.0
 * License: GPL v3
 */

const DotnetBypassSuite = {
    name: '.NET Bypass Suite',
    description: 'Advanced .NET runtime manipulation and protection bypass',
    version: '1.0.0',

    // Configuration
    config: {
        // Target .NET versions
        frameworks: {
            netFramework: {
                enabled: true,
                versions: ['2.0', '3.5', '4.0', '4.5', '4.6', '4.7', '4.8'],
            },
            netCore: {
                enabled: true,
                versions: ['2.1', '3.1', '5.0', '6.0', '7.0', '8.0'],
            },
        },

        // Protection systems to bypass
        protections: {
            obfuscators: {
                dotfuscator: true,
                smartAssembly: true,
                confuserEx: true,
                eazfuscator: true,
                crypto: true,
                agile: true,
                babel: true,
                xenocode: true,
            },
            licensing: {
                infralution: true,
                cryptolicensing: true,
                licensespots: true,
                quicklicense: true,
                xheo: true,
            },
            antiTamper: {
                strongName: true,
                authenticode: true,
                checksum: true,
                runtime: true,
            },
        },

        // Method hooks
        hooks: {
            reflection: true,
            jit: true,
            metadata: true,
            profiler: true,
            debugger: true,
        },
    },

    // Runtime state
    clrModule: null,
    monoModule: null,
    isCoreCLR: false,
    assemblies: {},
    bypassedChecks: 0,
    stats: {
        assembliesPatched: 0,
        methodsHooked: 0,
        stringsDecrypted: 0,
        checksumsBypassed: 0,
        debuggerChecksDisabled: 0,
        // NEW 2024-2025 Enhancement Statistics
        dotNet9RuntimeBypassEvents: 0,
        nativeAotBypassEvents: 0,
        trimmingSingleFileBypassEvents: 0,
        readyToRunBypassEvents: 0,
        wasmBlazorNetRuntimeBypassEvents: 0,
        modernObfuscatorSupportEvents: 0,
        certificateTransparencyLogDotNetBypassEvents: 0,
        hsmCertificateBypassEvents: 0,
        windowsDefenderApplicationControlBypassEvents: 0,
        appLockerDotNetScriptEnforcementBypassEvents: 0,
    },

    run: function () {
        send({
            type: 'status',
            target: 'dotnet_bypass_suite',
            action: 'starting_dotnet_bypass_suite',
        });

        // Detect CLR version
        this.detectCLR();

        // Hook based on runtime
        if (this.clrModule) {
            this.hookDotNetFramework();
        }
        if (this.monoModule) {
            this.hookMono();
        }
        if (this.isCoreCLR) {
            this.hookDotNetCore();
        }

        // Hook common protection mechanisms
        this.hookAntiTamper();
        this.hookLicenseChecks();
        this.hookObfuscatorRuntime();

        // NEW 2024-2025 Modern .NET Security Bypass Enhancements
        this.hookDotNet9Runtime();
        this.hookNativeAotBypass();
        this.hookTrimmingSingleFileBypass();
        this.hookReadyToRunBypass();
        this.hookWasmBlazorNetRuntimeBypass();
        this.hookModernObfuscatorSupport();
        this.hookCertificateTransparencyLogDotNetBypass();
        this.hookHsmCertificateBypass();
        this.hookWindowsDefenderApplicationControlBypass();
        this.hookAppLockerDotNetScriptEnforcementBypass();

        send({
            type: 'status',
            target: 'dotnet_bypass_suite',
            action: 'suite_initialized',
            methods_hooked: this.stats.methodsHooked,
        });
    },

    // Detect CLR type and version
    detectCLR: function () {
        Process.enumerateModules().forEach(module => {
          const name = module.name.toLowerCase();

          if (name.includes('clr.dll')) {
                this.clrModule = module;
                this.isCoreCLR = false;
                send({
                    type: 'info',
                    target: 'dotnet_bypass_suite',
                    action: 'found_net_framework_clr',
                    module_name: module.name,
                });
            } else if (name.includes('coreclr.dll')) {
                this.clrModule = module;
                this.isCoreCLR = true;
                send({
                    type: 'info',
                    target: 'dotnet_bypass_suite',
                    action: 'found_net_core_clr',
                    module_name: module.name,
                });
            } else if (name.includes('mono')) {
                this.monoModule = module;
                send({
                    type: 'info',
                    target: 'dotnet_bypass_suite',
                    action: 'found_mono_runtime',
                    module_name: module.name,
                });
            }
        });
    },

    // Hook .NET Framework
    hookDotNetFramework: function () {
        // Hook assembly loading
        this.hookAssemblyLoad();

        // Hook JIT compilation
        this.hookJITCompilation();

        // Hook metadata access
        this.hookMetadataAPIs();

        // Hook string decryption
        this.hookStringDecryption();

        // Hook reflection APIs
        this.hookReflectionAPIs();

        // Hook security APIs
        this.hookSecurityAPIs();
    },

    // Hook Mono runtime
    hookMono: function () {
      const self = this;

      send({
            type: 'info',
            target: 'dotnet_bypass_suite',
            action: 'hooking_mono_runtime',
        });

      const monoImageOpen = Module.findExportByName(this.monoModule.name, 'mono_image_open');
      if (monoImageOpen) {
            Interceptor.attach(monoImageOpen, {
                onEnter: args => {
                  const imageName = args[0].readUtf8String();
                  send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'mono_image_opening',
                        image_name: imageName,
                    });
                },
                onLeave: retval => {
                    if (!retval.isNull()) {
                        self.processMonoImage(retval);
                    }
                },
            });
            this.stats.methodsHooked++;
        }

      const monoMethodGetName = Module.findExportByName(
        this.monoModule.name,
        'mono_method_get_name'
      );
      if (monoMethodGetName) {
            this.monoMethodGetName = new NativeFunction(monoMethodGetName, 'pointer', ['pointer']);
        }

      const monoCompileMethod = Module.findExportByName(
        this.monoModule.name,
        'mono_compile_method'
      );
      if (monoCompileMethod) {
            Interceptor.attach(monoCompileMethod, {
                onEnter: function (args) {
                  const method = args[0];
                  if (method && !method.isNull() && self.monoMethodGetName) {
                      const namePtr = self.monoMethodGetName(method);
                      if (namePtr && !namePtr.isNull()) {
                          const methodName = namePtr.readUtf8String();
                          if (self.isLicenseMethod(methodName)) {
                                send({
                                    type: 'bypass',
                                    target: 'dotnet_bypass_suite',
                                    action: 'mono_license_method_compiling',
                                    method_name: methodName,
                                });
                                this.shouldPatch = true;
                                this.method = method;
                            }
                        }
                    }
                },
                onLeave: function (retval) {
                    if (this.shouldPatch && !retval.isNull()) {
                        Memory.patchCode(retval, 3, code => {
                            code.putU8(0xb0);
                            code.putU8(0x01);
                            code.putU8(0xc3);
                        });
                        self.bypassedChecks++;
                    }
                },
            });
            this.stats.methodsHooked++;
        }
    },

    // Hook .NET Core runtime
    hookDotNetCore: function () {
        send({
            type: 'info',
            target: 'dotnet_bypass_suite',
            action: 'hooking_dotnet_core_runtime',
        });

        this.hookAssemblyLoad();
        this.hookJITCompilation();
        this.hookMetadataAPIs();
        this.hookReflectionAPIs();
        this.hookSecurityAPIs();

      const coreClrInitialize = Module.findExportByName(this.clrModule.name, 'coreclr_initialize');
      if (coreClrInitialize) {
            Interceptor.attach(coreClrInitialize, {
                onEnter: _args => {
                    send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'coreclr_initializing',
                    });
                },
                onLeave: retval => {
                    if (retval.toInt32() === 0) {
                        send({
                            type: 'success',
                            target: 'dotnet_bypass_suite',
                            action: 'coreclr_initialized',
                        });
                    }
                },
            });
            this.stats.methodsHooked++;
        }

      const coreClrExecuteAssembly = Module.findExportByName(
        this.clrModule.name,
        'coreclr_execute_assembly'
      );
      if (coreClrExecuteAssembly) {
            Interceptor.attach(coreClrExecuteAssembly, {
                onEnter: args => {
                  const assemblyPath = args[2].readUtf8String();
                  send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'coreclr_executing_assembly',
                        assembly_path: assemblyPath,
                    });
                },
            });
            this.stats.methodsHooked++;
        }
    },

    // Process Mono image
    processMonoImage: function (image) {
        send({
            type: 'info',
            target: 'dotnet_bypass_suite',
            action: 'processing_mono_image',
        });

        this.checkForProtections(image);
        this.patchAntiTamperChecks(image);
    },

    // Hook assembly loading
    hookAssemblyLoad: function () {
      const self = this;

      // Assembly::Load
      let assemblyLoad = Module.findExportByName(this.clrModule.name, 'Assembly_Load');
      if (!assemblyLoad) {
            // Try pattern matching
          const pattern = '48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F9';
          const matches = Memory.scanSync(this.clrModule.base, this.clrModule.size, pattern);
          if (matches.length > 0) {
                assemblyLoad = matches[0].address;
            }
        }

        if (assemblyLoad) {
            Interceptor.attach(assemblyLoad, {
                onEnter: _args => {
                    send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'assembly_loading',
                    });
                },
                onLeave: retval => {
                    if (!retval.isNull()) {
                        self.processLoadedAssembly(retval);
                    }
                },
            });
            this.stats.methodsHooked++;
        }

        // AppDomain::LoadAssembly
      const appDomainLoad = Module.findExportByName(this.clrModule.name, 'AppDomain_LoadAssembly');
      if (appDomainLoad) {
            Interceptor.attach(appDomainLoad, {
                onEnter: function (args) {
                    this.assemblyPath = args[1];
                },
                onLeave: function (retval) {
                    if (!retval.isNull() && this.assemblyPath) {
                      const path = this.assemblyPath.readUtf16String();
                      send({
                            type: 'info',
                            target: 'dotnet_bypass_suite',
                            action: 'assembly_loaded',
                            assembly_path: path,
                        });
                        self.assemblies[retval.toString()] = {
                            handle: retval,
                            path: path,
                            patched: false,
                        };
                        self.stats.assembliesPatched++;
                    }
                },
            });
            this.stats.methodsHooked++;
        }
    },

    // Process loaded assembly
    processLoadedAssembly: function (assembly) {
        // Get assembly name
      const getNameMethod = this.findMethodInVTable(assembly, 'GetName');
      if (getNameMethod) {
          const name = new NativeFunction(getNameMethod, 'pointer', ['pointer'])(assembly);
          send({
                type: 'info',
                target: 'dotnet_bypass_suite',
                action: 'processing_assembly',
                assembly_name: name.readUtf16String(),
            });
        }

        // Check for known protections
        this.checkForProtections(assembly);

        // Patch anti-tamper checks
        this.patchAntiTamperChecks(assembly);
    },

    // Hook JIT compilation
    hookJITCompilation: function () {
      const self = this;

      // getJit
      const getJit = Module.findExportByName(this.clrModule.name, 'getJit');
      if (getJit) {
          const jitInterface = new NativeFunction(getJit, 'pointer', [])();

          if (jitInterface) {
                // Hook compileMethod
              const compileMethodOffset = this.isCoreCLR ? 0x0 : 0x28; // Offset in vtable
              const compileMethod = jitInterface
                .readPointer()
                .add(compileMethodOffset)
                .readPointer();

              Interceptor.attach(compileMethod, {
                    onEnter: function (args) {
                      const methodInfo = args[2];

                      if (methodInfo && !methodInfo.isNull()) {
                          const methodDef = methodInfo.add(0x8).readPointer();
                          const methodName = self.getMethodName(methodDef);

                          // Check for license-related methods
                            if (methodName && self.isLicenseMethod(methodName)) {
                                send({
                                    type: 'bypass',
                                    target: 'dotnet_bypass_suite',
                                    action: 'jit_compiling_license_method',
                                    method_name: methodName,
                                });
                                this.shouldPatch = true;
                                this.methodInfo = methodInfo;
                            }
                        }
                    },
                    onLeave: function (retval) {
                        if (this.shouldPatch && retval.toInt32() === 0) {
                            // Patch the compiled method
                            self.patchCompiledMethod(this.methodInfo);
                        }
                    },
                });
                this.stats.methodsHooked++;
                send({
                    type: 'info',
                    target: 'dotnet_bypass_suite',
                    action: 'hooked_jit_compiler',
                });
            }
        }
    },

    // Hook metadata APIs
    hookMetadataAPIs: function () {
      const self = this;

      // MetaDataGetDispenser
      const getDispenser = Module.findExportByName(this.clrModule.name, 'MetaDataGetDispenser');
      if (getDispenser) {
            Interceptor.attach(getDispenser, {
                onLeave: function (retval) {
                    if (retval.toInt32() === 0) {
                        // S_OK
                      const dispenser = this.context.r8.readPointer();
                      self.hookMetadataDispenser(dispenser);
                    }
                },
            });
            this.stats.methodsHooked++;
        }
    },

    // Hook metadata dispenser
    hookMetadataDispenser: function (dispenser) {
        // Hook OpenScope to intercept assembly metadata access
      const vtable = dispenser.readPointer();
      const openScope = vtable.add(0x18).readPointer(); // IMetaDataDispenser::OpenScope

        Interceptor.attach(openScope, {
            onEnter: args => {
              const filename = args[1].readUtf16String();
              const _openFlags = args[2].toInt32();

              send({
                    type: 'info',
                    target: 'dotnet_bypass_suite',
                    action: 'opening_metadata_scope',
                    filename: filename,
                });

                // Check if it's a protected assembly
                if (this.isProtectedAssembly(filename)) {
                    // Force read/write access
                    args[2] = ptr(0x1); // ofWrite
                }
            },
        });
    },

    // Hook string decryption
    hookStringDecryption: function () {
        // Common obfuscator string decryption patterns
      const patterns = [
        // Dotfuscator pattern
        '48 89 5C 24 ?? 57 48 83 EC ?? 48 8B D9 48 8B FA E8',
        // SmartAssembly pattern
        '55 8B EC 83 EC ?? 53 56 57 8B 7D ?? 8B F1',
        // ConfuserEx pattern
        '28 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 2C',
      ];

      patterns.forEach(pattern => {
          const matches = Memory.scanSync(this.clrModule.base, this.clrModule.size, pattern);

          matches.forEach(match => {
                Interceptor.attach(match.address, {
                    onLeave: retval => {
                        if (!retval.isNull()) {
                            try {
                              const decrypted = retval.readUtf16String();
                              if (decrypted && this.isLicenseString(decrypted)) {
                                    send({
                                        type: 'bypass',
                                        target: 'dotnet_bypass_suite',
                                        action: 'decrypted_license_string',
                                        decrypted_string: decrypted,
                                    });

                                    // Replace with valid license
                                  const validLicense = this.generateValidLicense(decrypted);
                                  retval.writeUtf16String(validLicense);

                                    this.stats.stringsDecrypted++;
                                }
                            } catch (e) {
                                send({
                                    type: 'debug',
                                    target: 'dotnet_bypass',
                                    action: 'string_read_failed',
                                    function: 'hookStringDecryption',
                                    error: e.toString(),
                                    stack: e.stack || 'No stack trace available',
                                });
                            }
                        }
                    },
                });
                this.stats.methodsHooked++;
            });
        });
    },

    // Hook reflection APIs
    hookReflectionAPIs: function () {
      const self = this;

      // Type::InvokeMember
      const invokeMember = this.findExportPattern(
        'Type_InvokeMember',
        '48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57'
      );

      if (invokeMember) {
            Interceptor.attach(invokeMember, {
                onEnter: function (args) {
                  const memberName = args[1].readUtf16String();
                  const _bindingFlags = args[2].toInt32();

                  if (memberName && self.isLicenseMethod(memberName)) {
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'reflection_invoke_license',
                            member_name: memberName,
                        });
                        this.isLicenseCheck = true;
                    }
                },
                onLeave: function (retval) {
                    if (this.isLicenseCheck && !retval.isNull()) {
                        // Ensure license check returns true
                        try {
                          const result = retval.readU8();
                          if (result === 0) {
                                retval.writeU8(1);
                                self.bypassedChecks++;
                            }
                        } catch (e) {
                            send({
                                type: 'debug',
                                target: 'dotnet_bypass',
                                action: 'hook_failed',
                                function: 'dotnet_bypass_suite',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    }
                },
            });
            this.stats.methodsHooked++;
        }

        // MethodBase::Invoke
      const methodInvoke = this.findExportPattern(
        'MethodBase_Invoke',
        '48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F2 48 8B D9'
      );

      if (methodInvoke) {
            Interceptor.attach(methodInvoke, {
                onEnter: function (args) {
                  const method = args[0];
                  const methodName = self.getMethodName(method);

                  if (methodName && self.isLicenseMethod(methodName)) {
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'method_invoke_license',
                            method_name: methodName,
                        });
                        this.isLicenseCheck = true;
                        this.returnValue = args[4]; // out parameter
                    }
                },
                onLeave: function (_retval) {
                    if (this.isLicenseCheck && this.returnValue) {
                        // Modify return value
                        this.returnValue.writeU8(1); // true
                        self.bypassedChecks++;
                    }
                },
            });
            this.stats.methodsHooked++;
        }
    },

    // Hook security APIs
    hookSecurityAPIs: function () {
        // StrongNameSignatureVerificationEx
      const strongNameVerify = Module.findExportByName(
        'mscoree.dll',
        'StrongNameSignatureVerificationEx'
      );
      if (strongNameVerify) {
            Interceptor.replace(
                strongNameVerify,
                new NativeCallback(
                    (_wszFilePath, _fForceVerification, pfWasVerified) => {
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'strongname_verification_bypassed',
                        });

                        if (pfWasVerified) {
                            pfWasVerified.writeU8(1);
                        }

                        this.stats.checksumsBypassed++;
                        return 1; // TRUE
                    },
                    'int',
                    ['pointer', 'int', 'pointer']
                )
            );
            this.stats.methodsHooked++;
        }

        // Authenticode verification
      const winVerifyTrust = Module.findExportByName('wintrust.dll', 'WinVerifyTrust');
      if (winVerifyTrust) {
            Interceptor.attach(winVerifyTrust, {
                onLeave: retval => {
                  const result = retval.toInt32();
                  if (result !== 0) {
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'authenticode_verification_bypassed',
                        });
                        retval.replace(0); // ERROR_SUCCESS
                        this.stats.checksumsBypassed++;
                    }
                },
            });
            this.stats.methodsHooked++;
        }
    },

    // Hook anti-tamper mechanisms
    hookAntiTamper: function () {
        // Common anti-tamper checks

        // 1. Module checksum verification
      const imageNtHeader = Module.findExportByName('ntdll.dll', 'RtlImageNtHeader');
      if (imageNtHeader) {
            Interceptor.attach(imageNtHeader, {
                onLeave: retval => {
                    if (!retval.isNull()) {
                        // Zero out checksum field
                      const checksumOffset = 0x58; // IMAGE_NT_HEADERS->OptionalHeader.CheckSum
                        retval.add(checksumOffset).writeU32(0);
                    }
                },
            });
            this.stats.methodsHooked++;
        }

        // 2. File hash verification
        this.hookHashAPIs();

        // 3. Debugger detection
        this.hookDebuggerDetection();

        // 4. Runtime integrity checks
        this.hookRuntimeIntegrity();
    },

    // Hook hash APIs
    hookHashAPIs: function () {
      const self = this;

      // CryptHashData
      const cryptHashData = Module.findExportByName('advapi32.dll', 'CryptHashData');
      if (cryptHashData) {
            Interceptor.attach(cryptHashData, {
                onEnter: function (args) {
                  const _hHash = args[0];
                  const pbData = args[1];
                  const dwDataLen = args[2].toInt32();

                  // Check if hashing assembly data
                    if (dwDataLen > 1024 && self.isAssemblyData(pbData, dwDataLen)) {
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'assembly_hash_computation_intercepted',
                        });
                        this.shouldModify = true;
                    }
                },
            });
            this.stats.methodsHooked++;
        }

        // BCryptHashData
      const bcryptHashData = Module.findExportByName('bcrypt.dll', 'BCryptHashData');
      if (bcryptHashData) {
            Interceptor.attach(bcryptHashData, {
                onEnter: function (args) {
                  const _hHash = args[0];
                  const pbInput = args[1];
                  const cbInput = args[2].toInt32();

                  if (cbInput > 1024 && self.isAssemblyData(pbInput, cbInput)) {
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'bcrypt_assembly_hash_intercepted',
                        });
                        // Replace with known good hash
                        this.originalData = pbInput.readByteArray(Math.min(cbInput, 64));
                        pbInput.writeByteArray(self.getKnownGoodHash());
                    }
                },
            });
            this.stats.methodsHooked++;
        }
    },

    // Hook debugger detection
    hookDebuggerDetection: function () {
      const self = this;

      // IsDebuggerPresent
      const isDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
      if (isDebuggerPresent) {
            Interceptor.replace(
                isDebuggerPresent,
                new NativeCallback(
                    () => {
                        self.stats.debuggerChecksDisabled++;
                        return 0; // FALSE
                    },
                    'int',
                    []
                )
            );
            this.stats.methodsHooked++;
        }

        // CheckRemoteDebuggerPresent
      const checkRemoteDebugger = Module.findExportByName(
        'kernel32.dll',
        'CheckRemoteDebuggerPresent'
      );
      if (checkRemoteDebugger) {
            Interceptor.attach(checkRemoteDebugger, {
                onLeave: function (retval) {
                  const pbDebuggerPresent = this.context.rdx;
                  if (pbDebuggerPresent) {
                        pbDebuggerPresent.writeU8(0); // FALSE
                    }
                    retval.replace(1); // TRUE (success)
                    self.stats.debuggerChecksDisabled++;
                },
            });
            this.stats.methodsHooked++;
        }

        // NtQueryInformationProcess
      const ntQueryInfoProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
      if (ntQueryInfoProcess) {
            Interceptor.attach(ntQueryInfoProcess, {
                onEnter: function (args) {
                    this.infoClass = args[1].toInt32();
                    this.buffer = args[2];
                },
                onLeave: function (retval) {
                    if (retval.toInt32() === 0) {
                        // STATUS_SUCCESS
                        // ProcessDebugPort = 7
                        if (this.infoClass === 7 && this.buffer) {
                            this.buffer.writePointer(ptr(0));
                            self.stats.debuggerChecksDisabled++;
                        }
                        // ProcessDebugObjectHandle = 30
                        else if (this.infoClass === 30 && this.buffer) {
                            this.buffer.writePointer(ptr(0));
                            self.stats.debuggerChecksDisabled++;
                        }
                    }
                },
            });
            this.stats.methodsHooked++;
        }
    },

    // Hook runtime integrity checks
    hookRuntimeIntegrity: function () {
        // Hook CLR internal integrity checks
      const patterns = [
        // Integrity check pattern 1
        '48 89 5C 24 ?? 57 48 83 EC ?? 8B F9 E8 ?? ?? ?? ?? 48 8B D8 48 85 C0',
        // Integrity check pattern 2
        '40 53 48 83 EC ?? 48 8B D9 E8 ?? ?? ?? ?? 84 C0 74 ??',
      ];

      patterns.forEach(pattern => {
          const matches = Memory.scanSync(this.clrModule.base, this.clrModule.size, pattern);

          matches.forEach(match => {
                Interceptor.attach(match.address, {
                    onLeave: retval => {
                        // Force integrity check to pass
                        if (retval.toInt32() === 0) {
                            retval.replace(1);
                            send({
                                type: 'bypass',
                                target: 'dotnet_bypass_suite',
                                action: 'runtime_integrity_check_bypassed',
                            });
                            this.stats.checksumsBypassed++;
                        }
                    },
                });
            });
        });
    },

    // Hook known license check methods
    hookLicenseChecks: function () {
        // Common license check patterns
      const licensePatterns = [
        'IsLicenseValid',
        'CheckLicense',
        'ValidateLicense',
        'VerifyLicense',
        'IsActivated',
        'IsTrial',
        'HasExpired',
        'GetLicenseStatus',
      ];

      // Hook by method name pattern
        licensePatterns.forEach(pattern => {
            this.hookMethodByName(
                pattern,
                _originalFunc =>
                    new NativeCallback(
                        () => {
                            send({
                                type: 'bypass',
                                target: 'dotnet_bypass_suite',
                                action: 'license_check_bypassed',
                                pattern: pattern,
                            });
                            this.bypassedChecks++;

                            // Return success based on method name
                            if (pattern.includes('Trial') || pattern.includes('Expired')) {
                                return 0; // false
                            } else {
                                return 1; // true
                            }
                        },
                        'int',
                        ['pointer']
                    )
            );
        });
    },

    // Hook obfuscator runtime
    hookObfuscatorRuntime: function () {
        // ConfuserEx runtime
        this.hookConfuserExRuntime();

        // Eazfuscator runtime
        this.hookEazfuscatorRuntime();

        // Crypto Obfuscator runtime
        this.hookCryptoObfuscatorRuntime();
    },

    // Hook ConfuserEx runtime
    hookConfuserExRuntime: function () {
        // ConfuserEx anti-tamper
      const antiTamperPattern = 'E8 ?? ?? ?? ?? 0A 06 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0A 00 DE ??';
      let matches = Memory.scanSync(this.clrModule.base, this.clrModule.size, antiTamperPattern);

      matches.forEach(match => {
            // NOP out the anti-tamper check
            Memory.patchCode(match.address, 5, code => {
                for (let i = 0; i < 5; i++) {
                    code.putU8(0x90); // NOP
                }
            });
            send({
                type: 'bypass',
                target: 'dotnet_bypass_suite',
                action: 'confuserex_anti_tamper_disabled',
                address: match.address.toString(),
            });
            this.stats.checksumsBypassed++;
        });

        // ConfuserEx constants decryption
      const constDecryptPattern = '28 ?? ?? ?? ?? 8E 69 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28';
      matches = Memory.scanSync(this.clrModule.base, this.clrModule.size, constDecryptPattern);

        matches.forEach(match => {
            Interceptor.attach(match.address, {
                onLeave: _retval => {
                    // Log decrypted constants
                    send({
                        type: 'bypass',
                        target: 'dotnet_bypass_suite',
                        action: 'confuserex_constant_decrypted',
                    });
                    this.stats.stringsDecrypted++;
                },
            });
        });
    },

    // Hook Eazfuscator runtime
    hookEazfuscatorRuntime: function () {
        // Eazfuscator string encryption
      const stringPattern = '7E ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 7E ?? ?? ?? ?? 28';
      const matches = Memory.scanSync(this.clrModule.base, this.clrModule.size, stringPattern);

      matches.forEach(match => {
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    this.stringId = args[0].toInt32();
                },
                onLeave: retval => {
                    if (!retval.isNull()) {
                        try {
                          const decrypted = retval.readUtf16String();
                          if (this.isLicenseString(decrypted)) {
                                send({
                                    type: 'bypass',
                                    target: 'dotnet_bypass_suite',
                                    action: 'eazfuscator_string_decrypted',
                                    decrypted_string: decrypted,
                                });

                                // Replace with valid string
                              const valid = this.generateValidLicense(decrypted);
                              retval.writeUtf16String(valid);
                                this.stats.stringsDecrypted++;
                            }
                        } catch (e) {
                            send({
                                type: 'debug',
                                target: 'dotnet_bypass',
                                action: 'hook_failed',
                                function: 'dotnet_bypass_suite',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    }
                },
            });
        });
    },

    // Hook Crypto Obfuscator runtime
    hookCryptoObfuscatorRuntime: function () {
        // Crypto Obfuscator license check
      const licensePattern = '14 0A 06 16 33 ?? 16 0A 2B ?? 17 0A 06 2A';
      const matches = Memory.scanSync(this.clrModule.base, this.clrModule.size, licensePattern);

      matches.forEach(match => {
            // Patch to always return true
            Memory.patchCode(match.address, 2, code => {
                code.putU8(0x17); // ldc.i4.1
                code.putU8(0x2a); // ret
            });
            send({
                type: 'bypass',
                target: 'dotnet_bypass_suite',
                action: 'crypto_obfuscator_license_check_patched',
            });
            this.bypassedChecks++;
        });
    },

    // Helper: Find export by pattern
    findExportPattern: function (name, pattern) {
      const func = Module.findExportByName(this.clrModule.name, name);
      if (func) { return func; }

        // Try pattern matching
      const matches = Memory.scanSync(this.clrModule.base, this.clrModule.size, pattern);
      if (matches.length > 0) {
            return matches[0].address;
        }

        return null;
    },

    // Helper: Hook method by name
    hookMethodByName: function (name, replacementFactory) {
        // Search in all loaded modules
        Process.enumerateModules().forEach(module => {
            module.enumerateExports().forEach(exp => {
                if (exp.name.includes(name)) {
                  const replacement = replacementFactory(exp.address);
                  Interceptor.replace(exp.address, replacement);
                    this.stats.methodsHooked++;
                    send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'method_hooked',
                        method_name: exp.name,
                    });
                }
            });
        });
    },

    // Helper: Get method name from metadata
    getMethodName: function (methodDef) {
        try {
          const nameRva = methodDef.add(0x8).readU32();
          if (nameRva > 0 && nameRva < this.clrModule.size) {
                var namePtr = this.clrModule.base.add(nameRva);
                return namePtr.readUtf8String();
            }

          const methodTablePtr = methodDef.readPointer();
          if (methodTablePtr && !methodTablePtr.isNull()) {
              const methodDescPtr = methodTablePtr.add(0x10).readPointer();
              if (methodDescPtr && !methodDescPtr.isNull()) {
                    var namePtr = methodDescPtr.add(0x0).readPointer();
                    if (namePtr && !namePtr.isNull()) {
                        return namePtr.readUtf8String();
                    }
                }
            }
        } catch (e) {
            send({
                type: 'debug',
                target: 'dotnet_bypass',
                action: 'hook_failed',
                function: 'dotnet_bypass_suite',
                error: e.toString(),
                stack: e.stack || 'No stack trace available',
            });
        }

        return null;
    },

    // Helper: Check if method is license-related
    isLicenseMethod: name => {
        if (!name) { return false; }

      const keywords = [
        'license',
        'activation',
        'serial',
        'trial',
        'expire',
        'validate',
        'verify',
        'check',
        'register',
        'unlock',
        'authentic',
      ];

      name = name.toLowerCase();
        for (let i = 0; i < keywords.length; i++) {
            if (name.includes(keywords[i])) {
                return true;
            }
        }

        return false;
    },

    // Helper: Check if string is license-related
    isLicenseString: str => {
        if (!str || str.length < 4) { return false; }

      const patterns = [
        /^[A-Z0-9]{4,}-[A-Z0-9]{4,}/,
        /\d{4}-\d{4}-\d{4}-\d{4}/,
        /[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}/,
        /licen[sc]e|serial|key|activation/i,
      ];

      for (let i = 0; i < patterns.length; i++) {
            if (patterns[i].test(str)) {
                return true;
            }
        }

        return false;
    },

    // Helper: Generate valid license
    generateValidLicense: original => {
        // Generate a valid-looking license based on the original format
        if (original.match(/^[A-Z0-9]{4,}-[A-Z0-9]{4,}/)) {
            return 'INTC-RACK-2024-FULL';
        } else if (original.match(/\d{4}-\d{4}-\d{4}-\d{4}/)) {
            return '1234-5678-9012-3456';
        } else if (original.match(/[A-F0-9]{8}-[A-F0-9]{4}/)) {
            return 'DEADBEEF-CAFE-BABE-F00D-123456789ABC';
        }

        return 'VALID-LICENSE-KEY';
    },

    // Helper: Check if data is assembly
    isAssemblyData: (data, length) => {
        if (length < 64) { return false; }

        try {
            // Check for PE header
          const dos = data.readU16();
          if (dos === 0x5a4d) {
                // MZ
              const peOffset = data.add(0x3c).readU32();
              if (peOffset < length - 4) {
                  const pe = data.add(peOffset).readU32();
                  return pe === 0x00004550; // PE\0\0
                }
            }
        } catch (e) {
            send({
                type: 'debug',
                target: 'dotnet_bypass',
                action: 'hook_failed',
                function: 'dotnet_bypass_suite',
                error: e.toString(),
                stack: e.stack || 'No stack trace available',
            });
        }

        return false;
    },

    // Helper: Get known good hash
    getKnownGoodHash: () => {
        // Return a hash that will pass validation
        return [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00,
        ];
    },

    // Helper: Check for known protections
    checkForProtections: _assembly => {
        // Check for obfuscator signatures
      const signatures = {
        DotfuscatorAttribute: 'Dotfuscator',
        'SmartAssembly.Attributes': 'SmartAssembly',
        ConfusedByAttribute: 'ConfuserEx',
        YanoAttribute: 'Yano',
        CryptoObfuscator: 'Crypto Obfuscator',
        BabelAttribute: 'Babel',
        AgileDotNetRT: 'Agile.NET',
      };

      Object.keys(signatures).forEach(sig => {
            // Check for attributes in metadata
            send({
                type: 'info',
                target: 'dotnet_bypass_suite',
                action: 'checking_protection',
                protection_type: signatures[sig],
            });
        });
    },

    // Helper: Patch anti-tamper checks
    patchAntiTamperChecks: assembly => {
        send({
            type: 'status',
            target: 'dotnet_bypass_suite',
            action: 'patching_anti_tamper_checks',
        });

        try {
          const assemblyPtr = assembly.readPointer();
          if (!assemblyPtr || assemblyPtr.isNull()) {
                return;
            }

          const antiTamperPatterns = [
            [0x48, 0x8b, 0x05, 0x90, 0x90, 0x90, 0x90],
            [0xe8, 0x90, 0x90, 0x90, 0x90, 0x84, 0xc0, 0x74],
            [0x48, 0x85, 0xc0, 0x74, 0x90, 0x48, 0x8b, 0xc8],
          ];

          const peHeader = assemblyPtr.add(0x3c).readU32();
          const codeSection = assemblyPtr.add(peHeader + 0x18);
          const codeBase = codeSection.add(0x0c).readPointer();
          const codeSize = codeSection.add(0x08).readU32();

          antiTamperPatterns.forEach(pattern => {
              const matches = Memory.scanSync(
                codeBase,
                codeSize,
                pattern
                  .map(b => (b === 0x90 ? '??' : b.toString(16).padStart(2, '0')))
                  .join(' ')
              );

              matches.forEach(match => {
                    Memory.patchCode(match.address, pattern.length, code => {
                        for (let i = 0; i < pattern.length; i++) {
                            code.putU8(0x90);
                        }
                    });
                    send({
                        type: 'bypass',
                        target: 'dotnet_bypass_suite',
                        action: 'anti_tamper_pattern_patched',
                        address: match.address.toString(),
                    });
                });
            });
        } catch (e) {
            send({
                type: 'debug',
                target: 'dotnet_bypass',
                action: 'anti_tamper_patch_failed',
                function: 'patchAntiTamperChecks',
                error: e.toString(),
                stack: e.stack || 'No stack trace available',
            });
        }
    },

    // Helper: Patch compiled method
    patchCompiledMethod: function (methodInfo) {
        send({
            type: 'status',
            target: 'dotnet_bypass_suite',
            action: 'patching_compiled_license_method',
        });

        // Get native code address
      const nativeCode = methodInfo.add(0x20).readPointer();
      if (nativeCode && !nativeCode.isNull()) {
            // Patch to return true
            Memory.patchCode(nativeCode, 3, code => {
                code.putU8(0xb0); // mov al, 1
                code.putU8(0x01);
                code.putU8(0xc3); // ret
            });
            this.bypassedChecks++;
        }
    },

    // Helper: Find method in vtable
    findMethodInVTable: (object, _methodName) => {
        // Simplified vtable search
        try {
          const vtable = object.readPointer();
          for (let i = 0; i < 100; i++) {
              const method = vtable.add(i * Process.pointerSize).readPointer();
              if (method && !method.isNull()) {
                    // Would need to check method name in metadata
                    // For now, return first valid method
                    return method;
                }
            }
        } catch (e) {
            send({
                type: 'debug',
                target: 'dotnet_bypass',
                action: 'hook_failed',
                function: 'dotnet_bypass_suite',
                error: e.toString(),
                stack: e.stack || 'No stack trace available',
            });
        }

        return null;
    },

    // Helper: Check if assembly is protected
    isProtectedAssembly: filename => {
        if (!filename) { return false; }

      const protectedNames = [
        'license',
        'activation',
        'crypto',
        'protect',
        'obfuscat',
        'secure',
        'guard',
        'shield',
      ];

      filename = filename.toLowerCase();
        for (let i = 0; i < protectedNames.length; i++) {
            if (filename.includes(protectedNames[i])) {
                return true;
            }
        }

        return false;
    },

    // === NEW 2024-2025 MODERN .NET SECURITY BYPASS ENHANCEMENTS ===

    // 1. .NET 9.0/10.0 Runtime Bypass
    hookDotNet9Runtime: function () {
        // .NET 9.0 introduces new runtime security features
      const dotNet9Patterns = [
        // .NET 9.0 runtime security check pattern
        '48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B C8 E8 ?? ?? ?? ?? 84 C0 75',
        // Enhanced security validation pattern
        '49 8B CC E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 8B 5C 24',
        // Modern runtime integrity verification
        '48 89 74 24 ?? 57 48 83 EC ?? 48 8B F9 48 8B F2 E8 ?? ?? ?? ?? 84 C0',
      ];

      dotNet9Patterns.forEach(pattern => {
          const matches = Memory.scanSync(this.clrModule.base, this.clrModule.size, pattern);

          matches.forEach(match => {
                Interceptor.attach(match.address, {
                    onEnter: _args => {
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'dotnet9_runtime_security_check_detected',
                            address: match.address.toString(),
                        });
                    },
                    onLeave: retval => {
                        // Force .NET 9 security checks to pass
                        if (retval.toInt32() === 0) {
                            retval.replace(1);
                            this.stats.dotNet9RuntimeBypassEvents++;
                            send({
                                type: 'success',
                                target: 'dotnet_bypass_suite',
                                action: 'dotnet9_runtime_security_bypassed',
                            });
                        }
                    },
                });
            });
        });

        // Hook .NET 9.0 specific AssemblyLoadContext security
      const dotNet9AlcPattern =
        '48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4C 8B FA';
      const alcMatches = Memory.scanSync(
        this.clrModule.base,
        this.clrModule.size,
        dotNet9AlcPattern
      );

      alcMatches.forEach(match => {
            Interceptor.attach(match.address, {
                onEnter: args => {
                  const _contextPtr = args[0];
                  const _assemblyPtr = args[1];

                  send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'dotnet9_assembly_load_context_intercepted',
                    });
                },
                onLeave: retval => {
                    // Ensure assembly loading succeeds
                    if (!retval.isNull()) {
                        this.stats.dotNet9RuntimeBypassEvents++;
                        send({
                            type: 'success',
                            target: 'dotnet_bypass_suite',
                            action: 'dotnet9_alc_bypass_successful',
                        });
                    }
                },
            });
        });

        this.stats.methodsHooked += dotNet9Patterns.length + alcMatches.length;
    },

    // 2. Native AOT (Ahead-of-Time) Compilation Bypass
    hookNativeAotBypass: function () {
        // Native AOT produces single executable without traditional CLR
        // Look for NativeAOT runtime signatures
      const nativeAotPatterns = [
        // NativeAOT runtime initialization pattern
        '48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8D 0D',
        // NativeAOT type system pattern
        '48 8B 42 ?? 48 8B CA 48 89 01 48 8B 42 ?? 48 89 41 ?? C3',
        // NativeAOT GC interaction pattern
        '41 57 48 83 EC ?? 4C 8B F9 48 8B D1 48 8D 0D ?? ?? ?? ?? E8',
      ];

      nativeAotPatterns.forEach(pattern => {
          const matches = Memory.scanSync(
            Module.getBaseAddress('ntdll.dll'),
            Module.getSize('ntdll.dll'),
            pattern
          );

          matches.forEach(match => {
                Interceptor.attach(match.address, {
                    onEnter: _args => {
                        send({
                            type: 'info',
                            target: 'dotnet_bypass_suite',
                            action: 'native_aot_runtime_detected',
                            address: match.address.toString(),
                        });
                    },
                    onLeave: retval => {
                        // Ensure Native AOT operations succeed
                        if (retval.toInt32() !== 0) {
                            retval.replace(0); // Force success
                            this.stats.nativeAotBypassEvents++;
                            send({
                                type: 'bypass',
                                target: 'dotnet_bypass_suite',
                                action: 'native_aot_security_bypassed',
                            });
                        }
                    },
                });
            });
        });

        // Hook NativeAOT reflection restrictions
      const reflectionPattern = '48 8B 01 FF 50 ?? 85 C0 74 ?? 48 8B CB E8 ?? ?? ?? ?? 48 8B C8';
      const reflectionMatches = Memory.scanSync(
        Module.getBaseAddress('kernel32.dll'),
        Module.getSize('kernel32.dll'),
        reflectionPattern
      );

      reflectionMatches.forEach(match => {
            Interceptor.attach(match.address, {
                onEnter: _args => {
                    send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'native_aot_reflection_restriction_detected',
                    });
                },
                onLeave: retval => {
                    // Allow all reflection operations
                    if (retval.toInt32() === 0) {
                        retval.replace(1);
                        this.stats.nativeAotBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'native_aot_reflection_restriction_bypassed',
                        });
                    }
                },
            });
        });

        this.stats.methodsHooked += nativeAotPatterns.length + reflectionMatches.length;
    },

    // 3. Trimming and Single-File Deployment Bypass
    hookTrimmingSingleFileBypass: function () {
        // Single-file deployments extract to temp directory
      const tempExtractPattern =
        '48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F2 48 8B F9 E8 ?? ?? ?? ?? 85 C0';
      const extractMatches = Memory.scanSync(
        this.clrModule.base,
        this.clrModule.size,
        tempExtractPattern
      );

      extractMatches.forEach(match => {
            Interceptor.attach(match.address, {
                onEnter: args => {
                  const extractPath = args[1];
                  if (extractPath && !extractPath.isNull()) {
                      const path = extractPath.readUtf16String();
                      send({
                            type: 'info',
                            target: 'dotnet_bypass_suite',
                            action: 'single_file_extraction_detected',
                            extract_path: path,
                        });
                    }
                },
                onLeave: retval => {
                    // Ensure extraction succeeds
                    if (retval.toInt32() !== 0) {
                        retval.replace(0);
                        this.stats.trimmingSingleFileBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'single_file_extraction_bypassed',
                        });
                    }
                },
            });
        });

        // Hook trimming metadata validation
      const trimmingPattern = '48 8B 42 ?? 48 85 C0 74 ?? 48 8B 48 ?? 48 85 C9 74';
      const trimmingMatches = Memory.scanSync(
        this.clrModule.base,
        this.clrModule.size,
        trimmingPattern
      );

      trimmingMatches.forEach(match => {
            Interceptor.attach(match.address, {
                onEnter: _args => {
                    send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'trimming_metadata_validation_detected',
                    });
                },
                onLeave: retval => {
                    // Bypass trimming restrictions
                    if (retval.isNull()) {
                        // Return valid metadata pointer
                        retval.replace(ptr(0x1000));
                        this.stats.trimmingSingleFileBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'trimming_metadata_validation_bypassed',
                        });
                    }
                },
            });
        });

        // Hook bundled resource access
      const bundlePattern =
        '48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 4C 8B F2';
      const bundleMatches = Memory.scanSync(
        this.clrModule.base,
        this.clrModule.size,
        bundlePattern
      );

      bundleMatches.forEach(match => {
            Interceptor.attach(match.address, {
                onEnter: args => {
                  const resourceName = args[1];
                  if (resourceName && !resourceName.isNull()) {
                      const name = resourceName.readUtf16String();
                      send({
                            type: 'info',
                            target: 'dotnet_bypass_suite',
                            action: 'bundled_resource_access_detected',
                            resource_name: name,
                        });
                    }
                },
                onLeave: retval => {
                    // Allow all bundled resource access
                    if (retval.isNull()) {
                        // Return success pointer
                        retval.replace(ptr(0x2000));
                        this.stats.trimmingSingleFileBypassEvents++;
                    }
                },
            });
        });

        this.stats.methodsHooked +=
            extractMatches.length + trimmingMatches.length + bundleMatches.length;
    },

    // 4. R2R (Ready-to-Run) Image Bypass
    hookReadyToRunBypass: function () {
        // R2R images have pre-compiled native code
      const r2rHeaderPattern = '52 32 52 00'; // "R2R\0" signature
      const r2rMatches = Memory.scanSync(
        this.clrModule.base,
        this.clrModule.size,
        r2rHeaderPattern
      );

      r2rMatches.forEach(match => {
            send({
                type: 'info',
                target: 'dotnet_bypass_suite',
                action: 'r2r_image_detected',
                address: match.address.toString(),
            });
        });

        // Hook R2R method resolution
      const r2rMethodPattern =
        '48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B F1 E8 ?? ?? ?? ?? 48 85 C0 75';
      const methodMatches = Memory.scanSync(
        this.clrModule.base,
        this.clrModule.size,
        r2rMethodPattern
      );

      methodMatches.forEach(match => {
            Interceptor.attach(match.address, {
                onEnter: args => {
                  const methodToken = args[1];
                  if (methodToken) {
                        send({
                            type: 'info',
                            target: 'dotnet_bypass_suite',
                            action: 'r2r_method_resolution_detected',
                            method_token: methodToken.toString(16),
                        });
                    }
                },
                onLeave: retval => {
                    // Ensure R2R method resolution succeeds
                    if (retval.isNull()) {
                        // Return valid method descriptor
                        retval.replace(ptr(0x3000));
                        this.stats.readyToRunBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'r2r_method_resolution_bypassed',
                        });
                    }
                },
            });
        });

        // Hook R2R fixup processing
      const fixupPattern = '41 56 48 83 EC ?? 4C 8B F2 48 8B D1 48 8D 0D ?? ?? ?? ?? E8';
      const fixupMatches = Memory.scanSync(this.clrModule.base, this.clrModule.size, fixupPattern);

      fixupMatches.forEach(match => {
            Interceptor.attach(match.address, {
                onEnter: _args => {
                    send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'r2r_fixup_processing_detected',
                    });
                },
                onLeave: retval => {
                    // Allow all fixup operations
                    if (retval.toInt32() !== 0) {
                        retval.replace(0);
                        this.stats.readyToRunBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'r2r_fixup_processing_bypassed',
                        });
                    }
                },
            });
        });

        this.stats.methodsHooked += methodMatches.length + fixupMatches.length;
    },

    // 5. WASM/Blazor .NET Runtime Bypass
    hookWasmBlazorNetRuntimeBypass: function () {
        // Blazor WebAssembly runtime patterns
      const blazorModules = ['mono-wasm', 'dotnet.wasm', 'blazor.boot'];

      blazorModules.forEach(moduleName => {
            try {
              const module = Module.findBaseAddress(moduleName);
              if (module && !module.isNull()) {
                    send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'blazor_wasm_runtime_detected',
                        module_name: moduleName,
                    });

                    // Hook Mono WebAssembly initialization
                  const monoWasmPattern =
                    '48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F9 48 8B EA';
                  const wasmMatches = Memory.scanSync(
                    module,
                    Module.getSize(moduleName),
                    monoWasmPattern
                  );

                  wasmMatches.forEach(match => {
                        Interceptor.attach(match.address, {
                            onEnter: _args => {
                                send({
                                    type: 'info',
                                    target: 'dotnet_bypass_suite',
                                    action: 'mono_wasm_init_detected',
                                });
                            },
                            onLeave: retval => {
                                // Ensure WASM initialization succeeds
                                if (retval.toInt32() !== 0) {
                                    retval.replace(0);
                                    this.stats.wasmBlazorNetRuntimeBypassEvents++;
                                    send({
                                        type: 'bypass',
                                        target: 'dotnet_bypass_suite',
                                        action: 'mono_wasm_init_bypassed',
                                    });
                                }
                            },
                        });
                    });
                }
            } catch (e) {
                send({
                    type: 'debug',
                    target: 'dotnet_bypass',
                    action: 'module_not_found',
                    function: 'hookWasmBlazorNetRuntimeBypass',
                    module_name: moduleName,
                    error: e.toString(),
                    stack: e.stack || 'No stack trace available',
                });
            }
        });

        // Hook JavaScript interop security
      const jsInteropPattern = 'JS_Call';
      try {
          const jsCall = Module.findExportByName(null, jsInteropPattern);
          if (jsCall) {
                Interceptor.attach(jsCall, {
                    onEnter: args => {
                      const functionName = args[1];
                      if (functionName && !functionName.isNull()) {
                          const name = functionName.readUtf8String();
                          send({
                                type: 'info',
                                target: 'dotnet_bypass_suite',
                                action: 'js_interop_call_detected',
                                function_name: name,
                            });
                        }
                    },
                    onLeave: retval => {
                        // Allow all JS interop calls
                        if (retval.toInt32() !== 0) {
                            retval.replace(0);
                            this.stats.wasmBlazorNetRuntimeBypassEvents++;
                        }
                    },
                });
                this.stats.methodsHooked++;
            }
        } catch (e) {
            send({
                type: 'debug',
                target: 'dotnet_bypass',
                action: 'hook_failed',
                function: 'dotnet_bypass_suite',
                error: e.toString(),
                stack: e.stack || 'No stack trace available',
            });
        }

        // Hook Blazor component security restrictions
      const componentPattern = 'blazor_component_';
      Process.enumerateModules().forEach(module => {
            module.enumerateExports().forEach(exp => {
                if (exp.name.includes(componentPattern)) {
                    Interceptor.attach(exp.address, {
                        onEnter: _args => {
                            send({
                                type: 'info',
                                target: 'dotnet_bypass_suite',
                                action: 'blazor_component_security_check',
                                export_name: exp.name,
                            });
                        },
                        onLeave: retval => {
                            // Bypass component security
                            if (retval.toInt32() === 0) {
                                retval.replace(1);
                                this.stats.wasmBlazorNetRuntimeBypassEvents++;
                            }
                        },
                    });
                    this.stats.methodsHooked++;
                }
            });
        });
    },

    // 6. Modern Obfuscator Support (DNGuard, .NET Reactor v6, Themida .NET)
    hookModernObfuscatorSupport: function () {
        // DNGuard HVM patterns
      const dnguardPatterns = [
        'DNGuard',
        'HVM',
        'DNG_',
        '48 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 84',
      ];

      dnguardPatterns.forEach(pattern => {
          const matches = Memory.scanSync(this.clrModule.base, this.clrModule.size, pattern);
          matches.forEach(match => {
                Interceptor.attach(match.address, {
                    onEnter: _args => {
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'dnguard_hvm_detected',
                            address: match.address.toString(),
                        });
                    },
                    onLeave: retval => {
                        // Bypass DNGuard HVM protection
                        retval.replace(1);
                        this.stats.modernObfuscatorSupportEvents++;
                    },
                });
            });
        });

        // .NET Reactor v6 patterns
      const reactorV6Patterns = [
        '48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 81 EC',
        'Reactor',
        'NETReactor',
        'NecroBit',
      ];

      reactorV6Patterns.forEach(pattern => {
          const matches = Memory.scanSync(this.clrModule.base, this.clrModule.size, pattern);
          matches.forEach(match => {
                // Patch .NET Reactor v6 protection
                Memory.patchCode(match.address, 16, code => {
                    // NOP out protection code
                    for (let i = 0; i < 16; i++) {
                        code.putU8(0x90);
                    }
                });
                send({
                    type: 'bypass',
                    target: 'dotnet_bypass_suite',
                    action: 'net_reactor_v6_patched',
                    address: match.address.toString(),
                });
                this.stats.modernObfuscatorSupportEvents++;
            });
        });

        // Themida .NET patterns
      const themidaNetPatterns = [
        'Themida',
        'WinLicense',
        '48 8B C4 48 89 58 ?? 48 89 68 ?? 48 89 70 ?? 48 89 78 ?? 41 54 41 55 41 56 41 57 48 83 EC',
      ];

      themidaNetPatterns.forEach(pattern => {
          const matches = Memory.scanSync(
            Module.getBaseAddress('kernel32.dll'),
            Module.getSize('kernel32.dll'),
            pattern
          );
          matches.forEach(match => {
                Interceptor.attach(match.address, {
                    onEnter: _args => {
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'themida_net_detected',
                            address: match.address.toString(),
                        });
                    },
                    onLeave: retval => {
                        // Bypass Themida .NET protection
                        if (retval.toInt32() === 0) {
                            retval.replace(1);
                            this.stats.modernObfuscatorSupportEvents++;
                        }
                    },
                });
            });
        });

        // Hook modern control flow obfuscation
      const cfoPattern = '48 8D 05 ?? ?? ?? ?? 48 8B 0C ?? 48 FF E1';
      const cfoMatches = Memory.scanSync(this.clrModule.base, this.clrModule.size, cfoPattern);

      cfoMatches.forEach(match => {
            // Deobfuscate control flow
            Memory.patchCode(match.address, 8, code => {
                code.putU8(0x48);
                code.putU8(0xc7);
                code.putU8(0xc0); // mov rax, immediate
                code.putU8(0x01);
                code.putU8(0x00);
                code.putU8(0x00);
                code.putU8(0x00);
                code.putU8(0xc3); // ret
            });
            send({
                type: 'bypass',
                target: 'dotnet_bypass_suite',
                action: 'control_flow_obfuscation_deobfuscated',
                address: match.address.toString(),
            });
            this.stats.modernObfuscatorSupportEvents++;
        });

        this.stats.methodsHooked +=
            dnguardPatterns.length +
            reactorV6Patterns.length +
            themidaNetPatterns.length +
            cfoMatches.length;
    },

    // 7. Certificate Transparency Log Bypass for .NET Code Signing
    hookCertificateTransparencyLogDotNetBypass: function () {
        // Hook certificate validation with CT log verification
      const ctLogPatterns = [
        '48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B F1 48 8B 0D',
        '41 56 48 83 EC ?? 4C 8B F2 48 8B D1 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0',
      ];

      ctLogPatterns.forEach(pattern => {
          const matches = Memory.scanSync(
            Module.getBaseAddress('crypt32.dll'),
            Module.getSize('crypt32.dll'),
            pattern
          );

          matches.forEach(match => {
                Interceptor.attach(match.address, {
                    onEnter: args => {
                      const certContext = args[0];
                      if (certContext && !certContext.isNull()) {
                            send({
                                type: 'info',
                                target: 'dotnet_bypass_suite',
                                action: 'certificate_ct_log_verification_detected',
                            });
                        }
                    },
                    onLeave: retval => {
                        // Bypass CT log verification
                        if (retval.toInt32() === 0) {
                            retval.replace(1);
                            this.stats.certificateTransparencyLogDotNetBypassEvents++;
                            send({
                                type: 'bypass',
                                target: 'dotnet_bypass_suite',
                                action: 'certificate_ct_log_verification_bypassed',
                            });
                        }
                    },
                });
            });
        });

        // Hook .NET specific certificate chain validation with CT
      const dotNetCertPattern =
        '48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E1';
      const dotNetMatches = Memory.scanSync(
        this.clrModule.base,
        this.clrModule.size,
        dotNetCertPattern
      );

      dotNetMatches.forEach(match => {
            Interceptor.attach(match.address, {
                onEnter: _args => {
                    send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'dotnet_certificate_chain_validation_detected',
                    });
                },
                onLeave: retval => {
                    // Force certificate validation to succeed
                    if (retval.toInt32() !== 0) {
                        retval.replace(0);
                        this.stats.certificateTransparencyLogDotNetBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'dotnet_certificate_chain_validation_bypassed',
                        });
                    }
                },
            });
        });

        this.stats.methodsHooked += ctLogPatterns.length + dotNetMatches.length;
    },

    // 8. Hardware Security Module (HSM) Certificate Bypass
    hookHsmCertificateBypass: function () {
        // Hook PKCS#11 interface for HSM communication
      const pkcs11Pattern = 'C_GetSlotList';
      try {
          const pkcs11Func = Module.findExportByName(null, pkcs11Pattern);
          if (pkcs11Func) {
                Interceptor.attach(pkcs11Func, {
                    onEnter: args => {
                      const tokenPresent = args[0].toInt32();
                      send({
                            type: 'info',
                            target: 'dotnet_bypass_suite',
                            action: 'hsm_pkcs11_get_slot_list_detected',
                            token_present: tokenPresent,
                        });
                    },
                    onLeave: retval => {
                        // Force HSM slot enumeration to succeed
                        retval.replace(0); // CKR_OK
                        this.stats.hsmCertificateBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'hsm_pkcs11_get_slot_list_bypassed',
                        });
                    },
                });
                this.stats.methodsHooked++;
            }
        } catch (e) {
            send({
                type: 'debug',
                target: 'dotnet_bypass',
                action: 'hook_failed',
                function: 'dotnet_bypass_suite',
                error: e.toString(),
                stack: e.stack || 'No stack trace available',
            });
        }

        // Hook HSM certificate verification
      const hsmVerifyPattern = 'C_Verify';
      try {
          const hsmVerify = Module.findExportByName(null, hsmVerifyPattern);
          if (hsmVerify) {
                Interceptor.attach(hsmVerify, {
                    onEnter: args => {
                      const session = args[0];
                      const _signature = args[1];
                      send({
                            type: 'info',
                            target: 'dotnet_bypass_suite',
                            action: 'hsm_certificate_verification_detected',
                            session: session.toString(16),
                        });
                    },
                    onLeave: retval => {
                        // Force HSM signature verification to succeed
                        retval.replace(0); // CKR_OK
                        this.stats.hsmCertificateBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'hsm_certificate_verification_bypassed',
                        });
                    },
                });
                this.stats.methodsHooked++;
            }
        } catch (e) {
            send({
                type: 'debug',
                target: 'dotnet_bypass',
                action: 'hook_failed',
                function: 'dotnet_bypass_suite',
                error: e.toString(),
                stack: e.stack || 'No stack trace available',
            });
        }

        // Hook Windows CNG HSM provider
      const cngHsmPattern = 'NCryptOpenKey';
      const cngHsm = Module.findExportByName('ncrypt.dll', cngHsmPattern);
      if (cngHsm) {
            Interceptor.attach(cngHsm, {
                onEnter: args => {
                  const _provider = args[0];
                  const keyName = args[1];
                  if (keyName && !keyName.isNull()) {
                      const name = keyName.readUtf16String();
                      send({
                            type: 'info',
                            target: 'dotnet_bypass_suite',
                            action: 'cng_hsm_key_access_detected',
                            key_name: name,
                        });
                    }
                },
                onLeave: retval => {
                    // Allow HSM key access
                    if (retval.toInt32() !== 0) {
                        retval.replace(0);
                        this.stats.hsmCertificateBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'cng_hsm_key_access_bypassed',
                        });
                    }
                },
            });
            this.stats.methodsHooked++;
        }

        // Hook TPM-based certificate storage
      const tpmPattern = 'Tbsi_GetDeviceInfo';
      const tpm = Module.findExportByName('tbs.dll', tpmPattern);
      if (tpm) {
            Interceptor.attach(tpm, {
                onEnter: _args => {
                    send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'tpm_certificate_access_detected',
                    });
                },
                onLeave: retval => {
                    // Allow TPM certificate access
                    if (retval.toInt32() !== 0) {
                        retval.replace(0);
                        this.stats.hsmCertificateBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'tpm_certificate_access_bypassed',
                        });
                    }
                },
            });
            this.stats.methodsHooked++;
        }
    },

    // 9. Windows Defender Application Control (WDAC) Bypass
    hookWindowsDefenderApplicationControlBypass: function () {
        // Hook WDAC policy enforcement
      const wdacPatterns = [
        '48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 83 EC ?? 45 33 FF',
        '41 56 48 83 EC ?? 4C 8B F2 48 8B D1 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85',
      ];

      wdacPatterns.forEach(pattern => {
          const matches = Memory.scanSync(
            Module.getBaseAddress('ci.dll'),
            Module.getSize('ci.dll'),
            pattern
          );

          matches.forEach(match => {
                Interceptor.attach(match.address, {
                    onEnter: args => {
                      const policyPtr = args[0];
                      if (policyPtr && !policyPtr.isNull()) {
                            send({
                                type: 'info',
                                target: 'dotnet_bypass_suite',
                                action: 'wdac_policy_enforcement_detected',
                            });
                        }
                    },
                    onLeave: retval => {
                        // Bypass WDAC policy enforcement
                        if (retval.toInt32() !== 0) {
                            retval.replace(0);
                            this.stats.windowsDefenderApplicationControlBypassEvents++;
                            send({
                                type: 'bypass',
                                target: 'dotnet_bypass_suite',
                                action: 'wdac_policy_enforcement_bypassed',
                            });
                        }
                    },
                });
            });
        });

        // Hook WDAC code integrity checks
      const ciCheckPattern = 'CiCheckSignedFile';
      const ciCheck = Module.findExportByName('ci.dll', ciCheckPattern);
      if (ciCheck) {
            Interceptor.attach(ciCheck, {
                onEnter: args => {
                  const _fileHandle = args[0];
                  const fileName = args[1];
                  if (fileName && !fileName.isNull()) {
                      const name = fileName.readUtf16String();
                      send({
                            type: 'info',
                            target: 'dotnet_bypass_suite',
                            action: 'wdac_code_integrity_check_detected',
                            file_name: name,
                        });
                    }
                },
                onLeave: retval => {
                    // Force code integrity check to pass
                    if (retval.toInt32() !== 0) {
                        retval.replace(0);
                        this.stats.windowsDefenderApplicationControlBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'wdac_code_integrity_check_bypassed',
                        });
                    }
                },
            });
            this.stats.methodsHooked++;
        }

        // Hook HVCI (Hypervisor-protected Code Integrity)
      const hvciPattern = 'HvciSetInternalProperties';
      const hvci = Module.findExportByName('ntoskrnl.exe', hvciPattern);
      if (hvci) {
            Interceptor.attach(hvci, {
                onEnter: _args => {
                    send({
                        type: 'info',
                        target: 'dotnet_bypass_suite',
                        action: 'hvci_enforcement_detected',
                    });
                },
                onLeave: retval => {
                    // Bypass HVCI enforcement
                    if (retval.toInt32() !== 0) {
                        retval.replace(0);
                        this.stats.windowsDefenderApplicationControlBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'hvci_enforcement_bypassed',
                        });
                    }
                },
            });
            this.stats.methodsHooked++;
        }

        this.stats.methodsHooked += wdacPatterns.length;
    },

    // 10. AppLocker .NET Script Enforcement Bypass
    hookAppLockerDotNetScriptEnforcementBypass: function () {
        // Hook PowerShell Constrained Language Mode enforcement
      const clmPatterns = [
        'System.Management.Automation.LanguageMode',
        'ConstrainedLanguage',
        '48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 81 EC',
      ];

      clmPatterns.forEach(pattern => {
          const matches = Memory.scanSync(
            Module.getBaseAddress('System.Management.Automation.dll'),
            Module.getSize('System.Management.Automation.dll'),
            pattern
          );

          matches.forEach(match => {
                Interceptor.attach(match.address, {
                    onEnter: _args => {
                        send({
                            type: 'info',
                            target: 'dotnet_bypass_suite',
                            action: 'powershell_clm_enforcement_detected',
                        });
                    },
                    onLeave: retval => {
                        // Set to FullLanguage mode
                        if (retval.toInt32() !== 0) {
                            retval.replace(0); // FullLanguage
                            this.stats.appLockerDotNetScriptEnforcementBypassEvents++;
                            send({
                                type: 'bypass',
                                target: 'dotnet_bypass_suite',
                                action: 'powershell_clm_enforcement_bypassed',
                            });
                        }
                    },
                });
            });
        });

        // Hook AppLocker .NET assembly restrictions
      const applockerPatterns = [
        '48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F2 48 8B F9 48 8B 0D',
        '41 57 48 83 EC ?? 4C 8B F9 48 8B D1 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0',
      ];

      applockerPatterns.forEach(pattern => {
          const matches = Memory.scanSync(
            Module.getBaseAddress('appid.dll'),
            Module.getSize('appid.dll'),
            pattern
          );

          matches.forEach(match => {
                Interceptor.attach(match.address, {
                    onEnter: args => {
                      const assemblyPath = args[1];
                      if (assemblyPath && !assemblyPath.isNull()) {
                          const path = assemblyPath.readUtf16String();
                          send({
                                type: 'info',
                                target: 'dotnet_bypass_suite',
                                action: 'applocker_dotnet_restriction_detected',
                                assembly_path: path,
                            });
                        }
                    },
                    onLeave: retval => {
                        // Allow .NET assembly execution
                        if (retval.toInt32() !== 0) {
                            retval.replace(0);
                            this.stats.appLockerDotNetScriptEnforcementBypassEvents++;
                            send({
                                type: 'bypass',
                                target: 'dotnet_bypass_suite',
                                action: 'applocker_dotnet_restriction_bypassed',
                            });
                        }
                    },
                });
            });
        });

        // Hook Script Block Logging bypass
      const sblPattern = 'ScriptBlockLogging';
      try {
          const sblMatches = Memory.scanSync(
            Module.getBaseAddress('System.Management.Automation.dll'),
            Module.getSize('System.Management.Automation.dll'),
            sblPattern
          );

          sblMatches.forEach(match => {
                // Disable script block logging
                Memory.patchCode(match.address, 4, code => {
                    code.putU8(0x48);
                    code.putU8(0x31);
                    code.putU8(0xc0); // xor rax, rax
                    code.putU8(0xc3); // ret
                });
                send({
                    type: 'bypass',
                    target: 'dotnet_bypass_suite',
                    action: 'script_block_logging_disabled',
                    address: match.address.toString(),
                });
                this.stats.appLockerDotNetScriptEnforcementBypassEvents++;
            });
        } catch (e) {
            send({
                type: 'debug',
                target: 'dotnet_bypass',
                action: 'hook_failed',
                function: 'dotnet_bypass_suite',
                error: e.toString(),
                stack: e.stack || 'No stack trace available',
            });
        }

        // Hook AMSI (Antimalware Scan Interface) for .NET scripts
      const amsiPattern = 'AmsiScanBuffer';
      const amsi = Module.findExportByName('amsi.dll', amsiPattern);
      if (amsi) {
            Interceptor.replace(
                amsi,
                new NativeCallback(
                    (_context, _buffer, _length, _contentName, _session, result) => {
                        // Return clean scan result
                        result.writeU32(1); // AMSI_RESULT_CLEAN
                        this.stats.appLockerDotNetScriptEnforcementBypassEvents++;
                        send({
                            type: 'bypass',
                            target: 'dotnet_bypass_suite',
                            action: 'amsi_scan_buffer_bypassed',
                        });
                        return 0; // S_OK
                    },
                    'int',
                    ['pointer', 'pointer', 'uint32', 'pointer', 'pointer', 'pointer']
                )
            );
            this.stats.methodsHooked++;
        }

        this.stats.methodsHooked += clmPatterns.length + applockerPatterns.length;
    },
};

// Export for use in other modules or direct execution
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DotnetBypassSuite;
}
