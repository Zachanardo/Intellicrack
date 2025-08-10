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

// Production-grade Windows Registry monitor for Frida
// Comprehensive monitoring with Native API hooks, anti-detection, and intelligent data analysis
'use strict';

if (Process.platform !== 'windows') {
  send({ type: 'error', target: 'registry_monitor', message: 'Unsupported platform', platform: Process.platform });
  return;
}

const config = {
  keyFilters: [
    '\\software\\',
    'windows nt\\currentversion',
    'licens',
    'activation',
    'adobe',
    'autodesk',
    'product',
    'machineguid',
    'tokens',
    'security'
  ],
  valueFilters: [
    'licens',
    'key',
    'serial',
    'token',
    'machineguid',
    'productid',
    'activation',
    'hwid'
  ],
  captureValuePreviewBytes: 256,
  includeBacktraceOnMatch: false,
  logFailures: true,
  enableNativeApiHooks: true,
  enableStealthMode: true,
  performanceThrottleMs: 5,
  maxEventsPerSecond: 1000
};

recv('registry_monitor_config', function onCfg(message) {
  try {
    const p = message.payload || {};
    if (Array.isArray(p.keyFilters)) config.keyFilters = p.keyFilters.map(s => String(s).toLowerCase());
    if (Array.isArray(p.valueFilters)) config.valueFilters = p.valueFilters.map(s => String(s).toLowerCase());
    if (typeof p.captureValuePreviewBytes === 'number') config.captureValuePreviewBytes = Math.max(0, p.captureValuePreviewBytes | 0);
    if (typeof p.includeBacktraceOnMatch === 'boolean') config.includeBacktraceOnMatch = p.includeBacktraceOnMatch;
    if (typeof p.logFailures === 'boolean') config.logFailures = p.logFailures;
    if (typeof p.enableNativeApiHooks === 'boolean') config.enableNativeApiHooks = p.enableNativeApiHooks;
    if (typeof p.enableStealthMode === 'boolean') config.enableStealthMode = p.enableStealthMode;
    if (typeof p.performanceThrottleMs === 'number') config.performanceThrottleMs = Math.max(0, p.performanceThrottleMs);
    if (typeof p.maxEventsPerSecond === 'number') config.maxEventsPerSecond = Math.max(10, p.maxEventsPerSecond);
    send({ type: 'info', target: 'registry_monitor', event: 'config_updated', config });
  } catch (e) {
    send({ type: 'error', target: 'registry_monitor', message: 'config_update_failed', error: String(e) });
  }
  recv('registry_monitor_config', onCfg);
}).wait();

// Performance throttling state
const performance = {
  eventCount: 0,
  lastSecond: Math.floor(Date.now() / 1000),
  lastEventTime: 0
};

// Registry constants
const REG_NONE = 0;
const REG_SZ = 1;
const REG_EXPAND_SZ = 2;
const REG_BINARY = 3;
const REG_DWORD = 4;
const REG_DWORD_BIG_ENDIAN = 5;
const REG_LINK = 6;
const REG_MULTI_SZ = 7;
const REG_RESOURCE_LIST = 8;
const REG_FULL_RESOURCE_DESCRIPTOR = 9;
const REG_RESOURCE_REQUIREMENTS_LIST = 10;
const REG_QWORD = 11;

const LSTATUS_MAP = {
  0: 'ERROR_SUCCESS',
  2: 'ERROR_FILE_NOT_FOUND',
  5: 'ERROR_ACCESS_DENIED',
  6: 'ERROR_INVALID_HANDLE',
  87: 'ERROR_INVALID_PARAMETER',
  234: 'ERROR_MORE_DATA',
  259: 'ERROR_NO_MORE_ITEMS'
};

const NT_STATUS_MAP = {
  0x00000000: 'STATUS_SUCCESS',
  0xC0000034: 'STATUS_OBJECT_NAME_NOT_FOUND',
  0xC0000022: 'STATUS_ACCESS_DENIED',
  0xC000000D: 'STATUS_INVALID_PARAMETER'
};

const predefinedRoots = new Map([
  ['0x80000000', 'HKEY_CLASSES_ROOT'],
  ['0x80000001', 'HKEY_CURRENT_USER'],
  ['0x80000002', 'HKEY_LOCAL_MACHINE'],
  ['0x80000003', 'HKEY_USERS'],
  ['0x80000004', 'HKEY_PERFORMANCE_DATA'],
  ['0x80000005', 'HKEY_CURRENT_CONFIG'],
  ['0x80000006', 'HKEY_DYN_DATA']
]);

const handlePaths = new Map();

function norm(s) {
  return (s || '').toLowerCase();
}

function readW(ptr) {
  try { if (ptr && !ptr.isNull()) return ptr.readUtf16String(); } catch (_) {}
  return null;
}

function readA(ptr) {
  try { if (ptr && !ptr.isNull()) return ptr.readAnsiString(); } catch (_) {}
  return null;
}

function readDword(ptr) {
  try { if (ptr && !ptr.isNull()) return ptr.readU32(); } catch (_) {}
  return null;
}

function readQword(ptr) {
  try { if (ptr && !ptr.isNull()) return ptr.readU64(); } catch (_) {}
  return null;
}

function readUnicodeString(ptr) {
  try {
    if (!ptr || ptr.isNull()) return null;
    const length = ptr.readU16();
    const buffer = ptr.add(Process.pointerSize === 8 ? 16 : 8).readPointer();
    return buffer.readUtf16String(length / 2);
  } catch (_) {}
  return null;
}

function rootForHandle(hKeyPtr) {
  if (!hKeyPtr) return null;
  const key = hKeyPtr.toString();
  if (predefinedRoots.has(key)) return predefinedRoots.get(key);
  if (handlePaths.has(key)) return handlePaths.get(key);
  return `UNKNOWN(${key})`;
}

function buildPath(hKeyPtr, subKeyStr) {
  const base = rootForHandle(hKeyPtr);
  if (subKeyStr && subKeyStr.length > 0) return `${base}\\${subKeyStr}`;
  return base;
}

function matchesFilters(fullKeyPath, valueName) {
  const k = norm(fullKeyPath);
  const v = norm(valueName || '');
  const keyHit = config.keyFilters.some(f => k.includes(f));
  const valHit = v.length > 0 && config.valueFilters.some(f => v.includes(f));
  return keyHit || valHit;
}

function shouldThrottle() {
  const now = Date.now();
  const currentSecond = Math.floor(now / 1000);

  if (currentSecond !== performance.lastSecond) {
    performance.eventCount = 0;
    performance.lastSecond = currentSecond;
  }

  if (performance.eventCount >= config.maxEventsPerSecond) {
    return true;
  }

  if (config.performanceThrottleMs > 0 && (now - performance.lastEventTime) < config.performanceThrottleMs) {
    return true;
  }

  performance.eventCount++;
  performance.lastEventTime = now;
  return false;
}

function symbolAt(addr) {
  try { return DebugSymbol.fromAddress(addr).toString(); } catch (_) { return null; }
}

function formatRegData(regType, dataPtr, dataSize, previewOnly = false) {
  if (!dataPtr || dataPtr.isNull() || !dataSize) return { formatted: null, raw: null };

  const size = typeof dataSize === 'number' ? dataSize : dataSize.toInt32();
  if (size <= 0 || size > config.captureValuePreviewBytes) return { formatted: null, raw: null };

  try {
    let formatted = null;
    let raw = null;

    switch (regType) {
      case REG_SZ:
      case REG_EXPAND_SZ:
        formatted = `"${dataPtr.readUtf16String(size / 2)}"`;
        break;

      case REG_DWORD:
        if (size >= 4) {
          const val = dataPtr.readU32();
          formatted = `0x${val.toString(16)} (${val})`;
        }
        break;

      case REG_QWORD:
        if (size >= 8) {
          const val = dataPtr.readU64();
          formatted = `0x${val.toString(16)} (${val})`;
        }
        break;

      case REG_MULTI_SZ:
        try {
          const strings = [];
          let offset = 0;
          while (offset < size - 2) {
            const str = dataPtr.add(offset).readUtf16String();
            if (!str) break;
            strings.push(str);
            offset += (str.length + 1) * 2;
          }
          formatted = `[${strings.map(s => `"${s}"`).join(', ')}]`;
        } catch (_) {}
        break;

      case REG_BINARY:
      default:
        // Try to detect common patterns
        if (size === 16) {
          // Possible GUID
          const bytes = dataPtr.readByteArray(16);
          if (bytes) {
            const arr = new Uint8Array(bytes);
            const guid = [
              arr.slice(0, 4).reverse(),
              arr.slice(4, 6).reverse(),
              arr.slice(6, 8).reverse(),
              arr.slice(8, 10),
              arr.slice(10, 16)
            ].map(chunk => Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join('')).join('-');
            formatted = `GUID: {${guid}}`;
          }
        } else if (size === 8) {
          // Possible timestamp (FILETIME)
          const low = dataPtr.readU32();
          const high = dataPtr.add(4).readU32();
          const filetime = high * 0x100000000 + low;
          if (filetime > 0) {
            const unixTime = (filetime - 116444736000000000) / 10000;
            if (unixTime > 0 && unixTime < Date.now() * 2) {
              formatted = `Timestamp: ${new Date(unixTime).toISOString()}`;
            }
          }
        } else if (size >= 4 && size <= 64) {
          // Check if it's printable ASCII/UTF-16
          let isPrintable = true;
          for (let i = 0; i < Math.min(size, 32); i += 2) {
            const char = dataPtr.add(i).readU16();
            if (char === 0) break;
            if (char < 32 || char > 126) {
              isPrintable = false;
              break;
            }
          }
          if (isPrintable) {
            try {
              const str = dataPtr.readUtf16String(size / 2);
              if (str && str.length > 0) formatted = `String: "${str}"`;
            } catch (_) {}
          }
        }

        // Always capture raw bytes for binary data
        const bytes = dataPtr.readByteArray(Math.min(size, previewOnly ? 32 : size));
        if (bytes) {
          const hex = Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, '0')).join(' ');
          raw = hex;
        }
        break;
    }

    return { formatted, raw };
  } catch (_) {
    return { formatted: null, raw: null };
  }
}

function sendEvent(e, includeBt) {
  if (shouldThrottle()) return;

  const evt = Object.assign({
    type: 'info',
    target: 'registry_monitor',
    pid: Process.id,
    timestamp: Date.now(),
    module: Process.enumerateModules()[0]?.name || null
  }, e);

  if (includeBt) {
    try {
      evt.backtrace = Thread.backtrace(e.context || null, Backtracer.ACCURATE)
        .slice(0, 10)
        .map(a => symbolAt(a))
        .filter(s => s);
    } catch (_) {}
  }
  send(evt);
}

function tryAttach(moduleName, exportName, callbacks) {
  try {
    const addr = Module.findExportByName(moduleName, exportName);
    if (!addr) return false;

    if (config.enableStealthMode) {
      // Add slight randomization to avoid detection
      const delay = Math.floor(Math.random() * 5);
      if (delay > 0) {
        setTimeout(() => {
          try {
            Interceptor.attach(addr, callbacks);
          } catch (_) {}
        }, delay);
      } else {
        Interceptor.attach(addr, callbacks);
      }
    } else {
      Interceptor.attach(addr, callbacks);
    }
    return true;
  } catch (_) {
    return false;
  }
}

function attachVariants(baseName, callbacksA, callbacksW) {
  tryAttach('advapi32.dll', baseName + 'A', callbacksA);
  tryAttach('advapi32.dll', baseName + 'W', callbacksW);
}

function decodeWow64(samDesired) {
  const out = { wow64_view: null };
  if (samDesired == null) return out;
  if (samDesired & 0x0100) out.wow64_view = '64';
  else if (samDesired & 0x0200) out.wow64_view = '32';
  return out;
}

function attachNativeApiHooks() {
  if (!config.enableNativeApiHooks) return;

  // NtOpenKeyEx
  tryAttach('ntdll.dll', 'NtOpenKeyEx', {
    onEnter(args) {
      this.keyHandlePtr = args[0];
      this.desiredAccess = args[1].toUInt32();

      const objectAttrs = args[2];
      if (!objectAttrs || objectAttrs.isNull()) return;

      try {
        const objectNamePtr = objectAttrs.add(Process.pointerSize === 8 ? 16 : 8).readPointer();
        const rootHandle = objectAttrs.add(Process.pointerSize === 8 ? 8 : 4).readPointer();

        let objectName = readUnicodeString(objectNamePtr) || '';
        let fullPath = objectName;

        if (!rootHandle.isNull()) {
          const rootPath = handlePaths.get(rootHandle.toString());
          if (rootPath) {
            fullPath = rootPath + '\\' + objectName;
          } else {
            const predefinedRoot = predefinedRoots.get(rootHandle.toString());
            if (predefinedRoot) {
              fullPath = predefinedRoot + '\\' + objectName;
            } else {
              fullPath = `[HANDLE_${rootHandle}]\\${objectName}`;
            }
          }
        }

        this.fullPath = fullPath;
      } catch (_) {
        this.fullPath = '[PARSE_ERROR]';
      }
    },
    onLeave(retval) {
      const status = retval.toUInt32();
      const statusStr = NT_STATUS_MAP[status] || `NTSTATUS_0x${status.toString(16)}`;
      const success = status === 0;

      if (success && this.keyHandlePtr && !this.keyHandlePtr.isNull()) {
        try {
          const newHandle = this.keyHandlePtr.readPointer();
          handlePaths.set(newHandle.toString(), this.fullPath);
        } catch (_) {}
      }

      if ((success && matchesFilters(this.fullPath)) || (!success && config.logFailures)) {
        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(this.fullPath);
        sendEvent({
          event: 'open_key',
          api: 'NtOpenKeyEx',
          key_path: this.fullPath,
          status: statusStr,
          success,
          desired_access: `0x${this.desiredAccess.toString(16)}`,
          ...decodeWow64(this.desiredAccess)
        }, includeBt);
      }
    }
  });

  // NtCreateKeyEx
  tryAttach('ntdll.dll', 'NtCreateKeyEx', {
    onEnter(args) {
      this.keyHandlePtr = args[0];
      this.desiredAccess = args[1].toUInt32();

      const objectAttrs = args[2];
      if (!objectAttrs || objectAttrs.isNull()) return;

      try {
        const objectNamePtr = objectAttrs.add(Process.pointerSize === 8 ? 16 : 8).readPointer();
        const rootHandle = objectAttrs.add(Process.pointerSize === 8 ? 8 : 4).readPointer();

        let objectName = readUnicodeString(objectNamePtr) || '';
        let fullPath = objectName;

        if (!rootHandle.isNull()) {
          const rootPath = handlePaths.get(rootHandle.toString());
          if (rootPath) {
            fullPath = rootPath + '\\' + objectName;
          } else {
            const predefinedRoot = predefinedRoots.get(rootHandle.toString());
            if (predefinedRoot) {
              fullPath = predefinedRoot + '\\' + objectName;
            } else {
              fullPath = `[HANDLE_${rootHandle}]\\${objectName}`;
            }
          }
        }

        this.fullPath = fullPath;
      } catch (_) {
        this.fullPath = '[PARSE_ERROR]';
      }

      this.dispositionPtr = args[6];
    },
    onLeave(retval) {
      const status = retval.toUInt32();
      const statusStr = NT_STATUS_MAP[status] || `NTSTATUS_0x${status.toString(16)}`;
      const success = status === 0;

      let disposition = null;
      if (success && this.dispositionPtr && !this.dispositionPtr.isNull()) {
        try {
          const dispValue = this.dispositionPtr.readU32();
          disposition = dispValue === 1 ? 'REG_CREATED_NEW_KEY' : 'REG_OPENED_EXISTING_KEY';
        } catch (_) {}
      }

      if (success && this.keyHandlePtr && !this.keyHandlePtr.isNull()) {
        try {
          const newHandle = this.keyHandlePtr.readPointer();
          handlePaths.set(newHandle.toString(), this.fullPath);
        } catch (_) {}
      }

      if ((success && matchesFilters(this.fullPath)) || (!success && config.logFailures)) {
        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(this.fullPath);
        sendEvent({
          event: 'create_key',
          api: 'NtCreateKeyEx',
          key_path: this.fullPath,
          status: statusStr,
          success,
          disposition,
          desired_access: `0x${this.desiredAccess.toString(16)}`,
          ...decodeWow64(this.desiredAccess)
        }, includeBt);
      }
    }
  });

  // NtQueryValueKey
  tryAttach('ntdll.dll', 'NtQueryValueKey', {
    onEnter(args) {
      this.keyHandle = args[0];
      this.valueName = readUnicodeString(args[1]) || '';
      this.infoClass = args[2].toUInt32();
      this.keyValueInfo = args[3];
      this.lengthPtr = args[5];
    },
    onLeave(retval) {
      const status = retval.toUInt32();
      const statusStr = NT_STATUS_MAP[status] || `NTSTATUS_0x${status.toString(16)}`;
      const success = status === 0;
      const keyPath = rootForHandle(this.keyHandle);

      if ((success && matchesFilters(keyPath, this.valueName)) || (!success && config.logFailures)) {
        const evt = {
          event: 'query_value',
          api: 'NtQueryValueKey',
          key_path: keyPath,
          value_name: this.valueName,
          status: statusStr,
          success,
          info_class: this.infoClass
        };

        if (success && this.keyValueInfo && !this.keyValueInfo.isNull()) {
          try {
            // KEY_VALUE_FULL_INFORMATION structure
            const regType = this.keyValueInfo.add(8).readU32();
            const dataLength = this.keyValueInfo.add(16).readU32();
            const dataOffset = this.keyValueInfo.add(20).readU32();

            evt.reg_type = regType;
            evt.data_len = dataLength;

            if (dataLength > 0 && dataOffset > 0) {
              const dataPtr = this.keyValueInfo.add(dataOffset);
              const formatted = formatRegData(regType, dataPtr, dataLength, true);
              if (formatted.formatted) evt.data_formatted = formatted.formatted;
              if (formatted.raw) evt.data_preview_hex = formatted.raw;
            }
          } catch (_) {}
        }

        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(keyPath, this.valueName);
        sendEvent(evt, includeBt);
      }
    }
  });

  // NtSetValueKey
  tryAttach('ntdll.dll', 'NtSetValueKey', {
    onEnter(args) {
      this.keyHandle = args[0];
      this.valueName = readUnicodeString(args[1]) || '';
      this.regType = args[3].toUInt32();
      this.data = args[4];
      this.dataSize = args[5].toUInt32();
    },
    onLeave(retval) {
      const status = retval.toUInt32();
      const statusStr = NT_STATUS_MAP[status] || `NTSTATUS_0x${status.toString(16)}`;
      const success = status === 0;
      const keyPath = rootForHandle(this.keyHandle);

      if ((success && matchesFilters(keyPath, this.valueName)) || (!success && config.logFailures)) {
        const evt = {
          event: 'set_value',
          api: 'NtSetValueKey',
          key_path: keyPath,
          value_name: this.valueName,
          status: statusStr,
          success,
          reg_type: this.regType,
          data_len: this.dataSize
        };

        if (success && this.data && !this.data.isNull() && this.dataSize > 0) {
          const formatted = formatRegData(this.regType, this.data, this.dataSize, true);
          if (formatted.formatted) evt.data_formatted = formatted.formatted;
          if (formatted.raw) evt.data_preview_hex = formatted.raw;
        }

        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(keyPath, this.valueName);
        sendEvent(evt, includeBt);
      }
    }
  });

  // NtDeleteKey
  tryAttach('ntdll.dll', 'NtDeleteKey', {
    onEnter(args) {
      this.keyHandle = args[0];
      this.keyPath = rootForHandle(this.keyHandle);
    },
    onLeave(retval) {
      const status = retval.toUInt32();
      const statusStr = NT_STATUS_MAP[status] || `NTSTATUS_0x${status.toString(16)}`;
      const success = status === 0;

      if ((success && matchesFilters(this.keyPath)) || (!success && config.logFailures)) {
        sendEvent({
          event: 'delete_key',
          api: 'NtDeleteKey',
          key_path: this.keyPath,
          status: statusStr,
          success
        });
      }
    }
  });

  // NtDeleteValueKey
  tryAttach('ntdll.dll', 'NtDeleteValueKey', {
    onEnter(args) {
      this.keyHandle = args[0];
      this.valueName = readUnicodeString(args[1]) || '';
      this.keyPath = rootForHandle(this.keyHandle);
    },
    onLeave(retval) {
      const status = retval.toUInt32();
      const statusStr = NT_STATUS_MAP[status] || `NTSTATUS_0x${status.toString(16)}`;
      const success = status === 0;

      if ((success && matchesFilters(this.keyPath, this.valueName)) || (!success && config.logFailures)) {
        sendEvent({
          event: 'delete_value',
          api: 'NtDeleteValueKey',
          key_path: this.keyPath,
          value_name: this.valueName,
          status: statusStr,
          success
        });
      }
    }
  });
}function attachCoreRegistryHooks() {
  // RegOpenKeyEx with enhanced error handling and status reporting
  attachVariants('RegOpenKeyEx', {
    onEnter(args) {
      this.hKey = args[0];
      this.subKey = readA(args[1]);
      this.samDesired = args[3].toUInt32 ? args[3].toUInt32() : (args[3] >>> 0);
      this.phkResult = args[4];
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const full = buildPath(this.hKey, this.subKey || '');

      if (success && this.phkResult && !this.phkResult.isNull()) {
        try {
          const newHandle = this.phkResult.readPointer();
          handlePaths.set(newHandle.toString(), full);
        } catch (_) {}
      }

      if ((success && matchesFilters(full)) || (!success && config.logFailures)) {
        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(full);
        sendEvent({
          event: 'open_key',
          api: 'RegOpenKeyExA',
          key_path: full,
          status: statusStr,
          success,
          sam_desired: this.samDesired,
          ...decodeWow64(this.samDesired)
        }, includeBt);
      }
    }
  }, {
    onEnter(args) {
      this.hKey = args[0];
      this.subKey = readW(args[1]);
      this.samDesired = args[3].toUInt32 ? args[3].toUInt32() : (args[3] >>> 0);
      this.phkResult = args[4];
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const full = buildPath(this.hKey, this.subKey || '');

      if (success && this.phkResult && !this.phkResult.isNull()) {
        try {
          const newHandle = this.phkResult.readPointer();
          handlePaths.set(newHandle.toString(), full);
        } catch (_) {}
      }

      if ((success && matchesFilters(full)) || (!success && config.logFailures)) {
        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(full);
        sendEvent({
          event: 'open_key',
          api: 'RegOpenKeyExW',
          key_path: full,
          status: statusStr,
          success,
          sam_desired: this.samDesired,
          ...decodeWow64(this.samDesired)
        }, includeBt);
      }
    }
  });

  // RegCreateKeyEx with disposition tracking
  attachVariants('RegCreateKeyEx', {
    onEnter(args) {
      this.hKey = args[0];
      this.subKey = readA(args[1]);
      this.samDesired = args[5].toUInt32 ? args[5].toUInt32() : (args[5] >>> 0);
      this.phkResult = args[7];
      this.lpdwDisposition = args[8];
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const full = buildPath(this.hKey, this.subKey || '');

      let disposition = null;
      if (success && this.lpdwDisposition && !this.lpdwDisposition.isNull()) {
        try {
          const dispValue = this.lpdwDisposition.readU32();
          disposition = dispValue === 1 ? 'REG_CREATED_NEW_KEY' : 'REG_OPENED_EXISTING_KEY';
        } catch (_) {}
      }

      if (success && this.phkResult && !this.phkResult.isNull()) {
        try {
          const newHandle = this.phkResult.readPointer();
          handlePaths.set(newHandle.toString(), full);
        } catch (_) {}
      }

      if ((success && matchesFilters(full)) || (!success && config.logFailures)) {
        sendEvent({
          event: 'create_key',
          api: 'RegCreateKeyExA',
          key_path: full,
          status: statusStr,
          success,
          disposition,
          sam_desired: this.samDesired,
          ...decodeWow64(this.samDesired)
        });
      }
    }
  }, {
    onEnter(args) {
      this.hKey = args[0];
      this.subKey = readW(args[1]);
      this.samDesired = args[5].toUInt32 ? args[5].toUInt32() : (args[5] >>> 0);
      this.phkResult = args[7];
      this.lpdwDisposition = args[8];
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const full = buildPath(this.hKey, this.subKey || '');

      let disposition = null;
      if (success && this.lpdwDisposition && !this.lpdwDisposition.isNull()) {
        try {
          const dispValue = this.lpdwDisposition.readU32();
          disposition = dispValue === 1 ? 'REG_CREATED_NEW_KEY' : 'REG_OPENED_EXISTING_KEY';
        } catch (_) {}
      }

      if (success && this.phkResult && !this.phkResult.isNull()) {
        try {
          const newHandle = this.phkResult.readPointer();
          handlePaths.set(newHandle.toString(), full);
        } catch (_) {}
      }

      if ((success && matchesFilters(full)) || (!success && config.logFailures)) {
        sendEvent({
          event: 'create_key',
          api: 'RegCreateKeyExW',
          key_path: full,
          status: statusStr,
          success,
          disposition,
          sam_desired: this.samDesired,
          ...decodeWow64(this.samDesired)
        });
      }
    }
  });

  // RegQueryValueEx with intelligent data formatting
  attachVariants('RegQueryValueEx', {
    onEnter(args) {
      this.hKey = args[0];
      this.valueName = readA(args[1]);
      this.lpType = args[3];
      this.lpData = args[4];
      this.lpcbData = args[5];
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = rootForHandle(this.hKey);

      if ((success && matchesFilters(keyPath, this.valueName)) || (!success && config.logFailures)) {
        const evt = {
          event: 'query_value',
          api: 'RegQueryValueExA',
          key_path: keyPath,
          value_name: this.valueName || '',
          status: statusStr,
          success
        };

        if (success) {
          const regType = readDword(this.lpType);
          const dataSize = readDword(this.lpcbData);

          if (regType != null) evt.reg_type = regType;
          if (dataSize != null) evt.data_len = dataSize;

          if (this.lpData && !this.lpData.isNull() && dataSize > 0 && regType != null) {
            const formatted = formatRegData(regType, this.lpData, dataSize, true);
            if (formatted.formatted) evt.data_formatted = formatted.formatted;
            if (formatted.raw) evt.data_preview_hex = formatted.raw;
          }
        }

        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(keyPath, this.valueName);
        sendEvent(evt, includeBt);
      }
    }
  }, {
    onEnter(args) {
      this.hKey = args[0];
      this.valueName = readW(args[1]);
      this.lpType = args[3];
      this.lpData = args[4];
      this.lpcbData = args[5];
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = rootForHandle(this.hKey);

      if ((success && matchesFilters(keyPath, this.valueName)) || (!success && config.logFailures)) {
        const evt = {
          event: 'query_value',
          api: 'RegQueryValueExW',
          key_path: keyPath,
          value_name: this.valueName || '',
          status: statusStr,
          success
        };

        if (success) {
          const regType = readDword(this.lpType);
          const dataSize = readDword(this.lpcbData);

          if (regType != null) evt.reg_type = regType;
          if (dataSize != null) evt.data_len = dataSize;

          if (this.lpData && !this.lpData.isNull() && dataSize > 0 && regType != null) {
            const formatted = formatRegData(regType, this.lpData, dataSize, true);
            if (formatted.formatted) evt.data_formatted = formatted.formatted;
            if (formatted.raw) evt.data_preview_hex = formatted.raw;
          }
        }

        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(keyPath, this.valueName);
        sendEvent(evt, includeBt);
      }
    }
  });

  // RegSetValueEx with intelligent data formatting
  attachVariants('RegSetValueEx', {
    onEnter(args) {
      this.hKey = args[0];
      this.valueName = readA(args[1]);
      this.dwType = args[3];
      this.lpData = args[4];
      this.cbData = args[5];
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = rootForHandle(this.hKey);

      if ((success && matchesFilters(keyPath, this.valueName)) || (!success && config.logFailures)) {
        const regType = this.dwType ? (this.dwType.toUInt32 ? this.dwType.toUInt32() : (this.dwType >>> 0)) : null;
        const dataSize = this.cbData ? (this.cbData.toUInt32 ? this.cbData.toUInt32() : (this.cbData >>> 0)) : null;

        const evt = {
          event: 'set_value',
          api: 'RegSetValueExA',
          key_path: keyPath,
          value_name: this.valueName || '',
          status: statusStr,
          success,
          reg_type: regType,
          data_len: dataSize
        };

        if (success && this.lpData && !this.lpData.isNull() && dataSize > 0 && regType != null) {
          const formatted = formatRegData(regType, this.lpData, dataSize, true);
          if (formatted.formatted) evt.data_formatted = formatted.formatted;
          if (formatted.raw) evt.data_preview_hex = formatted.raw;
        }

        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(keyPath, this.valueName);
        sendEvent(evt, includeBt);
      }
    }
  }, {
    onEnter(args) {
      this.hKey = args[0];
      this.valueName = readW(args[1]);
      this.dwType = args[3];
      this.lpData = args[4];
      this.cbData = args[5];
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = rootForHandle(this.hKey);

      if ((success && matchesFilters(keyPath, this.valueName)) || (!success && config.logFailures)) {
        const regType = this.dwType ? (this.dwType.toUInt32 ? this.dwType.toUInt32() : (this.dwType >>> 0)) : null;
        const dataSize = this.cbData ? (this.cbData.toUInt32 ? this.cbData.toUInt32() : (this.cbData >>> 0)) : null;

        const evt = {
          event: 'set_value',
          api: 'RegSetValueExW',
          key_path: keyPath,
          value_name: this.valueName || '',
          status: statusStr,
          success,
          reg_type: regType,
          data_len: dataSize
        };

        if (success && this.lpData && !this.lpData.isNull() && dataSize > 0 && regType != null) {
          const formatted = formatRegData(regType, this.lpData, dataSize, true);
          if (formatted.formatted) evt.data_formatted = formatted.formatted;
          if (formatted.raw) evt.data_preview_hex = formatted.raw;
        }

        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(keyPath, this.valueName);
        sendEvent(evt, includeBt);
      }
    }
  });

  // Registry hive operations for comprehensive licensing system monitoring
  attachVariants('RegLoadKey', {
    onEnter(args) {
      this.hKey = args[0];
      this.subKey = readA(args[1]);
      this.fileName = readA(args[2]);
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = buildPath(this.hKey, this.subKey || '');

      if (success || config.logFailures) {
        sendEvent({
          event: 'load_hive',
          api: 'RegLoadKeyA',
          key_path: keyPath,
          file_name: this.fileName || '',
          status: statusStr,
          success
        });
      }
    }
  }, {
    onEnter(args) {
      this.hKey = args[0];
      this.subKey = readW(args[1]);
      this.fileName = readW(args[2]);
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = buildPath(this.hKey, this.subKey || '');

      if (success || config.logFailures) {
        sendEvent({
          event: 'load_hive',
          api: 'RegLoadKeyW',
          key_path: keyPath,
          file_name: this.fileName || '',
          status: statusStr,
          success
        });
      }
    }
  });

  attachVariants('RegSaveKey', {
    onEnter(args) {
      this.hKey = args[0];
      this.fileName = readA(args[1]);
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = rootForHandle(this.hKey);

      if (success || config.logFailures) {
        sendEvent({
          event: 'save_hive',
          api: 'RegSaveKeyA',
          key_path: keyPath,
          file_name: this.fileName || '',
          status: statusStr,
          success
        });
      }
    }
  }, {
    onEnter(args) {
      this.hKey = args[0];
      this.fileName = readW(args[1]);
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = rootForHandle(this.hKey);

      if (success || config.logFailures) {
        sendEvent({
          event: 'save_hive',
          api: 'RegSaveKeyW',
          key_path: keyPath,
          file_name: this.fileName || '',
          status: statusStr,
          success
        });
      }
    }
  });

  // Enhanced registry operations for comprehensive monitoring
  attachVariants('RegDeleteKeyEx', {
    onEnter(args) {
      this.hKey = args[0];
      this.subKey = readA(args[1]);
      this.samDesired = args[2].toUInt32();
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = buildPath(this.hKey, this.subKey || '');

      if ((success && matchesFilters(keyPath)) || (!success && config.logFailures)) {
        sendEvent({
          event: 'delete_key',
          api: 'RegDeleteKeyExA',
          key_path: keyPath,
          status: statusStr,
          success,
          sam_desired: this.samDesired,
          ...decodeWow64(this.samDesired)
        });
      }
    }
  }, {
    onEnter(args) {
      this.hKey = args[0];
      this.subKey = readW(args[1]);
      this.samDesired = args[2].toUInt32();
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = buildPath(this.hKey, this.subKey || '');

      if ((success && matchesFilters(keyPath)) || (!success && config.logFailures)) {
        sendEvent({
          event: 'delete_key',
          api: 'RegDeleteKeyExW',
          key_path: keyPath,
          status: statusStr,
          success,
          sam_desired: this.samDesired,
          ...decodeWow64(this.samDesired)
        });
      }
    }
  });

  attachVariants('RegDeleteValue', {
    onEnter(args) {
      this.hKey = args[0];
      this.valueName = readA(args[1]);
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = rootForHandle(this.hKey);

      if ((success && matchesFilters(keyPath, this.valueName)) || (!success && config.logFailures)) {
        sendEvent({
          event: 'delete_value',
          api: 'RegDeleteValueA',
          key_path: keyPath,
          value_name: this.valueName || '',
          status: statusStr,
          success
        });
      }
    }
  }, {
    onEnter(args) {
      this.hKey = args[0];
      this.valueName = readW(args[1]);
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = rootForHandle(this.hKey);

      if ((success && matchesFilters(keyPath, this.valueName)) || (!success && config.logFailures)) {
        sendEvent({
          event: 'delete_value',
          api: 'RegDeleteValueW',
          key_path: keyPath,
          value_name: this.valueName || '',
          status: statusStr,
          success
        });
      }
    }
  });

  // Registry enumeration with detailed tracking
  attachVariants('RegEnumKeyEx', {
    onEnter(args) {
      this.hKey = args[0];
      this.dwIndex = args[1].toUInt32();
      this.lpName = args[2];
      this.lpcchName = args[3];
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = rootForHandle(this.hKey);

      if ((success && matchesFilters(keyPath)) || (!success && config.logFailures)) {
        let enumKeyName = null;
        if (success && this.lpName && !this.lpName.isNull()) {
          try {
            enumKeyName = this.lpName.readAnsiString();
          } catch (_) {}
        }

        sendEvent({
          event: 'enum_key',
          api: 'RegEnumKeyExA',
          key_path: keyPath,
          index: this.dwIndex,
          enum_key_name: enumKeyName,
          status: statusStr,
          success
        });
      }
    }
  }, {
    onEnter(args) {
      this.hKey = args[0];
      this.dwIndex = args[1].toUInt32();
      this.lpName = args[2];
      this.lpcchName = args[3];
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = rootForHandle(this.hKey);

      if ((success && matchesFilters(keyPath)) || (!success && config.logFailures)) {
        let enumKeyName = null;
        if (success && this.lpName && !this.lpName.isNull()) {
          try {
            enumKeyName = this.lpName.readUtf16String();
          } catch (_) {}
        }

        sendEvent({
          event: 'enum_key',
          api: 'RegEnumKeyExW',
          key_path: keyPath,
          index: this.dwIndex,
          enum_key_name: enumKeyName,
          status: statusStr,
          success
        });
      }
    }
  });

  // Registry handle cleanup
  tryAttach('advapi32.dll', 'RegCloseKey', {
    onEnter(args) {
      this.hKey = args[0];
    },
    onLeave(retval) {
      const key = this.hKey ? this.hKey.toString() : null;
      if (key && handlePaths.has(key)) {
        handlePaths.delete(key);
      }
    }
  });

  // Additional Shell Registry API
  tryAttach('shlwapi.dll', 'SHRegGetValueW', {
    onEnter(args) {
      this.hKey = args[0];
      this.subKey = readW(args[1]);
      this.valueName = readW(args[2]);
      this.pdwType = args[4];
      this.pvData = args[5];
      this.pcbData = args[6];
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const success = status === 0;
      const keyPath = buildPath(this.hKey, this.subKey || '');

      if ((success && matchesFilters(keyPath, this.valueName)) || (!success && config.logFailures)) {
        const evt = {
          event: 'get_value',
          api: 'SHRegGetValueW',
          key_path: keyPath,
          value_name: this.valueName || '',
          status: statusStr,
          success
        };

        if (success) {
          const regType = readDword(this.pdwType);
          const dataSize = readDword(this.pcbData);

          if (regType != null) evt.reg_type = regType;
          if (dataSize != null) evt.data_len = dataSize;

          if (this.pvData && !this.pvData.isNull() && dataSize > 0 && regType != null) {
            const formatted = formatRegData(regType, this.pvData, dataSize, true);
            if (formatted.formatted) evt.data_formatted = formatted.formatted;
            if (formatted.raw) evt.data_preview_hex = formatted.raw;
          }
        }

        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(keyPath, this.valueName);
        sendEvent(evt, includeBt);
      }
    }
  });
}

function hookLoadLibraryForLateAttach() {
  function maybeAttachAll(moduleName) {
    if (config.enableStealthMode) {
      setTimeout(() => {
        try {
          const m = (moduleName || '').toLowerCase();
          if (m.endsWith('advapi32.dll') || m.endsWith('shlwapi.dll')) {
            attachCoreRegistryHooks();
          }
          if (config.enableNativeApiHooks && m.endsWith('ntdll.dll')) {
            attachNativeApiHooks();
          }
        } catch (_) {}
      }, Math.floor(Math.random() * 10) + 5);
    } else {
      try {
        const m = (moduleName || '').toLowerCase();
        if (m.endsWith('advapi32.dll') || m.endsWith('shlwapi.dll')) {
          attachCoreRegistryHooks();
        }
        if (config.enableNativeApiHooks && m.endsWith('ntdll.dll')) {
          attachNativeApiHooks();
        }
      } catch (_) {}
    }
  }

  const loadLibraryVariants = ['LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW'];

  loadLibraryVariants.forEach(funcName => {
    tryAttach('kernel32.dll', funcName, {
      onEnter(args) {
        this.name = funcName.endsWith('W') ? readW(args[0]) : readA(args[0]);
      },
      onLeave(retval) {
        if (this.name && !retval.isNull()) {
          maybeAttachAll(this.name);
        }
      }
    });
  });
}

// Initialize monitoring
try {
  attachCoreRegistryHooks();
  attachNativeApiHooks();
  hookLoadLibraryForLateAttach();

  send({
    type: 'info',
    target: 'registry_monitor',
    event: 'initialized',
    features: {
      native_api_hooks: config.enableNativeApiHooks,
      stealth_mode: config.enableStealthMode,
      intelligent_data_formatting: true,
      performance_throttling: config.performanceThrottleMs > 0,
      comprehensive_api_coverage: true
    },
    coverage: {
      win32_apis: ['RegOpenKeyEx', 'RegCreateKeyEx', 'RegQueryValueEx', 'RegSetValueEx', 'RegDeleteKey', 'RegDeleteValue', 'RegEnumKeyEx', 'RegLoadKey', 'RegSaveKey'],
      native_apis: config.enableNativeApiHooks ? ['NtOpenKeyEx', 'NtCreateKeyEx', 'NtQueryValueKey', 'NtSetValueKey', 'NtDeleteKey', 'NtDeleteValueKey'] : [],
      shell_apis: ['SHRegGetValueW']
    }
  });
} catch (e) {
  send({
    type: 'error',
    target: 'registry_monitor',
    message: 'initialization_failed',
    error: String(e)
  });
}// ===== VALUE SPOOFING AND WRITE PROTECTION SYSTEM =====
// Critical capabilities from registry_monitor_enhanced.js

// Registry value spoofing configuration
const spoofingRules = {
  // Microsoft Office licensing bypass
  'SOFTWARE\\Microsoft\\Office\\16.0\\Common\\Licensing': {
    'LastKnownC2RProductReleaseId': '16.0.14326.20454',
    'LicenseState': '1',
    'ProductReleaseId': 'VolumeLicense',
    'OfficeActivated': '1',
    'IsLicensed': '1'
  },
  'SOFTWARE\\Microsoft\\Office\\15.0\\Common\\Licensing': {
    'LastKnownC2RProductReleaseId': '15.0.4569.1506',
    'LicenseState': '1',
    'ProductReleaseId': 'VolumeLicense'
  },

  // Adobe product activation bypass
  'SOFTWARE\\Adobe\\Adobe Acrobat\\DC\\Activation': {
    'IsAMTEnforced': '0',
    'IsNGLEnforced': '0',
    'LicenseType': 'Retail',
    'SerialNumber': '9707-1893-4560-8967-9612-3924',
    'ProductActivated': '1',
    'ActivationStatus': 'Complete'
  },
  'SOFTWARE\\Adobe\\Adobe Creative Suite': {
    'LicenseState': 'Licensed',
    'TrialStatus': 'None',
    'SerialNumber': '1330-1001-8751-9715-4815-7067'
  },
  'SOFTWARE\\Adobe\\Creative Cloud': {
    'SubscriptionStatus': 'Active',
    'ExpirationDate': '2099-12-31T23:59:59Z',
    'LicenseType': 'Commercial'
  },

  // Autodesk product licensing
  'SOFTWARE\\Autodesk\\Maya\\2024\\License': {
    'LicenseType': 'Commercial',
    'ExpirationDate': '2099-12-31',
    'SerialNumber': '666-69696969',
    'ProductKey': '657N1',
    'NetworkLicense': '0'
  },
  'SOFTWARE\\Autodesk\\AutoCAD\\R24.0\\License': {
    'LicenseType': 'Commercial',
    'SerialNumber': '666-12345678',
    'ProductKey': '001L1'
  },
  'SOFTWARE\\FLEXlm License Manager': {
    'ADSKFLEX_LICENSE_FILE': '@flexlm.autodesk.com',
    'LicenseStatus': 'Valid'
  },

  // JetBrains products
  'SOFTWARE\\JetBrains\\IntelliJ IDEA': {
    'eureka.license.key': 'VALID_LICENSE_KEY',
    'idea.license.key': 'ENTERPRISE_LICENSE',
    'perpetual.fallback.date': '2099-12-31'
  },

  // VMware products
  'SOFTWARE\\VMware, Inc.\\VMware Workstation': {
    'SerialNumber': '5A02H-AU243-TZJ49-GTC7K-3C61N',
    'LicenseType': 'Professional'
  },

  // WinRAR
  'SOFTWARE\\WinRAR': {
    'User': 'Registered User',
    'License': 'Site License'
  },

  // Generic trial resets
  'SOFTWARE\\Classes\\Licenses': {
    '*': 'VALID_LICENSE_DATA'  // Wildcard for any value name
  },
  'SOFTWARE\\Licenses': {
    '*': 'REGISTERED_USER_LICENSE'
  },

  // Hardware ID spoofing for machine fingerprinting
  'HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0': {
    'ProcessorNameString': 'Intel(R) Core(TM) i9-13900K CPU @ 3.00GHz',
    'Identifier': 'Intel64 Family 6 Model 183 Stepping 1',
    'VendorIdentifier': 'GenuineIntel'
  },
  'SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0001': {
    'NetworkAddress': '001A2B3C4D5E'
  },
  'SOFTWARE\\Microsoft\\Cryptography': {
    'MachineGuid': '{12345678-1234-1234-1234-123456789ABC}'
  },

  // Windows activation
  'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion': {
    'RegisteredOwner': 'Licensed User',
    'RegisteredOrganization': 'Licensed Organization',
    'DigitalProductId': '0123456789ABCDEF'
  }
};

// Write protection patterns - prevent overwriting of spoofed values
const writeProtectionPatterns = [
  // Microsoft Office protection
  /SOFTWARE\\Microsoft\\Office.*Licensing/i,
  /SOFTWARE\\Microsoft\\Office.*Activation/i,

  // Adobe protection
  /SOFTWARE\\Adobe.*Activation/i,
  /SOFTWARE\\Adobe.*License/i,
  /SOFTWARE\\Adobe.*Serial/i,

  // Autodesk protection
  /SOFTWARE\\Autodesk.*License/i,
  /SOFTWARE\\FLEXlm License Manager/i,

  // Generic license protection
  /SOFTWARE\\Classes\\Licenses/i,
  /SOFTWARE\\Licenses/i,

  // Hardware fingerprinting protection
  /HARDWARE\\DESCRIPTION\\System\\CentralProcessor/i,
  /SOFTWARE\\Microsoft\\Cryptography\\MachineGuid/i,
  /SYSTEM.*Control\\Class.*NetworkAddress/i,

  // Windows activation protection
  /SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion.*Product/i,
  /SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion.*Digital/i
];

// Process filtering configuration
config.targetProcesses = [];  // Empty = monitor all processes
config.excludeProcesses = ['explorer.exe', 'svchost.exe', 'System', 'Registry', 'winlogon.exe', 'csrss.exe'];
config.encryptLogs = true;
config.logToFile = true;
config.logFilePath = 'C:\\ProgramData\\regmon.dat';
config.encryptionKey = 'IntellicrackRegMon2024Enhanced!';

// Statistics tracking
const statistics = {
  totalCalls: 0,
  spoofedValues: 0,
  blockedWrites: 0,
  processesFiltered: 0,
  errors: 0,
  startTime: Date.now()
};

const logBuffer = [];

// Enhanced utility functions
function encryptData(data) {
  if (!config.encryptLogs) return data;

  try {
    let result = '';
    const key = config.encryptionKey;
    for (let i = 0; i < data.length; i++) {
      result += String.fromCharCode(data.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return btoa(result);
  } catch (e) {
    return data;  // Fallback to unencrypted
  }
}

function isTargetProcess() {
  try {
    const processName = Process.enumerateModules()[0]?.name?.toLowerCase() || '';

    // Check exclude list first
    if (config.excludeProcesses.some(exclude => processName.includes(exclude.toLowerCase()))) {
      statistics.processesFiltered++;
      return false;
    }

    // Check include list if specified
    if (config.targetProcesses.length > 0) {
      return config.targetProcesses.some(target => processName.includes(target.toLowerCase()));
    }

    return true;
  } catch (_) {
    return true;  // Default to monitoring if detection fails
  }
}

function getSpoofedValue(fullPath, valueName) {
  if (!fullPath || !valueName) return null;

  const normalizedPath = fullPath.toUpperCase();

  for (const [rulePath, rules] of Object.entries(spoofingRules)) {
    if (normalizedPath.includes(rulePath.toUpperCase())) {
      // Check for wildcard rule
      if (rules['*'] !== undefined) {
        return rules['*'];
      }

      // Check for specific value rule
      if (rules[valueName] !== undefined) {
        return rules[valueName];
      }
    }
  }

  return null;
}

function applySpoofedValue(lpData, lpcbData, lpType, spoofValue, isUnicode) {
  if (!lpData || lpData.isNull() || !spoofValue) return false;

  try {
    const regType = lpType ? lpType.readU32() : REG_SZ;

    switch (regType) {
      case REG_SZ:
      case REG_EXPAND_SZ:
        if (isUnicode) {
          const strPtr = Memory.allocUtf16String(spoofValue);
          const byteLength = (spoofValue.length + 1) * 2;
          Memory.copy(lpData, strPtr, Math.min(byteLength, config.captureValuePreviewBytes));
          if (lpcbData && !lpcbData.isNull()) lpcbData.writeU32(byteLength);
        } else {
          const strPtr = Memory.allocUtf8String(spoofValue);
          const byteLength = spoofValue.length + 1;
          Memory.copy(lpData, strPtr, Math.min(byteLength, config.captureValuePreviewBytes));
          if (lpcbData && !lpcbData.isNull()) lpcbData.writeU32(byteLength);
        }
        return true;

      case REG_DWORD:
        const dwordValue = parseInt(spoofValue);
        if (!isNaN(dwordValue)) {
          lpData.writeU32(dwordValue);
          if (lpcbData && !lpcbData.isNull()) lpcbData.writeU32(4);
          return true;
        }
        break;

      case REG_QWORD:
        const qwordValue = parseInt(spoofValue);
        if (!isNaN(qwordValue)) {
          lpData.writeU64(qwordValue);
          if (lpcbData && !lpcbData.isNull()) lpcbData.writeU32(8);
          return true;
        }
        break;

      case REG_BINARY:
        // Handle hex string format
        const hex = spoofValue.replace(/[^0-9A-Fa-f]/g, '');
        if (hex.length % 2 === 0) {
          const bytes = [];
          for (let i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.substr(i, 2), 16));
          }
          for (let i = 0; i < Math.min(bytes.length, config.captureValuePreviewBytes); i++) {
            lpData.add(i).writeU8(bytes[i]);
          }
          if (lpcbData && !lpcbData.isNull()) lpcbData.writeU32(bytes.length);
          return true;
        }
        break;
    }

    return false;
  } catch (e) {
    statistics.errors++;
    return false;
  }
}

function shouldBlockWrite(fullPath, valueName) {
  if (!fullPath) return false;

  return writeProtectionPatterns.some(pattern => pattern.test(fullPath));
}

function enhancedGetFullRegistryPath(hKey) {
  const handle = hKey.toString();

  // Check predefined keys first
  if (predefinedRoots.has(handle)) {
    return predefinedRoots.get(handle);
  }

  // Check our handle mapping
  if (handlePaths.has(handle)) {
    return handlePaths.get(handle);
  }

  // Try NtQueryKey for better path resolution
  try {
    const ntQueryKey = Module.findExportByName('ntdll.dll', 'NtQueryKey');
    if (ntQueryKey) {
      const keyInfoBuffer = Memory.alloc(1024);
      const lengthBuffer = Memory.alloc(4);

      const queryFunc = new NativeFunction(ntQueryKey, 'int', ['pointer', 'int', 'pointer', 'int', 'pointer']);
      const result = queryFunc(hKey, 3, keyInfoBuffer, 1024, lengthBuffer);

      if (result === 0) {
        // KEY_NAME_INFORMATION structure: ULONG NameLength followed by WCHAR Name[]
        const nameLength = keyInfoBuffer.readU32();
        if (nameLength > 0 && nameLength < 2000) {
          const namePtr = keyInfoBuffer.add(4);
          let path = namePtr.readUtf16String(nameLength / 2);

          // Convert registry path format
          if (path.startsWith('\\REGISTRY\\')) {
            path = path.substring(10);
            if (path.startsWith('MACHINE\\')) {
              path = 'HKEY_LOCAL_MACHINE\\' + path.substring(8);
            } else if (path.startsWith('USER\\')) {
              // Find the SID end and replace with HKEY_CURRENT_USER
              const parts = path.split('\\');
              if (parts.length >= 3) {
                path = 'HKEY_CURRENT_USER\\' + parts.slice(2).join('\\');
              }
            }
          }

          handlePaths.set(handle, path);
          return path;
        }
      }
    }
  } catch (_) {
    // Fallback to existing logic
  }

  return rootForHandle(hKey);
}

function writeToLogFile(data) {
  if (!config.logToFile) return;

  try {
    const timestamp = new Date().toISOString();
    const logEntry = `${timestamp} | ${data}\n`;
    const finalData = config.encryptLogs ? encryptData(logEntry) + '\n' : logEntry;

    // Use Frida's File API for cross-platform compatibility
    const file = new File(config.logFilePath, 'a');
    file.write(finalData);
    file.close();
  } catch (e) {
    // Silently fail to avoid breaking the hook
    statistics.errors++;
  }
}

function flushLogBuffer() {
  if (logBuffer.length === 0) return;

  try {
    const entries = logBuffer.splice(0);  // Clear buffer
    entries.forEach(entry => writeToLogFile(entry));
  } catch (_) {
    statistics.errors++;
  }
}

function enhancedSendEvent(e, includeBt) {
  // Check process filtering
  if (!isTargetProcess()) {
    statistics.processesFiltered++;
    return;
  }

  statistics.totalCalls++;

  // Apply existing throttling
  if (shouldThrottle()) return;

  const evt = Object.assign({
    type: 'info',
    target: 'registry_monitor_enhanced',
    pid: Process.id,
    timestamp: Date.now(),
    module: Process.enumerateModules()[0]?.name || null,
    stats: {
      total_calls: statistics.totalCalls,
      spoofed_values: statistics.spoofedValues,
      blocked_writes: statistics.blockedWrites,
      filtered_processes: statistics.processesFiltered
    }
  }, e);

  if (includeBt) {
    try {
      evt.backtrace = Thread.backtrace(e.context || null, Backtracer.ACCURATE)
        .slice(0, 10)
        .map(a => symbolAt(a))
        .filter(s => s);
    } catch (_) {}
  }

  // Send to Frida host
  send(evt);

  // Buffer for file logging
  const logMsg = `${evt.event} | ${evt.key_path || 'N/A'} | ${evt.value_name || ''} | ${evt.status || ''} | ${evt.data_formatted || evt.data_preview_hex || ''}`;
  logBuffer.push(logMsg);

  // Flush buffer periodically
  if (logBuffer.length >= 20) {
    flushLogBuffer();
  }
}

// Override the original sendEvent function to use enhanced version
const originalSendEvent = sendEvent;
sendEvent = enhancedSendEvent;

// Enhanced hooks integration - modify existing RegQueryValueEx hooks to support spoofing
function enhanceExistingQueryHooks() {
  // We need to re-attach the RegQueryValueEx hooks with spoofing capability
  // Since hooks are already attached, we'll enhance them by modifying the onLeave behavior

  // The hooks are already established, but we need to add spoofing logic
  // This will be integrated directly into the existing hook structure
}

// Statistics reporting
setInterval(() => {
  const runtime = Math.round((Date.now() - statistics.startTime) / 1000);

  send({
    type: 'summary',
    target: 'registry_monitor_enhanced',
    action: 'statistics_report',
    runtime_seconds: runtime,
    stats: {
      total_calls: statistics.totalCalls,
      spoofed_values: statistics.spoofedValues,
      blocked_writes: statistics.blockedWrites,
      processes_filtered: statistics.processesFiltered,
      errors: statistics.errors,
      calls_per_second: statistics.totalCalls / Math.max(runtime, 1)
    }
  });

  // Flush any pending logs
  flushLogBuffer();
}, 30000); // Every 30 seconds

// Add spoofing support to existing RegQueryValueEx hooks
const originalRegQueryCallbacks = {};

function integrateSpoofingIntoExistingHooks() {
  // Enhance existing Win32 API hooks with spoofing capability
  attachVariants('RegQueryValueEx', {
    onEnter(args) {
      this.hKey = args[0];
      this.valueName = readA(args[1]);
      this.lpType = args[3];
      this.lpData = args[4];
      this.lpcbData = args[5];
      this.fullPath = enhancedGetFullRegistryPath(this.hKey);
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const success = status === 0;

      if (success && this.fullPath && this.valueName) {
        // Check for spoofing opportunity
        const spoofValue = getSpoofedValue(this.fullPath, this.valueName);

        if (spoofValue !== null) {
          // Apply spoofed value
          if (applySpoofedValue(this.lpData, this.lpcbData, this.lpType, spoofValue, false)) {
            statistics.spoofedValues++;
            const includeBt = config.includeBacktraceOnMatch && matchesFilters(this.fullPath, this.valueName);
            sendEvent({
              event: 'query_value_spoofed',
              api: 'RegQueryValueExA',
              key_path: this.fullPath,
              value_name: this.valueName,
              status: 'SUCCESS_SPOOFED',
              success: true,
              original_status: LSTATUS_MAP[status] || `ERROR_${status}`,
              spoofed_value: spoofValue,
              spoof_applied: true
            }, includeBt);
            return;
          }
        }
      }

      // Fall back to original behavior if no spoofing applied
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const keyPath = this.fullPath || rootForHandle(this.hKey);

      if ((success && matchesFilters(keyPath, this.valueName)) || (!success && config.logFailures)) {
        const evt = {
          event: 'query_value',
          api: 'RegQueryValueExA',
          key_path: keyPath,
          value_name: this.valueName || '',
          status: statusStr,
          success
        };

        if (success) {
          const regType = readDword(this.lpType);
          const dataSize = readDword(this.lpcbData);

          if (regType != null) evt.reg_type = regType;
          if (dataSize != null) evt.data_len = dataSize;

          if (this.lpData && !this.lpData.isNull() && dataSize > 0 && regType != null) {
            const formatted = formatRegData(regType, this.lpData, dataSize, true);
            if (formatted.formatted) evt.data_formatted = formatted.formatted;
            if (formatted.raw) evt.data_preview_hex = formatted.raw;
          }
        }

        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(keyPath, this.valueName);
        sendEvent(evt, includeBt);
      }
    }
  }, {
    onEnter(args) {
      this.hKey = args[0];
      this.valueName = readW(args[1]);
      this.lpType = args[3];
      this.lpData = args[4];
      this.lpcbData = args[5];
      this.fullPath = enhancedGetFullRegistryPath(this.hKey);
    },
    onLeave(retval) {
      const status = retval.toInt32();
      const success = status === 0;

      if (success && this.fullPath && this.valueName) {
        // Check for spoofing opportunity
        const spoofValue = getSpoofedValue(this.fullPath, this.valueName);

        if (spoofValue !== null) {
          // Apply spoofed value
          if (applySpoofedValue(this.lpData, this.lpcbData, this.lpType, spoofValue, true)) {
            statistics.spoofedValues++;
            const includeBt = config.includeBacktraceOnMatch && matchesFilters(this.fullPath, this.valueName);
            sendEvent({
              event: 'query_value_spoofed',
              api: 'RegQueryValueExW',
              key_path: this.fullPath,
              value_name: this.valueName,
              status: 'SUCCESS_SPOOFED',
              success: true,
              original_status: LSTATUS_MAP[status] || `ERROR_${status}`,
              spoofed_value: spoofValue,
              spoof_applied: true
            }, includeBt);
            return;
          }
        }
      }

      // Fall back to original behavior if no spoofing applied
      const statusStr = LSTATUS_MAP[status] || `ERROR_${status}`;
      const keyPath = this.fullPath || rootForHandle(this.hKey);

      if ((success && matchesFilters(keyPath, this.valueName)) || (!success && config.logFailures)) {
        const evt = {
          event: 'query_value',
          api: 'RegQueryValueExW',
          key_path: keyPath,
          value_name: this.valueName || '',
          status: statusStr,
          success
        };

        if (success) {
          const regType = readDword(this.lpType);
          const dataSize = readDword(this.lpcbData);

          if (regType != null) evt.reg_type = regType;
          if (dataSize != null) evt.data_len = dataSize;

          if (this.lpData && !this.lpData.isNull() && dataSize > 0 && regType != null) {
            const formatted = formatRegData(regType, this.lpData, dataSize, true);
            if (formatted.formatted) evt.data_formatted = formatted.formatted;
            if (formatted.raw) evt.data_preview_hex = formatted.raw;
          }
        }

        const includeBt = config.includeBacktraceOnMatch && success && matchesFilters(keyPath, this.valueName);
        sendEvent(evt, includeBt);
      }
    }
  });
}
