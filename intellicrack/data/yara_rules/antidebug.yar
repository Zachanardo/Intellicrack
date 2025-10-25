
rule Anti_Debug_API
{
    meta:
        category = "anti_debug"
        confidence = 0.8
        description = "Detects anti-debugging API calls"

    strings:
        $api1 = "IsDebuggerPresent" ascii
        $api2 = "CheckRemoteDebuggerPresent" ascii
        $api3 = "NtQueryInformationProcess" ascii
        $api4 = "OutputDebugString" ascii
        $api5 = "GetTickCount" ascii

    condition:
        any of them
}

rule Anti_Debug_PEB
{
    meta:
        category = "anti_debug"
        confidence = 0.75
        description = "Detects PEB-based anti-debugging"

    strings:
        $peb1 = { 64 8B 30 8B 76 0C 8B 76 1C }  // PEB access
        $peb2 = { 65 8B 00 8B 40 ?? 8A 40 02 }  // BeingDebugged flag

    condition:
        any of them
}

rule Anti_VM_Detection
{
    meta:
        category = "anti_vm"
        confidence = 0.7
        description = "Detects anti-VM techniques"

    strings:
        $vm1 = "VMware" ascii nocase
        $vm2 = "VirtualBox" ascii nocase
        $vm3 = "QEMU" ascii nocase
        $vm4 = "Xen" ascii nocase
        $vm5 = "vbox" ascii nocase
        $vm6 = { 0F 01 0D 00 00 00 00 }  // SIDT instruction

    condition:
        any of them
}
