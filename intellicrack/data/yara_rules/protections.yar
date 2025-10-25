
rule VMProtect_Detection
{
    meta:
        category = "protection"
        confidence = 0.9
        description = "Detects VMProtect virtualization protection"

    strings:
        $vmp1 = ".vmp0" ascii
        $vmp2 = ".vmp1" ascii
        $vmp3 = "VMProtect" ascii nocase
        $vmp4 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 }

    condition:
        any of them
}

rule Themida_Detection
{
    meta:
        category = "protection"
        confidence = 0.85
        description = "Detects Themida/WinLicense protection"

    strings:
        $tmd1 = ".themida" ascii
        $tmd2 = "Themida" ascii nocase
        $tmd3 = "WinLicense" ascii nocase
        $tmd4 = { 8B 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 89 85 }

    condition:
        any of them
}

rule Enigma_Protector
{
    meta:
        category = "protection"
        confidence = 0.8
        description = "Detects Enigma Protector"

    strings:
        $enig1 = ".enigma1" ascii
        $enig2 = ".enigma2" ascii
        $enig3 = "Enigma Protector" ascii nocase

    condition:
        any of them
}
