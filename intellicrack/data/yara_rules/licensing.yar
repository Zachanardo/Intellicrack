
rule FlexLM_License
{
    meta:
        category = "licensing"
        confidence = 0.9
        description = "Detects FlexLM licensing system"

    strings:
        $flex1 = "FlexLM" ascii nocase
        $flex2 = "lm_checkout" ascii
        $flex3 = "VENDOR_NAME" ascii
        $flex4 = "license.dat" ascii nocase
        $flex5 = "lmgrd" ascii

    condition:
        any of them
}

rule HASP_Dongle
{
    meta:
        category = "licensing"
        confidence = 0.85
        description = "Detects HASP/Sentinel dongle protection"

    strings:
        $hasp1 = "hasp_login" ascii
        $hasp2 = "HASP HL" ascii
        $hasp3 = "Sentinel" ascii nocase
        $hasp4 = "aksusb" ascii
        $hasp5 = "hardlock.sys" ascii nocase

    condition:
        any of them
}

rule CodeMeter_License
{
    meta:
        category = "licensing"
        confidence = 0.8
        description = "Detects CodeMeter licensing"

    strings:
        $cm1 = "CodeMeter" ascii nocase
        $cm2 = "CmContainer" ascii
        $cm3 = "WibuCm" ascii
        $cm4 = ".WibuCm" ascii

    condition:
        any of them
}

rule Generic_License_Patterns
{
    meta:
        category = "licensing"
        confidence = 0.6
        description = "Generic licensing patterns"

    strings:
        $lic1 = "license key" ascii nocase
        $lic2 = "serial number" ascii nocase
        $lic3 = "activation code" ascii nocase
        $lic4 = "trial expired" ascii nocase
        $lic5 = "registration required" ascii nocase
        $lic6 = /License.*[Vv]iolation/ ascii

    condition:
        any of them
}
