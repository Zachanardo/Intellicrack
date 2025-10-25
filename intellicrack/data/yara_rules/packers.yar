
rule UPX_Packer
{
    meta:
        category = "packer"
        confidence = 0.95
        description = "Detects UPX packer"

    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "$Info: This file is packed with the UPX executable packer" ascii
        $upx3 = { 55 50 58 21 }

    condition:
        any of them
}

rule ASPack_Packer
{
    meta:
        category = "packer"
        confidence = 0.9
        description = "Detects ASPack packer"

    strings:
        $asp1 = ".aspack" ascii
        $asp2 = "ASPack" ascii nocase
        $asp3 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }

    condition:
        any of them
}

rule PECompact_Packer
{
    meta:
        category = "packer"
        confidence = 0.85
        description = "Detects PECompact packer"

    strings:
        $pec1 = "PECompact2" ascii
        $pec2 = ".pec1" ascii
        $pec3 = ".pec2" ascii

    condition:
        any of them
}
