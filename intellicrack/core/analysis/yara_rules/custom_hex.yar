
rule Custom_Hex_Pattern {
    meta:
        description = "Detects hex pattern"
    strings:
        $hex = { DE AD BE EF }
    condition:
        $hex
}
