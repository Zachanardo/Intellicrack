
rule Custom_License_Pattern {
    meta:
        description = "Detects custom license pattern"
    strings:
        $lic = "CUSTOM_LICENSE_KEY"
    condition:
        $lic
}
