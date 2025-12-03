
rule Custom_Signature_Test {
    strings:
        $sig = "UniqueTestSignature2025"
    condition:
        $sig
}
