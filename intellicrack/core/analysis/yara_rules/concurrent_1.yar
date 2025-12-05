
rule Concurrent_Rule_1 {
    meta:
        description = "Concurrent test rule 1"
    strings:
        $str = "TEST1"
    condition:
        $str
}
