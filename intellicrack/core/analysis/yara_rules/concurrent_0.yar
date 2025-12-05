
rule Concurrent_Rule_0 {
    meta:
        description = "Concurrent test rule 0"
    strings:
        $str = "TEST0"
    condition:
        $str
}
