
rule Concurrent_Rule_3 {
    meta:
        description = "Concurrent test rule 3"
    strings:
        $str = "TEST3"
    condition:
        $str
}
