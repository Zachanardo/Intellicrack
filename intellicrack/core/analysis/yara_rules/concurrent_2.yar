
rule Concurrent_Rule_2 {
    meta:
        description = "Concurrent test rule 2"
    strings:
        $str = "TEST2"
    condition:
        $str
}
