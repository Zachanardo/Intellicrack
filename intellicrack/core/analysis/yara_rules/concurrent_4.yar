
rule Concurrent_Rule_4 {
    meta:
        description = "Concurrent test rule 4"
    strings:
        $str = "TEST4"
    condition:
        $str
}
