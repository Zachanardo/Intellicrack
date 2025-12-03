
rule Concurrent_Rule_4 {
    strings:
        $s = "ConcurrentTest4"
    condition:
        $s
}
