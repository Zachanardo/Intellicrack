
rule Concurrent_Rule_1 {
    strings:
        $s = "ConcurrentTest1"
    condition:
        $s
}
