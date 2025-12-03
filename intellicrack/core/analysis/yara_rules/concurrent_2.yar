
rule Concurrent_Rule_2 {
    strings:
        $s = "ConcurrentTest2"
    condition:
        $s
}
