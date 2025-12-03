
rule Concurrent_Rule_3 {
    strings:
        $s = "ConcurrentTest3"
    condition:
        $s
}
