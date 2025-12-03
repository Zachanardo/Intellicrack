
rule Concurrent_Rule_10 {
    strings:
        $s = "ConcurrentTest10"
    condition:
        $s
}
