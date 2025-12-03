
rule Concurrent_Rule_12 {
    strings:
        $s = "ConcurrentTest12"
    condition:
        $s
}
