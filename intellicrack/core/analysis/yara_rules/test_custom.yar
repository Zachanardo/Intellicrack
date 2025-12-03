
rule Test_Custom_Pattern {
    meta:
        description = "Test custom pattern detection"
        category = "custom"
    strings:
        $pattern = "CustomTestPattern123"
    condition:
        $pattern
}
