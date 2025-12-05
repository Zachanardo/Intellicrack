
rule Custom_Test_Rule {
    meta:
        description = "Test custom rule"
        category = "custom"
    strings:
        $test = "TESTPATTERN"
    condition:
        $test
}
