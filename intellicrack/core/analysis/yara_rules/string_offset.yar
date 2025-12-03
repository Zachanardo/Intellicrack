
rule String_Offset_Test {
    strings:
        $s1 = "FirstPattern"
        $s2 = "SecondPattern"
    condition:
        any of them
}
