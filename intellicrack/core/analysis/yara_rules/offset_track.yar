
rule Offset_Tracking_Test {
    strings:
        $marker = "OFFSETMARKER"
    condition:
        $marker
}
