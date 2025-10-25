
rule MSVC_Compiler
{
    meta:
        category = "compiler"
        confidence = 0.9
        description = "Microsoft Visual C++ compiler"

    strings:
        $msvc1 = "Microsoft (R) 32-bit C/C++ Optimizing Compiler" ascii
        $msvc2 = "MSVCR" ascii
        $msvc3 = ".rdata$zzz" ascii

    condition:
        any of them
}

rule Delphi_Compiler
{
    meta:
        category = "compiler"
        confidence = 0.85
        description = "Borland Delphi compiler"

    strings:
        $delphi1 = "Borland" ascii
        $delphi2 = "@AbstractError" ascii
        $delphi3 = "Controls.TControl" ascii

    condition:
        any of them
}

rule GCC_Compiler
{
    meta:
        category = "compiler"
        confidence = 0.8
        description = "GNU GCC compiler"

    strings:
        $gcc1 = "GCC: " ascii
        $gcc2 = "__gmon_start__" ascii
        $gcc3 = ".eh_frame" ascii

    condition:
        any of them
}
