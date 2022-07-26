rule poqexec {
    strings:
        $a = "poqexec.exe"
    
    condition:
        any of them
}
