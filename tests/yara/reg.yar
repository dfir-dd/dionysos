rule OneDrive {
    strings:
        $a = "OneDrive.exe"
    
    condition:
        any of them
}
