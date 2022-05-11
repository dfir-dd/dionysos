rule world {
    strings:
        $world = "world"
    
    condition:
        any of them
}