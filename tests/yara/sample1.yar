rule world {
    strings:
        $world = "world"
				$lorem = "ipsum"
    
    condition:
        any of them
}
