# `dionysos`
Scanner for certain IoCs

# Usage
```
dionysos 0.1.0

Scanner for certain IoCs

USAGE:
    dionysos [OPTIONS]

OPTIONS:
    -h, --help           Print help information
    -P, --path <PATH>    path to registry hive file
    -V, --version        Print version information
```

# Developer guide

## How to add scanners

Take, for example, the `FilenameScanner`, which tries to do a simple filename match:

```rust
use crate::consumer::*;
use crate::scanner_result::{ScannerResult, ScannerFinding};
use provider_derive::*;
use consumer_derive::*;

#[has_consumers_list]
#[has_thread_handle]
#[derive(FileProvider)]
#[derive(FileConsumer)]
#[derive(Default)]
pub struct FilenameScanner {}

impl FileHandler for FilenameScanner {
    fn handle_file(result: &ScannerResult) {
        if result.filename().ends_with(".rs") {
            result.add_finding(ScannerFinding::Filename("*.rs".to_owned()));
        }        
    }
}

```