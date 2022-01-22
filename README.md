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

### 1. Declare scanner result type

You should enhance the class `ScannerFinding` in [src/scanner_result.rs](src/scanner_result.rs).

### 2. Implementation of the scanner

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

### 3. Add your scanner to the scanner chain

Which is currently hard-coded in `Dionysos::run()` (in [src/dionysos.rs](src/dionysis.rs))

# Feature ideas

- use yara rules, including modules (e.g. import "hash")
- use lists of regular expressions for filesystem searches
- write results to console / log
- output must use an easy-to-parse format, while optionally staying human readable to best effort
- highly optional: use the same list to search MFT & UsnJrnl in case files were deleted
- usage via console, cmd args
- optional: curses fontend (???)
- configuration of log level via command line
- levensthein-scanner
- use of one parameter to pass yara rules, which might be a file, a zip container or a directory
