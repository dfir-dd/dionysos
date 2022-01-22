# `dionysos`
Scanner for various IoCs

# Installation

```shell
cargo install dionysos
```

# Usage
```
dionysos 0.1.0

Scanner for various IoCs

USAGE:
    dionysos [OPTIONS]

OPTIONS:
    -F, --filename <FILENAME_REGEX>    regular expression to match against the basename of files.
                                       This parameter can be specified multiple times
    -h, --help                         Print help information
    -P, --path <PATH>                  path to registry hive file
    -v                                 level of verbosity (specify multiple times to increase
                                       verbosity
    -V, --version                      Print version information
    -Y, --yara <YARA_RULES>            use yara scanner with the specified ruleset. This can be a
                                       single file, a zip file or a directory containing lots of
                                       yara files. Yara files must end with 'yar' or 'yara', and zip
                                       files must end with 'zip'
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
use std::sync::Arc;

#[has_consumers_list]
#[has_thread_handle]
#[derive(FileProvider)]
#[derive(FileConsumer)]
#[derive(Default)]
pub struct FilenameScanner {
    #[consumer_data]
    patterns: Arc<Vec<regex::Regex>>,

    unsealed_patterns: Vec<regex::Regex>,
}

impl FilenameScanner {
    pub fn seal(&mut self) {
        self.patterns = Arc::new(std::mem::take(&mut self.unsealed_patterns));
    }

    pub fn add_patterns(&mut self, mut patterns: Vec<regex::Regex>) {
        self.unsealed_patterns.append(&mut patterns);
    }
}


impl FileHandler<Vec<regex::Regex>> for FilenameScanner {
    fn handle_file(result: &ScannerResult, patterns: Arc<Vec<regex::Regex>>) {
        for p in patterns.iter() {
            if p.is_match(result.filename()) {
                result.add_finding(ScannerFinding::Filename(p.to_string()));
            }
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
