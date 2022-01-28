# `dionysos`
Scanner for various IoCs

# Installation

```shell
cargo install dionysos
```

# Usage
```
dionysos 0.1.4
Jan Starke <Jan.Starke@t-systems.com>
Scanner for various IoCs

USAGE:
    dionysos [OPTIONS]

OPTIONS:
    -F, --filename <FILENAME_REGEX>    regular expression to match against the basename of files.
                                       This parameter can be specified multiple times
    -h, --help                         Print help information
        --omit-levenshtein             do not run the Levenshtein scanner
    -P, --path <PATH>                  path which must be scanned
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
use crate::filescanner::*;
use crate::scanner_result::{ScannerFinding};
use std::path::Path;

pub struct FilenameScanner {
    patterns: Vec<regex::Regex>,
}

impl FilenameScanner {
    pub fn new(patterns: Vec<regex::Regex>) -> Self {
        Self {   
            patterns,
        }
    }
}

impl FileScanner for FilenameScanner
{
    fn scan_file(&self, file: &Path) -> Vec<anyhow::Result<ScannerFinding>> {
        let filename = file.to_str().unwrap();
        self.patterns
            .iter()
            .filter(|p|p.is_match(&filename))
            .map(|r|Ok(ScannerFinding::Filename(r.to_string())))
            .collect()
    }
}
```

### 3. Add your scanner to the scanner chain

Which is currently hard-coded in `Dionysos::run()` (in [src/dionysos.rs](src/dionysis.rs))

# Feature ideas

- [x] use yara rules,
- [ ] including modules (e.g. import "hash")
- [x] use lists of regular expressions for filesystem searches
- [ ] write results to console / log
- [ ] output must use an easy-to-parse format, while optionally staying human readable to best effort
- [ ] highly optional: use the same list to search MFT & UsnJrnl in case files were deleted
- [x] usage via console, cmd args
- [ ] optional: curses fontend (???)
- [x] configuration of log level via command line
- [x] levensthein-scanner
- [x] use of one parameter to pass yara rules, which might be a file, a zip container or a directory
- [ ] Scan Windows Registry files
- [ ] Scan Windows Event Logs
