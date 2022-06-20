# `dionysos`
Scanner for various IoCs

# Installation

```shell
sudo apt install libyara-dev
cargo install dionysos
```

# Usage
```
dionysos 0.11.0
Jan Starke <Jan.Starke@t-systems.com>
Scanner for various IoCs

USAGE:
    dionysos [OPTIONS]

OPTIONS:
    -C, --scan-compressed
            allow yara to scan compressed files. Currently, xz, bz2 and gz are supported

        --decompression-buffer <DECOMPRESSION_BUFFER_SIZE>
            maximum size (in MiB) of decompression buffer (per thread), which is used to scan
            compressed files [default: 128]

        --evtx
            also do YARA scan in Windows EVTX records (exported as JSON)

    -f, --format <OUTPUT_FORMAT>
            output format [default: txt] [possible values: csv, txt]

    -F, --filename <FILENAMES>
            regular expression to match against the basename of files. This parameter can be
            specified multiple times

    -h, --help
            Print help information

    -H, --file-hash <FILE_HASH>
            Hash of file to match against. Use any of MD5, SHA1 or SHA256

    -L, --log-file <LOG_FILE>
            path of the file to write logs to. Logs will always be appended

        --omit-levenshtein
            do not run the Levenshtein scanner

    -p, --threads <THREADS>
            use the specified NUMBER of threads [default: 16]

    -P, --path <PATH>
            path which must be scanned

        --progress
            display a progress bar (requires counting the number of files to be scanned before a
            progress bar can be displayed)

    -q, --quiet
            Less output per occurrence

        --reg
            also do YARA scan in Windows registry hive files

    -s, --print-strings
            print matching strings (only used by yara currently)

    -v, --verbose
            More output per occurrence

    -V, --version
            Print version information

    -Y, --yara <YARA>
            use yara scanner with the specified ruleset. This can be a single file, a zip file or a
            directory containing lots of yara files. Yara files must end with 'yar' or 'yara', and
            zip files must end with 'zip'

        --yara-timeout <YARA_TIMEOUT>
            timeout for the yara scanner, in seconds [default: 240]

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
use walkdir::DirEntry;

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
    fn scan_file(&self, file: &DirEntry) -> Vec<anyhow::Result<ScannerFinding>> {
        let filename = file.path().to_str().unwrap();
        self.patterns
            .iter()
            .filter(|p|p.is_match(&filename))
            .map(|r|Ok(ScannerFinding::Filename(r.to_string())))
            .collect()
    }
}
```

### 3. Add your scanner to the scanner chain

Which is currently hard-coded in `Dionysos::run()` (in [src/dionysos.rs](src/dionysos.rs))
