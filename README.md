[![Crates.io](https://img.shields.io/crates/v/dionysos)](https://crates.io/crates/dionysos)
![Crates.io](https://img.shields.io/crates/l/dionysos)
![Crates.io (latest)](https://img.shields.io/crates/dv/dionysos)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/janstarke/dionysos/rust-clippy%20analyze?label=clippy)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/janstarke/dionysos/publish%20at%20crates.io?label=crates.io)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/janstarke/dionysos/Build%20static%20Debian%20package?label=build%20debian%20package)
[![Codecov](https://img.shields.io/codecov/c/github/janstarke/dionysos)](https://app.codecov.io/gh/janstarke/dionysos)

# `dionysos`
Scanner for various IoCs

# Installation

```shell
sudo apt install libyara-dev
cargo install dionysos
```

# Features 

| Feature | Details |
|-|-|
|Scanners | filenames (by regular expressions), similar filenames (Levenshtein), yara, hashes|
| Output formats | human-readable text (txt), comma-separated values (csv, conforming to RFC4180), JavaScript Object Notation (json), can be selected with `--format <txt\|csv\|json>` |
| Scan of compressed files | yara-scan of zip, xz, gz and bz2 compressed files is supported; see `-C` switch. Be aware that files are decompressed into a decompression buffer, and that every thread gets its own decompression buffer. You should make sure that you have sufficient memory. If you need larger buffers, you can limit the number of threads using `--threads` |
| Special features | yara-scan in Windows evtx files and Windows registry hives using `--evtx` and `--reg`|


# Usage
```
Usage: dionysos [OPTIONS]

Options:
  -v, --verbose...
          Increase logging verbosity
  -q, --quiet...
          Decrease logging verbosity
  -P, --path <PATH>
          path which must be scanned
  -f, --format <OUTPUT_FORMAT>
          output format [default: txt] [possible values: csv, txt, json]
  -O, --output-file <OUTPUT_FILE>
          path of the file to write results to. Specify '-' write to STDOUT,
          which is the default
  -Y, --yara <YARA>
          use yara scanner with the specified ruleset. This can be a single
          file, a zip file or a directory containing lots of yara files. Yara
          files must end with 'yar' or 'yara', and zip files must end with 'zip'
      --yara-timeout <YARA_TIMEOUT>
          timeout for the yara scanner, in seconds [default: 240]
  -s, --print-strings
          print matching strings (only used by yara currently)
      --evtx
          also do YARA scan in Windows EVTX records (exported as JSON)
      --reg
          also do YARA scan in Windows registry hive files
  -C, --scan-compressed
          allow yara to scan compressed files. Currently, xz, bz2 and gz are
          supported
      --decompression-buffer <DECOMPRESSION_BUFFER_SIZE>
          maximum size (in MiB) of decompression buffer (per thread), which is
          used to scan compressed files [default: 128]
      --exclude-pattern <EXCLUDE_PATTERN>
          do not scan files whose names match the specified regular expression
          (case sensitive match)
  -H, --file-hash <FILE_HASH>
          Hash of file to match against. Use any of MD5, SHA1 or SHA256. This
          parameter can be specified multiple times
  -F, --filename <FILENAMES>
          regular expression to match against the basename of files. This
          parameter can be specified multiple times
      --levenshtein
          run the Levenshtein scanner
  -p, --threads <THREADS>
          use the specified NUMBER of threads [default: 24]
      --progress
          display a progress bar (requires counting the number of files to be
          scanned before a progress bar can be displayed)
  -L, --log-file <LOG_FILE>
          path of the file to write error logs to. Error logs will always be
          appended Be aware that this are not the results (e.g. matching yara
          rules) of this program
  -h, --help
          Print help
  -V, --version
          Print version
```

# Developer guide

## How to add scanners

### 1. Implement a special result type for the scanner

For example, say we want to scan for files whose name match a regular expression. Our finding type could look like this:

```rust
struct FilenameFinding {
    filename: String,
    pattern: regex::Regex,
}
```

Every finding type needs to implement `Display` and `ScannerFinding`:

```rust
impl ScannerFinding for FilenameFinding {

    fn format_readable(&self, file: &str, _show_details: bool) -> Vec<String> {
        vec![
            format!("the name of '{}' matches the pattern /{}/", file, self.pattern)
        ]
    }

    fn format_csv<'a, 'b>(&'b self, file: &'a str) -> HashSet<crate::scanner_result::CsvLine> {
        hashset![CsvLine::new("Filename", &self.filename, file, String::new())]
    }

    fn to_json(&self, file: &str) -> serde_json::Value {
        json!({
            "01_scanner": "filename",
            "02_suspicious_file": file,
            "03_pattern": format!("{}", self.pattern)
        })
    }
}
```

### 2. Implementation of the scanner

Take, for example, the `FilenameScanner`, which tries to do a simple filename match:

```rust
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

impl Display for FilenameScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", "FilenameScanner")
    }
}

impl FileScanner for FilenameScanner
{
    fn scan_file(&self, file: &DirEntry) -> Vec<anyhow::Result<Box<dyn ScannerFinding>>> {
        let file = file.path();
        let filename = file.to_str().unwrap();
        let mut results = Vec::new();
        for pattern in self.patterns.iter() {
            if pattern.is_match(&filename) {
                results.push(
                    Ok(
                        Box::new(
                            FilenameFinding{
                                filename: filename.to_owned(),
                                pattern: pattern.clone()
                            }
                        ) as Box<dyn ScannerFinding>
                    )
                )
            }
        }
        results
    }
}
```

### 3. Add your scanner to the scanner chain

Which is currently hard-coded in `Dionysos::run()` (in [src/dionysos.rs](src/dionysos.rs))
