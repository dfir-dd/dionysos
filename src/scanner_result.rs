use std::fmt::Display;
use std::path::{PathBuf, Path};
use crate::dionysos::Cli;
use std::fmt;
use std::str;

pub struct CsvLine {
    scanner_name: String,
    rule_name: String,
    found_in_file: String,
    details: String,
}

impl CsvLine {
    pub fn new(scanner_name: &str, rule_name: &str, found_in_file: &str, details: String) -> Self {
        Self {
            scanner_name: scanner_name.to_owned(),
            rule_name: rule_name.to_owned(),
            found_in_file: found_in_file.to_owned(),
            details
        }
    }
}

impl Display for CsvLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            writeln!(f, "\"{}\";\"{}\";\"{}\";\"{}\"",
                self.scanner_name,
                self.rule_name,
                self.found_in_file,
                self.details
            )
        } else {
            writeln!(f, "\"{}\";\"{}\";\"{}\";\"\"",
                self.scanner_name,
                self.rule_name,
                self.found_in_file
            )
        }
    }
}

pub trait ScannerFinding: Send + Sync {
    fn format_readable(&self, f: &mut std::fmt::Formatter, file: &PathBuf) -> std::fmt::Result;
    fn format_csv(&self, file: &str) -> Vec<CsvLine>;
}

pub struct ScannerResult {
    filename: PathBuf,
    findings: Vec<Box<dyn ScannerFinding>>
}

impl ScannerResult {
    pub fn filename(&self) -> &str {
        self.filename.to_str().as_ref().unwrap()
    }

    pub fn add_finding(&mut self, finding: Box<dyn ScannerFinding>) {
        self.findings.push(finding);
    }

    pub fn has_findings(&self) -> bool {
        ! self.findings.is_empty()
    }

    pub (crate) fn display(&self, cli: &Cli) -> String {
        let mut lines = Vec::new();
        let filename = escape(self.filename());
        for finding in self.findings.iter() {
            lines.extend(
                finding.format_csv(&filename).iter().map(|csv| if cli.print_strings {
                    format!("{:#}", csv)
                } else {
                    format!("{}", csv)
                })
            );
        }
        lines.join("")
    }
}

impl From<&Path> for ScannerResult {
    fn from(path: &Path) -> Self {
        Self {
            filename: path.to_owned(),
            findings: Vec::new()
        }
    }
}

pub fn escape(value: &str) -> String {
    str::replace(value, "\"", "\\\"")
}

pub fn escape_vec(v: &Vec<u8>) -> String {
    v.iter()
    .map(|b| {let c = char::from(*b); if c.is_ascii_graphic() {
        c.to_string() } else {
            format!("\\{:02x}", b)
        }
    }).collect::<Vec<String>>().join("")
}