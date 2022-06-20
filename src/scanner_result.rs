use std::collections::HashSet;
use std::fmt::Display;
use std::path::{PathBuf, Path};
use serde_json::Value;

use crate::dionysos::Cli;
use std::fmt;
use std::str;

#[derive(PartialEq, Eq, Hash)]
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
            write!(f, "\"{}\";\"{}\";\"{}\";\"{}\"",
                escape(&self.scanner_name),
                escape(&self.rule_name),
                escape(&self.found_in_file),
                escape(&self.details)
            )
        } else {
            write!(f, "\"{}\";\"{}\";\"{}\";\"\"",
                escape(&self.scanner_name),
                escape(&self.rule_name),
                escape(&self.found_in_file)
            )
        }
    }
}

pub trait ScannerFinding: Send + Sync {
    fn format_readable(&self, file: &str, show_details: bool) -> Vec<String>;
    fn format_csv(&self, file: &str) -> HashSet<CsvLine>;
    fn to_json(&self, file: &str) -> Value;
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
        let mut unique_lines = HashSet::new();
        let mut lines = Vec::new();
        let filename = escape(self.filename());
        for finding in self.findings.iter() {
            match cli.output_format {
                crate::dionysos::OutputFormat::CSV => {
                    unique_lines.extend(
                        finding.format_csv(&filename).iter().map(|csv| if cli.print_strings {
                            format!("{:#}", csv)
                        } else {
                            format!("{}", csv)
                        })
                    );
                },
                crate::dionysos::OutputFormat::TXT => {
                    lines.extend(
                        finding.format_readable( &filename, cli.print_strings)
                    );
                },
                crate::dionysos::OutputFormat::JSON => {
                    lines.push(
                        finding.to_json(&filename).to_string()
                    )
                }
            }
        }
        lines.extend(unique_lines);
        lines.join("\n")
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