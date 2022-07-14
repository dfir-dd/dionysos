use std::collections::HashSet;
use std::path::{Path};
use serde_json::Value;

use crate::csv_line::CsvLine;
use crate::dionysos::Cli;
use std::str;

pub trait ScannerFinding: Send + Sync {
    fn format_readable(&self, file: &str, show_details: bool) -> Vec<String>;
    fn format_csv(&self, file: &str) -> HashSet<CsvLine>;
    fn to_json(&self, file: &str) -> Value;
}

pub struct ScannerResult {
    filename: String,
    findings: Vec<Box<dyn ScannerFinding>>
}

impl ScannerResult {
    pub fn filename(&self) -> &str {
        &self.filename[..]
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
            filename: path.to_string_lossy().to_string(),
            findings: Vec::new()
        }
    }
}

impl From<String> for ScannerResult {
    fn from(filename: String) -> Self {
        Self {
            filename: filename,
            findings: Vec::new()
        }
    }
}

pub fn escape(value: &str) -> String {
    str::replace(value, "\"", "\\\"")
}