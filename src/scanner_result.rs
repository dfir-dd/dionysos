use std::collections::HashSet;
use std::fmt::Display;
use std::path::Path;
use serde_json::Value;

use crate::csv_line::CsvLine;
use std::str;

pub trait ScannerFinding: Send + Sync + Display {
    fn format_csv(&self) -> HashSet<CsvLine>;
    fn to_json(&self) -> Value;

    fn found_in_file(&self) -> &str;
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


    pub fn add_findings(&mut self, findings: impl Iterator<Item=Box<dyn ScannerFinding>>) {
        self.findings.extend(findings);
    }

    pub fn has_findings(&self) -> bool {
        ! self.findings.is_empty()
    }

    pub fn findings(&self) -> std::slice::Iter<'_, std::boxed::Box<dyn ScannerFinding>> {
        self.findings.iter()
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
            filename,
            findings: Vec::new()
        }
    }
}

pub fn escape(value: &str) -> String {
    str::replace(value, "\"", "\\\"")
}