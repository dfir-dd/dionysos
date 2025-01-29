use std::collections::HashSet;
use std::fmt::Display;
use serde_json::Value;

use crate::csv_line::CsvLine;
use std::str;

pub trait ScannerFinding: Send + Sync + Display {
    fn format_csv(&self) -> HashSet<CsvLine>;
    fn to_json(&self) -> Value;

    fn found_in_file(&self) -> &str;
}

pub struct ScannerResult {
    findings: Vec<Box<dyn ScannerFinding>>
}

impl ScannerResult {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }
    pub fn add_finding(&mut self, finding: Box<dyn ScannerFinding>) {
        self.findings.push(finding);
    }

    pub fn has_findings(&self) -> bool {
        ! self.findings.is_empty()
    }

    pub fn findings(&self) -> std::slice::Iter<'_, std::boxed::Box<dyn ScannerFinding>> {
        self.findings.iter()
    }
}

pub fn escape(value: &str) -> String {
    str::replace(value, "\"", "\\\"")
}