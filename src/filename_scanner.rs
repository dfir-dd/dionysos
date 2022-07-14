use std::collections::HashSet;
use std::fmt::Display;

use maplit::hashset;
use serde_json::json;
use walkdir::DirEntry;

use crate::filescanner::*;
use crate::csv_line::CsvLine;
use crate::scanner_result::ScannerFinding;

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
        write!(f, "FilenameScanner")
    }
}

impl FileScanner for FilenameScanner
{
    fn scan_file(&self, file: &DirEntry) -> Vec<anyhow::Result<Box<dyn ScannerFinding>>> {
        let file = file.path();
        let filename = file.to_str().unwrap();
        let mut results = Vec::new();
        for pattern in self.patterns.iter() {
            if pattern.is_match(filename) {
                results.push(
                    Ok(
                        Box::new(
                            FilenameFinding{
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

struct FilenameFinding {
    pattern: regex::Regex,
}

impl ScannerFinding for FilenameFinding {
    fn format_readable(&self, file: &str, _show_details: bool) -> Vec<String> {
        vec![
            format!("the name of '{}' matches the pattern /{}/", file, self.pattern)
        ]
    }

    fn format_csv(&self, file: &str) -> HashSet<CsvLine> {
        hashset![CsvLine::new("Filename", &format!("{}", self.pattern), file, String::new())]
    }
    fn to_json(&self, file: &str) -> serde_json::Value {
        json!({
            "01_scanner": "filename",
            "02_suspicious_file": file,
            "03_pattern": format!("{}", self.pattern)
        })
    }
}