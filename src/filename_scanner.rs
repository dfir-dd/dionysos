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

    fn scan_file_str(&self, filename: &str, filepath: &str) -> Vec<anyhow::Result<Box<dyn ScannerFinding>>> {
        let mut results = Vec::new();
        for pattern in self.patterns.iter() {
            if pattern.is_match(filename) {
                results.push(
                    Ok(
                        Box::new(
                            FilenameFinding{
                                pattern: pattern.clone(),
                                found_in_file: filepath.to_owned()
                            }
                        ) as Box<dyn ScannerFinding>
                    )
                )
            }
        }
        results
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
        self.scan_file_str(
            file.file_name().to_str().unwrap_or(& file.file_name().to_string_lossy()), 
            file.path().to_str().unwrap_or(& file.path().to_string_lossy()))
    }
}

struct FilenameFinding {
    pattern: regex::Regex,
    found_in_file: String,
}

impl Display for FilenameFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let found_in_file = self.found_in_file();
        let pattern = &self.pattern;
        writeln!(f, "the name of '{found_in_file}' matches the pattern /{pattern}/")
    }
}

impl ScannerFinding for FilenameFinding {

    fn format_csv(&self) -> HashSet<CsvLine> {
        let file = self.found_in_file();
        hashset![CsvLine::new("Filename", &format!("{}", self.pattern), file, String::new())]
    }
    fn to_json(&self) -> serde_json::Value {
        let file = self.found_in_file();
        json!({
            "01_scanner": "filename",
            "02_suspicious_file": file,
            "03_pattern": format!("{}", self.pattern)
        })
    }

    fn found_in_file(&self) -> &str {
        &self.found_in_file[..]
    }
}