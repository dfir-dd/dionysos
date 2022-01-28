use crate::consumer::*;
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

