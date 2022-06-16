use std::fmt::Display;

use walkdir::DirEntry;

use crate::filescanner::*;
use crate::scanner_result::{ScannerFinding, CsvLine};

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
        self.patterns
            .iter()
            .filter(|p|p.is_match(&filename))
            .map(|r|Ok(Box::new(FilenameFinding{filename: r.to_string()}) as Box<dyn ScannerFinding>))
            .collect()
    }
}


struct FilenameFinding {
    filename: String,
}

impl ScannerFinding for FilenameFinding {
    fn format_readable(&self, f: &mut std::fmt::Formatter, file: &std::path::PathBuf) -> std::fmt::Result {
        todo!()
    }

    fn format_csv<'a, 'b>(&'b self, file: &'a str) -> Vec<crate::scanner_result::CsvLine> {
        vec![CsvLine::new("Filename", &self.filename, file, String::new())]
    }
}