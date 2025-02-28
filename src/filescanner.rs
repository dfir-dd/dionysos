use std::fmt::Display;
use walkdir::DirEntry;
use crate::scanner_result::*;

pub trait FileScanner: Display + Sync + Send
{
    fn scan_file(&self, file: &DirEntry) -> Vec<anyhow::Result<Box<dyn ScannerFinding>>>;
}
