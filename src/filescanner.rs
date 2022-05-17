use walkdir::DirEntry;

use crate::scanner_result::*;

pub trait FileScanner
{
    fn scan_file(&self, file: &DirEntry) -> Vec<anyhow::Result<ScannerFinding>>;
}

pub trait CloneScanner {
    fn clone_scanner(&self) -> Self;
}