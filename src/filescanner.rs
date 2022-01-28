use crate::scanner_result::*;
use std::path::Path;

pub trait FileScanner
{
    fn scan_file(&self, file: &Path) -> Vec<anyhow::Result<ScannerFinding>> ;
}

