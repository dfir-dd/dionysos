use crate::consumer::*;
use crate::scanner_result::{ScannerFinding};
use std::path::Path;

#[derive(Default)]
pub struct LevenshteinScanner {
}

impl FileScanner for LevenshteinScanner {
    fn scan_file(&self, file: &Path) -> Vec<anyhow::Result<ScannerFinding>> {
        static WELLKNOWN_FILES: [&'static str; 8] = [
            "svchost.exe",
            "explorer.exe",
            "iexplore.exe",
            "lsass.exe",
            "chrome.exe",
            "csrss.exe",
            "firefox.exe",
            "winlogon.exe"
        ];
        match file.to_str() {
            Some(os_fn) => {
                WELLKNOWN_FILES
                    .iter()
                    .filter(|l| levenshtein::levenshtein(os_fn, **l) == 1)
                    .map(|l| Ok(ScannerFinding::Levenshtein((*l).to_owned())))
                    .collect()
            }
            None => vec![]
        }
    }
}

