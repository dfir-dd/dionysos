use maplit::hashset;
use serde_json::json;
use walkdir::DirEntry;

use crate::filescanner::*;
use crate::csv_line::CsvLine;
use crate::scanner_result::ScannerFinding;
use std::collections::HashSet;
use std::fmt::Display;
use std::path::Path;
pub struct LevenshteinScanner {
    wellknown_files: Vec<Vec<char>>
}

impl Default for LevenshteinScanner {
    fn default() -> Self {
        static WELLKNOWN_FILES: [&str; 8] = [
            "svchost.exe",
            "explorer.exe",
            "iexplore.exe",
            "lsass.exe",
            "chrome.exe",
            "csrss.exe",
            "firefox.exe",
            "winlogon.exe"
        ];
        let wellknown_files = WELLKNOWN_FILES.iter().map(|s| s.chars().collect()).collect();
        Self {
            wellknown_files
        }
    }
}

impl FileScanner for LevenshteinScanner {
    fn scan_file(&self, file: &DirEntry) -> Vec<anyhow::Result<Box<dyn ScannerFinding>>> {
        self.intern_scan_file(file.path())
    }
}

impl Display for LevenshteinScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "LevenshteinScanner")
    }
}

impl LevenshteinScanner {
    fn intern_scan_file(&self, file: &Path) -> Vec<anyhow::Result<Box<dyn ScannerFinding>>> {        
        match file.file_name() {
            None => vec![],
            Some(file_name) => match file_name.to_str() {
                Some(os_fn) => {
                    let res:  Vec<anyhow::Result<Box<dyn ScannerFinding>>> = self.wellknown_files
                        .iter()
                        .filter(|l| has_levenshtein_distance_one(&os_fn.chars().collect(), l))
                        .map(|l| Ok(Box::new(LevenshteinScannerFinding{file_name: l.iter().collect()}) as Box<dyn ScannerFinding>))
                        .collect();
                    if file_name == "expl0rer.exe" {
                        assert_eq!(res.len(), 1);
                    }
                    res
                }
                None => vec![]
            }
        }
    }
}


struct LevenshteinScannerFinding {
    file_name: String,
}

impl ScannerFinding for LevenshteinScannerFinding {
    fn format_readable(&self, file: &str, _show_details: bool) -> Vec<String> {
        vec![
            format!("the name of the file {} is very similar to {}", file, self.file_name)
        ]
    }

    fn format_csv(&self, file: &str) -> HashSet<CsvLine> {
        hashset![CsvLine::new("Levenshtein", &self.file_name, file, String::new())]
    }

    fn to_json(&self, file: &str) -> serde_json::Value {
        json!({
            "01_scanner": "levenshtein",
            "02_suspicious_file": file,
            "03_original_name": self.file_name
        })
    }
}

/**
 * This function was inspirered by:
 * https://github.com/wooorm/levenshtein-rs
 * 
 * `levenshtein-rs` - levenshtein
 *
 * MIT licensed.
 *
 * Copyright (c) 2016 Titus Wormer <tituswormer@gmail.com>
 */
pub fn has_levenshtein_distance_one(a: &Vec<char>, b: &Vec<char>) -> bool {
    let mut result = 0;
    let dist = 1;

    /* Shortcut optimizations / degenerate cases. */
    if a == b {
        return false;
    }

    let length_a = a.len();
    let length_b = b.len();

    if length_a == 0 {
        return length_b == dist;
    }

    if length_b == 0 {
        return length_a == dist;
    }

    // if both string lengths differ more than 1, their
    // Levenshtein distance must be more than 1
    if length_a > length_b {
        if length_a - length_b > 1 {
            return false;
        }
    } else if length_b - length_a > 1 {
        return false;
    }

    /* Initialize the vector.
     *
     * This is why it’s fast, normally a matrix is used,
     * here we use a single vector. */
    let mut cache: Vec<usize> = (1..).take(length_a).collect();
    let mut distance_a;
    let mut distance_b;

    /* Loop. */
    for (index_b, code_b) in b.iter().enumerate() {
        result = index_b;
        distance_a = index_b;

        for (index_a, code_a) in a.iter().enumerate() {
            distance_b = if code_a == code_b {
                distance_a
            } else {
                distance_a + 1
            };

            distance_a = cache[index_a];

            result = if distance_a > result {
                if distance_b > result {
                    result + 1
                } else {
                    distance_b
                }
            } else if distance_b > distance_a {
                distance_a + 1
            } else {
                distance_b
            };

            cache[index_a] = result;
        }
    }

    result == dist
}


#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use super::LevenshteinScanner;

    #[test]
    fn test_equal() {
        let scanner = LevenshteinScanner::default();
        let filename = env!("CARGO_MANIFEST_DIR").to_owned() + "/explorer.exe";
        let sample = PathBuf::from(&filename);
        let results = scanner.intern_scan_file(&sample);
        assert!(results.is_empty(), "invalid result for {}", filename);
    }

    #[test]
    fn test_distance_one() {
        let samples = vec![
            "expl0rer.exe",
            "explor3r.exe",
            "3xplorer.exe"
        ];
        let scanner = LevenshteinScanner::default();
        for sample_fn in samples {
            let filename = env!("CARGO_MANIFEST_DIR").to_owned() + sample_fn;
            let sample = PathBuf::from(&filename);
            let results = scanner.intern_scan_file(&sample);
            match results.last() {
                None => assert!(results.is_empty(), "invalid result for {}", filename),
                Some(result) => match result {
                    Err(why) => panic!("error in scan_result: {:?}", why),
                    Ok(_) => ()
                }
            }
        }
    }


    #[test]
    fn test_distance_more_than_one() {
        let samples = vec![
            "3xpl0rer.exe",
            "expl0r3r.exe",
            "3xpl0rer.exe"
        ];
        let scanner = LevenshteinScanner::default();
        for sample_fn in samples {
            let filename = env!("CARGO_MANIFEST_DIR").to_owned() + sample_fn;
            let sample = PathBuf::from(&filename);
            let results = scanner.intern_scan_file(&sample);
            assert!(results.is_empty(), "invalid result for {}", filename);
        }
    }
}