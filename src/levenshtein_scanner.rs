use crate::filescanner::*;
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
                    .filter(|l| has_levenshtein_distance_one(os_fn, **l))
                    .map(|l| Ok(ScannerFinding::Levenshtein((*l).to_owned())))
                    .collect()
            }
            None => vec![]
        }
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
#[must_use]
pub fn has_levenshtein_distance_one(a: &str, b: &str) -> bool {
    let mut result = 0;
    let dist = 1;

    /* Shortcut optimizations / degenerate cases. */
    if a == b {
        return false;
    }

    let length_a = a.chars().count();
    let length_b = b.chars().count();

    if length_a == 0 {
        return length_b == dist;
    }

    if length_b == 0 {
        return length_a == dist;
    }

    /* Initialize the vector.
     *
     * This is why it’s fast, normally a matrix is used,
     * here we use a single vector. */
    let mut cache: Vec<usize> = (1..).take(length_a).collect();
    let mut distance_a;
    let mut distance_b;

    /* Loop. */
    for (index_b, code_b) in b.chars().enumerate() {
        result = index_b;
        if result > dist {
            return false;
        }
        distance_a = index_b;

        for (index_a, code_a) in a.chars().enumerate() {
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

            if result > dist {
                return false;
            }

            cache[index_a] = result;
        }
    }

    result == dist
}


#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use crate::filescanner::*;
    use super::LevenshteinScanner;

    #[test]
    fn test_equal() {
        let scanner = LevenshteinScanner::default();
        let filename = env!("CARGO_MANIFEST_DIR").to_owned() + "/explorer.exe";
        let sample = PathBuf::from(&filename);
        let results = scanner.scan_file(&sample);
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
            let results = scanner.scan_file(&sample);
            match results.last() {
                None => assert!(results.is_empty(), "invalid result for {}", filename),
                Some(result) => match result {
                    Err(why) => assert!(false, "error in scan_result: {:?}", why),
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
            let results = scanner.scan_file(&sample);
            assert!(results.is_empty(), "invalid result for {}", filename);
        }
    }
}