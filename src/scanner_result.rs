use std::path::{PathBuf, Path};
use crate::yara_scanner::YaraFinding;
use std::fmt;
use std::str;

pub enum ScannerFinding {
    Yara(YaraFinding),
    Filename(String),
    Levenshtein(String),
}

pub struct ScannerResult {
    filename: PathBuf,
    findings: Vec<ScannerFinding>
}

impl ScannerResult {
    pub fn filename(&self) -> &str {
        self.filename.to_str().as_ref().unwrap()
    }

    pub fn raw_filename(&self) -> &PathBuf {
        &self.filename
    }

    pub fn add_finding(&mut self, finding: ScannerFinding) {
        self.findings.push(finding);
    }

    pub fn has_findings(&self) -> bool {
        ! self.findings.is_empty()
    }
}

impl From<&Path> for ScannerResult {
    fn from(path: &Path) -> Self {
        Self {
            filename: path.to_owned(),
            findings: Vec::new()
        }
    }
}

fn escape(value: &str) -> String {
    str::replace(value, "\"", "\\\"")
}

impl fmt::Display for ScannerResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let filename = escape(self.filename());
        for finding in self.findings.iter() {
            match finding {
                ScannerFinding::Yara(yara_finding) => {
                    write!(f, "\"{}\";\"{}\";\"{}\"", "Yara", escape(&yara_finding.identifier), &filename)?;
                }
                ScannerFinding::Filename(regex) => {
                    write!(f, "\"{}\";\"{}\";\"{}\"", "Filename", escape(regex), &filename)?;
                }
                ScannerFinding::Levenshtein(original) => {
                    write!(f, "\"{}\";\"{}\";\"{}\"", "Levenshtein", escape(original), &filename)?;
                }
            }
        }
        Ok(())
    }
}