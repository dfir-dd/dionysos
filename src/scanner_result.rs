use std::path::{PathBuf, Path};
use std::sync::Mutex;
use crate::yara_scanner::YaraFinding;

pub enum ScannerFinding {
    Yara(YaraFinding),
    Filename(String)
}

pub struct ScannerResult {
    filename: PathBuf,
    findings: Mutex<Vec<ScannerFinding>>
}

impl ScannerResult {
    pub fn filename(&self) -> &str {
        self.filename.to_str().as_ref().unwrap()
    }

    pub fn add_finding(&self, finding: ScannerFinding) {
        if let Ok(mut findings) = self.findings.lock() {
            findings.push(finding);
        }
    }

    pub fn has_findings(&self) -> bool {
        match self.findings.lock() {
            Ok(findings) => {
                ! findings.is_empty()
            }
            Err(why) => {
                panic!("unable to acquire lock to results of '{}': {}", self.filename(), why)
            }
        }
    }
}

impl From<&Path> for ScannerResult {
    fn from(path: &Path) -> Self {
        Self {
            filename: path.to_owned(),
            findings: Mutex::new(Vec::new())
        }
    }
}