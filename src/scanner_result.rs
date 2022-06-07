use std::path::{PathBuf, Path};
use crate::dionysos::Cli;
use crate::hash_scanner::CryptoHash;
use crate::yara::YaraFinding;
use std::fmt;
use std::str;

pub enum ScannerFinding {
    Yara(YaraFinding),
    Filename(String),
    Levenshtein(String),
    Hash(CryptoHash)
}

pub struct ScannerResult {
    filename: PathBuf,
    findings: Vec<ScannerFinding>
}

impl ScannerResult {
    pub fn filename(&self) -> &str {
        self.filename.to_str().as_ref().unwrap()
    }

    pub fn add_finding(&mut self, finding: ScannerFinding) {
        self.findings.push(finding);
    }

    pub fn has_findings(&self) -> bool {
        ! self.findings.is_empty()
    }

    pub (crate) fn display(&self, cli: &Cli) -> String {
        let mut lines = Vec::new();
        let filename = escape(self.filename());
        for finding in self.findings.iter() {
            match &finding {
                ScannerFinding::Yara(yara_finding) => {
                    let headline = format!("\"{}\";\"{}\";\"{}\"", "Yara", escape(&yara_finding.identifier), &filename);
                    if cli.print_strings && ! yara_finding.strings.is_empty() {
                        for s in yara_finding.strings.iter() {
                            if s.matches.is_empty() {
                                match &yara_finding.value_data {
                                    None => lines.push(format!("{};\"{}\"", headline, escape(&s.identifier))),
                                    Some(d) => lines.push(format!("{};\"{} in {}\"", headline, escape(&s.identifier), escape(d))),
                                }
                                
                            } else {
                                for m in s.matches.iter() {
                                    match &yara_finding.value_data {
                                        None => lines.push(format!("{};\"{} at offset {:x}: {}\"", headline, escape(&s.identifier), m.offset, escape_vec(&m.data))),
                                        Some(d) => lines.push(format!("{};\"{} at offset {:x}: {} in ({})\"", headline, escape(&s.identifier), m.offset, escape_vec(&m.data), escape(d)))
                                    }
                                }
                            }
                        }
                    } else {
                        lines.push(format!("{};\"\"", headline));
                    }
                }
                ScannerFinding::Filename(regex) => {
                    lines.push(format!("\"{}\";\"{}\";\"{}\";\"\"", "Filename", escape(regex), &filename));
                }
                ScannerFinding::Levenshtein(original) => {
                    lines.push(format!("\"{}\";\"{}\";\"{}\";\"\"", "Levenshtein", escape(original), &filename));
                }
                &ScannerFinding::Hash(hash) => {
                    lines.push(format!("\"{}\";\"{}\";\"{}\";\"\"", "Hash", hash, &filename));
                }
            }
        }
        lines.join("\n") + "\n"
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

pub fn escape(value: &str) -> String {
    str::replace(value, "\"", "\\\"")
}

pub fn escape_vec(v: &Vec<u8>) -> String {
    v.iter()
    .map(|b| {let c = char::from(*b); if c.is_ascii_graphic() {
        c.to_string() } else {
            format!("\\{:02x}", b)
        }
    }).collect::<Vec<String>>().join("")
}

impl fmt::Display for ScannerResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let filename = escape(self.filename());
        for finding in self.findings.iter() {
            match &finding {
                ScannerFinding::Yara(yara_finding) => {
                    writeln!(f, "\"{}\";\"{}\";\"{}\"", "Yara", escape(&yara_finding.identifier), &filename)?;
                }
                ScannerFinding::Filename(regex) => {
                    writeln!(f, "\"{}\";\"{}\";\"{}\"", "Filename", escape(regex), &filename)?;
                }
                ScannerFinding::Levenshtein(original) => {
                    writeln!(f, "\"{}\";\"{}\";\"{}\"", "Levenshtein", escape(original), &filename)?;
                }
                &ScannerFinding::Hash(hash) => {
                    writeln!(f, "\"{}\";\"{}\";\"{}\"", "Hash", hash, &filename)?;
                }
            }
        }
        Ok(())
    }
}