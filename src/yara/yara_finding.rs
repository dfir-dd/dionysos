use std::collections::HashSet;

use serde_json::{json, Value};

use crate::csv_line::CsvLine;
use crate::scanner_result::ScannerFinding;

use super::yara_string::YaraString;

pub struct YaraFinding {
    pub identifier: String,
    pub namespace: String,
    //pub metadatas: Vec<Metadata<'r>>,
    pub tags: Vec<String>,
    pub strings: Vec<YaraString>,
    pub value_data: Option<String>,
    pub contained_file: Option<String>
}

impl From<yara::Rule<'_>> for YaraFinding {
    fn from(rule: yara::Rule) -> Self {
        Self {
            identifier: rule.identifier.to_owned(),
            namespace: rule.namespace.to_owned(),
            tags: rule.tags.iter().map(|s|String::from(*s)).collect(),
            strings: rule.strings.into_iter().map(|s| s.into()).collect(),
            value_data: None,
            contained_file: None,
        }
    }
}

impl YaraFinding {
    
    pub fn with_value_data(mut self, data: String) -> Self {
        self.value_data = Some(data);
        self
    }

    pub fn with_contained_file(mut self, file: &str) -> Self {
        self.contained_file = Some(file.to_owned());
        self
    }
}


impl ScannerFinding for YaraFinding {
    fn format_readable(&self, file: &str, show_details: bool) -> Vec<String> {
        let mut lines = Vec::new();
        
        lines.push(format!("Yara: {} {}", self.identifier, file));

        if show_details {
            for s in self.strings.iter() {
                if s.matches.is_empty() {
                    match &self.value_data {
                        None => lines.push(format!("  {} matches", s.identifier)),
                        Some(d) => lines.push(format!("  '{}' matches to {}", d,s.identifier)),
                    }
                } else {
                    match &self.value_data {
                        None => lines.push(format!("  {} has the following matches:", s.identifier)),
                        Some(d) => lines.push(format!("  {} has the following matches in '{}':", s.identifier, d))
                    }
                
                    for m in s.matches.iter() {
                        lines.push(format!("    0x{:08x}: {}", m.offset, escape_vec(&m.data)));
                    }
                }
            }
        } 
        lines
    }

    fn format_csv(&self, file: &str) -> HashSet<CsvLine> {
        let mut lines = HashSet::new();

        if self.strings.is_empty() {
            lines.insert(
                CsvLine::new("Yara", &self.identifier, file, String::new())
            );
        } else {
            for s in self.strings.iter() {
                if s.matches.is_empty() {
                    match &self.value_data {
                        None => {lines.insert(
                            CsvLine::new("Yara",&self.identifier,file,s.identifier.clone())
                        );}
                        Some(d) => {lines.insert(
                            CsvLine::new("Yara",&self.identifier,file,format!("{} in {}", s.identifier, d))
                        );}
                    }
                } else {
                    for m in s.matches.iter() {
                        match &self.value_data {
                            None => {lines.insert(
                                CsvLine::new("Yara",&self.identifier,file,
                                format!("{} at offset {:x}: {}", s.identifier, m.offset, escape_vec(&m.data)))
                            );}
                            Some(d) => {lines.insert(
                                CsvLine::new("Yara",&self.identifier,file,
                                format!("{} at offset {:x}: {} in ({})", s.identifier, m.offset, escape_vec(&m.data), d))
                            );}
                        }
                    }
                }
            }
        }

        lines
    }
    fn to_json(&self, file: &str) -> serde_json::Value {
        json!({
            "01_scanner": "yara",
            "02_suspicious_file": file,
            "03_value": self.value_data,
            "04_strings": self.strings.iter().map(|s: &YaraString| {
                json!({
                    "identifier": s.identifier,
                    "matches": s.matches.iter().map(|m| json!({
                        "offset": m.offset,
                        "data": escape_vec(&m.data)
                    })).collect::<Vec<Value>>()
                })
            }).collect::<Vec<Value>>(),
            "05_contained_file": self.contained_file
        })
    }
}


pub fn escape_vec(v: &[u8]) -> String {
    v.iter()
    .map(|b| {let c = char::from(*b); if c.is_ascii_graphic() {
        c.to_string() } else {
            format!("\\{:02x}", b)
        }
    }).collect::<Vec<String>>().join("")
}