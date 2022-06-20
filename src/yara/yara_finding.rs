use std::collections::HashSet;

use crate::scanner_result::{ScannerFinding, CsvLine};

use super::yara_string::YaraString;

pub struct YaraFinding {
    pub identifier: String,
    pub namespace: String,
    //pub metadatas: Vec<Metadata<'r>>,
    pub tags: Vec<String>,
    pub strings: Vec<YaraString>,
    pub value_data: Option<String>
}

impl From<yara::Rule<'_>> for YaraFinding {
    fn from(rule: yara::Rule) -> Self {
        Self {
            identifier: rule.identifier.to_owned(),
            namespace: rule.namespace.to_owned(),
            tags: rule.tags.iter().map(|s|String::from(*s)).collect(),
            strings: rule.strings.into_iter().map(|s| s.into()).collect(),
            value_data: None
        }
    }
}

impl YaraFinding {
    pub fn with_value_data(mut self, data: String) -> Self {
        self.value_data = Some(data);
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

    fn format_csv<'a, 'b>(&'b self, file: &'a str) -> HashSet<crate::scanner_result::CsvLine> {
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
}


pub fn escape_vec(v: &Vec<u8>) -> String {
    v.iter()
    .map(|b| {let c = char::from(*b); if c.is_ascii_graphic() {
        c.to_string() } else {
            format!("\\{:02x}", b)
        }
    }).collect::<Vec<String>>().join("")
}