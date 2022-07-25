use serde::{Serialize, Deserialize};

#[derive(PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CsvLine {
    scanner_name: String,
    rule_name: String,
    found_in_file: String,
    details: String,
}

impl CsvLine {
    pub fn new(scanner_name: &str, rule_name: &str, found_in_file: &str, details: String) -> Self {
        Self {
            scanner_name: scanner_name.to_owned(),
            rule_name: rule_name.to_owned(),
            found_in_file: found_in_file.to_owned(),
            details
        }
    }

    pub fn found_in_file(&self) -> &str {
        &self.found_in_file[..]
    }

    pub fn rule_name(&self) -> &str {
        &self.rule_name[..]
    }
}
