use serde::Serialize;

const CSV_SEP: char = ',';

#[derive(PartialEq, Eq, Hash, Serialize)]
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
}
