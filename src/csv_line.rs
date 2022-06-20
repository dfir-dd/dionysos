use std::fmt::{Display, self};

const CSV_SEP: char = ',';

#[derive(PartialEq, Eq, Hash)]
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

    fn escape(value: &str) -> String {
        str::replace(value, "\"", "\"\"")
    }
}

impl Display for CsvLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "\"{}\"{CSV_SEP}\"{}\"{CSV_SEP}\"{}\"{CSV_SEP}\"{}\"",
                Self::escape(&self.scanner_name),
                Self::escape(&self.rule_name),
                Self::escape(&self.found_in_file),
                Self::escape(&self.details)
            )
        } else {
            write!(f, "\"{}\"{CSV_SEP}\"{}\"{CSV_SEP}\"{}\"{CSV_SEP}\"\"",
                Self::escape(&self.scanner_name),
                Self::escape(&self.rule_name),
                Self::escape(&self.found_in_file)
            )
        }
    }
}
