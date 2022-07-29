use std::{collections::HashSet, fmt::Display};

use assert_cmd::assert::IntoOutputPredicate;
use predicates_core::{reflection::PredicateReflection, Predicate};

use crate::common::{data_path, filenames_from_json};

use super::DionysosPredicate;


pub (crate)struct JsonFormatOutputPredicate<'a> {
    expected_files: Vec<&'a str>
}

impl<'a> JsonFormatOutputPredicate<'a> {
    #[allow(dead_code)]
    pub fn new(expected_files: Vec<&'a str>) -> Self {
        Self {
            expected_files
        }
    }
}

pub (crate) struct JsonOutputContainsFiles {
    expected_files: HashSet<String>
}

impl JsonOutputContainsFiles {
    pub fn new(expected_files: Vec<&str>) -> Self {
        let data_path = data_path();
        let expected_files: HashSet<String> = expected_files.into_iter().map(|s|data_path.join(s).display().to_string()).collect();
        Self {
            expected_files
        }
    }
}

impl Display for JsonOutputContainsFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JsonFormatOutputPredicate")
    }
}

impl PredicateReflection for JsonOutputContainsFiles {}

impl Predicate<[u8]> for JsonOutputContainsFiles {
    fn eval(&self, variable: &[u8]) -> bool {
        let x = String::from_utf8_lossy(variable);
        println!("parsing: {}", x);

        let files = filenames_from_json(variable);
        assert_eq!(files, self.expected_files);
        true
    }
}

impl<'a> IntoOutputPredicate<JsonOutputContainsFiles> for JsonFormatOutputPredicate<'a> {
    type Predicate = JsonOutputContainsFiles;

    fn into_output(self) -> JsonOutputContainsFiles {
        Self::Predicate::new(self.expected_files)
    }
}

impl<'a> DionysosPredicate<JsonOutputContainsFiles> for JsonFormatOutputPredicate<'a>{
    fn expected_format(&self) -> libdionysos::OutputFormat {
        libdionysos::OutputFormat::Json
    }
}