use crate::consumer::*;
use crate::scanner_result::{ScannerResult, ScannerFinding};
use dionysos_provider_derive::*;
use dionysos_consumer_derive::*;
use std::sync::Arc;

#[has_consumers_list]
#[has_thread_handle]
#[derive(FileProvider)]
#[derive(FileConsumer)]
#[derive(Default)]
pub struct FilenameScanner {
    #[consumer_data]
    patterns: Arc<Vec<regex::Regex>>,

    unsealed_patterns: Vec<regex::Regex>,
}

impl FilenameScanner {
    pub fn seal(&mut self) {
        self.patterns = Arc::new(std::mem::take(&mut self.unsealed_patterns));
    }

    pub fn add_patterns(&mut self, mut patterns: Vec<regex::Regex>) {
        self.unsealed_patterns.append(&mut patterns);
    }
}


impl FileHandler<Vec<regex::Regex>> for FilenameScanner {
    fn handle_file(result: &ScannerResult, patterns: Arc<Vec<regex::Regex>>) {
        for p in patterns.iter() {
            if p.is_match(result.filename()) {
                result.add_finding(ScannerFinding::Filename(p.to_string()));
            }
        }
    }
}

