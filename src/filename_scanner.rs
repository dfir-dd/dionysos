use crate::consumer::*;
use crate::scanner_result::{ScannerResult, ScannerFinding};
use dionysos_derives::*;
use std::sync::Arc;

#[derive(FileProvider)]
#[derive(FileConsumer)]
pub struct FilenameScanner {
    #[consumer_data]
    patterns: Arc<Vec<regex::Regex>>,

    #[consumers_list]
    consumers: Vec<Box<dyn FileConsumer>>,

    #[thread_handle]
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl FilenameScanner {
    pub fn new(patterns: Vec<regex::Regex>) -> Self {
        Self {
            patterns: Arc::new(patterns),
            consumers: Vec::default(),
            thread_handle: None
        }
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

