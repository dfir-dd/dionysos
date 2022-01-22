use crate::consumer::*;
use crate::scanner_result::{ScannerResult, ScannerFinding};
use provider_derive::*;
use consumer_derive::*;
use std::sync::Arc;

#[has_consumers_list]
#[has_thread_handle]
#[derive(FileProvider)]
#[derive(FileConsumer)]
#[derive(Default)]
pub struct FilenameScanner {}

impl FileHandler<()> for FilenameScanner {
    fn handle_file(result: &ScannerResult, _data: Arc<()>) {
        if result.filename().ends_with(".rs") {
            result.add_finding(ScannerFinding::Filename("*.rs".to_owned()));
        }        
    }
}

