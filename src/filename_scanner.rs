use yara;
use crate::consumer::*;
use crate::scanner_result::{ScannerResult, ScannerFinding};
use std::sync::mpsc::Receiver;
use std::thread;
use std::sync::Arc;
use provider_derive::*;
use log;

#[derive(FileProvider)]
pub struct FilenameScanner {
    // needed for providers
    consumers: Vec<Box<dyn FileConsumer>>,

    // needed for Consumers
    thread_handle: Option<thread::JoinHandle<()>>
}

//implement_provider_for!(FilenameScanner, consumers);
implement_consumer_for!(FilenameScanner, thread_handle, consumers);

impl FilenameScanner {
    pub fn new() -> Self {
        Self {
            consumers: Vec::new(),
            thread_handle: None
        }
    }

    implement_worker!(FilenameScanner, scan_filename);

    fn scan_filename(result: &ScannerResult) {
        if result.filename().ends_with(".rs") {
            result.add_finding(ScannerFinding::Filename("*.rs".to_owned()));
        }        
    }
}

