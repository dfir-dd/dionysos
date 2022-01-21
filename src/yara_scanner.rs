use yara;
use crate::consumer::*;
use crate::scanner_result::ScannerResult;
use std::sync::mpsc::Receiver;
use std::thread;
use std::sync::Arc;
use log;

pub struct YaraScanner {
    // needed for providers
    consumers: Vec<Box<dyn FileConsumer>>,

    // needed for Consumers
    thread_handle: Option<thread::JoinHandle<()>>
}

implement_provider_for!(YaraScanner, consumers);
implement_consumer_for!(YaraScanner, thread_handle, consumers);

impl YaraScanner {
    pub fn new() -> Self {
        Self {
            consumers: Vec::new(),
            thread_handle: None
        }
    }

    implement_worker!(YaraScanner, scan_yara);

    fn scan_yara(result: &ScannerResult) {
        
    }
}

