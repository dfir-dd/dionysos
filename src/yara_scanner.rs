use yara;
use crate::consumer::*;
use crate::scanner_result::ScannerResult;
use std::sync::mpsc::Receiver;
use std::thread;
use std::sync::Arc;
use provider_derive::*;
use consumer_derive::*;
use log;

#[has_consumers_list]
#[has_thread_handle]
#[derive(FileProvider)]
#[derive(FileConsumer)]
#[derive(Default)]
pub struct YaraScanner {}

impl FileHandler for YaraScanner {
    fn handle_file(result: &ScannerResult) {
        
    }
}

