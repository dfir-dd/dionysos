use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use crate::consumer::*;
use crate::scanner_result::ScannerResult;
use consumer_derive::*;

#[has_thread_handle]
pub struct StdoutPrinter {
}

implement_consumer_for!(StdoutPrinter, thread_handle);

impl StdoutPrinter {
    pub fn new() -> Self {
        Self {
            thread_handle: None,
        }
    }

    implement_worker!(StdoutPrinter, print_filename);
    fn print_filename(result: &ScannerResult) {
        if result.has_findings() {
            println!("{}", result.filename());
        }
    }
}