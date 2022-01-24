use std::sync::Arc;
use crate::consumer::*;
use crate::scanner_result::ScannerResult;
use dionysos_provider_derive::*;
use dionysos_consumer_derive::*;

#[derive(FileConsumer)]
#[derive(Default)]
pub struct StdoutPrinter {
    #[thread_handle]
    thread_handle: Option<std::thread::JoinHandle<()>>,
}


impl FileHandler<()> for StdoutPrinter {
    fn handle_file(result: &ScannerResult, _: Arc<()>) {
        if result.has_findings() {
            println!("{}", result.filename());
        }
    }
}