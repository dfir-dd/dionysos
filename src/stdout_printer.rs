use std::sync::Arc;
use crate::consumer::*;
use crate::scanner_result::ScannerResult;
use dionysos_provider_derive::*;
use dionysos_consumer_derive::*;

#[has_consumers_list] // FIXME: this struct does not need a consumers list
#[has_thread_handle]
#[derive(FileConsumer)]
#[derive(Default)]
pub struct StdoutPrinter {}


impl FileHandler<()> for StdoutPrinter {
    fn handle_file(result: &ScannerResult, _: Arc<()>) {
        if result.has_findings() {
            println!("{}", result.filename());
        }
    }
}