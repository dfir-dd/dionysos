use std::sync::Arc;
use crate::consumer::*;
use crate::scanner_result::ScannerResult;

#[derive(Default)]
pub struct StdoutPrinter {
}

impl FileHandler<()> for StdoutPrinter {
    fn handle_file(result: &ScannerResult, _: Arc<()>) {
        if result.has_findings() {
            println!("{}", result);
        }
    }
}