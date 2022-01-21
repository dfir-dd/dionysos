use anyhow::Result;

mod file_enumerator;
mod consumer;
mod dionysos;
mod yara_scanner;
mod filename_scanner;
mod stdout_printer;
mod scanner_result;
use dionysos::*;

fn main() -> Result <()> {
    let app: Dionysos = Dionysos::new()?;
    app.run()
}
