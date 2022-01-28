use anyhow::Result;

mod filescanner;
mod dionysos;
mod yara_scanner;
mod filename_scanner;
mod scanner_result;
mod levenshtein_scanner;
use dionysos::*;

fn main() -> Result <()> {
    let app: Dionysos = Dionysos::new()?;
    app.run()
}
