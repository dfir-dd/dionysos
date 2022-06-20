use anyhow::Result;

mod filescanner;
mod dionysos;
mod yara;
mod filename_scanner;
mod scanner_result;
mod levenshtein_scanner;
mod hash_scanner;
mod csv_line;

use dionysos::*;

fn main() -> Result <()> {
    let app: Dionysos = Dionysos::new()?;
    app.run()
}
