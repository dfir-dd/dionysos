use anyhow::Result;

#[macro_use]
mod macros;

mod file_enumerator;
mod consumer;
mod dionysos;
mod yara_scanner;
use dionysos::*;

fn main() -> Result <()> {
    let app: Dionysos = Dionysos::new()?;
    app.run()
}
