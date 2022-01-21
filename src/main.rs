use anyhow::Result;

mod file_enumerator;
mod consumer;
mod dionysos;
use dionysos::*;

fn main() -> Result <()> {
    let app: Dionysos = Dionysos::new()?;
    app.run()
}
