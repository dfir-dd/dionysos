use anyhow::Result;

mod dionysos;
use dionysos::*;

fn main() -> Result <()> {
    let app: Dionysos = Dionysos::new()?;
    app.run()
}
