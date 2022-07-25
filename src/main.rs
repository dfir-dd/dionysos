use anyhow::Result;
use clap::Parser;
use libdionysos::{Cli, Dionysos};

fn main() -> Result <()> {
    let cli = Cli::parse();
    let app: Dionysos = Dionysos::new(cli)?;
    app.run()
}
