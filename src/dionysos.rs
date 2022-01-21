use anyhow::Result;
use clap::{App, Arg};
use std::path::{PathBuf};

pub struct Dionysos {
    path: PathBuf
}

impl Dionysos {
    pub fn new() -> Result<Self> {
        Self::parse_options()
    }

    pub fn run(&self) -> Result<()> {
        Ok(())
    }

    fn parse_options() -> Result<Self> {
        let app = App::new(env!("CARGO_PKG_NAME"))
            .version(env!("CARGO_PKG_VERSION"))
            .author(env!("CARGO_PKG_AUTHORS"))
            .about(env!("CARGO_PKG_DESCRIPTION"))
            .arg(
                Arg::new("PATH")
                    .help("path to registry hive file")
                    .required(false)
                    .multiple_occurrences(false)
                    .multiple_values(false)
                    .takes_value(true),
            )
            ;
        
        let matches = app.get_matches();
        let path = match matches.value_of("PATH") {
            Some(path) => PathBuf::from(&path),
            None => PathBuf::from("/"),
        };

        Ok(Self {
            path
        })
    }
}