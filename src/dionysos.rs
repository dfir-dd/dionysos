use anyhow::Result;
use clap::{App, Arg};
use std::path::PathBuf;

use crate::file_enumerator::*;
use crate::consumer::*;
use crate::yara_scanner::YaraScanner;
use crate::filename_scanner::FilenameScanner;
use crate::stdout_printer::StdoutPrinter;

pub struct Dionysos {
    path: PathBuf
}

impl Dionysos {
    pub fn new() -> Result<Self> {
        Self::parse_options()
    }

    pub fn run(&self) -> Result<()> {
        let mut enumerator = FileEnumerator::new(self.path.clone());

        let mut yara_scanner = YaraScanner::new();
        let mut filename_scanner = FilenameScanner::new();
        yara_scanner.register_consumer(StdoutPrinter::new());
        filename_scanner.register_consumer(yara_scanner);
        enumerator.register_consumer(filename_scanner);
        enumerator.run()?;

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
                    .long("path")
                    .short('P')
                    .required(false)
                    .multiple_occurrences(false)
                    .multiple_values(false)
                    .takes_value(true),
            )
            ;
        
        let matches = app.get_matches();
        let path = match matches.value_of("PATH") {
            Some(path) => PathBuf::from(&path),

            #[cfg(target_os = "windows")]
            None => PathBuf::from("\\"),

            #[cfg(not(target_os = "windows"))]
            None => PathBuf::from("/"),
        };

        Ok(Self {
            path
        })
    }
}