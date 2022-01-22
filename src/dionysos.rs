use anyhow::{Result, anyhow};
use clap::{App, Arg};
use std::path::PathBuf;
use simplelog::{TermLogger, LevelFilter, Config, TerminalMode, ColorChoice};

use crate::file_enumerator::*;
use crate::consumer::*;
use crate::yara_scanner::YaraScanner;
use crate::filename_scanner::FilenameScanner;
use crate::stdout_printer::StdoutPrinter;

pub struct Dionysos {
    path: PathBuf,
    loglevel: LevelFilter,
}

impl Dionysos {
    pub fn new() -> Result<Self> {
        Self::parse_options()
    }

    pub fn run(&self) -> Result<()> {
        self.init_logging()?;

        let mut enumerator = FileEnumerator::new(self.path.clone());

        let mut yara_scanner = YaraScanner::default();
        let mut filename_scanner = FilenameScanner::default();
        yara_scanner.register_consumer(StdoutPrinter::default());
        filename_scanner.register_consumer(yara_scanner);
        enumerator.register_consumer(filename_scanner);
        enumerator.run()?;

        Ok(())
    }

    fn init_logging(&self) -> Result<()> {
        match TermLogger::init(
            self.loglevel,
            Config::default(),
            TerminalMode::Stderr,
            ColorChoice::Auto) {
                Err(why) => Err(anyhow!(why)),
                _ => Ok(()),
            }
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
            .arg(
                Arg::new("VERBOSITY")
                    .help("level of verbosity (specify multiple times to increase verbosity")
                    .short('v')
                    .required(false)
                    .takes_value(false)
                    .multiple_occurrences(true)
            )
            .arg(
                Arg::new("YARA_RULES")
                    .help("use yara scanner with the specified ruleset. This can be a single file, a zip file or a directory containing lots of yara files. Yara files must end with 'yar' or 'yara', and zip files must end with 'zip'")
                    .short('Y')
                    .long("yara")
                    .required(false)
                    .multiple_occurrences(false)
                    .multiple_values(false)
                    .takes_value(true)
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

        let loglevel = match matches.occurrences_of("VERBOSITY") {
            0 => LevelFilter::Off,
            1 => LevelFilter::Error,
            2 => LevelFilter::Warn,
            3 => LevelFilter::Info,
            4 => LevelFilter::Debug,
            _ => LevelFilter::Trace
        };

        Ok(Self {
            path,
            loglevel
        })
    }
}