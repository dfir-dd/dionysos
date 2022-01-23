use anyhow::{Result, anyhow};
use clap::{App, Arg};
use std::path::PathBuf;
use simplelog::{TermLogger, LevelFilter, Config, TerminalMode, ColorChoice};
use regex;

use crate::file_enumerator::*;
use crate::consumer::*;
use crate::yara_scanner::YaraScanner;
use crate::filename_scanner::FilenameScanner;
use crate::stdout_printer::StdoutPrinter;

pub struct Dionysos {
    path: PathBuf,
    loglevel: LevelFilter,
    yara_rules: Option<PathBuf>,
    filenames: Vec<regex::Regex>,
}

impl Dionysos {
    pub fn new() -> Result<Self> {
        Self::parse_options()
    }

    pub fn run(&self) -> Result<()> {
        self.init_logging()?;

        //let mut scanner_chain = FileEnumerator::new(self.path.clone());
        let mut scanner_chain: Box<dyn FileConsumer> = Box::new(StdoutPrinter::default());

        if let Some(ref yara_rules) = self.yara_rules {
            let mut yara_scanner = YaraScanner::default();
            yara_scanner.add_rules(yara_rules)?;
            yara_scanner.seal();
            yara_scanner.register_consumer(scanner_chain);
            scanner_chain = Box::new(yara_scanner);
        };

        if !self.filenames.is_empty() {
            let mut filename_scanner = FilenameScanner::default();
            filename_scanner.add_patterns(self.filenames.clone());
            filename_scanner.seal();
            filename_scanner.register_consumer(scanner_chain);
            scanner_chain = Box::new(filename_scanner);
        }

        let mut enumerator = FileEnumerator::new(self.path.clone());
        enumerator.register_consumer(scanner_chain);
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
                    .help("path which must be scanned")
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
            .arg(
                Arg::new("FILENAME_REGEX")
                    .help("regular expression to match against the basename of files. This parameter can be specified multiple times")
                    .short('F')
                    .long("filename")
                    .required(false)
                    .multiple_values(false)
                    .multiple_occurrences(true)
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

        let yara_rules = match matches.value_of("YARA_RULES") {
            None => None,
            Some(p) => {
                let yara_rules = PathBuf::from(&p);
                if ! yara_rules.exists() {
                    return Err(anyhow!("unable to read yara rules from '{}'", p));
                }
                Some(yara_rules)
            }
        };

        let filenames: Vec<regex::Regex> = match matches.values_of("FILENAME_REGEX") {
            Some(f) => {
                let mut filenames = Vec::new();
                for s in f {
                    let re = regex::Regex::new(s)?;
                    filenames.push(re);
                }
                filenames
            }
            None => Vec::new(),
        };

        Ok(Self {
            path,
            loglevel,
            yara_rules,
            filenames
        })
    }
}