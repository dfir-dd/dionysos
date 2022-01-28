use anyhow::{Result, anyhow};
use clap::{App, Arg};
use walkdir::WalkDir;
use std::path::{PathBuf};
use simplelog::{TermLogger, LevelFilter, Config, TerminalMode, ColorChoice};
use regex;
use std::sync::Arc;
use indicatif::ProgressBar;

use crate::consumer::*;
use crate::scanner_result::{ScannerResult};
use crate::yara_scanner::YaraScanner;
use crate::filename_scanner::FilenameScanner;
use crate::levenshtein_scanner::LevenshteinScanner;

pub struct Dionysos {
    path: PathBuf,
    loglevel: LevelFilter,
    yara_rules: Option<PathBuf>,
    filenames: Vec<regex::Regex>,
    omit_levenshtein: bool
}

fn handle_file(scanners: Arc<Vec<Box<dyn FileScanner>>>, entry: walkdir::DirEntry) -> ScannerResult{
    let mut result = ScannerResult::from(entry.path());
    for scanner in scanners.iter() {
        for res in scanner.scan_file(entry.path()).into_iter() {
            match res {
                Err(why) => {
                    log::error!("{}", why);
                }

                Ok(res) => {
                    result.add_finding(res);
                }
            }
        }
    }
    result
}

impl Dionysos {
    pub fn new() -> Result<Self> {
        Self::parse_options()
    }

    pub fn run(&self) -> Result<()> {
        self.init_logging()?;
        let mut scanners: Vec<Box<dyn FileScanner>> = Vec::new();

        if let Some(ref yara_rules) = self.yara_rules {
            let yara_scanner = YaraScanner::new(yara_rules)?;
            scanners.push(Box::new(yara_scanner));
        };

        if !self.filenames.is_empty() {
            let filename_scanner = FilenameScanner::new(self.filenames.clone());
            scanners.push(Box::new(filename_scanner));
        }

        if !self.omit_levenshtein {
            let levenshtein_scanner = LevenshteinScanner::default();
            scanners.push(Box::new(levenshtein_scanner));
        }

        let scanners = Arc::new(scanners);

        let mut results = Vec::new();
        let count = WalkDir::new(&self.path).into_iter().count();
        let progress = ProgressBar::new(count as u64);
        for entry in WalkDir::new(&self.path).into_iter().filter_map(|e| e.ok()) {
            let result = handle_file(Arc::clone(&scanners), entry);
            results.push(result);
            progress.inc(1);
        }
        progress.finish_and_clear();

        for result in results.iter() {
            if result.has_findings() {
                println!("{}", result);
            }
        }
        
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
            .arg(
                Arg::new("OMIT_LEVENSHTEIN")
                    .help("do not run the Levenshtein scanner")
                    .long("omit-levenshtein")
                    .required(false)
                    .takes_value(false)
                    .multiple_occurrences(false)
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
            filenames,
            omit_levenshtein: matches.is_present("OMIT_LEVENSHTEIN")
        })
    }
}