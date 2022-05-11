use anyhow::{Result, anyhow};
use clap::Parser;
use futures::future;
use futures::executor::block_on;
use walkdir::WalkDir;
use std::path::{PathBuf};
use simplelog::{TermLogger, LevelFilter, Config, TerminalMode, ColorChoice};
use regex;
use std::sync::Arc;
use indicatif::ProgressBar;

use crate::filescanner::*;
use crate::scanner_result::{ScannerResult};
use crate::yara_scanner::YaraScanner;
use crate::filename_scanner::FilenameScanner;
use crate::levenshtein_scanner::LevenshteinScanner;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,
    
    /// regular expression to match against the basename of files.
    /// This parameter can be specified multiple times
    #[clap(short('F'), long("filename"))]
    filenames: Vec<String>,

    /// do not run the Levenshtein scanner
    #[clap(long("omit-levenshtein"))]
    omit_levenshtein: bool,

    /// path which must be scanned
    #[clap(short('P'), long("path"))]
    path: Option<String>,

    /// use yara scanner with the specified ruleset. This can be a
    /// single file, a zip file or a directory containing lots of
    /// yara files. Yara files must end with 'yar' or 'yara', and zip
    /// files must end with 'zip'
    #[clap(short('Y'), long("yara"))]
    yara: Option<String>,

    /// allow yara to scan compressed files. Currently, xz, bz2 and gz are supported
    #[clap(short('C'), long("scan-compressed"))]
    scan_compressed: bool,

    /// maximum size (in MiB) of decompression buffer, which is used to scan compressed files
    #[clap(long("decompression-buffer"), default_value_t=128)]
    decompression_buffer_size: usize
}

pub struct Dionysos {
    path: PathBuf,
    loglevel: LevelFilter,
    yara_rules: Option<PathBuf>,
    filenames: Vec<regex::Regex>,
    cli: Cli,
}

async fn handle_file(scanners: Arc<Vec<Box<dyn FileScanner>>>, entry: walkdir::DirEntry) -> ScannerResult {
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
            let yara_scanner = YaraScanner::new(yara_rules)?
                .with_scan_compressed(self.cli.scan_compressed)
                .with_buffer_size(self.cli.decompression_buffer_size);
            scanners.push(Box::new(yara_scanner));
        };

        if !self.filenames.is_empty() {
            let filename_scanner = FilenameScanner::new(self.filenames.clone());
            scanners.push(Box::new(filename_scanner));
        }

        if !self.cli.omit_levenshtein {
            let levenshtein_scanner = LevenshteinScanner::default();
            scanners.push(Box::new(levenshtein_scanner));
        }

        let scanners = Arc::new(scanners);

        let mut results = Vec::new();
        let count = WalkDir::new(&self.path).into_iter().count();
        let progress = ProgressBar::new(count as u64);
        
        let max_workers = 8;
        let mut workers = Vec::new();

        for entry in WalkDir::new(&self.path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file()) {
            while workers.len() >= max_workers {
                let selector_future = future::select_all(workers);
                let (result, _, wrkrs) = block_on(selector_future);
                results.push(result);
                progress.inc(1);
                workers = wrkrs;
            }
            workers.push(Box::pin(handle_file(Arc::clone(&scanners), entry)));
        }

        while ! workers.is_empty() {
            let selector_future = future::select_all(workers);
            let (result, _, wrkrs) = block_on(selector_future);
            results.push(result);
            progress.inc(1);
            workers = wrkrs;
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
        let cli = Cli::parse();
        
        let path = match &cli.path {
            Some(path) => PathBuf::from(&path),

            #[cfg(target_os = "windows")]
            None => PathBuf::from("\\"),

            #[cfg(not(target_os = "windows"))]
            None => PathBuf::from("/"),
        };

        let yara_rules = match &cli.yara {
            None => None,
            Some(p) => {
                let yara_rules = PathBuf::from(&p);
                if ! yara_rules.exists() {
                    return Err(anyhow!("unable to read yara rules from '{}'", p));
                }
                Some(yara_rules)
            }
        };

        let filenames: Vec<regex::Regex> = cli.filenames.iter()
            .map(|f| {
                regex::Regex::new(f).unwrap()
            })
            .collect();

        Ok(Self {
            path,
            loglevel: cli.verbose.log_level_filter(),
            yara_rules,
            filenames,
            cli
        })
    }
}