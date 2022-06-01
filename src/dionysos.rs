use anyhow::{Result, anyhow};
use clap::Parser;
use walkdir::WalkDir;
use std::fs::{OpenOptions};
use std::path::{PathBuf};
use std::{thread};
use simplelog::{TermLogger, LevelFilter, Config, TerminalMode, ColorChoice, WriteLogger, ConfigBuilder};
use regex;
use std::sync::{Arc, mpsc};
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};

use crate::filescanner::*;
use crate::scanner_result::{ScannerResult};
use crate::yara_scanner::YaraScanner;
use crate::filename_scanner::FilenameScanner;
use crate::levenshtein_scanner::LevenshteinScanner;
use crate::hash_scanner::HashScanner;

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
    decompression_buffer_size: usize,

    /// path of the file to write logs to. Logs will always be appended
    #[clap(short('L'), long("log-file"))]
    log_file: Option<String>,

    /// Hash of file to match against. Use any of MD5, SHA1 or SHA256
    #[clap(short('H'), long("file-hash"))]
    file_hash: Vec<String>,

    /// timeout for the yara scanner, in seconds
    #[clap(long("yara-timeout"), default_value_t=240)]
    yara_timeout: u16
}

pub struct Dionysos {
    path: PathBuf,
    loglevel: LevelFilter,
    yara_rules: Option<PathBuf>,
    filenames: Vec<regex::Regex>,
    cli: Cli,
}

fn handle_file(scanners: &Arc<Vec<Box<dyn FileScanner>>>, entry: &walkdir::DirEntry) -> ScannerResult {
    let mut result = ScannerResult::from(entry.path());
    for scanner in scanners.iter() {
        for res in scanner.scan_file(&entry).into_iter() {
            match res {
                Err(why) => {
                    log::error!("{}", why);
                }

                Ok(res) => {
                    log::trace!("new finding from {} for {}", scanner, entry.path().display());
                    result.add_finding(res);
                }
            }
        }
    }
    result
}

fn worker(  rx: spmc::Receiver<walkdir::DirEntry>,
            tx: mpsc::Sender<ScannerResult>,
        scanners: Arc<Vec<Box<dyn FileScanner>>>, mystatus: ProgressBar) {
    let rx = &rx;
    let tx = &tx;
    loop {
        let x = rx.recv();
        match &x {
            Ok(ref entry) => {
                mystatus.set_message(entry.file_name().to_string_lossy().to_string());
                mystatus.inc(1);

                let result = handle_file(&scanners, entry);
                if let Err(why) = tx.send(result) {
                    log::error!("error while sending a scanner result from the worker: {}", why);
                    drop(rx);
                    drop(tx);
                    return;
                }
            },
            Err(_) => {
                mystatus.finish_and_clear();
                drop(rx);
                drop(tx);
            },
        }
    }
}

impl Dionysos {
    pub fn new() -> Result<Self> {
        Self::parse_options()
    }

    pub fn run(&self) -> Result<()> {
        self.init_logging()?;

        log::info!("running dionysos version {}", env!("CARGO_PKG_VERSION"));

        let mut scanners: Vec<Box<dyn FileScanner>> = Vec::new();

        if let Some(ref yara_rules) = self.yara_rules {
            let yara_scanner = YaraScanner::new(yara_rules)?
                .with_scan_compressed(self.cli.scan_compressed)
                .with_buffer_size(self.cli.decompression_buffer_size)
                .with_timeout(self.cli.yara_timeout);
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

        if !self.cli.file_hash.is_empty() {
            let hash_scanner = HashScanner::default()
                .with_hashes(&self.cli.file_hash)?;
            scanners.push(Box::new(hash_scanner));
        }

        let scanners = Arc::new(scanners);

        let count = WalkDir::new(&self.path).into_iter().count();
        
        let m_progress = MultiProgress::new();
        let progress_style = ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:32.cyan/blue} {pos:>9}/{len:9}({percent}%) {msg}")
                .progress_chars("##-");
        
        let max_workers = 8;
        let mut workers = Vec::new();

        let (mut tx_in, rx_in) = spmc::channel();
        let (tx_out, rx_out) = mpsc::channel(); 
        for _id in 0..max_workers {
            log::trace!("creating worker #{}", _id);
            let progress = ProgressBar::new(count as u64);
            progress.set_style(progress_style.clone());
            let pb = m_progress.add(progress);

            let scanner = Arc::clone(&scanners);
            let rx = rx_in.clone();
            let tx = tx_out.clone();
            let worker = thread::spawn(move ||{
                worker(rx, tx, scanner, pb)
            });
            workers.push(worker);
        }
        m_progress.set_move_cursor(true);

        for entry in WalkDir::new(&self.path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file()) {
            log::info!("scanning '{}'", entry.path().display());
            tx_in.send(entry)?;
        }

        loop {
            match rx_out.recv() {
                Err(_why) => {
                    drop(rx_out);
                    break;
                }
                Ok(result) => {
                    if result.has_findings() {
                        print!("{}", result);
                    }
                }
            }
        }

        m_progress.join_and_clear()?;
        
        Ok(())
    }

    fn init_logging(&self) -> Result<()> {
        match &self.cli.log_file {
            None => match TermLogger::init(
                self.loglevel,
                Config::default(),
                TerminalMode::Stderr,
                ColorChoice::Auto) {
                    Err(why) => Err(anyhow!(why)),
                    _ => Ok(()),
                },
            Some(log_file_name) => {
                let log_file = match OpenOptions::new().create(true).append(true).open(log_file_name) {
                    Ok(file) => file,
                    Err(why) => {
                        eprintln!("unable to write to log file: '{}'", log_file_name);
                        return Err(anyhow!(why));
                    }
                };

                let config = ConfigBuilder::default()
                    .set_time_format_rfc3339()
                    .build();

                match WriteLogger::init(
                    self.loglevel,
                    config,
                    log_file
                ) {
                    Err(why) => Err(anyhow!(why)),
                    _ => Ok(()),
                }
            }
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