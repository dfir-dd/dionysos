use anyhow::{anyhow, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use simplelog::{
    ColorChoice, Config, ConfigBuilder, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use walkdir::WalkDir;

use crate::cli::Cli;
use crate::filename_scanner::FilenameScanner;
use crate::filescanner::*;
use crate::hash_scanner::HashScanner;
use crate::levenshtein_scanner::LevenshteinScanner;
use crate::scanner_result::ScannerResult;
use crate::yara::YaraScanner;

use rayon::{prelude::*, current_thread_index};

scoped_tls::scoped_thread_local!(
    #[allow(clippy::declare_interior_mutable_const)]
    static PROGRESS: ProgressBarSet
);

struct ProgressBarSet {
    m_progress: MultiProgress,
    overall_progress: ProgressBar,
    spinner_bars: Vec<ProgressBar>
}

/// this needs to be a global variable,
/// because it is read by serialization code, which has no state by default
static mut DISPLAY_STRINGS: bool = false;

pub(crate) fn display_strings() -> bool {
    unsafe { DISPLAY_STRINGS }
}

pub(crate) fn skip_display_strings() -> bool {
    !display_strings()
}

fn set_display_strings(val: bool) {
    unsafe { DISPLAY_STRINGS = val }
}

pub struct Dionysos {
    path: PathBuf,
    loglevel: LevelFilter,
    yara_rules: Option<PathBuf>,
    filenames: Vec<regex::Regex>,
    cli: Cli,
}

fn handle_file(
    scanners: &Arc<Vec<Box<dyn FileScanner>>>,
    entry: &walkdir::DirEntry,
) -> ScannerResult {
    let mut result = ScannerResult::new();
    for scanner in scanners.iter() {
        log::trace!(
            "starting {} on {}",
            scanner,
            entry.file_name().to_string_lossy()
        );
        let begin = Instant::now();

        for res in scanner.scan_file(entry).into_iter() {
            match res {
                Err(why) => {
                    log::error!("{}", why);
                }

                Ok(res) => {
                    log::trace!(
                        "new finding from {} for {}",
                        scanner,
                        entry.path().display()
                    );
                    result.add_finding(res);
                }
            }
        }

        log::trace!(
            "finished {} on {} in {}s",
            scanner,
            entry.file_name().to_string_lossy(),
            Instant::now().duration_since(begin).as_secs_f64()
        );
    }
    result
}

impl Dionysos {
    pub fn new(cli: Cli) -> Result<Self> {
        Self::parse_options(cli)
    }

    pub fn run(&self) -> Result<()> {
        // ignore errors here
        let _ = self.init_logging();

        log::info!("running dionysos version {}", env!("CARGO_PKG_VERSION"));

        let scanners = self.init_scanners()?;
        
        /* this closure does all the work, and will be running inside of a thread pool */
        let pooled_operation = || match self.cli.output_file() {
            None => self.scan_to_output(scanners, std::io::stdout()),
            Some(filename) => self.scan_to_output(
                scanners,
                File::create(filename).expect("unable to write to destination file"),
            ),
        };

        /* create thread pool, with or without a progress bar, and run the workers */
        match self.create_progress()? {
            None => {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(self.cli.threads)
                    .build()?;
                pool.install(pooled_operation);
            }
            Some(progress) =>  {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(self.cli.threads)
                    .build_scoped(
                        |thread| PROGRESS.set(&progress, || thread.run()),
                        |pool| pool.install(pooled_operation),
                    )?;

                progress.m_progress.clear()?;
            }
        }

        Ok(())
    }

    fn scan_to_output<W: Write + Send>(&self, scanners: Arc<Vec<Box<dyn FileScanner>>>, output: W) {
        let output = self.cli.output_format.to_options(output);
        let filename_filter = |e: &walkdir::DirEntry| {
            match self.cli.exclude_pattern.as_ref() {
                None => true,
                Some(r) => {
                    match e.file_name().to_str() {
                        Some(filename) => !r.is_match(filename),
                        None => !r.is_match(&e.file_name().to_string_lossy())
                    }
                }
            }
        };  

        WalkDir::new(&self.path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(filename_filter)
            .par_bridge()
            .for_each(|entry| {
                log::info!("scanning '{}'", entry.path().display());

                if PROGRESS.is_set() {
                    PROGRESS.with(|pbs| {
                        let idx = current_thread_index().unwrap();
                        pbs.spinner_bars[idx].set_message(entry.path().to_string_lossy().to_string());
                    });
                }

                let result = handle_file(&scanners, &entry);

                if result.has_findings() {
                    output.print_result(&result);
                }

                if PROGRESS.is_set() {
                    PROGRESS.with(|pbs| {
                        let idx = current_thread_index().unwrap();
                        pbs.overall_progress.inc(1);
                        pbs.spinner_bars[idx].inc(1);
                    });
                }
            });
    }

    fn create_progress(
        &self,
    ) -> Result<Option<ProgressBarSet>> {
        if self.cli.display_progress {
            let m_progress = MultiProgress::new();
            let progress_style = ProgressStyle::default_bar()
                .template(
                    "[{elapsed_precise}] {bar:32.cyan/blue} {pos:>9}/{len:9}({percent}%) {msg}",
                )?
                .progress_chars("##-");
            let count = WalkDir::new(&self.path).into_iter().count();
            let progress = m_progress.add(ProgressBar::new(count as u64));
            progress.set_style(progress_style);

            let spinner_style =
                ProgressStyle::with_template("{prefix:.bold.dim} {spinner} {wide_msg}")?;
            let mut progress_bars = Vec::new();
            for _ in 0..self.cli.threads {
                let pb = m_progress.add(ProgressBar::new_spinner());
                pb.set_style(spinner_style.clone());
                progress_bars.push(pb);
            }

            let pbs = ProgressBarSet {
                m_progress,
                overall_progress: progress,
                spinner_bars: progress_bars
            };

            Ok(Some(pbs))
        } else {
            Ok(None)
        }
    }

    fn init_scanners(&self) -> Result<Arc<Vec<Box<dyn FileScanner>>>> {
        let mut scanners: Vec<Box<dyn FileScanner>> = Vec::new();

        if let Some(ref yara_rules) = self.yara_rules {
            let yara_scanner = YaraScanner::new(yara_rules)?
                .with_scan_compressed(self.cli.scan_compressed)
                .with_buffer_size(self.cli.decompression_buffer_size)
                .with_timeout(self.cli.yara_timeout);

            #[cfg(feature = "scan_evtx")]
            let yara_scanner = yara_scanner.with_scan_evtx(self.cli.yara_scan_evtx);

            #[cfg(feature = "scan_reg")]
            let yara_scanner = yara_scanner.with_scan_reg(self.cli.yara_scan_reg);

            scanners.push(Box::new(yara_scanner));
        };

        if !self.filenames.is_empty() {
            let filename_scanner = FilenameScanner::new(self.filenames.clone());
            scanners.push(Box::new(filename_scanner));
        }

        if self.cli.levenshtein {
            let levenshtein_scanner = LevenshteinScanner::default();
            scanners.push(Box::new(levenshtein_scanner));
        }

        if !self.cli.file_hash.is_empty() {
            let hash_scanner = HashScanner::default().with_hashes(&self.cli.file_hash)?;
            scanners.push(Box::new(hash_scanner));
        }

        Ok(Arc::new(scanners))
    }

    fn init_logging(&self) -> Result<()> {
        match &self.cli.log_file {
            None => match TermLogger::init(
                self.loglevel,
                Config::default(),
                TerminalMode::Stderr,
                ColorChoice::Auto,
            ) {
                Err(why) => Err(anyhow!(why)),
                _ => Ok(()),
            },
            Some(log_file_name) => {
                let log_file = match OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_file_name)
                {
                    Ok(file) => file,
                    Err(why) => {
                        eprintln!("unable to write to log file: '{}'", log_file_name);
                        return Err(anyhow!(why));
                    }
                };

                let config = ConfigBuilder::default().set_time_format_rfc3339().build();

                match WriteLogger::init(self.loglevel, config, log_file) {
                    Err(why) => Err(anyhow!(why)),
                    _ => Ok(()),
                }
            }
        }
    }

    fn parse_options(cli: Cli) -> Result<Self> {
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
                if !yara_rules.exists() {
                    return Err(anyhow!("unable to read yara rules from '{}'", p));
                }
                Some(yara_rules)
            }
        };

        let filenames: Vec<regex::Regex> = cli
            .filenames
            .iter()
            .map(|f| regex::Regex::new(f).unwrap())
            .collect();

        set_display_strings(cli.print_strings);

        Ok(Self {
            path,
            loglevel: cli.verbose.log_level_filter(),
            yara_rules,
            filenames,
            cli,
        })
    }
}
