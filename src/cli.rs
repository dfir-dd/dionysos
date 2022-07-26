use std::{io::Write, fs::File};

use clap::Parser;
use clap_verbosity_flag::Verbosity;

use crate::output_format::OutputFormat;

#[derive(Parser, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[clap(flatten)]
    pub(crate) verbose: clap_verbosity_flag::Verbosity,

    /// path which must be scanned
    #[clap(short('P'), long("path"), display_order(10))]
    pub(crate) path: Option<String>,

    /// output format
    #[clap(short('f'),long("format"), arg_enum, default_value_t=OutputFormat::Txt, display_order(20))]
    pub(crate) output_format: OutputFormat,

    /// path of the file to write results to. Specify '-' write to STDOUT.
    #[clap(short('O'), long("output-file"), default_value_t = String::from("-"), display_order(30))]
    output_file: String,

    /// use yara scanner with the specified ruleset. This can be a
    /// single file, a zip file or a directory containing lots of
    /// yara files. Yara files must end with 'yar' or 'yara', and zip
    /// files must end with 'zip'
    #[clap(short('Y'), long("yara"), display_order(100))]
    pub(crate) yara: Option<String>,

    /// timeout for the yara scanner, in seconds
    #[clap(long("yara-timeout"), default_value_t = 240, display_order(110))]
    pub(crate) yara_timeout: u16,

    /// print matching strings (only used by yara currently)
    #[clap(short('s'), long("print-strings"), display_order(120))]
    pub(crate) print_strings: bool,

    /// also do YARA scan in Windows EVTX records (exported as JSON)
    #[clap(long("evtx"), display_order(130))]
    #[cfg(feature = "scan_evtx")]
    pub(crate) yara_scan_evtx: bool,

    /// also do YARA scan in Windows registry hive files
    #[clap(long("reg"), display_order(130))]
    #[cfg(feature = "scan_reg")]
    pub(crate) yara_scan_reg: bool,

    /// allow yara to scan compressed files. Currently, xz, bz2 and gz are supported
    #[clap(short('C'), long("scan-compressed"), display_order(140))]
    pub(crate) scan_compressed: bool,

    /// maximum size (in MiB) of decompression buffer (per thread), which is used to scan compressed files
    #[clap(
        long("decompression-buffer"),
        default_value_t = 128,
        display_order(150)
    )]
    pub(crate) decompression_buffer_size: usize,

    /// Hash of file to match against. Use any of MD5, SHA1 or SHA256.
    /// This parameter can be specified multiple times
    #[clap(short('H'), long("file-hash"), display_order(200))]
    pub(crate) file_hash: Vec<String>,

    /// regular expression to match against the basename of files.
    /// This parameter can be specified multiple times
    #[clap(short('F'), long("filename"), display_order(210))]
    pub(crate) filenames: Vec<String>,

    /// run the Levenshtein scanner
    #[clap(long("levenshtein"), display_order(220))]
    pub(crate) levenshtein: bool,

    /// use the specified NUMBER of threads
    #[clap(short('p'), long("threads"), default_value_t = num_cpus::get(), display_order(300))]
    pub(crate) threads: usize,

    /// display a progress bar (requires counting the number of files to be scanned before a progress bar can be displayed)
    #[clap(long("progress"), display_order(310))]
    pub(crate) display_progress: bool,

    /// path of the file to write error logs to. Error logs will always be appended
    /// Be aware that this are not the results (e.g. matching yara rules) of this program.
    #[clap(short('L'), long("log-file"), display_order(520))]
    pub(crate) log_file: Option<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            verbose: Verbosity::new(0, 0),
            path: Default::default(),
            output_format: OutputFormat::Csv,
            yara: Default::default(),
            yara_timeout: Default::default(),
            print_strings: Default::default(),
            yara_scan_evtx: Default::default(),
            yara_scan_reg: Default::default(),
            scan_compressed: Default::default(),
            decompression_buffer_size: 128,
            file_hash: Default::default(),
            filenames: Default::default(),
            levenshtein: Default::default(),
            threads: num_cpus::get(),
            display_progress: Default::default(),
            log_file: Default::default(),
            output_file: String::from("-"),
        }
    }
}

impl Cli {
    pub fn with_path(mut self, path: String) -> Self {
        self.path = Some(path);
        self
    }

    pub fn with_yara(mut self, yara: String) -> Self {
        self.yara = Some(yara);
        self
    }

    pub fn with_yara_evtx(mut self, use_evtx: bool) -> Self {
        self.yara_scan_evtx = use_evtx;
        self
    }

    pub fn with_yara_reg(mut self, use_reg: bool) -> Self {
        self.yara_scan_reg = use_reg;
        self
    }

    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.output_format = format;
        self
    }

    pub fn with_output_file(mut self, filename: String) -> Self {
        self.output_file = filename;
        self
    }

    pub fn with_scan_compressed(mut self, scan_compressed: bool) -> Self {
        self.scan_compressed = scan_compressed;
        self
    }

    pub fn with_hash(mut self, hash: &str) -> Self {
        self.file_hash.push(hash.to_owned());
        self
    }

    pub fn with_filename(mut self, filename: &str) -> Self {
        self.filenames.push(filename.to_owned());
        self
    }

    pub fn open_result_stream(&self) -> std::io::Result<Box<dyn Write>> {
        let stream =
        if self.output_file == "-" {
            Box::new(std::io::stdout()) as Box<dyn Write>
        } else {
            let stream = File::create(&self.output_file)?;
            Box::new(stream) as Box<dyn Write>
        };
        Ok(stream)
    }
}
