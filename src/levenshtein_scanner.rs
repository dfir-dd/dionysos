use crate::consumer::*;
use crate::worker::*;
use crate::scanner_result::{ScannerResult, ScannerFinding};
use dionysos_derives::*;
use std::sync::Arc;

#[derive(FileProvider)]
#[derive(FileConsumer)]
#[derive(Default)]
pub struct LevenshteinScanner {
    #[consumers_list]
    consumers: Vec<Box<dyn FileConsumer>>,

    #[thread_handle]
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl FileHandler<()> for LevenshteinScanner {
    fn handle_file(result: &ScannerResult, _data: Arc<()>) {
        static WELLKNOWN_FILES: [&'static str; 8] = [
            "svchost.exe",
            "exporer.exe",
            "iexplore.exe",
            "lsass.exe",
            "chrome.exe",
            "csrss.exe",
            "firefox.exe",
            "winlogon.exe"
        ];

        match result.raw_filename().file_name() {
            Some(os_fn) => {
                match os_fn.to_str() {
                    Some(basename) => {
                        for wellknown_file in WELLKNOWN_FILES {
                            if levenshtein::levenshtein(basename, wellknown_file) == 1 {
                                result.add_finding(ScannerFinding::Levenshtein(wellknown_file.to_owned()));
                            }
                        }
                    }
                    None => ()
                }
            }
            None => return
        }
    }
}

