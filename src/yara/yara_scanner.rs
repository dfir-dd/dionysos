use walkdir::DirEntry;
use yara;
use anyhow::{Result, anyhow};
use crate::yara::YaraScannerError;
use crate::filescanner::*;
use crate::scanner_result;
use crate::scanner_result::*;
use crate::yara::yara_finding::YaraFinding;
use std::fmt::Display;
use std::io::Read;
use std::path::Path;
use std::time::Instant;
use walkdir::WalkDir;
use std::fs::File;
use std::io::BufReader;
use filemagic::magic;
use flate2::read::GzDecoder;
use xz::read::XzDecoder;
use bzip2::read::BzDecoder;

#[cfg(feature="evtx")]
use evtx;

#[cfg(feature="evtx")]
use serde_json::Value;

#[cfg(target_family="unix")]
use file_owner::PathExt;

use super::yara_externals::YaraExternals;

pub struct YaraScanner {
    rules: yara::Rules,
    scan_compressed: bool,
    timeout: u16,
    buffer_size: usize,
    scan_evtx: bool,
    //scan_reg: bool,
}

#[derive(Debug)]
enum FileType {
    GZip,
    BZip2,
    XZ,
    Evtx,
    Reg,
    Uncompressed
}


impl Display for YaraScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", "YaraScanner")
    }
}

impl FileScanner for YaraScanner
{
    fn scan_file(&self, file: &DirEntry) -> Vec<anyhow::Result<ScannerFinding>> {
        let mut results = Vec::new();
        let file = file.path();
        
        let magic = match magic!().unwrap().file(file) {
            Ok(magic) => {
                log::info!("treating '{}' as '{}'", file.display(), &magic);
                Some(magic)
            }
            Err(why) => { 
                log::warn!("unable to determine file type for '{}': {}",
                    file.display(), why);
                None
            }
        };

        // prepare externals, which are required by some signature-base rules
        let mut externals = YaraExternals::default()
            .with_filepath(file.display().to_string())
            .with_filename(file.file_name().unwrap().to_str().unwrap().to_string())
            .with_extension(match file.extension(){
                Some(f) => f.to_string_lossy().to_string(),
                None => "-".to_owned()
            })
            .with_filetype(magic.clone().or(Some("-".to_owned())).unwrap());
        
        externals = if cfg!(target_family = "unix") {
            externals.with_owner(match file.display().to_string().owner(){
                Ok(owner) => match owner.name() {
                    Ok(name) => name.or(Some(owner.id().to_string())).unwrap(),
                    Err(why) => {
                        log::warn!("unable to retrieve owner name: {:?}", why);
                        owner.id().to_string()
                    }
                }
                Err(why) => return vec![Err(anyhow!("unable to determine file owner: {:?}", why))]
            })
        } else {
            externals.with_owner("-".to_owned())
        };

        // check if the file is a compressed file
        let file_type = 
        if self.scan_compressed {

            if let Some(m) = &magic {
                if m == "XZ compressed data"                         {FileType::XZ}
                else if m.starts_with("gzip compressed data")        {FileType::GZip}
                else if m.starts_with("bzip2 compressed data")       {FileType::BZip2}
                else if m.starts_with("MS Windows Vista Event Log,") {FileType::Evtx}
                else if m.starts_with("MS Windows registry file, NT/2000 or above") {FileType::Reg}
                else {FileType::Uncompressed}
            } else {
                FileType::Uncompressed
            }
        } else {
            if let Some(m) = &magic {
                if m.contains("compressed data") {
                    log::warn!("'{}' contains compressed data, but it will not be decompressed before the scan. Consider using the '-C' flag", file.display());
                    FileType::Uncompressed
                }
                else if m.starts_with("MS Windows Vista Event Log,") {FileType::Evtx}
                else if m.starts_with("MS Windows registry file, NT/2000 or above") {FileType::Reg}
                else {
                    FileType::Uncompressed
                }
            } else {
                FileType::Uncompressed}
        };

        let decompression_result = match file_type {
            FileType::GZip => self.read_into_buffer(GzDecoder::new(File::open(file).unwrap())),
            FileType::BZip2 => self.read_into_buffer(BzDecoder::new(File::open(file).unwrap())),
            FileType::XZ => self.read_into_buffer(XzDecoder::new(File::open(file).unwrap())),
            _ => Ok((0, vec![]))
        };

        let buffer = match decompression_result {
            Ok((0, buffer)) => buffer, // no decompression took place
            Err(why) => return vec![Err(anyhow!("error while decompressing a file: {:?}", why))],
            Ok((bytes, buffer)) => {
                if bytes == buffer.capacity() {
                    log::warn!("file '{}' could not be decompressed completely", file.display())
                } else {
                    assert!(! buffer.is_empty());
                    log::info!("uncompressed {} bytes from '{}'", bytes, file.display());
                }
                buffer
            }
        };

        let mut scanner = match self.rules.scanner() {
            Err(why) => return vec![Err(anyhow!("unable to create yara scanner: {:?}", why))],
            Ok(scanner) => scanner
        };
        scanner.set_timeout(self.timeout.into());

        for entry in externals.to_hashmap() {
            if let Err(why) = scanner.define_variable(entry.0, entry.1) {
                return vec![Err(anyhow!("unable to define external yara variable '{}': {:?}", entry.0, why))];
            }
        }

        #[cfg(feature="evtx")]
        if self.scan_evtx && cfg!(feature="evtx") && matches!(file_type, FileType::Evtx) {
            match self.scan_evtx(&mut scanner, &file) {
                Err(why) => return vec![Err(anyhow!("{}", why))],
                Ok(results) => return results.into_iter().map(|r| Ok(ScannerFinding::Yara(r))).collect(),
            }
        }
        
        #[cfg(feature="reg")]
        if self.scan_reg && cfg!(feature="reg") && matches!(file_type, FileType::Reg) {
            match self.scan_reg(&scanner, &file) {
                Err(why) => return vec![Err(anyhow!("{}", why))],
                Ok(results) => Ok(results)
            }

        }
        let scan_result = match buffer.is_empty() {
            true => scanner.scan_file(&file),
            false => scanner.scan_mem(&buffer).or_else(|e| Err(yara::Error::Yara(e))),
        };


        match scan_result {
            Err(why) => {
                results.push(Err(anyhow!("yara scan error with '{}': {}", file.display(), why)));
            }
            Ok(res) => {
                results.extend(res.into_iter().map(|r| {
                    log::trace!("new yara finding: {} in '{}'",
                        scanner_result::escape(&r.identifier),
                        file.display());
                    Ok(ScannerFinding::Yara(YaraFinding::from(r)))}
                ));
            }
        }
        results
    }
}

impl YaraScanner {
    pub fn new<P>(path: P) -> Result<Self> where P: AsRef<Path> {
        let mut rules_str = Vec::new();
        let metadata = std::fs::metadata(&path)?;
        if metadata.is_file() {
            if Self::points_to_zip_file(&path)? {
                Self::add_rules_from_zip(&mut rules_str, &path)?;
            } else if Self::points_to_yara_file(&path)? {
                Self::add_rules_from_yara(&mut rules_str, path)?;
            } else {
                log::warn!("file '{}' is neither a yara nor a zip file; I'll ignore it", path.as_ref().display());
            }
        } else {
            Self::add_rules_from_directory(&mut rules_str, path)?;
        }

        let mut compiler = yara::Compiler::new()?;
        for entry in YaraExternals::dummy().to_hashmap() {
            compiler.define_variable(entry.0, entry.1)?;
        }
        for rule in rules_str.into_iter() {
            compiler = compiler.add_rules_str(&rule)?;
        }

        Ok(Self {
            rules: compiler.compile_rules()?,
            scan_compressed: false,
            timeout: 240,
            buffer_size: 128,

            scan_evtx: false,
            //scan_reg: false,
        })
    }

    pub fn with_scan_compressed(mut self, scan_compressed: bool) -> Self {
        self.scan_compressed = scan_compressed;
        self
    }

    pub fn with_buffer_size(mut self, buffer_size: usize) -> Self {
        self.buffer_size = buffer_size;
        self
    }

    pub fn with_timeout(mut self, timeout: u16) -> Self {
        self.timeout = timeout;
        self
    }


    #[cfg(feature="reg")]
    pub fn with_scan_reg(mut self, scan_reg: bool) -> Self {
        self.scan_reg = scan_reg;
        self
    }

    #[cfg(feature="evtx")]
    pub fn with_scan_evtx(mut self, scan_evtx: bool) -> Self {
        self.scan_evtx = scan_evtx;
        self
    }

    fn add_rules_from_yara<P>(
        rules: &mut Vec<String>,
        path: P) -> Result<()> where P: AsRef<Path> {
        Self::add_rules_from_stream(rules, &path, &mut BufReader::new(File::open(&path)?))
    }

    fn add_rules_from_stream<P, R>(
            rules: &mut Vec<String>,
            path: P, stream: &mut R) -> Result<()> where P: AsRef<Path>, R: std::io::Read {
        log::trace!("parsing yara file: '{}'", path.as_ref().display());
        let mut yara_content = String::new();
        stream.read_to_string(&mut yara_content)?;
        
        rules.push(yara_content);
        
        Ok(())
    }

    fn add_rules_from_zip<P>(
        rules: &mut Vec<String>,
        path: P) -> Result<()> where P: AsRef<Path> {

        let zip_file = BufReader::new(File::open(&path)?);
        let mut zip = zip::ZipArchive::new(zip_file)?;
        for i in 0..zip.len() {
            let mut file = zip.by_index(i)?;
            if file.is_file() {
                match file.enclosed_name() {
                    Some(file_path) => match file_path.to_str() {
                        Some(name) => {
                            if Self::is_yara_filename(name) {
                                // create PathBuf to let rust release all immutable borrows of `file`
                                let file_path = file_path.to_path_buf();
                                Self::add_rules_from_stream(rules, file_path.to_path_buf(), &mut file)?;
                            }
                        }
                        None => {
                            log::warn!("found no enclosed name for {}, ignoring that file", file.name());
                        }
                    }
                    None => {
                        log::warn!("found no enclosed name for {}, ignoring that file", file.name());
                    }
                }
            }
        }
        Ok(())
    }
    
    fn add_rules_from_directory<P>(
        rules: &mut Vec<String>,
        path: P) -> Result<()> where P: AsRef<Path> {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if Self::points_to_yara_file(&path)? {
                Self::add_rules_from_yara(rules, path)?;
            }
        }
        Ok(())
    }

    fn points_to_yara_file<P>(path: P) -> Result<bool> where P: AsRef<Path> {
        let filename = match path.as_ref().file_name()
                .and_then(|v| v.to_str()) {
                Some(v) => v,
                None => return Err(anyhow!("unable to read filename"))
            };
        return Ok(Self::is_yara_filename(filename));
    }

    fn is_yara_filename(filename: &str) -> bool {
        let lc_filename = filename.to_lowercase();
        lc_filename.ends_with(".yar") || lc_filename.ends_with(".yara")
    }

    fn points_to_zip_file<P>(path: P) -> Result<bool> where P: AsRef<Path> {
        let filename = match path.as_ref().file_name()
                .and_then(|v| v.to_str()) {
                Some(v) => v,
                None => return Err(anyhow!("unable to read filename"))
            };
        return Ok(Self::is_zip_filename(filename));
    }

    fn is_zip_filename(filename: &str) -> bool {
        let lc_filename = filename.to_lowercase();
        lc_filename.ends_with(".zip")
    }

    fn read_into_buffer<R: Read>(&self, reader: R) -> std::io::Result<(usize, Vec<u8>)> {
        log::trace!("decompressing file");
        let begin = Instant::now();
        let mut buffer = Vec::with_capacity(1024*1024*self.buffer_size);

        let mut reader_with_limit = BufReader::new(reader.take(buffer.capacity() as u64));
        
        let res = reader_with_limit.read_to_end(&mut buffer);
        match res {
            Ok(bytes) => {
                log::trace!("decompression of {} bytes done in {}s", bytes, Instant::now().duration_since(begin).as_secs_f64());
                Ok((bytes, buffer))
            }
            Err(why) => {
                log::trace!("decompression failed: {}", why);
                Err(why)
            },
        }
    }

    #[cfg(feature="evtx")]
    fn scan_evtx<'a>(&self, scanner: &'a mut yara::Scanner, file: &Path) -> Result<Vec<YaraFinding>, YaraScannerError> {
        log::error!("scanning for IOCs inside evtx file '{}'", file.display());

        let mut results = Vec::new();
        let mut parser = evtx::EvtxParser::from_path(file)?;
        for result in parser.records_json_value() {
            match result {
                Err(why) => return Err(why.into()),
                Ok(record) => {
                    let res = Self::scan_json(scanner, &record.data)?;
                    results.extend(res.into_iter().map(|yr| yr.with_value_data(record.data.to_string())));
                }
            }
        }
        Ok(results)
    }

    #[cfg(feature="evtx")]
    fn scan_json<'a>(scanner: &'a mut yara::Scanner, val: &Value) -> Result<Vec<YaraFinding>, YaraScannerError> {
        let mut results = Vec::new();
        match val {
            Value::Null => Ok(vec![]),
            Value::Bool(_) => Ok(vec![]),
            Value::Number(_) => Ok(vec![]),
            Value::String(s) => {
                results.extend(Self::scan_string(scanner, s)?);
                Ok(results)
            }
            Value::Array(a) => {
                for v in a.iter() {
                    results.extend(Self::scan_json(scanner, v)?);
                }
                Ok(results)
            }
            Value::Object(o) => {
                for (_n, v) in o.iter() {
                    results.extend(Self::scan_json(scanner, v)?);
                }
                Ok(results)
            }
        }
    }

    #[cfg(feature="evtx")]
    fn scan_string<'a>(scanner: &'a mut yara::Scanner, s: &String) -> Result<Vec<YaraFinding>, YaraScannerError> {
        match scanner.scan_mem(s.as_bytes()) {
            Err(why) => return Err(why.into()),
            Ok(r) => {
                Ok(r.into_iter().map(|rule| YaraFinding::from(rule)).collect())
            }
        }
    }
}

