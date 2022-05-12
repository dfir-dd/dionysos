use filemagic::Magic;
use yara;
use anyhow::{Result, anyhow};
use crate::filescanner::*;
use crate::scanner_result::*;
use std::cell::RefCell;
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;
use std::fs::File;
use std::io::BufReader;
use filemagic::magic;
use flate2::read::GzDecoder;
use xz::read::XzDecoder;
use bzip2::read::BzDecoder;

pub struct YaraFinding {
    pub identifier: String,
    pub namespace: String,
    //pub metadatas: Vec<Metadata<'r>>,
    pub tags: Vec<String>,
    //pub strings: Vec<String>,
}

impl From<&yara::Rule<'_>> for YaraFinding {
    fn from(rule: &yara::Rule) -> Self {
        Self {
            identifier: rule.identifier.to_owned(),
            namespace: rule.namespace.to_owned(),
            tags: rule.tags.iter().map(|s|String::from(*s)).collect(),
        }
    }
}

pub struct YaraScanner {
    rules: Vec<yara::Rules>,
    scan_compressed: bool,
    magic: Magic,
    buffer: RefCell<Vec<u8>>
}

enum CompressionType {
    GZip,
    BZip2,
    XZ,
    Uncompressed
}

impl FileScanner for YaraScanner
{
    fn scan_file(&self, file: &Path) -> Vec<anyhow::Result<ScannerFinding>> {
        let mut results = Vec::new();

        // check if the file is a compressed file
        let compression_type = 
        if self.scan_compressed {
            let magic = match self.magic.file(file) {
                Ok(magic) => {
                    Some(magic)
                }
                Err(why) => { 
                    log::warn!("unable to determin file type for '{}': {}",
                        file.display(), why);
                    None
                }
            };

            if let Some(m) = &magic {
                if m == "XZ compressed data"                    {CompressionType::XZ}
                else if m.starts_with("gzip compressed data")   {CompressionType::GZip}
                else if m.starts_with("bzip2 compressed data")  {CompressionType::BZip2}
                else {CompressionType::Uncompressed}
            } else {
                CompressionType::Uncompressed
            }
        } else {
            CompressionType::Uncompressed
        };

        self.buffer.borrow_mut().clear();

        let decompression_result = match compression_type {
            CompressionType::GZip => self.read_into_buffer(GzDecoder::new(File::open(file).unwrap())),
            CompressionType::BZip2 => self.read_into_buffer(BzDecoder::new(File::open(file).unwrap())),
            CompressionType::XZ => self.read_into_buffer(XzDecoder::new(File::open(file).unwrap())),
            _ => Ok(0)
        };

        match decompression_result {
            Ok(0) => (), // no decompression took place
            Err(why) => return vec![Err(anyhow!(why))],
            Ok(bytes) => {
                if bytes == self.buffer.borrow().capacity() {
                    log::warn!("file '{}' could not be decompressed completely, read {} of possible {} bytes",
                        file.display(),
                        bytes,
                        self.buffer.borrow().capacity())
                }
            }
        }

        for rules in self.rules.iter() {
            let scan_result = match self.buffer.borrow().is_empty() {
                true => rules.scan_file(&file, 120),
                false => rules.scan_mem(&self.buffer.borrow()[..], 120).or_else(|e| Err(yara::Error::Yara(e))),
            };

            match scan_result {
                Err(why) => {
                    results.push(Err(anyhow!("yara scan error with '{}': {}", file.display(), why)));
                }
                Ok(res) => {
                    results.extend(res.iter().map(|r| Ok(ScannerFinding::Yara(YaraFinding::from(r)))));
                }
            }
        }
        results
    }
}

impl YaraScanner {
    pub fn new<P>(path: P) -> Result<Self> where P: AsRef<Path> {
        let mut rules = Vec::new();
        let metadata = std::fs::metadata(&path)?;
        if metadata.is_file() {
            if Self::points_to_zip_file(&path)? {
                Self::add_rules_from_zip(&mut rules, &path)?;
            } else if Self::points_to_yara_file(&path)? {
                Self::add_rules_from_yara(&mut rules, path)?;
            } else {
                log::warn!("file '{}' is neither a yara nor a zip file; I'll ignore it", path.as_ref().display());
            }
        } else {
            Self::add_rules_from_directory(&mut rules, path)?;
        }

        Ok(Self {
            rules: rules,
            scan_compressed: false,
            magic: magic!().unwrap(),
            buffer: RefCell::new(Vec::with_capacity(1024*1024*128))
        })
    }

    pub fn with_scan_compressed(mut self, scan_compressed: bool) -> Self {
        self.scan_compressed = scan_compressed;
        self
    }

    #[allow(unused_mut)]
    pub fn with_buffer_size(mut self, buffer_size: usize) -> Self {
        self.buffer.replace(Vec::with_capacity(1024*1024*buffer_size));
        self
    }

    fn add_rules_from_yara<P>(rules: &mut Vec<yara::Rules>, path: P) -> Result<()> where P: AsRef<Path> {
        Self::add_rules_from_stream(rules, &path, &mut BufReader::new(File::open(&path)?))
    }

    fn add_rules_from_stream<P, R>(my_rules: &mut Vec<yara::Rules>, path: P, stream: &mut R) -> Result<()> where P: AsRef<Path>, R: std::io::Read {
        log::info!("parsing yara file: '{}'", path.as_ref().display());
        let mut yara_content = String::new();
        stream.read_to_string(&mut yara_content)?;

        // FIXME: currently, we use a new compiler for every rules,
        // because of https://github.com/Hugal31/yara-rust/issues/47
        match yara::Compiler::new()?.add_rules_str(&yara_content) {
            Ok(compiler) => {
                match compiler.compile_rules() {
                    Ok(rules) => {
                        my_rules.push(rules);
                    }
                    Err(why) => {
                        log::warn!("yara: compiler error in '{}'", path.as_ref().display());
                        log::warn!("message was: '{}'", why);
                    }
                }
            }
            Err(why) => {
                log::warn!("yara: unable to load content from '{}'", path.as_ref().display());
                log::warn!("message was: '{}'", why);
            }
        }
        
        Ok(())
    }

    fn add_rules_from_zip<P>(rules: &mut Vec<yara::Rules>, path: P) -> Result<()> where P: AsRef<Path> {
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
    
    fn add_rules_from_directory<P>(rules: &mut Vec<yara::Rules>, path: P) -> Result<()> where P: AsRef<Path> {
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

    fn read_into_buffer<R: Read>(&self, reader: R) -> std::io::Result<usize> {
        let mut reader_with_limit = BufReader::new(reader.take(self.buffer.borrow().capacity() as u64));
        reader_with_limit.read_to_end(&mut self.buffer.borrow_mut())
    }
}

