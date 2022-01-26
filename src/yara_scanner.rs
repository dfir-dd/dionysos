use yara;
use anyhow::{Result, anyhow};
use crate::consumer::*;
use crate::worker::*;
use crate::scanner_result::*;
use dionysos_derives::*;
use std::path::Path;
use walkdir::WalkDir;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

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
            tags: rule.tags.iter().map(|s|String::from(*s)).collect()
        }
    }
}

#[derive(FileProvider)]
#[derive(FileConsumer)]
pub struct YaraScanner {
    #[consumer_data]
    rules: Arc<Vec<yara::Rules>>,

    #[consumers_list]
    consumers: Vec<Box<dyn FileConsumer>>,

    #[thread_handle]
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl FileHandler<Vec<yara::Rules>> for YaraScanner {
    fn handle_file(result: &ScannerResult, data: Arc<Vec<yara::Rules>>) {
        for rules in data.iter() {
            match rules.scan_file(result.filename(), 120) {
                Err(why) => {
                    log::error!("yara scan error: {}", why);
                }
                Ok(results) => {
                    for rule in results {
                        result.add_finding(ScannerFinding::Yara(YaraFinding::from(&rule)));
                    }
                }
            }
        }
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
            rules: Arc::new(rules),
            consumers: Vec::new(),
            thread_handle: None,
        })
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
}

