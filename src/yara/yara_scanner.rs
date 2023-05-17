use crate::filescanner::*;
use crate::scanner_result;
use crate::scanner_result::*;
use crate::yara::yara_finding::YaraFinding;
use anyhow::{anyhow, Result};
use bzip2::read::BzDecoder;
use filemagic::magic;
use flate2::read::GzDecoder;
use nt_hive2::CleanHive;
use nt_hive2::Hive;
use nt_hive2::HiveParseMode;
use nt_hive2::KeyNode;
use std::fmt::Display;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;
use std::time::Instant;
use walkdir::DirEntry;
use walkdir::WalkDir;
use xz::read::XzDecoder;

#[cfg(feature = "scan_evtx")]
use serde_json::Value;

#[cfg(target_family = "unix")]
use file_owner::PathExt;

use super::yara_externals::YaraExternals;

pub struct YaraScanner {
    rules: yara::Rules,
    scan_compressed: bool,
    timeout: u16,
    buffer_size: usize,
    scan_evtx: bool,
    scan_reg: bool,
}

#[derive(Debug)]
enum FileType {
    GZip,
    BZip2,
    XZ,
    Zip,
    Evtx,
    Reg,
    Uncompressed,
}

impl Display for YaraScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "YaraScanner")
    }
}

impl FileScanner for YaraScanner {
    fn scan_file(&self, file: &DirEntry) -> Vec<anyhow::Result<Box<dyn ScannerFinding>>> {
        let mut results = Vec::new();
        let file = file.path();

        let magic = match magic!().unwrap().file(file) {
            Ok(magic) => {
                log::info!("treating '{}' as '{}'", file.display(), &magic);
                Some(magic)
            }
            Err(why) => {
                log::warn!(
                    "unable to determine file type for '{}': {}",
                    file.display(),
                    why
                );
                None
            }
        };

        // prepare externals, which are required by some signature-base rules
        let mut externals = YaraExternals::default()
            .with_filepath(file.display().to_string())
            .with_filename(file.file_name().unwrap().to_str().unwrap().to_string())
            .with_extension(match file.extension() {
                Some(f) => f.to_string_lossy().to_string(),
                None => "-".to_owned(),
            })
            .with_filetype(magic.clone().unwrap_or_else(|| "-".to_owned()));

        #[cfg(target_family = "unix")]
        {
            externals = externals.with_owner(match file.display().to_string().owner() {
                Ok(owner) => match owner.name() {
                    Ok(name) => name.unwrap_or_else(|| owner.id().to_string()),
                    Err(why) => {
                        log::warn!("unable to retrieve owner name: {:?}", why);
                        owner.id().to_string()
                    }
                },
                Err(why) => return vec![Err(anyhow!("unable to determine file owner: {:?}", why))],
            });
        }

        #[cfg(not(target_family = "unix"))]
        {
            externals.with_owner("-".to_owned());
        }

        let mut scanner = match self.rules.scanner() {
            Err(why) => return vec![Err(anyhow!("unable to create yara scanner: {:?}", why))],
            Ok(scanner) => scanner,
        };
        scanner.set_timeout(self.timeout.into());

        for entry in externals.to_hashmap() {
            if let Err(why) = scanner.define_variable(entry.0, entry.1) {
                return vec![Err(anyhow!(
                    "unable to define external yara variable '{}': {:?}",
                    entry.0,
                    why
                ))];
            }
        }

        // check if the file is a compressed file and must be decompressed before scanning
        let file_type = self.get_filetype(magic, file);

        let scan_result = match file_type {
            FileType::GZip => self.scan_compressed(
                &mut scanner,
                GzDecoder::new(File::open(file).unwrap()),
                &file.display().to_string(),
            ),

            FileType::BZip2 => self.scan_compressed(
                &mut scanner,
                BzDecoder::new(File::open(file).unwrap()),
                &file.display().to_string(),
            ),

            FileType::XZ => self.scan_compressed(
                &mut scanner,
                XzDecoder::new(File::open(file).unwrap()),
                &file.display().to_string(),
            ),

            FileType::Zip => {
                self.scan_zip_archive(scanner, File::open(file).unwrap(), &file.to_string_lossy())
            }

            FileType::Evtx => {
                #[cfg(feature = "scan_evtx")]
                if self.scan_evtx {
                    self.scan_evtx(&mut scanner, file)
                } else {
                    self.scan_file(&mut scanner, file)
                }

                #[cfg(not(feature = "scan_evtx"))]
                scanner.scan_file(&file).or_else(|e| Err(anyhow!(e)))
            }

            FileType::Reg => {
                #[cfg(feature = "scan_reg")]
                if self.scan_reg && matches!(file_type, FileType::Reg) {
                    let hive_file = File::open(file).unwrap();
                    let hive = match Hive::new(hive_file, HiveParseMode::NormalWithBaseBlock) {
                        Ok(hive) => hive.treat_hive_as_clean(),
                        Err(why) => return vec![Err(anyhow!("{}", why))],
                    };

                    if hive.is_primary_file() {
                        log::trace!(
                            "scanning for IOCs inside registry hive file '{}'",
                            file.display()
                        );

                        self.scan_reg(&mut scanner, hive, &file.to_string_lossy())
                    } else {
                        log::trace!(
                            "'{}' is no primary hive file, using the normal yara scanner",
                            file.display()
                        );
                        self.scan_file(&mut scanner, file)
                    }
                } else {
                    self.scan_file(&mut scanner, file)
                }

                #[cfg(not(feature = "scan_reg"))]
                scanner.scan_file(&file).or_else(|e| Err(anyhow!(e)))
            }
            FileType::Uncompressed => self.scan_file(&mut scanner, file),
        };

        match scan_result {
            Err(why) => {
                results.push(Err(anyhow!(
                    "yara scan error with '{}': {}",
                    file.display(),
                    why
                )));
            }
            Ok(res) => {
                results.extend(res.into_iter().map(|r| {
                    log::trace!(
                        "new yara finding: {} in '{}'",
                        scanner_result::escape(&r.identifier),
                        file.display()
                    );
                    Ok(Box::new(r) as Box<dyn ScannerFinding>)
                }));
            }
        }

        results
    }
}

impl YaraScanner {
    pub fn new<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let mut rules_str = Vec::new();
        let metadata = std::fs::metadata(&path)?;
        if metadata.is_file() {
            if Self::points_to_zip_file(&path)? {
                Self::add_rules_from_zip(&mut rules_str, &path)?;
            } else if Self::points_to_yara_file(&path)? {
                Self::add_rules_from_yara(&mut rules_str, path)?;
            } else {
                log::warn!(
                    "file '{}' is neither a yara nor a zip file; I'll ignore it",
                    path.as_ref().display()
                );
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
            scan_reg: false,
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

    #[cfg(feature = "scan_reg")]
    pub fn with_scan_reg(mut self, scan_reg: bool) -> Self {
        self.scan_reg = scan_reg;
        self
    }

    #[cfg(feature = "scan_evtx")]
    pub fn with_scan_evtx(mut self, scan_evtx: bool) -> Self {
        self.scan_evtx = scan_evtx;
        self
    }

    fn add_rules_from_yara<P>(rules: &mut Vec<String>, path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        Self::add_rules_from_stream(rules, &path, &mut BufReader::new(File::open(&path)?))
    }

    fn add_rules_from_stream<P, R>(rules: &mut Vec<String>, path: P, stream: &mut R) -> Result<()>
    where
        P: AsRef<Path>,
        R: std::io::Read,
    {
        log::trace!("parsing yara file: '{}'", path.as_ref().display());
        let mut yara_content = String::new();
        stream.read_to_string(&mut yara_content)?;

        rules.push(yara_content);

        Ok(())
    }

    fn add_rules_from_zip<P>(rules: &mut Vec<String>, path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
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
                                Self::add_rules_from_stream(rules, &file_path, &mut file)?;
                            }
                        }
                        None => {
                            log::warn!(
                                "found no enclosed name for {}, ignoring that file",
                                file.name()
                            );
                        }
                    },
                    None => {
                        log::warn!(
                            "found no enclosed name for {}, ignoring that file",
                            file.name()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn add_rules_from_directory<P>(rules: &mut Vec<String>, path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if Self::points_to_yara_file(path)? {
                Self::add_rules_from_yara(rules, path)?;
            }
        }
        Ok(())
    }

    fn points_to_yara_file<P>(path: P) -> Result<bool>
    where
        P: AsRef<Path>,
    {
        let filename = match path.as_ref().file_name().and_then(|v| v.to_str()) {
            Some(v) => v,
            None => return Err(anyhow!("unable to read filename")),
        };
        Ok(Self::is_yara_filename(filename))
    }

    fn is_yara_filename(filename: &str) -> bool {
        let lc_filename = filename.to_lowercase();
        lc_filename.ends_with(".yar") || lc_filename.ends_with(".yara")
    }

    fn points_to_zip_file<P>(path: P) -> Result<bool>
    where
        P: AsRef<Path>,
    {
        let filename = match path.as_ref().file_name().and_then(|v| v.to_str()) {
            Some(v) => v,
            None => return Err(anyhow!("unable to read filename")),
        };
        Ok(Self::is_zip_filename(filename))
    }

    fn is_zip_filename(filename: &str) -> bool {
        let lc_filename = filename.to_lowercase();
        lc_filename.ends_with(".zip")
    }

    fn read_into_buffer<R: Read>(&self, reader: R) -> std::io::Result<(usize, Vec<u8>)> {
        log::trace!("decompressing file");
        let begin = Instant::now();
        let mut buffer = Vec::with_capacity(1024 * 1024 * self.buffer_size);

        let mut reader_with_limit = BufReader::new(reader.take(buffer.capacity() as u64));

        let res = reader_with_limit.read_to_end(&mut buffer);
        match res {
            Ok(bytes) => {
                log::trace!(
                    "decompression of {} bytes done in {}s",
                    bytes,
                    Instant::now().duration_since(begin).as_secs_f64()
                );
                Ok((bytes, buffer))
            }
            Err(why) => {
                log::trace!("decompression failed: {}", why);
                Err(why)
            }
        }
    }

    #[cfg(feature = "scan_evtx")]
    fn scan_evtx<'a>(
        &self,
        scanner: &'a mut yara::Scanner,
        file: &Path,
    ) -> anyhow::Result<Vec<YaraFinding>> {
        log::trace!("scanning for IOCs inside evtx file '{}'", file.display());
        let filename = file.display().to_string();

        let mut results = Vec::new();
        let mut parser = evtx::EvtxParser::from_path(file)?;
        for result in parser.records_json_value() {
            match result {
                Err(why) => return Err(why.into()),
                Ok(record) => {
                    let res = Self::scan_json(scanner, &record.data, &filename)?;
                    results.extend(
                        res.into_iter()
                            .map(|yr| yr.with_value_data(record.data.to_string())),
                    );
                }
            }
        }
        Ok(results)
    }

    #[cfg(feature = "scan_evtx")]
    fn scan_json<'a>(
        scanner: &'a mut yara::Scanner,
        val: &Value,
        filename: &str,
    ) -> anyhow::Result<Vec<YaraFinding>> {
        let mut results = Vec::new();
        match val {
            Value::Null => Ok(vec![]),
            Value::Bool(_) => Ok(vec![]),
            Value::Number(_) => Ok(vec![]),
            Value::String(s) => {
                results.extend(Self::scan_string(scanner, s, filename)?);
                Ok(results)
            }
            Value::Array(a) => {
                for v in a.iter() {
                    results.extend(Self::scan_json(scanner, v, filename)?);
                }
                Ok(results)
            }
            Value::Object(o) => {
                for (_n, v) in o.iter() {
                    results.extend(Self::scan_json(scanner, v, filename)?);
                }
                Ok(results)
            }
        }
    }

    #[cfg(feature = "scan_evtx")]
    fn scan_string<'a>(
        scanner: &'a mut yara::Scanner,
        s: &String,
        filename: &str,
    ) -> Result<Vec<YaraFinding>, yara::YaraError> {
        match scanner.scan_mem(s.as_bytes()) {
            Err(why) => Err(why),
            Ok(r) => Ok(r
                .into_iter()
                .map(|r| YaraFinding::new(r, filename.to_string()))
                .collect()),
        }
    }

    #[cfg(feature = "scan_reg")]
    fn scan_reg<'a>(
        &self,
        scanner: &'a mut yara::Scanner,
        mut hive: Hive<File, CleanHive>,
        filename: &str,
    ) -> anyhow::Result<Vec<YaraFinding>> {
        let root_key = hive.root_key_node()?;

        match Self::scan_key(scanner, &mut hive, &root_key, String::new(), filename) {
            Err(why) => Err(why),
            Ok(results) => Ok(results),
        }
    }

    fn scan_key<'a>(
        scanner: &'a mut yara::Scanner,
        hive: &mut Hive<File, CleanHive>,
        key: &KeyNode,
        path: String,
        filename: &str,
    ) -> anyhow::Result<Vec<YaraFinding>> {
        let mut results = Vec::new();
        for v in key.values() {
            match v.value() {
                nt_hive2::RegistryValue::RegSZ(s)
                | nt_hive2::RegistryValue::RegExpandSZ(s)
                | nt_hive2::RegistryValue::RegResourceList(s)
                | nt_hive2::RegistryValue::RegFullResourceDescriptor(s)
                | nt_hive2::RegistryValue::RegResourceRequirementsList(s) => {
                    results.extend(
                        Self::scan_string(scanner, s, filename)?
                            .into_iter()
                            .map(|r| r.with_value_data(Self::key_display(&path, v.name(), s))),
                    );
                }
                nt_hive2::RegistryValue::RegBinary(b) => {
                    results.extend(scanner.scan_mem(&b[..])?.into_iter().map(|r| {
                        YaraFinding::new(r, filename.to_string())
                            .with_value_data(Self::key_display(&path, v.name(), "<binary data>"))
                    }))
                }
                nt_hive2::RegistryValue::RegMultiSZ(sl) => {
                    for s in sl {
                        results.extend(
                            Self::scan_string(scanner, s, filename)?
                                .into_iter()
                                .map(|r| r.with_value_data(Self::key_display(&path, v.name(), s))),
                        );
                    }
                }
                _ => (),
            }
        }

        for subkey in key.subkeys(hive)?.iter() {
            let subkey_path = format!("{}/{}", path, subkey.borrow().name());
            results.extend(Self::scan_key(
                scanner,
                hive,
                &subkey.borrow(),
                subkey_path,
                filename,
            )?);
        }

        Ok(results)
    }

    fn key_display(path: &str, attr_name: &str, attr_value: &str) -> String {
        format!("{}/@{} = '{}'", path, attr_name, attr_value)
    }

    fn get_filetype(&self, magic: Option<String>, file: &Path) -> FileType {
        let file_type = if self.scan_compressed {
            if let Some(m) = &magic {
                if m == "XZ compressed data" {
                    FileType::XZ
                } else if m.starts_with("gzip compressed data") {
                    FileType::GZip
                } else if m.starts_with("bzip2 compressed data") {
                    FileType::BZip2
                } else if m.starts_with("MS Windows Vista Event Log,") {
                    FileType::Evtx
                } else if m.starts_with("MS Windows registry file, NT/2000 or above") {
                    FileType::Reg
                } else if m.starts_with("Zip archive data") {
                    FileType::Zip
                } else {
                    if m.contains("compressed data") {
                        log::warn!("unknown compression format: '{}', file will be handled without decompression", m);
                    }
                    FileType::Uncompressed
                }
            } else {
                FileType::Uncompressed
            }
        } else if let Some(m) = &magic {
            if m.contains("compressed data") || m.contains("archive data") {
                log::warn!("'{}' contains compressed data, but it will not be decompressed before the scan. Consider using the '-C' flag", file.display());
                FileType::Uncompressed
            } else if m.starts_with("MS Windows Vista Event Log,") {
                FileType::Evtx
            } else if m.starts_with("MS Windows registry file, NT/2000 or above") {
                FileType::Reg
            } else {
                FileType::Uncompressed
            }
        } else {
            FileType::Uncompressed
        };
        file_type
    }

    fn scan_file(
        &self,
        scanner: &mut yara::Scanner<'_>,
        file: &Path,
    ) -> anyhow::Result<Vec<YaraFinding>> {
        let filename = file.display().to_string();

        match scanner.scan_file(file) {
            Err(why) => Err(why.into()),
            Ok(results) => Ok(results
                .into_iter()
                .map(|r| YaraFinding::new(r, filename.clone()))
                .collect()),
        }
    }

    fn scan_compressed<R: Read>(
        &self,
        scanner: &mut yara::Scanner,
        reader: R,
        file_display_name: &str,
    ) -> anyhow::Result<Vec<YaraFinding>> {
        let (bytes, buffer) = self.read_into_buffer(reader)?;

        if bytes == buffer.capacity() {
            log::warn!("file '{file_display_name}' could not be decompressed completely")
        } else if buffer.is_empty() {
            log::warn!("uncompressed no bytes from '{}'", file_display_name);
        } else {
            log::info!("uncompressed {bytes} bytes from '{file_display_name}'");
        }

        match scanner.scan_mem(&buffer) {
            Err(why) => Err(why.into()),
            Ok(results) => Ok(results
                .into_iter()
                .map(|r| YaraFinding::new(r, file_display_name.to_owned()))
                .collect()),
        }
    }

    fn scan_zip_archive(
        &self,
        mut scanner: yara::Scanner,
        reader: File,
        zip_name: &str,
    ) -> anyhow::Result<Vec<YaraFinding>> {
        let mut results = Vec::new();

        if let Ok(mut zip) = zip::ZipArchive::new(reader) {
            for i in 0..zip.len() {
                let file = zip.by_index(i)?;
                if file.is_file() {
                    let filename = file.name().to_owned();
                    let display_name = format!("{zip_name}:{filename}");
                    scanner.define_variable("filename", &filename[..])?;

                    match self.scan_compressed(&mut scanner, file, &display_name) {
                        Ok(res) => {
                            results
                                .extend(res.into_iter().map(|r| r.with_contained_file(&filename)));
                        }
                        Err(why) => return Err(why),
                    }
                }
            }
        }
        Ok(results)
    }
}
