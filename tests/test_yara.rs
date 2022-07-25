
use std::{path::PathBuf, fs::File, collections::HashSet, io::{BufReader, Read, Cursor, BufRead}};

use libdionysos::{Cli, OutputFormat, Dionysos, CsvLine};
use serde_json::Value;
use serial_test::serial;
use tempfile::tempdir;

const UNCOMPRESSED_EXPECTED_FILES: & [&str] = &[
    "sample.zip",
    "sample1.txt",
    "sample1.txt.xz"
];

const COMPRESSED_EXPECTED_FILES: & [&str] = &[
    "sample.zip:sample1.txt",
    "sample1.txt",
    "sample1.txt.bz2",
    "sample1.txt.gz",
    "sample1.txt.xz"
];

fn run_dionysos(cli: Cli) -> String {
    let results_dir = tempdir().unwrap();
    let results_filename = PathBuf::from(results_dir.path().display().to_string())
        .join("results");

    let cli = cli
        .with_output_file(results_filename.display().to_string());
    {
        let dionysos = Dionysos::new(cli).unwrap();
        dionysos.run().unwrap();
    }

    let mut input_file = BufReader::new(File::open(results_filename).unwrap());
    let mut buf = String::new();
    input_file.read_to_string(&mut buf).unwrap();
    results_dir.close().unwrap();
    buf
}

fn test_yara_common(format: OutputFormat, scan_compressed: bool, extract_filenames: fn(String) -> HashSet<String>) {
    let result = run_dionysos(prepare_cli()
        .with_format(format)
        .with_scan_compressed(scan_compressed));
    let data_path = data_path();

    let expected_files = if scan_compressed {
        &COMPRESSED_EXPECTED_FILES
    } else {
        &UNCOMPRESSED_EXPECTED_FILES
    };
    
    let detected_files = extract_filenames(result);
    for file in expected_files.iter() {
        let file = data_path.join(file);
        assert!(detected_files.contains(& file.display().to_string()));
    }
}

fn filenames_from_csv(result: String) -> HashSet<String> {
    let mut reader = csv::Reader::from_reader(Cursor::new(result));
    let mut files = HashSet::new();
    for result in reader.deserialize() { 
        let line: CsvLine = result.unwrap();
        files.insert(line.found_in_file().to_owned());
    }
    files
}

fn filenames_from_json(result: String) -> HashSet<String> {
    let reader = BufReader::new(Cursor::new(result));

    let mut files = HashSet::new();
    for line in reader.lines() {

        let v: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let filename = v.get("02_suspicious_file").unwrap().as_str().unwrap();

        files.insert(filename.to_owned());
    }
    files
}

#[test]
fn test_yara_csv() {
    test_yara_common(
        OutputFormat::Csv,
        false,
        filenames_from_csv
    );
}


#[test]
fn test_yara_csv_with_compression() {
    test_yara_common(
        OutputFormat::Csv,
        true,
        filenames_from_csv
    );
}


#[test]
fn test_yara_json() {
    test_yara_common(
        OutputFormat::Json,
        false,
        filenames_from_json
    );
}


#[test]
fn test_yara_json_with_compression() {
    test_yara_common(
        OutputFormat::Json,
        true,
        filenames_from_json
    );
}

#[test]
fn test_yara_txt() {
    let result = run_dionysos(prepare_cli().with_format(OutputFormat::Txt));
    
    let expected_files = vec![
        "sample.zip",
        "sample1.txt",
        "sample1.txt.xz"
    ];
    for file in expected_files.into_iter() {
        let file = data_path().join(file);
        assert!(result.contains(&file.display().to_string()));
    }
}

fn data_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .canonicalize()
        .unwrap()
}

fn prepare_cli() -> Cli {
    let yara_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("yara")
        .join("sample1.yar")
        .canonicalize()
        .unwrap();
    let data_path = data_path();
    
    Cli::default()
        .with_path(data_path.display().to_string())
        .with_yara(yara_file.display().to_string())
}