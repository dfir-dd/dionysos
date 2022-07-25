
use std::{path::PathBuf, fs::File, collections::HashSet, io::{BufReader, Read, Cursor, BufRead}};

use libdionysos::{Cli, OutputFormat, Dionysos, CsvLine};
use serde_json::Value;
use serial_test::serial;
use tempfile::{tempdir, TempDir};

fn run_dionysos(cli: Cli) -> String {
    let mut results_dir = tempdir().unwrap();
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

#[test]
#[serial]
fn test_yara_csv() {
    let result = run_dionysos(prepare_cli().with_format(OutputFormat::Csv));

    let mut reader = csv::Reader::from_reader(Cursor::new(result));
    let mut results = HashSet::new();
    for result in reader.deserialize() { 
        let line: CsvLine = result.unwrap();
        results.insert(line.found_in_file().to_owned());
    }

    let expected_files = vec![
        "sample.zip",
        "sample1.txt",
        "sample1.txt.xz"
    ];
    for file in expected_files.into_iter() {
        let file = data_path().join(file);
        assert!(results.contains(& file.display().to_string()));
    }
}

#[test]
#[serial]
fn test_yara_txt() {
    let mut result = run_dionysos(prepare_cli().with_format(OutputFormat::Txt));
    
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

#[test]
#[serial]
fn test_yara_json() {
    let result = run_dionysos(prepare_cli().with_format(OutputFormat::Json));
    let reader = BufReader::new(Cursor::new(result));

    let mut files = HashSet::new();
    for line in reader.lines() {

        let v: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let filename = v.get("02_suspicious_file").unwrap().as_str().unwrap();

        files.insert(filename.to_owned());
    }

    let expected_files = vec![
        "sample.zip",
        "sample1.txt",
        "sample1.txt.xz"
    ];
    for file in expected_files.into_iter() {
        let file = data_path().join(file);
        assert!(files.contains(& file.display().to_string()), "missing file {} in {:?}", file.display(), files);
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