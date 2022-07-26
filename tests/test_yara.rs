
use std::path::PathBuf;

use common::{data_path, filenames_from, run_dionysos};
use libdionysos::{Cli, OutputFormat};

mod common;

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

fn test_yara_common(format: OutputFormat, scan_compressed: bool) {
    let extract_filenames = filenames_from(&format);
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

#[test]
fn test_yara_csv() {
    test_yara_common(
        OutputFormat::Csv,
        false
    );
}


#[test]
fn test_yara_csv_with_compression() {
    test_yara_common(
        OutputFormat::Csv,
        true
    );
}


#[test]
fn test_yara_json() {
    test_yara_common(
        OutputFormat::Json,
        false
    );
}


#[test]
fn test_yara_json_with_compression() {
    test_yara_common(
        OutputFormat::Json,
        true
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