use common::{data_path, run_dionysos};
use libdionysos::{Cli, OutputFormat};

use crate::common::filenames_from;

mod common;

#[test]
fn test_md5_csv() {
    test_hash("e6a65c3b01c87ea2f31134e3345a2c67", 
    "sample2.txt", 
    OutputFormat::Csv);
}

#[test]
fn test_sha1_csv() {
    test_hash("47b76fed75208dffbba1a44296ae2ecf5f670c59", 
    "sample2.txt",
    OutputFormat::Csv);
}

#[test]
fn test_sha256_csv() {
    test_hash("49bd6f1ad0ddd3763d1ce074b00804fd2d84433d90fbda287e62c38327cb67b7", 
    "sample2.txt",
    OutputFormat::Csv);
}

#[test]
fn test_md5_json() {
    test_hash("e6a65c3b01c87ea2f31134e3345a2c67", 
    "sample2.txt", 
    OutputFormat::Json);
}

#[test]
fn test_sha1_json() {
    test_hash("47b76fed75208dffbba1a44296ae2ecf5f670c59", 
    "sample2.txt",
    OutputFormat::Json);
}

#[test]
fn test_sha256_json() {
    test_hash("49bd6f1ad0ddd3763d1ce074b00804fd2d84433d90fbda287e62c38327cb67b7", 
    "sample2.txt",
    OutputFormat::Json);
}

fn test_hash(hash: &str, expected_file: &str, format: OutputFormat) {
    let data_path = data_path();
    let extract_filenames = filenames_from(&format);
    
    let cli = Cli::default()
        .with_path(data_path.display().to_string())
        .with_format(format)
        .with_hash(hash)
        ;
    
    let result = run_dionysos(cli);
    let files = extract_filenames(result);

    assert_eq!(files.len(), 1);
    assert!(files.contains(expected_file));
}