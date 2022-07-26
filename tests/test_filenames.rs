use std::collections::HashSet;

use common::{data_path, run_dionysos};
use libdionysos::{Cli, OutputFormat};

use crate::common::filenames_from;

mod common;

#[test]
fn test_complete() {
    test_filename(r"^sample2.txt$", 
    vec!["sample2.txt"],
    OutputFormat::Csv);
}

#[test]
fn test_prefix1() {
    test_filename("sample1", 
    vec!["sample1.txt", "sample1.txt.gz", "sample1.txt.xz", "sample1.txt.bz2"],
    OutputFormat::Csv);
}

#[test]
fn test_suffix() {
    test_filename(r"\.txt$", 
    vec!["sample1.txt", "sample2.txt"],
    OutputFormat::Json);
}


fn test_filename(pattern: &str, expected_files: Vec<&str>, format: OutputFormat) {
    let data_path = data_path();
    let extract_filenames = filenames_from(&format);
    
    let cli = Cli::default()
        .with_path(data_path.display().to_string())
        .with_format(format)
        .with_filename(pattern)
        ;
    
    let result = run_dionysos(cli);
    let files = extract_filenames(result);
    let expected_files: HashSet<String> = expected_files.into_iter().map(|s|data_path.join(s).display().to_string()).collect();

    assert_eq!(files, expected_files);
}