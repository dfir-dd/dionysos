pub (crate) mod predicates;

use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader, Cursor, Read},
    path::PathBuf,
};

use libdionysos::{Cli, CsvLine, Dionysos, OutputFormat};
use serde_json::Value;
use tempfile::tempdir;


pub fn data_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .canonicalize()
        .unwrap()
}

pub fn filenames_from_csv<T: std::convert::AsRef<[u8]>>(result: T) -> HashSet<String> {
    let mut reader = csv::Reader::from_reader(Cursor::new(result));
    let mut files = HashSet::new();
    for result in reader.deserialize() {
        let line: CsvLine = result.unwrap();
        files.insert(line.found_in_file().to_owned());
    }
    files
}

pub fn filenames_from_json<T: std::convert::AsRef<[u8]>>(result: T) -> HashSet<String> {
    let reader = BufReader::new(Cursor::new(result));

    let mut files = HashSet::new();
    for line in reader.lines() {
        let v: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let filename = v.get("02_suspicious_file").unwrap().as_str().unwrap();

        files.insert(filename.to_owned());
    }
    files
}

pub fn run_dionysos(cli: Cli) -> String {
    let results_dir = tempdir().unwrap();
    let results_filename = PathBuf::from(results_dir.path().display().to_string()).join("results");

    let cli = cli.with_output_file(results_filename.display().to_string());
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

pub fn filenames_from(format: &OutputFormat) -> fn(String) -> HashSet<String> {
    match format {
        OutputFormat::Csv => filenames_from_csv,
        OutputFormat::Txt => unimplemented!(),
        OutputFormat::Json => filenames_from_json,
    }
}

