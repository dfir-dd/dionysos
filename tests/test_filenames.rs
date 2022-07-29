use assert_cmd::Command;
use common::{data_path};
use predicates_core::{Predicate};

use crate::common::predicates::json::*;
use crate::common::predicates::DionysosPredicate;

mod common;
macro_rules! json_format {
    () => (
        JsonFormatOutputPredicate::new($crate::vec::Vec::new())
    );
    ($($x:expr),+ $(,)?) => (
        JsonFormatOutputPredicate::new(<[_]>::into_vec(Box::new([$($x),+])))
    );
}

#[test]
fn test_complete() {
    test_filename(r"^sample2.txt$", json_format!("sample2.txt"));
}

#[test]
fn test_prefix1() {
    test_filename("sample1", json_format!("sample1.txt", "sample1.txt.gz", "sample1.txt.xz", "sample1.txt.bz2"));
}

#[test]
fn test_suffix() {
    test_filename(r"\.txt$", json_format!("sample1.txt", "sample2.txt"));
}

fn test_filename<D, P>(pattern: &str, predicate: D) where D: DionysosPredicate<P>, P: Predicate<[u8]> {
    let data_path = data_path();
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    cmd.arg("--path").arg(data_path.display().to_string());
    cmd.arg("--filename").arg(pattern);
    cmd.arg("--format").arg(<&str>::from(predicate.expected_format()));
    cmd.assert().success().stdout(predicate);

}
