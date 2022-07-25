use std::io::Write;

use crate::{output_destination::OutputDestination, scanner_result::ScannerResult};


pub(crate) struct OutputMethods<W: Write> {
    pub(crate) destination: OutputDestination<W>,
    pub(crate) print_strings: bool,
}

impl<W> OutputMethods<W>
where
    W: Write,
{
    pub fn with_print_strings(mut self, print_strings: bool) -> Self {
        self.print_strings = print_strings;
        self
    }

    pub fn print_strings(&self) -> bool {
        self.print_strings
    }

    pub fn destination(&self) -> &OutputDestination<W> {
        &self.destination
    }

    pub fn print_result(&mut self, result: &ScannerResult) {
        for finding in result.findings() {
            match self.destination {
                OutputDestination::Csv(ref mut wtr) => {
                    for f in finding.format_csv().into_iter() {
                        let _ = wtr.serialize(f);
                    }
                },
                OutputDestination::Txt(ref mut wtr) => {
                    let _ = write!(wtr, "{}", finding);
                },
                OutputDestination::Json(ref mut wtr) => {
                    let output = serde_json::to_string(&finding.to_json()).expect("unable to serialize to JSON");
                    let _ = writeln!(wtr, "{}", output);
                }
            }
        }
    }
}