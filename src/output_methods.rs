use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use crate::{output_destination::OutputDestination, scanner_result::ScannerResult};

pub(crate) struct OutputMethods<W: Write> {
    pub(crate) destination: Arc<Mutex<OutputDestination<W>>>,
}

impl<W> From<OutputDestination<W>> for OutputMethods<W> where W: Write {
    fn from(destination: OutputDestination<W>) -> Self {
        Self {
            destination: Arc::new(Mutex::new(destination))
        }
    }
}

impl<W> OutputMethods<W>
where
    W: Write,
{
    pub fn print_result(&self, result: &ScannerResult) {
        let mut destination = self
            .destination
            .lock()
            .expect("unable to acquire output mutex");

        for finding in result.findings() {
            match *destination {
                OutputDestination::Csv(ref mut wtr) => {
                    for f in finding.format_csv().into_iter() {
                        let _ = wtr.serialize(f);
                    }
                }
                OutputDestination::Txt(ref mut wtr) => {
                    let _ = write!(wtr, "{}", finding);
                }
                OutputDestination::Json(ref mut wtr) => {
                    let output = serde_json::to_string(&finding.to_json())
                        .expect("unable to serialize to JSON");
                    let _ = writeln!(wtr, "{}", output);
                }
            }
        }
    }
}
