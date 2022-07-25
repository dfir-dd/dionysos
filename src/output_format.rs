use std::io::Write;

use clap::ArgEnum;

use crate::{output_methods::OutputMethods, output_destination::OutputDestination};


#[derive(ArgEnum, Clone)]
pub enum OutputFormat {
    Csv,
    Txt,
    Json,
}

impl OutputFormat {
    pub(crate) fn into_options<W: Write>(self, destination: W) -> OutputMethods<W> {
        let destination = match self {
            OutputFormat::Csv => OutputDestination::Csv(csv::Writer::from_writer(destination)),
            OutputFormat::Txt => OutputDestination::Txt(destination),
            OutputFormat::Json => OutputDestination::Json(destination),
        };
        OutputMethods {
            destination
        }
    }
}