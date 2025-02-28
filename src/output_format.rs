use std::io::Write;

use clap::ValueEnum;

use crate::{output_methods::OutputMethods, output_destination::OutputDestination};


#[derive(ValueEnum, Clone)]
pub enum OutputFormat {
    Csv,
    Txt,
    Json,
}

impl OutputFormat {
    pub(crate) fn to_options<W: Write>(&self, destination: W) -> OutputMethods<W> {
        let destination = match self {
            OutputFormat::Csv => OutputDestination::Csv(Box::new(csv::Writer::from_writer(destination))),
            OutputFormat::Txt => OutputDestination::Txt(destination),
            OutputFormat::Json => OutputDestination::Json(destination),
        };
        destination.into()
    }
}

impl From<OutputFormat> for &str {
    fn from(val: OutputFormat) -> Self {
        match val {
            OutputFormat::Csv => "csv",
            OutputFormat::Txt => "txt",
            OutputFormat::Json => "json",
        }
    }
}