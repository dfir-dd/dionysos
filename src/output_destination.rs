use std::io::Write;


pub(crate) enum OutputDestination<W: Write> {
    Csv(Box<csv::Writer<W>>),
    Txt(W),
    Json(W),
}