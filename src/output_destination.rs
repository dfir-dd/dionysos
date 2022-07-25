use std::io::Write;


pub(crate) enum OutputDestination<W: Write> {
    Csv(csv::Writer<W>),
    Txt(W),
    Json(W),
}