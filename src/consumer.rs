use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::sync::mpsc::{channel, Sender};
use crate::scanner_result::*;

pub trait FileConsumer: Send + Sync {
    fn start_with(&mut self, receiver: Receiver<Arc<ScannerResult>>);
    fn join(&mut self);
}

pub trait FileProvider: Send + Sync {
    fn register_consumer<T>(&mut self, consumer: T)
    where
        T: FileConsumer + 'static;
}

pub fn generate_senders<'a, I>(consumers: I) -> Vec<Sender<Arc<ScannerResult>>>
where
    I: Iterator<Item = &'a mut Box<dyn FileConsumer>>,
{
    let mut senders = Vec::new();
    for consumer in consumers {
        let (tx, rx) = channel();
        consumer.start_with(rx);
        senders.push(tx);
    }
    senders
}
