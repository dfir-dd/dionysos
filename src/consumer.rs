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

pub trait FileHandler {
    fn handle_file(result: &ScannerResult);
}

pub trait HasConsumers {
    fn take_consumers(&self) -> Vec<Box<dyn FileConsumer>>;
}

pub trait HasWorker: FileHandler {
    fn worker(rx: Receiver<Arc<ScannerResult>>,
        mut consumers: Vec<Box<dyn FileConsumer>>) {

        let mut senders = generate_senders(consumers.iter_mut());
        loop {
            let result = match rx.recv() {
                Err(_) => break,
                Ok(filename) => filename,
            };

            //FIXME: this could be spread over multiple threads
            Self::handle_file(&result);

            for sender in senders.iter() {
                match sender.send(Arc::clone(&result)) {
                    Err(why) => {
                        log::error!("send: {}", why);
                    }
                    Ok(_) => ()
                }
            }
        }

        senders.clear();

        for consumer in consumers.iter_mut() {
            consumer.join();
        }

        consumers.clear();
    }
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
