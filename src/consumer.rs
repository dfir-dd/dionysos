use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::sync::mpsc::{channel, Sender};

pub trait FileConsumer: Send + Sync {
    fn start_with(&mut self, receiver: Receiver<Arc<PathBuf>>);
    fn join(&mut self) -> thread::Result<ConsumerResult>;
}

pub trait FileProvider: Send + Sync {
    fn register_consumer<T>(&mut self, consumer: T)
    where
        T: FileConsumer + 'static;
}

pub struct StdoutPrinter {
    thread_handle: Option<thread::JoinHandle<thread::Result<ConsumerResult>>>,
}

pub fn generate_senders<'a, I>(consumers: I) -> Vec<Sender<Arc<PathBuf>>>
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

impl StdoutPrinter {
    pub fn new() -> Self {
        Self {
            thread_handle: None,
        }
    }

    fn print_filename(receiver: Receiver<Arc<PathBuf>>) -> thread::Result<ConsumerResult> {
        loop {
            let filename = match receiver.recv() {
                Err(_) => break,
                Ok(filename) => filename,
            };

            println!("{}", filename.to_str().unwrap());
        }
        Ok(ConsumerResult::NoInfo)
    }
}

pub enum ConsumerResult {
    NoInfo
}

impl FileConsumer for StdoutPrinter {
    fn start_with(&mut self, receiver: Receiver<Arc<PathBuf>>) {
        let handle = thread::spawn(move || Self::print_filename(receiver));
        self.thread_handle = Some(handle);
    }

    fn join(&mut self) -> thread::Result<ConsumerResult> {
        if let Some(th) = self.thread_handle.take() {
            th.join();
        }
        Ok(ConsumerResult::NoInfo)
    }
}
