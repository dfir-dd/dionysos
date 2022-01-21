use anyhow::Result;
use crate::consumer::*;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Sender, Receiver};
use walkdir::WalkDir;
use std::sync::Arc;

pub struct FileEnumerator {
    path: PathBuf,
    consumers: Vec<Box<dyn FileConsumer>>,
    senders: Vec<Sender<Arc<PathBuf>>>
}

impl FileEnumerator {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            consumers: Vec::new(),
            senders: Vec::new(),
        }
    }

    pub fn run(&mut self) -> Result<()> {
        for entry in WalkDir::new(&self.path).into_iter().filter_map(|e| e.ok()) {
            let path = Arc::new(entry.path().to_owned());
            for sender in self.senders.iter() {
                sender.send(Arc::clone(&path))?;
            }
        }

        self.senders.clear();

        for consumer in self.consumers.iter_mut() {
            consumer.join();
        }

        self.consumers.clear();
        Ok(())
    }
}

impl FileProvider for FileEnumerator {
    fn register_consumer<T>(&mut self, mut consumer: T)
    where
        T: FileConsumer + 'static,
    {
        let (tx, rx) = channel();
        consumer.start_with(rx);
        self.consumers.push(Box::new(consumer));
        self.senders.push(tx);
    }
}
