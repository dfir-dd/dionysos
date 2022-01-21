use anyhow::Result;
use crate::consumer::*;
use crate::scanner_result::ScannerResult;
use std::path::PathBuf;
use walkdir::WalkDir;
use std::sync::Arc;

pub struct FileEnumerator {
    path: PathBuf,
    consumers: Vec<Box<dyn FileConsumer>>
}

impl FileEnumerator {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            consumers: Vec::new()
        }
    }

    pub fn run(&mut self) -> Result<()> {
        let mut senders = generate_senders(self.consumers.iter_mut());
        for entry in WalkDir::new(&self.path).into_iter().filter_map(|e| e.ok()) {
            let path: Arc<ScannerResult> = Arc::new(ScannerResult::from(entry.path()));
            for sender in senders.iter() {
                sender.send(Arc::clone(&path))?;
            }
        }

        senders.clear();

        for consumer in self.consumers.iter_mut() {
            consumer.join();
        }

        self.consumers.clear();
        Ok(())
    }
}

impl FileProvider for FileEnumerator {
    fn register_consumer<T>(&mut self, consumer: T)
    where
        T: FileConsumer + 'static,
    {
        self.consumers.push(Box::new(consumer));
    }
}
