use crate::consumer::*;
use std::path::PathBuf;

struct FileEnumerator {
    path: PathBuf,
    consumers: Vec<Box<dyn FileConsumer>>,
}

impl FileEnumerator {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            consumers: Vec::new(),
        }
    }

    pub fn register_consumer<T>(&mut self, consumer: T)
    where
        T: FileConsumer + 'static,
    {
        self.consumers.push(Box::new(consumer));
    }
}
