use std::sync::mpsc::Receiver;
use std::path::PathBuf;
use std::thread;
use std::sync::Arc;

pub trait FileConsumer {
    fn start_with(&mut self, receiver: Receiver<Arc<PathBuf>>);
    fn join(&mut self);
}

pub struct StdoutPrinter {
    thread_handle: Option<thread::JoinHandle<()>>
}

impl Default for StdoutPrinter {
    fn default() -> Self {
        Self {
            thread_handle: None
        }
    }
}

impl StdoutPrinter {
    fn print_filename(receiver: Receiver<Arc<PathBuf>>) {
        loop {
            let filename = match receiver.recv() {
                Err(_) => break,
                Ok(filename) => filename
            };

            println!("{}", filename.to_str().unwrap());
        }
    }

}

impl FileConsumer for StdoutPrinter {
    fn start_with(&mut self, receiver: Receiver<Arc<PathBuf>>) {
        let handle = thread::spawn(move || Self::print_filename(receiver));
        self.thread_handle = Some(handle);
    }

    fn join(&mut self) {
        if let Some(th) = self.thread_handle.take() {
            th.join();
        }
    }
}