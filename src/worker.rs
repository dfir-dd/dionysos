use std::sync::mpsc::Receiver;
use std::sync::Arc;
use crate::scanner_result::*;
use crate::consumer::*;

pub trait HasWorker<D>: FileHandler<D> {
    fn worker(rx: Receiver<Arc<ScannerResult>>,
        mut consumers: Vec<Box<dyn FileConsumer>>,
        data: Arc<D>) {

        let mut senders = generate_senders(consumers.iter_mut());
        loop {
            let result = match rx.recv() {
                Err(_) => break,
                Ok(filename) => filename,
            };

            //FIXME: this could be spread over multiple threads
            Self::handle_file(&result, Arc::clone(&data));

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
