use yara;
use crate::consumer::*;
use std::sync::mpsc::Receiver;
use std::path::PathBuf;
use std::thread;
use std::sync::Arc;
use log;
use crate::macros::*;

pub struct YaraScanner {
    // needed for providers
    consumers: Vec<Box<dyn FileConsumer>>,

    // needed for Consumers
    thread_handle: Option<thread::JoinHandle<thread::Result<ConsumerResult>>>
}

implement_provider_for!(YaraScanner, consumers);
implement_consumer_for!(YaraScanner, thread_handle, consumers);

impl YaraScanner {
    pub fn new() -> Self {
        Self {
            consumers: Vec::new(),
            thread_handle: None
        }
    }

    fn scan_yara(rx: Receiver<Arc<PathBuf>>,
        mut consumers: Vec<Box<dyn FileConsumer>>) -> thread::Result<ConsumerResult> {
        let mut senders = generate_senders(consumers.iter_mut());
        loop {
            let filename = match rx.recv() {
                Err(_) => break,
                Ok(filename) => filename,
            };

            for sender in senders.iter() {
                match sender.send(Arc::clone(&filename)) {
                    Err(why) => {
                        log::error!("send: {}", why);
                        return Err(Box::new(why));
                    }
                    Ok(_) => ()
                }
            }
        }

        senders.clear();

        for consumer in consumers.iter_mut() {
            match consumer.join() {
                Err(why) => {
                    // the consumer should have already handled this,
                    // so we simply forward the error
                    //log::error!("join: {:?}", why);
                    return Err(Box::new(why));
                }
                Ok(_) => ()
            }
        }

        consumers.clear();
        Ok(ConsumerResult::NoInfo)
    }
}

