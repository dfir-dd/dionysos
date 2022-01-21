
macro_rules! implement_provider_for {
    ($type_name: ident, $consumers: ident) => {
        
        impl FileProvider for $type_name {
            fn register_consumer<T>(&mut self, consumer: T)
            where
                T: FileConsumer + 'static,
            {
                self.$consumers.push(Box::new(consumer));
            }
        }
    };
}

macro_rules! implement_start_with {
    ($type_name: ident, $thread_handle: ident) => {
        fn start_with(&mut self, receiver: Receiver<Arc<ScannerResult>>) {
            let handle = thread::spawn(|| Self::worker(receiver, Vec::new()));
            self.$thread_handle = Some(handle);
        }
    };

    ($type_name: ident, $thread_handle: ident, $param1: ident) => {
        fn start_with(&mut self, receiver: Receiver<Arc<ScannerResult>>) {
            let $param1 = std::mem::take(&mut self.$param1);
            let handle = thread::spawn(|| Self::worker(receiver, $param1));
            self.$thread_handle = Some(handle);
        }
    };
}

macro_rules! implement_join {
    ($type_name: ident, $thread_handle: ident) => {
        fn join(&mut self) {
            if let Some(th) = self.$thread_handle.take() {
                match th.join() {
                    Err(why) => {
                        log::error!("join: {:?}", why);
                        // do not abort, instead also join() the remaining threads
                        // return Err(Box::new(why));
                    }
                    Ok(_) => ()
                }
            }
        }
    };
}

macro_rules! implement_worker {
    ($type_name: ident, $worker_name: ident) => {
        fn worker(rx: Receiver<Arc<ScannerResult>>,
            mut consumers: Vec<Box<dyn FileConsumer>>) {
            let mut senders = generate_senders(consumers.iter_mut());
            loop {
                let result = match rx.recv() {
                    Err(_) => break,
                    Ok(filename) => filename,
                };

                Self::$worker_name(&result);

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
    };
}

macro_rules! implement_consumer_for {
    ($type_name: ident, $thread_handle: ident) => {
        impl FileConsumer for $type_name {
            implement_start_with!($type_name, $thread_handle);
            implement_join!($type_name, $thread_handle);
        }
    };

    ($type_name: ident, $thread_handle: ident, $($param: ident),+ ) => {
        impl FileConsumer for $type_name {
            implement_start_with!($type_name, $thread_handle, $($param),+);
            implement_join!($type_name, $thread_handle);
        }
    };
}