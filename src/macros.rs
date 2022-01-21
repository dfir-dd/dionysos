
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
        fn start_with(&mut self, receiver: Receiver<Arc<PathBuf>>) {
            let handle = thread::spawn(|| Self::scan_yara(receiver));
            self.$thread_handle = Some(handle);
        }
    };

    ($type_name: ident, $thread_handle: ident, $param1: ident) => {
        fn start_with(&mut self, receiver: Receiver<Arc<PathBuf>>) {
            let $param1 = std::mem::take(&mut self.$param1);
            let handle = thread::spawn(|| Self::scan_yara(receiver, $param1));
            self.$thread_handle = Some(handle);
        }
    };
}

macro_rules! implement_consumer_for {
    ($type_name: ident, $thread_handle: ident, $($param: ident),* ) => {
        impl FileConsumer for $type_name {
            implement_start_with!($type_name, $thread_handle, $($param),*);
        
            fn join(&mut self) -> thread::Result<ConsumerResult> {
                if let Some(th) = self.$thread_handle.take() {
                    match th.join() {
                        Err(why) => {
                            log::error!("join: {:?}", why);
                            return Err(Box::new(why));
                        }
                        Ok(_) => ()
                    }
                }
                Ok(ConsumerResult::NoInfo)
            }
        }
    };
}