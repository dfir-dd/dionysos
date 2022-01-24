use proc_macro::{self, TokenStream};
use quote::quote;

mod find_fields;
use find_fields::*;

#[proc_macro_derive(FileProvider, attributes(consumers_list))]
pub fn derive_file_provider(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).unwrap();
    let ident = &ast.ident;
    
    let fields = find_fields_by_attrname(&ast, "consumers_list");
    let consumers_list = match fields.len() {
        0 => panic!("no field with attribute consumers_list found"),
        1 => &fields[0],
        _ => panic!("multiple fields with #[consumers_list] defined")
    };

    let cl_ident = &consumers_list.ident;

    let output = quote! {
        impl FileProvider for #ident {
            fn register_consumer(&mut self, consumer: Box<dyn FileConsumer>) {
                self.#cl_ident.push(consumer);
            }
        }
    };
    output.into()
}

#[proc_macro_derive(FileConsumer, attributes(consumer_data, thread_handle))]
pub fn derive_file_consumer(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).unwrap();
    let ident = &ast.ident;

    let fields = find_fields_by_attrname(&ast, "consumers_list");
    let consumers_list = match fields.len() {
        0 => None,
        1 => fields.into_iter().next(),
        _ => panic!("multiple fields with #[consumers_list] defined")
    };

    let fields = find_fields_by_attrname(&ast, "thread_handle");
    let thread_handle = match fields.len() {
        0 => panic!("no field with attribute thread_handle found"),
        1 => &fields[0],
        _ => panic!("multiple fields with #[thread_handle] defined")
    };


    let fields = find_fields_by_attrname(&ast, "consumer_data");
    let mut consumer_data = match fields.len() {
        0 => None,
        1 =>  {
            let field = &fields[0];
            Some((field.ident.clone().unwrap(), field.ty.clone()))
        }
        _ => panic!("multiple fields with #[consumer_data] defined")
    };

    if let Some(cd) = consumer_data.take() {
        let outer_type = cd.1.clone();
        match outer_type {
            syn::Type::Path(path) => {
                'outer: for segment in path.path.segments.iter() {
                    match &segment.arguments {
                        syn::PathArguments::AngleBracketed(args) => {
                            for arg in args.args.iter() {
                                match arg {
                                    syn::GenericArgument::Type(t) => {
                                        consumer_data = Some((cd.0, t.clone()));
                                        break 'outer;
                                    }
                                    _ => ()
                                }
                            }
                        }
                        _ => ()
                    }
                }
            }
            _ => ()
        }
    }

    let has_worker = match consumer_data {
        None => {
            quote!{
                impl HasWorker<()> for #ident {}
            }
        }
        Some(ref cd) => {
            let consumerdata_type = &cd.1;
            quote! {
                impl HasWorker<#consumerdata_type> for #ident {}
            }
        }
    };

    let consumers_ref = match consumers_list {
        Some(cl) => {
            let cl_ident = &cl.ident;
            quote! {
                lstd::mem::take(&mut self.#cl_ident)
            }
        }
        None => {
            quote!{
                Vec::new()
            }
        }
    };

    let start_with = match consumer_data {
        None => {
            quote!{
                fn start_with(&mut self, receiver: std::sync::mpsc::Receiver<std::sync::Arc<ScannerResult>>) {
                    let dummy = Arc::new(());
                    let consumers = #consumers_ref;
                    let handle = std::thread::spawn(|| Self::worker(receiver, consumers, dummy));
                    self.thread_handle = Some(handle);
                }
            }
        }
        Some(ref cd) => {
            let consumerdata_name = &cd.0;
            quote! {
                fn start_with(&mut self, receiver: std::sync::mpsc::Receiver<std::sync::Arc<ScannerResult>>) {
                    let data = Arc::clone(&self.#consumerdata_name);
                    let consumers = std::mem::take(&mut self.consumers);
                    let handle = std::thread::spawn(|| Self::worker(receiver, consumers, data));
                    self.thread_handle = Some(handle);
                }
            }
        }
    };

    let th_ident = &thread_handle.ident;

    let output = quote! {
        #has_worker

        impl FileConsumer for #ident {
            fn join(&mut self) {
                if let Some(th) = self.#th_ident.take() {
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
            #start_with
        }
    };
    output.into()
}