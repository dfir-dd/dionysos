use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput, parse::Parser};

#[proc_macro_derive(FileConsumer, attributes(consumer_data))]
pub fn derive(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).unwrap();
    let ident = &ast.ident;

    let mut consumer_data: Option<(proc_macro2::Ident, syn::Type)> = None;
    match ast.data {
        syn::Data::Struct(ref data_struct) => match data_struct.fields {
            syn::Fields::Named(ref fields_named) => {
                for field in fields_named.named.iter() {
                    for attr in field.attrs.iter() {
                        match attr.parse_meta().unwrap() {
                            syn::Meta::Path(ref path)
                                    if path
                                        .get_ident()
                                        .unwrap()
                                        .to_string()
                                        == "consumer_data" => {
                                    let item = field.clone();
                                    consumer_data = Some((item.ident.unwrap(), item.ty));
                                    break;
                                }
                            _ => ()
                        }
                    }
                    if consumer_data.is_some() { break; }
                }
            }
            _ => ()
        }
        _ => ()
    }

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

    let start_with = match consumer_data {
        None => {
            quote!{
                fn start_with(&mut self, receiver: std::sync::mpsc::Receiver<std::sync::Arc<ScannerResult>>) {
                    let dummy = Arc::new(());
                    let consumers = std::mem::take(&mut self.consumers);
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

    let output = quote! {
        #has_worker

        impl FileConsumer for #ident {
            fn join(&mut self) {
                if let Some(th) = self.thread_handle.take() {
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

#[proc_macro_attribute]
pub fn has_thread_handle(_args: TokenStream, input: TokenStream) -> TokenStream  {
    let mut ast = parse_macro_input!(input as DeriveInput);
    match &mut ast.data {
        syn::Data::Struct(ref mut struct_data) => {           
            match &mut struct_data.fields {
                syn::Fields::Named(fields) => {
                    fields
                        .named
                        .push(syn::Field::parse_named.parse2(quote! { thread_handle: Option<std::thread::JoinHandle<()>> }).unwrap());
                }   
                _ => {
                    ()
                }
            }              
            
            return quote! {
                #ast
            }.into();
        }
        _ => panic!("`add_field` has to be used with structs "),
    }
}