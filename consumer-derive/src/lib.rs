use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput, parse::Parser};

#[proc_macro_derive(FileConsumer)]
pub fn derive(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl HasWorker for #ident {}

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

            fn start_with(&mut self, receiver: Receiver<Arc<ScannerResult>>) {
                let consumers = std::mem::take(&mut self.consumers);
                let handle = thread::spawn(|| Self::worker(receiver, consumers));
                self.thread_handle = Some(handle);
            }
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
                        .push(syn::Field::parse_named.parse2(quote! { thread_handle: Option<thread::JoinHandle<()>> }).unwrap());
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