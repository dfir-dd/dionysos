use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput, parse::Parser};
use dionysos_synhelper::*;

#[proc_macro_derive(FileProvider, attributes(consumers_list))]
pub fn derive(input: TokenStream) -> TokenStream {
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