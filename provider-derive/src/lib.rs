use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput, parse::Parser};

#[proc_macro_derive(FileProvider)]
pub fn derive(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl FileProvider for #ident {
            fn register_consumer(&mut self, consumer: Box<dyn FileConsumer>) {
                self.consumers.push(consumer);
            }
        }
    };
    output.into()
}

#[proc_macro_attribute]
pub fn has_consumers_list(_args: TokenStream, input: TokenStream) -> TokenStream  {
    let mut ast = parse_macro_input!(input as DeriveInput);
    match &mut ast.data {
        syn::Data::Struct(ref mut struct_data) => {           
            match &mut struct_data.fields {
                syn::Fields::Named(fields) => {
                    fields
                        .named
                        .push(syn::Field::parse_named.parse2(quote! { consumers: Vec<Box<dyn FileConsumer>> }).unwrap());
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