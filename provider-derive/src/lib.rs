use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(FileProvider)]
pub fn derive(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl FileProvider for #ident {
            fn register_consumer<T>(&mut self, consumer: T)
            where
                T: FileConsumer + 'static,
            {
                self.consumers.push(Box::new(consumer));
            }
        }
    };
    output.into()
}