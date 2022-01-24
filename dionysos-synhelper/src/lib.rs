
pub fn find_fields_by_attrname(ast: &syn::DeriveInput, attrname: &str) -> Vec<syn::Field> {
    let mut result = Vec::new();
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
                                        == attrname => {
                                    result.push(field.clone());
                                }
                            _ => ()
                        }
                    }
                }
            }
            _ => ()
        }
        _ => ()
    }
    result
}