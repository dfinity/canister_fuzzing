use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

#[proc_macro_derive(FuzzerState)]
pub fn derive_fuzzer_state(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let fields = match input.data {
        Data::Struct(ref data) => &data.fields,
        _ => {
            return syn::Error::new_spanned(name, "FuzzerState can only be derived for structs")
                .to_compile_error()
                .into();
        }
    };

    let field_access = match fields {
        Fields::Unnamed(ref fields) => {
            if fields.unnamed.len() == 1 {
                quote! { 0 }
            } else {
                return syn::Error::new_spanned(name, "FuzzerState derive currently only supports newtype structs (tuple structs with one field)").to_compile_error().into();
            }
        }
        Fields::Named(ref fields) => {
            let state_field = fields
                .named
                .iter()
                .find(|f| f.ident.as_ref().map(|id| id == "state").unwrap_or(false));

            if let Some(f) = state_field {
                let id = &f.ident;
                quote! { #id }
            } else {
                return syn::Error::new_spanned(
                    name,
                    "FuzzerState derive on named structs requires a field named 'state'",
                )
                .to_compile_error()
                .into();
            }
        }
        Fields::Unit => {
            return syn::Error::new_spanned(name, "FuzzerState cannot be derived for unit structs")
                .to_compile_error()
                .into();
        }
    };

    let expanded = quote! {
        impl AsRef<canfuzz::fuzzer::FuzzerState> for #name {
            fn as_ref(&self) -> &canfuzz::fuzzer::FuzzerState {
                &self.#field_access
            }
        }

        impl AsMut<canfuzz::fuzzer::FuzzerState> for #name {
            fn as_mut(&mut self) -> &mut canfuzz::fuzzer::FuzzerState {
                &mut self.#field_access
            }
        }
    };

    TokenStream::from(expanded)
}
