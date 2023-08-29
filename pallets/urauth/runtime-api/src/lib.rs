//! Runtime API definition for the urauth pallet.

#![cfg_attr(not(feature = "std"), no_std)]

use codec::Codec;
use pallet_urauth::{UpdateDocField, URAuthDoc, URI};

sp_api::decl_runtime_apis! {
    pub trait URAuthApi<Account> 
    where
        Account: Codec
    {
        fn get_updated_urauth_doc(uri: URI, update_field: UpdateDocField<Account>, updated_at: Option<u128>) -> Option<URAuthDoc<Account>>;
    }
}