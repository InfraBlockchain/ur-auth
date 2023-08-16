#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Codec, Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::{
    traits::{MaybeSerializeDeserialize, AtLeast32BitUnsigned, Verify, IdentifyAccount},
    RuntimeDebug, FixedPointOperand, 
    transaction_validity::InvalidTransaction,
};
use sp_core::*;

pub type DomainName = Vec<u8>;
pub type OwnerDid = Vec<u8>;
pub type Weight = u16;

pub type AccountIdFor<T> = <T as Config>::AccountId;

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum URAuthSignedPayload<T: Config> {
    Request { uri: Uri, owner_did: OwnerDid },
    Update { urauth_doc: URAuthDoc<AccountIdFor<T>, T::Balance, T::Signature>, owner_did: OwnerDid }
}

impl<T: Config> Encode for URAuthSignedPayload<T> {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.using_encoded(|payload| {
            if payload.len() > 256 {
                f(&blake2_256(payload)[..])
            } else {
                f(payload)
            }
        })
    }
}

pub enum URAuthDocField {
    AccessRule()
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct Uri(Vec<u8>);

// Multisig-enabled DID 
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct MultiDid<Account> {
	ids: Vec<(Account, Weight)>,
	// Sum(weight) >= threshold
	threshold: Weight,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum ContentMetadata {
	MetadataV1 { content_address: Vec<u8> },
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum CopyrightInfo {
	Text(Vec<u8>), 
	CopyrightInfoV1 { copyright_address: Vec<u8> }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct AccessRule<Balance> { 
	path: Vec<u8>,
	rules: Vec<Rule<Balance>>,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct UserAgent(Vec<u8>);

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct Rule<Balance> {
	user_agents: Vec<UserAgent>,
	allow: Vec<(ContentType, Balance)>,
	disallow: Vec<ContentType>
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum ContentType {
	Any,
	Image,
	Video,
	Text,
	Code,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum Proof<Signature> { 
	// To be defined 
	// Digital Sig
	ProofV1 { proof_value: Signature } 
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct URAuthDoc<Account, Balance, Signature> {
    id: Vec<u8>,
    uri: Uri,
	created_at: u64,
	updated_at: u64, 
	owner_did: MultiDid<Account>,
	identity_info: Vec<Vec<u8>>,
	content_metadata: ContentMetadata,
	copyright_info: CopyrightInfo,
	access_rules: Vec<AccessRule<Balance>>,
	proofs: Proof<Signature>,
}

pub use pallet::*;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Balance: Parameter
            + Member
            + AtLeast32BitUnsigned
            + Codec
            + Default
            + Copy
            + MaybeSerializeDeserialize
            + sp_std::fmt::Debug
            + MaxEncodedLen
            + TypeInfo
            + FixedPointOperand;
        /// A Signature can be verified with a specific `PublicKey`. The additional traits are boilerplate.
        type Signature: Verify<Signer = <Self as pallet::Config>::AccountId> + Encode + Decode + Parameter;
        /// A PublicKey can be converted into an `AccountId`. This is required by the `Signature` type.
        /// The additional traits are boilerplate.
        type AccountId: IdentifyAccount<AccountId = <Self as pallet::Config>::AccountId> + Encode + Decode + Parameter;
    }

    #[pallet::storage]
    #[pallet::unbounded]
    pub type URAuthDocs<T: Config> = StorageMap<_, Blake2_128Concat, Uri, URAuthDoc<AccountIdFor<T>, T::Balance, sr25519::Signature>>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        URAuthRegisterRequested,
        URAuthTreeRegistered
    }

    #[pallet::error]
    pub enum Error<T> {
        NoneValue,
        StorageOverflow,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(1_000)]
        pub fn urauth_request_register_domain_owner(
            origin: OriginFor<T>, 
            domain_name: DomainName, 
            owner_did: OwnerDid, 
            owner_account: AccountIdFor<T>,
            owner_sig: T::Signature,
        ) -> DispatchResult {
            let owner = ensure_signed(origin)?;
            let raw_payload = (domain_name, owner_did).encode();
            if !owner_sig.verify(&raw_payload, owner_account) {
                return Err(InvalidTransaction::BadProof.into())
            }
            Self::deposit_event(Event::<T>::URAuthRegisterRequested);

            Ok(())
        }
    }
}
