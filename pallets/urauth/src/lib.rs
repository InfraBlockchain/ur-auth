#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Codec, Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

use frame_support::{pallet_prelude::*, BoundedVec};

use frame_system::pallet_prelude::*;
use sp_consensus_vrf::schnorrkel::Randomness;
use sp_core::*;
use sp_runtime::{
    traits::{AtLeast32BitUnsigned, IdentifyAccount, MaybeSerializeDeserialize, Verify},
    FixedPointOperand, MultiSignature, MultiSigner, RuntimeDebug,
};

pub use pallet::*;

#[cfg(test)]
pub mod tests;

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
pub struct DID<Account> {
    pub did: Account,
    pub weight: DIDWeight,
}
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct URI(Vec<u8>);

pub type DIDWeight = u16;
pub type OwnerDID = Vec<u8>;
pub type DocId = Vec<u8>;
pub type DomainName = Vec<u8>;

#[derive(Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum URAuthSignedPayload<T: Config> {
    Request {
        uri: URI,
        owner_did: OwnerDID,
    },
    Challenge {
        uri: URI,
        admin_did: OwnerDID,
        challenge: Vec<u8>,
        timestamp: Vec<u8>,
    },
    Update {
        urauth_doc: URAuthDoc<T::AccountId, T::Balance>,
        owner_did: OwnerDID,
    },
}

impl<T: Config> Encode for URAuthSignedPayload<T> {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        let raw_payload = match self {
            URAuthSignedPayload::Request { uri, owner_did } => (uri, owner_did).encode(),
            URAuthSignedPayload::Challenge {
                uri,
                admin_did,
                challenge,
                timestamp,
            } => (uri, admin_did, challenge, timestamp).encode(),
            URAuthSignedPayload::Update {
                urauth_doc,
                owner_did,
            } => (urauth_doc, owner_did).encode(),
        };
        if raw_payload.len() > 256 {
            f(&blake2_256(&raw_payload)[..])
        } else {
            f(&raw_payload)
        }
    }
}

// Multisig-enabled DID
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct MultiDID<Account> {
    dids: Vec<DID<Account>>,
    // Sum(weight) >= threshold
    threshold: DIDWeight,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum ContentMetadata {
    MetadataV1 { content_address: Vec<u8> },
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum CopyrightInfo {
    Text(Vec<u8>),
    CopyrightInfoV1 { copyright_address: Vec<u8> },
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
    disallow: Vec<ContentType>,
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
pub enum Proof {
    // To be defined
    // Digital Sig
    ProofV1 { proof_value: MultiSignature },
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct URAuthDoc<Account, Balance> {
    id: DocId,
    uri: URI,
    created_at: u64,
    updated_at: u64,
    owner_did: MultiDID<Account>,
    identity_info: Option<Vec<Vec<u8>>>,
    content_metadata: Option<ContentMetadata>,
    copyright_info: Option<CopyrightInfo>,
    access_rules: Option<Vec<AccessRule<Balance>>>,
    proofs: Option<Proof>,
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type MaxOracleMemembers: Get<u32>;

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

        type OracleOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

    #[pallet::storage]
    #[pallet::unbounded]
    pub type URAuthDocs<T: Config> =
        StorageMap<_, Blake2_128Concat, URI, URAuthDoc<T::AccountId, T::Balance>>;

    #[pallet::storage]
    #[pallet::unbounded]
    pub type ChallengeValue<T: Config> = StorageMap<_, Twox128, URI, Randomness>;

    #[pallet::storage]
    #[pallet::getter(fn oracle_members)]
    pub type OracleMembers<T: Config> =
        StorageValue<_, BoundedVec<T::AccountId, T::MaxOracleMemembers>, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        URAuthRegisterRequested,
        URAuthTreeRegistered,
    }

    #[pallet::error]
    pub enum Error<T> {
        BadProof,
        BadChallengeValue,
        NotOracleMember,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(1_000)]
        pub fn urauth_request_register_domain_owner(
            origin: OriginFor<T>,
            uri: URI,
            owner_did: OwnerDID,
            signer: MultiSigner,
            signature: MultiSignature,
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let urauth_signed_payload = URAuthSignedPayload::<T>::Request {
                uri: uri.clone(),
                owner_did,
            };
            if !urauth_signed_payload
                .using_encoded(|payload| signature.verify(payload, &signer.into_account()))
            {
                return Err(Error::<T>::BadProof.into());
            }
            let challenge_value = Self::challenge_value();
            ChallengeValue::<T>::insert(&uri, challenge_value);
            Self::deposit_event(Event::<T>::URAuthRegisterRequested);

            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(1_000)]
        pub fn verify_challenge(origin: OriginFor<T>, challenge_value: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let oracle_members = Self::oracle_members();
            ensure!(oracle_members.contains(&who), Error::<T>::NotOracleMember);
            // Create a str slice from the body.
            let json_str = sp_std::str::from_utf8(&challenge_value)
                .map_err(|_| Error::<T>::BadChallengeValue)?;
            match lite_json::parse_json(json_str) {
                Ok(obj) => match obj {
                    lite_json::JsonValue::Object(obj) => {}
                    _ => return Err(Error::<T>::BadChallengeValue.into()),
                },
                Err(_) => return Err(Error::<T>::BadChallengeValue.into()),
            }
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(1_000)]
        pub fn register_new_urauth_doc(
            origin: OriginFor<T>,
            uri: URI,
            urauth_doc: URAuthDoc<T::AccountId, T::Balance>,
        ) -> DispatchResult {
            T::OracleOrigin::ensure_origin(origin)?;

            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    // ToDo
    fn challenge_value() -> Randomness {
        Default::default()
    }

    fn find_json_value(
        json_object: lite_json::JsonObject,
        field_name: String,
    ) -> Result<Option<String>, DispatchError> {
        let (_, json_value) = json_object
            .iter()
            .find(|(field, _)| field.iter().copied().eq(field_name.chars()))
            .ok_or(Error::<T>::BadChallengeValue)?;
        match json_value {
            lite_json::JsonValue::String(v) => Ok(Some(v.iter().collect::<String>())),
            lite_json::JsonValue::Object(v) => {
                Self::find_json_value(v.clone(), "proofValue".into())
            }
            _ => Ok(None),
        }
    }
}
