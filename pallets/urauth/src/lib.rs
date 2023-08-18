#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Codec, Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

use frame_support::{pallet_prelude::*, BoundedVec };

use frame_system::pallet_prelude::*;
use sp_consensus_vrf::schnorrkel::Randomness;
use sp_core::*;
use sp_runtime::{
    traits::{AtLeast32BitUnsigned, IdentifyAccount, MaybeSerializeDeserialize, Verify, BlakeTwo256, Hash},
    FixedPointOperand, MultiSignature, MultiSigner, 
};

pub use pallet::*;

pub mod types;
pub use types::*;

#[cfg(test)]
pub mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

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
    pub type URAuthTree<T: Config> =
        StorageMap<_, Blake2_128Concat, URI, URAuthDoc<T::AccountId, T::Balance>>;

    #[pallet::storage]
    #[pallet::unbounded]
    pub type URIMetadata<T: Config> = 
        StorageMap<_, Twox128, URI, Metadata, OptionQuery>;

    #[pallet::storage]
    #[pallet::unbounded]
    #[pallet::getter(fn uri_approval_status)]
    pub type URIVerificationInfo<T: Config> = 
        StorageMap<_, Twox128, URI, (BoundedVec<(H256, ApprovalCount), T::MaxOracleMemembers>, Threshold)>;

    #[pallet::storage]
    #[pallet::unbounded]
    pub type ChallengeValue<T: Config> = StorageMap<_, Twox128, URI, Randomness>;

    #[pallet::storage]
    #[pallet::getter(fn oracle_members)]
    pub type OracleMembers<T: Config> =
        StorageValue<_, BoundedVec<T::AccountId, T::MaxOracleMemembers>, ValueQuery>;

    #[pallet::storage]
    #[pallet::unbounded]
    pub type URAuthConfig<T: Config> = StorageValue<_, ChallengeValueConfig, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        URAuthRegisterRequested { uri: URI },
        InvalidChallengeValue,
        URAuthTreeRegistered { uri: URI, urauth_doc: URAuthDoc<T::AccountId, T::Balance> },
    }

    #[pallet::error]
    pub enum Error<T> {
        BadProof,
        BadSigner,
        ErrorConvertToString,
        BadChallengeValue,
        NotOracleMember,
        URINotVerfied, 
        AccountMissing,
        ChallengeValueNotProvided
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {

        #[pallet::call_index(0)]
        #[pallet::weight(1_000)]
        // ToDo: Check uri(regex?), owner_did, signer
        pub fn urauth_request_register_domain_owner(
            origin: OriginFor<T>,
            uri: URI,
            owner_did: OwnerDID,
            challenge_value: Option<Randomness>,
            signer: MultiSigner,
            signature: MultiSignature,
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let urauth_signed_payload = URAuthSignedPayload::<T>::Request {
                uri: uri.clone(),
                owner_did: owner_did.clone(),
            };

            // Check whether account id of owner did and signer are same
            let owner_account_id = Self::account_id_from_did(String::from_utf8_lossy(&owner_did).to_string())?;
            let raw_signer = String::from_utf8_lossy(signer.clone().into_account().as_ref()).to_string();
            ensure!(owner_account_id == raw_signer, Error::<T>::BadSigner);
            
            // Check signature 
            if !urauth_signed_payload
                .using_encoded(|payload| signature.verify(payload, &signer.into_account()))
            {
                return Err(Error::<T>::BadProof.into());
            }

            let cv = if URAuthConfig::<T>::get().is_calc_enabled() {
                Self::challenge_value()
            } else {
                challenge_value.ok_or(Error::<T>::ChallengeValueNotProvided)?
            };
        
            ChallengeValue::<T>::insert(&uri, cv);
            URIMetadata::<T>::insert(&uri, Metadata::new(uri.inner(), owner_did.clone(), cv));

            Self::deposit_event(Event::<T>::URAuthRegisterRequested { uri });

            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(1_000)]
        /// ToDo: URI Verification Period
        pub fn verify_challenge(origin: OriginFor<T>, challenge_value: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(Self::oracle_members().contains(&who), Error::<T>::NotOracleMember);

            Self::try_handle_challenge_value(challenge_value)?;
            // Verification logistics
            // 
            // 1. OwnerDID of URI == Challenge Value's DID
            // 2. Verify signature
            if !Self::do_verify_challenge_value() {
                Self::deposit_event(Event::<T>::InvalidChallengeValue )
            }

            // If valid,
            // 1. Store on `Requested::<T>::insert(uri, Vec<(Hash, ApproveCount)>)
            // 2. Other Oracle Nodes will send extrinsic and do same stuff
            // 3. Check Requested::<T>::get(uri) == Hash'(challenge_value)
            // 4. If same, Requested::<T>::insert(uri, (Hash, ApproveCount+1))
            // 5. If not same, Requested::<T>::insert(uri, (Hash', ApproveCount'))
            // 6. Over 2/3 of `OracleMembers::<T>` has done, tally 
            // 7. Call register method register_new_urauth_doc(URAuthDoc::new(uri, admin_did, proof?))
            // IF 2/3?:
            //     do_register()
            // ELSE:
            //     DELETE?
            //     OK(())
            // 

            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    // ToDo
    fn challenge_value() -> Randomness {
        Default::default()
    }

    fn do_verify_challenge_value() -> bool {
        false
    }

    /// Return
    /// 
    /// (Signature, RuntimeGereratedProof, AccountId)
    fn try_handle_challenge_value(challenge_value: Vec<u8>) -> Result<(), DispatchError> {
        let json_str = sp_std::str::from_utf8(&challenge_value)
                .map_err(|_| Error::<T>::ErrorConvertToString)?;

        match lite_json::parse_json(json_str) {
            Ok(obj) => match obj {
                // ToDo: Check domain, admin_did, challenge
                lite_json::JsonValue::Object(obj) => {
                    let domain = Self::find_json_value(&obj, String::from("domain"))?.ok_or(Error::<T>::BadChallengeValue)?;
                    let owner_did = Self::find_json_value(&obj, String::from("adminDID"))?.ok_or(Error::<T>::BadChallengeValue)?;
                    let challenge = Self::find_json_value(&obj, String::from("challenge"))?.ok_or(Error::<T>::BadChallengeValue)?;
                    let timestamp = Self::find_json_value(&obj, String::from("timestamp"))?.ok_or(Error::<T>::BadChallengeValue)?;
                    let proof = Self::find_json_value(&obj, String::from("proof"))?.ok_or(Error::<T>::BadChallengeValue)?;
                }
                _ => return Err(Error::<T>::BadChallengeValue.into()),
            },
            Err(_) => return Err(Error::<T>::BadChallengeValue.into()),
        }

        Ok(())
    }

    fn find_json_value(
        json_object: &lite_json::JsonObject,
        field_name: String,
    ) -> Result<Option<String>, DispatchError> {
        let (_, json_value) = json_object
            .iter()
            .find(|(field, _)| field.iter().copied().eq(field_name.chars()))
            .ok_or(Error::<T>::BadChallengeValue)?;
        match json_value {
            lite_json::JsonValue::String(v) => Ok(Some(v.iter().collect::<String>())),
            lite_json::JsonValue::Object(v) => {
                Self::find_json_value(v, "proofValue".into())
            }
            _ => Ok(None),
        }
    }

    fn account_id_from_did(owner_did: String) -> Result<String, DispatchError> {
        let split = owner_did.split(':').collect::<Vec<&str>>();
        let account_id = split.last().ok_or(Error::<T>::AccountMissing)?;
        Ok(account_id.to_string())  
    }
}
