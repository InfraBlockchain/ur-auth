#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Codec, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use safe_regex::{regex, Matcher0};

use frame_support::{pallet_prelude::*, BoundedVec};

use frame_system::pallet_prelude::*;
use sp_consensus_vrf::schnorrkel::Randomness;
use sp_core::*;
use sp_runtime::{
    traits::{
        AtLeast32BitUnsigned, BlakeTwo256, Hash, IdentifyAccount, MaybeSerializeDeserialize, Verify,
    },
    FixedPointOperand, MultiSignature, MultiSigner, AccountId32,
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
    }

    #[pallet::storage]
    #[pallet::unbounded]
    pub type URAuthTree<T: Config> =
        StorageMap<_, Twox128, URI, URAuthDoc<T::AccountId, T::Balance>>;

    #[pallet::storage]
    #[pallet::unbounded]
    pub type URIMetadata<T: Config> = StorageMap<_, Twox128, URI, Metadata, OptionQuery>;

    #[pallet::storage]
    #[pallet::unbounded]
    #[pallet::getter(fn uri_verification_info)]
    pub type URIVerificationInfo<T: Config> =
        StorageMap<_, Twox128, URI, VerificationSubmission<T>>;

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
        URAuthRegisterRequested {
            uri: URI,
        },
        URAuthTreeRegistered {
            uri: URI,
            urauth_doc: URAuthDoc<T::AccountId, T::Balance>,
        },
        VerificationSubmitted {
            member: T::AccountId,
            digest: H256,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        BadProof,
        BadSigner,
        ErrorConvertToString,
        ErrorConvertToAccountId,
        BadChallengeValue,
        BadRequest,
        BadSignature,
        NotOracleMember,
        URINotVerfied,
        AccountMissing,
        ChallengeValueNotProvided,
        AlreadySubmitted,
        InvalidURI
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(1_000)]
        pub fn urauth_request_register_domain_owner(
            origin: OriginFor<T>,
            uri: URI,
            owner_did: OwnerDID,
            challenge_value: Option<Randomness>,
            signer: MultiSigner,
            signature: MultiSignature,
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            ensure!(Self::is_valid_uri(&uri.inner()), Error::<T>::InvalidURI);

            let urauth_signed_payload = URAuthSignedPayload::<T>::Request {
                uri: uri.clone(),
                owner_did: owner_did.clone(),
            };

            // Check whether account id of owner did and signer are same
            Self::check_is_valid_owner(&owner_did, signer.clone().into_account().as_ref())?;

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
            ensure!(
                Self::oracle_members().contains(&who),
                Error::<T>::NotOracleMember
            );

            // Parse json
            let (sig, raw_payload, uri, signer) = Self::try_handle_challenge_value(challenge_value)?;

            // 1. OwnerDID of URI == Challenge Value's DID
            // 2. Verify signature
            Self::try_verify_challenge_value(sig, raw_payload, uri, signer)?;

            // If valid,
            // 1. Store on `Requested::<T>::insert(uri, Vec<(Hash, ApproveCount)>)
            // 2. Other Oracle Nodes will send extrinsic and do same stuff
            // 3. Check Requested::<T>::get(uri) == Hash'(challenge_value)
            // 4. If same, Requested::<T>::insert(uri, (Hash, ApproveCount+1))
            // 5. If not same, Requested::<T>::insert(uri, (Hash', ApproveCount'))
            // 6. Over 60% of `OracleMembers::<T>` has done, tally
            // 7. Call register method register_new_urauth_doc(URAuthDoc::new(uri, admin_did, proof?))
            // IF >= 60% ?:
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

    fn try_verify_challenge_value(sig: Vec<u8>, raw_payload: Vec<u8>, uri: URI, signer: Vec<u8>) -> Result<(), DispatchError> {
        let multi_sig = Self::raw_signature_to_multi_sig(&sig)?;
        let account_id = AccountId32::try_from(&signer[..]).map_err(|_| Error::<T>::ErrorConvertToAccountId)?;
        if !raw_payload.using_encoded(|m| multi_sig.verify(m, &account_id)) {
            return Err(Error::<T>::BadProof.into())
        }
        let uri_metadata = URIMetadata::<T>::get(&uri).ok_or(Error::<T>::BadRequest)?; 
        Self::check_is_valid_owner(&uri_metadata.owner_did, &signer).map_err(|_| Error::<T>::BadSigner)?;
        Ok(())
    }

    fn check_is_valid_owner(owner_did: &Vec<u8>, signer: &[u8]) -> Result<(), DispatchError> {
        let owner_account_id =
            Self::account_id_from_did(owner_did)?;
        let raw_signer =
            String::from_utf8_lossy(&signer).to_string().as_bytes().to_vec();
        ensure!(owner_account_id == raw_signer, Error::<T>::BadSigner);
        Ok(())
    }

    fn raw_signature_to_multi_sig(sig: &Vec<u8>) -> Result<MultiSignature, DispatchError> {
        let full_str_sig = String::from_utf8_lossy(sig).to_string().to_lowercase();
        if full_str_sig.contains("ed25519") {
            let sig = ed25519::Signature::try_from(&sig[..]).map_err(|_| Error::<T>::BadSignature)?;
            Ok(MultiSignature::Ed25519(sig))
        } else if full_str_sig.contains("sr25519") {
            let sig = sr25519::Signature::try_from(&sig[..]).map_err(|_| Error::<T>::BadSignature)?;
            Ok(MultiSignature::Sr25519(sig))
        } else {
            let sig = ecdsa::Signature::try_from(&sig[..]).map_err(|_| Error::<T>::BadSignature)?;
            Ok(MultiSignature::Ecdsa(sig))
        }
    }

    fn is_valid_uri(_uri: &Vec<u8>) -> bool {
        let _matcher: Matcher0<_> = regex!(br"");
        // if !matcher.is_match(&[]) {
        //     return Err(Error::<T>::InvalidURI.into());
        // }
        true
    }

    /// Return
    ///
    /// (Signature, RuntimeGereratedProof, AccountId)
    fn try_handle_challenge_value(challenge_value: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>, URI, Vec<u8>), DispatchError> {
        let json_str = sp_std::str::from_utf8(&challenge_value)
            .map_err(|_| Error::<T>::ErrorConvertToString)?;

        match lite_json::parse_json(json_str) {
            Ok(obj) => match obj {
                // ToDo: Check domain, admin_did, challenge
                lite_json::JsonValue::Object(obj) => {
                    let uri = Self::find_json_value(&obj, String::from("domain"), None)?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let owner_did = Self::find_json_value(&obj, String::from("adminDID"), None)?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let challenge = Self::find_json_value(&obj, String::from("challenge"), None)?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let timestamp = Self::find_json_value(&obj, String::from("timestamp"), None)?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let proof_type = Self::find_json_value(&obj, String::from("proof"), Some(String::from("type")))?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let proof = Self::find_json_value(&obj, String::from("proof"), Some(String::from("proofValue")))?
                        .ok_or(Error::<T>::BadChallengeValue)?;

                    let mut raw_payload: Vec<u8> = Default::default();
                    let signer = Self::account_id_from_did(&owner_did)?;
                    URAuthSignedPayload::<T>::Challenge { uri: URI::new(uri.clone()), owner_did, challenge, timestamp }.using_encoded(|m| raw_payload = m.to_vec());

                    return Ok((proof, raw_payload, URI::new(uri), signer))
                }
                _ => return Err(Error::<T>::BadChallengeValue.into()),
            },
            Err(_) => return Err(Error::<T>::BadChallengeValue.into()),
        }
    }

    fn find_json_value(
        json_object: &lite_json::JsonObject,
        field_name: String,
        sub_field: Option<String>,
    ) -> Result<Option<Vec<u8>>, DispatchError> {
        let sub = sub_field.map_or("".into(), |s| s);
        let (_, json_value) = json_object
            .iter()
            .find(|(field, _)| field.iter().copied().eq(field_name.chars()))
            .ok_or(Error::<T>::BadChallengeValue)?;
        match json_value {
            lite_json::JsonValue::String(v) => Ok(Some(v.iter().collect::<String>().as_bytes().to_vec())),
            lite_json::JsonValue::Object(v) => Self::find_json_value(v, sub, None),
            _ => Ok(None),
        }
    }

    fn account_id_from_did(raw_owner_did: &Vec<u8>) -> Result<Vec<u8>, DispatchError> {
        let owner_did = String::from_utf8_lossy(raw_owner_did).to_string();
        let split: Vec<&str> = owner_did.split(':').collect::<Vec<&str>>();
        let account_id = split.last().ok_or(Error::<T>::AccountMissing)?.clone();
        Ok(account_id.as_bytes().to_vec())
    }
}
