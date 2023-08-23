#![cfg_attr(not(feature = "std"), no_std)]

use codec::Encode;
use fixedstr::zstr;

use frame_support::{pallet_prelude::*, BoundedVec, traits::UnixTime };

use frame_system::pallet_prelude::*;
use sp_consensus_vrf::schnorrkel::Randomness;
use sp_core::*;
use sp_runtime::{
    traits::{
        BlakeTwo256, IdentifyAccount, Verify,
    },
    AccountId32, MultiSignature, MultiSigner,
};
use sp_std::vec::Vec;

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

        type UnixTime: UnixTime;

        type MaxOracleMemembers: Get<u32>;

        type AuthorizedOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

    #[pallet::storage]
    #[pallet::unbounded]
    pub type URAuthTree<T: Config> =
        StorageMap<_, Twox128, URI, URAuthDoc<T>>;

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
    pub type UpdateDocStatus<T: Config> = StorageMap<_, Blake2_128Concat, DocId, RemainingThreshold>;

    #[pallet::storage]
    #[pallet::getter(fn oracle_members)]
    pub type OracleMembers<T: Config> =
        StorageValue<_, BoundedVec<T::AccountId, T::MaxOracleMemembers>, ValueQuery>;

    #[pallet::storage]
    #[pallet::unbounded]
    pub type URAuthConfig<T: Config> = StorageValue<_, ChallengeValueConfig, ValueQuery>;

    #[pallet::storage]
    pub type Counter<T: Config> = StorageValue<_, URAuthDocCount, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        URAuthRegisterRequested {
            uri: URI,
        },
        URAuthTreeRegistered {
            count: URAuthDocCount,
            uri: URI,
            urauth_doc: URAuthDoc<T>,
        },
        VerificationSubmitted {
            member: T::AccountId,
            digest: H256,
        },
        VerificationInfo {
            uri: URI,
            progress_status: VerificationResult,
        },
        URAuthDocUpdated {
            updated_field: UpdateDocField<T::AccountId>,
            urauth_doc: URAuthDoc<T>
        },
        URIRemoved {
            uri: URI,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        Overflow,
        BadProof,
        BadSigner,
        BadChallengeValue,
        BadRequest,
        ErrorConvertToString,
        ErrorConvertToAccountId,
        ErrorConvertToSignature,
        ErrorDecodeBs58,
        ErrorDecodeAccountId,
        ErrorDecodeHex,
        NotOracleMember,
        URINotVerfied,
        AccountMissing,
        OwnerMissing,
        ProofMissing,
        ChallengeValueMissing,
        ChallengeValueNotProvided,
        AlreadySubmitted,
        MaxOracleMembers,
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

            let urauth_signed_payload = URAuthSignedPayload::<T>::Request {
                uri: uri.clone(),
                owner_did: owner_did.clone(),
            };

            // Check whether account id of owner did and signer are same
            let signer_account_id = Self::account_id_from_source(AccountIdSource::AccountId32(
                signer.clone().into_account(),
            ))?;
            Self::check_is_valid_owner(&owner_did, &signer_account_id)?;

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
            URIMetadata::<T>::insert(&uri, Metadata::new(owner_did, cv));

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
            let (sig, proof_type, raw_payload, uri, raw_owner_did, challenge) =
                Self::try_handle_challenge_value(&challenge_value)?;

            // 1. OwnerDID of URI == Challenge Value's DID
            // 2. Verify signature
            let owner = Self::try_verify_challenge_value(
                sig,
                proof_type,
                raw_payload,
                &uri,
                &raw_owner_did,
                challenge,
            )?;
            let member_count = Self::oracle_members().len();
            let mut vs = if let Some(vs) = URIVerificationInfo::<T>::get(&uri) {
                vs
            } else {
                VerificationSubmission::<T>::default()
            };
            let res = vs.submit(member_count, (who, BlakeTwo256::hash(&challenge_value)))?;
            match res {
                VerificationResult::Complete => {
                    let mut count = Counter::<T>::get();
                    count = count.checked_add(1).ok_or(Error::<T>::Overflow)?;
                    let urauth_doc: URAuthDoc<T> =
                        URAuthDoc::new(Self::doc_id(count), uri.clone(), MultiDID::new(owner, 1), Self::unix_time());
                    Counter::<T>::put(count);
                    URAuthTree::<T>::insert(&uri, urauth_doc.clone());
                    Self::deposit_event(Event::<T>::URAuthTreeRegistered {
                        count,
                        uri: uri.clone(),
                        urauth_doc,
                    })
                }
                VerificationResult::Tie => Self::remove_all_uri_related(uri.clone()),
                _ => { /* In progress */ }
            }
            Self::deposit_event(Event::<T>::VerificationInfo {
                uri,
                progress_status: res,
            });

            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(1_000)]
        pub fn add_oracle_member(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
            T::AuthorizedOrigin::ensure_origin(origin)?;

            OracleMembers::<T>::mutate(|m| {
                m.try_push(who).map_err(|_| Error::<T>::MaxOracleMembers)
            })?;

            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    fn doc_id(index: u128) -> [u8; 16] {
        let b = index.to_le_bytes();
        nuuid::Uuid::from_bytes(b).to_bytes()
    }

    fn unix_time() -> u128 {
		T::UnixTime::now().as_millis()
	}

    // ToDo
    fn challenge_value() -> Randomness {
        Default::default()
    }

    fn try_verify_challenge_value(
        sig: Vec<u8>,
        proof_type: Vec<u8>,
        raw_payload: Vec<u8>,
        uri: &URI,
        raw_owner_did: &Vec<u8>,
        challenge: Vec<u8>
    ) -> Result<T::AccountId, DispatchError> {
        let multi_sig = Self::raw_signature_to_multi_sig(&proof_type, &sig)?;
        let signer = Self::account_id32_from_raw_did(raw_owner_did.clone())?;
        if !multi_sig.verify(&raw_payload[..], &signer) {
            return Err(Error::<T>::BadProof.into());
        }
        let uri_metadata = URIMetadata::<T>::get(uri).ok_or(Error::<T>::BadRequest)?;
        let signer = Self::account_id_from_source(AccountIdSource::DID(raw_owner_did.clone()))?;
        Self::check_is_valid_owner(&uri_metadata.owner_did, &signer)
            .map_err(|_| Error::<T>::BadSigner)?;
        Self::check_challenge_value(uri, challenge)?;
        Ok(signer)
    }

    fn check_is_valid_owner(
        raw_owner_did: &Vec<u8>,
        signer: &T::AccountId,
    ) -> Result<(), DispatchError> {
        let owner_account_id =
            Self::account_id_from_source(AccountIdSource::DID(raw_owner_did.clone()))?;
        ensure!(&owner_account_id == signer, Error::<T>::BadSigner);
        Ok(())
    }

    fn check_challenge_value(
        uri: &URI,
        challenge: Vec<u8>
    ) -> Result<(), DispatchError> {
        let cv = ChallengeValue::<T>::get(&uri).ok_or(Error::<T>::ChallengeValueMissing)?;
        ensure!(challenge == cv.to_vec(), Error::<T>::BadChallengeValue);
        Ok(())
    }

    fn raw_signature_to_multi_sig(
        proof_type: &Vec<u8>,
        sig: &Vec<u8>,
    ) -> Result<MultiSignature, DispatchError> {
        let zstr_proof = zstr::<128>::from_raw(proof_type).to_ascii_lower();
        let proof_type = zstr_proof.to_str();
        if proof_type.contains("ed25519") {
            let sig = ed25519::Signature::try_from(&sig[..])
                .map_err(|_| Error::<T>::ErrorConvertToSignature)?;
            Ok(sig.into())
        } else if proof_type.contains("sr25519") {
            let sig = sr25519::Signature::try_from(&sig[..])
                .map_err(|_| Error::<T>::ErrorConvertToSignature)?;
            Ok(sig.into())
        } else {
            let sig = ecdsa::Signature::try_from(&sig[..])
                .map_err(|_| Error::<T>::ErrorConvertToSignature)?;
            Ok(sig.into())
        }
    }

    fn remove_all_uri_related(uri: URI) {
        URIMetadata::<T>::remove(&uri);
        URIVerificationInfo::<T>::remove(&uri);
        ChallengeValue::<T>::remove(&uri);

        Self::deposit_event(Event::<T>::URIRemoved { uri })
    }

    /// Return
    ///
    /// (Signature, RuntimeGereratedProof, AccountId)
    fn try_handle_challenge_value(
        challenge_value: &Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, URI, Vec<u8>, Vec<u8>), DispatchError> {
        let json_str = sp_std::str::from_utf8(challenge_value)
            .map_err(|_| Error::<T>::ErrorConvertToString)?;

        match lite_json::parse_json(json_str) {
            Ok(obj) => match obj {
                // ToDo: Check domain, admin_did, challenge
                lite_json::JsonValue::Object(obj) => {
                    let uri = Self::find_json_value(&obj, "domain", None)?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let owner_did = Self::find_json_value(&obj, "adminDID", None)?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let challenge = Self::find_json_value(&obj, "challenge", None)?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let timestamp = Self::find_json_value(&obj, "timestamp", None)?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let proof_type = Self::find_json_value(&obj, "proof", Some("type"))?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let hex_proof = Self::find_json_value(&obj, "proof", Some("proofValue"))?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let mut proof = [0u8; 64];
                    hex::decode_to_slice(hex_proof, &mut proof as &mut [u8])
                        .map_err(|_| Error::<T>::ErrorDecodeHex)?;
                    let mut challenge_bytes = [0u8; 32];
                    hex::decode_to_slice(challenge.clone(), &mut challenge_bytes as &mut [u8])
                        .map_err(|_| Error::<T>::ErrorDecodeHex)?;
                    let mut raw_payload: Vec<u8> = Default::default();
                    let raw_owner_did = owner_did.clone();
                    URAuthSignedPayload::<T>::Challenge {
                        uri: URI::new(uri.clone()),
                        owner_did,
                        challenge,
                        timestamp,
                    }
                    .using_encoded(|m| raw_payload = m.to_vec());

                    return Ok((
                        proof.to_vec(),
                        proof_type,
                        raw_payload,
                        URI::new(uri),
                        raw_owner_did,
                        challenge_bytes.to_vec(),
                    ));
                }
                _ => return Err(Error::<T>::BadChallengeValue.into()),
            },
            Err(_) => return Err(Error::<T>::BadChallengeValue.into()),
        }
    }

    fn find_json_value(
        json_object: &lite_json::JsonObject,
        field_name: &str,
        sub_field: Option<&str>,
    ) -> Result<Option<Vec<u8>>, DispatchError> {
        let sub = sub_field.map_or("", |s| s);
        let (_, json_value) = json_object
            .iter()
            .find(|(field, _)| field.iter().copied().eq(field_name.chars()))
            .ok_or(Error::<T>::BadChallengeValue)?;
        match json_value {
            lite_json::JsonValue::String(v) => {
                Ok(Some(v.iter().map(|c| *c as u8).collect::<Vec<u8>>()))
            }
            lite_json::JsonValue::Object(v) => Self::find_json_value(v, sub, None),
            _ => Ok(None),
        }
    }

    fn account_id_from_source(source: AccountIdSource) -> Result<T::AccountId, DispatchError> {
        let account_id32 = match source {
            AccountIdSource::DID(mut raw_owner_did) => {
                let byte_len = raw_owner_did.len();
                if byte_len < 48 {
                    return Err(Error::<T>::BadChallengeValue.into());
                }
                let actual_owner_did: Vec<u8> =
                    raw_owner_did.drain(byte_len - 48..byte_len).collect();
                let mut output = bs58::decode(actual_owner_did)
                    .into_vec()
                    .map_err(|_| Error::<T>::ErrorDecodeBs58)?;
                let temp: Vec<u8> = output.drain(1..33).collect();
                let mut raw_account_id = [0u8; 32];
                let buf = &temp[..raw_account_id.len()];
                raw_account_id.copy_from_slice(buf);
                raw_account_id.into()
            }
            AccountIdSource::AccountId32(id) => id,
        };

        let account_id = T::AccountId::decode(&mut account_id32.as_ref())
            .map_err(|_| Error::<T>::ErrorDecodeAccountId)?;
        Ok(account_id)
    }

    fn account_id32_from_raw_did(mut raw_owner_did: Vec<u8>) -> Result<AccountId32, DispatchError> {
        let byte_len = raw_owner_did.len();
        if byte_len < 48 {
            return Err(Error::<T>::BadChallengeValue.into());
        }
        let actual_owner_did: Vec<u8> = raw_owner_did.drain(byte_len - 48..byte_len).collect();
        let mut output = bs58::decode(actual_owner_did)
            .into_vec()
            .map_err(|_| Error::<T>::ErrorDecodeBs58)?;
        let temp: Vec<u8> = output.drain(1..33).collect();
        let mut raw_account_id = [0u8; 32];
        let buf = &temp[..raw_account_id.len()];
        raw_account_id.copy_from_slice(buf);

        Ok(raw_account_id.into())
    }
}
