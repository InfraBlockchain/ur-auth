#![cfg_attr(not(feature = "std"), no_std)]

use codec::Encode;
use fixedstr::zstr;

use frame_support::{pallet_prelude::*, traits::UnixTime, BoundedVec};

use frame_system::pallet_prelude::*;
use sp_consensus_vrf::schnorrkel::Randomness;
use sp_core::*;
use sp_runtime::{
    traits::{BlakeTwo256, IdentifyAccount, Verify},
    AccountId32, MultiSignature, MultiSigner,
};
use sp_std::vec::Vec;

pub use pallet::*;

pub mod types;
pub use types::*;

#[cfg(test)]
pub mod mock;

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

        type MaxOracleMembers: Get<u32>;

        type AuthorizedOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

    #[pallet::storage]
    #[pallet::unbounded]
    /// **Description:**
    ///
    /// Store the `URAuthDoc` corresponding to the verified URI by Oracle nodes.
    /// The `URAuthDoc` contains definitions such as the DID of the owner for that URI and access permissions.
    ///
    /// **Key:**
    ///
    /// URI
    ///
    /// **Value:**
    ///
    /// URAuthDoc
    pub type URAuthTree<T: Config> = StorageMap<_, Twox128, URI, URAuthDoc<T::AccountId>>;

    #[pallet::storage]
    #[pallet::unbounded]
    /// **Description:**
    ///
    /// Temporarily store the URIMetadata(owner_did and challenge_value) for the unverified URI in preparation for its verification.
    ///
    /// **Key:**
    ///
    /// URI
    ///
    /// **Value:**
    ///
    /// URIMetadata
    pub type URIMetadata<T: Config> = StorageMap<_, Twox128, URI, Metadata, OptionQuery>;

    #[pallet::storage]
    #[pallet::unbounded]
    #[pallet::getter(fn uri_verification_info)]
    /// **Description:**
    ///
    /// When validation is initiated by the Oracle node, store the submission status.
    /// For the requested URI, the Oracle node submits based on the Challenge Value and continues until it reaches a threshold value or higher.
    ///
    /// **Key:**
    ///
    /// URI
    ///
    /// **Value:**
    ///
    /// VerificationSubmission
    pub type URIVerificationInfo<T: Config> =
        StorageMap<_, Twox128, URI, VerificationSubmission<T>>;

    #[pallet::storage]
    #[pallet::unbounded]
    /// **Description:**
    ///
    /// A random Challenge value is stored for the requested URI.
    /// The Randomness consists of a random value of 32 bytes.
    ///
    /// **Key:**
    ///
    /// URI
    ///
    /// **Value:**
    ///
    /// schnorrkel::Randomness
    pub type ChallengeValue<T: Config> = StorageMap<_, Twox128, URI, Randomness>;

    #[pallet::storage]
    #[pallet::unbounded]
    /// **Description:**
    ///
    /// The status of the URAuthDoc that has been requested for update on a specific field is stored in the form of UpdateDocStatus.
    /// URAuthDoc updates are only possible when the UpdateStatus is set to `Available`.
    /// 
    /// **Key:**
    ///
    /// DocId
    ///
    /// **Value:**
    ///
    /// UpdateDocStatus
    pub type URAuthDocUpdateStatus<T: Config> =
        StorageMap<_, Blake2_128Concat, DocId, UpdateDocStatus<T::AccountId>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn oracle_members)]
    /// **Description:**
    ///
    /// Contains the AccountId information of the Oracle node.
    /// 
    /// **Value:**
    ///
    /// BoundedVec<T::AccoutnId, T::MaxOracleMembers>
    pub type OracleMembers<T: Config> =
        StorageValue<_, BoundedVec<T::AccountId, T::MaxOracleMembers>, ValueQuery>;

    #[pallet::storage]
    #[pallet::unbounded]
    /// **Description:**
    ///
    /// Contains various _config_ information for the URAuth pallet.
    /// 
    /// **Value:**
    ///
    /// ChallengeValueConfig
    pub type URAuthConfig<T: Config> = StorageValue<_, ChallengeValueConfig, ValueQuery>;

    /// **Description:**
    ///
    /// A counter used for generating the document id of the URAuthDoc.
    /// 
    /// **Value:**
    ///
    /// URAuthDocCount
    #[pallet::storage]
    pub type Counter<T: Config> = StorageValue<_, URAuthDocCount, ValueQuery>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub oracle_members: Vec<T::AccountId>,
        pub challenge_value_config: ChallengeValueConfig,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            GenesisConfig {
                oracle_members: Default::default(),
                challenge_value_config: Default::default(),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            let oracle_members: BoundedVec<T::AccountId, T::MaxOracleMembers> = self
                .oracle_members
                .clone()
                .try_into()
                .expect("Max Oracle members reached!");
            OracleMembers::<T>::put(oracle_members);
            URAuthConfig::<T>::put(self.challenge_value_config.clone());
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// URI is requested for its ownership.
        URAuthRegisterRequested {
            uri: URI,
        },
        /// `URAuthDoc` is registered on `URAuthTree`.
        URAuthTreeRegistered {
            count: URAuthDocCount,
            uri: URI,
            urauth_doc: URAuthDoc<T::AccountId>,
        },
        /// Oracle member has submitted its verification of challenge value.
        VerificationSubmitted {
            member: T::AccountId,
            digest: H256,
        },
        /// Result of `VerificationSubmission`.
        VerificationInfo {
            uri: URI,
            progress_status: VerificationSubmissionResult,
        },
        /// `URAuthDoc` has been updated for specific fiend.
        URAuthDocUpdated {
            update_doc_field: UpdateDocField<T::AccountId>,
            urauth_doc: URAuthDoc<T::AccountId>,
        },
        /// Update of `URAuthDoc` is in progress.
        UpdateInProgress {
            urauth_doc: URAuthDoc<T::AccountId>,
            update_doc_status: UpdateDocStatus<T::AccountId>,
        },
        /// Request of registering URI has been removed.
        Removed {
            uri: URI,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// May have overflowed its type(e.g Counter)
        Overflow,
        /// General error to do with the owner's proofs (e.g. signature).
        BadProof,
        /// The sending address is disabled or known to be invalid.
        BadSigner,
        /// General error on challenge value(e.g parsing json-string, different challenge value).
        BadChallengeValue,
        /// Error on verifying challenge before requesting its ownership.
        BadRequest,
        /// Error on converting raw-json to json-string.
        ErrorConvertToString,
        /// Error on converting raw-signature to concrete type signature.
        ErrorConvertToSignature,
        /// Error on decoding raw-did to bs58 encoding
        ErrorDecodeBs58,
        /// Error on converting `AccountId32` to `T::AccountId`
        ErrorDecodeAccountId,
        /// Error on decoding hex encoding string to actual string
        ErrorDecodeHex,
        /// General error on updating `URAuthDoc`(e.g Invalid UpdatedAt, Different update field)
        ErrorOnUpdateDoc,
        /// General error on updating `URAuthDocUpdateStatus`(e.g ProofMissing for updating `URAuthDoc`)
        ErrorOnUpdateDocStatus,
        /// Error on some authorized calls which required origin as Oracle member
        NotOracleMember,
        /// Error when signer of signature is not `URAuthDoc` owner.
        NotURAuthDocOwner,
        /// General error on proof where it is required but it is not given.
        ProofMissing,
        /// Error when challenge value is not stored for requested URI.
        ChallengeValueMissing,
        /// Challenge value is not provided when `ChallengeValueConfig.randomness` is false.
        ChallengeValueNotProvided,
        /// When try to update `URAuthDoc` which has not registered.
        URAuthTreeNotRegistered,
        /// Oracle node has voted more than once
        AlreadySubmitted,
        /// When trying to add oracle member more than `T::MaxOracleMembers`
        MaxOracleMembers,
        /// When trying to update different field on `UpdateInProgress` field
        UpdateInProgress,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {

        // Description:
		// This transaction is for a domain owner to request ownership registration in the URAuthTree. 
        // It involves verifying the signature for the data owner's DID on the given URI and, 
        // if valid, generating a Challenge Value and storing it in the Storage.
		//
		// Origin:
		// ** Signed call **
		//
		// Params:
		// - uri: URI to be claimed its ownership
        // - owner_did: URI owner's DID
        // - challenge_value: Challenge value for verification
        // - signer: Entity who creates signature
        // - proof: Proof of URI's ownership 
		//
		// Logic:
		// 1. Creation of a message for signature verification: `payload = (uri, owner_did).encode()`
        // 2. Signature verification
        // 3. If the signature is valid, generate a metadata(owner_did, challenge_value)
        #[pallet::call_index(0)]
        #[pallet::weight(1_000)]
        pub fn urauth_request_register_domain_owner(
            origin: OriginFor<T>,
            uri: URI,
            owner_did: OwnerDID,
            challenge_value: Option<Randomness>,
            signer: MultiSigner,
            proof: MultiSignature,
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;

            Self::verify_request_proof(&uri, &owner_did, &proof, signer)?;

            let cv = if URAuthConfig::<T>::get().randomness_enabled() {
                Self::challenge_value()
            } else {
                challenge_value.ok_or(Error::<T>::ChallengeValueNotProvided)?
            };

            ChallengeValue::<T>::insert(&uri, cv);
            URIMetadata::<T>::insert(&uri, Metadata::new(owner_did, cv));

            Self::deposit_event(Event::<T>::URAuthRegisterRequested { uri });

            Ok(())
        }

        // Description:
		// Oracle node will download `challenge-value.json` and call this transaction
        // , which is responsible for validating the challenge
        // To successfully register the `URAuthDoc` in the `URAuthTree`, 
        // it's necessary that over 60% of the members in OracleMembers::<T> submit their validations. 
        // Additionally, the approvals must meet this threshold to be considered valid for the registration of the URAuthDoc in the URAuthTree.
		//
		// Origin:
		// ** Signed call **
		//
		// Params:
		// - challenge_value: Raw of challenge-value-json-string.
        // 
		// Logic:
		// 1. Creation of a message for signature verification: `payload = (uri, owner_did).encode()`
        // 2. Signature verification
        // 3. If the signature is valid, generate a metadata(owner_did, challenge_value)
        #[pallet::call_index(1)]
        #[pallet::weight(1_000)]
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
            Self::handle_verification_submission_result(&res, vs, &uri, owner)?;
            Self::deposit_event(Event::<T>::VerificationInfo {
                uri,
                progress_status: res,
            });

            Ok(())
        }

        // Description:
		// After the registration in the URAuthTree is completed, 
        // this transaction allows the owner to update the URAuthDoc. 
        // Upon verifying the proof and if it's valid, 
        // the transaction compares the weight values of owner DIDs and the threshold. 
        // Finally, the updated URAuthDoc is stored in the URAuthTree.
		//
		// Origin:
		// ** Signed call **
		//
		// Params:
		// - uri: Key of `URAuthTree`
        // - update_doc_field: Which field of `URAuthDoc` to update
        // - updated_at: Timeframe of updating `URAuthDoc`
        // - proof: Proof of updating `URAuthDoc`
        // 
		// Logic:
		// 1. Update the doc based on `UpdateDocStatus` & `UpdateDocField`
        // 2. Verify its given proof
        // 3. If valid, store on `URAuthTree` based on Multi DIDs weight and threshold
        #[pallet::call_index(2)]
        #[pallet::weight(1_000)]
        pub fn update_urauth_doc(
            origin: OriginFor<T>,
            uri: URI,
            update_doc_field: UpdateDocField<T::AccountId>,
            updated_at: u128,
            proof: Option<Proof>,
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let (mut updated_urauth_doc, mut update_doc_status) =
                Self::try_update_urauth_doc(&uri, &update_doc_field, updated_at, proof.clone())?;
            let (owner, proof) = Self::try_verify_urauth_doc_proof(&updated_urauth_doc, proof)?;
            Self::try_store_updated_urauth_doc(
                owner,
                proof,
                &mut updated_urauth_doc,
                &mut update_doc_status,
                update_doc_field,
            )?;

            Ok(())
        }

        // Description:
        // This transaction involves adding members of the Oracle node to the verification request after downloading the Challenge Value.
		//
		// Origin:
		// ** Root(Authorized) privileged call **
		//
		// Params:
		// - who: Whom to be included as Oracle member
        #[pallet::call_index(3)]
        #[pallet::weight(1_000)]
        pub fn add_oracle_member(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
            T::AuthorizedOrigin::ensure_origin(origin)?;

            OracleMembers::<T>::mutate(|m| {
                m.try_push(who).map_err(|_| Error::<T>::MaxOracleMembers)
            })?;

            Ok(())
        }

        // Description:
        // This transaction allows for the update of various configurations within the URAuth pallet.
		//
		// Origin:
		// ** Root(Authorized) privileged call **
		//
		// Params:
		// - randomness_enabled: Flag whether to create its randomness on-chain
        #[pallet::call_index(4)]
        #[pallet::weight(1_000)]
        pub fn update_urauth_config(
            origin: OriginFor<T>,
            randomness_enabled: bool,
        ) -> DispatchResult {
            T::AuthorizedOrigin::ensure_origin(origin)?;

            URAuthConfig::<T>::mutate(|challenge_value_config| {
                challenge_value_config.randomness_enabled = randomness_enabled;
            });

            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    /// 16 bytes uuid based on `URAuthDocCount`
    fn doc_id(index: u128) -> [u8; 16] {
        let b = index.to_le_bytes();
        nuuid::Uuid::from_bytes(b).to_bytes()
    }

    fn unix_time() -> u128 {
        T::UnixTime::now().as_millis()
    }

    fn challenge_value() -> Randomness {
        Default::default()
    }

    /// Verify `request` signature
    /// 
    /// 1. Check whether owner and signer are same
    /// 2. Check the signature 
    fn verify_request_proof(
        uri: &URI,
        owner_did: &OwnerDID,
        signature: &MultiSignature,
        signer: MultiSigner,
    ) -> Result<(), DispatchError> {
        let urauth_signed_payload = URAuthSignedPayload::<T::AccountId>::Request {
            uri: uri.clone(),
            owner_did: owner_did.clone(),
        };

        // Check whether account id of owner did and signer are same
        let signer_account_id = Self::account_id_from_source(AccountIdSource::AccountId32(
            signer.clone().into_account(),
        ))?;

        Self::check_is_valid_owner(owner_did, &signer_account_id)?;

        // Check signature
        if !urauth_signed_payload
            .using_encoded(|payload| signature.verify(payload, &signer.into_account()))
        {
            return Err(Error::<T>::BadProof.into());
        }

        Ok(())
    }

    /// Handle the result of _challenge value_ verification based on `VerificationSubmissionResult`
    fn handle_verification_submission_result(
        res: &VerificationSubmissionResult,
        verficiation_submission: VerificationSubmission<T>,
        uri: &URI,
        owner_did: T::AccountId,
    ) -> Result<(), DispatchError> {
        match res {
            VerificationSubmissionResult::Complete => {
                let mut count = Counter::<T>::get();
                count = count.checked_add(1).ok_or(Error::<T>::Overflow)?;
                let urauth_doc: URAuthDoc<T::AccountId> = URAuthDoc::new(
                    Self::doc_id(count),
                    uri.clone(),
                    MultiDID::new(owner_did, 1),
                    Self::unix_time(),
                );
                Counter::<T>::put(count);
                URAuthTree::<T>::insert(&uri, urauth_doc.clone());
                Self::remove_all_uri_related(uri.clone());
                Self::deposit_event(Event::<T>::URAuthTreeRegistered {
                    count,
                    uri: uri.clone(),
                    urauth_doc,
                })
            }
            VerificationSubmissionResult::Tie => Self::remove_all_uri_related(uri.clone()),
            VerificationSubmissionResult::InProgress => {
                URIVerificationInfo::<T>::insert(&uri, verficiation_submission)
            }
        }

        Ok(())
    }

    /// Verify _challenge value_
    /// 
    /// 1. Check given signature 
    /// 2. Check whether `signer` and `owner` are identical
    /// 3. Check whether `given` challenge value is same with `onchain` challenge value
    fn try_verify_challenge_value(
        sig: Vec<u8>,
        proof_type: Vec<u8>,
        raw_payload: Vec<u8>,
        uri: &URI,
        raw_owner_did: &Vec<u8>,
        challenge: Vec<u8>,
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
    
    /// Check whether `owner` and `signer` are identical
    fn check_is_valid_owner(
        raw_owner_did: &Vec<u8>,
        signer: &T::AccountId,
    ) -> Result<(), DispatchError> {
        let owner_account_id =
            Self::account_id_from_source(AccountIdSource::DID(raw_owner_did.clone()))?;
        ensure!(&owner_account_id == signer, Error::<T>::BadSigner);
        Ok(())
    }

    /// Check whether `given` challenge value is same with `onchain` challenge value
    /// 
    /// ## Errors
    /// 
    /// `ChallengeValueMissing`
    /// 
    /// Challenge value for given _uri_ is not stored
    /// 
    /// - `BadChallengeValue`
    /// 
    /// Given challenge value and onchain challenge value are not identical
    fn check_challenge_value(uri: &URI, challenge: Vec<u8>) -> Result<(), DispatchError> {
        let cv = ChallengeValue::<T>::get(&uri).ok_or(Error::<T>::ChallengeValueMissing)?;
        ensure!(challenge == cv.to_vec(), Error::<T>::BadChallengeValue);
        Ok(())
    }

    /// Update the `URAuthDoc` based on `UpdateDocField`. 
    /// If it is first time requestsed, `UpdateStatus` would be `Available`.
    /// Otherwise, `InProgress { .. }`. 
    /// 
    /// ## Errors
    /// `ProofMissing`
    /// `URAuthTreeNotRegistered`
    fn try_update_urauth_doc(
        uri: &URI,
        update_doc_field: &UpdateDocField<T::AccountId>,
        updated_at: u128,
        maybe_proof: Option<Proof>,
    ) -> Result<(URAuthDoc<T::AccountId>, UpdateDocStatus<T::AccountId>), DispatchError> {
        let _ = maybe_proof.ok_or(Error::<T>::ProofMissing)?;
        let mut urauth_doc =
            URAuthTree::<T>::get(uri).ok_or(Error::<T>::URAuthTreeNotRegistered)?;
        let mut update_doc_status = URAuthDocUpdateStatus::<T>::get(&urauth_doc.id);
        Self::do_try_update_doc(
            &mut urauth_doc,
            &mut update_doc_status,
            update_doc_field,
            updated_at,
        )?;

        Ok((urauth_doc, update_doc_status))
    }

    /// Try to store _updated_ `URAuthDoc` on `URAuthTree::<T>`.
    /// 
    /// Check whether _did_weight_ is greater of equal to _remaining_threshold_.
    /// If it is bigger, _1. remove all previous proofs 2. and store on `URAuthTree::<T>`._
    /// Otherwise, update `URAuthDocUpdateStatus`.
    fn handle_updated_urauth_doc(
        signer: AccountId32,
        proof: Proof,
        urauth_doc: &mut URAuthDoc<T::AccountId>,
        update_doc_status: &mut UpdateDocStatus<T::AccountId>,
        update_doc_field: UpdateDocField<T::AccountId>,
    ) -> Result<(), DispatchError> {
        let multi_did = urauth_doc.get_multi_did();
        let uri = urauth_doc.get_uri();
        let account_id = Pallet::<T>::account_id_from_source(AccountIdSource::AccountId32(signer))?;
        let did_weight = multi_did
            .get_did_weight(&account_id)
            .ok_or(Error::<T>::NotURAuthDocOwner)?;
        let remaining_threshold = update_doc_status.remaining_threshold;
        update_doc_status
            .handle_in_progress(did_weight, update_doc_field.clone(), proof)
            .map_err(|_| Error::<T>::ErrorOnUpdateDocStatus)?;
        if did_weight >= remaining_threshold {
            let new_proofs = update_doc_status.get_proofs();
            urauth_doc.handle_proofs(new_proofs);
            URAuthTree::<T>::insert(uri, urauth_doc.clone());
            URAuthDocUpdateStatus::<T>::remove(urauth_doc.id);
            Pallet::<T>::deposit_event(Event::<T>::URAuthDocUpdated {
                update_doc_field,
                urauth_doc: urauth_doc.clone(),
            });
        } else {
            URAuthDocUpdateStatus::<T>::insert(urauth_doc.id, update_doc_status.clone());
            Pallet::<T>::deposit_event(Event::<T>::UpdateInProgress {
                urauth_doc: urauth_doc.clone(),
                update_doc_status: update_doc_status.clone(),
            });
        }
        Ok(())
    }

    /// Try verify proof of _updated_ `URAuthDoc`.
    /// 
    /// ## Errors
    /// `ProofMissing` : Proof is not provided
    /// 
    /// `NotURAuthDocOwner` : If signer is not owner of `URAuthDoc`
    /// 
    /// `BadProof` : Signature is not valid
    fn try_verify_urauth_doc_proof(
        urauth_doc: &URAuthDoc<T::AccountId>,
        proof: Option<Proof>,
    ) -> Result<(AccountId32, Proof), DispatchError> {
        let (owner_did, sig) = match proof.clone().ok_or(Error::<T>::ProofMissing)? {
            Proof::ProofV1 { did, proof } => (did, proof),
        };
        let owner_account = Self::account_id_from_source(AccountIdSource::DID(owner_did.clone()))?;
        if !urauth_doc.multi_owner_did.is_owner(&owner_account) {
            return Err(Error::<T>::NotURAuthDocOwner.into());
        }
        let payload = URAuthSignedPayload::<T::AccountId>::Update {
            urauth_doc: urauth_doc.clone(),
            owner_did: owner_did.clone(),
        };
        let signer = Pallet::<T>::account_id32_from_raw_did(owner_did)?;
        if !payload.using_encoded(|m| sig.verify(m, &signer)) {
            return Err(Error::<T>::BadProof.into());
        }

        Ok((signer, proof.expect("Already checked!")))
    }

    /// Try to store _updated_urauth_doc_ on `URAuthTree::<T>` based on `URAuthDocStatus`
    fn try_store_updated_urauth_doc(
        signer: AccountId32,
        proof: Proof,
        urauth_doc: &mut URAuthDoc<T::AccountId>,
        update_doc_status: &mut UpdateDocStatus<T::AccountId>,
        updated_doc_field: UpdateDocField<T::AccountId>,
    ) -> Result<(), DispatchError> {
        Self::handle_updated_urauth_doc(
            signer,
            proof,
            urauth_doc,
            update_doc_status,
            updated_doc_field,
        )?;

        Ok(())
    }

    /// Convert raw signature type to _concrete(`MultiSignature`)_ signature type
    /// 
    /// ## Error
    /// `ErrorConvertToSignature`
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

    /// Remove all `URI` related data when `VerificationSubmissionResult::Complete` or `VerificationSubmissionResult::Tie`
    /// 
    /// ## Changes
    /// `URIMetadata`, `URIVerificationInfo`, `ChallengeValue`
    fn remove_all_uri_related(uri: URI) {
        URIMetadata::<T>::remove(&uri);
        URIVerificationInfo::<T>::remove(&uri);
        ChallengeValue::<T>::remove(&uri);

        Self::deposit_event(Event::<T>::Removed { uri })
    }

    /// Try prase the raw-json and return opaque type of 
    /// (`Signature`, `proof type`, `payload`, `uri`, `owner_did`, `challenge`)
    /// 
    /// ## Errors
    /// `ErrorConvertToString`
    /// - Error on converting raw-json to string-json
    /// 
    /// `BadChallengeValue`
    /// - When input is not type of `lite_json::Object` 
    /// - Fail on parsing some fields
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
                    let mut raw_payload: Vec<u8> = Default::default();
                    let raw_owner_did = owner_did.clone();
                    URAuthSignedPayload::<T::AccountId>::Challenge {
                        uri: URI::new(uri.clone()),
                        owner_did,
                        challenge: challenge.clone(),
                        timestamp,
                    }
                    .using_encoded(|m| raw_payload = m.to_vec());

                    return Ok((
                        proof.to_vec(),
                        proof_type,
                        raw_payload,
                        URI::new(uri),
                        raw_owner_did,
                        challenge,
                    ));
                }
                _ => return Err(Error::<T>::BadChallengeValue.into()),
            },
            Err(_) => return Err(Error::<T>::BadChallengeValue.into()),
        }
    }

    /// Method for finding _json_value_ based on `field_name` and `sub_field`
    /// 
    /// ## Error
    /// `BadChallengeValue`
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

    /// Try to convert some id sources to `T::AccountId` based on `AccountIdSource::DID` or `AccountIdSource::AccountId32`
    /// 
    /// ## Error
    /// `BadChallengeValue`: Since AccountId is length of _48_. If is shorter than 48, we assume it is invalid.
    /// 
    /// `ErrorDecodeAccountId` : Fail on convert from `AccountId32` to `T::AccountId`
    fn account_id_from_source(source: AccountIdSource) -> Result<T::AccountId, DispatchError> {
        let account_id32 = match source {
            AccountIdSource::DID(mut raw_owner_did) => {
                let byte_len = raw_owner_did.len();
                if byte_len < 48 {
                    return Err(Error::<T>::BadChallengeValue.into());
                }
                let actual_owner_did: Vec<u8> =
                    raw_owner_did.drain(byte_len-48..byte_len).collect();
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

    /// Try to convert from `raw_owner_did` to `AccountId32`
    /// 
    /// ## Error
    /// `BadChallengeValue`, `ErrorDecodeBs58`
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

impl<T: Config> Pallet<T> {
    /// Check whether `updated_at` is greater than `prev_updated_at`
    /// 
    /// ## Error
    /// `ErrorOnUpdateDoc`
    fn check_valid_updated_at(prev: u128, now: u128) -> Result<(), DispatchError> {
        if !prev <= now {
            return Err(Error::<T>::ErrorOnUpdateDoc.into());
        }
        Ok(())
    }

    /// Try handle for updating `URAuthDocStatus`
    /// 
    /// ## Error
    /// `ErrorOnUpdateDoc` : Try to update on different field 
    fn handle_update_doc_status(
        update_doc_status: &mut UpdateDocStatus<T::AccountId>,
        update_doc_field: &UpdateDocField<T::AccountId>,
        threshold: DIDWeight,
    ) -> Result<(), DispatchError> {
        match &update_doc_status.status {
            UpdateStatus::Available => {
                update_doc_status.handle_available(threshold, update_doc_field.clone());
            }
            UpdateStatus::InProgress { field, .. } => {
                if field != update_doc_field {
                    return Err(Error::<T>::ErrorOnUpdateDoc.into());
                }
            }
        }

        Ok(())
    }

    /// Try to update doc and return _Err_ if any.
    /// 
    /// ## Errors
    /// 
    /// `ErrorOnUpdateDoc`
    /// - _updated_at_ is less than _pref_updated_at_
    /// - Try to update on different field 
    /// - Threshold is bigger than sum of _multi_dids'_ weight
    pub fn do_try_update_doc(
        urauth_doc: &mut URAuthDoc<T::AccountId>,
        update_doc_status: &mut UpdateDocStatus<T::AccountId>,
        update_doc_field: &UpdateDocField<T::AccountId>,
        updated_at: u128,
    ) -> Result<(), DispatchError> {
        let prev_updated_at = urauth_doc.updated_at;
        Self::check_valid_updated_at(prev_updated_at, updated_at)?;
        Self::handle_update_doc_status(
            update_doc_status,
            update_doc_field,
            urauth_doc.get_threshold(),
        )?;

        urauth_doc
            .update_doc(update_doc_field.clone(), updated_at)
            .map_err(|e| {
                log::warn!(" 🚨 Error on update urauth_doc {:?} 🚨", e);
                Error::<T>::ErrorOnUpdateDoc
            })?;

        Ok(())
    }

    /// ## **RUNTIME API METHOD**
    /// 
    /// Return _updated_ `Some(URAuthDoc)`. 
    /// Return `None` if given `URI` is not registered on `URAuthTree` 
    /// or `ErrorOnUpdateDoc`.
    pub fn get_updated_doc(
        uri: URI,
        update_doc_field: UpdateDocField<T::AccountId>,
        updated_at: u128,
    ) -> Option<URAuthDoc<T::AccountId>> {
        if let Some(mut urauth_doc) = URAuthTree::<T>::get(&uri) {
            match urauth_doc.update_doc(update_doc_field, updated_at) {
                Ok(_) => Some(urauth_doc.clone()),
                Err(_) => None,
            }
        } else {
            None
        }
    }
}
