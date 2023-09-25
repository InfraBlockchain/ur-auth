#![cfg_attr(not(feature = "std"), no_std)]

use codec::Encode;
use fixedstr::zstr;

use frame_support::{
    pallet_prelude::*,
    traits::{ConstU32, UnixTime},
    BoundedVec,
};

use frame_system::pallet_prelude::*;
use sp_consensus_vrf::schnorrkel::Randomness;
use sp_core::*;
use sp_runtime::{
    traits::{BlakeTwo256, IdentifyAccount, Verify},
    AccountId32, MultiSignature, MultiSigner,
};
use sp_std::vec::Vec;
use xcm::latest::MultiAsset;

pub use pallet::*;

pub mod types;
pub use types::*;

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

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

        /// Parser for URAuth Pallet such as _challenge-value_, _URI_
        type URAuthParser: Parser<Self>;
        /// Time used for computing document creation.
        ///
        /// It is guaranteed to start being called from the first `on_finalize`. Thus value at
        /// genesis is not used.
        type UnixTime: UnixTime;

        /// The current members of Oracle.
        type MaxOracleMembers: Get<u32>;

        /// URI list which should be verified by _Oracle_
        #[pallet::constant]
        type MaxURIByOracle: Get<u32>;

        /// The origin which may be used within _authorized_ call.
        /// **Root** can always do this.
        type AuthorizedOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

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
    #[pallet::storage]
    pub type URAuthTree<T: Config> = StorageMap<_, Twox128, URI, URAuthDoc<T::AccountId>>;

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
    #[pallet::storage]
    pub type Metadata<T: Config> = StorageMap<_, Twox128, URI, RequestMetadata>;

    #[pallet::storage]
    pub type DataSet<T: Config> = StorageMap<_, Twox128, URI, DataSetMetadata<AnyText>>;

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
    #[pallet::storage]
    #[pallet::unbounded]
    #[pallet::getter(fn uri_verification_info)]
    pub type URIVerificationInfo<T: Config> =
        StorageMap<_, Twox128, URI, VerificationSubmission<T>>;

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
    #[pallet::storage]
    pub type ChallengeValue<T: Config> = StorageMap<_, Twox128, URI, Randomness>;
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
    #[pallet::storage]
    pub type URAuthDocUpdateStatus<T: Config> =
        StorageMap<_, Blake2_128Concat, DocId, UpdateDocStatus<T::AccountId>, ValueQuery>;

    /// **Description:**
    ///
    /// Contains the AccountId information of the Oracle node.
    ///
    /// **Value:**
    ///
    /// BoundedVec<T::AccountId, T::MaxOracleMembers>
    #[pallet::storage]
    #[pallet::getter(fn oracle_members)]
    pub type OracleMembers<T: Config> =
        StorageValue<_, BoundedVec<T::AccountId, T::MaxOracleMembers>, ValueQuery>;

    #[pallet::storage]
    pub type URIByOracle<T: Config> = 
        StorageValue<_, BoundedVec<URI, T::MaxURIByOracle>, ValueQuery>;

    /// **Description:**
    ///
    /// Contains various _config_ information for the URAuth pallet.
    ///
    /// **Value:**
    ///
    /// ChallengeValueConfig
    #[pallet::storage]
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
        pub uris_by_oracle: Vec<Vec<u8>>
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            GenesisConfig {
                oracle_members: Default::default(),
                challenge_value_config: Default::default(),
                uris_by_oracle: Default::default(),
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
            let uris_by_oracle: BoundedVec<URI, T::MaxURIByOracle> = self
                .uris_by_oracle
                .iter()
                .map(|uri| { 
                    let bounded_uri = uri.to_owned().try_into().expect("Too Long!");
                    bounded_uri
                })
                .collect::<Vec<URI>>()
                .try_into()
                .expect("Too long");
            URIByOracle::<T>::put(uris_by_oracle);
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// URI is requested for its ownership.
        URAuthRegisterRequested { uri: URI },
        /// `URAuthDoc` is registered on `URAuthTree`.
        URAuthTreeRegistered {
            claim_type: ClaimType,
            uri: URI,
            urauth_doc: URAuthDoc<T::AccountId>,
        },
        /// Oracle member has submitted its verification of challenge value.
        VerificationSubmitted { member: T::AccountId, digest: H256 },
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
        /// List of `URIByOracle` has been added
        URIByOracleAdded {
            uri: URI,
        },
        /// List of `URIByOracle` has been removed
        URIByOracleRemoved {
            uri: URI,
        },
        /// Request of registering URI has been removed.
        Removed { uri: URI },
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
        /// General error on requesting ownership(e.g URAuth Request, Challenge Value)
        BadRequest,
        /// General error on claiming ownership
        BadClaim,
        /// General error on URI
        BadURI,
        /// Size is over limit of `MAX_*`
        OverMaxSize,
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
        /// General error on parsing (e.g URI, Challenge Value)
        ErrorOnParse,
        /// Error on some authorized calls which required origin as Oracle member
        NotOracleMember,
        /// Error when signer of signature is not `URAuthDoc` owner.
        NotURAuthDocOwner,
        /// Given URI is not URI which should be verified by Oracle
        NotURIByOracle,
        /// Given URI is not base URI
        NotBaseURI,
        /// Given URI is not valid
        NotValidURI,
        /// Given URI should be claimed by Oracle
        NotClaimByOracle,
        /// General error on proof where it is required but it is not given.
        ProofMissing,
        /// Error when challenge value is not stored for requested URI.
        ChallengeValueMissing,
        /// Given uri should have protocol
        ProtocolMissing,
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
    impl<T: Config> Pallet<T> 
    where
        ClaimTypeFor<T>: From<ClaimType>,
    {
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
        pub fn urauth_request_register_ownership(
            origin: OriginFor<T>,
            uri: Vec<u8>,
            owner_did: Vec<u8>,
            challenge_value: Option<Randomness>,
            claim_type: ClaimType,
            signer: MultiSigner,
            proof: MultiSignature,
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let bounded_uri: URI = uri.try_into().map_err(|_| Error::<T>::OverMaxSize)?;
            let bounded_owner_did: OwnerDID =
                owner_did.try_into().map_err(|_| Error::<T>::OverMaxSize)?;
            let _ = Self::verify_request_proof(&bounded_uri, &bounded_owner_did, &proof, signer)?;

            let cv = if URAuthConfig::<T>::get().randomness_enabled() {
                Self::challenge_value()
            } else {
                challenge_value.ok_or(Error::<T>::ChallengeValueNotProvided)?
            };

            ChallengeValue::<T>::insert(&bounded_uri, cv);
            Metadata::<T>::insert(&bounded_uri, RequestMetadata::new(bounded_owner_did, cv, claim_type));

            Self::deposit_event(Event::<T>::URAuthRegisterRequested { uri: bounded_uri });

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
            let (sig, proof_type, raw_payload, uri, owner_did, challenge) =
                Self::try_handle_challenge_value(&challenge_value)?;

            // 1. OwnerDID of URI == Challenge Value's DID
            // 2. Verify signature
            let (owner, claim_type) = Self::try_verify_challenge_value(
                sig,
                proof_type,
                raw_payload,
                &uri,
                &owner_did,
                challenge,
            )?;
            let member_count = Self::oracle_members().len();
            let mut vs = if let Some(vs) = URIVerificationInfo::<T>::get(&uri) {
                vs
            } else {
                VerificationSubmission::<T>::default()
            };
            let res = vs.submit(member_count, (who, BlakeTwo256::hash(&challenge_value)))?;
            Self::handle_verification_submission_result(&res, vs, &uri, owner, claim_type)?;
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
            let (owner, proof) =
                Self::try_verify_urauth_doc_proof(&uri, &updated_urauth_doc, proof)?;
            Self::try_store_updated_urauth_doc(
                owner,
                proof,
                uri,
                &mut updated_urauth_doc,
                &mut update_doc_status,
                update_doc_field,
            )?;

            Ok(())
        }

        // Description:
        // Claim ownership of `ClaimType::*`.
        // This doesn't require any challenge json verification.
        // Once signature is verified, URAuthDoc will be registered on URAuthTree.
        //
        // Origin:
        // ** Signed call **
        //
        // Params:
        // - claim_type: Type of claim to register on URAuthTree
        // - uri: URI to be claimed its ownership
        // - owner_did: URI owner's DID
        // - signer: Entity who creates signature
        // - proof: Proof of URI's ownership
        //
        // Logic:
        // 1. Verify signature
        // 2. Verify signer is one of the parent owners
        // 3. Once it is verified, create new URAuthDoc based on `claim_type`
        #[pallet::call_index(3)]
        #[pallet::weight(1_000)]
        pub fn claim_ownership(
            origin: OriginFor<T>,
            claim_type: ClaimType,
            uri: Vec<u8>,
            owner_did: Vec<u8>,
            signer: MultiSigner,
            proof: MultiSignature,
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let bounded_uri: URI = uri.clone().try_into().map_err(|_| Error::<T>::OverMaxSize)?;
            let bounded_owner_did: OwnerDID =
                owner_did.try_into().map_err(|_| Error::<T>::OverMaxSize)?;
            let signer_acc = Self::verify_request_proof(&bounded_uri, &bounded_owner_did, &proof, signer)?;
            T::URAuthParser::check_parent_owner(&uri, &signer_acc, &claim_type)?;
            let owner =
                Self::account_id_from_source(AccountIdSource::DID(bounded_owner_did.to_vec()))?;
            // ToDo: Check that raw_url is not base
            let urauth_doc = match claim_type.clone() {
                ClaimType::Dataset {
                    data_source,
                    name,
                    description,
                    ..
                } => {
                    let bounded_name: AnyText =
                        name.try_into().map_err(|_| Error::<T>::OverMaxSize)?;
                    let bounded_description: AnyText = description
                        .try_into()
                        .map_err(|_| Error::<T>::OverMaxSize)?;
                    let bounded_data_source: Option<URI> = match data_source {
                        Some(ds) => {
                            let bounded: URI =
                                ds.try_into().map_err(|_| Error::<T>::OverMaxSize)?;
                            Some(bounded)
                        }
                        None => None,
                    };
                    DataSet::<T>::insert(
                        &bounded_uri,
                        DataSetMetadata::<AnyText>::new(bounded_name, bounded_description),
                    );
                    Self::new_urauth_doc(owner, None, bounded_data_source)?
                },
                _ => Self::new_urauth_doc(owner, None, None)?
            };

            URAuthTree::<T>::insert(&bounded_uri, urauth_doc.clone());
            Self::deposit_event(Event::<T>::URAuthTreeRegistered {
                claim_type,
                uri: bounded_uri,
                urauth_doc,
            });

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
        #[pallet::call_index(4)]
        #[pallet::weight(1_000)]
        pub fn add_oracle_member(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
            T::AuthorizedOrigin::ensure_origin(origin)?;

            OracleMembers::<T>::mutate(|m| {
                m.try_push(who).map_err(|_| Error::<T>::MaxOracleMembers)
            })?;

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
        #[pallet::call_index(5)]
        #[pallet::weight(1_000)]
        pub fn kick_oracle_member(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
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
        #[pallet::call_index(6)]
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

        #[pallet::call_index(7)]
        #[pallet::weight(1_000)]
        pub fn add_uri_by_oracle(
            origin: OriginFor<T>,
            uri: Vec<u8>
        ) -> DispatchResult {
            // ToDo: Governance 
            T::AuthorizedOrigin::ensure_origin(origin)?;
            let bounded_uri: URI = uri.try_into().map_err(|_| Error::<T>::OverMaxSize)?;
            URIByOracle::<T>::try_mutate(|uris| -> DispatchResult {
                uris.try_push(bounded_uri.clone()).map_err(|_| Error::<T>::OverMaxSize)?;
                Ok(())
            })?;
            Self::deposit_event(Event::<T>::URIByOracleAdded { uri: bounded_uri });
            Ok(())
        }

        #[pallet::call_index(8)]
        #[pallet::weight(1_000)]
        pub fn remove_uri_by_oracle(
            origin: OriginFor<T>,
            uri: Vec<u8>
        ) -> DispatchResult {
            // ToDo: Governance 
            T::AuthorizedOrigin::ensure_origin(origin)?;
            let bounded_uri: URI = uri.try_into().map_err(|_| Error::<T>::OverMaxSize)?;
            URIByOracle::<T>::try_mutate(|uris| -> DispatchResult {
                let uri = uris.into_iter()
                    .filter(|u| {
                        *u != &bounded_uri
                    })
                    .map(|u| u.clone())
                    .collect::<Vec<URI>>();
                *uris = uri.try_into().map_err(|_| Error::<T>::OverMaxSize)?;
                Ok(())
            })?;
            Self::deposit_event(Event::<T>::URIByOracleRemoved { uri: bounded_uri });
            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    /// 16 bytes uuid based on `URAuthDocCount`
    fn doc_id() -> Result<DocId, DispatchError> {
        let count = Counter::<T>::get();
        Counter::<T>::try_mutate(|c| -> DispatchResult {
            *c = c.checked_add(1).ok_or(Error::<T>::Overflow)?;
            Ok(())
        })?;
        let b = count.to_le_bytes();

        Ok(nuuid::Uuid::from_bytes(b).to_bytes())
    }

    fn unix_time() -> u128 {
        <T as Config>::UnixTime::now().as_millis()
    }

    fn challenge_value() -> Randomness {
        Default::default()
    }

    fn new_urauth_doc(
        owner_did: T::AccountId,
        asset: Option<MultiAsset>,
        data_source: Option<URI>,
    ) -> Result<URAuthDoc<T::AccountId>, DispatchError> {
        let doc_id = Self::doc_id()?;
        Ok(URAuthDoc::new(
            doc_id,
            MultiDID::new(owner_did, 1),
            Self::unix_time(),
            asset,
            data_source,
        ))
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
    ) -> Result<T::AccountId, DispatchError> {
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

        Ok(signer_account_id)
    }

    /// Handle the result of _challenge value_ verification based on `VerificationSubmissionResult`
    fn handle_verification_submission_result(
        res: &VerificationSubmissionResult,
        verification_submission: VerificationSubmission<T>,
        uri: &URI,
        owner_did: T::AccountId,
        claim_type: ClaimType
    ) -> Result<(), DispatchError> {
        match res {
            VerificationSubmissionResult::Complete => {
                let urauth_doc = Self::new_urauth_doc(owner_did, None, None)?;
                URAuthTree::<T>::insert(&uri, urauth_doc.clone());
                Self::remove_all_uri_related(uri.clone());
                Self::deposit_event(Event::<T>::URAuthTreeRegistered {
                    claim_type,
                    uri: uri.clone(),
                    urauth_doc,
                })
            }
            VerificationSubmissionResult::Tie => Self::remove_all_uri_related(uri.clone()),
            VerificationSubmissionResult::InProgress => {
                URIVerificationInfo::<T>::insert(&uri, verification_submission)
            }
        }

        Ok(())
    }

    /// Verify _challenge value_
    ///
    /// 1. Check given signature
    /// 2. Check whether `signer` and `owner` are identical
    /// 3. Check whether `given` challenge value is same with `on-chain` challenge value
    fn try_verify_challenge_value(
        sig: Vec<u8>,
        proof_type: Vec<u8>,
        raw_payload: Vec<u8>,
        uri: &URI,
        owner_did: &OwnerDID,
        challenge: Vec<u8>,
    ) -> Result<(T::AccountId, ClaimType), DispatchError> {
        let multi_sig = Self::raw_signature_to_multi_sig(&proof_type, &sig)?;
        let signer = Self::account_id32_from_raw_did(owner_did.to_vec())?;
        if !multi_sig.verify(&raw_payload[..], &signer) {
            return Err(Error::<T>::BadProof.into());
        }
        let uri_metadata = Metadata::<T>::get(uri).ok_or(Error::<T>::BadRequest)?;
        let signer = Self::account_id_from_source(AccountIdSource::DID(owner_did.to_vec()))?;
        Self::check_is_valid_owner(&uri_metadata.owner_did, &signer)
            .map_err(|_| Error::<T>::BadSigner)?;
        Self::check_challenge_value(uri, challenge)?;
        Ok((signer, uri_metadata.claim_type))
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

    /// Check whether `given` challenge value is same with `on-chain` challenge value
    ///
    /// ## Errors
    ///
    /// `ChallengeValueMissing`
    ///
    /// Challenge value for given _uri_ is not stored
    ///
    /// - `BadChallengeValue`
    ///
    /// Given challenge value and on-chain challenge value are not identical
    fn check_challenge_value(uri: &URI, challenge: Vec<u8>) -> Result<(), DispatchError> {
        let cv = ChallengeValue::<T>::get(&uri).ok_or(Error::<T>::ChallengeValueMissing)?;
        ensure!(challenge == cv.to_vec(), Error::<T>::BadChallengeValue);
        Ok(())
    }

    /// Update the `URAuthDoc` based on `UpdateDocField`.
    /// If it is first time requested, `UpdateStatus` would be `Available`.
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
        uri: URI,
        urauth_doc: &mut URAuthDoc<T::AccountId>,
        update_doc_status: &mut UpdateDocStatus<T::AccountId>,
        update_doc_field: UpdateDocField<T::AccountId>,
    ) -> Result<(), DispatchError> {
        let multi_did = urauth_doc.get_multi_did();
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
        uri: &URI,
        urauth_doc: &URAuthDoc<T::AccountId>,
        proof: Option<Proof>,
    ) -> Result<(AccountId32, Proof), DispatchError> {
        let (owner_did, sig) = match proof.clone().ok_or(Error::<T>::ProofMissing)? {
            Proof::ProofV1 { did, proof } => (did, proof),
        };
        let owner_account = Self::account_id_from_source(AccountIdSource::DID(owner_did.to_vec()))?;
        if !urauth_doc.multi_owner_did.is_owner(&owner_account) {
            return Err(Error::<T>::NotURAuthDocOwner.into());
        }
        let payload = URAuthSignedPayload::<T::AccountId>::Update {
            uri: uri.clone(),
            urauth_doc: urauth_doc.clone(),
            owner_did: owner_did.clone(),
        };
        let signer = Pallet::<T>::account_id32_from_raw_did(owner_did.to_vec())?;
        if !payload.using_encoded(|m| sig.verify(m, &signer)) {
            return Err(Error::<T>::BadProof.into());
        }

        Ok((signer, proof.expect("Already checked!")))
    }

    /// Try to store _updated_urauth_doc_ on `URAuthTree::<T>` based on `URAuthDocStatus`
    fn try_store_updated_urauth_doc(
        signer: AccountId32,
        proof: Proof,
        uri: URI,
        urauth_doc: &mut URAuthDoc<T::AccountId>,
        update_doc_status: &mut UpdateDocStatus<T::AccountId>,
        updated_doc_field: UpdateDocField<T::AccountId>,
    ) -> Result<(), DispatchError> {
        Self::handle_updated_urauth_doc(
            signer,
            proof,
            uri,
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
        Metadata::<T>::remove(&uri);
        URIVerificationInfo::<T>::remove(&uri);
        ChallengeValue::<T>::remove(&uri);

        Self::deposit_event(Event::<T>::Removed { uri })
    }

    /// Try parse the raw-json and return opaque type of
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
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, URI, OwnerDID, Vec<u8>), DispatchError> {
        let json_str = sp_std::str::from_utf8(challenge_value)
            .map_err(|_| Error::<T>::ErrorConvertToString)?;

        return match lite_json::parse_json(json_str) {
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
                    let bounded_uri: URI = uri.try_into().map_err(|_| Error::<T>::OverMaxSize)?;
                    let bounded_owner_did: OwnerDID =
                        owner_did.try_into().map_err(|_| Error::<T>::OverMaxSize)?;
                    URAuthSignedPayload::<T::AccountId>::Challenge {
                        uri: bounded_uri.clone(),
                        owner_did: bounded_owner_did.clone(),
                        challenge: challenge.clone(),
                        timestamp,
                    }
                        .using_encoded(|m| raw_payload = m.to_vec());

                    Ok((
                        proof.to_vec(),
                        proof_type,
                        raw_payload,
                        bounded_uri,
                        bounded_owner_did,
                        challenge,
                    ))
                }
                _ => Err(Error::<T>::BadChallengeValue.into()),
            },
            Err(_) => Err(Error::<T>::BadChallengeValue.into()),
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
