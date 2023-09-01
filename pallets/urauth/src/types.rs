use super::*;

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_runtime::RuntimeDebug;
use sp_std::collections::btree_map::BTreeMap;

pub type DIDWeight = u16;
pub type OwnerDID = Vec<u8>;
pub type DocId = [u8; 16];
pub type DomainName = Vec<u8>;
pub type ApprovalCount = u32;
pub type Threshold = u32;
pub type URAuthDocCount = u128;
pub type RemainingThreshold = u16;

/// Opaque bytes of uri
#[derive(Encode, Decode, Clone, PartialEq, Eq, Default, RuntimeDebug, TypeInfo)]
pub struct URI(pub Vec<u8>);

impl URI {
    pub fn new(raw: Vec<u8>) -> Self {
        Self(raw)
    }

    pub fn inner(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Metadata for verifying challenge value 
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct Metadata {
    pub owner_did: Vec<u8>,
    pub challenge_value: Randomness,
}

impl Metadata {
    pub fn new(owner_did: Vec<u8>, challenge_value: Randomness) -> Self {
        Self {
            owner_did,
            challenge_value,
        }
    }
}

/// Submission detail for verifying challenge value
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct VerificationSubmission<T: Config> {
    pub voters: Vec<T::AccountId>,
    pub status: BTreeMap<H256, ApprovalCount>,
    pub threshold: Threshold,
}

impl<T: Config> Default for VerificationSubmission<T> {
    fn default() -> Self {
        Self {
            voters: Default::default(),
            status: BTreeMap::new(),
            threshold: 1,
        }
    }
}

impl<T: Config> VerificationSubmission<T> {
    /// Submit its verfication info. Threshold will be changed based on _oracle members_.
    /// 
    /// ## Logistics
    /// 1. Update the threshold based on number of _oracle member_.
    /// 2. Check whether given `T::AccountId` has already submitted.
    /// 3. Check whether to end its verification. `self.check_is_end`
    /// 
    /// ## Errors
    /// `AlreadySubmitted`
    pub fn submit(
        &mut self,
        member_count: usize,
        submission: (T::AccountId, H256),
    ) -> Result<VerificationSubmissionResult, DispatchError> {
        self.update_threshold(member_count);
        for acc in self.voters.iter() {
            if &submission.0 == acc {
                return Err(Error::<T>::AlreadySubmitted.into());
            }
        }
        self.voters.push(submission.0);
        Ok(self.check_is_end(member_count, submission.1))
    }

    /// Check whether to finish its verification and return `VerificationSubmissionResult`. 
    fn check_is_end(&mut self, member_count: usize, digest: H256) -> VerificationSubmissionResult {
        let mut is_end = false;
        self.status.entry(digest)
            .and_modify(|v| {
                *v = v.saturating_add(1);
                    if *v >= self.threshold {
                        is_end = true;
                    }
            })
            .or_insert(1);

        if is_end {
            return VerificationSubmissionResult::Complete;
        }

        if self.threshold == 1 {
            VerificationSubmissionResult::Complete
        } else if self.voters.len() == member_count {
            VerificationSubmissionResult::Tie
        } else {
            VerificationSubmissionResult::InProgress
        }
    }

    /// Update the treshold of `VerificationSubmission` based on member count. 
    /// `Threshold = (membmer_count * 3 / 5) + remainder`
    pub fn update_threshold(&mut self, member_count: usize) {
        let threshold = (member_count * 3 / 5) as Threshold;
        let check_sum: Threshold = if (member_count * 3) % 5 == 0 { 0 } else { 1 };
        self.threshold = threshold.saturating_add(check_sum);
    }
}

/// Result state of verifying challenge value
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum VerificationSubmissionResult {
    /// Threshold has not yet reached.
    InProgress,
    /// Number of approval of a challenge value has reached to threshold.
    Complete,
    /// Number of voters and oracle member are same.
    Tie,
}

/// Configuration of challenge value.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct ChallengeValueConfig {
    pub randomness_enabled: bool,
}

impl Default for ChallengeValueConfig {
    fn default() -> Self {
        Self {
            randomness_enabled: false,
        }
    }
}

impl ChallengeValueConfig {
    pub fn randomness_enabled(&self) -> bool {
        self.randomness_enabled
    }
}

/// A payload factory for creating message for verifying its signature.
#[derive(Decode, Clone, PartialEq, Eq)]
pub enum URAuthSignedPayload<Account> {
    Request {
        uri: URI,
        owner_did: OwnerDID,
    },
    Challenge {
        uri: URI,
        owner_did: OwnerDID,
        challenge: Vec<u8>,
        timestamp: Vec<u8>,
    },
    Update {
        urauth_doc: URAuthDoc<Account>,
        owner_did: OwnerDID,
    },
}

impl<Account: Encode> Encode for URAuthSignedPayload<Account> {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        let raw_payload = match self {
            URAuthSignedPayload::Request { uri, owner_did } => (uri, owner_did).encode(),
            URAuthSignedPayload::Challenge {
                uri,
                owner_did,
                challenge,
                timestamp,
            } => (uri, owner_did, challenge, timestamp).encode(),
            URAuthSignedPayload::Update {
                urauth_doc,
                owner_did,
            } => {
                let URAuthDoc {
                    id,
                    uri,
                    created_at,
                    updated_at,
                    multi_owner_did,
                    identity_info,
                    content_metadata,
                    copyright_info,
                    access_rules,
                    ..
                } = urauth_doc;

                (
                    id,
                    uri,
                    created_at,
                    updated_at,
                    multi_owner_did,
                    identity_info,
                    content_metadata,
                    copyright_info,
                    access_rules,
                    owner_did,
                )
                    .encode()
            }
        };
        if raw_payload.len() > 256 {
            f(&sp_io::hashing::blake2_256(&raw_payload)[..])
        } else {
            f(&raw_payload)
        }
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum AccountIdSource {
    DID(Vec<u8>),
    AccountId32(AccountId32),
}

/// DID with its weight
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
pub struct WeightedDID<Account> {
    pub did: Account,
    pub weight: DIDWeight,
}

impl<Account> WeightedDID<Account> {
    pub fn new(acc: Account, weight: DIDWeight) -> Self {
        Self { did: acc, weight }
    }
}

/// Owners of `URAuthDoc`. Its entities can update the doc based on its weight and threshold.
#[derive(Encode, Decode, Clone, PartialEq, Debug, Eq, TypeInfo)]
pub struct MultiDID<Account> {
    pub dids: Vec<WeightedDID<Account>>,
    // Sum(weight) >= threshold
    pub threshold: DIDWeight,
}

impl<Account: PartialEq> MultiDID<Account> {
    pub fn new(acc: Account, weight: DIDWeight) -> Self {
        Self {
            dids: sp_std::vec![WeightedDID::<Account>::new(acc, weight)],
            threshold: weight,
        }
    }

    /// Check whether given account is owner of `URAuthDoc`
    pub fn is_owner(&self, who: &Account) -> bool {
        for weighted_did in self.dids.iter() {
            if &weighted_did.did == who {
                return true;
            }
        }
        false
    }

    pub fn get_threshold(&self) -> DIDWeight {
        self.threshold
    }

    pub fn add_owner(&mut self, weighted_did: WeightedDID<Account>) {
        self.dids.push(weighted_did);
    }

    pub fn get_did_weight(self, who: &Account) -> Option<DIDWeight> {
        if let Some(weighted_did) = self
            .dids
            .into_iter()
            .find(|weighted_did| &weighted_did.did == who)
        {
            return Some(weighted_did.weight);
        }
        None
    }

    /// Get sum of owners' weight
    pub fn total_weight(&self) -> DIDWeight {
        let mut total = 0;
        for did in self.dids.iter() {
            total += did.weight;
        }
        total
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum StorageProvider {
    IPFS,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct ContentAddress {
    storage_provider: StorageProvider,
    cid: Vec<u8>,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum ContentMetadata {
    MetadataV1 { content_address: ContentAddress },
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum CopyrightInfo {
    Text(Vec<u8>),
    CopyrightInfoV1 { content_address: ContentAddress },
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum AccessRule {
    AccessRuleV1 { path: Vec<u8>, rules: Vec<Rule> },
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct UserAgent(pub Vec<u8>);

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct Rule {
    pub user_agents: Vec<UserAgent>,
    pub allow: Vec<(ContentType, Price)>,
    pub disallow: Vec<ContentType>,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum PriceUnit {
    USDPerMb,
    KRWPerMb,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct Price {
    pub price: u64,
    pub decimals: u8,
    pub unit: PriceUnit,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum ContentType {
    Image,
    Video,
    Text,
    Code,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum Proof {
    ProofV1 { did: Vec<u8>, proof: MultiSignature },
}

#[derive(Encode, Decode, Clone, PartialEq, Debug, Eq, TypeInfo)]
pub struct URAuthDoc<Account> {
    pub id: DocId,
    pub uri: URI,
    pub created_at: u128,
    pub updated_at: u128,
    pub multi_owner_did: MultiDID<Account>,
    pub identity_info: Option<Vec<Vec<u8>>>,
    pub content_metadata: Option<ContentMetadata>,
    pub copyright_info: Option<CopyrightInfo>,
    pub access_rules: Option<Vec<AccessRule>>,
    pub proofs: Option<Vec<Proof>>,
}

impl<Account> URAuthDoc<Account>
where
    Account: PartialEq + Clone,
{
    pub fn new(id: DocId, uri: URI, multi_owner_did: MultiDID<Account>, created_at: u128) -> Self {
        Self {
            id,
            uri,
            multi_owner_did,
            created_at,
            updated_at: created_at,
            identity_info: None,
            content_metadata: None,
            copyright_info: None,
            access_rules: None,
            proofs: None,
        }
    }

    pub fn get_threshold(&self) -> DIDWeight {
        self.multi_owner_did.threshold
    }

    pub fn get_uri(&self) -> URI {
        self.uri.clone()
    }

    pub fn get_multi_did(&self) -> MultiDID<Account> {
        self.multi_owner_did.clone()
    }

    pub fn handle_proofs(&mut self, proofs: Option<Vec<Proof>>) {
        self.remove_all_prev_proofs();
        self.proofs = proofs;
    }

    pub fn add_proof(&mut self, proof: Proof) {
        let mut some_proofs = self
            .proofs
            .take()
            .map_or(Default::default(), |proofs| proofs);
        some_proofs.push(proof);
        self.proofs = Some(some_proofs);
    }

    pub fn update_doc(
        &mut self,
        update_doc_field: UpdateDocField<Account>,
        updated_at: u128,
    ) -> Result<(), URAuthDocUpdateError> {
        self.updated_at = updated_at;
        match update_doc_field {
            UpdateDocField::MultiDID(weighted_did) => {
                self.multi_owner_did.add_owner(weighted_did);
            }
            UpdateDocField::Threshold(new) => {
                let total_weight = self.multi_owner_did.total_weight();
                if total_weight < new {
                    return Err(URAuthDocUpdateError::ThreholdError);
                }
                self.multi_owner_did.threshold = new;
            }
            UpdateDocField::IdentityInfo(identity_info) => {
                self.identity_info = identity_info;
            }
            UpdateDocField::ContentMetadata(content_metadata) => {
                self.content_metadata = content_metadata;
            }
            UpdateDocField::CopyrightInfo(copyright_info) => {
                self.copyright_info = copyright_info;
            }
            UpdateDocField::AccessRules(access_rules) => {
                self.access_rules = access_rules;
            }
        };

        Ok(())
    }

    fn remove_all_prev_proofs(&mut self) {
        self.proofs = Some(Vec::new());
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum UpdateDocField<Account> {
    MultiDID(WeightedDID<Account>),
    Threshold(DIDWeight),
    IdentityInfo(Option<Vec<Vec<u8>>>),
    ContentMetadata(Option<ContentMetadata>),
    CopyrightInfo(Option<CopyrightInfo>),
    AccessRules(Option<Vec<AccessRule>>),
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum UpdateStatus<Account> {
    /// Hold updated field and its proofs. Proofs will be stored on `URAuthDoc`
    InProgress {
        field: UpdateDocField<Account>,
        proofs: Option<Vec<Proof>>,
    },
    Available,
}

/// Status for updating `URAuthDoc`
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct UpdateDocStatus<Account> {
    /// Threshold for updating
    pub remaining_threshold: DIDWeight,
    pub status: UpdateStatus<Account>,
}

impl<Account> Default for UpdateDocStatus<Account> {
    fn default() -> Self {
        Self {
            remaining_threshold: Default::default(),
            status: UpdateStatus::Available,
        }
    }
}

impl<Account: Clone> UpdateDocStatus<Account> {
    pub fn is_update_available(&self) -> bool {
        matches!(self.status, UpdateStatus::Available)
    }

    /// Handle on `UpdateStatus::Available`. 
    /// 
    /// 1. Set its _remaining_threshold_ to threshold of `URAuthDoc`
    /// 2. Set its `UpdateStatus` to `UpdateStatus::InProgress`. 
    /// Define its variant to `"to be updated"` field and _proofs_ to be `None`
    pub fn handle_available(
        &mut self,
        threshold: DIDWeight,
        update_doc_field: UpdateDocField<Account>,
    ) {
        self.remaining_threshold = threshold;
        self.status = UpdateStatus::InProgress { field: update_doc_field, proofs: None };
    }

    /// Handle on `UpdateStatus::InProgress`
    /// 
    /// 1. Add proof 
    /// 2. Decrease its threshold with amount of _did_weight_
    /// 
    /// ## Error
    /// `ProofMissing`
    pub fn handle_in_progress(
        &mut self,
        did_weight: DIDWeight,
        update_doc_field: UpdateDocField<Account>,
        proof: Proof,
    ) -> Result<(), UpdateDocStatusError> {
        if let Some(proofs) = self.add_proof(proof) {
            self.calc_remaining_threshold(did_weight);
            self.status = UpdateStatus::InProgress { field: update_doc_field, proofs: Some(proofs) };
        } else {
            return Err(UpdateDocStatusError::ProofMissing.into());
        }

        Ok(())
    }

    /// Get all proofs of `UpdateStatus::InProgress { proofs, ..}`. Otherwise, `None`
    pub fn get_proofs(&self) -> Option<Vec<Proof>> {
        match self.status.clone() {
            UpdateStatus::InProgress { proofs, .. } => proofs,
            _ => None,
        }
    }

    /// Add given proof on `UpdateStatus::InProgress { .. }`. Otherwise, `None`
    fn add_proof(&mut self, proof: Proof) -> Option<Vec<Proof>> {
        let maybe_proofs = match self.status.clone() {
            UpdateStatus::InProgress { proofs, .. } => {
                let mut ps = if let Some(proofs) = proofs {
                    proofs
                } else {
                    Default::default()
                };
                ps.push(proof);
                Some(ps)
            }
            _ => None,
        };
        maybe_proofs
    }

    /// Decrease threshold with amount to _did_weight. 
    fn calc_remaining_threshold(&mut self, did_weight: DIDWeight) {
        self.remaining_threshold = self.remaining_threshold.saturating_sub(did_weight);
    }
}

/// Errors that may happen on update `URAuthDoc`
#[derive(PartialEq, sp_runtime::RuntimeDebug)]
pub enum URAuthDocUpdateError {
    /// Threshold should be less than total weight of owners
    ThreholdError,
}

impl sp_runtime::traits::Printable for URAuthDocUpdateError {
    fn print(&self) {
        "URAuthDocUpdateError".print();
        match self {
            Self::ThreholdError => "GreaterThanTotalWeight".print(),
        }
    }
}

/// Errors that may happen on `UpdateDocStatus`
#[derive(PartialEq, sp_runtime::RuntimeDebug)]
pub enum UpdateDocStatusError {
    /// Proof should be existed on update`URAuthDoc`
    ProofMissing,
}

impl sp_runtime::traits::Printable for UpdateDocStatusError {
    fn print(&self) {
        "UpdateDocStatusError".print();
        match self {
            Self::ProofMissing => "PrrofMissingOnUpdate".print(),
        }
    }
}
