use super::*;

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
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

#[derive(Encode, Decode, Clone, PartialEq, Eq, Default, RuntimeDebug, MaxEncodedLen, TypeInfo)]
pub enum Status {
    #[default]
    Requested,
    Verfied,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Default, RuntimeDebug, TypeInfo)]
pub struct URI(Vec<u8>);

impl URI {
    pub fn new(raw: Vec<u8>) -> Self {
        Self(raw)
    }

    pub fn inner(&self) -> Vec<u8> {
        self.0.clone()
    }
}

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

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct VerificationSubmission<T: Config> {
    pub submission: Vec<(T::AccountId, H256)>,
    pub threshold: Threshold,
}

impl<T: Config> Default for VerificationSubmission<T> {
    fn default() -> Self {
        Self {
            submission: Default::default(),
            threshold: 1,
        }
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum VerificationResult {
    InProgress,
    Complete,
    Tie,
}

impl<T: Config> VerificationSubmission<T> {
    pub fn submit(
        &mut self,
        member_count: usize,
        submission: (T::AccountId, H256),
    ) -> Result<VerificationResult, DispatchError> {
        self.update_threshold(member_count);
        for (acc, _) in self.submission.iter() {
            if &submission.0 == acc {
                return Err(Error::<T>::AlreadySubmitted.into());
            }
        }
        self.submission.push(submission);
        Ok(self.check_is_end(member_count))
    }

    fn check_is_end(&self, member_count: usize) -> VerificationResult {
        let mut map: BTreeMap<H256, ApprovalCount> = BTreeMap::new();
        let mut is_end = false;
        for (_, c) in self.submission.iter() {
            map.entry(*c)
                .and_modify(|v| {
                    *v = v.saturating_add(1);
                    if *v >= self.threshold {
                        is_end = true;
                    }
                })
                .or_insert(1);
        }

        if is_end {
            return VerificationResult::Complete;
        }

        if self.threshold == 1 {
            VerificationResult::Complete
        } else if self.submission.len() == member_count {
            VerificationResult::Tie
        } else {
            VerificationResult::InProgress
        }
    }

    pub fn update_threshold(&mut self, member_count: usize) {
        let threshold = (member_count * 3 / 5) as Threshold;
        let check_sum: Threshold = if (member_count * 3) % 5 == 0 { 0 } else { 1 };
        self.threshold = threshold.saturating_add(check_sum);
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct ChallengeValueConfig {
    pub is_calc_enabled: bool,
}

impl Default for ChallengeValueConfig {
    fn default() -> Self {
        Self {
            is_calc_enabled: false,
        }
    }
}

impl ChallengeValueConfig {
    pub fn is_calc_enabled(&self) -> bool {
        self.is_calc_enabled
    }

    pub fn set_is_calc_enabled(&mut self, enabled: bool) {
        self.is_calc_enabled = enabled;
    }
}

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
// Multisig-enabled DID
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

    pub fn is_owner(&self, who: &Account) -> bool {
        for weighted_did in self.dids.iter() {
            if &weighted_did.did == who {
                return true
            }
        }
        false
    }

    pub fn get_threshold(&self) -> DIDWeight {
        self.threshold
    }

    pub fn set_threshold(&mut self, new: DIDWeight) {
        self.threshold = new;
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
    proofs: Option<Vec<Proof>>,
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

    pub fn get_uri(&self) -> URI {
        self.uri.clone()
    }

    pub fn get_multi_did(&self) -> MultiDID<Account> {
        self.multi_owner_did.clone()
    }

    pub fn remove_all_proofs(&mut self) {
        self.proofs = Some(Vec::new());
    }

    fn check_valid_updated_at(&self, now: u128) -> bool {
        let prev = self.updated_at;
        sp_std::if_std! {println!("prev {:?} now {:?}", prev, now)}
        prev <= now
    }

    pub fn update_doc(
        &mut self,
        update_field: &UpdateDocField<Account>,
        updated_at: Option<u128>,
    ) -> Result<DIDWeight, URAuthDocUpdateError> {
        if !matches!(update_field, UpdateDocField::Proof(_)) {
            if let Some(now) = updated_at {
                if !self.check_valid_updated_at(now) {
                    return Err(URAuthDocUpdateError::InvalidUpdate)
                }
                self.updated_at = now;
            } else {
                return Err(URAuthDocUpdateError::UpdatedAtMissing);
            }
        }
        let current_threshold = self.multi_owner_did.get_threshold();
        match update_field.clone() {
            UpdateDocField::MultiDID(weighted_did) => {
                self.multi_owner_did.add_owner(weighted_did);
            }
            UpdateDocField::Threshold(new) => {
                let total_weight = self.multi_owner_did.total_weight();
                if total_weight < new {
                    return Err(URAuthDocUpdateError::ThreholdError);
                }
                self.multi_owner_did.set_threshold(new);
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
            UpdateDocField::Proof(proof) => {
                let mut updated = self
                    .proofs
                    .take()
                    .map_or(Default::default(), |proofs| proofs);
                updated.push(proof);
                self.proofs = Some(updated);
            }
        };

        Ok(current_threshold)
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
    Proof(Proof),
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct UpdateDocStatus {
    pub remaining_threshold: DIDWeight,
    pub status: UpdateStatus
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum UpdateStatus {
    InProgress,
    Available
}

impl UpdateDocStatus {
    pub fn default(threshold: DIDWeight) -> Self {
        Self {
            remaining_threshold: threshold,
            status: UpdateStatus::Available
        }
    }

    pub fn is_update_available(&self) -> bool {
        matches!(self.status, UpdateStatus::Available)
    }

    pub fn calc_remaining_threshold(&mut self, did_weight: DIDWeight) {
        self.remaining_threshold = self.remaining_threshold.saturating_sub(did_weight);
    }

    pub fn set_status(&mut self, status: UpdateStatus) {
        self.status = status;
    }
}

/// Errors that may happen on offence reports.
#[derive(PartialEq, sp_runtime::RuntimeDebug)]
pub enum URAuthDocUpdateError {
    UpdatedAtMissing,
    ThreholdError,
    InvalidUpdate,
}

impl sp_runtime::traits::Printable for URAuthDocUpdateError {
    fn print(&self) {
        "URAuthDocUpdateError".print();
        match self {
            Self::UpdatedAtMissing => "UpdatedAtMissing".print(),
            Self::ThreholdError => "GreaterThanTotalWeight".print(),
            Self::InvalidUpdate => "InvalidUpdatedAt".print()
        }
    }
}
