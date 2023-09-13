use core::f64::consts::E;

use super::*;

use codec::{Decode, Encode, MaxEncodedLen};
pub use max_size::*;
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;
use sp_std::collections::btree_map::BTreeMap;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

pub type Rules = Vec<Rule>;
pub type DocId = [u8; 16];
pub type DIDWeight = u16;
pub type ApprovalCount = u32;
pub type Threshold = u32;
pub type URAuthDocCount = u128;

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum ClaimType {
    WebsiteDomain,
    WebServiceAccount,
    File,
    Dataset {
        data_source: Option<Vec<u8>>,
        name: Vec<u8>,
        description: Vec<u8>,
    },
}

impl MaxEncodedLen for ClaimType {
    fn max_encoded_len() -> usize {
        URI::max_encoded_len() + URI::max_encoded_len()
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Debug, Eq, TypeInfo, MaxEncodedLen)]
pub struct DataSetMetadata<BoundedString> {
    name: BoundedString,
    description: BoundedString,
}

impl<BoundedString> DataSetMetadata<BoundedString> {
    pub fn new(name: BoundedString, description: BoundedString) -> Self {
        Self { name, description }
    }
}

/// Metadata for verifying challenge value
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct Metadata {
    pub owner_did: OwnerDID,
    pub challenge_value: Randomness,
}

impl Metadata {
    pub fn new(owner_did: OwnerDID, challenge_value: Randomness) -> Self {
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
        self.status
            .entry(digest)
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
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
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
        uri: URI,
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
                uri,
                urauth_doc,
                owner_did,
            } => {
                let URAuthDoc {
                    id,
                    created_at,
                    updated_at,
                    multi_owner_did,
                    identity_info,
                    content_metadata,
                    copyright_info,
                    access_rules,
                    asset,
                    data_source,
                    ..
                } = urauth_doc;

                (
                    uri,
                    id,
                    created_at,
                    updated_at,
                    multi_owner_did,
                    identity_info,
                    content_metadata,
                    copyright_info,
                    access_rules,
                    asset,
                    data_source,
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

impl<Account> MaxEncodedLen for MultiDID<Account>
where
    Account: Encode + MaxEncodedLen,
{
    fn max_encoded_len() -> usize {
        WeightedDID::<Account>::max_encoded_len() * MAX_OWNER_DID_SIZE as usize
    }
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

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum IdentityInfo {
    IdentityInfoV1 { vc: VerfiableCredential },
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum StorageProvider {
    IPFS,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct ContentAddress {
    storage_provider: StorageProvider,
    cid: URI,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum ContentMetadata {
    MetadataV1 { content_address: ContentAddress },
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum CopyrightInfo {
    Text(AnyText),
    CopyrightInfoV1 { content_address: ContentAddress },
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum AccessRule {
    AccessRuleV1 { path: AnyText, rules: Rules },
}

impl MaxEncodedLen for AccessRule {
    fn max_encoded_len() -> usize {
        AnyText::max_encoded_len() + Rule::max_encoded_len() * MAX_RULES_NUM
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct Rule {
    pub user_agents: Vec<UserAgent>,
    pub allow: Vec<(ContentType, Price)>,
    pub disallow: Vec<ContentType>,
}

impl MaxEncodedLen for Rule {
    fn max_encoded_len() -> usize {
        UserAgent::max_encoded_len() * MAX_USER_AGENTS_NUM
            + (ContentType::max_encoded_len() + Price::max_encoded_len()) * 4
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum PriceUnit {
    USDPerMb,
    KRWPerMb,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct Price {
    pub price: u64,
    pub decimals: u8,
    pub unit: PriceUnit,
}

#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum ContentType {
    #[default]
    All,
    Image,
    Video,
    Text,
    Code,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum Proof {
    ProofV1 {
        did: OwnerDID,
        proof: MultiSignature,
    },
}

#[derive(Encode, Decode, Clone, PartialEq, Debug, Eq, TypeInfo)]
pub struct URAuthDoc<Account> {
    pub id: DocId,
    pub created_at: u128,
    pub updated_at: u128,
    pub multi_owner_did: MultiDID<Account>,
    pub identity_info: Option<Vec<IdentityInfo>>,
    pub content_metadata: Option<ContentMetadata>,
    pub copyright_info: Option<CopyrightInfo>,
    pub access_rules: Option<Vec<AccessRule>>,
    pub asset: Option<MultiAsset>,
    pub data_source: Option<URI>,
    pub proofs: Option<Vec<Proof>>,
}

impl<Account> MaxEncodedLen for URAuthDoc<Account>
where
    Account: Encode + MaxEncodedLen,
{
    fn max_encoded_len() -> usize {
        DocId::max_encoded_len()
            + u128::max_encoded_len()
            + u128::max_encoded_len()
            + MultiDID::<Account>::max_encoded_len()
            + IdentityInfo::max_encoded_len() * MAX_MULTI_OWNERS_NUM
            + AccessRule::max_encoded_len() * MAX_ACCESS_RULES
            + CopyrightInfo::max_encoded_len()
            + ContentMetadata::max_encoded_len()
            + Proof::max_encoded_len() * MAX_MULTI_OWNERS_NUM
            + MultiAsset::max_encoded_len()
            + URI::max_encoded_len()
    }
}

impl<Account> URAuthDoc<Account>
where
    Account: PartialEq + Clone,
{
    pub fn new(
        id: DocId,
        multi_owner_did: MultiDID<Account>,
        created_at: u128,
        asset: Option<MultiAsset>,
        data_source: Option<URI>,
    ) -> Self {
        Self {
            id,
            multi_owner_did,
            created_at,
            updated_at: created_at,
            identity_info: None,
            content_metadata: None,
            copyright_info: None,
            access_rules: None,
            proofs: None,
            asset,
            data_source,
        }
    }

    pub fn get_threshold(&self) -> DIDWeight {
        self.multi_owner_did.threshold
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
    IdentityInfo(Option<Vec<IdentityInfo>>),
    ContentMetadata(Option<ContentMetadata>),
    CopyrightInfo(Option<CopyrightInfo>),
    AccessRules(Option<Vec<AccessRule>>),
}

impl<Account> MaxEncodedLen for UpdateDocField<Account> 
where 
    Account: Encode
{
    fn max_encoded_len() -> usize {
        AccessRule::max_encoded_len() * MAX_ACCESS_RULES
    }
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

impl<Account> MaxEncodedLen for UpdateStatus<Account> 
where
    Account: Encode
{
    fn max_encoded_len() -> usize {
        UpdateDocField::<Account>::max_encoded_len()
            + Proof::max_encoded_len() * MAX_MULTI_OWNERS_NUM
    }
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
        self.status = UpdateStatus::InProgress {
            field: update_doc_field,
            proofs: None,
        };
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
            self.status = UpdateStatus::InProgress {
                field: update_doc_field,
                proofs: Some(proofs),
            };
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

pub trait Parser<T: Config> {

    type ChallengeValue: Default;

    fn root_uri(raw_url: &Vec<u8>) -> Result<URI, DispatchError>;

    fn parent_uris(raw_url: &Vec<u8>) -> Result<Vec<URI>, DispatchError>;

    fn challenge_json() -> Result<Self::ChallengeValue, DispatchError> {
        Ok(Default::default())
    }
}

pub struct URAuthParser;
impl<T: Config> Parser<T> for URAuthParser {

    type ChallengeValue = Vec<u8>;

    fn root_uri(raw_url: &Vec<u8>) -> Result<URI, DispatchError> {
        let maybe_root = sp_std::str::from_utf8(&raw_url[..])
            .map_err(|_| Error::<T>::ErrorConvertToString)?;
        match ada_url::Url::parse(maybe_root, None) {
            Ok(url) => {
                let mut root = url.host();
                let mut protocol: Option<&str> = None;
                if url.scheme_type() != ada_url::SchemeType::Http && 
                    url.scheme_type() != ada_url::SchemeType::Https {
                    protocol = Some(url.protocol());
                }
                let domain = addr::parse_domain_name(root)
                    .map_err(|e| {
                        sp_std::if_std! { println!("{:?}", e) }
                        Error::<T>::ErrorOnParse
                    })?;
                root = domain.root().ok_or(Error::<T>::ErrorOnParse)?;
                if let Some(protocol) = protocol {
                    let mut raw_root: Vec<u8> = Vec::new();
                    raw_root.append(&mut protocol.as_bytes().to_vec());
                    raw_root.append(&mut "//".as_bytes().to_vec());
                    raw_root.append(&mut root.as_bytes().to_vec());
                    return Ok(
                        raw_root.try_into().map_err(|_| Error::<T>::OverMaxSize)?
                    )
                }
                Ok(
                    root
                        .as_bytes()
                        .to_vec()
                        .try_into()
                        .map_err(|_| Error::<T>::OverMaxSize)?
                )
            },
            Err(e) => { 
                sp_std::if_std! { println!("{:?}", e) }
                let mut root = maybe_root;
                match addr::parse_domain_name(root) {
                    Ok(domain) => {
                        root = domain.root().ok_or(Error::<T>::ErrorOnParse)?;
                    },
                    Err(e) => {
                        sp_std::if_std! { println!("{:?}", e) }
                        root = root
                            .split('/')
                            .collect::<Vec<&str>>()
                            .first()
                            .ok_or(Error::<T>::ErrorOnParse)?;
                    }
                }
                Ok(
                    root
                        .as_bytes()
                        .to_vec()
                        .try_into()
                        .map_err(|_| Error::<T>::OverMaxSize)?
                )
            }
        }
    }
    
    fn parent_uris(raw_url: &Vec<u8>) -> Result<Vec<URI>, DispatchError> {
        let input = sp_std::str::from_utf8(raw_url)
            .map_err(|_| Error::<T>::ErrorOnParse)?;
        match ada_url::Url::parse(input, None) {
            Ok(url) => { 

                Ok(Default::default()
            )},
            Err(_) => { Ok(Default::default())}
        }
    }
}

pub mod max_size {

    use super::*;

    /// Maximum number of `URAuthDoc` owners we expect in a single `MultiDID` value. Note this is not (yet)
    /// enforced, and just serves to provide a sensible `max_encoded_len` for `MultiDID`.
    pub const MAX_MULTI_OWNERS_NUM: usize = 5;

    /// Maximum number of `access_rules` we expect in a single `MultiDID` value. Note this is not (yet)
    /// enforced, and just serves to provide a sensible `max_encoded_len` for `MultiDID`.
    pub const MAX_ACCESS_RULES: usize = 100;

    /// Maximum number of `user agents` we expect in a single `MultiDID` value. Note this is not (yet)
    /// enforced, and just serves to provide a sensible `max_encoded_len` for `MultiDID`.
    pub const MAX_USER_AGENTS_NUM: usize = 5;

    /// Maximum number of `rule` we expect in a single `MultiDID` value. Note this is not (yet)
    /// enforced, and just serves to provide a sensible `max_encoded_len` for `MultiDID`.
    pub const MAX_RULES_NUM: usize = 20;

    /// URI is up to 3 KB
    pub const MAX_URI_SIZE: u32 = 3 * 1024;

    pub type URI = BoundedVec<u8, ConstU32<MAX_URI_SIZE>>;

    /// Owner did is up to 64 bytes
    pub const MAX_OWNER_DID_SIZE: u32 = 64;

    pub type OwnerDID = BoundedVec<u8, ConstU32<MAX_OWNER_DID_SIZE>>;

    /// Common size is up to 100 bytes
    pub const MAX_COMMON_SIZE: u32 = 100;

    pub type AnyText = BoundedVec<u8, ConstU32<MAX_COMMON_SIZE>>;

    pub type UserAgent = AnyText;

    /// Encoded size of VC is up to 1 KB.
    pub const MAX_IDENTITY_INFO: u32 = 1024;

    pub type VerfiableCredential = BoundedVec<u8, ConstU32<MAX_IDENTITY_INFO>>;
}
