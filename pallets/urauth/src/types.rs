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

#[derive(Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum URAuthSignedPayload<T: Config> {
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
        urauth_doc: URAuthDoc<T>,
        updated_at: u128,
        owner_did: OwnerDID,
    },
}

impl<T: Config> Encode for URAuthSignedPayload<T> {
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
                updated_at,
                owner_did,
            } => (urauth_doc, updated_at, owner_did).encode(),
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
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct MultiDID<Account> {
    dids: Vec<WeightedDID<Account>>,
    // Sum(weight) >= threshold
    threshold: DIDWeight,
}

impl<Account: PartialEq> MultiDID<Account> {
    pub fn new(acc: Account, weight: DIDWeight) -> Self {
        Self {
            dids: sp_std::vec![WeightedDID::<Account>::new(acc, weight)],
            threshold: weight,
        }
    }

    pub fn add_owner(&mut self, weighted_did: WeightedDID<Account>) {
        self.dids.push(weighted_did);
    }

    pub fn get_did_weight(self, who: &Account) -> Option<DIDWeight> {
        if let Some(weighted_did) = self.dids.into_iter().find(|weighted_did| {
            &weighted_did.did == who
        }) {
            return Some(weighted_did.weight)
        }
        None
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
    AccessRuleV1 {
        path: Vec<u8>,
        rules: Vec<Rule>,
    },
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct UserAgent(Vec<u8>);

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct Rule {
    user_agents: Vec<UserAgent>,                     
    allow: Vec<(ContentType, Price)>, 
    disallow: Vec<ContentType>,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum PriceUnit {
    USDPerMb,
    KRWPerMb
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct Price {
    pub price: u64,
    pub decimals: u8,
    pub unit: PriceUnit
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

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebugNoBound, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct URAuthDoc<T: Config> {
    id: DocId,
    uri: URI,
    created_at: u128,
    updated_at: u128,
    multi_owner_did: MultiDID<T::AccountId>,
    identity_info: Option<Vec<Vec<u8>>>,
    content_metadata: Option<ContentMetadata>,
    copyright_info: Option<CopyrightInfo>,
    access_rules: Option<Vec<AccessRule>>,
    proofs: Option<Vec<Proof>>,
}

impl<T: Config> URAuthDoc<T> {
    pub fn new(id: DocId, uri: URI, multi_owner_did: MultiDID<T::AccountId>, created_at: u128) -> Self {
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

    fn get_uri(&self) -> URI {
        self.uri.clone()
    }

    fn get_multi_did(&self) -> MultiDID<T::AccountId> {
        self.multi_owner_did.clone()
    }

    pub fn try_update_doc(&mut self, field: UpdateDocField<T::AccountId>, updated_at: u128, proof: Option<Proof>) -> Result<(), DispatchError> {

        let (owner_did, sig) = match proof.ok_or(Error::<T>::ProofMissing)? {
            Proof::ProofV1 { did, proof } => (did, proof)
        };

        let urauth_doc = match field.clone() {
            UpdateDocField::MultiDID(weighted_did) => {
                self.multi_owner_did.add_owner(weighted_did);
                self
            },
            UpdateDocField::IdentityInfo(identity_info) => { 
                self.identity_info = identity_info;
                self
            },
            UpdateDocField::ContentMetadata(content_metadata) => { 
                self.content_metadata = content_metadata;
                self
            },
            UpdateDocField::CopyrightInfo(copyright_info) => { 
                self.copyright_info = copyright_info;
                self
            },
            UpdateDocField::AccessRules(access_rules) => {
                self.access_rules = access_rules;
                self
            }
        };
        let payload = URAuthSignedPayload::<T>::Update { urauth_doc: urauth_doc.clone(), updated_at, owner_did: owner_did.clone() };
        let signer = Pallet::<T>::account_id32_from_raw_did(owner_did)?;
        if !payload.using_encoded(|m| sig.verify(m, &signer)) {
            return Err(Error::<T>::BadProof.into())
        }
        let multi_did = urauth_doc.get_multi_did();
        let mut remaining = UpdateDocStatus::<T>::get(&urauth_doc.id).map_or(multi_did.threshold, |v| v);
        let uri = urauth_doc.get_uri();
        let account_id = Pallet::<T>::account_id_from_source(AccountIdSource::AccountId32(signer))?;
        let did_weight = multi_did.get_did_weight(&account_id).ok_or(Error::<T>::AccountMissing)?;
        if did_weight >= remaining {
            URAuthTree::<T>::insert(&uri, urauth_doc.clone());
            UpdateDocStatus::<T>::remove(&urauth_doc.id);
            Pallet::<T>::deposit_event(Event::<T>::URAuthDocUpdated { updated_field: field, urauth_doc: urauth_doc.clone() })
        } else {
            remaining = remaining.saturating_sub(did_weight);
            UpdateDocStatus::<T>::insert(&urauth_doc.id, remaining);
        }
        Ok(())
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum UpdateDocField<Account> {
    MultiDID(WeightedDID<Account>),
    IdentityInfo(Option<Vec<Vec<u8>>>),
    ContentMetadata(Option<ContentMetadata>),
    CopyrightInfo(Option<CopyrightInfo>),
    AccessRules(Option<Vec<AccessRule>>)
}
