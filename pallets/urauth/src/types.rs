
use super::*;

use codec::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

pub type DIDWeight = u16;
pub type OwnerDID = Vec<u8>;
pub type DocId = Vec<u8>;
pub type DomainName = Vec<u8>;
pub type ApprovalCount = u32;
pub type Threshold = u32;

#[derive(Encode, Decode, Clone, PartialEq, Eq, Default, RuntimeDebug, MaxEncodedLen, TypeInfo)]
pub enum Status {
    #[default]
    Requested,
    Verfied
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
pub struct DID<Account> {
    pub did: Account,
    pub weight: DIDWeight,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct URI(Vec<u8>);

impl URI {
    pub fn inner(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct Metadata {
    pub uri: Vec<u8>,
    pub owner_did: Vec<u8>,
    pub challenge_value: Randomness,
}

impl Metadata {
    pub fn new(uri: Vec<u8>, owner_did: Vec<u8>, challenge_value: Randomness) -> Self {
        Self {
            uri, owner_did, challenge_value
        }
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct ChallengeValueConfig {
    pub is_calc_enabled: bool,
    pub challenge_value_fields: Vec<ChallengeValueField>,
}

impl Default for ChallengeValueConfig {
    fn default() -> Self {
        Self {
            is_calc_enabled: false,
            challenge_value_fields: [ChallengeValueField::URI, ChallengeValueField::OwnerDID, ChallengeValueField::Challenge, ChallengeValueField::Timestamp, ChallengeValueField::Proof].to_vec()
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

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
pub enum ChallengeValueField {
    URI,
    OwnerDID,
    Challenge,
    Timestamp,
    Proof
}

impl From<ChallengeValueField> for String {
    fn from(value: ChallengeValueField) -> Self {
        match value {
            ChallengeValueField::URI => "domain".into(),
            ChallengeValueField::OwnerDID => "ownerDID".into(),
            ChallengeValueField::Challenge => "challenge".into(),
            ChallengeValueField::Timestamp => "timestamp".into(),
            ChallengeValueField::Proof => "proof".into()
        }
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
    path: Vec<u8>, // e.g "/public"
    rules: Vec<Rule<Balance>>, 
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct UserAgent(Vec<u8>);

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct Rule<Balance> {
    user_agents: Vec<UserAgent>, // e.g "GPTBot"
    allow: Vec<(ContentType, Balance, ContentSize)>, // e.g (Image, 1DUSD/MB)
    disallow: Vec<ContentType>,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum ContentSize {
    Mega,
    Giga
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