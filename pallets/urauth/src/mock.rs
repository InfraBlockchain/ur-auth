
pub use crate::{self as pallet_urauth, *};
use frame_support::{parameter_types, traits::Everything};
use frame_system::EnsureRoot;
use sp_core::H256;
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
    AccountId32,
};

pub type MockBalance = u128;
pub type MockAccountId = AccountId32;
pub type MockBlockNumber = u64;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

pub const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
pub const BOB_SS58: &str = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";

frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>} = 1,
        Timestamp: pallet_timestamp::{Pallet, Call, Storage} = 2,
        URAuth: pallet_urauth::{Pallet, Call, Storage, Event<T>} = 99,
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const SS58Prefix: u8 = 42;
}

impl frame_system::Config for Test {
    type BaseCallFilter = Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Index = u64;
    type BlockNumber = MockBlockNumber;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = MockAccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = SS58Prefix;
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = frame_support::traits::ConstU64<5>;
    type WeightInfo = ();
}

parameter_types! {
    pub const MaxOracleMemembers: u32 = 5;
}

impl pallet_urauth::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type UnixTime = Timestamp;
    type MaxOracleMemembers = MaxOracleMemembers;
    type AuthorizedOrigin = EnsureRoot<MockAccountId>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1)); // For 'Event'
    ext
}

pub struct ExtBuilder {
    pub oracle_member_count: u32,
}

pub struct MockURAuthHelper<Account: Encode> {
    pub mock_doc_manager: MockURAuthDocManager,
    pub mock_pnv_manager: MockPnVManager<Account>,
}

pub enum ProofType<Account: Encode> {
    Request(URI, OwnerDID),
    Challenge(URI, OwnerDID, Vec<u8>, Vec<u8>),
    Update(URAuthDoc<Account>, Vec<u8>)
}

pub struct MockPnVManager<Account: Encode> {
    pub proof_type: ProofType<Account>
}

impl<Account: Encode> MockPnVManager<Account> {

    pub fn set_proof_type(&mut self, proof_type: ProofType<Account>) {
        self.proof_type = proof_type;
    }

    pub fn raw_payload(&self) -> Vec<u8> {

        match &self.proof_type {
            ProofType::Request(uri, owner_did) => {
                (uri, owner_did).encode()
            },
            ProofType::Challenge(uri, owner_did, challenge, timestamp) => {    
                (uri, owner_did, challenge, timestamp).encode()
            },
            ProofType::Update(urauth_doc, owner_did) => {
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
        }
    }

    pub fn create_signature(&self, signer: sp_keyring::AccountKeyring) -> MultiSignature {
        let raw_payload = self.raw_payload();
        let sig = signer.sign(&raw_payload);
        sig.into()
    }

    fn verify() {}
}

pub struct MockURAuthDocManager {
    pub uri: String,
    pub owner_did: String,
    pub challenge_value: String,
    pub timestamp: String,
    pub proof_type: String,
    pub proof: String,
}

impl MockURAuthDocManager {

    pub fn to_uri(&self) -> URI {
        URI(self.uri.as_bytes().to_vec())
    }

    pub fn new(uri: String, account_id: String, challenge_value: String, timestamp: String, proof_type: String, proof: String) -> Self {
        let owner_did = MockURAuthDocManager::generate_did(account_id.as_str());
        Self {
            uri,
            owner_did,
            challenge_value,
            timestamp,
            proof_type,
            proof
        }
    }

    fn generate_did(account_id: &str) -> String {
        format!("{}{}", "did:infra:ua:", account_id)
    }

    pub fn generate_json(
        &self
    ) -> String {
        use lite_json::Serialize;
    
        let mut object_elements = vec![];
    
        let object_key = "domain".chars().collect();
        object_elements.push((
            object_key,
            lite_json::JsonValue::String(self.uri.chars().collect()),
        ));
    
        let object_key = "adminDID".chars().collect();
        object_elements.push((
            object_key,
            lite_json::JsonValue::String(self.owner_did.chars().collect()),
        ));
    
        let object_key = "challenge".chars().collect();
        object_elements.push((
            object_key,
            lite_json::JsonValue::String(self.challenge_value.chars().collect()),
        ));
    
        let object_key = "timestamp".chars().collect();
        object_elements.push((
            object_key,
            lite_json::JsonValue::String(self.timestamp.chars().collect()),
        ));
    
        let mut proof_object = vec![];
        let object_key = "type".chars().collect();
        proof_object.push((
            object_key,
            lite_json::JsonValue::String(self.proof_type.chars().collect()),
        ));
    
        let object_key = "proofValue".chars().collect();
        proof_object.push((
            object_key,
            lite_json::JsonValue::String(self.proof.chars().collect()),
        ));
    
        let object_key = "proof".chars().collect();
        object_elements.push((object_key, lite_json::JsonValue::Object(proof_object)));
    
        let object_value = lite_json::JsonValue::Object(object_elements);
    
        // Convert the object to a JSON string.
        let json = object_value.format(4);
        let json_output = std::str::from_utf8(&json).unwrap();
    
        json_output.to_string()
    }
}

impl ExtBuilder {
    fn build(self) -> sp_io::TestExternalities {
        let storage = frame_system::GenesisConfig::default()
            .build_storage::<Test>()
            .unwrap();
        let mut ext = sp_io::TestExternalities::from(storage);
        ext.execute_with(|| System::set_block_number(1));
        ext
    }

    pub fn build_and_execute(self, test: impl FnOnce() -> ()) {
        let mut ext = self.build();
        ext.execute_with(test);
    }
}


