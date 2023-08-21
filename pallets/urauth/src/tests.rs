pub use super::{VerificationResult, VerificationSubmission};
pub use crate as pallet_urauth;
use frame_support::{parameter_types, traits::Everything};
use sp_core::{H256, ByteArray};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup}, AccountId32,
};

pub type MockBalance = u128;
pub type MockAccountId = u64;
pub type MockBlockNumber = u64;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>} = 1,
        URAuth: pallet_urauth::{Pallet, Call, Storage, Event<T>} = 2,
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

parameter_types! {
    pub const MaxOracleMemembers: u32 = 5;
}

impl pallet_urauth::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Balance = MockBalance;
    type MaxOracleMemembers = MaxOracleMemembers;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap()
        .into()
}

fn find_json_value(
    json_object: lite_json::JsonObject,
    field_name: String,
    sub_field: Option<String>,
) -> Option<String> {
    let sub = sub_field.map_or("".into(), |s| s);
    let (_, json_value) = json_object
        .iter()
        .find(|(field, _)| field.iter().copied().eq(field_name.chars()))
        .unwrap();
    match json_value {
        lite_json::JsonValue::String(v) => Some(v.iter().collect::<String>()),
        lite_json::JsonValue::Object(v) => find_json_value(v.clone(), sub, None),
        _ => None,
    }
}

fn which_sig(sig: String) -> String {
    if sig.contains("ed25519") {
        return "ED25519 SIGNATURE".into();
    } else if sig.contains("sr25519") {
        return "SR25519 SIGNATURE".into();
    } else if sig.contains("ecdsa") {
        return "ECDSA SIGNATURE".into();
    } else {
        return "NONE".into();
    }
}

#[test]
fn json_parse_works() {
    use lite_json::{json_parser::parse_json, JsonValue};
    use sp_std::str::FromStr;
    use bs58;

    let json_string = r#"
        {
            "domain" : "website1.com",
            "adminDID" : "did:infra:ua:5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV",
            "challenge" : "__random_challenge_value__",
            "timestamp": "2023-07-28T10:17:21Z",
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2023-07-28T17:29:31Z",
                "verificationMethod": "did:infra:ua:i3jr3...qW3dt#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "gweEDz58DAdFfa9.....CrfFPP2oumHKtz"
            }
        } 
	"#;
    let json_data = parse_json(json_string).expect("Invalid!");
    let mut domain: String = "".into();
    let mut admin_did: String = "".into();
    let mut challenge: String = "".into();
    let mut timestamp: String = "".into();
    let mut proof_type: String = "".into();
    let mut proof: String = "".into();

    match json_data {
        JsonValue::Object(obj_value) => {
            domain = find_json_value(obj_value.clone(), "domain".into(), None).unwrap();
            admin_did = find_json_value(obj_value.clone(), "adminDID".into(), None).unwrap();
            challenge = find_json_value(obj_value.clone(), "challenge".into(), None).unwrap();
            timestamp = find_json_value(obj_value.clone(), "timestamp".into(), None).unwrap();
            proof_type = find_json_value(obj_value.clone(), "proof".into(), Some("type".into()))
                .unwrap()
                .to_lowercase();
            proof = find_json_value(obj_value.clone(), "proof".into(), Some("proofValue".into()))
                .unwrap();
        }
        _ => {}
    }
    let account_id = account_id_from_did_raw(admin_did.clone().as_bytes().to_vec());
    let mut output = bs58::decode(account_id.clone()).into_vec().unwrap();
    let cut_address_vec: Vec<u8> = output.drain(1..33).collect();
    println!("{:?}", cut_address_vec);
    let mut array = [0u8; 32];
    let bytes = &cut_address_vec[..array.len()];
    array.copy_from_slice(bytes);  
    let account32: AccountId32 = array.into();
    println!("{:?}", account32.as_slice().to_vec());
    println!("Proof type is => {:?}", which_sig(proof_type.clone()));
    println!(
        "도메인 => {:?}, 어드민 => {:?}, 퍼블릭키 => {:?}, 어카운트 아이디 32 => {:?}, 챌린지 => {:?}, 타임스탬프 => {:?}, 프루프 타입 => {:?}, 프루프 => {:?}",
        domain, admin_did, account_id, account32 , challenge, timestamp, proof_type, proof
    );
}

#[test]
fn verification_submission_dynamic_threshold_works() {
    let mut submission: VerificationSubmission<Test> = Default::default();
    submission.update_threshold(1);
    assert_eq!(submission.threshold, 1);
    submission.update_threshold(2);
    assert_eq!(submission.threshold, 2);
    submission.update_threshold(3);
    assert_eq!(submission.threshold, 2);
    submission.update_threshold(4);
    assert_eq!(submission.threshold, 3);
    submission.update_threshold(5);
    assert_eq!(submission.threshold, 3);
}

#[test]
fn verfiication_submission_update_status_works() {
    use sp_runtime::traits::{BlakeTwo256, Hash};

    // Complete
    let mut s1: VerificationSubmission<Test> = Default::default();
    let h1 = BlakeTwo256::hash(&1u32.to_le_bytes());
    s1.submit(3, (1, h1)).unwrap();
    let res = s1.submit(3, (1, h1));
    assert_eq!(
        res,
        Err(sp_runtime::DispatchError::Module(sp_runtime::ModuleError {
            index: 2,
            error: [8, 0, 0, 0],
            message: Some("AlreadySubmitted")
        }))
    );
    println!("{:?}", s1);

    // Tie
    let mut s2: VerificationSubmission<Test> = Default::default();
    let h1 = BlakeTwo256::hash(&1u32.to_le_bytes());
    let h2 = BlakeTwo256::hash(&2u32.to_le_bytes());
    let h3 = BlakeTwo256::hash(&3u32.to_le_bytes());
    let res = s2.submit(3, (1, h1)).unwrap();
    assert_eq!(res, VerificationResult::InProgress);
    let res = s2.submit(3, (2, h2)).unwrap();
    assert_eq!(res, VerificationResult::InProgress);
    let res = s2.submit(3, (3, h3)).unwrap();
    assert_eq!(res, VerificationResult::Tie);

    // 1 member and submit
    let mut s3: VerificationSubmission<Test> = Default::default();
    let h1 = BlakeTwo256::hash(&1u32.to_le_bytes());
    let res = s3.submit(1, (1, h1)).unwrap();
    assert_eq!(res, VerificationResult::Complete);
}

#[test]
fn uuid_works() {
    use nuuid::Uuid;
    let uuid = Uuid::new_v4();
    println!("{:?}", uuid);
}

fn account_id_from_did_raw(mut raw: Vec<u8>) -> Vec<u8> {

    let res: Vec<u8> = raw.drain(raw.len()-48..raw.len()).collect();
    res
}
