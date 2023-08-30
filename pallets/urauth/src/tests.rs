pub use super::*;
pub use crate::{self as pallet_urauth, Event as URAuthEvent, *};
use frame_support::{assert_noop, assert_ok, parameter_types, traits::Everything};
use frame_system::EnsureRoot;
use sp_core::H256;
use sp_keyring::AccountKeyring::*;
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
    AccountId32, MultiSignature, MultiSigner,
};

pub type MockBalance = u128;
pub type MockAccountId = AccountId32;
pub type MockBlockNumber = u64;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
const BOB_SS58: &str = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";
// const ALICE_SIG: &str = "686c98752ecc7dccac8d36fc6c6e6440a40c9b6c1d829603712e1be35a5dc82bfa77c78c0a696619ce42060f66cdd860e517e00e8277db82417f3aed17941983";
// const ALICE_CHALLENGE_VALUE: &str = "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]";

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

fn find_json_value(
    json_object: lite_json::JsonObject,
    field_name: &str,
    sub_field: Option<&str>,
) -> Option<Vec<u8>> {
    let sub = sub_field.map_or("".into(), |s| s);
    let (_, json_value) = json_object
        .iter()
        .find(|(field, _)| field.iter().copied().eq(field_name.chars()))
        .unwrap();
    match json_value {
        lite_json::JsonValue::String(v) => Some(v.iter().map(|c| *c as u8).collect::<Vec<u8>>()),
        lite_json::JsonValue::Object(v) => find_json_value(v.clone(), sub, None),
        _ => None,
    }
}

fn account_id_from_did_raw(mut raw: Vec<u8>) -> AccountId32 {
    let actual_owner_did: Vec<u8> = raw.drain(raw.len() - 48..raw.len()).collect();
    let mut output = bs58::decode(actual_owner_did).into_vec().unwrap();
    let temp: Vec<u8> = output.drain(1..33).collect();
    let mut raw_account_id = [0u8; 32];
    let buf = &temp[..raw_account_id.len()];
    raw_account_id.copy_from_slice(buf);
    raw_account_id.into()
}

#[test]
fn json_parse_works() {
    use lite_json::{json_parser::parse_json, JsonValue};

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
    let mut domain: Vec<u8> = vec![];
    let mut admin_did: Vec<u8> = vec![];
    let mut challenge: Vec<u8> = vec![];
    let mut timestamp: Vec<u8> = vec![];
    let mut proof_type: Vec<u8> = vec![];
    let mut proof: Vec<u8> = vec![];

    match json_data {
        JsonValue::Object(obj_value) => {
            domain = find_json_value(obj_value.clone(), "domain", None).unwrap();
            admin_did = find_json_value(obj_value.clone(), "adminDID", None).unwrap();
            challenge = find_json_value(obj_value.clone(), "challenge", None).unwrap();
            timestamp = find_json_value(obj_value.clone(), "timestamp", None).unwrap();
            proof_type = find_json_value(obj_value.clone(), "proof", Some("type")).unwrap();
            proof = find_json_value(obj_value.clone(), "proof".into(), Some("proofValue")).unwrap();
        }
        _ => {}
    }
    assert!(domain == "website1.com".as_bytes().to_vec());
    assert!(
        admin_did
            == "did:infra:ua:5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV"
                .as_bytes()
                .to_vec()
    );
    assert!(challenge == "__random_challenge_value__".as_bytes().to_vec());
    assert!(timestamp == "2023-07-28T10:17:21Z".as_bytes().to_vec());
    assert!(proof_type == "Ed25519Signature2020".as_bytes().to_vec());
    assert!(proof == "gweEDz58DAdFfa9.....CrfFPP2oumHKtz".as_bytes().to_vec());
    let account_id32 = account_id_from_did_raw(admin_did);
    println!("AccountId32 => {:?}", account_id32);
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
    // Complete
    let mut s1: VerificationSubmission<Test> = Default::default();
    let h1 = BlakeTwo256::hash(&1u32.to_le_bytes());
    s1.submit(3, (Alice.to_account_id(), h1)).unwrap();
    let res = s1.submit(3, (Alice.to_account_id(), h1));
    assert_eq!(
        res,
        Err(sp_runtime::DispatchError::Module(sp_runtime::ModuleError {
            index: 2,
            error: [13, 0, 0, 0],
            message: Some("AlreadySubmitted")
        }))
    );
    println!("{:?}", s1);

    // Tie
    let mut s2: VerificationSubmission<Test> = Default::default();
    let h1 = BlakeTwo256::hash(&1u32.to_le_bytes());
    let h2 = BlakeTwo256::hash(&2u32.to_le_bytes());
    let h3 = BlakeTwo256::hash(&3u32.to_le_bytes());
    let res = s2.submit(3, (Alice.to_account_id(), h1)).unwrap();
    assert_eq!(res, VerificationSubmissionResult::InProgress);
    let res = s2.submit(3, (Bob.to_account_id(), h2)).unwrap();
    assert_eq!(res, VerificationSubmissionResult::InProgress);
    let res = s2.submit(3, (Charlie.to_account_id(), h3)).unwrap();
    assert_eq!(res, VerificationSubmissionResult::Tie);

    // 1 member and submit
    let mut s3: VerificationSubmission<Test> = Default::default();
    let h1 = BlakeTwo256::hash(&1u32.to_le_bytes());
    let res = s3.submit(1, (Alice.to_account_id(), h1)).unwrap();
    assert_eq!(res, VerificationSubmissionResult::Complete);
}

pub enum SigType {
    URI(String, String),
    Challenge(URI, String, String, String),
}

fn create_signature(keyring: sp_keyring::AccountKeyring, sig_type: SigType) -> MultiSignature {
    let msg = match sig_type {
        SigType::URI(uri, did) => {
            let raw_uri = uri.as_bytes().to_vec();
            let raw_did = did.as_bytes().to_vec();

            (raw_uri, raw_did).encode()
        }
        SigType::Challenge(uri, owner_did, challenge, timestamp) => {
            let raw_did = owner_did.as_bytes().to_vec();
            let raw_challenge = challenge.as_bytes().to_vec();
            let raw_timestamp = timestamp.as_bytes().to_vec();

            (uri, raw_did, raw_challenge, raw_timestamp).encode()
        }
    };

    let sig = keyring.sign(&msg);
    sig.into()
}

fn generate_did(account_id: &str) -> String {
    format!("{}{}", "did:infra:ua:", account_id)
}

#[test]
fn sig_works() {
    let sig = create_signature(
        Alice,
        SigType::URI("www.website1.com".into(), generate_did(ALICE_SS58)),
    );
    let msg = (
        "www.website1.com".as_bytes().to_vec(),
        generate_did(ALICE_SS58),
    )
        .encode();
    let _ = create_signature(
        Alice,
        SigType::Challenge(
            URI::new("www.website1.com".as_bytes().to_vec()), 
            "did:infra:ua:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".into(), 
            "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]".into(), 
            "2023-07-28T10:17:21Z".into()
        )
    );
    assert!(sig.verify(&msg[..], &Alice.to_account_id()));
}

#[test]
fn urauth_request_register_domain_owner_works() {
    let uri = URI::new("www.website1.com".as_bytes().to_vec());
    let owner_did = generate_did(ALICE_SS58);
    let challenge_value = Some(Randomness::default());
    let signer = MultiSigner::Sr25519(Alice.public());
    let signature = create_signature(
        Alice,
        SigType::URI("www.website1.com".into(), generate_did(ALICE_SS58)),
    );
    new_test_ext().execute_with(|| {
        assert_ok!(URAuth::urauth_request_register_domain_owner(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            owner_did.as_bytes().to_vec(),
            challenge_value.clone(),
            signer.clone(),
            signature.clone()
        ));

        let metadata = URIMetadata::<Test>::get(&uri).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&metadata.owner_did),
            generate_did(ALICE_SS58)
        );
        assert_eq!(metadata.challenge_value, Randomness::default());
        println!("{:?}", String::from_utf8_lossy(&metadata.owner_did));
        System::assert_has_event(URAuthEvent::URAuthRegisterRequested { uri: uri.clone() }.into());

        assert_noop!(
            URAuth::urauth_request_register_domain_owner(
                RuntimeOrigin::signed(Alice.to_account_id()),
                uri.clone(),
                generate_did(BOB_SS58).as_bytes().to_vec(),
                challenge_value.clone(),
                signer.clone(),
                signature.clone()
            ),
            Error::<Test>::BadSigner
        );

        let signature2 = create_signature(
            Alice,
            SigType::URI("www.website.com".into(), generate_did(ALICE_SS58)),
        );

        assert_noop!(
            URAuth::urauth_request_register_domain_owner(
                RuntimeOrigin::signed(Alice.to_account_id()),
                uri.clone(),
                owner_did.as_bytes().to_vec(),
                challenge_value.clone(),
                signer.clone(),
                signature2
            ),
            Error::<Test>::BadProof
        );

        let signature3 = create_signature(
            Alice,
            SigType::URI("www.website1.com".into(), generate_did(BOB_SS58)),
        );
        assert_noop!(
            URAuth::urauth_request_register_domain_owner(
                RuntimeOrigin::signed(Alice.to_account_id()),
                uri.clone(),
                owner_did.as_bytes().to_vec(),
                challenge_value.clone(),
                signer.clone(),
                signature3
            ),
            Error::<Test>::BadProof
        );
    });
}

#[test]
fn verify_challenge_works() {
    let uri = URI::new("www.website1.com".into());
    let owner_did = generate_did(ALICE_SS58);
    let challenge_value = "E40Bzg8kAvOIjswwxc29WaQCHuOKwoZC";
    let timestamp = "2023-07-28T10:17:21Z";
    let msg = (
        uri.clone(),
        owner_did.as_bytes().to_vec(),
        challenge_value.as_bytes().to_vec(),
        timestamp.as_bytes().to_vec(),
    )
        .encode();
    let sig = Alice.sign(&msg);
    let request_signature = create_signature(
        Alice,
        SigType::URI("www.website1.com".into(), generate_did(ALICE_SS58)),
    );

    let json_str = generate_json(
        "www.website1.com".into(),
        owner_did.clone(),
        challenge_value.into(),
        timestamp.into(),
        "Sr25519Signature2020".into(),
        hex::encode(sig).clone(),
    );
    println!("{:?}", json_str);
    new_test_ext().execute_with(|| {
        assert_ok!(URAuth::add_oracle_member(
            RuntimeOrigin::root(),
            Alice.to_account_id()
        ));

        assert_ok!(URAuth::urauth_request_register_domain_owner(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            owner_did.as_bytes().to_vec(),
            Some(challenge_value.as_bytes().to_vec()[..].try_into().unwrap()),
            MultiSigner::Sr25519(Alice.public()),
            request_signature
        ));

        assert_ok!(URAuth::verify_challenge(
            RuntimeOrigin::signed(Alice.to_account_id()),
            json_str.as_bytes().to_vec()
        ));

        System::assert_has_event(
            URAuthEvent::<Test>::VerificationInfo {
                uri: uri.clone(),
                progress_status: VerificationSubmissionResult::Complete,
            }
            .into(),
        );
        let urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("{:?}", urauth_doc);
    });
}

fn generate_json(
    domain: String,
    owner_did: String,
    challenge_value: String,
    timestamp: String,
    proof_type: String,
    proof: String,
) -> String {
    use lite_json::Serialize;

    let mut object_elements = vec![];

    let object_key = "domain".chars().collect();
    object_elements.push((
        object_key,
        lite_json::JsonValue::String(domain.chars().collect()),
    ));

    let object_key = "adminDID".chars().collect();
    object_elements.push((
        object_key,
        lite_json::JsonValue::String(owner_did.chars().collect()),
    ));

    let object_key = "challenge".chars().collect();
    object_elements.push((
        object_key,
        lite_json::JsonValue::String(challenge_value.chars().collect()),
    ));

    let object_key = "timestamp".chars().collect();
    object_elements.push((
        object_key,
        lite_json::JsonValue::String(timestamp.chars().collect()),
    ));

    let mut proof_object = vec![];
    let object_key = "type".chars().collect();
    proof_object.push((
        object_key,
        lite_json::JsonValue::String(proof_type.chars().collect()),
    ));

    let object_key = "proofValue".chars().collect();
    proof_object.push((
        object_key,
        lite_json::JsonValue::String(proof.chars().collect()),
    ));

    let object_key = "proof".chars().collect();
    object_elements.push((object_key, lite_json::JsonValue::Object(proof_object)));

    let object_value = lite_json::JsonValue::Object(object_elements);

    // Convert the object to a JSON string.
    let json = object_value.format(4);
    let json_output = std::str::from_utf8(&json).unwrap();

    json_output.to_string()
}

#[test]
fn uuid_works() {
    use nuuid::Uuid;

    let uuid = Uuid::from_bytes([0; 16]);
    println!("{:?}", uuid);
}

#[test]
fn fixed_str_works() {
    use fixedstr::*;
    let str1 = zstr::<8>::from("ABCD");
    let str1_string = str1.to_str();
    println!("{:?}", str1_string);
    let str1_to_lower = str1.to_ascii_lower();
    println!("{:?}", str1_to_lower.to_str());

    let proof_type: &str = "Ed25519Signature2020";
    let raw = proof_type.as_bytes().to_vec();
    let len = raw.len();
    println!("{:?}", len);
}

#[test]
fn update_urauth_doc_works() {
    let uri = URI::new("www.website1.com".into());
    let owner_did = generate_did(ALICE_SS58);
    let challenge_value = "E40Bzg8kAvOIjswwxc29WaQCHuOKwoZC";
    let timestamp = "2023-07-28T10:17:21Z";
    let msg = (
        uri.clone(),
        owner_did.as_bytes().to_vec(),
        challenge_value.as_bytes().to_vec(),
        timestamp.as_bytes().to_vec(),
    )
        .encode();
    let sig = Alice.sign(&msg);
    let request_signature = create_signature(
        Alice,
        SigType::URI("www.website1.com".into(), generate_did(ALICE_SS58)),
    );

    let json_str = generate_json(
        "www.website1.com".into(),
        owner_did.clone(),
        challenge_value.into(),
        timestamp.into(),
        "Sr25519Signature2020".into(),
        hex::encode(sig).clone(),
    );
    new_test_ext().execute_with(|| {
        assert_ok!(URAuth::add_oracle_member(
            RuntimeOrigin::root(),
            Alice.to_account_id()
        ));

        assert_ok!(URAuth::urauth_request_register_domain_owner(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            owner_did.as_bytes().to_vec(),
            Some(challenge_value.as_bytes().to_vec()[..].try_into().unwrap()),
            MultiSigner::Sr25519(Alice.public()),
            request_signature
        ));

        assert_ok!(URAuth::verify_challenge(
            RuntimeOrigin::signed(Alice.to_account_id()),
            json_str.as_bytes().to_vec()
        ));
        let mut urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("{:?}", urauth_doc);
        let mut update_doc_status = URAuthDocUpdateStatus::<Test>::get(&urauth_doc.id);
        let update_field = UpdateDocField::AccessRules(Some(vec![AccessRule::AccessRuleV1 {
            path: "/raf".as_bytes().to_vec(),
            rules: vec![Rule {
                user_agents: vec![UserAgent("GPTBOT".as_bytes().to_vec())],
                allow: vec![(
                    ContentType::Image,
                    Price {
                        price: 100,
                        decimals: 4,
                        unit: PriceUnit::USDPerMb,
                    },
                )],
                disallow: vec![ContentType::Video, ContentType::Code],
            }],
        }]));
        urauth_doc
            .update_doc(&mut update_doc_status, &update_field, 1)
            .unwrap();
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
        } = urauth_doc.clone();
        let payload = (
            id,
            uri.clone(),
            created_at,
            updated_at,
            multi_owner_did,
            identity_info,
            content_metadata,
            copyright_info,
            access_rules,
            owner_did.as_bytes().to_vec(),
        )
            .encode();
        let proof = Alice.sign(&payload[..]);
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            update_field,
            1u128,
            Some(Proof::ProofV1 {
                did: owner_did.as_bytes().to_vec(),
                proof: proof.into()
            })
        ));
        let mut urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("Updated Access Rule => {:?}", urauth_doc);

        let update_field = UpdateDocField::MultiDID(WeightedDID {
            did: Bob.to_account_id(),
            weight: 1,
        });
        let mut update_doc_status = URAuthDocUpdateStatus::<Test>::get(&urauth_doc.id);
        urauth_doc
            .update_doc(&mut update_doc_status, &update_field, 2)
            .unwrap();
        let payload = create_urauth_doc_payload(urauth_doc, owner_did.clone());
        let proof = Alice.sign(&payload[..]);
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            update_field,
            2u128,
            Some(Proof::ProofV1 {
                did: owner_did.as_bytes().to_vec(),
                proof: proof.into()
            })
        ));

        let mut urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("Updated DIDs => {:?}", urauth_doc);

        let update_field = UpdateDocField::Threshold(2);
        let mut update_doc_status = URAuthDocUpdateStatus::<Test>::get(&urauth_doc.id);
        urauth_doc
            .update_doc(&mut update_doc_status, &update_field, 3)
            .unwrap();
        let payload = create_urauth_doc_payload(urauth_doc, owner_did.clone());
        let proof = Alice.sign(&payload[..]);
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            update_field,
            3u128,
            Some(Proof::ProofV1 {
                did: owner_did.as_bytes().to_vec(),
                proof: proof.into()
            })
        ));

        let mut urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("Updated Threshold => {:?}", urauth_doc);

        let update_field = UpdateDocField::MultiDID(WeightedDID {
            did: Charlie.to_account_id(),
            weight: 1,
        });
        let mut update_doc_status = URAuthDocUpdateStatus::<Test>::get(&urauth_doc.id);
        println!("UpdateDocStatus => {:?}", update_doc_status);
        urauth_doc
            .update_doc(&mut update_doc_status, &update_field, 4)
            .unwrap();
        let payload = create_urauth_doc_payload(urauth_doc.clone(), owner_did.clone());
        let proof = Alice.sign(&payload[..]);
        let ura_proof = Proof::ProofV1 {
            did: owner_did.as_bytes().to_vec(),
            proof: proof.clone().into(),
        };
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            update_field,
            4,
            Some(Proof::ProofV1 {
                did: owner_did.as_bytes().to_vec(),
                proof: proof.into()
            })
        ));

        urauth_doc.add_proof(ura_proof);
        System::assert_has_event(
            URAuthEvent::UpdateInProgress {
                urauth_doc: urauth_doc.clone(),
                update_doc_status: UpdateDocStatus {
                    remaining_threshold: 1,
                    status: UpdateStatus::InProgress(UpdateDocField::MultiDID(WeightedDID {
                        did: Charlie.to_account_id(),
                        weight: 1,
                    })),
                },
            }
            .into(),
        );

        let mut urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("Updated Threshold => {:?}", urauth_doc);

        let update_field = UpdateDocField::MultiDID(WeightedDID {
            did: Charlie.to_account_id(),
            weight: 1,
        });
        let mut update_doc_status = URAuthDocUpdateStatus::<Test>::get(&urauth_doc.id);
        println!("UpdateDocStatus => {:?}", update_doc_status);
        urauth_doc
            .update_doc(&mut update_doc_status, &update_field, 4)
            .unwrap();
        let bob_did = generate_did(BOB_SS58);
        let payload = create_urauth_doc_payload(urauth_doc.clone(), bob_did.clone());
        let proof = Bob.sign(&payload[..]);
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Bob.to_account_id()),
            uri.clone(),
            update_field,
            4,
            Some(Proof::ProofV1 {
                did: bob_did.as_bytes().to_vec(),
                proof: proof.into()
            })
        ));

        let urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("Updated Threshold => {:?}", urauth_doc);
        assert!(URAuthDocUpdateStatus::<Test>::get(&urauth_doc.id) == Default::default())
    });
}

fn create_urauth_doc_payload(urauth_doc: URAuthDoc<MockAccountId>, owner_did: String) -> Vec<u8> {
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
    } = urauth_doc.clone();
    let raw = (
        id,
        uri.clone(),
        created_at,
        updated_at,
        multi_owner_did,
        identity_info,
        content_metadata,
        copyright_info,
        access_rules,
        owner_did.as_bytes().to_vec(),
    )
        .encode();
    if raw.len() > 256 {
        sp_io::hashing::blake2_256(&raw).to_vec()
    } else {
        raw
    }
}
