pub use crate::{self as pallet_urauth, mock::*, Event as URAuthEvent, *};

use frame_support::{assert_noop, assert_ok};
use sp_keyring::AccountKeyring::*;
use sp_runtime::{traits::BlakeTwo256, AccountId32, MultiSigner};

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

#[test]
fn urauth_request_register_domain_owner_works() {
    let mut urauth_helper = MockURAuthHelper::<MockAccountId>::default(None, None, None, None);
    let (uri, owner_did, _, _) = urauth_helper.deconstruct_urauth_doc();
    let signer = MultiSigner::Sr25519(Alice.public());
    let signature = urauth_helper.create_signature(
        Alice,
        ProofType::Request(
            URI("www.website1.com".into()),
            urauth_helper.raw_owner_did(),
        ),
    );
    new_test_ext().execute_with(|| {
        assert_ok!(URAuth::urauth_request_register_domain_owner(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            owner_did.clone(),
            Some(urauth_helper.challenge_value()),
            signer.clone(),
            signature.clone()
        ));

        let metadata = URIMetadata::<Test>::get(&uri).unwrap();
        assert!(
            String::from_utf8_lossy(&metadata.owner_did) == urauth_helper.owner_did()
                && metadata.challenge_value == urauth_helper.challenge_value()
        );
        System::assert_has_event(URAuthEvent::URAuthRegisterRequested { uri: uri.clone() }.into());

        // Different DID owner with signature should fail
        assert_noop!(
            URAuth::urauth_request_register_domain_owner(
                RuntimeOrigin::signed(Alice.to_account_id()),
                uri.clone(),
                urauth_helper.generate_did(BOB_SS58).as_bytes().to_vec(),
                Some(urauth_helper.challenge_value()),
                signer.clone(),
                signature.clone()
            ),
            Error::<Test>::BadSigner
        );

        let signature2 = urauth_helper.create_signature(
            Alice,
            ProofType::Request(
                URI::new("www.website.com".into()),
                urauth_helper.raw_owner_did(),
            ),
        );

        // Different URI with signature should fail
        assert_noop!(
            URAuth::urauth_request_register_domain_owner(
                RuntimeOrigin::signed(Alice.to_account_id()),
                uri.clone(),
                urauth_helper.raw_owner_did(),
                Some(urauth_helper.challenge_value()),
                signer.clone(),
                signature2
            ),
            Error::<Test>::BadProof
        );

        let signature3 = urauth_helper.create_signature(
            Bob,
            ProofType::Request(
                URI::new("www.website1.com".into()),
                urauth_helper.generate_did(BOB_SS58).as_bytes().to_vec(),
            ),
        );
        assert_noop!(
            URAuth::urauth_request_register_domain_owner(
                RuntimeOrigin::signed(Alice.to_account_id()),
                uri.clone(),
                owner_did,
                Some(urauth_helper.challenge_value()),
                signer.clone(),
                signature3
            ),
            Error::<Test>::BadProof
        );
    });
}

#[test]
fn verify_challenge_works() {
    let mut urauth_helper = MockURAuthHelper::<MockAccountId>::default(None, None, None, None);
    let (uri, owner_did, challenge_value, timestamp) = urauth_helper.deconstruct_urauth_doc();
    let request_sig = urauth_helper.create_signature(
        Alice,
        ProofType::Request(uri.clone(), urauth_helper.raw_owner_did()),
    );
    let challenge_sig = urauth_helper.create_sr25519_signature(
        Alice,
        ProofType::Challenge(uri.clone(), owner_did.clone(), challenge_value, timestamp),
    );
    let challenge_value =
        urauth_helper.generate_json("Sr25519Signature2020".into(), hex::encode(challenge_sig));
    new_test_ext().execute_with(|| {
        assert_ok!(URAuth::add_oracle_member(
            RuntimeOrigin::root(),
            Alice.to_account_id()
        ));

        assert_ok!(URAuth::urauth_request_register_domain_owner(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            owner_did,
            Some(urauth_helper.challenge_value()),
            MultiSigner::Sr25519(Alice.public()),
            request_sig
        ));

        assert_ok!(URAuth::verify_challenge(
            RuntimeOrigin::signed(Alice.to_account_id()),
            challenge_value
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

#[test]
fn update_urauth_doc_works() {
    let mut urauth_helper = MockURAuthHelper::<MockAccountId>::default(None, None, None, None);
    let (uri, owner_did, challenge_value, timestamp) = urauth_helper.deconstruct_urauth_doc();
    let request_sig =
        urauth_helper.create_signature(Alice, ProofType::Request(uri.clone(), owner_did.clone()));
    let challenge_sig = urauth_helper.create_sr25519_signature(
        Alice,
        ProofType::Challenge(
            uri.clone(),
            owner_did.clone(),
            challenge_value.clone(),
            timestamp.clone(),
        ),
    );
    let challenge_value =
        urauth_helper.generate_json("Sr25519Signature2020".into(), hex::encode(challenge_sig));
    new_test_ext().execute_with(|| {
        assert_ok!(URAuth::add_oracle_member(
            RuntimeOrigin::root(),
            Alice.to_account_id()
        ));

        assert_ok!(URAuth::urauth_request_register_domain_owner(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            owner_did.clone(),
            Some(urauth_helper.challenge_value()),
            MultiSigner::Sr25519(Alice.public()),
            request_sig
        ));

        assert_ok!(URAuth::verify_challenge(
            RuntimeOrigin::signed(Alice.to_account_id()),
            challenge_value
        ));

        let mut urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("");
        println!("BEFORE UPDATE");
        println!("");
        println!("{:?}", urauth_doc);

        let update_doc_field = UpdateDocField::AccessRules(Some(vec![AccessRule::AccessRuleV1 {
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
        urauth_doc.update_doc(update_doc_field.clone(), 1).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(urauth_doc.clone(), owner_did.clone()),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            update_doc_field,
            1u128,
            Some(Proof::ProofV1 {
                did: owner_did.clone(),
                proof: update_signature.into()
            })
        ));
        let mut urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("");
        println!("AFTER UPDATE ACCESS RULE");
        println!("");
        println!("{:?}", urauth_doc);

        let update_doc_field = UpdateDocField::MultiDID(WeightedDID {
            did: Bob.to_account_id(),
            weight: 1,
        });
        urauth_doc.update_doc(update_doc_field.clone(), 2).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(urauth_doc.clone(), owner_did.clone()),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            update_doc_field,
            2u128,
            Some(Proof::ProofV1 {
                did: owner_did.clone(),
                proof: update_signature.into()
            })
        ));

        let mut urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("");
        println!("AFTER UPDATE DID OWNERS: ADD BOB");
        println!("");
        println!("{:?}", urauth_doc);

        let update_doc_field = UpdateDocField::<MockAccountId>::Threshold(2);
        urauth_doc.update_doc(update_doc_field.clone(), 3).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(urauth_doc.clone(), owner_did.clone()),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            update_doc_field,
            3u128,
            Some(Proof::ProofV1 {
                did: owner_did.clone(),
                proof: update_signature.into()
            })
        ));

        let mut urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("");
        println!("AFTER UPDATE THRESOLD: FROM 1 TO 2");
        println!("");
        println!("{:?}", urauth_doc);

        let update_doc_field = UpdateDocField::MultiDID(WeightedDID {
            did: Charlie.to_account_id(),
            weight: 1,
        });
        urauth_doc.update_doc(update_doc_field.clone(), 4).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(urauth_doc.clone(), owner_did.clone()),
        );
        let ura_update_proof = Proof::ProofV1 {
            did: owner_did.clone(),
            proof: update_signature.clone().into(),
        };
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            update_doc_field,
            4,
            Some(Proof::ProofV1 {
                did: owner_did.clone(),
                proof: update_signature.into()
            })
        ));

        println!(
            "URAUTHDOC UPDATE STATUS => {:?}",
            URAuthDocUpdateStatus::<Test>::get(&urauth_doc.id)
        );
        System::assert_has_event(
            URAuthEvent::UpdateInProgress {
                urauth_doc: urauth_doc.clone(),
                update_doc_status: UpdateDocStatus {
                    remaining_threshold: 1,
                    status: UpdateStatus::InProgress {
                        field: UpdateDocField::MultiDID(WeightedDID {
                            did: Charlie.to_account_id(),
                            weight: 1,
                        }),
                        proofs: Some(vec![ura_update_proof]),
                    },
                },
            }
            .into(),
        );

        // Since threhold is 2, URAUTH Document has not been updated.
        // Bob should sign for update.
        let mut urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("Document => {:?}", urauth_doc);
        let update_doc_field = UpdateDocField::MultiDID(WeightedDID {
            did: Charlie.to_account_id(),
            weight: 1,
        });
        urauth_doc.update_doc(update_doc_field.clone(), 4).unwrap();
        let bob_did = urauth_helper.generate_did(BOB_SS58);
        let update_signature = urauth_helper.create_sr25519_signature(
            Bob,
            ProofType::Update(urauth_doc.clone(), bob_did.as_bytes().to_vec()),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Bob.to_account_id()),
            uri.clone(),
            update_doc_field,
            4,
            Some(Proof::ProofV1 {
                did: bob_did.as_bytes().to_vec(),
                proof: update_signature.into()
            })
        ));

        let urauth_doc = URAuthTree::<Test>::get(&uri).unwrap();
        println!("{:?}", urauth_doc);
        let proofs = urauth_doc.clone().proofs.unwrap();
        for proof in proofs {
            match proof {
                Proof::ProofV1 { did, .. } => {
                    println!("{:?}", String::from_utf8_lossy(&did));
                }
            }
        }
        assert!(urauth_doc.clone().proofs.unwrap().len() == 2);
        println!("");
        println!("AFTER UPDATE DID OWNERS: ADD CHARILE");
        println!("");
        println!("{:?}", urauth_doc);
    });
}

#[test]
fn verify_challenge_with_multiple_oracle_members() {
    let mut urauth_helper = MockURAuthHelper::<MockAccountId>::default(None, None, None, None);
    let (uri, owner_did, challenge_value, timestamp) = urauth_helper.deconstruct_urauth_doc();
    let request_sig =
        urauth_helper.create_signature(Alice, ProofType::Request(uri.clone(), owner_did.clone()));
    let challenge_sig = urauth_helper.create_sr25519_signature(
        Alice,
        ProofType::Challenge(
            uri.clone(),
            owner_did.clone(),
            challenge_value.clone(),
            timestamp.clone(),
        ),
    );
    let challenge_value =
        urauth_helper.generate_json("Sr25519Signature2020".into(), hex::encode(challenge_sig));

    new_test_ext().execute_with(|| {
        assert_ok!(URAuth::add_oracle_member(
            RuntimeOrigin::root(),
            Alice.to_account_id()
        ));
        assert_ok!(URAuth::add_oracle_member(
            RuntimeOrigin::root(),
            Bob.to_account_id()
        ));
        assert_ok!(URAuth::add_oracle_member(
            RuntimeOrigin::root(),
            Charlie.to_account_id()
        ));
        assert!(OracleMembers::<Test>::get().len() == 3);

        assert_ok!(URAuth::urauth_request_register_domain_owner(
            RuntimeOrigin::signed(Alice.to_account_id()),
            uri.clone(),
            owner_did.clone(),
            Some(urauth_helper.challenge_value()),
            MultiSigner::Sr25519(Alice.public()),
            request_sig
        ));

        assert_ok!(URAuth::verify_challenge(
            RuntimeOrigin::signed(Alice.to_account_id()),
            challenge_value.clone()
        ));

        System::assert_has_event(
            URAuthEvent::VerificationInfo {
                uri: uri.clone(),
                progress_status: VerificationSubmissionResult::InProgress,
            }
            .into(),
        );

        assert_noop!(
            URAuth::verify_challenge(
                RuntimeOrigin::signed(Dave.to_account_id()),
                challenge_value.clone()
            ),
            Error::<Test>::NotOracleMember
        );

        assert_ok!(URAuth::verify_challenge(
            RuntimeOrigin::signed(Bob.to_account_id()),
            challenge_value
        ));

        System::assert_has_event(
            URAuthEvent::VerificationInfo {
                uri: uri.clone(),
                progress_status: VerificationSubmissionResult::Complete,
            }
            .into(),
        );
    })
}
