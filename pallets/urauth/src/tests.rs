pub use crate::{self as pallet_urauth, mock::*, Event as URAuthEvent, *};

use frame_support::{assert_noop, assert_ok, debug};
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
fn urauth_request_register_ownership_works() {
    let mut urauth_helper = MockURAuthHelper::<MockAccountId>::default(None, None, None, None);
    let (uri, owner_did, _, _) = urauth_helper.deconstruct_urauth_doc(None);
    let bounded_uri = urauth_helper.bounded_uri(None);
    let signer = MultiSigner::Sr25519(Alice.public());
    let signature = urauth_helper.create_signature(
        Alice,
        ProofType::Request(
            urauth_helper.bounded_uri(None),
            urauth_helper.raw_owner_did(),
        ),
    );
    new_test_ext().execute_with(|| {
        assert_ok!(URAuth::urauth_request_register_ownership(
            RuntimeOrigin::signed(Alice.to_account_id()),
            "www.website1.com".as_bytes().to_vec(),
            owner_did.clone(),
            Some(urauth_helper.challenge_value()),
            signer.clone(),
            signature.clone()
        ));
        let metadata = URIMetadata::<Test>::get(&bounded_uri).unwrap();
        assert!(
            String::from_utf8_lossy(&metadata.owner_did) == urauth_helper.owner_did()
                && metadata.challenge_value == urauth_helper.challenge_value()
        );
        System::assert_has_event(
            URAuthEvent::URAuthRegisterRequested {
                uri: bounded_uri.clone(),
            }
            .into(),
        );

        // Different DID owner with signature should fail
        assert_noop!(
            URAuth::urauth_request_register_ownership(
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
                urauth_helper.bounded_uri(Some("www.website.com".into())),
                urauth_helper.raw_owner_did(),
            ),
        );

        // Different URI with signature should fail
        assert_noop!(
            URAuth::urauth_request_register_ownership(
                RuntimeOrigin::signed(Alice.to_account_id()),
                uri.clone(),
                owner_did.clone(),
                Some(urauth_helper.challenge_value()),
                signer.clone(),
                signature2
            ),
            Error::<Test>::BadProof
        );

        let signature3 = urauth_helper.create_signature(
            Bob,
            ProofType::Request(
                bounded_uri.clone(),
                urauth_helper
                    .generate_did(BOB_SS58)
                    .as_bytes()
                    .to_vec()
                    .try_into()
                    .expect("Too long"),
            ),
        );
        assert_noop!(
            URAuth::urauth_request_register_ownership(
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
    let (uri, owner_did, challenge_value, timestamp) = urauth_helper.deconstruct_urauth_doc(None);
    let bounded_uri = urauth_helper.bounded_uri(None);
    let bounded_owner_did = urauth_helper.raw_owner_did();
    let request_sig = urauth_helper.create_signature(
        Alice,
        ProofType::Request(bounded_uri.clone(), urauth_helper.raw_owner_did()),
    );
    let challenge_sig = urauth_helper.create_sr25519_signature(
        Alice,
        ProofType::Challenge(
            bounded_uri.clone(),
            bounded_owner_did.clone(),
            challenge_value,
            timestamp,
        ),
    );
    let challenge_value =
        urauth_helper.generate_json("Sr25519Signature2020".into(), hex::encode(challenge_sig));
    new_test_ext().execute_with(|| {
        assert_ok!(URAuth::add_oracle_member(
            RuntimeOrigin::root(),
            Alice.to_account_id()
        ));

        assert_ok!(URAuth::urauth_request_register_ownership(
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
                uri: bounded_uri.clone(),
                progress_status: VerificationSubmissionResult::Complete,
            }
            .into(),
        );
        let urauth_doc = URAuthTree::<Test>::get(&bounded_uri).unwrap();
        debug_doc(&urauth_doc);
    });
}

#[test]
fn update_urauth_doc_works() {
    let mut urauth_helper = MockURAuthHelper::<MockAccountId>::default(None, None, None, None);
    let (uri, owner_did, challenge_value, timestamp) = urauth_helper.deconstruct_urauth_doc(None);
    let bounded_uri = urauth_helper.bounded_uri(None);
    let bounded_owner_did = urauth_helper.raw_owner_did();
    let request_sig = urauth_helper.create_signature(
        Alice,
        ProofType::Request(bounded_uri.clone(), bounded_owner_did.clone()),
    );
    let challenge_sig = urauth_helper.create_sr25519_signature(
        Alice,
        ProofType::Challenge(
            bounded_uri.clone(),
            bounded_owner_did.clone(),
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

        assert_ok!(URAuth::urauth_request_register_ownership(
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

        let mut urauth_doc = URAuthTree::<Test>::get(&bounded_uri).unwrap();
        debug_doc(&urauth_doc);

        let update_doc_field = UpdateDocField::AccessRules(None);
        urauth_doc.update_doc(update_doc_field.clone(), 1).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(
                bounded_uri.clone(),
                urauth_doc.clone(),
                bounded_owner_did.clone(),
            ),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            bounded_uri.clone(),
            update_doc_field,
            1u128,
            Some(Proof::ProofV1 {
                did: bounded_owner_did.clone(),
                proof: update_signature.into()
            })
        ));

        let update_doc_field = UpdateDocField::AccessRules(Some(vec![AccessRule::AccessRuleV1 {
            path: "/raf".as_bytes().to_vec().try_into().expect("Too long!"),
            rules: vec![Rule {
                user_agents: vec!["GPTBOT".as_bytes().to_vec().try_into().expect("Too long")],
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
        urauth_doc.update_doc(update_doc_field.clone(), 2).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(
                bounded_uri.clone(),
                urauth_doc.clone(),
                bounded_owner_did.clone(),
            ),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            bounded_uri.clone(),
            update_doc_field,
            2u128,
            Some(Proof::ProofV1 {
                did: bounded_owner_did.clone(),
                proof: update_signature.into()
            })
        ));
        let mut urauth_doc = URAuthTree::<Test>::get(&bounded_uri).unwrap();
        debug_doc(&urauth_doc);

        let update_doc_field = UpdateDocField::MultiDID(WeightedDID {
            did: Bob.to_account_id(),
            weight: 1,
        });
        urauth_doc.update_doc(update_doc_field.clone(), 3).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(
                bounded_uri.clone(),
                urauth_doc.clone(),
                bounded_owner_did.clone(),
            ),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            bounded_uri.clone(),
            update_doc_field,
            3u128,
            Some(Proof::ProofV1 {
                did: bounded_owner_did.clone(),
                proof: update_signature.into()
            })
        ));

        let mut urauth_doc = URAuthTree::<Test>::get(&bounded_uri).unwrap();
        debug_doc(&urauth_doc);

        let update_doc_field = UpdateDocField::<MockAccountId>::Threshold(2);
        urauth_doc.update_doc(update_doc_field.clone(), 4).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(
                bounded_uri.clone(),
                urauth_doc.clone(),
                bounded_owner_did.clone(),
            ),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            bounded_uri.clone(),
            update_doc_field,
            4u128,
            Some(Proof::ProofV1 {
                did: bounded_owner_did.clone(),
                proof: update_signature.into()
            })
        ));

        let mut urauth_doc = URAuthTree::<Test>::get(&bounded_uri).unwrap();
        debug_doc(&urauth_doc);

        let update_doc_field = UpdateDocField::MultiDID(WeightedDID {
            did: Charlie.to_account_id(),
            weight: 1,
        });
        urauth_doc.update_doc(update_doc_field.clone(), 5).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(
                bounded_uri.clone(),
                urauth_doc.clone(),
                bounded_owner_did.clone(),
            ),
        );
        let ura_update_proof = Proof::ProofV1 {
            did: bounded_owner_did.clone(),
            proof: update_signature.clone().into(),
        };
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            bounded_uri.clone(),
            update_doc_field,
            5,
            Some(Proof::ProofV1 {
                did: bounded_owner_did.clone(),
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
        let mut urauth_doc = URAuthTree::<Test>::get(&bounded_uri).unwrap();

        let update_doc_field = UpdateDocField::MultiDID(WeightedDID {
            did: Charlie.to_account_id(),
            weight: 1,
        });
        urauth_doc.update_doc(update_doc_field.clone(), 5).unwrap();
        let bob_did: OwnerDID = urauth_helper
            .generate_did(BOB_SS58)
            .as_bytes()
            .to_vec()
            .try_into()
            .expect("Too long");
        let update_signature = urauth_helper.create_sr25519_signature(
            Bob,
            ProofType::Update(bounded_uri.clone(), urauth_doc.clone(), bob_did.clone()),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Bob.to_account_id()),
            bounded_uri.clone(),
            update_doc_field,
            5,
            Some(Proof::ProofV1 {
                did: bob_did,
                proof: update_signature.into()
            })
        ));

        let urauth_doc = URAuthTree::<Test>::get(&bounded_uri).unwrap();
        debug_doc(&urauth_doc);
        let proofs = urauth_doc.clone().proofs.unwrap();
        for proof in proofs {
            match proof {
                Proof::ProofV1 { did, .. } => {
                    println!("{:?}", String::from_utf8_lossy(&did));
                }
            }
        }
        assert!(urauth_doc.clone().proofs.unwrap().len() == 2);
        debug_doc(&urauth_doc);
    });
}

#[test]
fn verify_challenge_with_multiple_oracle_members() {
    let mut urauth_helper = MockURAuthHelper::<MockAccountId>::default(None, None, None, None);
    let (uri, owner_did, challenge_value, timestamp) = urauth_helper.deconstruct_urauth_doc(None);
    let bounded_uri = urauth_helper.bounded_uri(None);
    let bounded_owner_did = urauth_helper.raw_owner_did();
    let request_sig = urauth_helper.create_signature(
        Alice,
        ProofType::Request(bounded_uri.clone(), bounded_owner_did.clone()),
    );
    let challenge_sig = urauth_helper.create_sr25519_signature(
        Alice,
        ProofType::Challenge(
            bounded_uri.clone(),
            bounded_owner_did.clone(),
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

        assert_ok!(URAuth::urauth_request_register_ownership(
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
                uri: bounded_uri.clone(),
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
                uri: bounded_uri.clone(),
                progress_status: VerificationSubmissionResult::Complete,
            }
            .into(),
        );
    })
}

#[test]
fn claim_file_ownership_works() {
    new_test_ext().execute_with(|| {
        let mut urauth_helper = MockURAuthHelper::<AccountId32>::default(None, None, None, None);
        let (_, owner_did, _, _) = urauth_helper.deconstruct_urauth_doc(None);
        let bounded_uri = urauth_helper.bounded_uri(Some("urauth://file".into()));
        let bounded_owner_did = urauth_helper.raw_owner_did();
        let request_sig = urauth_helper.create_signature(
            Alice,
            ProofType::Request(bounded_uri.clone(), bounded_owner_did.clone()),
        );
        assert_ok!(URAuth::claim_ownership(
            RuntimeOrigin::signed(Alice.to_account_id()),
            ClaimType::File,
            "urauth://file".into(),
            owner_did,
            MultiSigner::Sr25519(Alice.public()),
            request_sig
        ));
        let urauth_doc = URAuthTree::<Test>::get(&bounded_uri);
        println!("{:?}", urauth_doc);
        println!(
            "Size of URAUTH DOCUMENT => {:?} bytes",
            urauth_doc.encode().len()
        );
    })
}

#[test]
fn register_dataset_works() {
    new_test_ext().execute_with(|| {
        let mut urauth_helper = MockURAuthHelper::<AccountId32>::default(None, None, None, None);
        let (_, owner_did, _, _) = urauth_helper.deconstruct_urauth_doc(None);
        let bounded_uri = urauth_helper.bounded_uri(Some("urauth://file".into()));
        let bounded_owner_did = urauth_helper.raw_owner_did();
        let request_sig = urauth_helper.create_signature(
            Alice,
            ProofType::Request(bounded_uri.clone(), bounded_owner_did.clone()),
        );

        assert_ok!(URAuth::claim_ownership(
            RuntimeOrigin::signed(Alice.to_account_id()),
            ClaimType::Dataset {
                data_source: Some("ipfs://{SHA256}".into()),
                name: "".into(),
                description: "".into()
            },
            "urauth://file".into(),
            owner_did,
            MultiSigner::Sr25519(Alice.public()),
            request_sig,
        ));

        let urauth_doc = URAuthTree::<Test>::get(&bounded_uri);
        println!("{:?}", urauth_doc);
        println!(
            "Size of URAUTH DOCUMENT is {:?} b",
            urauth_doc.encode().len() as f32
        );
    })
}

#[test]
fn max_encoded_len() {
    println!("{:?}", IdentityInfo::max_encoded_len());
    println!("{:?}", Rule::max_encoded_len());
    println!("{:?}", AccessRule::max_encoded_len());
    println!(
        "MAX URAUTH DOCUMENT SIZE is {:?} MB",
        URAuthDoc::<AccountId32>::max_encoded_len() as f32 / 1_000_000f32
    );
}

#[test]
fn parse_string_works() {
    use ada_url::Url;
    use addr::parse_domain_name;

    let u = Url::parse("http://sub2.sub1.instagram.com/coco/post", None)
        .expect("bad url");
    let host = u.host();
    println!("Host => {:?}", host);
    let all_path = u.pathname().split('/').collect::<Vec<&str>>();
    let all_path = all_path.into_iter().filter(|p| p.len() != 0).collect::<Vec<&str>>();
    println!("All path => {:?}", all_path);
    let domain_name = parse_domain_name(u.hostname()).expect("Bad URL");
    if domain_name.prefix().is_some() {
        let prefix = domain_name.prefix().expect("Checked!");
        let prefix = prefix.split(['.']).collect::<Vec<&str>>();
        println!(" Prefix => {:?}", prefix);
    }
    println!("Root domain => {:?}", domain_name.root().expect("No Root"));
}

#[test]
fn parser_works() {
    parse_and_check_root("https://instagram.com", "instagram.com");
    parse_and_check_root("https://www.instagram.com", "instagram.com");
    parse_and_check_root("https://sub2.sub1.www.instagram.com", "instagram.com");
    parse_and_check_root("www.instagram.com", "instagram.com");
    parse_and_check_root("instagram.com", "instagram.com");
    parse_and_check_root("instagram.com/user", "instagram.com");
    parse_and_check_root("instagram.com/user/challenge.json", "instagram.com");
    parse_and_check_root("ftp://sub2.sub1.www.instagram.com", "ftp://instagram.com");
    parse_and_check_root("smtp://sub2.sub1.www.instagram.com", "smtp://instagram.com");
}

fn parse_and_check_root(url: &str, expect: &str) {
    let urauth_helper = MockURAuthHelper::<AccountId32>::default(None, None, None, None);
    let url: String = url.into();
    let raw_url: Vec<u8> = url.clone().into();
    let root_uri = <URAuthParser as Parser<Test>>::root_uri(&raw_url).unwrap();
    assert!(root_uri == urauth_helper.bounded_uri(Some(expect.into())));
}
