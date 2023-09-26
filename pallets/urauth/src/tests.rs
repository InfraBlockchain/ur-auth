pub use crate::{self as pallet_urauth, mock::*, Event as URAuthEvent, *};

use frame_support::{assert_noop, assert_ok};
use sp_keyring::AccountKeyring::*;
use sp_runtime::{AccountId32, MultiSigner};

#[test]
fn request_register_ownership_works() {
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
        assert_ok!(URAuth::add_uri_by_oracle(
            RuntimeOrigin::root(),
            ClaimType::WebsiteDomain,
            URIRequestType::Oracle { is_root: true },
            "https://www.website1.com".into()
        ));

        assert_ok!(URAuth::request_register_ownership(
            RuntimeOrigin::signed(Alice.to_account_id()),
            ClaimType::WebsiteDomain,
            "www.website1.com".as_bytes().to_vec(),
            URIRequestType::Oracle { is_root: true },
            owner_did.clone(),
            Some(urauth_helper.challenge_value()),
            signer.clone(),
            signature.clone()
        ));
        let metadata = Metadata::<Test>::get(&bounded_uri).unwrap();
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
            URAuth::request_register_ownership(
                RuntimeOrigin::signed(Alice.to_account_id()),
                ClaimType::WebsiteDomain,
                uri.clone(),
                URIRequestType::Oracle { is_root: true },
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
            URAuth::request_register_ownership(
                RuntimeOrigin::signed(Alice.to_account_id()),
                ClaimType::WebsiteDomain,
                uri.clone(),
                URIRequestType::Oracle { is_root: true },
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
            URAuth::request_register_ownership(
                RuntimeOrigin::signed(Alice.to_account_id()),
                ClaimType::WebsiteDomain,
                uri.clone(),
                URIRequestType::Oracle { is_root: true },
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

        assert_ok!(URAuth::request_register_ownership(
            RuntimeOrigin::signed(Alice.to_account_id()),
            ClaimType::WebsiteDomain,
            uri.clone(),
            URIRequestType::Oracle { is_root: true },
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

        assert_ok!(URAuth::request_register_ownership(
            RuntimeOrigin::signed(Alice.to_account_id()),
            ClaimType::WebsiteDomain,
            uri.clone(),
            URIRequestType::Oracle { is_root: true },
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

        assert_ok!(URAuth::request_register_ownership(
            RuntimeOrigin::signed(Alice.to_account_id()),
            ClaimType::WebsiteDomain,
            uri.clone(),
            URIRequestType::Oracle { is_root: true },
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
            URIRequestType::Any {
                maybe_parent_acc: Alice.to_account_id()
            },
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
            "urauth://dataset/{CID}".into(),
            URIRequestType::Any {
                maybe_parent_acc: Alice.to_account_id()
            },
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
fn integrity_test() {
    let mut urauth_helper = MockURAuthHelper::<AccountId32>::default(None, None, None, None);
    let (uri, owner_did, challenge_value, timestamp) = urauth_helper.deconstruct_urauth_doc(None);
    let bounded_uri = urauth_helper.bounded_uri(None);
    let bounded_owner_did = urauth_helper.raw_owner_did();
    let signer = MultiSigner::Sr25519(Alice.public());
    let r_sig = urauth_helper.create_signature(
        Alice,
        ProofType::Request(
            urauth_helper.bounded_uri(None),
            urauth_helper.raw_owner_did(),
        ),
    );
    let c_sig = urauth_helper.create_sr25519_signature(
        Alice,
        ProofType::Challenge(
            bounded_uri.clone(),
            bounded_owner_did.clone(),
            challenge_value,
            timestamp,
        ),
    );
    let challenge_json =
        urauth_helper.generate_json("Sr25519Signature2020".into(), hex::encode(c_sig));

    let request_call = RequestCall::new(
        RuntimeOrigin::signed(Alice.to_account_id()),
        ClaimType::WebsiteDomain,
        "www.website1.com".as_bytes().to_vec(),
        URIRequestType::Oracle { is_root: true },
        owner_did.clone(),
        Some(urauth_helper.challenge_value()),
        signer.clone(),
        r_sig.clone(),
    );

    new_test_ext().execute_with(|| {
        assert_ok!(URAuth::add_oracle_member(
            RuntimeOrigin::root(),
            Alice.to_account_id()
        ));
        // Request type should be 'Oracle'
        assert_noop!(
            request_call
                .clone()
                .set_request_type(URIRequestType::Any {
                    maybe_parent_acc: Alice.to_account_id()
                })
                .runtime_call(),
            Error::<Test>::BadClaim
        );
        // Domain without host should fail
        assert_noop!(
            request_call
                .clone()
                .set_uri("news:comp.infosystems".as_bytes().to_vec())
                .runtime_call(),
            Error::<Test>::BadClaim
        );
        // URI which is not root should fail
        assert_noop!(
            request_call
                .clone()
                .set_uri("sub1.website1.com".as_bytes().to_vec())
                .runtime_call(),
            Error::<Test>::NotRootURI
        );
        assert_ok!(request_call.runtime_call());
    })
}
