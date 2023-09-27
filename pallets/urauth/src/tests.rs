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
    let r_sig = urauth_helper.create_signature(
        Alice,
        ProofType::Request(
            urauth_helper.bounded_uri(None),
            urauth_helper.raw_owner_did(),
        ),
    );
    let request_call = RequestCall::new(
        RuntimeOrigin::signed(Alice.to_account_id()),
        ClaimType::WebsiteDomain,
        uri,
        URIRequestType::Oracle { is_root: true },
        owner_did.clone(),
        Some(urauth_helper.challenge_value()),
        signer.clone(),
        r_sig.clone(),
    );
    new_test_ext().execute_with(|| {
        assert_ok!(URAuth::add_uri_by_oracle(
            RuntimeOrigin::root(),
            ClaimType::WebsiteDomain,
            URIRequestType::Oracle { is_root: true },
            "https://www.website1.com".into()
        ));

        assert_ok!(request_call.clone().runtime_call());
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
            request_call
                .clone()
                .set_owner_did(urauth_helper.generate_did(BOB_SS58).as_bytes().to_vec())
                .runtime_call(),
            Error::<Test>::BadSigner
        );

        // Different URI with signature should fail
        assert_noop!(
            request_call
                .clone()
                .set_sig(urauth_helper.create_signature(
                    Alice,
                    ProofType::Request(
                        urauth_helper.bounded_uri(Some("www.website.com".into())),
                        urauth_helper.raw_owner_did(),
                    ),
                ))
                .runtime_call(),
            Error::<Test>::BadProof
        );

        // Sign with different DID should fail
        assert_noop!(
            request_call
                .set_sig(
                    urauth_helper.create_signature(
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
                    )
                )
                .runtime_call(),
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
        let register_uri: URI = "website1.com".as_bytes().to_vec().try_into().unwrap();
        let urauth_doc = URAuthTree::<Test>::get(&register_uri).unwrap();
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

        let register_uri: URI = "website1.com".as_bytes().to_vec().try_into().unwrap();
        let mut urauth_doc = URAuthTree::<Test>::get(&register_uri).unwrap();
        debug_doc(&urauth_doc);

        let update_doc_field = UpdateDocField::AccessRules(None);
        urauth_doc.update_doc(update_doc_field.clone(), 1).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(
                register_uri.clone(),
                urauth_doc.clone(),
                bounded_owner_did.clone(),
            ),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            register_uri.clone(),
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
                register_uri.clone(),
                urauth_doc.clone(),
                bounded_owner_did.clone(),
            ),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            register_uri.clone(),
            update_doc_field,
            2u128,
            Some(Proof::ProofV1 {
                did: bounded_owner_did.clone(),
                proof: update_signature.into()
            })
        ));
        let mut urauth_doc = URAuthTree::<Test>::get(&register_uri).unwrap();
        debug_doc(&urauth_doc);

        let update_doc_field = UpdateDocField::MultiDID(WeightedDID {
            did: Bob.to_account_id(),
            weight: 1,
        });
        urauth_doc.update_doc(update_doc_field.clone(), 3).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(
                register_uri.clone(),
                urauth_doc.clone(),
                bounded_owner_did.clone(),
            ),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            register_uri.clone(),
            update_doc_field,
            3u128,
            Some(Proof::ProofV1 {
                did: bounded_owner_did.clone(),
                proof: update_signature.into()
            })
        ));

        let mut urauth_doc = URAuthTree::<Test>::get(&register_uri).unwrap();
        debug_doc(&urauth_doc);

        let update_doc_field = UpdateDocField::<MockAccountId>::Threshold(2);
        urauth_doc.update_doc(update_doc_field.clone(), 4).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(
                register_uri.clone(),
                urauth_doc.clone(),
                bounded_owner_did.clone(),
            ),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Alice.to_account_id()),
            register_uri.clone(),
            update_doc_field,
            4u128,
            Some(Proof::ProofV1 {
                did: bounded_owner_did.clone(),
                proof: update_signature.into()
            })
        ));

        let mut urauth_doc = URAuthTree::<Test>::get(&register_uri).unwrap();
        debug_doc(&urauth_doc);

        let update_doc_field = UpdateDocField::MultiDID(WeightedDID {
            did: Charlie.to_account_id(),
            weight: 1,
        });
        urauth_doc.update_doc(update_doc_field.clone(), 5).unwrap();
        let update_signature = urauth_helper.create_sr25519_signature(
            Alice,
            ProofType::Update(
                register_uri.clone(),
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
            register_uri.clone(),
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
        let mut urauth_doc = URAuthTree::<Test>::get(&register_uri).unwrap();

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
            ProofType::Update(register_uri.clone(), urauth_doc.clone(), bob_did.clone()),
        );
        assert_ok!(URAuth::update_urauth_doc(
            RuntimeOrigin::signed(Bob.to_account_id()),
            register_uri.clone(),
            update_doc_field,
            5,
            Some(Proof::ProofV1 {
                did: bob_did,
                proof: update_signature.into()
            })
        ));

        let urauth_doc = URAuthTree::<Test>::get(&register_uri).unwrap();
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
        uri,
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
                    is_root: true,
                    maybe_parent_acc: None
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
        assert_ok!(request_call.clone().runtime_call());
        assert_ok!(URAuth::verify_challenge(
            RuntimeOrigin::signed(Alice.to_account_id()),
            challenge_json
        ));
        let reigstered_uri: URI = "website1.com".as_bytes().to_vec().try_into().unwrap();
        let urauth_doc = URAuthTree::<Test>::get(&reigstered_uri).unwrap();
        debug_doc(&urauth_doc);
        let uri = "sub2.sub1.website1.com".as_bytes().to_vec();
        // Registered URI should not be requested.
        assert_noop!(
            request_call.clone().runtime_call(),
            Error::<Test>::AlreadyRegistered
        );

        // Parent should be Alice
        assert_noop!(
            request_call
                .clone()
                .set_challenge(None)
                .set_uri(uri.clone())
                .set_request_type(URIRequestType::Any {
                    is_root: false,
                    maybe_parent_acc: Some(Bob.to_account_id())
                })
                .runtime_call(),
            Error::<Test>::NotURAuthDocOwner
        );

        let bob_did = urauth_helper.generate_did(BOB_SS58).as_bytes().to_vec();

        assert_ok!(request_call
            .clone()
            .set_challenge(None)
            .set_uri(uri.clone())
            .set_signer(Bob.into())
            .set_owner_did(bob_did.clone())
            .set_request_type(URIRequestType::Any {
                is_root: false,
                maybe_parent_acc: Some(Alice.to_account_id())
            })
            .set_sig(urauth_helper.create_signature(
                Bob,
                ProofType::Request(
                    uri.clone().try_into().unwrap(),
                    bob_did.clone().try_into().unwrap()
                )
            ))
            .runtime_call());
        let reigstered_uri: URI = uri.try_into().unwrap();
        let urauth_doc = URAuthTree::<Test>::get(&reigstered_uri).unwrap();
        debug_doc(&urauth_doc);

        let uri = "website2.com/user".as_bytes().to_vec();
        // Request URI not in URIByOracle should be fail
        assert_noop!(
            request_call
                .clone()
                .set_request_type(URIRequestType::Oracle { is_root: false })
                .set_uri(uri.clone())
                .set_owner_did(bob_did.clone())
                .set_sig(urauth_helper.create_signature(
                    Bob,
                    ProofType::Request(
                        uri.clone().try_into().unwrap(),
                        bob_did.clone().try_into().unwrap()
                    )
                ))
                .runtime_call(),
            Error::<Test>::BadClaim
        );
        assert_ok!(URAuth::add_uri_by_oracle(
            RuntimeOrigin::root(),
            ClaimType::WebServiceAccount,
            URIRequestType::Oracle { is_root: false },
            "website2.com/*".into()
        ));
        assert_ok!(request_call
            .clone()
            .set_request_type(URIRequestType::Oracle { is_root: false })
            .set_uri(uri.clone())
            .set_owner_did(bob_did.clone())
            .set_signer(Bob.into())
            .set_sig(urauth_helper.create_signature(
                Bob,
                ProofType::Request(uri.try_into().unwrap(), bob_did.clone().try_into().unwrap())
            ))
            .runtime_call());
        let uri = "website3.com/user".as_bytes().to_vec();
        let uri2 = "website3.com/feed/1/2/3".as_bytes().to_vec();
        assert_ok!(URAuth::add_uri_by_oracle(
            RuntimeOrigin::root(),
            ClaimType::WebServiceAccount,
            URIRequestType::Oracle { is_root: false },
            "website3.com/feed/*".into()
        ));
        assert_noop!(
            request_call
                .clone()
                .set_request_type(URIRequestType::Oracle { is_root: false })
                .set_uri(uri.clone())
                .set_owner_did(bob_did.clone())
                .set_sig(urauth_helper.create_signature(
                    Bob,
                    ProofType::Request(
                        uri.clone().try_into().unwrap(),
                        bob_did.clone().try_into().unwrap()
                    )
                ))
                .runtime_call(),
            Error::<Test>::BadClaim
        );
        assert_ok!(request_call
            .clone()
            .set_request_type(URIRequestType::Oracle { is_root: false })
            .set_uri(uri2.clone())
            .set_owner_did(bob_did.clone())
            .set_signer(Bob.into())
            .set_sig(urauth_helper.create_signature(
                Bob,
                ProofType::Request(
                    uri2.try_into().unwrap(),
                    bob_did.clone().try_into().unwrap()
                )
            ))
            .runtime_call());
        let uri = "urauth://file/cid".as_bytes().to_vec();
        assert_ok!(request_call
            .clone()
            .set_challenge(None)
            .set_claim_type(ClaimType::File)
            .set_request_type(URIRequestType::Any {
                is_root: true,
                maybe_parent_acc: None
            })
            .set_uri(uri.clone())
            .set_sig(urauth_helper.create_signature(
                Alice,
                ProofType::Request(
                    uri.try_into().unwrap(),
                    owner_did.clone().try_into().unwrap()
                )
            ))
            .runtime_call());
        let uri = "urauth://file/cid/1".as_bytes().to_vec();
        assert_noop!(
            request_call
                .clone()
                .set_challenge(None)
                .set_claim_type(ClaimType::File)
                .set_request_type(URIRequestType::Any {
                    is_root: true,
                    maybe_parent_acc: None
                })
                .set_uri(uri.clone())
                .set_sig(urauth_helper.create_signature(
                    Alice,
                    ProofType::Request(
                        uri.clone().try_into().unwrap(),
                        owner_did.clone().try_into().unwrap()
                    )
                ))
                .runtime_call(),
            Error::<Test>::NotRootURI
        );
        assert_noop!(
            request_call
                .clone()
                .set_challenge(None)
                .set_claim_type(ClaimType::File)
                .set_request_type(URIRequestType::Any {
                    is_root: false,
                    maybe_parent_acc: Some(Bob.to_account_id())
                })
                .set_uri(uri.clone())
                .set_sig(urauth_helper.create_signature(
                    Alice,
                    ProofType::Request(
                        uri.clone().try_into().unwrap(),
                        owner_did.clone().try_into().unwrap()
                    )
                ))
                .runtime_call(),
            Error::<Test>::NotURAuthDocOwner
        );
        assert_ok!(request_call
            .clone()
            .set_challenge(None)
            .set_claim_type(ClaimType::File)
            .set_request_type(URIRequestType::Any {
                is_root: false,
                maybe_parent_acc: Some(Alice.to_account_id())
            })
            .set_uri(uri.clone())
            .set_sig(urauth_helper.create_signature(
                Alice,
                ProofType::Request(
                    uri.try_into().unwrap(),
                    owner_did.clone().try_into().unwrap()
                )
            ))
            .runtime_call());
        let uri = "website4.com".as_bytes().to_vec();
        let bounded_uri: URI = uri.clone().try_into().unwrap();
        assert_ok!(request_call
            .clone()
            .set_uri(uri.clone())
            .set_sig(urauth_helper.create_signature(Alice, ProofType::Request(bounded_uri.clone(), owner_did.try_into().unwrap())))
            .runtime_call()
        );
        run_to_block(5);
        assert!(Metadata::<Test>::get(&bounded_uri).is_none());
        assert!(URIVerificationInfo::<Test>::get(&bounded_uri).is_none());
        assert!(ChallengeValue::<Test>::get(&bounded_uri).is_none());
    })
}
