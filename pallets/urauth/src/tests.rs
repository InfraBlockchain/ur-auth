
pub use super::{VerificationSubmission, VerificationResult};

fn find_json_value(json_object: lite_json::JsonObject, field_name: String) -> Option<String> {
    let (_, json_value) = json_object
        .iter()
        .find(|(field, _)| field.iter().copied().eq(field_name.chars()))
        .unwrap();
    match json_value {
        lite_json::JsonValue::String(v) => Some(v.iter().collect::<String>()),
        lite_json::JsonValue::Object(v) => find_json_value(v.clone(), "proofValue".into()),
        _ => None,
    }
}

#[test]
fn json_parse_works() {
    use lite_json::{json_parser::parse_json, JsonValue};

    let json_string = r#"
        {
            "domain" : "website1.com",
            "adminDID" : "did:infra:ua:i3jr3...qW3dt",
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
    let mut proof: String = "".into();
    match json_data {
        JsonValue::Object(obj_value) => {
            domain = find_json_value(obj_value.clone(), "domain".into()).unwrap();
            admin_did = find_json_value(obj_value.clone(), "adminDID".into()).unwrap();
            challenge = find_json_value(obj_value.clone(), "challenge".into()).unwrap();
            timestamp = find_json_value(obj_value.clone(), "timestamp".into()).unwrap();
            proof = find_json_value(obj_value.clone(), "proof".into()).unwrap();
        }
        _ => {}
    }
    let did_clone = admin_did.clone();
    let pk = did_clone.split(':').collect::<Vec<&str>>();
    println!(
        "도메인 => {:?}, 어드민 => {:?}, 퍼블릭키 => {:?}, 챌린지 => {:?}, 타임스탬프 => {:?}, 프루프 => {:?}",
        domain, admin_did, pk.last().unwrap(), challenge, timestamp, proof
    );
}

#[test]
fn verification_submission_dynamic_threshold_works() {
    let mut submission: VerificationSubmission = Default::default();
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
    let mut s1: VerificationSubmission = Default::default();
    let h1 = BlakeTwo256::hash(&1u32.to_le_bytes());
    s1.update_status(3, &h1);
    let res = s1.update_status(3, &h1);
    assert_eq!(res, VerificationResult::Complete);
    println!("{:?}", s1);

    // Tie
    let mut s2: VerificationSubmission = Default::default();
    let h1 = BlakeTwo256::hash(&1u32.to_le_bytes());
    let h2 = BlakeTwo256::hash(&2u32.to_le_bytes());
    let h3 = BlakeTwo256::hash(&3u32.to_le_bytes());
    let res = s2.update_status(3, &h1);
    assert_eq!(res, VerificationResult::InProgress);
    let res = s2.update_status(3, &h2);
    assert_eq!(res, VerificationResult::InProgress);
    let res = s2.update_status(3, &h3);
    assert_eq!(res, VerificationResult::Tie);

    let mut s3: VerificationSubmission = Default::default();
    let h1 = BlakeTwo256::hash(&1u32.to_le_bytes());
    let res = s3.update_status(1, &h1);
    assert_eq!(res, VerificationResult::Complete);
}


